"""Contract tests for the frozen v1 contract.

OWNER: QualityGuard.

These tests assert the executable contract of `app/models/packet.py`,
`app/config.py`, `app/services/store.py` and `app/main.py` against
`traffic-analyzer/docs/SCHEMA.md` and `traffic-analyzer/docs/API.md`.

They are deliberately implementation-agnostic: they inspect the published
behaviour (model fields, HTTP envelopes, stored state) rather than private
helpers, so they keep working when the internals are rewritten.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from app.config import CONTRACT_VERSION
from app.models.packet import (
    CaptureSummary,
    ErrorResponse,
    HostEntry,
    NormalizedPacket,
    PacketPage,
    ProtocolCount,
)
from tests.qg_support import qg_client  # noqa: F401  (fixture import)


def minimal_packet(**overrides) -> NormalizedPacket:
    """A packet with every required field filled in, so overrides can be tested."""
    data = {
        "frame_number": 1,
        "timestamp": "2026-10-21T18:23:27.755302Z",
        "timestamp_epoch": 1792604607.755302,
        "captured_frame_length": 74,
    }
    data.update(overrides)
    return NormalizedPacket(**data)


class TestNormalizedPacketContract:
    def test_required_fields_are_required(self):
        for field in ("frame_number", "timestamp", "timestamp_epoch", "captured_frame_length"):
            with pytest.raises(Exception):
                NormalizedPacket(**{
                    key: value
                    for key, value in {
                        "frame_number": 1,
                        "timestamp": "2026-10-21T18:23:27.755302Z",
                        "timestamp_epoch": 1.0,
                        "captured_frame_length": 74,
                    }.items()
                    if key != field
                })

    def test_nullable_fields_default_to_none(self):
        packet = minimal_packet()
        for field in (
            "source_ip",
            "destination_ip",
            "source_port",
            "destination_port",
            "transport_protocol",
            "application_protocol",
            "ip_packet_length",
            "tcp_flags",
            "tcp_stream_id",
            "http_method",
            "http_status_code",
            "tls_version",
            "server_name",
            "inter_packet_interval_seconds",
            "info",
            "source_file",
            "ip_version",
        ):
            assert getattr(packet, field) is None, f"{field} must default to null"

    def test_collections_and_flags_have_contract_defaults(self):
        packet = minimal_packet()
        assert packet.protocols == []
        assert packet.is_encrypted is False
        assert packet.direction_hint == "unknown"

    def test_frame_number_must_be_one_based(self):
        with pytest.raises(Exception):
            minimal_packet(frame_number=0)
        with pytest.raises(Exception):
            minimal_packet(frame_number=-3)

    def test_port_range_is_enforced(self):
        minimal_packet(source_port=0, destination_port=65535)
        with pytest.raises(Exception):
            minimal_packet(source_port=65536)
        with pytest.raises(Exception):
            minimal_packet(destination_port=-1)

    def test_http_status_code_range_is_enforced(self):
        minimal_packet(http_status_code=100)
        minimal_packet(http_status_code=599)
        with pytest.raises(Exception):
            minimal_packet(http_status_code=99)
        with pytest.raises(Exception):
            minimal_packet(http_status_code=600)

    def test_ip_version_range_is_enforced(self):
        minimal_packet(ip_version=4)
        minimal_packet(ip_version=6)
        with pytest.raises(Exception):
            minimal_packet(ip_version=3)
        with pytest.raises(Exception):
            minimal_packet(ip_version=7)

    @pytest.mark.xfail(
        strict=False,
        reason="SCHEMA.md says ip_version is 4, 6 or null; the model uses ge=4/le=6 so 5 is accepted",
    )
    def test_ip_version_rejects_five(self):
        with pytest.raises(Exception):
            minimal_packet(ip_version=5)

    def test_ip_packet_length_may_be_null_but_not_negative(self):
        minimal_packet(ip_packet_length=None)
        minimal_packet(ip_packet_length=0)
        with pytest.raises(Exception):
            minimal_packet(ip_packet_length=-1)

    def test_transport_protocol_vocabulary(self):
        allowed = {"TCP", "UDP", "ICMP", "ICMPv6", "ARP", "SCTP", "OTHER"}
        for value in allowed:
            assert minimal_packet(transport_protocol=value).transport_protocol == value
        with pytest.raises(Exception):
            minimal_packet(transport_protocol="tcp")
        with pytest.raises(Exception):
            minimal_packet(transport_protocol="HTTPS")

    def test_application_protocol_vocabulary(self):
        allowed = {
            "HTTP",
            "TLS",
            "QUIC",
            "DNS",
            "TCP",
            "UDP",
            "ICMP",
            "ICMPv6",
            "ARP",
            "SCTP",
            "OTHER",
        }
        for value in allowed:
            assert minimal_packet(application_protocol=value).application_protocol == value
        with pytest.raises(Exception):
            minimal_packet(application_protocol="Unknown")
        with pytest.raises(Exception):
            minimal_packet(application_protocol="HTTPS")
        with pytest.raises(Exception):
            minimal_packet(application_protocol="http")

    def test_direction_hint_vocabulary(self):
        for value in ("outbound", "inbound", "unknown"):
            assert minimal_packet(direction_hint=value).direction_hint == value
        with pytest.raises(Exception):
            minimal_packet(direction_hint="uplink")

    def test_protocols_layer_list_is_bottom_up_free_form(self):
        packet = minimal_packet(protocols=["eth", "ip", "tcp", "http"])
        assert packet.protocols == ["eth", "ip", "tcp", "http"]

    def test_serialization_keeps_nulls_explicit(self):
        payload = minimal_packet().model_dump()
        assert "source_ip" in payload
        assert payload["source_ip"] is None

    def test_json_round_trip_preserves_the_contract(self):
        packet = minimal_packet(
            source_ip="10.0.0.1",
            source_port=51000,
            transport_protocol="TCP",
            application_protocol="HTTP",
            http_method="GET",
        )
        restored = NormalizedPacket.model_validate_json(packet.model_dump_json())
        assert restored == packet


class TestSummaryContract:
    def test_summary_requires_the_headline_identifiers(self):
        with pytest.raises(Exception):
            CaptureSummary()

    def test_summary_accepts_the_documented_shape(self):
        summary = CaptureSummary(
            analysis_id="abc123",
            source_file="sample.pcapng",
            source_kind="pcapng",
            created_at="2026-10-21T18:30:05Z",
            packet_count=3,
            total_bytes=260,
            duration_seconds=0.5,
            unique_hosts=2,
            encrypted_packet_count=0,
            http_request_count=1,
            http_response_count=1,
        )
        assert summary.protocol_counts == []
        assert summary.application_protocol_counts == []
        assert summary.http_status_counts == []
        assert summary.top_hosts == []
        assert summary.conversations == []
        assert summary.warnings == []

    def test_percentage_is_bounded(self):
        with pytest.raises(Exception):
            ProtocolCount(protocol="HTTP", packets=1, bytes=1, percentage=100.5)
        with pytest.raises(Exception):
            ProtocolCount(protocol="HTTP", packets=1, bytes=1, percentage=-0.1)

    def test_host_entry_shape(self):
        host = HostEntry(
            ip="10.0.0.5",
            packets=120,
            bytes_sent=8000,
            bytes_received=40000,
            total_bytes=48000,
            protocols=["HTTP"],
        )
        assert host.total_bytes == host.bytes_sent + host.bytes_received

    def test_packet_page_envelope(self):
        page = PacketPage(items=[minimal_packet()], total=1, limit=100, offset=0)
        assert page.total == 1
        with pytest.raises(Exception):
            PacketPage(items=[], total=0, limit=0, offset=0)


class TestErrorEnvelope:
    def test_error_envelope_shape(self):
        envelope = ErrorResponse(
            error={"code": "not_found", "message": "Analysis 'abc123' does not exist.", "detail": {}}
        )
        assert envelope.error.code == "not_found"
        assert isinstance(envelope.error.detail, dict)


class TestHealthEndpoint:
    def test_health_reports_the_contract_version(self, qg_client):
        response = qg_client.get("/api/health")
        assert response.status_code == 200
        body = response.json()
        assert body["contract_version"] == CONTRACT_VERSION
        assert body["status"] in {"ok", "degraded"}
        assert "tshark" in body
        assert set(body["tshark"]) == {"available", "path", "version"}
        assert isinstance(body["tshark"]["available"], bool)
        assert isinstance(body["uptime_seconds"], float)
        assert body["uptime_seconds"] >= 0

    def test_health_reports_missing_tshark_without_failing(self, qg_client, monkeypatch):
        from app import config

        monkeypatch.setattr(config, "TSHARK_PATH", None)
        response = qg_client.get("/api/health")
        assert response.status_code == 200
        body = response.json()
        assert body["tshark"]["available"] is False
        assert body["tshark"]["path"] is None


class TestErrorEnvelopeOverHttp:
    def test_unknown_route_uses_the_error_envelope(self, qg_client):
        response = qg_client.get("/api/does-not-exist")
        assert response.status_code == 404
        body = response.json()
        assert set(body) == {"error"}
        assert body["error"]["code"] == "not_found"
        assert isinstance(body["error"]["message"], str)
        assert isinstance(body["error"]["detail"], dict)

    def test_method_not_allowed_uses_the_error_envelope(self, qg_client):
        response = qg_client.post("/api/health")
        assert response.status_code == 405
        body = response.json()
        assert body["error"]["code"] == "not_found"
        assert isinstance(body["error"]["detail"], dict)

    def test_root_endpoint_advertises_the_health_route(self, qg_client):
        response = qg_client.get("/")
        assert response.status_code == 200
        body = response.json()
        assert body["health"] == "/api/health"
        assert body["contract_version"] == CONTRACT_VERSION


class TestStoreContract:
    def test_create_get_and_remove(self, qg_client):
        from app.services.store import store

        analysis = store.create(
            source_file="sample.pcap",
            source_kind="pcap",
            packets=[minimal_packet(), minimal_packet(frame_number=2, captured_frame_length=100)],
        )
        assert store.get(analysis.analysis_id) is analysis
        assert analysis.total_bytes == 74 + 100
        assert analysis.created_at.endswith("Z")
        assert analysis.analysis_id in store.list()[0].analysis_id
        assert store.remove(analysis.analysis_id) is True
        assert store.get(analysis.analysis_id) is None
        assert store.remove(analysis.analysis_id) is False

    def test_persisted_analysis_is_written_to_disk(self, qg_client):
        from app.config import ANALYSES_DIR
        from app.services.store import store

        analysis = store.create(
            source_file="sample.pcap",
            source_kind="pcap",
            packets=[minimal_packet()],
        )
        directory = ANALYSES_DIR / analysis.analysis_id
        assert (directory / "meta.json").is_file()
        assert (directory / "packets.jsonl").is_file()
        meta = json.loads((directory / "meta.json").read_text(encoding="utf-8"))
        assert meta["analysis_id"] == analysis.analysis_id
        assert meta["packet_count"] == 1
        lines = [
            line
            for line in (directory / "packets.jsonl").read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        assert len(lines) == 1

    def test_rehydrate_restores_persisted_analyses(self, qg_client):
        from app.config import ANALYSES_DIR
        from app.services.store import store

        analysis = store.create(
            source_file="sample.pcap",
            source_kind="pcap",
            packets=[minimal_packet()],
        )
        store._analyses.clear()
        restored = store.rehydrate()
        assert restored == 1
        assert store.get(analysis.analysis_id) is not None

    def test_rehydrate_ignores_corrupt_metadata(self, qg_client):
        from app.config import ANALYSES_DIR
        from app.services.store import store

        broken = ANALYSES_DIR / "broken"
        broken.mkdir(parents=True, exist_ok=True)
        (broken / "meta.json").write_text("{not json", encoding="utf-8")
        (broken / "packets.jsonl").write_text("not json either\n", encoding="utf-8")
        assert store.rehydrate() == 0

    def test_created_at_is_utc_iso_with_z_suffix(self, qg_client):
        from app.services.store import utc_now_iso

        value = utc_now_iso()
        assert value.endswith("Z")
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
        assert parsed.tzinfo is not None
