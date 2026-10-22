"""Statistics correctness tests.

OWNER: QualityGuard.

Every expectation in this module is hand-computed from the fixture that is
built inside the test, using the byte accounting rules of
`docs/SCHEMA.md` section 4:

* `captured_frame_length` is the whole frame on the wire, link header included.
  It is the only number summed for byte totals.
* `ip_packet_length` is the IP datagram size only and is `null` for frames that
  carry no IP header.
* Percentages are floats rounded to two decimals.

The capture used by most tests is built frame by frame in `build_reference_capture`
so that the expected packet count, byte totals, duration and inter-packet
intervals are all known exactly before the code under test runs.
"""

from __future__ import annotations

import math
from pathlib import Path

import pytest

from tests import qg_support as q
from tests.qg_support import qg_client, qg_offline_client  # noqa: F401  (fixture imports)

UPLOAD_ROUTE = "/api/analysis/upload"


def _route_exists(path: str, method: str) -> bool:
    from app.main import app

    paths = app.openapi().get("paths", {})
    return path in paths and method.lower() in paths[path]


pytestmark = pytest.mark.skipif(
    not _route_exists(UPLOAD_ROUTE, "POST"),
    reason="POST /api/analysis/upload is not implemented yet (owner: PacketCore)",
)


BASE_EPOCH = 1_700_000_000.0


def build_reference_capture(path: Path) -> tuple[Path, list[dict]]:
    """Six frames with exactly known lengths, timestamps and expectations.

    Returns the capture path and a description of every frame, so a test can
    assert against numbers derived from the fixture instead of from the code
    under test.
    """
    http_req = q.http_request("GET", "/index.html", "example.com")
    http_res = q.http_response(200, "OK")
    dns_q = q.dns_query("example.com")
    hello = q.tls_client_hello("secure.example.com")
    quic = q.quic_initial()
    arp = q.frame_arp()

    frames = [
        (BASE_EPOCH, q.frame_ipv4_tcp(src_port=51000, dst_port=80, payload=http_req)),
        (BASE_EPOCH + 0.100, q.frame_ipv4_tcp(src_ip="10.0.0.2", dst_ip="10.0.0.1", src_port=80, dst_port=51000, payload=http_res)),
        (BASE_EPOCH + 0.300, q.frame_ipv4_udp(src_port=51001, dst_port=53, payload=dns_q)),
        (BASE_EPOCH + 0.600, q.frame_ipv4_tcp(src_port=51002, dst_port=443, payload=hello)),
        (BASE_EPOCH + 1.000, q.frame_ipv4_udp(src_port=51003, dst_port=443, payload=quic)),
        (BASE_EPOCH + 1.500, arp),
    ]

    expectations = [
        {
            "frame_number": 1,
            "timestamp": "2023-11-14T22:13:20.000000Z",
            "timestamp_epoch": BASE_EPOCH,
            "source_ip": "10.0.0.1",
            "destination_ip": "10.0.0.2",
            "source_port": 51000,
            "destination_port": 80,
            "transport_protocol": "TCP",
            "application_protocol": "HTTP",
            "http_method": "GET",
            "ip_version": 4,
            "captured_frame_length": len(frames[0][1]),
            "ip_packet_length": len(frames[0][1]) - 14,
            "interval": None,
            "is_encrypted": False,
        },
        {
            "frame_number": 2,
            "timestamp": "2023-11-14T22:13:20.100000Z",
            "timestamp_epoch": BASE_EPOCH + 0.100,
            "source_ip": "10.0.0.2",
            "destination_ip": "10.0.0.1",
            "source_port": 80,
            "destination_port": 51000,
            "transport_protocol": "TCP",
            "application_protocol": "HTTP",
            "http_status_code": 200,
            "ip_version": 4,
            "captured_frame_length": len(frames[1][1]),
            "ip_packet_length": len(frames[1][1]) - 14,
            "interval": 0.100,
            "is_encrypted": False,
        },
        {
            "frame_number": 3,
            "timestamp": "2023-11-14T22:13:20.300000Z",
            "timestamp_epoch": BASE_EPOCH + 0.300,
            "source_ip": "10.0.0.1",
            "destination_ip": "10.0.0.2",
            "source_port": 51001,
            "destination_port": 53,
            "transport_protocol": "UDP",
            "application_protocol": "DNS",
            "ip_version": 4,
            "captured_frame_length": len(frames[2][1]),
            "ip_packet_length": len(frames[2][1]) - 14,
            "interval": 0.200,
            "is_encrypted": False,
        },
        {
            "frame_number": 4,
            "timestamp": "2023-11-14T22:13:20.600000Z",
            "timestamp_epoch": BASE_EPOCH + 0.600,
            "source_ip": "10.0.0.1",
            "destination_ip": "10.0.0.2",
            "source_port": 51002,
            "destination_port": 443,
            "transport_protocol": "TCP",
            "application_protocol": "TLS",
            "ip_version": 4,
            "captured_frame_length": len(frames[3][1]),
            "ip_packet_length": len(frames[3][1]) - 14,
            "interval": 0.300,
            "is_encrypted": True,
        },
        {
            "frame_number": 5,
            "timestamp": "2023-11-14T22:13:21.000000Z",
            "timestamp_epoch": BASE_EPOCH + 1.000,
            "source_ip": "10.0.0.1",
            "destination_ip": "10.0.0.2",
            "source_port": 51003,
            "destination_port": 443,
            "transport_protocol": "UDP",
            "application_protocol": "QUIC",
            "ip_version": 4,
            "captured_frame_length": len(frames[4][1]),
            "ip_packet_length": len(frames[4][1]) - 14,
            "interval": 0.400,
            "is_encrypted": True,
        },
        {
            "frame_number": 6,
            "timestamp": "2023-11-14T22:13:21.500000Z",
            "timestamp_epoch": BASE_EPOCH + 1.500,
            "source_ip": None,
            "destination_ip": None,
            "source_port": None,
            "destination_port": None,
            "transport_protocol": "ARP",
            "application_protocol": "ARP",
            "ip_version": None,
            "captured_frame_length": len(frames[5][1]),
            "ip_packet_length": None,
            "interval": 0.500,
            "is_encrypted": False,
        },
    ]
    return q.write_pcap_frames(path, frames), expectations


@pytest.fixture()
def reference_capture(tmp_path: Path):
    path, expectations = build_reference_capture(tmp_path / "reference.pcap")
    return path, expectations


def upload(client, path: Path, filename: str = "reference.pcap") -> dict:
    with path.open("rb") as handle:
        response = client.post(
            UPLOAD_ROUTE,
            files={"file": (filename, handle.read(), "application/octet-stream")},
        )
    assert response.status_code == 201, response.text
    return response.json()


def get_summary(client, analysis_id: str) -> dict:
    response = client.get(f"/api/analysis/{analysis_id}/summary")
    assert response.status_code == 200, response.text
    return response.json()


def get_packets(client, analysis_id: str, **params) -> dict:
    response = client.get(f"/api/analysis/{analysis_id}/packets", params=params)
    assert response.status_code == 200, response.text
    return response.json()


class TestSummaryAggregates:
    def test_packet_count_matches_the_capture(self, qg_client, reference_capture):
        path, expectations = reference_capture
        analysis_id = upload(qg_client, path)["analysis_id"]
        summary = get_summary(qg_client, analysis_id)
        assert summary["packet_count"] == len(expectations) == 6

    def test_total_bytes_is_the_sum_of_the_frame_lengths(self, qg_client, reference_capture):
        path, expectations = reference_capture
        analysis_id = upload(qg_client, path)["analysis_id"]
        summary = get_summary(qg_client, analysis_id)
        expected = sum(item["captured_frame_length"] for item in expectations)
        assert summary["total_bytes"] == expected

    def test_total_bytes_never_uses_the_ip_length(self, qg_client, reference_capture):
        path, expectations = reference_capture
        analysis_id = upload(qg_client, path)["analysis_id"]
        summary = get_summary(qg_client, analysis_id)
        ip_total = sum(item["ip_packet_length"] or 0 for item in expectations)
        assert summary["total_bytes"] != ip_total
        assert summary["total_bytes"] == ip_total + 14 * 5 + expectations[5]["captured_frame_length"]

    def test_capture_duration_is_the_span_between_first_and_last_packet(
        self, qg_client, reference_capture
    ):
        path, expectations = reference_capture
        analysis_id = upload(qg_client, path)["analysis_id"]
        summary = get_summary(qg_client, analysis_id)
        assert summary["duration_seconds"] == pytest.approx(1.5, abs=1e-6)

    def test_first_and_last_timestamps_come_from_the_capture(self, qg_client, reference_capture):
        path, expectations = reference_capture
        analysis_id = upload(qg_client, path)["analysis_id"]
        summary = get_summary(qg_client, analysis_id)
        assert summary["first_timestamp"] == expectations[0]["timestamp"]
        assert summary["last_timestamp"] == expectations[-1]["timestamp"]

    def test_unique_hosts_counts_addresses_not_packets(self, qg_client, reference_capture):
        path, expectations = reference_capture
        analysis_id = upload(qg_client, path)["analysis_id"]
        summary = get_summary(qg_client, analysis_id)
        assert summary["unique_hosts"] == 2

    def test_http_request_and_response_counts(self, qg_client, reference_capture):
        path, expectations = reference_capture
        analysis_id = upload(qg_client, path)["analysis_id"]
        summary = get_summary(qg_client, analysis_id)
        assert summary["http_request_count"] == 1
        assert summary["http_response_count"] == 1

    def test_encrypted_packet_count(self, qg_client, reference_capture):
        path, expectations = reference_capture
        analysis_id = upload(qg_client, path)["analysis_id"]
        summary = get_summary(qg_client, analysis_id)
        assert summary["encrypted_packet_count"] == 2

    def test_created_at_is_utc_iso(self, qg_client, reference_capture):
        path, _ = reference_capture
        result = upload(qg_client, path)
        assert result["created_at"].endswith("Z")
        assert result["status"] == "complete"
        assert result["source_kind"] in {"pcap", "pcapng", "csv", "live"}

    def test_summary_is_stable_across_repeated_requests(self, qg_client, reference_capture):
        path, _ = reference_capture
        analysis_id = upload(qg_client, path)["analysis_id"]
        first = get_summary(qg_client, analysis_id)
        second = get_summary(qg_client, analysis_id)
        assert first == second


class TestProtocolDistribution:
    def test_protocol_counts_do_not_double_count(self, qg_client, reference_capture):
        path, expectations = reference_capture
        analysis_id = upload(qg_client, path)["analysis_id"]
        summary = get_summary(qg_client, analysis_id)
        assert sum(entry["packets"] for entry in summary["protocol_counts"]) == 6

    def test_application_protocol_counts_do_not_double_count(self, qg_client, reference_capture):
        path, expectations = reference_capture
        analysis_id = upload(qg_client, path)["analysis_id"]
        summary = get_summary(qg_client, analysis_id)
        assert sum(entry["packets"] for entry in summary["application_protocol_counts"]) == 6

    def test_percentages_sum_to_one_hundred(self, qg_client, reference_capture):
        path, _ = reference_capture
        analysis_id = upload(qg_client, path)["analysis_id"]
        summary = get_summary(qg_client, analysis_id)
        total = sum(entry["percentage"] for entry in summary["application_protocol_counts"])
        assert total == pytest.approx(100.0, abs=0.05)

    def test_percentage_is_rounded_to_two_decimals(self, qg_client, reference_capture):
        path, _ = reference_capture
        analysis_id = upload(qg_client, path)["analysis_id"]
        summary = get_summary(qg_client, analysis_id)
        for entry in summary["application_protocol_counts"]:
            assert entry["percentage"] == round(entry["percentage"], 2)

    def test_percentage_matches_the_hand_computed_share(self, qg_client, reference_capture):
        path, expectations = reference_capture
        analysis_id = upload(qg_client, path)["analysis_id"]
        summary = get_summary(qg_client, analysis_id)
        by_protocol = {entry["protocol"]: entry for entry in summary["application_protocol_counts"]}
        assert by_protocol["HTTP"]["packets"] == 2
        assert by_protocol["HTTP"]["percentage"] == pytest.approx(33.33, abs=0.01)
        assert by_protocol["HTTP"]["bytes"] == (
            expectations[0]["captured_frame_length"] + expectations[1]["captured_frame_length"]
        )
        assert by_protocol["TLS"]["packets"] == 1
        assert by_protocol["TLS"]["percentage"] == pytest.approx(16.67, abs=0.01)
        assert by_protocol["QUIC"]["packets"] == 1
        assert by_protocol["DNS"]["packets"] == 1
        assert by_protocol["ARP"]["packets"] == 1

    def test_protocol_endpoint_matches_the_summary(self, qg_client, reference_capture):
        path, _ = reference_capture
        analysis_id = upload(qg_client, path)["analysis_id"]
        summary = get_summary(qg_client, analysis_id)
        response = qg_client.get(f"/api/analysis/{analysis_id}/protocols")
        assert response.status_code == 200
        body = response.json()
        assert body["total"] == len(body["items"])
        assert sum(entry["packets"] for entry in body["items"]) == 6


class TestPacketFields:
    def test_frame_numbers_are_one_based_and_ordered(self, qg_client, reference_capture):
        path, expectations = reference_capture
        analysis_id = upload(qg_client, path)["analysis_id"]
        page = get_packets(qg_client, analysis_id)
        assert [item["frame_number"] for item in page["items"]] == [1, 2, 3, 4, 5, 6]
        assert page["total"] == 6

    def test_ipv4_fields(self, qg_client, reference_capture):
        path, expectations = reference_capture
        analysis_id = upload(qg_client, path)["analysis_id"]
        page = get_packets(qg_client, analysis_id)
        first = page["items"][0]
        assert first["source_ip"] == "10.0.0.1"
        assert first["destination_ip"] == "10.0.0.2"
        assert first["source_port"] == 51000
        assert first["destination_port"] == 80
        assert first["transport_protocol"] == "TCP"
        assert first["ip_version"] == 4

    def test_frame_length_versus_ip_packet_length(self, qg_client, reference_capture):
        path, expectations = reference_capture
        analysis_id = upload(qg_client, path)["analysis_id"]
        page = get_packets(qg_client, analysis_id)
        for item, expected in zip(page["items"], expectations):
            assert item["captured_frame_length"] == expected["captured_frame_length"]
            assert item["ip_packet_length"] == expected["ip_packet_length"]
            if expected["ip_packet_length"] is not None:
                assert item["captured_frame_length"] == item["ip_packet_length"] + 14

    def test_non_ip_frame_has_null_ip_fields(self, qg_client, reference_capture):
        path, _ = reference_capture
        analysis_id = upload(qg_client, path)["analysis_id"]
        page = get_packets(qg_client, analysis_id)
        arp = page["items"][5]
        assert arp["source_ip"] is None
        assert arp["destination_ip"] is None
        assert arp["source_port"] is None
        assert arp["destination_port"] is None
        assert arp["ip_packet_length"] is None
        assert arp["ip_version"] is None
        assert arp["captured_frame_length"] == 42

    def test_timestamp_is_iso_utc_with_z_suffix(self, qg_client, reference_capture):
        path, expectations = reference_capture
        analysis_id = upload(qg_client, path)["analysis_id"]
        page = get_packets(qg_client, analysis_id)
        for item, expected in zip(page["items"], expectations):
            assert item["timestamp"].endswith("Z")
            assert item["timestamp"] == expected["timestamp"]
            assert item["timestamp_epoch"] == pytest.approx(expected["timestamp_epoch"], abs=1e-6)

    def test_inter_packet_interval_is_the_delta_to_the_previous_packet(
        self, qg_client, reference_capture
    ):
        path, expectations = reference_capture
        analysis_id = upload(qg_client, path)["analysis_id"]
        page = get_packets(qg_client, analysis_id)
        for item, expected in zip(page["items"], expectations):
            if expected["interval"] is None:
                assert item["inter_packet_interval_seconds"] is None
            else:
                assert item["inter_packet_interval_seconds"] == pytest.approx(
                    expected["interval"], abs=1e-6
                )

    def test_http_fields_only_appear_on_observed_http(self, qg_client, reference_capture):
        path, _ = reference_capture
        analysis_id = upload(qg_client, path)["analysis_id"]
        page = get_packets(qg_client, analysis_id)
        by_number = {item["frame_number"]: item for item in page["items"]}
        assert by_number[1]["http_method"] == "GET"
        assert by_number[1]["http_status_code"] is None
        assert by_number[2]["http_status_code"] == 200
        assert by_number[2]["http_method"] is None
        for number in (3, 4, 5, 6):
            assert by_number[number]["http_method"] is None
            assert by_number[number]["http_status_code"] is None

    def test_server_name_is_reported_for_the_tls_handshake(self, qg_client, reference_capture):
        path, _ = reference_capture
        analysis_id = upload(qg_client, path)["analysis_id"]
        page = get_packets(qg_client, analysis_id)
        assert page["items"][3]["server_name"] == "secure.example.com"

    def test_protocols_layer_list_is_populated(self, qg_client, reference_capture):
        path, _ = reference_capture
        analysis_id = upload(qg_client, path)["analysis_id"]
        page = get_packets(qg_client, analysis_id)
        assert "ip" in page["items"][0]["protocols"]
        assert "tcp" in page["items"][0]["protocols"]

    def test_source_file_is_recorded(self, qg_client, reference_capture):
        path, _ = reference_capture
        analysis_id = upload(qg_client, path)["analysis_id"]
        page = get_packets(qg_client, analysis_id)
        assert page["items"][0]["source_file"] == "reference.pcap"


class TestHostAggregates:
    def test_host_byte_directions_are_consistent(self, qg_client, reference_capture):
        path, _ = reference_capture
        analysis_id = upload(qg_client, path)["analysis_id"]
        response = qg_client.get(f"/api/analysis/{analysis_id}/hosts")
        assert response.status_code == 200
        hosts = {entry["ip"]: entry for entry in response.json()["items"]}
        assert set(hosts) == {"10.0.0.1", "10.0.0.2"}
        for entry in hosts.values():
            assert entry["total_bytes"] == entry["bytes_sent"] + entry["bytes_received"]

    def test_host_totals_match_the_capture(self, qg_client, reference_capture):
        path, expectations = reference_capture
        analysis_id = upload(qg_client, path)["analysis_id"]
        response = qg_client.get(f"/api/analysis/{analysis_id}/hosts")
        hosts = {entry["ip"]: entry for entry in response.json()["items"]}
        sent = sum(
            item["captured_frame_length"]
            for item in expectations
            if item["source_ip"] == "10.0.0.1"
        )
        received = sum(
            item["captured_frame_length"]
            for item in expectations
            if item["destination_ip"] == "10.0.0.1"
        )
        assert hosts["10.0.0.1"]["bytes_sent"] == sent
        assert hosts["10.0.0.1"]["bytes_received"] == received

    def test_host_packets_count_matches_the_capture(self, qg_client, reference_capture):
        path, expectations = reference_capture
        analysis_id = upload(qg_client, path)["analysis_id"]
        response = qg_client.get(f"/api/analysis/{analysis_id}/hosts")
        hosts = {entry["ip"]: entry for entry in response.json()["items"]}
        assert hosts["10.0.0.1"]["packets"] == sum(
            1 for item in expectations if item["source_ip"] == "10.0.0.1"
        )
        assert hosts["10.0.0.2"]["packets"] == sum(
            1 for item in expectations if item["source_ip"] == "10.0.0.2"
        )

    def test_arp_frame_is_not_attributed_to_a_host(self, qg_client, reference_capture):
        path, _ = reference_capture
        analysis_id = upload(qg_client, path)["analysis_id"]
        response = qg_client.get(f"/api/analysis/{analysis_id}/hosts")
        hosts = response.json()["items"]
        assert sum(entry["packets"] for entry in hosts) == 5


class TestDegenerateCaptures:
    def test_empty_capture_produces_an_empty_analysis(self, qg_client, tmp_path):
        path = q.write_pcap_frames(tmp_path / "empty.pcap", [])
        result = upload(qg_client, path, "empty.pcap")
        assert result["packet_count"] == 0
        assert result["total_bytes"] == 0
        summary = get_summary(qg_client, result["analysis_id"])
        assert summary["packet_count"] == 0
        assert summary["total_bytes"] == 0
        assert summary["duration_seconds"] == 0
        assert summary["unique_hosts"] == 0
        assert summary["protocol_counts"] == [] or all(
            entry["packets"] == 0 for entry in summary["protocol_counts"]
        )

    def test_single_packet_capture_has_zero_duration(self, qg_client, tmp_path):
        frame = q.frame_ipv4_tcp(payload=q.http_request())
        path = q.write_pcap_frames(tmp_path / "one.pcap", [(BASE_EPOCH, frame)])
        analysis_id = upload(qg_client, path, "one.pcap")["analysis_id"]
        summary = get_summary(qg_client, analysis_id)
        assert summary["packet_count"] == 1
        assert summary["duration_seconds"] == 0
        page = get_packets(qg_client, analysis_id)
        assert page["items"][0]["inter_packet_interval_seconds"] is None

    def test_two_packets_with_the_same_timestamp_have_zero_duration(self, qg_client, tmp_path):
        frames = [
            (BASE_EPOCH, q.frame_ipv4_tcp(payload=q.http_request())),
            (BASE_EPOCH, q.frame_ipv4_tcp(src_port=51001, payload=q.http_response())),
        ]
        path = q.write_pcap_frames(tmp_path / "same.pcap", frames)
        analysis_id = upload(qg_client, path, "same.pcap")["analysis_id"]
        summary = get_summary(qg_client, analysis_id)
        assert summary["duration_seconds"] == 0
        page = get_packets(qg_client, analysis_id)
        assert page["items"][1]["inter_packet_interval_seconds"] == 0

    def test_capture_of_a_single_non_ip_frame(self, qg_client, tmp_path):
        path = q.write_pcap_frames(tmp_path / "arp.pcap", [(BASE_EPOCH, q.frame_arp())])
        analysis_id = upload(qg_client, path, "arp.pcap")["analysis_id"]
        summary = get_summary(qg_client, analysis_id)
        assert summary["packet_count"] == 1
        assert summary["unique_hosts"] == 0
        page = get_packets(qg_client, analysis_id)
        assert page["items"][0]["ip_packet_length"] is None
