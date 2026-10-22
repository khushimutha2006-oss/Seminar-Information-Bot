"""End-to-end tests of the analysis read path.

OWNER: QualityGuard.

These tests drive the public HTTP contract of `traffic-analyzer/docs/API.md`
from upload to export and assert that the numbers reported by the different
endpoints agree with each other and with the file that was uploaded.

The capture files are built byte by byte in `tests/qg_support.py`, so the
expected packet count, byte total and duration are known before the code under
test runs. No test needs root privileges, a live network or TShark.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tests import qg_support as q
from tests.qg_support import qg_isolated_storage  # noqa: F401  (fixture import)

UPLOAD_ROUTE = "/api/analysis/upload"

#: The column order of `NormalizedPacket` as documented in `docs/SCHEMA.md` §1.
SCHEMA_COLUMN_ORDER = [
    "frame_number",
    "timestamp",
    "timestamp_epoch",
    "source_ip",
    "destination_ip",
    "source_port",
    "destination_port",
    "transport_protocol",
    "application_protocol",
    "captured_frame_length",
    "ip_packet_length",
    "tcp_flags",
    "tcp_stream_id",
    "http_method",
    "http_status_code",
    "tls_version",
    "server_name",
    "inter_packet_interval_seconds",
    "is_encrypted",
    "protocols",
    "info",
    "source_file",
    "ip_version",
    "direction_hint",
]


def _route_exists(path: str, method: str) -> bool:
    from app.main import app

    paths = app.openapi().get("paths", {})
    return path in paths and method.lower() in paths[path]


pytestmark = pytest.mark.skipif(
    not _route_exists(UPLOAD_ROUTE, "POST"),
    reason="POST /api/analysis/upload is not implemented yet (owner: PacketCore)",
)


def upload(client, path: Path, filename: str = "capture.pcap", **data):
    with path.open("rb") as handle:
        return client.post(
            UPLOAD_ROUTE,
            files={"file": (filename, handle.read(), "application/octet-stream")},
            data=data or None,
        )


@pytest.fixture()
def three_packet_capture(tmp_path: Path):
    """A capture with exactly three frames and a known byte total."""
    frames = [
        (1_700_000_000.0, q.frame_ipv4_tcp(src_port=51000, dst_port=80, payload=q.http_request())),
        (1_700_000_000.5, q.frame_ipv4_udp(src_port=51001, dst_port=53, payload=q.dns_query())),
        (
            1_700_000_001.0,
            q.frame_ipv4_tcp(src_port=51002, dst_port=443, payload=q.tls_client_hello()),
        ),
    ]
    path = q.write_pcap_frames(tmp_path / "three.pcap", frames)
    return path, [len(frame) for _, frame in frames]


class TestUpload:
    def test_upload_returns_201_with_the_documented_body(self, client, three_packet_capture):
        path, lengths = three_packet_capture
        response = upload(client, path, "three.pcap")
        assert response.status_code == 201, response.text
        body = response.json()
        assert set(body) == {
            "analysis_id",
            "status",
            "source_file",
            "source_kind",
            "packet_count",
            "total_bytes",
            "warnings",
            "created_at",
        }
        assert body["status"] in {"complete", "partial"}
        assert body["source_kind"] == "pcap"
        assert body["source_file"] == "three.pcap"
        assert body["created_at"].endswith("Z")
        assert isinstance(body["warnings"], list)

    def test_packet_count_equals_the_number_of_frames_in_the_file(
        self, client, three_packet_capture
    ):
        path, lengths = three_packet_capture
        body = upload(client, path, "three.pcap").json()
        assert body["packet_count"] == 3 == len(lengths)
        assert body["packet_count"] > 0

    def test_total_bytes_is_the_sum_of_the_frame_lengths(self, client, three_packet_capture):
        path, lengths = three_packet_capture
        body = upload(client, path, "three.pcap").json()
        assert body["total_bytes"] == sum(lengths)
        assert body["total_bytes"] > 0

    def test_analysis_id_is_a_uuid_hex_string(self, client, three_packet_capture):
        path, _ = three_packet_capture
        body = upload(client, path, "three.pcap").json()
        analysis_id = body["analysis_id"]
        assert isinstance(analysis_id, str)
        assert len(analysis_id) == 32
        int(analysis_id, 16)

    def test_two_uploads_get_different_ids(self, client, three_packet_capture):
        path, _ = three_packet_capture
        first = upload(client, path, "a.pcap").json()["analysis_id"]
        second = upload(client, path, "b.pcap").json()["analysis_id"]
        assert first != second


class TestReadPathConsistency:
    def test_every_read_route_agrees_on_the_packet_count(self, client, three_packet_capture):
        path, lengths = three_packet_capture
        analysis_id = upload(client, path, "three.pcap").json()["analysis_id"]

        summary = client.get(f"/api/analysis/{analysis_id}/summary").json()
        packets = client.get(f"/api/analysis/{analysis_id}/packets").json()
        protocols = client.get(f"/api/analysis/{analysis_id}/protocols").json()

        assert summary["packet_count"] == 3
        assert packets["total"] == 3
        assert len(packets["items"]) == 3
        assert sum(entry["packets"] for entry in protocols["items"]) == 3

    def test_summary_total_bytes_matches_the_packet_list(self, client, three_packet_capture):
        path, lengths = three_packet_capture
        analysis_id = upload(client, path, "three.pcap").json()["analysis_id"]
        summary = client.get(f"/api/analysis/{analysis_id}/summary").json()
        packets = client.get(f"/api/analysis/{analysis_id}/packets").json()
        assert summary["total_bytes"] == sum(
            item["captured_frame_length"] for item in packets["items"]
        )
        assert summary["total_bytes"] == sum(lengths)

    def test_protocol_percentages_add_up_to_one_hundred(self, client, three_packet_capture):
        path, _ = three_packet_capture
        analysis_id = upload(client, path, "three.pcap").json()["analysis_id"]
        protocols = client.get(f"/api/analysis/{analysis_id}/protocols").json()
        total = sum(entry["percentage"] for entry in protocols["items"])
        assert total == pytest.approx(100.0, abs=0.05)

    def test_duration_matches_the_timestamps_of_the_capture(self, client, three_packet_capture):
        path, _ = three_packet_capture
        analysis_id = upload(client, path, "three.pcap").json()["analysis_id"]
        summary = client.get(f"/api/analysis/{analysis_id}/summary").json()
        packets = client.get(f"/api/analysis/{analysis_id}/packets").json()
        assert summary["duration_seconds"] == pytest.approx(1.0, abs=1e-6)
        assert summary["first_timestamp"] == packets["items"][0]["timestamp"]
        assert summary["last_timestamp"] == packets["items"][-1]["timestamp"]

    def test_csv_export_has_one_row_per_packet(self, client, three_packet_capture):
        path, _ = three_packet_capture
        analysis_id = upload(client, path, "three.pcap").json()["analysis_id"]
        response = client.get(f"/api/analysis/{analysis_id}/export/packets.csv")
        assert response.status_code == 200
        rows = response.text.strip().splitlines()
        assert len(rows) == 4  # header plus three packets
        assert rows[0].split(",")[0] == "frame_number"

    def test_summary_json_export_contains_the_summary(self, client, three_packet_capture):
        path, _ = three_packet_capture
        analysis_id = upload(client, path, "three.pcap").json()["analysis_id"]
        response = client.get(f"/api/analysis/{analysis_id}/export/summary.json")
        assert response.status_code == 200
        body = response.json()
        assert body["analysis_id"] == analysis_id
        assert body["packet_count"] == 3
        summary = client.get(f"/api/analysis/{analysis_id}/summary").json()
        for key, value in summary.items():
            assert body[key] == value

    def test_csv_export_is_a_csv_download(self, client, three_packet_capture):
        path, _ = three_packet_capture
        analysis_id = upload(client, path, "three.pcap").json()["analysis_id"]
        response = client.get(f"/api/analysis/{analysis_id}/export/packets.csv")
        assert response.headers["content-type"].startswith("text/csv")
        assert "attachment" in response.headers.get("content-disposition", "")
        assert f"packets-{analysis_id}.csv" in response.headers.get("content-disposition", "")


class TestCsvExportShape:
    def test_column_order_follows_the_schema(self, client, three_packet_capture):
        path, _ = three_packet_capture
        analysis_id = upload(client, path, "three.pcap").json()["analysis_id"]
        response = client.get(f"/api/analysis/{analysis_id}/export/packets.csv")
        header = response.text.splitlines()[0].split(",")
        assert header[: len(SCHEMA_COLUMN_ORDER)] == SCHEMA_COLUMN_ORDER

    def test_every_column_is_a_known_model_field(self, client, three_packet_capture):
        from app.models.packet import NormalizedPacket

        path, _ = three_packet_capture
        analysis_id = upload(client, path, "three.pcap").json()["analysis_id"]
        response = client.get(f"/api/analysis/{analysis_id}/export/packets.csv")
        header = response.text.splitlines()[0].split(",")
        known = set(NormalizedPacket.model_fields)
        unknown = [column for column in header if column not in known]
        assert not unknown, f"the export invents columns: {unknown}"

    def test_null_values_are_written_as_empty_cells(self, client, tmp_path):
        frames = [
            (1_700_000_000.0, q.frame_arp()),
        ]
        path = q.write_pcap_frames(tmp_path / "arp.pcap", frames)
        analysis_id = upload(client, path, "arp.pcap").json()["analysis_id"]
        response = client.get(f"/api/analysis/{analysis_id}/export/packets.csv")
        rows = response.text.strip().splitlines()
        assert len(rows) == 2
        row = rows[1].split(",")
        header = rows[0].split(",")
        assert row[header.index("source_ip")] == ""
        assert row[header.index("destination_ip")] == ""
        assert row[header.index("ip_packet_length")] == ""
        assert "None" not in response.text
        assert "null" not in response.text.lower()


class TestEmptyCapture:
    def test_empty_capture_is_accepted(self, client, empty_pcap):
        response = upload(client, empty_pcap, "empty.pcap")
        assert response.status_code == 201, response.text
        body = response.json()
        assert body["packet_count"] == 0
        assert body["total_bytes"] == 0
        assert body["status"] == "complete"

    def test_empty_capture_endpoints_answer_with_empty_lists(self, client, empty_pcap):
        analysis_id = upload(client, empty_pcap, "empty.pcap").json()["analysis_id"]
        summary = client.get(f"/api/analysis/{analysis_id}/summary")
        packets = client.get(f"/api/analysis/{analysis_id}/packets")
        protocols = client.get(f"/api/analysis/{analysis_id}/protocols")
        hosts = client.get(f"/api/analysis/{analysis_id}/hosts")
        for response in (summary, packets, protocols, hosts):
            assert response.status_code == 200, response.text
        assert summary.json()["packet_count"] == 0
        assert summary.json()["total_bytes"] == 0
        assert summary.json()["duration_seconds"] == 0
        assert packets.json()["items"] == []
        assert packets.json()["total"] == 0
        assert protocols.json()["items"] == []
        assert hosts.json()["items"] == []

    def test_empty_capture_csv_export_has_only_a_header(self, client, empty_pcap):
        analysis_id = upload(client, empty_pcap, "empty.pcap").json()["analysis_id"]
        response = client.get(f"/api/analysis/{analysis_id}/export/packets.csv")
        assert response.status_code == 200
        lines = response.text.strip().splitlines()
        assert len(lines) == 1
        assert lines[0].startswith("frame_number")


class TestCsvUpload:
    def test_csv_upload_counts_its_rows(self, client, sample_csv):
        response = upload(client, sample_csv, "sample.csv")
        assert response.status_code == 201, response.text
        body = response.json()
        assert body["packet_count"] == 2
        assert body["source_kind"] == "csv"
        assert body["total_bytes"] > 0

    def test_csv_upload_is_readable_through_the_api(self, client, sample_csv):
        analysis_id = upload(client, sample_csv, "sample.csv").json()["analysis_id"]
        packets = client.get(f"/api/analysis/{analysis_id}/packets").json()
        assert packets["total"] == 2
        assert packets["items"][0]["frame_number"] == 1
        assert packets["items"][0]["source_ip"] == "10.0.0.1"
        assert packets["items"][0]["source_port"] == 51000
        assert packets["items"][0]["captured_frame_length"] == 74


class TestUnknownAnalysis:
    @pytest.mark.parametrize(
        "route",
        [
            "/summary",
            "/packets",
            "/protocols",
            "/hosts",
            "/export/packets.csv",
            "/export/summary.json",
        ],
    )
    def test_unknown_analysis_id_returns_404_with_the_envelope(self, client, route):
        response = client.get(f"/api/analysis/does-not-exist{route}")
        assert response.status_code == 404, response.text
        body = response.json()
        assert set(body) == {"error"}
        assert set(body["error"]) == {"code", "message", "detail"}
        assert body["error"]["code"] == "not_found"
        assert isinstance(body["error"]["detail"], dict)


class TestPaginationAndFilters:
    def test_limit_keeps_the_total_and_returns_one_item(self, client, three_packet_capture):
        path, _ = three_packet_capture
        analysis_id = upload(client, path, "three.pcap").json()["analysis_id"]
        page = client.get(
            f"/api/analysis/{analysis_id}/packets", params={"limit": 1}
        ).json()
        assert page["total"] == 3
        assert page["limit"] == 1
        assert page["offset"] == 0
        assert len(page["items"]) == 1

    def test_offset_walks_through_the_pages(self, client, three_packet_capture):
        path, _ = three_packet_capture
        analysis_id = upload(client, path, "three.pcap").json()["analysis_id"]
        first = client.get(
            f"/api/analysis/{analysis_id}/packets", params={"limit": 2, "offset": 0}
        ).json()
        second = client.get(
            f"/api/analysis/{analysis_id}/packets", params={"limit": 2, "offset": 2}
        ).json()
        assert [item["frame_number"] for item in first["items"]] == [1, 2]
        assert [item["frame_number"] for item in second["items"]] == [3]
        assert first["total"] == second["total"] == 3

    def test_filter_by_application_protocol_returns_only_matches(
        self, client, three_packet_capture
    ):
        path, _ = three_packet_capture
        analysis_id = upload(client, path, "three.pcap").json()["analysis_id"]
        page = client.get(
            f"/api/analysis/{analysis_id}/packets", params={"protocol": "HTTP"}
        ).json()
        assert page["total"] == 1
        assert len(page["items"]) == 1
        assert page["items"][0]["application_protocol"] == "HTTP"

    def test_filter_by_transport_protocol(self, client, three_packet_capture):
        path, _ = three_packet_capture
        analysis_id = upload(client, path, "three.pcap").json()["analysis_id"]
        page = client.get(
            f"/api/analysis/{analysis_id}/packets", params={"transport": "UDP"}
        ).json()
        assert page["total"] == 1
        assert page["items"][0]["transport_protocol"] == "UDP"

    def test_filter_by_source_ip_and_port(self, client, three_packet_capture):
        path, _ = three_packet_capture
        analysis_id = upload(client, path, "three.pcap").json()["analysis_id"]
        page = client.get(
            f"/api/analysis/{analysis_id}/packets",
            params={"src_ip": "10.0.0.1", "src_port": 51000},
        ).json()
        assert page["total"] == 1
        assert page["items"][0]["source_port"] == 51000

    def test_filter_by_byte_range(self, client, three_packet_capture):
        path, lengths = three_packet_capture
        analysis_id = upload(client, path, "three.pcap").json()["analysis_id"]
        page = client.get(
            f"/api/analysis/{analysis_id}/packets",
            params={"min_bytes": min(lengths), "max_bytes": max(lengths)},
        ).json()
        assert page["total"] == 3

    def test_filter_that_matches_nothing_returns_an_empty_page(self, client, three_packet_capture):
        path, _ = three_packet_capture
        analysis_id = upload(client, path, "three.pcap").json()["analysis_id"]
        page = client.get(
            f"/api/analysis/{analysis_id}/packets", params={"protocol": "NOPE"}
        ).json()
        assert page["total"] == 0
        assert page["items"] == []

    def test_ordering_by_frame_length(self, client, three_packet_capture):
        path, lengths = three_packet_capture
        analysis_id = upload(client, path, "three.pcap").json()["analysis_id"]
        page = client.get(
            f"/api/analysis/{analysis_id}/packets",
            params={"order_by": "captured_frame_length", "order_dir": "desc"},
        ).json()
        sizes = [item["captured_frame_length"] for item in page["items"]]
        assert sizes == sorted(sizes, reverse=True)
