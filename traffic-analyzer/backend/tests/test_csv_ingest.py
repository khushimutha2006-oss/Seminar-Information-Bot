"""Tests for CSV ingestion."""

from __future__ import annotations

from pathlib import Path

import pytest

from app.services.csv_ingest import load_csv


HEADER = (
    "frame_number,timestamp,source_ip,destination_ip,source_port,destination_port,"
    "transport_protocol,application_protocol,captured_frame_length,ip_packet_length"
)


def write_csv(path: Path, *rows: str) -> Path:
    path.write_text("\n".join([HEADER, *rows]) + "\n", encoding="utf-8")
    return path


class TestLoadCsv:
    def test_reads_a_valid_capture(self, tmp_path: Path):
        path = write_csv(
            tmp_path / "capture.csv",
            "1,2026-10-21T18:00:00.000000Z,10.0.0.1,10.0.0.2,51000,80,TCP,HTTP,74,60",
            "2,2026-10-21T18:00:00.010000Z,10.0.0.2,10.0.0.1,80,51000,TCP,HTTP,120,60",
        )
        packets, warnings = load_csv(path)
        assert len(packets) == 2
        assert packets[0].frame_number == 1
        assert packets[0].source_ip == "10.0.0.1"
        assert packets[0].application_protocol == "HTTP"
        assert packets[0].captured_frame_length == 74
        assert packets[0].timestamp == "2026-10-21T18:00:00.000000Z"
        assert packets[0].timestamp_epoch == pytest.approx(1792605600.0)

    def test_empty_optional_columns_become_none(self, tmp_path: Path):
        path = write_csv(tmp_path / "capture.csv", "1,2026-10-21T18:00:00.000000Z,,,,,TCP,TCP,74,")
        packets, _ = load_csv(path)
        assert packets[0].source_ip is None
        assert packets[0].source_port is None
        assert packets[0].ip_packet_length is None

    def test_unparsable_numbers_are_ignored(self, tmp_path: Path):
        path = write_csv(tmp_path / "capture.csv", "1,2026-10-21T18:00:00.000000Z,10.0.0.1,,abc,80,TCP,TCP,74,x")
        packets, _ = load_csv(path)
        assert packets[0].source_port is None
        assert packets[0].ip_packet_length is None

    def test_row_with_an_unusable_frame_number_is_skipped_with_a_warning(self, tmp_path: Path):
        path = write_csv(
            tmp_path / "capture.csv",
            "not-a-number,2026-10-21T18:00:00.000000Z,10.0.0.1,10.0.0.2,1,2,TCP,TCP,74,60",
        )
        packets, warnings = load_csv(path)
        assert packets == []
        assert warnings

    def test_header_only_file_is_not_an_error(self, tmp_path: Path):
        path = write_csv(tmp_path / "capture.csv")
        packets, warnings = load_csv(path)
        assert packets == []
        assert warnings

    def test_unknown_columns_are_ignored(self, tmp_path: Path):
        path = tmp_path / "capture.csv"
        path.write_text(
            HEADER + ",extra_column\n"
            "1,2026-10-21T18:00:00.000000Z,10.0.0.1,10.0.0.2,51000,80,TCP,HTTP,74,60,ignore me\n",
            encoding="utf-8",
        )
        packets, _ = load_csv(path)
        assert len(packets) == 1

    def test_missing_file_raises(self, tmp_path: Path):
        with pytest.raises(FileNotFoundError):
            load_csv(tmp_path / "missing.csv")
