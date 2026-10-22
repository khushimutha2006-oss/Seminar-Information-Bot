"""Tests for the pure-python capture reader.

Covers both container formats, both endiannesses, both timestamp resolutions,
truncated frames and corrupt files. No TShark, no root, no network.
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from app.services.pcap_reader import PcapReaderError, RawFrame, read_capture

from tests import support


def _write_pcap_with_magic(path: Path, frames: list[bytes], magic: int, endian: str = "<") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as handle:
        handle.write(struct.pack(f"{endian}IHHiIII", magic, 2, 4, 0, 0, 262144, 1))
        for index, frame in enumerate(frames):
            handle.write(
                struct.pack(
                    f"{endian}IIII",
                    int(support.struct.unpack("!I", frame[:4])[0]) if False else 1_700_000_000 + index,
                    0,
                    len(frame),
                    len(frame),
                )
            )
            handle.write(frame)
    return path


class TestClassicPcap:
    def test_reads_little_endian_microsecond_capture(self, tmp_path: Path):
        path = support.write_pcap(tmp_path / "le.pcap", [support.build_frame()])
        frames = read_capture(path)
        assert len(frames) == 1
        frame = frames[0]
        assert isinstance(frame, RawFrame)
        assert frame.frame_number == 1
        assert frame.link_type == 1
        assert frame.captured_length == frame.original_length > 0
        assert frame.timestamp_epoch == pytest.approx(1_700_000_000.0)

    def test_reads_big_endian_capture(self, tmp_path: Path):
        frame_bytes = support.build_frame()
        path = tmp_path / "be.pcap"
        with path.open("wb") as handle:
            handle.write(struct.pack(">IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1))
            handle.write(struct.pack(">IIII", 1_700_000_000, 0, len(frame_bytes), len(frame_bytes)))
            handle.write(frame_bytes)
        frames = read_capture(path)
        assert len(frames) == 1
        assert frames[0].timestamp_epoch == pytest.approx(1_700_000_000.0)

    def test_reads_nanosecond_resolution_capture(self, tmp_path: Path):
        frame_bytes = support.build_frame()
        path = tmp_path / "ns.pcap"
        with path.open("wb") as handle:
            handle.write(struct.pack("<IHHiIII", 0xA1B23C4D, 2, 4, 0, 0, 262144, 1))
            handle.write(struct.pack("<IIII", 1_700_000_000, 500_000_000, len(frame_bytes), len(frame_bytes)))
            handle.write(frame_bytes)
        frames = read_capture(path)
        assert frames[0].timestamp_epoch == pytest.approx(1_700_000_000.5)

    def test_empty_capture_is_valid(self, empty_pcap: Path):
        assert read_capture(empty_pcap) == []

    def test_truncated_frame_is_reported_not_raised(self, tmp_path: Path):
        frame_bytes = support.build_frame()
        path = tmp_path / "truncated.pcap"
        with path.open("wb") as handle:
            handle.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1))
            handle.write(struct.pack("<IIII", 1_700_000_000, 0, len(frame_bytes) - 10, len(frame_bytes)))
            handle.write(frame_bytes[: len(frame_bytes) - 10])
        frames = read_capture(path)
        assert len(frames) == 1
        assert frames[0].original_length > frames[0].captured_length

    def test_corrupt_file_raises_typed_error(self, tmp_path: Path):
        path = tmp_path / "corrupt.pcap"
        path.write_bytes(b"\x00\x01\x02\x03not a capture at all")
        with pytest.raises(PcapReaderError):
            read_capture(path)

    def test_missing_file_raises_file_not_found(self, tmp_path: Path):
        with pytest.raises(FileNotFoundError):
            read_capture(tmp_path / "missing.pcap")


class TestPcapng:
    def _write_minimal_pcapng(self, path: Path, payloads: list[bytes]) -> Path:
        """Write a pcapng file with one interface and one Enhanced Packet Block per frame."""
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("wb") as handle:
            # Section Header Block
            handle.write(struct.pack("<III", 0x0A0D0D0A, 28, 0x1A2B3C4D))
            handle.write(struct.pack("<HHq", 1, 0, -1))
            handle.write(struct.pack("<I", 28))
            # Interface Description Block (link type 1 = Ethernet)
            handle.write(struct.pack("<II", 0x00000001, 20))
            handle.write(struct.pack("<HHI", 1, 0, 262144))
            handle.write(struct.pack("<I", 20))
            for index, payload in enumerate(payloads):
                # Enhanced Packet Block: the packet data is padded to a 4 byte boundary
                # and the block length counts the header, the data and the trailer.
                padded = payload + b"\x00" * ((4 - len(payload) % 4) % 4)
                body = struct.pack("<IIIII", 0, 0, 0, len(payload), len(payload)) + padded
                total_length = 8 + len(body) + 4
                handle.write(struct.pack("<II", 0x00000006, total_length))
                handle.write(body)
                handle.write(struct.pack("<I", total_length))
        return path

    def test_reads_enhanced_packet_blocks(self, tmp_path: Path):
        path = self._write_minimal_pcapng(tmp_path / "sample.pcapng", [support.build_frame()])
        frames = read_capture(path)
        assert len(frames) == 1
        assert frames[0].link_type == 1
        assert frames[0].captured_length > 0

    def test_pcapng_with_no_packets_is_valid(self, tmp_path: Path):
        path = self._write_minimal_pcapng(tmp_path / "empty.pcapng", [])
        assert read_capture(path) == []
