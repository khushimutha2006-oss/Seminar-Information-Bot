"""Shared test helpers.

Owned by the lead (integration). Provides a dependency-free classic-pcap writer so the
test suite never needs TShark, root privileges or a live network.
"""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Iterable, Optional

PCAP_MAGIC_LE = 0xA1B2C3D4
LINKTYPE_ETHERNET = 1


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for index in range(0, len(data), 2):
        total += (data[index] << 8) + data[index + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def ethernet_frame(
    src_mac: bytes = b"\x02\x00\x00\x00\x00\x01",
    dst_mac: bytes = b"\x02\x00\x00\x00\x00\x02",
    ethertype: int = 0x0800,
    payload: bytes = b"",
) -> bytes:
    return dst_mac + src_mac + struct.pack("!H", ethertype) + payload


def ipv4_header(
    src_ip: str = "10.0.0.1",
    dst_ip: str = "10.0.0.2",
    protocol: int = 6,
    payload_length: int = 0,
    ident: int = 1,
) -> bytes:
    src = bytes(int(part) for part in src_ip.split("."))
    dst = bytes(int(part) for part in dst_ip.split("."))
    total_length = 20 + payload_length
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_length,
        ident,
        0x4000,
        64,
        protocol,
        0,
        src,
        dst,
    )
    checksum = _checksum(header)
    header = header[:10] + struct.pack("!H", checksum) + header[12:]
    return header


def tcp_segment(
    src_port: int = 1234,
    dst_port: int = 80,
    seq: int = 1,
    ack: int = 1,
    flags: int = 0x18,
    payload: bytes = b"",
) -> bytes:
    offset_flags = (5 << 12) | flags
    return struct.pack(
        "!HHIIHHHH",
        src_port,
        dst_port,
        seq,
        ack,
        offset_flags,
        65535,
        0,
        0,
    ) + payload


def udp_datagram(src_port: int = 5353, dst_port: int = 53, payload: bytes = b"") -> bytes:
    length = 8 + len(payload)
    return struct.pack("!HHHH", src_port, dst_port, length, 0) + payload


def build_frame(
    src_ip: str = "10.0.0.1",
    dst_ip: str = "10.0.0.2",
    src_port: int = 1234,
    dst_port: int = 80,
    payload: bytes = b"",
    protocol: int = 6,
    ethertype: int = 0x0800,
) -> bytes:
    """Build one Ethernet frame carrying IPv4 + TCP/UDP."""
    if protocol == 6:
        transport = tcp_segment(src_port, dst_port, payload=payload)
    else:
        transport = udp_datagram(src_port, dst_port, payload)
    ip = ipv4_header(src_ip, dst_ip, protocol, len(transport), ident=len(payload) + 1)
    return ethernet_frame(ethertype=ethertype, payload=ip + transport)


def write_pcap(path: Path, frames: Iterable[bytes], start_epoch: float = 1_700_000_000.0) -> Path:
    """Write frames into a classic little-endian pcap file."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as handle:
        handle.write(struct.pack("<IHHiIII", PCAP_MAGIC_LE, 2, 4, 0, 0, 262144, LINKTYPE_ETHERNET))
        for index, frame in enumerate(frames):
            seconds = int(start_epoch) + index // 1000
            microseconds = (index % 1000) * 1000
            handle.write(struct.pack("<IIII", seconds, microseconds, len(frame), len(frame)))
            handle.write(frame)
    return path


def sample_http_capture(path: Path) -> Path:
    """A tiny capture with a plaintext HTTP request/response and a DNS query."""
    request = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
    response = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
    dns_query = bytes.fromhex("abcd0100000100000000000003777777076578616d706c6503636f6d0000010001")
    frames = [
        build_frame(src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=51000, dst_port=80, payload=request),
        build_frame(src_ip="10.0.0.2", dst_ip="10.0.0.1", src_port=80, dst_port=51000, payload=response),
        build_frame(src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=51001, dst_port=53, payload=dns_query, protocol=17),
    ]
    return write_pcap(path, frames)


def sample_empty_capture(path: Path) -> Path:
    return write_pcap(path, [])


def write_csv_capture(path: Path) -> Path:
    """A CSV export shaped like the analyzer's own CSV output."""
    rows = [
        "frame_number,timestamp,source_ip,destination_ip,source_port,destination_port,"
        "transport_protocol,application_protocol,captured_frame_length,ip_packet_length",
        "1,2026-10-21T18:00:00.000000Z,10.0.0.1,10.0.0.2,51000,80,TCP,HTTP,74,60",
        "2,2026-10-21T18:00:00.010000Z,10.0.0.2,10.0.0.1,80,51000,TCP,HTTP,120,60",
    ]
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(rows) + "\n", encoding="utf-8")
    return path


def find_capture_fixture() -> Optional[Path]:
    """Return a real pcap shipped with the repository, when one exists."""
    candidates = [
        Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "sample.pcap",
        Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "sample.pcapng",
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None
