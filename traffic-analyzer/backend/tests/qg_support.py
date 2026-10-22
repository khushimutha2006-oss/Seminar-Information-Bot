"""Fixture builders for the QualityGuard test suite.

OWNER: QualityGuard.

Extends the lead-owned helpers in `tests.support` with the frame types the
contract talks about but the shared helper does not build: IPv6, ICMP, ARP,
TLS records, QUIC long headers and DNS messages, plus a pcap writer that takes
explicit per-frame timestamps so that inter-packet intervals and capture
duration can be hand-computed.

Every builder produces a frame whose on-the-wire length is exactly
`len(frame)`, so a test can assert byte totals by adding up the lengths of the
frames it built.
"""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Iterable, Optional, Sequence

import pytest

from tests.support import LINKTYPE_ETHERNET, PCAP_MAGIC_LE

ETH_HEADER_LEN = 14
IPV4_HEADER_LEN = 20
IPV6_HEADER_LEN = 40
TCP_HEADER_LEN = 20
UDP_HEADER_LEN = 8
ARP_PAYLOAD_LEN = 28

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_ARP = 0x0806
ETHERTYPE_IPV6 = 0x86DD

IPPROTO_ICMP = 1
IPPROTO_TCP = 6
IPPROTO_UDP = 17
IPPROTO_ICMPV6 = 58

TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_ACK = 0x10


def ones_complement_checksum(data: bytes) -> int:
    """RFC 1071 internet checksum over `data`."""
    if len(data) % 2:
        data = data + b"\x00"
    total = 0
    for index in range(0, len(data), 2):
        total += (data[index] << 8) + data[index + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def ethernet_header(ethertype: int, payload_len: int) -> bytes:
    """Ethernet II header with a deterministic MAC pair."""
    return b"\x02\x00\x00\x00\x00\x02" + b"\x02\x00\x00\x00\x00\x01" + struct.pack("!H", ethertype)


def ipv4_header(
    src_ip: str = "10.0.0.1",
    dst_ip: str = "10.0.0.2",
    protocol: int = IPPROTO_TCP,
    payload_len: int = 0,
    ident: int = 1,
    ttl: int = 64,
) -> bytes:
    """IPv4 header with a valid header checksum and a correct total length."""
    src = bytes(int(part) for part in src_ip.split("."))
    dst = bytes(int(part) for part in dst_ip.split("."))
    total_length = IPV4_HEADER_LEN + payload_len
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_length,
        ident & 0xFFFF,
        0x4000,
        ttl,
        protocol,
        0,
        src,
        dst,
    )
    checksum = ones_complement_checksum(header)
    return header[:10] + struct.pack("!H", checksum) + header[12:]


def ipv6_header(
    src_ip: str = "2001:db8::1",
    dst_ip: str = "2001:db8::2",
    protocol: int = IPPROTO_TCP,
    payload_len: int = 0,
    hop_limit: int = 64,
) -> bytes:
    """IPv6 header. The payload length field excludes the 40 byte header."""
    src = _ipv6_bytes(src_ip)
    dst = _ipv6_bytes(dst_ip)
    return (
        struct.pack("!IHBB", 0x60000000, payload_len, protocol, hop_limit)
        + src
        + dst
    )


def _ipv6_bytes(address: str) -> bytes:
    import ipaddress

    return ipaddress.IPv6Address(address).packed


def tcp_segment(
    src_port: int = 51000,
    dst_port: int = 80,
    seq: int = 1,
    ack: int = 1,
    flags: int = TCP_PSH | TCP_ACK,
    payload: bytes = b"",
    window: int = 65535,
) -> bytes:
    """TCP header (data offset 5, no options) followed by the payload."""
    offset_flags = (5 << 12) | flags
    return (
        struct.pack("!HHIIHHHH", src_port, dst_port, seq, ack, offset_flags, window, 0, 0)
        + payload
    )


def udp_datagram(src_port: int = 51000, dst_port: int = 53, payload: bytes = b"") -> bytes:
    length = UDP_HEADER_LEN + len(payload)
    return struct.pack("!HHHH", src_port, dst_port, length, 0) + payload


def icmp_echo(identifier: int = 1, sequence: int = 1, payload: bytes = b"") -> bytes:
    body = struct.pack("!BBHHH", 8, 0, 0, identifier, sequence) + payload
    checksum = ones_complement_checksum(body)
    return body[:2] + struct.pack("!H", checksum) + body[4:]


def arp_payload(sender_ip: str = "10.0.0.1", target_ip: str = "10.0.0.2") -> bytes:
    return (
        struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1)
        + b"\x02\x00\x00\x00\x00\x01"
        + bytes(int(part) for part in sender_ip.split("."))
        + b"\x00\x00\x00\x00\x00\x00"
        + bytes(int(part) for part in target_ip.split("."))
    )


def frame_ipv4_tcp(
    src_ip: str = "10.0.0.1",
    dst_ip: str = "10.0.0.2",
    src_port: int = 51000,
    dst_port: int = 80,
    payload: bytes = b"",
    flags: int = TCP_PSH | TCP_ACK,
    ident: int = 1,
) -> bytes:
    segment = tcp_segment(src_port, dst_port, flags=flags, payload=payload)
    ip = ipv4_header(src_ip, dst_ip, IPPROTO_TCP, len(segment), ident=ident)
    return ethernet_header(ETHERTYPE_IPV4, len(ip) + len(segment)) + ip + segment


def frame_ipv4_udp(
    src_ip: str = "10.0.0.1",
    dst_ip: str = "10.0.0.2",
    src_port: int = 51000,
    dst_port: int = 53,
    payload: bytes = b"",
    ident: int = 1,
) -> bytes:
    datagram = udp_datagram(src_port, dst_port, payload)
    ip = ipv4_header(src_ip, dst_ip, IPPROTO_UDP, len(datagram), ident=ident)
    return ethernet_header(ETHERTYPE_IPV4, len(ip) + len(datagram)) + ip + datagram


def frame_ipv6_tcp(
    src_ip: str = "2001:db8::1",
    dst_ip: str = "2001:db8::2",
    src_port: int = 51000,
    dst_port: int = 80,
    payload: bytes = b"",
    flags: int = TCP_PSH | TCP_ACK,
) -> bytes:
    segment = tcp_segment(src_port, dst_port, flags=flags, payload=payload)
    ip = ipv6_header(src_ip, dst_ip, IPPROTO_TCP, len(segment))
    return ethernet_header(ETHERTYPE_IPV6, len(ip) + len(segment)) + ip + segment


def frame_ipv6_udp(
    src_ip: str = "2001:db8::1",
    dst_ip: str = "2001:db8::2",
    src_port: int = 51000,
    dst_port: int = 53,
    payload: bytes = b"",
) -> bytes:
    datagram = udp_datagram(src_port, dst_port, payload)
    ip = ipv6_header(src_ip, dst_ip, IPPROTO_UDP, len(datagram))
    return ethernet_header(ETHERTYPE_IPV6, len(ip) + len(datagram)) + ip + datagram


def frame_ipv4_icmp(
    src_ip: str = "10.0.0.1",
    dst_ip: str = "10.0.0.2",
    payload: bytes = b"",
    ident: int = 1,
) -> bytes:
    message = icmp_echo(payload=payload)
    ip = ipv4_header(src_ip, dst_ip, IPPROTO_ICMP, len(message), ident=ident)
    return ethernet_header(ETHERTYPE_IPV4, len(ip) + len(message)) + ip + message


def frame_arp(
    sender_ip: str = "10.0.0.1",
    target_ip: str = "10.0.0.2",
) -> bytes:
    payload = arp_payload(sender_ip, target_ip)
    return ethernet_header(ETHERTYPE_ARP, len(payload)) + payload


def tls_client_hello(server_name: str = "example.com") -> bytes:
    """A TLS 1.2 ClientHello record carrying an SNI extension.

    Layout: record header (type 0x16, version 0x0303, length), handshake
    header (type 0x01 client_hello, 3 byte length), client_version, random,
    session id, cipher suites, compression, extensions with SNI.
    """
    host = server_name.encode("ascii")
    sni_entry = b"\x00" + struct.pack("!H", len(host)) + host
    sni_list = struct.pack("!H", len(sni_entry)) + sni_entry
    sni_extension = struct.pack("!HH", 0x0000, len(sni_list)) + sni_list
    extensions = sni_extension
    body = (
        b"\x03\x03"
        + bytes(range(32))
        + b"\x00"
        + struct.pack("!H", 2)
        + b"\x00\x2f"
        + b"\x01\x00"
        + struct.pack("!H", len(extensions))
        + extensions
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x03" + struct.pack("!H", len(handshake)) + handshake


def tls_application_data(payload_len: int = 64) -> bytes:
    """An encrypted TLS record (type 0x17). The body is opaque ciphertext."""
    body = bytes((index * 7 + 3) % 256 for index in range(payload_len))
    return b"\x17\x03\x03" + struct.pack("!H", len(body)) + body


def quic_initial(version: int = 1, dcid: bytes = b"\x0a\x0b\x0c\x0d", payload_len: int = 32) -> bytes:
    """A QUIC long header Initial packet (version 1) with protected payload."""
    header = b"\xc3" + struct.pack("!I", version) + bytes([len(dcid)]) + dcid
    length = struct.pack("!H", 4 + payload_len)
    body = b"\x01\x08\x00" + bytes(payload_len)
    return header + length + body


def dns_query(name: str = "example.com", transaction_id: int = 0xABCD) -> bytes:
    labels = b"".join(bytes([len(label)]) + label.encode("ascii") for label in name.split("."))
    return (
        struct.pack("!HHHHHH", transaction_id, 0x0100, 1, 0, 0, 0)
        + labels
        + b"\x00"
        + struct.pack("!HH", 1, 1)
    )


def dns_response(name: str = "example.com", transaction_id: int = 0xABCD) -> bytes:
    labels = b"".join(bytes([len(label)]) + label.encode("ascii") for label in name.split("."))
    answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + bytes([93, 184, 216, 34])
    return (
        struct.pack("!HHHHHH", transaction_id, 0x8180, 1, 1, 0, 0)
        + labels
        + b"\x00"
        + struct.pack("!HH", 1, 1)
        + answer
    )


def http_request(method: str = "GET", path: str = "/index.html", host: str = "example.com") -> bytes:
    return (
        f"{method} {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: qg-test\r\n\r\n"
    ).encode("ascii")


def http_response(status: int = 200, reason: str = "OK") -> bytes:
    return (
        f"HTTP/1.1 {status} {reason}\r\nContent-Type: text/html\r\nContent-Length: 0\r\n\r\n"
    ).encode("ascii")


def write_pcap_frames(
    path: Path,
    frames: Sequence[tuple[float, bytes]],
    linktype: int = LINKTYPE_ETHERNET,
    magic: int = PCAP_MAGIC_LE,
    endianness: str = "<",
    snaplen: int = 262144,
) -> Path:
    """Write (epoch_seconds, frame) pairs into a classic pcap file.

    Timestamps are microsecond precision; the microsecond field carries the
    remainder so that `timestamp_epoch` round-trips to within 1 microsecond.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as handle:
        handle.write(
            struct.pack(
                f"{endianness}IHHiIII",
                magic,
                2,
                4,
                0,
                0,
                snaplen,
                linktype,
            )
        )
        for epoch, frame in frames:
            seconds = int(epoch)
            microseconds = int(round((epoch - seconds) * 1_000_000))
            if microseconds >= 1_000_000:
                seconds += 1
                microseconds -= 1_000_000
            handle.write(
                struct.pack(
                    f"{endianness}IIII",
                    seconds,
                    microseconds,
                    len(frame),
                    len(frame),
                )
            )
            handle.write(frame)
    return path


def write_truncated_pcap(path: Path, complete_frames: int = 1, cut_bytes: int = 20) -> Path:
    """A pcap whose last record is cut off in the middle of the frame data."""
    frames = [
        frame_ipv4_tcp(payload=http_request()),
        frame_ipv4_udp(payload=dns_query()),
    ]
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as handle:
        handle.write(
            struct.pack("<IHHiIII", PCAP_MAGIC_LE, 2, 4, 0, 0, 262144, LINKTYPE_ETHERNET)
        )
        for index, frame in enumerate(frames):
            handle.write(
                struct.pack("<IIII", 1_700_000_000 + index, 0, len(frame), len(frame))
            )
            if index < complete_frames:
                handle.write(frame)
            else:
                handle.write(frame[:cut_bytes])
    return path


def write_garbage_file(path: Path, size: int = 512) -> Path:
    """A file that is not a capture at all."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(bytes((index * 31 + 7) % 256 for index in range(size)))
    return path


def write_pcapng(path: Path, frames: Sequence[tuple[float, bytes]]) -> Path:
    """Write a minimal pcapng file with one interface and one enhanced packet block."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as handle:
        handle.write(struct.pack("<III", 0x0A0D0D0A, 28, 0x1A2B3C4D))
        handle.write(struct.pack("<HHq", 1, 0, 262144))
        handle.write(struct.pack("<I", 28))
        handle.write(struct.pack("<I", 28))
        for epoch, frame in frames:
            padded = frame + b"\x00" * ((-len(frame)) % 4)
            options_len = 20
            block_len = 32 + len(padded)
            handle.write(struct.pack("<II", 6, block_len))
            handle.write(struct.pack("<II", 0, epoch))
            handle.write(
                struct.pack("<II", len(frame), len(frame))
            )
            handle.write(padded)
            handle.write(struct.pack("<HH", 0, 0))
            handle.write(struct.pack("<I", 0x00000001))
            handle.write(struct.pack("<I", block_len))
    return path


def write_csv_rows(path: Path, header: Iterable[str], rows: Iterable[Iterable[str]]) -> Path:
    """Write a CSV file with a header row and the given data rows."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [",".join(header)]
    for row in rows:
        lines.append(",".join("" if cell is None else str(cell) for cell in row))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


CSV_HEADER = (
    "frame_number",
    "timestamp",
    "source_ip",
    "destination_ip",
    "source_port",
    "destination_port",
    "transport_protocol",
    "application_protocol",
    "captured_frame_length",
    "ip_packet_length",
)


def expected_frame_length(ip_version: int, transport: str, payload_len: int = 0) -> int:
    """Hand-computed on-the-wire length of a frame, link header included."""
    link = ETH_HEADER_LEN
    if ip_version == 4:
        network = IPV4_HEADER_LEN
    else:
        network = IPV6_HEADER_LEN
    if transport == "TCP":
        transport_len = TCP_HEADER_LEN
    elif transport == "UDP":
        transport_len = UDP_HEADER_LEN
    elif transport == "ARP":
        return link + ARP_PAYLOAD_LEN
    else:
        transport_len = 0
    return link + network + transport_len + payload_len


def find_free_port() -> int:
    """An unused local TCP port, used by the socket-level security checks."""
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def optional_path(candidate: Path) -> Optional[Path]:
    """Return `candidate` when it exists, otherwise None."""
    candidate = Path(candidate)
    return candidate if candidate.exists() else None


def isolate_storage(tmp_path: Path, monkeypatch) -> Path:
    """Point every module that caches a data directory at a temporary folder.

    `app.services.store` binds `ANALYSES_DIR` at import time, so patching
    `app.config` alone leaves the store writing into the real `backend/data`
    tree. Both bindings are redirected here.
    """
    from app import config
    from app.services import store as store_module

    data_dir = tmp_path / "qg-data"
    directories = {
        "DATA_DIR": data_dir,
        "ANALYSES_DIR": data_dir / "analyses",
        "CAPTURES_DIR": data_dir / "captures",
        "UPLOADS_DIR": data_dir / "uploads",
    }
    for name, value in directories.items():
        monkeypatch.setattr(config, name, value)
        if hasattr(store_module, name):
            monkeypatch.setattr(store_module, name, value)
    config.ensure_directories()
    store_module.store._analyses.clear()
    return data_dir


def disable_tshark(monkeypatch) -> None:
    """Make the host look like a machine without TShark.

    The pure-python reader is the deterministic path, so tests that assert
    hand-computed values must not depend on the TShark dissector.
    """
    from app import config

    monkeypatch.setattr(config, "TSHARK_PATH", None)
    monkeypatch.setattr(config, "DUMPCAP_PATH", None)
    monkeypatch.setattr(config, "shutil", _NoShutil())


class _NoShutil:
    """Stand-in for the `shutil` module that never finds a capture tool."""

    @staticmethod
    def which(_name: str) -> None:
        return None

    def __getattr__(self, item):
        raise AttributeError(item)


@pytest.fixture(autouse=True)
def qg_isolated_storage(tmp_path: Path, monkeypatch):
    """Keep every test in this module from writing into the repository.

    `app.services.store` binds `ANALYSES_DIR` at import time, so patching
    `app.config` alone leaves the store writing into the real `backend/data`
    tree. This fixture redirects both bindings for the duration of the test.
    """
    isolate_storage(tmp_path, monkeypatch)
    yield


@pytest.fixture()
def qg_client(tmp_path: Path, monkeypatch):
    """A TestClient whose storage is fully isolated in a temporary directory.

    The shared `client` fixture only redirects `app.config`, but
    `app.services.store` binds `ANALYSES_DIR` at import time, so analyses
    written during a test would land in the repository's real `backend/data`
    tree. This fixture redirects both bindings.
    """
    from fastapi.testclient import TestClient

    isolate_storage(tmp_path, monkeypatch)
    from app.main import app

    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture()
def qg_offline_client(tmp_path: Path, monkeypatch):
    """A TestClient for a host without TShark, so the pure-python reader is used."""
    from fastapi.testclient import TestClient

    isolate_storage(tmp_path, monkeypatch)
    disable_tshark(monkeypatch)
    from app.main import app

    with TestClient(app) as test_client:
        yield test_client
