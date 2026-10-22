"""Tests for the normalization layer and the honesty rules of the contract.

The contract (docs/SCHEMA.md) is strict about what may be claimed:

* HTTP is only reported when a request or status line was really observed.
* TCP port 443 alone is not proof of HTTPS, and UDP port 443 is not proof of QUIC.
* A missing field stays ``None``; it is never turned into 0 or "".
* Byte counts and timestamps come from the capture, not from the wall clock.
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from app.services.normalize import normalize_raw_frames, normalize_tshark_rows
from app.services.pcap_reader import RawFrame

from tests import support


def _frames(*payloads: bytes, link_type: int = 1) -> list[RawFrame]:
    return [
        RawFrame(
            frame_number=index,
            timestamp_epoch=1_700_000_000.0 + (index - 1),
            captured_length=len(payload),
            original_length=len(payload),
            link_type=link_type,
            data=payload,
        )
        for index, payload in enumerate(payloads, start=1)
    ]


class TestRawFrameNormalization:
    def test_plaintext_http_request_is_detected(self):
        request = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
        frame = support.build_frame(payload=request)
        packets, _ = normalize_raw_frames(_frames(frame), "sample.pcap")
        packet = packets[0]
        assert packet.application_protocol == "HTTP"
        assert packet.http_method == "GET"
        assert packet.http_status_code is None
        assert packet.server_name == "example.com"
        assert packet.is_encrypted is False

    def test_plaintext_http_response_is_detected(self):
        response = b"HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\n\r\n"
        frame = support.build_frame(payload=response)
        packets, _ = normalize_raw_frames(_frames(frame), "sample.pcap")
        assert packets[0].application_protocol == "HTTP"
        assert packets[0].http_status_code == 404
        assert packets[0].http_method is None

    def test_tls_record_is_never_reported_as_http(self):
        # TLS handshake record: content type 0x16, version 0x0301
        tls = bytes([0x16, 0x03, 0x01, 0x00, 0x50]) + b"\x00" * 60
        frame = support.build_frame(src_port=51000, dst_port=443, payload=tls)
        packets, _ = normalize_raw_frames(_frames(frame), "sample.pcap")
        packet = packets[0]
        assert packet.application_protocol == "TLS"
        assert packet.is_encrypted is True
        assert packet.http_method is None
        assert packet.http_status_code is None
        assert packet.tls_version == "TLSv1.0"

    def test_tcp_port_443_without_tls_is_not_https(self):
        # A plain TCP segment to port 443 proves nothing about the protocol.
        frame = support.build_frame(src_port=51000, dst_port=443, payload=b"\x01\x02\x03\x04")
        packets, _ = normalize_raw_frames(_frames(frame), "sample.pcap")
        packet = packets[0]
        assert packet.application_protocol == "TCP"
        assert packet.is_encrypted is False
        assert packet.http_method is None

    def test_udp_port_443_alone_is_not_quic(self):
        frame = support.build_frame(
            src_port=51000, dst_port=443, payload=b"\x11\x22\x33\x44", protocol=17
        )
        packets, _ = normalize_raw_frames(_frames(frame), "sample.pcap")
        packet = packets[0]
        assert packet.application_protocol == "UDP"
        assert packet.is_encrypted is False
        assert "quic" not in packet.protocols

    def test_quic_long_header_is_detected(self):
        quic = bytes([0xC0, 0x00, 0x00, 0x00, 0x01]) + b"\x00" * 40
        frame = support.build_frame(src_port=51000, dst_port=443, payload=quic, protocol=17)
        packets, _ = normalize_raw_frames(_frames(frame), "sample.pcap")
        packet = packets[0]
        assert packet.application_protocol == "QUIC"
        assert packet.is_encrypted is True
        assert packet.quic_version == "0x00000001"

    def test_dns_needs_a_dns_header_not_only_port_53(self):
        # Port 53 with a payload that is not a DNS message must not be called DNS.
        frame = support.build_frame(
            src_port=51000, dst_port=53, payload=b"\x00\x01\x02\x03\x04", protocol=17
        )
        packets, _ = normalize_raw_frames(_frames(frame), "sample.pcap")
        assert packets[0].application_protocol == "UDP"

    def test_dns_message_is_detected(self):
        dns = bytes.fromhex("abcd0100000100000000000003777777076578616d706c6503636f6d0000010001")
        frame = support.build_frame(src_port=51000, dst_port=53, payload=dns, protocol=17)
        packets, _ = normalize_raw_frames(_frames(frame), "sample.pcap")
        assert packets[0].application_protocol == "DNS"

    def test_non_ip_frame_keeps_addresses_empty(self):
        arp = support.ethernet_frame(ethertype=0x0806, payload=b"\x00" * 28)
        packets, _ = normalize_raw_frames(_frames(arp), "sample.pcap")
        packet = packets[0]
        assert packet.source_ip is None
        assert packet.destination_ip is None
        assert packet.transport_protocol == "ARP"
        assert packet.ip_packet_length is None

    def test_ip_and_tcp_fields_are_extracted(self):
        frame = support.build_frame(src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=1234, dst_port=80)
        packets, _ = normalize_raw_frames(_frames(frame), "sample.pcap")
        packet = packets[0]
        assert packet.source_ip == "10.0.0.1"
        assert packet.destination_ip == "10.0.0.2"
        assert packet.source_port == 1234
        assert packet.destination_port == 80
        assert packet.transport_protocol == "TCP"
        assert packet.ip_version == 4
        assert packet.ip_packet_length == 40
        assert packet.captured_frame_length == len(frame)

    def test_inter_packet_interval_is_none_for_the_first_packet(self):
        frame = support.build_frame()
        packets, _ = normalize_raw_frames(_frames(frame, frame), "sample.pcap")
        assert packets[0].inter_packet_interval_seconds is None
        assert packets[1].inter_packet_interval_seconds == pytest.approx(1.0)

    def test_timestamps_come_from_the_capture(self):
        frames = _frames(support.build_frame())
        packets, _ = normalize_raw_frames(frames, "sample.pcap")
        assert packets[0].timestamp == "2023-11-14T22:13:20.000000Z"
        assert packets[0].timestamp_epoch == pytest.approx(1_700_000_000.0)

    def test_frame_numbers_are_one_based(self):
        frame = support.build_frame()
        packets, _ = normalize_raw_frames(_frames(frame, frame, frame), "sample.pcap")
        assert [p.frame_number for p in packets] == [1, 2, 3]


class TestTSharkRowNormalization:
    def _row(self, **overrides) -> dict[str, str]:
        row = {
            "frame.number": "1",
            "frame.time_epoch": "1792608963.970381",
            "frame.len": "74",
            "frame.protocols": "eth:ethertype:ip:tcp:http",
            "ip.src": "10.0.0.1",
            "ip.dst": "10.0.0.2",
            "tcp.srcport": "51000",
            "tcp.dstport": "80",
            "ip.len": "60",
            "tcp.flags": "0x0018",
            "tcp.stream": "0",
            "http.request.method": "GET",
            "http.response.code": "",
            "http.host": "example.com",
            "tls.record.version": "",
            "tls.handshake.extensions_server_name": "",
            "_ws.col.Protocol": "HTTP",
            "_ws.col.Info": "GET / HTTP/1.1",
        }
        row.update(overrides)
        return row

    def test_http_row(self):
        packets, _ = normalize_tshark_rows([self._row()], "sample.pcap")
        packet = packets[0]
        assert packet.application_protocol == "HTTP"
        assert packet.http_method == "GET"
        assert packet.server_name == "example.com"
        assert packet.is_encrypted is False

    def test_tls_row_is_encrypted_and_not_http(self):
        row = self._row(
            **{
                "frame.protocols": "eth:ethertype:ip:tcp:tls",
                "tcp.dstport": "443",
                "http.request.method": "",
                "http.host": "",
                "tls.record.version": "0x0303",
                "tls.handshake.extensions_server_name": "api.github.com",
                "_ws.col.Protocol": "TLS",
            }
        )
        packets, _ = normalize_tshark_rows([row], "sample.pcap")
        packet = packets[0]
        assert packet.application_protocol == "TLS"
        assert packet.is_encrypted is True
        assert packet.http_method is None
        assert packet.tls_version == "0x0303"
        assert packet.server_name == "api.github.com"

    def test_quic_row(self):
        row = self._row(
            **{
                "frame.protocols": "eth:ethertype:ip:udp:quic",
                "udp.srcport": "51000",
                "udp.dstport": "443",
                "tcp.srcport": "",
                "tcp.dstport": "",
                "http.request.method": "",
                "http.host": "",
                "_ws.col.Protocol": "QUIC",
            }
        )
        packets, _ = normalize_tshark_rows([row], "sample.pcap")
        assert packets[0].application_protocol == "QUIC"
        assert packets[0].is_encrypted is True

    def test_ipv6_row(self):
        row = self._row(
            **{
                "frame.protocols": "eth:ethertype:ipv6:tcp",
                "ip.src": "",
                "ip.dst": "",
                "ipv6.src": "2001:db8::1",
                "ipv6.dst": "2001:db8::2",
                "ipv6.plen": "20",
                "ip.len": "",
            }
        )
        packets, _ = normalize_tshark_rows([row], "sample.pcap")
        packet = packets[0]
        assert packet.source_ip == "2001:db8::1"
        assert packet.destination_ip == "2001:db8::2"
        assert packet.ip_version == 6
        assert packet.ip_packet_length == 60  # 40 byte IPv6 header + 20 byte payload

    def test_missing_values_stay_none(self):
        row = self._row(
            **{
                "ip.src": "",
                "ip.dst": "",
                "tcp.srcport": "",
                "tcp.dstport": "",
                "ip.len": "",
                "http.request.method": "",
                "http.host": "",
                "frame.protocols": "eth:ethertype:ip:tcp",
                "_ws.col.Protocol": "TCP",
            }
        )
        packets, _ = normalize_tshark_rows([row], "sample.pcap")
        packet = packets[0]
        assert packet.source_ip is None
        assert packet.source_port is None
        assert packet.ip_packet_length is None
        assert packet.http_method is None
