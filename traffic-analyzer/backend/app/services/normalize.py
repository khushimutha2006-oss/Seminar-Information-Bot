"""Packet normalization service.

Converts raw frames (from the built-in pure-Python reader) and structured TShark
field rows into canonical ``NormalizedPacket`` instances.
"""

from __future__ import annotations

import socket
import struct
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from ..models.packet import NormalizedPacket
from .pcap_reader import RawFrame


def _format_iso_utc(epoch: float) -> str:
    dt = datetime.fromtimestamp(epoch, tz=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


# QUIC versions we accept as evidence that a UDP datagram really is QUIC:
# version negotiation (0), QUIC v1 (1), QUIC v2 (0x6b3343cf).
_QUIC_KNOWN_VERSIONS = {0x00000000, 0x00000001, 0x6B3343CF}


def _looks_like_dns(payload: bytes) -> bool:
    """Check that a payload really looks like a DNS message.

    The port number alone is not evidence, so the message header is validated:
    the reserved Z bits must be clear and the section counts must be plausible.
    """
    if len(payload) < 12:
        return False
    flags = struct.unpack("!H", payload[2:4])[0]
    if flags & 0x0070:  # reserved Z bits must be zero
        return False
    qdcount = struct.unpack("!H", payload[4:6])[0]
    ancount = struct.unpack("!H", payload[6:8])[0]
    nscount = struct.unpack("!H", payload[8:10])[0]
    arcount = struct.unpack("!H", payload[10:12])[0]
    return qdcount <= 4 and ancount <= 64 and nscount <= 4 and arcount <= 8


def _looks_like_quic(payload: bytes) -> tuple[bool, Optional[str]]:
    """Detect a QUIC long header.

    Returns ``(is_quic, version)``. A UDP port of 443 is deliberately NOT accepted
    as evidence: port numbers alone never prove a protocol.
    """
    if len(payload) < 5:
        return False, None
    if not payload[0] & 0x80:  # long header form has the high bit set
        return False, None
    version = struct.unpack("!I", payload[1:5])[0]
    if version in _QUIC_KNOWN_VERSIONS:
        return True, f"0x{version:08x}"
    if version & 0xFFFFFF00 == 0xFF000000:  # draft versions (0xff0000XX)
        return True, f"0x{version:08x}"
    return False, None


def _extract_tls_sni(payload: bytes) -> tuple[Optional[str], Optional[str]]:
    """Parse TLS record header for version and ClientHello SNI server_name."""
    if len(payload) < 5:
        return None, None
    content_type = payload[0]
    rec_version_raw = struct.unpack("!H", payload[1:3])[0]
    version_map = {
        0x0301: "TLSv1.0",
        0x0302: "TLSv1.1",
        0x0303: "TLSv1.2",
        0x0304: "TLSv1.3",
    }
    tls_version = version_map.get(rec_version_raw, f"0x{rec_version_raw:04x}")
    server_name = None

    if content_type == 0x16 and len(payload) >= 47:  # Handshake
        hs_type = payload[5]
        if hs_type == 0x01:  # ClientHello
            try:
                offset = 43  # After 5 bytes record hdr + 4 bytes hs hdr + 2 bytes client ver + 32 bytes random
                if offset < len(payload):
                    session_id_len = payload[offset]
                    offset += 1 + session_id_len
                if offset + 2 <= len(payload):
                    cs_len = struct.unpack("!H", payload[offset : offset + 2])[0]
                    offset += 2 + cs_len
                if offset < len(payload):
                    comp_len = payload[offset]
                    offset += 1 + comp_len
                if offset + 2 <= len(payload):
                    ext_total_len = struct.unpack("!H", payload[offset : offset + 2])[0]
                    offset += 2
                    ext_end = min(offset + ext_total_len, len(payload))
                    while offset + 4 <= ext_end:
                        ext_type, ext_len = struct.unpack("!HH", payload[offset : offset + 4])
                        offset += 4
                        if ext_type == 0x0000 and offset + 5 <= ext_end:  # server_name
                            # list_len (2), name_type (1), name_len (2)
                            sni_len = struct.unpack("!H", payload[offset + 3 : offset + 5])[0]
                            sni_bytes = payload[offset + 5 : offset + 5 + sni_len]
                            server_name = sni_bytes.decode("utf-8", errors="ignore")
                            break
                        offset += ext_len
            except Exception:
                pass

    return tls_version, server_name


def normalize_raw_frames(
    frames: list[RawFrame], source_file: str
) -> tuple[list[NormalizedPacket], list[str]]:
    packets: list[NormalizedPacket] = []
    warnings: list[str] = []

    prev_epoch: Optional[float] = None

    for frame in frames:
        data = frame.data
        frame_len = frame.captured_length
        epoch = frame.timestamp_epoch
        timestamp_str = _format_iso_utc(epoch)

        interval = None
        if prev_epoch is not None:
            interval = round(epoch - prev_epoch, 6)
        prev_epoch = epoch

        protocols = ["eth"]
        source_ip: Optional[str] = None
        destination_ip: Optional[str] = None
        source_port: Optional[int] = None
        destination_port: Optional[int] = None
        transport_proto: Optional[str] = None
        app_proto: Optional[str] = None
        ip_version: Optional[int] = None
        ip_packet_length: Optional[int] = None
        tcp_flags: Optional[str] = None
        tcp_stream_id: Optional[int] = None
        http_method: Optional[str] = None
        http_status_code: Optional[int] = None
        tls_version: Optional[str] = None
        server_name: Optional[str] = None
        quic_version: Optional[str] = None
        is_encrypted = False
        info: Optional[str] = None

        if len(data) >= 14:
            ethertype = struct.unpack("!H", data[12:14])[0]
            offset = 14
            if ethertype == 0x8100 and len(data) >= 18:  # 802.1Q VLAN
                ethertype = struct.unpack("!H", data[16:18])[0]
                offset = 18

            if ethertype == 0x0800 and len(data) >= offset + 20:  # IPv4
                ip_version = 4
                protocols.append("ip")
                ihl = (data[offset] & 0x0F) * 4
                ip_total_len = struct.unpack("!H", data[offset + 2 : offset + 4])[0]
                ip_packet_length = ip_total_len
                proto_num = data[offset + 9]
                source_ip = socket.inet_ntoa(data[offset + 12 : offset + 16])
                destination_ip = socket.inet_ntoa(data[offset + 16 : offset + 20])
                p_offset = offset + ihl

                if proto_num == 1:  # ICMP
                    transport_proto = "ICMP"
                    app_proto = "ICMP"
                    protocols.append("icmp")
                elif proto_num == 6:  # TCP
                    transport_proto = "TCP"
                    protocols.append("tcp")
                    if len(data) >= p_offset + 20:
                        source_port, destination_port = struct.unpack("!HH", data[p_offset : p_offset + 4])
                        tcp_hdr_len = ((data[p_offset + 12] >> 4) & 0x0F) * 4
                        flags_num = struct.unpack("!H", data[p_offset + 12 : p_offset + 14])[0] & 0x01FF
                        tcp_flags = f"0x{flags_num:04x}"
                        payload = data[p_offset + tcp_hdr_len : offset + ip_total_len]

                        # Check HTTP
                        methods = (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ", b"PATCH ", b"CONNECT ", b"TRACE ")
                        if any(payload.startswith(m) for m in methods):
                            app_proto = "HTTP"
                            protocols.append("http")
                            first_line = payload.split(b"\r\n", 1)[0].decode("utf-8", errors="ignore")
                            parts = first_line.split(" ")
                            if parts:
                                http_method = parts[0]
                                info = first_line
                            # check Host header
                            for line in payload.split(b"\r\n"):
                                if line.lower().startswith(b"host:"):
                                    server_name = line.split(b":", 1)[1].strip().decode("utf-8", errors="ignore")
                                    break
                        elif payload.startswith(b"HTTP/1.") or payload.startswith(b"HTTP/2"):
                            app_proto = "HTTP"
                            protocols.append("http")
                            first_line = payload.split(b"\r\n", 1)[0].decode("utf-8", errors="ignore")
                            parts = first_line.split(" ")
                            if len(parts) >= 2 and parts[1].isdigit():
                                http_status_code = int(parts[1])
                                info = first_line
                        elif len(payload) >= 5 and payload[0] in (0x16, 0x17, 0x14, 0x15) and payload[1] == 0x03:
                            app_proto = "TLS"
                            is_encrypted = True
                            protocols.append("tls")
                            t_ver, s_name = _extract_tls_sni(payload)
                            tls_version = t_ver
                            if s_name:
                                server_name = s_name
                        elif source_port == 443 or destination_port == 443:
                            # Honesty rule: port 443 without TLS record fields is TCP, app_proto TCP
                            app_proto = "TCP"
                        else:
                            app_proto = "TCP"

                elif proto_num == 17:  # UDP
                    transport_proto = "UDP"
                    protocols.append("udp")
                    if len(data) >= p_offset + 8:
                        source_port, destination_port = struct.unpack("!HH", data[p_offset : p_offset + 4])
                        udp_len = struct.unpack("!H", data[p_offset + 4 : p_offset + 6])[0]
                        payload = data[p_offset + 8 : p_offset + udp_len]

                        if (source_port == 53 or destination_port == 53) and _looks_like_dns(payload):
                            app_proto = "DNS"
                            protocols.append("dns")
                        else:
                            quic_detected, quic_ver = _looks_like_quic(payload)
                            if quic_detected:
                                app_proto = "QUIC"
                                is_encrypted = True
                                protocols.append("quic")
                                quic_version = quic_ver
                            elif source_port == 443 or destination_port == 443:
                                # Honesty rule: UDP/443 on its own proves nothing.
                                app_proto = "UDP"
                            else:
                                app_proto = "UDP"
                else:
                    transport_proto = "OTHER"
                    app_proto = "OTHER"

            elif ethertype == 0x86DD and len(data) >= offset + 40:  # IPv6
                ip_version = 6
                protocols.append("ipv6")
                payload_len = struct.unpack("!H", data[offset + 4 : offset + 6])[0]
                ip_packet_length = 40 + payload_len
                proto_num = data[offset + 6]
                source_ip = socket.inet_ntop(socket.AF_INET6, data[offset + 8 : offset + 24])
                destination_ip = socket.inet_ntop(socket.AF_INET6, data[offset + 24 : offset + 40])
                p_offset = offset + 40

                if proto_num == 58:  # ICMPv6
                    transport_proto = "ICMPv6"
                    app_proto = "ICMPv6"
                    protocols.append("icmpv6")
                elif proto_num == 6:  # TCP
                    transport_proto = "TCP"
                    protocols.append("tcp")
                    if len(data) >= p_offset + 20:
                        source_port, destination_port = struct.unpack("!HH", data[p_offset : p_offset + 4])
                        app_proto = "TCP"
                elif proto_num == 17:  # UDP
                    transport_proto = "UDP"
                    protocols.append("udp")
                    if len(data) >= p_offset + 8:
                        source_port, destination_port = struct.unpack("!HH", data[p_offset : p_offset + 4])
                        udp_len = struct.unpack("!H", data[p_offset + 4 : p_offset + 6])[0]
                        payload = data[p_offset + 8 : p_offset + udp_len]
                        if (source_port == 53 or destination_port == 53) and _looks_like_dns(payload):
                            app_proto = "DNS"
                            protocols.append("dns")
                        else:
                            quic_detected, quic_ver = _looks_like_quic(payload)
                            if quic_detected:
                                app_proto = "QUIC"
                                is_encrypted = True
                                protocols.append("quic")
                                quic_version = quic_ver
                            else:
                                app_proto = "UDP"
                else:
                    transport_proto = "OTHER"
                    app_proto = "OTHER"

            elif ethertype == 0x0806:  # ARP
                transport_proto = "ARP"
                app_proto = "ARP"
                protocols.append("arp")
                ip_version = None
                ip_packet_length = None
            else:
                transport_proto = "OTHER"
                app_proto = "OTHER"

        packet = NormalizedPacket(
            frame_number=frame.frame_number,
            timestamp=timestamp_str,
            timestamp_epoch=epoch,
            source_ip=source_ip,
            destination_ip=destination_ip,
            source_port=source_port,
            destination_port=destination_port,
            transport_protocol=transport_proto,
            application_protocol=app_proto,
            captured_frame_length=frame_len,
            ip_packet_length=ip_packet_length,
            tcp_flags=tcp_flags,
            tcp_stream_id=tcp_stream_id,
            http_method=http_method,
            http_status_code=http_status_code,
            tls_version=tls_version,
            server_name=server_name,
            quic_version=quic_version,
            inter_packet_interval_seconds=interval,
            is_encrypted=is_encrypted,
            protocols=protocols,
            info=info,
            source_file=source_file,
            ip_version=ip_version,
            direction_hint="unknown",
        )
        packets.append(packet)

    return packets, warnings


def normalize_tshark_rows(
    rows: list[dict[str, str]], source_file: str
) -> tuple[list[NormalizedPacket], list[str]]:
    packets: list[NormalizedPacket] = []
    warnings: list[str] = []

    prev_epoch: Optional[float] = None

    for idx, row in enumerate(rows, start=1):
        try:
            fn_raw = row.get("frame.number")
            frame_num = int(fn_raw) if fn_raw and fn_raw.isdigit() else idx

            epoch_raw = row.get("frame.time_epoch") or "0.0"
            epoch = float(epoch_raw)
            timestamp_str = _format_iso_utc(epoch)

            interval = None
            if prev_epoch is not None:
                interval = round(epoch - prev_epoch, 6)
            prev_epoch = epoch

            cap_len_raw = row.get("frame.len") or "0"
            cap_len = int(cap_len_raw)

            # Protocols layer list
            proto_str = row.get("frame.protocols") or ""
            protocols = [p.strip() for p in proto_str.split(":") if p.strip()] or ["eth"]

            # IPs
            src_ip = row.get("ip.src") or row.get("ipv6.src") or None
            dst_ip = row.get("ip.dst") or row.get("ipv6.dst") or None
            ip_ver = 4 if row.get("ip.src") else (6 if row.get("ipv6.src") else None)

            # IP length
            ip_len = None
            if row.get("ip.len"):
                try:
                    ip_len = int(row["ip.len"])
                except ValueError:
                    pass
            elif row.get("ipv6.plen"):
                try:
                    ip_len = 40 + int(row["ipv6.plen"])
                except ValueError:
                    pass

            # Ports & transport
            src_port = None
            dst_port = None
            trans_proto = None

            if row.get("tcp.srcport") or row.get("tcp.dstport"):
                trans_proto = "TCP"
                src_port = int(row["tcp.srcport"]) if row.get("tcp.srcport") else None
                dst_port = int(row["tcp.dstport"]) if row.get("tcp.dstport") else None
            elif row.get("udp.srcport") or row.get("udp.dstport"):
                trans_proto = "UDP"
                src_port = int(row["udp.srcport"]) if row.get("udp.srcport") else None
                dst_port = int(row["udp.dstport"]) if row.get("udp.dstport") else None
            elif "arp" in protocols or row.get("_ws.col.Protocol") == "ARP":
                trans_proto = "ARP"
            elif "icmp" in protocols or row.get("_ws.col.Protocol") == "ICMP":
                trans_proto = "ICMP"
            elif "icmpv6" in protocols or row.get("_ws.col.Protocol") == "ICMPv6":
                trans_proto = "ICMPv6"
            elif src_ip or dst_ip:
                trans_proto = "OTHER"

            tcp_flags = row.get("tcp.flags") or None
            tcp_stream = int(row["tcp.stream"]) if row.get("tcp.stream") and row["tcp.stream"].isdigit() else None

            # Application protocol & extras
            http_m = row.get("http.request.method") or None
            http_code = int(row["http.response.code"]) if row.get("http.response.code") and row["http.response.code"].isdigit() else None
            server_name = row.get("tls.handshake.extensions_server_name") or row.get("http.host") or None
            tls_ver = row.get("tls.record.version") or None

            ws_proto = (row.get("_ws.col.Protocol") or "").upper()
            is_encrypted = False
            app_proto = None

            if http_m or http_code:
                app_proto = "HTTP"
                is_encrypted = False
            elif tls_ver or server_name or "tls" in protocols or ws_proto == "TLS":
                app_proto = "TLS"
                is_encrypted = True
            elif "quic" in protocols or ws_proto in ("QUIC", "HTTP3"):
                app_proto = "QUIC"
                is_encrypted = True
            elif "dns" in protocols or ws_proto == "DNS":
                app_proto = "DNS"
                is_encrypted = False
            elif trans_proto in ("ARP", "ICMP", "ICMPv6"):
                app_proto = trans_proto
            elif trans_proto in ("TCP", "UDP"):
                app_proto = trans_proto
            else:
                app_proto = "OTHER"

            info = row.get("_ws.col.Info") or None

            packet = NormalizedPacket(
                frame_number=frame_num,
                timestamp=timestamp_str,
                timestamp_epoch=epoch,
                source_ip=src_ip,
                destination_ip=dst_ip,
                source_port=src_port,
                destination_port=dst_port,
                transport_protocol=trans_proto,
                application_protocol=app_proto,
                captured_frame_length=cap_len,
                ip_packet_length=ip_len,
                tcp_flags=tcp_flags,
                tcp_stream_id=tcp_stream,
                http_method=http_m,
                http_status_code=http_code,
                tls_version=tls_ver,
                server_name=server_name,
                inter_packet_interval_seconds=interval,
                is_encrypted=is_encrypted,
                protocols=protocols,
                info=info,
                source_file=source_file,
                ip_version=ip_ver,
                direction_hint="unknown",
            )
            packets.append(packet)
        except Exception as exc:
            warnings.append(f"Row {idx}: failed to normalize: {exc}")

    return packets, warnings
