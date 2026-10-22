"""CSV capture ingestion service.

Imports Wireshark CSV exports and the analyzer's own CSV format into canonical
``NormalizedPacket`` objects.
"""

from __future__ import annotations

import csv
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from ..models.packet import NormalizedPacket


def _parse_time(val: str, prev_epoch: Optional[float] = None) -> tuple[str, float]:
    val = val.strip()
    if not val:
        epoch = (prev_epoch or 0.0)
        dt = datetime.fromtimestamp(epoch, tz=timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ"), epoch

    # Check ISO-8601
    try:
        dt = datetime.fromisoformat(val.replace("Z", "+00:00"))
        epoch = dt.timestamp()
        dt_utc = datetime.fromtimestamp(epoch, tz=timezone.utc)
        return dt_utc.strftime("%Y-%m-%dT%H:%M:%S.%fZ"), epoch
    except ValueError:
        pass

    # Check numeric float
    try:
        sec = float(val)
        epoch = sec if sec > 1_000_000_000.0 else (1_700_000_000.0 + sec)
        dt = datetime.fromtimestamp(epoch, tz=timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ"), epoch
    except ValueError:
        epoch = (prev_epoch or 0.0)
        dt = datetime.fromtimestamp(epoch, tz=timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ"), epoch


def load_csv(path: str | Path) -> tuple[list[NormalizedPacket], list[str]]:
    file_path = Path(path)
    if not file_path.is_file():
        raise FileNotFoundError(f"CSV file not found: {file_path.name}")

    content = file_path.read_text(encoding="utf-8", errors="replace")
    lines = [line.strip() for line in content.splitlines() if line.strip()]
    if not lines:
        return [], []

    # Detect delimiter
    sample = lines[0]
    delimiter = "\t" if "\t" in sample and "," not in sample else (";" if ";" in sample and "," not in sample else ",")

    reader = csv.DictReader(lines, delimiter=delimiter)
    if not reader.fieldnames:
        return [], ["CSV file has no header row."]

    # Build key mapping
    col_map: dict[str, str] = {}
    for fn in reader.fieldnames:
        clean = fn.strip().lower()
        if clean in ("no.", "frame_number", "frame.number", "packet"):
            col_map["frame_number"] = fn
        elif clean in ("time", "timestamp", "frame.time_epoch", "epoch"):
            col_map["timestamp"] = fn
        elif clean in ("source", "source_ip", "ip.src", "src"):
            col_map["source_ip"] = fn
        elif clean in ("destination", "destination_ip", "ip.dst", "dst"):
            col_map["destination_ip"] = fn
        elif clean in ("protocol", "application_protocol", "_ws.col.protocol"):
            col_map["protocol"] = fn
        elif clean in ("length", "captured_frame_length", "frame.len", "len"):
            col_map["length"] = fn
        elif clean in ("ip_packet_length", "ip.len"):
            col_map["ip_packet_length"] = fn
        elif clean in ("source_port", "src_port", "tcp.srcport", "udp.srcport"):
            col_map["source_port"] = fn
        elif clean in ("destination_port", "dst_port", "tcp.dstport", "udp.dstport"):
            col_map["destination_port"] = fn
        elif clean in ("transport", "transport_protocol"):
            col_map["transport_protocol"] = fn
        elif clean in ("info", "_ws.col.info"):
            col_map["info"] = fn
        elif clean in ("http_method", "http.request.method"):
            col_map["http_method"] = fn
        elif clean in ("http_status_code", "http.response.code"):
            col_map["http_status_code"] = fn
        elif clean in ("tls_version", "tls.record.version"):
            col_map["tls_version"] = fn
        elif clean in ("server_name", "host", "http.host", "tls.handshake.extensions_server_name"):
            col_map["server_name"] = fn

    packets: list[NormalizedPacket] = []
    warnings: list[str] = []
    prev_epoch: Optional[float] = None

    if "length" not in col_map:
        warnings.append(
            "CSV has no length column; byte totals for this capture are reported as 0."
        )

    for idx, row in enumerate(reader, start=1):
        try:
            fn_val = row.get(col_map.get("frame_number", ""))
            if not fn_val or not fn_val.isdigit():
                warnings.append(
                    f"CSV row {idx}: missing or unusable frame_number, the row was skipped."
                )
                continue
            frame_number = int(fn_val)

            t_val = row.get(col_map.get("timestamp", "")) or ""
            timestamp_str, epoch = _parse_time(t_val, prev_epoch)

            interval = None
            if prev_epoch is not None:
                interval = round(epoch - prev_epoch, 6)
            prev_epoch = epoch

            len_val = row.get(col_map.get("length", "")) or ""
            if "length" in col_map and not len_val.isdigit():
                warnings.append(
                    f"CSV row {idx}: missing or unusable frame length, the row was skipped."
                )
                continue
            captured_frame_length = int(len_val) if len_val.isdigit() else 0

            ip_len_val = row.get(col_map.get("ip_packet_length", "")) or None
            ip_packet_length = int(ip_len_val) if ip_len_val and ip_len_val.isdigit() else None

            src_ip = row.get(col_map.get("source_ip", "")) or None
            dst_ip = row.get(col_map.get("destination_ip", "")) or None

            src_p = row.get(col_map.get("source_port", ""))
            dst_p = row.get(col_map.get("destination_port", ""))
            source_port = int(src_p) if src_p and src_p.isdigit() else None
            destination_port = int(dst_p) if dst_p and dst_p.isdigit() else None

            trans_proto = row.get(col_map.get("transport_protocol", "")) or None
            raw_proto = (row.get(col_map.get("protocol", "")) or "").strip()

            if not trans_proto:
                if raw_proto.upper() in ("TCP", "HTTP", "TLS", "HTTPS"):
                    trans_proto = "TCP"
                elif raw_proto.upper() in ("UDP", "DNS", "QUIC"):
                    trans_proto = "UDP"
                elif raw_proto.upper() in ("ARP", "ICMP", "ICMPV6"):
                    trans_proto = raw_proto.upper()
                elif src_ip or dst_ip:
                    trans_proto = "TCP" if (source_port and source_port in (80, 443)) else "OTHER"

            app_proto = None
            is_encrypted = False
            raw_upper = raw_proto.upper()
            if raw_upper in ("HTTP",):
                app_proto = "HTTP"
            elif raw_upper in ("TLS", "HTTPS", "SSL"):
                app_proto = "TLS"
                is_encrypted = True
            elif raw_upper in ("QUIC", "HTTP3"):
                app_proto = "QUIC"
                is_encrypted = True
            elif raw_upper in ("DNS",):
                app_proto = "DNS"
            elif raw_upper in ("ARP", "ICMP", "ICMPV6", "TCP", "UDP"):
                app_proto = raw_upper
            elif trans_proto in ("TCP", "UDP"):
                app_proto = trans_proto
            else:
                app_proto = "OTHER"

            http_m = row.get(col_map.get("http_method", "")) or None
            http_c_raw = row.get(col_map.get("http_status_code", "")) or None
            http_c = int(http_c_raw) if http_c_raw and http_c_raw.isdigit() else None
            tls_v = row.get(col_map.get("tls_version", "")) or None
            s_name = row.get(col_map.get("server_name", "")) or None
            info = row.get(col_map.get("info", "")) or None

            ip_version = None
            if src_ip:
                ip_version = 6 if ":" in src_ip else 4

            packet = NormalizedPacket(
                frame_number=frame_number,
                timestamp=timestamp_str,
                timestamp_epoch=epoch,
                source_ip=src_ip,
                destination_ip=dst_ip,
                source_port=source_port,
                destination_port=destination_port,
                transport_protocol=trans_proto,
                application_protocol=app_proto,
                captured_frame_length=captured_frame_length,
                ip_packet_length=ip_packet_length,
                http_method=http_m,
                http_status_code=http_c,
                tls_version=tls_v,
                server_name=s_name,
                inter_packet_interval_seconds=interval,
                is_encrypted=is_encrypted,
                protocols=[trans_proto.lower()] if trans_proto else ["eth"],
                info=info,
                source_file=file_path.name,
                ip_version=ip_version,
            )
            packets.append(packet)
        except Exception as exc:
            warnings.append(f"CSV row {idx}: {exc}")

    if not packets and not warnings:
        warnings.append("CSV contained no data rows.")

    return packets, warnings
