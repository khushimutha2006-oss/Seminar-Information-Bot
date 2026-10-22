# Normalized Packet Schema (canonical contract v1)

This file is the **contract**. The Pydantic model `backend/app/models/packet.py` is the
executable version of it. Field names, types, and units here are authoritative.
Do not rename or change types without the lead's approval.

## 1. The normalized packet record

Every packet in the system is represented by `NormalizedPacket`. Fields that the capture
does not contain are `null` — never faked, never defaulted to zero, never omitted from
the payload.

| Field | Type | Unit / format | Nullable | Meaning |
|---|---|---|---|---|
| `frame_number` | integer | 1-based ordinal | no | Position of the frame in the capture file, as reported by the dissector. |
| `timestamp` | string | ISO-8601 UTC, e.g. `2026-10-21T18:23:27.755302Z` | no | Absolute capture time, microsecond precision, timezone `Z`. |
| `timestamp_epoch` | number | seconds (float, Unix epoch) | no | Same instant as `timestamp`, numeric form, for arithmetic. |
| `source_ip` | string | IPv4/IPv6 literal | yes | Source address when the frame carries an IP header. |
| `destination_ip` | string | IPv4/IPv6 literal | yes | Destination address when the frame carries an IP header. |
| `source_port` | integer | 0-65535 | yes | Source transport port (TCP/UDP). |
| `destination_port` | integer | 0-65535 | yes | Destination transport port (TCP/UDP). |
| `transport_protocol` | string | enum §3 | yes | `TCP`, `UDP`, `ICMP`, `ICMPv6`, `ARP`, `SCTP`, `OTHER`, or `null`. |
| `application_protocol` | string | enum §3 | yes | The **observed** application protocol, or `null` when it cannot be established. |
| `captured_frame_length` | integer | bytes | no | Bytes on the wire for the whole frame (`frame.len`). Always present. |
| `ip_packet_length` | integer | bytes | yes | Total IP datagram length: `ip.len` for IPv4, `40 + ipv6.plen` for IPv6, `null` for non-IP frames. |
| `tcp_flags` | string | e.g. `0x0018` | yes | TCP flag word as reported by the dissector, when present. |
| `tcp_stream_id` | integer | >= 0 | yes | TCP conversation index. Dissector-provided when available, otherwise assigned by the analyzer deterministically. |
| `http_method` | string | e.g. `GET` | yes | **Only** when an HTTP request was actually parsed and observed. |
| `http_status_code` | integer | 100-599 | yes | **Only** when an HTTP response was actually parsed and observed. |
| `tls_version` | string | e.g. `TLSv1.3`, `0x0303` | yes | Record/handshake version observed inside a TLS record. |
| `server_name` | string | DNS name | yes | TLS SNI / HTTP Host, when actually observed in the clear. |
| `inter_packet_interval_seconds` | number | seconds (float) | yes | Delta from the previous packet **in the same capture**, `null` for the first packet. |
| `is_encrypted` | boolean | — | no | True only when the payload was actually seen inside a TLS/QUIC/SRTP container. |
| `protocols` | array of strings | layer names, bottom-up | no | Protocol layers the dissector reported, e.g. `["eth","ip","tcp","http"]`. Empty for undecodable frames. |
| `info` | string | free text | yes | Dissector summary line. Informational only. |
| `source_file` | string | file name | yes | Capture file the packet came from. |
| `ip_version` | integer | 4, 6, or null | yes | IP version, `null` for non-IP frames. |
| `direction_hint` | string | `outbound`, `inbound`, `unknown` | no | Best-effort direction relative to the capture host. Never claimed as ground truth. |

### 1.1 Optional honesty extras (contract v1.1)

These fields are additive. They never replace a field above; they explain how the
classification was reached, so the UI can show uncertainty instead of hiding it.

| Field | Type | Meaning |
|---|---|---|
| `detected_protocol` | string | Raw protocol name the dissector reported, if any. |
| `protocol_confidence` | string | `high`, `medium`, `low` or `unknown`. |
| `protocol_evidence` | array of strings | Short reasons that produced `application_protocol` (e.g. `"http.request.method observed"`). |
| `quic_version` | string | QUIC version, when observed. |
| `timestamp_has_date` | boolean | `false` when the source only carried a time of day, so no calendar date was invented. |

A client that does not know these fields must ignore them. A server that cannot
produce them may omit them; they are never required.

### 1.2 Honesty rules (non-negotiable)

1. A packet is **never** reported as HTTP unless an HTTP request line or status line was
   actually observed in the payload.
2. TCP port 443 is **not** proof of HTTPS. TLS is only asserted when TLS fields are
   present. `application_protocol` is `TLS`, never `HTTP`, for encrypted traffic.
3. UDP port 443 is **not** proof of HTTPS; it is very often QUIC. If the dissector
   reports the QUIC layer, `application_protocol` is `QUIC`.
4. A frame that is truncated, malformed, or not IP (ARP, 802.3, VLAN-only, etc.) still
   appears in the capture with the fields that are knowable and `null` elsewhere.
5. `application_protocol` is `null` rather than a guess when the evidence is absent.

## 2. Timestamps

* Source of truth: the capture file's own timestamps (nanosecond resolution in pcapng,
  microsecond in classic pcap).
* `timestamp_epoch` is the raw value read from the file, converted to float seconds.
* `timestamp` is derived from `timestamp_epoch` and rendered as ISO-8601 in UTC with a
  `Z` suffix and microsecond precision.
* Never use the wall clock of the machine running the analysis.

## 3. Protocol label vocabulary

Exactly these strings, case-sensitive. Anything else is `null` (application) or `OTHER`
(transport).

**Transport (`transport_protocol`)** — `TCP`, `UDP`, `ICMP`, `ICMPv6`, `ARP`, `SCTP`, `OTHER`.

**Application (`application_protocol`)** — observed only:

| Label | Set when |
|---|---|
| `HTTP` | An HTTP request line or status line was parsed. |
| `TLS` | TLS record/handshake fields were parsed. Payload is encrypted; `is_encrypted=true`. |
| `QUIC` | The QUIC layer was dissected. Payload is encrypted; `is_encrypted=true`. |
| `DNS` | DNS message fields were parsed. |
| `TLS` for SRTP? | Not used. SRTP is reported via `protocols` layer list only. |
| `TCP` / `UDP` | Transport present, no application layer recognised. |
| `ICMP` / `ICMPv6` / `ARP` | Non-IP or ICMP frames. |
| `OTHER` | Frame decoded but no recognised layer above transport. |
| `null` | Nothing could be established. |

## 4. Byte accounting

* `captured_frame_length` — bytes actually on the wire for the frame, including link
  header. This is the number used for byte totals.
* `ip_packet_length` — IP datagram size only (no link header). `null` for non-IP frames.
* Byte totals in the statistics engine sum `captured_frame_length`. The UI must label
  them "bytes on the wire" and must not mix the two columns.

## 5. Derived aggregates

The statistics engine (`backend/app/services/stats.py`) produces:

* `summary` — see `CaptureSummary` in `models/packet.py`.
* `protocols` — list of `{protocol, packets, bytes, percentage}`.
* `hosts` — list of `{ip, packets, bytes_sent, bytes_received, total_bytes, protocols}`.
* `conversations` — list of `{source_ip, source_port, destination_ip, destination_port,
  transport_protocol, packets, bytes}` (optional extra, same file).

All percentages are floats in the range 0-100 rounded to 2 decimals.

## 6. Storage / identity

* Every analysis gets an `analysis_id` (UUID4 hex string) and a `created_at` timestamp.
* The in-memory store is authoritative for the running process. Analyses live in
  `backend/data/analyses/<analysis_id>/` with the normalised packets persisted as
  JSONL and the source capture copied in when the source is a local file.
* A restart loses nothing that was persisted; re-hydration is best effort.

## 7. Change control

Any change to this file or to `models/packet.py` is a contract change: bump the version
string in `backend/app/config.py` (`CONTRACT_VERSION`), note it in the git commit
message, and notify the lead so the frontend can be updated in the same day.
