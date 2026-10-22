# HTTP API Contract (canonical contract v1)

Base URL: `http://localhost:8000`  •  All routes are prefixed with `/api`.
Content type: JSON except the CSV export and the upload multipart request.
The canonical Pydantic models live in `backend/app/models/packet.py`.

## 0. Conventions

* Every response is JSON except `GET /api/analysis/{id}/export/packets.csv`
  (`text/csv`) and `GET /api/analysis/{id}/export/summary.json` (`application/json`).
* Every list endpoint is paginated with `limit` (default 100, max 1000) and `offset`
  (default 0), and returns an envelope `{items, total, limit, offset}`.
* Timestamps are ISO-8601 UTC with `Z` suffix.
* Byte counts are integers.

### Error envelope

All errors use the same shape, with the HTTP status code carrying the category:

```json
{
  "error": {
    "code": "not_found",
    "message": "Analysis 'abc123' does not exist.",
    "detail": { "analysis_id": "abc123" }
  }
}
```

| Status | `code` | When |
|---|---|---|
| 400 | `invalid_request` | Malformed parameters, unparsable upload, bad CSV. |
| 404 | `not_found` | Unknown analysis id or route. |
| 409 | `conflict` | A capture is already running; capture already stopped. |
| 415 | `unsupported_media_type` | Upload is not pcap/pcapng/CSV. |
| 422 | `validation_error` | Pydantic request-body validation failure. |
| 500 | `internal_error` | Unexpected failure. |
| 503 | `unavailable` | TShark missing, or capture permission denied. |

`detail` is always an object (may be empty), never a string.

## 1. Health

### `GET /api/health`

```json
{
  "status": "ok",
  "contract_version": "v1",
  "app_version": "1.0.0",
  "tshark": { "available": true, "path": "/usr/bin/tshark", "version": "TShark 4.2.2" },
  "python": "3.12.3",
  "uptime_seconds": 12.3
}
```

`status` is `ok` when the API can serve traffic. `tshark.available=false` is **not** an
error: offline analysis still works, live capture does not.

## 2. Capture

### `GET /api/capture/status`

```json
{
  "running": false,
  "capture_id": null,
  "interface": null,
  "started_at": null,
  "stopped_at": null,
  "packets_captured": 0,
  "packets_filtered": 0,
  "capture_file": null,
  "filter": null,
  "last_error": null,
  "tshark_available": true
}
```

`capture_file` is the **file name only** — absolute paths never leave the backend. The
endpoint never answers with a 500: if the packet counter fails, the last known count is
reported and `last_error` explains why.

### `GET /api/capture/interfaces`

```json
{
  "source": "tshark",
  "tshark_available": true,
  "interfaces": [
    { "index": 1, "name": "wlp2s0", "description": "Intel ...", "is_loopback": false, "addresses": ["192.168.1.5"] }
  ],
  "message": null
}
```

`source` is `tshark`, `dumpcap` or `none`. When no capture tool is available, or the
listing fails, the list is empty or falls back to the system network devices and
`message` explains what happened in beginner-friendly words. **This endpoint never
answers with a 500**: an unusable capture setup is a normal state, not a crash.

### `POST /api/capture/start`

Request body:

```json
{ "interface": "wlp2s0", "duration_seconds": 30, "filter": "tcp port 80", "display_filter": "http" }
```

* `interface` (string, required) — interface name from `/api/capture/interfaces`.
* `duration_seconds` (int, optional, 1..3600) — auto-stop.
* `filter` (string, optional) — TShark **capture** filter (BPF), e.g. `tcp port 80`.
* `display_filter` (string, optional) — TShark display filter applied while reading.

Response `202`:

```json
{
  "status": "running",
  "capture_id": "b7d1...",
  "interface": "wlp2s0",
  "started_at": "2026-10-21T18:30:00Z",
  "filter": "tcp port 80",
  "message": "Capture started on 'wlp2s0'."
}
```

If a capture is already running: `409 conflict`. If the tool is missing or the interface
is unknown or the process dies immediately: `503 unavailable` (missing tool) / `400
invalid_request` (bad interface).

### `POST /api/capture/stop`

Request body: `{ "capture_id": "b7d1..." }` (optional — stops the running capture).

Response `200`:

```json
{
  "status": "stopped",
  "capture_id": "b7d1...",
  "packets_captured": 1204,
  "capture_file": "capture-b7d1....pcapng",
  "analysis_id": "3c9e...",
  "message": "Capture stopped and analysed.",
  "error": null
}
```

The stopped capture is analysed automatically and the resulting `analysis_id` is returned
so the UI can jump straight to the results. `analysis_id` is `null` if the capture file
could not be analysed; in that case `error` explains why and the file name is still
returned. The request still succeeds, because stopping the capture did succeed.

## 3. Analysis

### `POST /api/analysis/upload`

`multipart/form-data` with:

* `file` (binary, required) — `.pcap`, `.pcapng`, `.cap`, or `.csv`.
* `format` (optional form field) — `auto` (default), `pcap`, `csv`.

`auto` decides by file extension and by content sniffing (pcap magic `0xa1b2c3d4`,
pcapng magic `0x0a0d0d0a`).

Response `201`:

```json
{
  "analysis_id": "3c9e...",
  "status": "complete",
  "source_file": "sample.pcapng",
  "source_kind": "pcapng",
  "packet_count": 1204,
  "total_bytes": 981234,
  "warnings": ["Frame 12: truncated IP header"],
  "created_at": "2026-10-21T18:30:05Z"
}
```

Errors: `415` (unsupported type), `400` (empty or unparsable file), `413` (too large —
upload limit is 256 MB by default).

### `GET /api/analysis/{analysis_id}/summary`

Returns a `CaptureSummary` object (see `models/packet.py`).

Two aggregate fields exist so the charts are computed over the **whole** capture and
never over a single page of rows (contract v1.2):

```jsonc
"timeline": [
  { "timestamp": "2026-10-21T18:00:00.000000Z", "packets": 12, "bytes": 8400 }
],
"size_distribution": [
  { "label": "0-63", "min_bytes": 0, "max_bytes": 63, "packets": 10, "bytes": 400 },
  { "label": "1500+", "min_bytes": 1500, "max_bytes": null, "packets": 3, "bytes": 4800 }
]
```

* `timeline` — chronological buckets over the capture. The bucket width starts at one
  second and widens for long captures so there are never more than 120 buckets.
  `timestamp` is the bucket start (ISO-8601 UTC).
* `size_distribution` — the fixed size ranges `0-63`, `64-127`, `128-255`, `256-511`,
  `512-1023`, `1024-1499`, `1500-3999`, `4000-8999`, `9000+` in bytes. `max_bytes` is
  `null` for the last bucket. All nine ranges are always present, even when empty.

Both fields are optional: a client must handle their absence (older backend) by hiding
that chart, not by failing.

### `GET /api/analysis/{analysis_id}/packets`

Query parameters (all optional):

| Param | Type | Meaning |
|---|---|---|
| `limit` | int 1..1000, default 100 | Page size. |
| `offset` | int >= 0, default 0 | Rows to skip. |
| `q` | string | Case-insensitive substring over IP, port, protocol, host name, HTTP method. |
| `protocol` | string | Exact match on `application_protocol` (case-insensitive). |
| `transport` | string | Exact match on `transport_protocol`. |
| `src_ip` / `dst_ip` | string | Exact address match. |
| `src_port` / `dst_port` | int | Exact port match. |
| `method` | string | HTTP method match. |
| `status_code` | int | HTTP status code match. |
| `min_bytes` / `max_bytes` | int | `captured_frame_length` range. |
| `start` / `end` | ISO-8601 | Timestamp range, inclusive. |
| `encrypted` | bool | `true`/`false` filters on `is_encrypted`. |
| `order_by` | string | `frame_number`, `timestamp`, `captured_frame_length`, `source_ip`, `destination_ip`. Default `frame_number`. |
| `order_dir` | string | `asc` or `desc`. Default `asc`. |

Response: `{ "items": [NormalizedPacket, ...], "total": 1204, "limit": 100, "offset": 0 }`.

### `GET /api/analysis/{analysis_id}/protocols`

Response: `{ "items": [ { "protocol": "HTTP", "packets": 300, "bytes": 210000, "percentage": 24.92 }, ... ], "total": 6, "transport_items": [ { "protocol": "TCP", "packets": 1200, "bytes": 900000, "percentage": 99.75 }, ... ] }`

* `items` is the **application**-layer distribution (HTTP, TLS, QUIC, DNS, …). Each packet
  is counted once, so the packet counts sum to the analysis packet count.
* `transport_items` is the **transport**-layer distribution (TCP, UDP, ICMP, …). It is an
  additive field; clients that only need the application view can ignore it.

### `GET /api/analysis/{analysis_id}/hosts`

Response: `{ "items": [ { "ip": "10.0.0.5", "packets": 120, "bytes_sent": 8000, "bytes_received": 40000, "total_bytes": 48000, "protocols": ["HTTP"] } ], "total": 12 }`

### `GET /api/analysis/{analysis_id}/export/packets.csv`

* `text/csv`, `Content-Disposition: attachment; filename="packets-<id>.csv"`.
* Columns in the exact order of `NormalizedPacket` field order from `SCHEMA.md`.
* `null` values are written as an empty cell.
* Honours the same filter query parameters as `/packets`; `limit`/`offset` are ignored
  when `all=true` is passed (default: export every packet of the analysis).

### `GET /api/analysis/{analysis_id}/export/summary.json`

* `application/json`, `Content-Disposition: attachment; filename="summary-<id>.json"`.
* Body: the full `CaptureSummary` plus `"analysis_id"`.

### `GET /api/analysis/samples`

Lists the sample captures that ship with the project, so the UI can offer a
"Try sample" button that works without the user having a capture file.

```json
{
  "samples": [
    {
      "name": "sample_real_traffic.pcapng",
      "description": "A real capture of 1 150 packets taken from a home network: plaintext HTTP, TLS with a server name, DNS and bulk TCP traffic.",
      "size_bytes": 1118620,
      "kind": "pcapng"
    }
  ],
  "count": 1
}
```

### `POST /api/analysis/samples/{name}`

Analyses one of the bundled samples and returns the same body as
`POST /api/analysis/upload` (`AnalysisUploadResult`, HTTP 201). An unknown name is
`404`; a name that tries to escape the sample folder is rejected.

## 4. Route summary

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/health` | Liveness + toolchain report. |
| GET | `/api/capture/status` | Live capture state. |
| GET | `/api/capture/interfaces` | List capture interfaces. |
| POST | `/api/capture/start` | Start a live capture. |
| POST | `/api/capture/stop` | Stop the live capture and analyse it. |
| GET | `/api/analysis/samples` | List the bundled sample captures. |
| POST | `/api/analysis/samples/{name}` | Analyse a bundled sample capture. |
| POST | `/api/analysis/upload` | Upload a pcap/pcapng/CSV and analyse it. |
| GET | `/api/analysis/{id}/summary` | Capture summary statistics. |
| GET | `/api/analysis/{id}/packets` | Paginated, filterable packet table. |
| GET | `/api/analysis/{id}/protocols` | Protocol distribution. |
| GET | `/api/analysis/{id}/hosts` | Host/conversation table. |
| GET | `/api/analysis/{id}/export/packets.csv` | CSV export. |
| GET | `/api/analysis/{id}/export/summary.json` | JSON summary export. |

## 5. Frontend integration rules

* The React app calls only the routes above. It never receives the whole packet array
  in one response — it always pages.
* The dev server proxies `/api` → `http://localhost:8000` (Vite `server.proxy`).
* The API base URL is overridable at build time with `VITE_API_BASE_URL`.
* The UI must render a clear message when `tshark.available` is `false` (offline analysis
  still works) and when an analysis fails, using the `error.message` text.
