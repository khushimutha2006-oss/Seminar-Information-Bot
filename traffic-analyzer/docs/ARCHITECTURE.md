# Architecture, Ownership and Working Rules

## 1. Component map

```
traffic-analyzer/
├── docs/
│   ├── SCHEMA.md          canonical normalized-packet contract      (lead, frozen)
│   ├── API.md             canonical HTTP contract                    (lead, frozen)
│   └── ARCHITECTURE.md    this file                                  (lead)
├── backend/
│   ├── app/
│   │   ├── main.py        FastAPI app, error envelope, CORS         (lead)
│   │   ├── config.py      settings, tool discovery                   (lead)
│   │   ├── models/        Pydantic contract models                  (lead)
│   │   ├── services/
│   │   │   ├── store.py       analysis registry + persistence       (lead)
│   │   │   ├── pcap_reader.py pure-python pcap/pcapng reader       (PacketCore)
│   │   │   ├── normalize.py   raw -> NormalizedPacket, protocol cls (PacketCore)
│   │   │   ├── stats.py       summary/protocol/host aggregates      (PacketCore)
│   │   │   ├── tshark.py      tshark adapter + live capture        (CaptureBridge)
│   │   │   └── csv_ingest.py  CSV ingestion                         (CaptureBridge)
│   │   └── routers/
│   │       ├── health.py      GET /api/health                       (lead)
│   │       ├── capture.py     live capture routes                   (CaptureBridge)
│   │       └── analysis.py    analysis routes                       (PacketCore)
│   └── tests/             pytest suite                              (see §3)
└── frontend/              React + TypeScript + Vite app              (InsightUI)
```

## 2. Data flow

```
pcap / pcapng / csv
        │
        ├── tshark adapter (CaptureBridge)  ──► field rows (dicts)
        └── pure-python reader (PacketCore) ──► RawFrame objects
                                │
                                ▼
                    normalize.py (PacketCore)
                                │  NormalizedPacket
                                ▼
                    stats.py (PacketCore)  ──► CaptureSummary / ProtocolCount / HostEntry
                                │
                                ▼
                    store.py (lead)  ──► analysis_id
                                │
                                ▼
                    routers/analysis.py (PacketCore) ──► JSON / CSV
```

The TShark path is preferred when the binary is available because it dissects protocols
the pure-python reader does not know. The pure-python reader is the fallback and the
basis of the hermetic unit tests.

## 3. File ownership (strict)

| Owner | Files |
|---|---|
| Lead | `app/main.py`, `app/config.py`, `app/models/**`, `app/services/store.py`, `app/routers/health.py`, `tests/conftest.py`, `tests/support.py`, `docs/**` |
| PacketCore | `app/services/pcap_reader.py`, `app/services/normalize.py`, `app/services/stats.py`, `app/routers/analysis.py`, `tests/test_pcap_reader.py`, `tests/test_normalize.py`, `tests/test_stats.py`, `tests/test_analysis_api.py` |
| CaptureBridge | `app/services/tshark.py`, `app/services/csv_ingest.py`, `app/routers/capture.py`, `tests/test_tshark.py`, `tests/test_capture_api.py`, `tests/test_csv_ingest.py` |
| InsightUI | everything under `frontend/` |
| QualityGuard | `tests/test_e2e.py`, `tests/test_security.py`, `docs/SECURITY.md`, frontend test tooling under `frontend/tests/` |

**Nobody edits a file owned by somebody else.** If a change to another owner's file is
unavoidable, describe it in the final report instead of making it.

## 4. Integration rules

* All work happens on a dedicated branch per specialist, branched from the contract
  commit. The lead merges branches into `feature/traffic-analyzer`.
* A branch is "integrated" only after the lead has merged it and re-run the test suite.
* The lead owns the final wiring: router registration, dependency versions, README,
  and the end-to-end acceptance run.

## 5. Shared definitions (do not duplicate)

* Timestamp format, byte definitions, protocol labels and nullability: `docs/SCHEMA.md`.
* Route shapes, query parameters, error envelope: `docs/API.md`.
* Pydantic models: `app/models/packet.py` — import from here, do not redefine.
* Test helpers: `tests/support.py` — import from here, do not redefine.

## 6. Frozen cross-module interfaces

These signatures are part of the contract. Implement them exactly — the lead's
`app/services/pipeline.py` composes them.

**`app/services/pcap_reader.py` (PacketCore)**

```python
@dataclass
class RawFrame:
    frame_number: int          # 1-based
    timestamp_epoch: float     # seconds
    captured_length: int       # bytes actually stored in the file
    original_length: int       # bytes on the wire
    link_type: int             # 1 = Ethernet
    data: bytes                # the stored bytes

def read_capture(path: str | Path) -> list[RawFrame]: ...
```

**`app/services/normalize.py` (PacketCore)**

```python
def normalize_tshark_rows(rows: list[dict[str, str]], source_file: str) -> tuple[list[NormalizedPacket], list[str]]: ...
def normalize_raw_frames(frames: list[RawFrame], source_file: str) -> tuple[list[NormalizedPacket], list[str]]: ...
```

`rows` maps a TShark field name to its string value; an empty string means "absent".

**`app/services/tshark.py` (CaptureBridge)**

```python
class TSharkUnavailable(RuntimeError): ...

def is_available() -> bool: ...
def tshark_version() -> str | None: ...
def dissect_file(path: str | Path) -> list[dict[str, str]]: ...   # raises TSharkUnavailable
def list_interfaces() -> list[dict]: ...
```

**`app/services/csv_ingest.py` (CaptureBridge)**

```python
def load_csv(path: str | Path) -> tuple[list[NormalizedPacket], list[str]]: ...
```

**`app/services/stats.py` (PacketCore)**

```python
def build_summary(analysis_id: str, source_file: str, source_kind: str,
                  packets: list[NormalizedPacket], warnings: list[str]) -> CaptureSummary: ...
def protocol_counts(packets: list[NormalizedPacket]) -> list[ProtocolCount]: ...
def host_counts(packets: list[NormalizedPacket]) -> list[HostEntry]: ...
def filter_packets(packets: list[NormalizedPacket], **filters) -> list[NormalizedPacket]: ...
```

**`app/services/pipeline.py` (lead)** — `load_capture`, `load_csv`, `load_any`,
`detect_source_kind`. It imports the services above lazily, so it keeps working while
the branches are still being merged.

## 7. How to run the backend
The system Python on this machine has an incompatible `httpx`/`starlette` pair, so use a
virtualenv. One shared interpreter is used by every worktree:

```bash
/home/abhaysawant/.venvs/traffic-analyzer/bin/python -m pytest        # from backend/
/home/abhaysawant/.venvs/traffic-analyzer/bin/python -m uvicorn app.main:app --port 8000
```

The main worktree also has its own copy in `backend/.venv` (git-ignored) for the demo.

## 8. Constraints that apply to everybody

* Unit tests must not require root, a live network, or a TShark installation. Tests that
  need TShark must skip cleanly when it is missing (`pytest.mark.skipif`).
* Never label encrypted traffic as HTTP. Port 443 alone proves nothing; UDP 443 is
  usually QUIC.
* Never fabricate a field. Unknown means `null`.
* Keep the server-side working on Node-less hosts: the backend must start with
  `uvicorn app.main:app` and no arguments.
