"""In-memory + on-disk store for analyses.

The process-local dict is authoritative while the app runs. Every analysis is also
written to ``data/analyses/<analysis_id>/`` so results survive a restart (re-hydration
is best effort and never blocks startup).
"""

from __future__ import annotations

import json
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from ..config import ANALYSES_DIR, ensure_directories
from ..models.packet import NormalizedPacket


def utc_now_iso() -> str:
    """Current UTC time as ISO-8601 with microsecond precision and a `Z` suffix."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


def new_analysis_id() -> str:
    return uuid.uuid4().hex


@dataclass
class Analysis:
    analysis_id: str
    source_file: str
    source_kind: str
    created_at: str
    packets: list[NormalizedPacket] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    source_path: Optional[str] = None

    @property
    def total_bytes(self) -> int:
        return sum(packet.captured_frame_length for packet in self.packets)

    def directory(self) -> Path:
        return ANALYSES_DIR / self.analysis_id


class AnalysisStore:
    """Thread-safe registry of analyses."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._analyses: dict[str, Analysis] = {}

    def create(
        self,
        source_file: str,
        source_kind: str,
        packets: list[NormalizedPacket],
        warnings: Optional[list[str]] = None,
        source_path: Optional[str] = None,
        analysis_id: Optional[str] = None,
    ) -> Analysis:
        analysis = Analysis(
            analysis_id=analysis_id or new_analysis_id(),
            source_file=source_file,
            source_kind=source_kind,
            created_at=utc_now_iso(),
            packets=list(packets),
            warnings=list(warnings or []),
            source_path=source_path,
        )
        with self._lock:
            self._analyses[analysis.analysis_id] = analysis
        self.persist(analysis)
        return analysis

    def put(self, analysis: Analysis) -> Analysis:
        with self._lock:
            self._analyses[analysis.analysis_id] = analysis
        self.persist(analysis)
        return analysis

    def get(self, analysis_id: str) -> Optional[Analysis]:
        with self._lock:
            return self._analyses.get(analysis_id)

    def list(self) -> list[Analysis]:
        with self._lock:
            return sorted(self._analyses.values(), key=lambda item: item.created_at, reverse=True)

    def remove(self, analysis_id: str) -> bool:
        with self._lock:
            return self._analyses.pop(analysis_id, None) is not None

    # ---------------------------------------------------------------- persistence

    def persist(self, analysis: Analysis) -> None:
        """Write the analysis to disk. Failures are non-fatal (the app keeps running)."""
        try:
            ensure_directories()
            directory = analysis.directory()
            directory.mkdir(parents=True, exist_ok=True)
            meta = {
                "analysis_id": analysis.analysis_id,
                "source_file": analysis.source_file,
                "source_kind": analysis.source_kind,
                "created_at": analysis.created_at,
                "packet_count": len(analysis.packets),
                "total_bytes": analysis.total_bytes,
                "warnings": analysis.warnings,
                "source_path": analysis.source_path,
            }
            (directory / "meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
            with (directory / "packets.jsonl").open("w", encoding="utf-8") as handle:
                for packet in analysis.packets:
                    handle.write(packet.model_dump_json())
                    handle.write("\n")
        except OSError:
            return

    def rehydrate(self) -> int:
        """Reload persisted analyses at startup. Returns the number restored."""
        restored = 0
        try:
            ensure_directories()
            directories = sorted(p for p in ANALYSES_DIR.iterdir() if p.is_dir())
        except OSError:
            return 0
        for directory in directories:
            meta_path = directory / "meta.json"
            packets_path = directory / "packets.jsonl"
            if not meta_path.is_file() or not packets_path.is_file():
                continue
            try:
                meta = json.loads(meta_path.read_text(encoding="utf-8"))
                packets = []
                with packets_path.open("r", encoding="utf-8") as handle:
                    for line in handle:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            packets.append(NormalizedPacket.model_validate_json(line))
                        except ValueError:
                            continue
                analysis = Analysis(
                    analysis_id=meta.get("analysis_id", directory.name),
                    source_file=meta.get("source_file", directory.name),
                    source_kind=meta.get("source_kind", "pcap"),
                    created_at=meta.get("created_at", utc_now_iso()),
                    packets=packets,
                    warnings=list(meta.get("warnings", [])),
                    source_path=meta.get("source_path"),
                )
            except (OSError, ValueError, TypeError):
                continue
            with self._lock:
                self._analyses[analysis.analysis_id] = analysis
            restored += 1
        return restored


store = AnalysisStore()
