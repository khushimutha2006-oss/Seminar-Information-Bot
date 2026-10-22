"""Capture ingestion pipeline (composition layer).

OWNER: lead (integration). This module is the single place that turns a capture file
into normalized packets. It is written defensively so that it still works while the
individual service modules are being developed in parallel:

* TShark is preferred because it dissects protocols the built-in reader does not know.
* When TShark is unavailable (binary missing) the built-in pure-python reader is used.
* When neither service module is importable yet, a clear error is raised instead of an
  obscure `ImportError` at call time.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from ..models.packet import NormalizedPacket

PCAP_MAGICS = {
    b"\xa1\xb2\xc3\xd4",  # little endian, microsecond
    b"\xd4\xc3\xb2\xa1",  # big endian, microsecond
    b"\xa1\xb2\x3c\x4d",  # little endian, nanosecond
    b"\x4d\x3c\xb2\xa1",  # big endian, nanosecond
}
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"


@dataclass
class CaptureLoadResult:
    """Outcome of ingesting one capture file."""

    packets: list[NormalizedPacket] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    source_kind: str = "unknown"
    reader: str = "none"

    @property
    def total_bytes(self) -> int:
        return sum(packet.captured_frame_length for packet in self.packets)


class CaptureNotReadable(RuntimeError):
    """Raised when a capture file cannot be read by any available reader."""


def detect_source_kind(path: str | Path) -> str:
    """Classify a file as ``pcap``, ``pcapng``, ``csv`` or ``unknown`` by content."""
    file_path = Path(path)
    try:
        with file_path.open("rb") as handle:
            head = handle.read(8)
    except OSError as exc:
        # Only the file name is reported; absolute paths never leave the backend.
        raise CaptureNotReadable(f"Cannot open '{file_path.name}': {exc.strerror or exc}") from exc

    if head[:4] == PCAPNG_MAGIC:
        return "pcapng"
    if head[:4] in PCAP_MAGICS:
        return "pcap"
    if file_path.suffix.lower() == ".csv":
        return "csv"
    try:
        text = head.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return "unknown"
    if "," in text and any(char.isalpha() for char in text):
        return "csv"
    return "unknown"


def load_capture(path: str | Path, prefer_tshark: bool = True) -> CaptureLoadResult:
    """Load a pcap/pcapng file into normalized packets.

    Tries TShark first, falls back to the built-in pure-python reader. Raises
    :class:`CaptureNotReadable` when neither reader can handle the file.
    """
    file_path = Path(path)
    source_kind = detect_source_kind(file_path)
    if source_kind not in {"pcap", "pcapng"}:
        raise CaptureNotReadable(
            f"'{file_path.name}' is not a pcap/pcapng capture (detected: {source_kind})."
        )

    warnings: list[str] = []

    if prefer_tshark:
        tshark_error: Optional[str] = None
        try:
            from .tshark import TSharkUnavailable, dissect_file
        except ImportError:
            dissect_file = None  # type: ignore[assignment]
            TSharkUnavailable = RuntimeError  # type: ignore[misc, assignment]
        if dissect_file is not None:
            try:
                rows = dissect_file(file_path)
            except TSharkUnavailable as exc:
                tshark_error = str(exc)
            except (OSError, RuntimeError) as exc:
                tshark_error = str(exc)
            else:
                try:
                    from .normalize import normalize_tshark_rows
                except ImportError as exc:
                    raise CaptureNotReadable(
                        "The normalization service is not available yet: "
                        f"{exc}. Re-run once the analyzer core is integrated."
                    ) from exc
                packets, normalize_warnings = normalize_tshark_rows(
                    rows, source_file=file_path.name
                )
                warnings.extend(normalize_warnings)
                if tshark_error:
                    warnings.append(f"TShark fallback used: {tshark_error}")
                return CaptureLoadResult(
                    packets=packets,
                    warnings=warnings,
                    source_kind=source_kind,
                    reader="tshark",
                )

    try:
        from .normalize import normalize_raw_frames
        from .pcap_reader import read_capture
    except ImportError as exc:
        raise CaptureNotReadable(
            f"The built-in capture reader is not available yet: {exc}"
        ) from exc

    frames = read_capture(file_path)
    packets, reader_warnings = normalize_raw_frames(frames, source_file=file_path.name)
    warnings.extend(reader_warnings)
    if prefer_tshark:
        warnings.append(
            "TShark was not usable for this capture; the built-in reader was used instead."
        )
    return CaptureLoadResult(
        packets=packets,
        warnings=warnings,
        source_kind=source_kind,
        reader="python",
    )


def load_csv(path: str | Path) -> CaptureLoadResult:
    """Load a CSV export (or any CSV shaped like one) into normalized packets."""
    try:
        from .csv_ingest import load_csv as _load_csv
    except ImportError as exc:
        raise CaptureNotReadable(
            f"The CSV ingestion service is not available yet: {exc}"
        ) from exc
    packets, warnings = _load_csv(Path(path))
    return CaptureLoadResult(
        packets=packets,
        warnings=warnings,
        source_kind="csv",
        reader="csv",
    )


def load_any(path: str | Path, prefer_tshark: bool = True) -> CaptureLoadResult:
    """Load a capture or CSV file, choosing the reader from the file content."""
    source_kind = detect_source_kind(path)
    if source_kind == "csv":
        return load_csv(path)
    return load_capture(path, prefer_tshark=prefer_tshark)


def store_upload(
    source_path: str | Path, target_dir: str | Path, original_name: Optional[str] = None
) -> Path:
    """Copy an uploaded file into the uploads directory and return the new path.

    ``original_name`` keeps the name the user uploaded under, so the stored file and
    every error message refer to the file the user recognises. The name is reduced to
    its basename, so it can never escape ``target_dir``.
    """
    source = Path(source_path)
    target_dir = Path(target_dir)
    target_dir.mkdir(parents=True, exist_ok=True)
    safe_name = os.path.basename(original_name or source.name) or "upload"
    destination = target_dir / safe_name
    counter = 1
    while destination.exists():
        destination = target_dir / f"{Path(safe_name).stem}-{counter}{Path(safe_name).suffix}"
        counter += 1
    destination.write_bytes(source.read_bytes())
    return destination
