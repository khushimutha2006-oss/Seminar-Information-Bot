"""Application configuration.

Every value can be overridden with an environment variable so the app can run from a
container, a CI runner or a laptop without code changes.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Optional

APP_VERSION = "1.0.0"
CONTRACT_VERSION = "v1"

BASE_DIR = Path(__file__).resolve().parents[1]
DATA_DIR = Path(os.environ.get("TRAFFIC_ANALYZER_DATA_DIR", BASE_DIR / "data"))
ANALYSES_DIR = DATA_DIR / "analyses"
CAPTURES_DIR = DATA_DIR / "captures"
UPLOADS_DIR = DATA_DIR / "uploads"

# Sample captures that ship with the project, used by the "Try sample" button.
SAMPLE_CAPTURES_DIR = Path(
    os.environ.get("TRAFFIC_ANALYZER_SAMPLES_DIR", BASE_DIR.parent / "sample_captures")
)

HOST = os.environ.get("TRAFFIC_ANALYZER_HOST", "0.0.0.0")
PORT = int(os.environ.get("TRAFFIC_ANALYZER_PORT", "8000"))

# Maximum accepted upload size, bytes.
MAX_UPLOAD_BYTES = int(os.environ.get("TRAFFIC_ANALYZER_MAX_UPLOAD_BYTES", 256 * 1024 * 1024))

# Comma separated list of origins allowed by CORS.
CORS_ORIGINS = [
    origin.strip()
    for origin in os.environ.get(
        "TRAFFIC_ANALYZER_CORS_ORIGINS",
        "http://localhost:5174,http://127.0.0.1:5174,http://localhost:4173",
    ).split(",")
    if origin.strip()
]

# How long a tshark/dumpcap call may run before it is killed.
TSHARK_TIMEOUT_SECONDS = int(os.environ.get("TRAFFIC_ANALYZER_TSHARK_TIMEOUT", 300))
# Timeout for the short probe used to detect tshark.
TSHARK_PROBE_TIMEOUT_SECONDS = 10


def _resolve_tshark() -> Optional[str]:
    """Locate a tshark binary.

    Order: explicit env var, then PATH, then the usual absolute locations. Returning
    ``None`` is a supported state: offline analysis still works without tshark.
    """
    explicit = os.environ.get("TRAFFIC_ANALYZER_TSHARK")
    if explicit:
        candidate = Path(explicit)
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
        return None
    found = shutil.which("tshark")
    if found:
        return found
    for path in ("/usr/bin/tshark", "/usr/local/bin/tshark", "/opt/homebrew/bin/tshark"):
        candidate = Path(path)
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(path)
    return None


def _resolve_dumpcap() -> Optional[str]:
    explicit = os.environ.get("TRAFFIC_ANALYZER_DUMPCAP")
    if explicit:
        candidate = Path(explicit)
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
        return None
    found = shutil.which("dumpcap")
    if found:
        return found
    for path in ("/usr/bin/dumpcap", "/usr/local/bin/dumpcap"):
        candidate = Path(path)
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(path)
    return None


TSHARK_PATH: Optional[str] = _resolve_tshark()
DUMPCAP_PATH: Optional[str] = _resolve_dumpcap()


def tshark_version() -> Optional[str]:
    """Return the first line of ``tshark --version`` or ``None`` when unavailable."""
    if not TSHARK_PATH:
        return None
    try:
        completed = subprocess.run(
            [TSHARK_PATH, "--version"],
            capture_output=True,
            text=True,
            timeout=TSHARK_PROBE_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if completed.returncode != 0:
        return None
    first_line = (completed.stdout or "").strip().splitlines()
    return first_line[0].strip() if first_line else None


def ensure_directories() -> None:
    for directory in (DATA_DIR, ANALYSES_DIR, CAPTURES_DIR, UPLOADS_DIR):
        directory.mkdir(parents=True, exist_ok=True)
