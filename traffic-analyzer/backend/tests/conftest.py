"""Pytest configuration and shared fixtures.

Owned by the lead (integration). Test modules that need extra fixtures should define
them locally instead of editing this file, so parallel branches never conflict.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tests import support  # noqa: E402


@pytest.fixture()
def sample_pcap(tmp_path: Path) -> Path:
    """A classic pcap with an HTTP request/response pair and a DNS query."""
    return support.sample_http_capture(tmp_path / "sample.pcap")


@pytest.fixture()
def empty_pcap(tmp_path: Path) -> Path:
    """A valid but empty classic pcap."""
    return support.sample_empty_capture(tmp_path / "empty.pcap")


@pytest.fixture()
def sample_csv(tmp_path: Path) -> Path:
    """A CSV capture shaped like the analyzer's CSV export."""
    return support.write_csv_capture(tmp_path / "sample.csv")


@pytest.fixture()
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """FastAPI TestClient with an isolated data directory."""
    from app import config

    data_dir = tmp_path / "data"
    monkeypatch.setattr(config, "DATA_DIR", data_dir)
    monkeypatch.setattr(config, "ANALYSES_DIR", data_dir / "analyses")
    monkeypatch.setattr(config, "CAPTURES_DIR", data_dir / "captures")
    monkeypatch.setattr(config, "UPLOADS_DIR", data_dir / "uploads")
    config.ensure_directories()

    from app.main import app
    from app.services import store as store_module

    store_module.store._analyses.clear()

    from fastapi.testclient import TestClient

    with TestClient(app) as test_client:
        yield test_client
