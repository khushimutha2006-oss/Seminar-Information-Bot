"""Liveness and toolchain reporting."""

from __future__ import annotations

import platform
import time

from fastapi import APIRouter

from ..config import APP_VERSION, CONTRACT_VERSION, TSHARK_PATH, tshark_version
from ..models.packet import HealthResponse, TSharkInfo

router = APIRouter()

_STARTED_AT = time.time()


@router.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    """Report API liveness and whether TShark is usable on this host.

    A missing TShark is reported, not raised: offline analysis still works without it.
    """
    version = tshark_version()
    available = bool(TSHARK_PATH and version)
    return HealthResponse(
        status="ok",
        contract_version=CONTRACT_VERSION,
        app_version=APP_VERSION,
        tshark=TSharkInfo(
            available=available,
            path=TSHARK_PATH if available else None,
            version=version,
        ),
        python=platform.python_version(),
        uptime_seconds=round(time.time() - _STARTED_AT, 3),
    )
