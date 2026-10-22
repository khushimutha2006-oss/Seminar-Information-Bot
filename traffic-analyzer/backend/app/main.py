"""FastAPI application for the HTTP/HTTPS traffic analyzer.

Entry point: ``uvicorn app.main:app --reload`` from the ``backend`` directory.
"""

from __future__ import annotations

import logging
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from .config import APP_VERSION, CONTRACT_VERSION, CORS_ORIGINS, ensure_directories
from .routers import analysis, capture, health
from .services.store import store

logger = logging.getLogger("traffic_analyzer.api")

_STARTED_AT = time.time()


@asynccontextmanager
async def lifespan(app: FastAPI):
    ensure_directories()
    restored = store.rehydrate()
    if restored:
        print(f"[traffic-analyzer] restored {restored} analysis(es) from disk")
    yield


app = FastAPI(
    title="Traffic Analyzer API",
    description=(
        "Backend for the Python-based HTTP/HTTPS traffic analyzer. "
        f"Contract {CONTRACT_VERSION} - see traffic-analyzer/docs/API.md."
    ),
    version=APP_VERSION,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS or ["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    """Render every HTTP error with the contract's error envelope."""
    detail = exc.detail
    code = {
        400: "invalid_request",
        404: "not_found",
        405: "not_found",
        409: "conflict",
        413: "payload_too_large",
        415: "unsupported_media_type",
        422: "validation_error",
        503: "unavailable",
    }.get(exc.status_code, "internal_error" if exc.status_code >= 500 else "invalid_request")
    if isinstance(detail, dict):
        message = str(detail.get("message", detail))
        extra = {k: v for k, v in detail.items() if k != "message"}
    else:
        message = str(detail)
        extra = {}
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": {"code": code, "message": message, "detail": extra}},
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=422,
        content={
            "error": {
                "code": "validation_error",
                "message": "Request validation failed.",
                "detail": {"errors": _safe_errors(exc.errors())},
            }
        },
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    """Last resort handler.

    The technical detail (type and traceback) stays in the server log; the client
    only learns that something went wrong, so no internal detail is leaked.
    """
    logger.exception("unhandled error while serving %s %s", request.method, request.url.path)
    return JSONResponse(
        status_code=500,
        content={
            "error": {
                "code": "internal_error",
                "message": (
                    "The server hit an unexpected problem. The details are in the "
                    "server log; the analysis can be retried."
                ),
                "detail": {},
            }
        },
    )


def _safe_errors(errors: list) -> list:
    """Strip non-serialisable values out of pydantic error payloads."""
    safe = []
    for error in errors:
        item = {key: value for key, value in error.items() if key != "ctx"}
        item["loc"] = [str(part) for part in error.get("loc", [])]
        safe.append(item)
    return safe


app.include_router(health.router, prefix="/api", tags=["health"])
app.include_router(capture.router, prefix="/api/capture", tags=["capture"])
app.include_router(analysis.router, prefix="/api/analysis", tags=["analysis"])


@app.get("/", include_in_schema=False)
async def root():
    return {
        "name": "Traffic Analyzer API",
        "version": APP_VERSION,
        "contract_version": CONTRACT_VERSION,
        "docs": "/docs",
        "health": "/api/health",
    }
