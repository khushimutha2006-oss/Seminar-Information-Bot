"""Analysis router.

Provides capture upload, summary, packets explorer, protocol/host breakdowns,
and CSV/JSON export endpoints.
"""

from __future__ import annotations

import csv
import io
import json
import logging
import tempfile
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, File, Form, HTTPException, Query, Response, UploadFile
from starlette.responses import Response

from ..config import MAX_UPLOAD_BYTES, SAMPLE_CAPTURES_DIR, UPLOADS_DIR
from ..models.packet import (
    AnalysisUploadResult,
    CaptureSummary,
    HostPage,
    NormalizedPacket,
    PacketPage,
    ProtocolPage,
    SampleInfo,
    SamplePage,
)
from ..services import pipeline, stats
from ..services.pipeline import CaptureNotReadable, detect_source_kind, store_upload
from ..services.store import Analysis, new_analysis_id, store, utc_now_iso

router = APIRouter()
LOGGER = logging.getLogger("traffic_analyzer.analysis")

SCHEMA_EXPORT_COLUMNS = [
    "frame_number",
    "timestamp",
    "timestamp_epoch",
    "source_ip",
    "destination_ip",
    "source_port",
    "destination_port",
    "transport_protocol",
    "application_protocol",
    "captured_frame_length",
    "ip_packet_length",
    "tcp_flags",
    "tcp_stream_id",
    "http_method",
    "http_status_code",
    "tls_version",
    "server_name",
    "inter_packet_interval_seconds",
    "is_encrypted",
    "protocols",
    "info",
    "source_file",
    "ip_version",
    "direction_hint",
]


@router.post("/upload", response_model=AnalysisUploadResult, status_code=201)
async def upload_capture(
    file: UploadFile = File(...),
    format: Optional[str] = Form(default="auto"),
) -> AnalysisUploadResult:
    filename = file.filename or "upload"
    if ".." in filename or "/" in filename or "\\" in filename:
        raise HTTPException(
            status_code=400,
            detail={"message": f"Path traversal in filename '{filename}' is forbidden.", "filename": filename},
        )
    # Read content and check size
    content = await file.read()
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=413,
            detail={"message": f"File size exceeds maximum allowed upload ({MAX_UPLOAD_BYTES} bytes).", "size": len(content)},
        )

    # Save to a temporary file first for detection and validation
    with tempfile.NamedTemporaryFile(delete=False, suffix=Path(filename).suffix) as tmp:
        tmp.write(content)
        tmp_path = Path(tmp.name)

    try:
        source_kind = detect_source_kind(tmp_path)
        ext = Path(filename).suffix.lower()

        # Check supported formats
        if source_kind == "unknown" and ext not in (".pcap", ".pcapng", ".cap", ".csv"):
            raise HTTPException(
                status_code=415,
                detail={"message": f"Unsupported media type for '{filename}'. Allowed: .pcap, .pcapng, .cap, .csv", "filename": filename},
            )

        if source_kind == "unknown" and len(content) == 0:
            # Empty file
            if ext in (".pcap", ".pcapng", ".cap"):
                source_kind = "pcap"
            elif ext == ".csv":
                source_kind = "csv"
            else:
                raise HTTPException(
                    status_code=400,
                    detail={"message": f"Empty or unparsable file '{filename}'", "filename": filename},
                )

        # Store permanently in UPLOADS_DIR, keeping the name the user uploaded under
        dest_path = store_upload(tmp_path, UPLOADS_DIR, original_name=filename)

        # Ingest capture
        try:
            result = pipeline.load_any(dest_path)
            for p in result.packets:
                p.source_file = filename
        except CaptureNotReadable as exc:
            raise HTTPException(
                status_code=400,
                detail={"message": f"Could not read capture '{filename}': {exc}", "filename": filename},
            ) from exc
        except Exception as exc:
            # A malformed capture must be a useful client error, not an unhandled
            # 500. Keep the implementation detail in the server log.
            LOGGER.exception("unexpected capture parsing failure for uploaded file %s", filename)
            raise HTTPException(
                status_code=400,
                detail={"message": f"Could not analyse capture '{filename}'. The file may be malformed or unsupported.", "filename": filename},
            ) from exc

        # Create Analysis record
        a_id = new_analysis_id()
        created_at = utc_now_iso()
        analysis = Analysis(
            analysis_id=a_id,
            source_file=filename,
            source_kind=result.source_kind,
            created_at=created_at,
            packets=result.packets,
            warnings=result.warnings,
            source_path=str(dest_path),
        )
        store.put(analysis)

        return AnalysisUploadResult(
            analysis_id=a_id,
            status="complete",
            source_file=filename,
            source_kind=result.source_kind,
            packet_count=len(result.packets),
            total_bytes=result.total_bytes,
            warnings=result.warnings,
            created_at=created_at,
        )
    finally:
        if tmp_path.exists():
            tmp_path.unlink()


def _get_analysis_or_404(analysis_id: str) -> Analysis:
    analysis = store.get(analysis_id)
    if not analysis:
        raise HTTPException(
            status_code=404,
            detail={"message": f"Analysis '{analysis_id}' does not exist.", "analysis_id": analysis_id},
        )
    return analysis


# Sample captures that ship with the project. The "Try sample" button in the UI
# analyses one of them, so a beginner can see the full workflow without having a
# capture file at hand.
SAMPLE_DESCRIPTIONS = {
    "demo_traffic.pcap": "A tiny synthetic capture with an HTTP request, an HTTP response and a DNS query.",
    "sample_real_traffic.pcapng": (
        "A real capture of 1 150 packets taken from a home network: plaintext HTTP, "
        "TLS with a server name, DNS and bulk TCP traffic."
    ),
    "demo_traffic.csv": "The same tiny capture in CSV form, to show the spreadsheet import.",
}


@router.get("/samples", response_model=SamplePage)
async def list_samples() -> SamplePage:
    """List the sample captures that ship with the project."""
    samples: list[SampleInfo] = []
    if SAMPLE_CAPTURES_DIR.is_dir():
        for path in sorted(SAMPLE_CAPTURES_DIR.iterdir()):
            if path.suffix.lower() not in {".pcap", ".pcapng", ".cap", ".csv"}:
                continue
            samples.append(
                SampleInfo(
                    name=path.name,
                    description=SAMPLE_DESCRIPTIONS.get(path.name, "A sample capture."),
                    size_bytes=path.stat().st_size,
                    kind=path.suffix.lstrip(".").lower(),
                )
            )
    return SamplePage(samples=samples, count=len(samples))


@router.post("/samples/{name}", response_model=AnalysisUploadResult, status_code=201)
async def analyse_sample(name: str) -> AnalysisUploadResult:
    """Analyse one of the bundled sample captures and return the analysis."""
    safe_name = Path(name).name
    if safe_name != name or "/" in name or "\\" in name or ".." in name:
        raise HTTPException(
            status_code=400,
            detail={"message": "Invalid sample name.", "name": name},
        )
    path = SAMPLE_CAPTURES_DIR / safe_name
    if not path.is_file():
        raise HTTPException(
            status_code=404,
            detail={"message": f"The sample '{safe_name}' does not exist.", "name": safe_name},
        )
    try:
        result = pipeline.load_any(path)
    except CaptureNotReadable as exc:
        raise HTTPException(
            status_code=400,
            detail={"message": f"The sample '{safe_name}' could not be read: {exc}", "name": safe_name},
        ) from exc

    analysis = Analysis(
        analysis_id=new_analysis_id(),
        source_file=safe_name,
        source_kind=result.source_kind,
        created_at=utc_now_iso(),
        packets=result.packets,
        warnings=result.warnings,
        source_path=str(path),
    )
    store.put(analysis)
    return AnalysisUploadResult(
        analysis_id=analysis.analysis_id,
        status="complete",
        source_file=safe_name,
        source_kind=result.source_kind,
        packet_count=len(result.packets),
        total_bytes=result.total_bytes,
        warnings=result.warnings,
        created_at=analysis.created_at,
    )


@router.get("/{analysis_id}/summary", response_model=CaptureSummary)
async def get_summary(analysis_id: str) -> CaptureSummary:
    analysis = _get_analysis_or_404(analysis_id)
    return stats.build_summary(
        analysis_id=analysis.analysis_id,
        source_file=analysis.source_file,
        source_kind=analysis.source_kind,
        packets=analysis.packets,
        warnings=analysis.warnings,
        created_at=analysis.created_at,
    )


@router.get("/{analysis_id}/packets", response_model=PacketPage)
async def get_packets(
    analysis_id: str,
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    q: Optional[str] = None,
    protocol: Optional[str] = None,
    transport: Optional[str] = None,
    src_ip: Optional[str] = None,
    dst_ip: Optional[str] = None,
    src_port: Optional[int] = None,
    dst_port: Optional[int] = None,
    method: Optional[str] = None,
    status_code: Optional[int] = None,
    min_bytes: Optional[int] = None,
    max_bytes: Optional[int] = None,
    start: Optional[str] = None,
    end: Optional[str] = None,
    encrypted: Optional[bool] = None,
    order_by: str = Query(default="frame_number"),
    order_dir: str = Query(default="asc"),
) -> PacketPage:
    analysis = _get_analysis_or_404(analysis_id)
    filtered = stats.filter_packets(
        analysis.packets,
        q=q,
        protocol=protocol,
        transport=transport,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        method=method,
        status_code=status_code,
        min_bytes=min_bytes,
        max_bytes=max_bytes,
        start=start,
        end=end,
        encrypted=encrypted,
        order_by=order_by,
        order_dir=order_dir,
    )
    total = len(filtered)
    page_items = filtered[offset : offset + limit]
    return PacketPage(
        items=page_items,
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/{analysis_id}/protocols", response_model=ProtocolPage)
async def get_protocols(analysis_id: str) -> ProtocolPage:
    """Application protocol distribution, with the transport layer alongside it."""
    analysis = _get_analysis_or_404(analysis_id)
    app_protos = stats.application_protocol_counts(analysis.packets)
    transport_protos = stats.protocol_counts(analysis.packets)
    return ProtocolPage(
        items=app_protos,
        total=len(app_protos),
        transport_items=transport_protos,
    )


@router.get("/{analysis_id}/hosts", response_model=HostPage)
async def get_hosts(analysis_id: str) -> HostPage:
    analysis = _get_analysis_or_404(analysis_id)
    hosts = stats.host_counts(analysis.packets)
    return HostPage(items=hosts, total=len(hosts))


@router.get("/{analysis_id}/export/packets.csv")
async def export_packets_csv(
    analysis_id: str,
    all: bool = Query(default=True),
    limit: int = Query(default=100, ge=1),
    offset: int = Query(default=0, ge=0),
    q: Optional[str] = None,
    protocol: Optional[str] = None,
    transport: Optional[str] = None,
    src_ip: Optional[str] = None,
    dst_ip: Optional[str] = None,
    src_port: Optional[int] = None,
    dst_port: Optional[int] = None,
    method: Optional[str] = None,
    status_code: Optional[int] = None,
    min_bytes: Optional[int] = None,
    max_bytes: Optional[int] = None,
    start: Optional[str] = None,
    end: Optional[str] = None,
    encrypted: Optional[bool] = None,
    order_by: str = Query(default="frame_number"),
    order_dir: str = Query(default="asc"),
) -> Response:
    analysis = _get_analysis_or_404(analysis_id)
    filtered = stats.filter_packets(
        analysis.packets,
        q=q,
        protocol=protocol,
        transport=transport,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        method=method,
        status_code=status_code,
        min_bytes=min_bytes,
        max_bytes=max_bytes,
        start=start,
        end=end,
        encrypted=encrypted,
        order_by=order_by,
        order_dir=order_dir,
    )

    if not all:
        target_packets = filtered[offset : offset + limit]
    else:
        target_packets = filtered

    output = io.StringIO()
    writer = csv.writer(output, lineterminator="\n")
    writer.writerow(SCHEMA_EXPORT_COLUMNS)

    for p in target_packets:
        row = []
        for col in SCHEMA_EXPORT_COLUMNS:
            val = getattr(p, col, None)
            if val is None:
                row.append("")
            elif col == "protocols":
                row.append(":".join(val) if isinstance(val, list) else str(val))
            elif isinstance(val, bool):
                row.append("true" if val else "false")
            else:
                row.append(str(val))
        writer.writerow(row)

    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="packets-{analysis_id}.csv"'},
    )


@router.get("/{analysis_id}/export/summary.json")
async def export_summary_json(analysis_id: str) -> Response:
    analysis = _get_analysis_or_404(analysis_id)
    summary = stats.build_summary(
        analysis_id=analysis.analysis_id,
        source_file=analysis.source_file,
        source_kind=analysis.source_kind,
        packets=analysis.packets,
        warnings=analysis.warnings,
        created_at=analysis.created_at,
    )
    body = summary.model_dump()
    return Response(
        content=json.dumps(body, indent=2),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="summary-{analysis_id}.json"'},
    )
