"""Canonical data models for the traffic analyzer contract v1.

Field names, types and units are defined in `traffic-analyzer/docs/SCHEMA.md`.
This module is the executable contract: other modules import from here and must not
redefine these shapes.
"""

from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, Field

TransportProtocol = Literal["TCP", "UDP", "ICMP", "ICMPv6", "ARP", "SCTP", "OTHER"]

ApplicationProtocol = Literal[
    "HTTP",
    "TLS",
    "QUIC",
    "DNS",
    "TCP",
    "UDP",
    "ICMP",
    "ICMPv6",
    "ARP",
    "SCTP",
    "OTHER",
]


class NormalizedPacket(BaseModel):
    """One packet, normalised across every ingestion path.

    Fields that the capture does not provide are ``None``. Nothing is invented.
    """

    frame_number: int = Field(..., ge=1, description="1-based frame ordinal in the capture")
    timestamp: str = Field(..., description="ISO-8601 UTC timestamp, microsecond precision")
    timestamp_epoch: float = Field(..., description="Unix epoch seconds, float")
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_port: Optional[int] = Field(default=None, ge=0, le=65535)
    destination_port: Optional[int] = Field(default=None, ge=0, le=65535)
    transport_protocol: Optional[TransportProtocol] = None
    application_protocol: Optional[ApplicationProtocol] = None
    captured_frame_length: int = Field(..., ge=0, description="Bytes on the wire for the frame")
    ip_packet_length: Optional[int] = Field(default=None, ge=0, description="IP datagram size in bytes")
    tcp_flags: Optional[str] = None
    tcp_stream_id: Optional[int] = Field(default=None, ge=0)
    http_method: Optional[str] = None
    http_status_code: Optional[int] = Field(default=None, ge=100, le=599)
    tls_version: Optional[str] = None
    server_name: Optional[str] = None
    inter_packet_interval_seconds: Optional[float] = None
    is_encrypted: bool = False
    protocols: list[str] = Field(default_factory=list)
    info: Optional[str] = None
    source_file: Optional[str] = None
    ip_version: Optional[int] = Field(default=None, ge=4, le=6)
    direction_hint: Literal["outbound", "inbound", "unknown"] = "unknown"

    # Optional honesty extras (contract v1.1). They never replace the fields above;
    # they explain how the classification was reached so the UI can show uncertainty.
    detected_protocol: Optional[str] = Field(
        default=None, description="Raw protocol name reported by the dissector, if any"
    )
    protocol_confidence: Optional[str] = Field(
        default=None, description="How certain the application protocol is: high | medium | low | unknown"
    )
    protocol_evidence: list[str] = Field(
        default_factory=list, description="Short reasons that produced the application protocol"
    )
    quic_version: Optional[str] = Field(default=None, description="QUIC version when observed")
    timestamp_has_date: bool = Field(
        default=True,
        description="False when the source only carried a time of day, so no date was invented",
    )



class ProtocolCount(BaseModel):
    protocol: str
    packets: int = Field(..., ge=0)
    bytes: int = Field(..., ge=0)
    percentage: float = Field(..., ge=0, le=100)


class HttpStatusCount(BaseModel):
    status_code: int = Field(..., ge=100, le=599)
    packets: int = Field(..., ge=0)
    percentage: float = Field(..., ge=0, le=100)


class HostEntry(BaseModel):
    ip: str
    packets: int = Field(..., ge=0)
    bytes_sent: int = Field(..., ge=0)
    bytes_received: int = Field(..., ge=0)
    total_bytes: int = Field(..., ge=0)
    protocols: list[str] = Field(default_factory=list)


class ConversationEntry(BaseModel):
    source_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_ip: Optional[str] = None
    destination_port: Optional[int] = None
    transport_protocol: Optional[str] = None
    packets: int = Field(..., ge=0)
    bytes: int = Field(..., ge=0)


class TimelineBucket(BaseModel):
    """One time bucket of the capture, used for the traffic-over-time chart."""

    timestamp: str = Field(..., description="ISO-8601 UTC start of the bucket")
    packets: int = Field(..., ge=0)
    bytes: int = Field(..., ge=0)


class SizeBucket(BaseModel):
    """One frame-size range of the capture, used for the size histogram."""

    label: str = Field(..., description="Human readable range, e.g. '128-255'")
    min_bytes: Optional[int] = Field(default=None, ge=0)
    max_bytes: Optional[int] = Field(default=None, ge=0)
    packets: int = Field(..., ge=0)
    bytes: int = Field(..., ge=0)


class CaptureSummary(BaseModel):
    analysis_id: str
    source_file: str
    source_kind: str = Field(..., description="pcap | pcapng | csv | live")
    created_at: str
    packet_count: int = Field(..., ge=0)
    total_bytes: int = Field(..., ge=0)
    duration_seconds: float = Field(..., ge=0)
    first_timestamp: Optional[str] = None
    last_timestamp: Optional[str] = None
    unique_hosts: int = Field(..., ge=0)
    encrypted_packet_count: int = Field(..., ge=0)
    http_request_count: int = Field(..., ge=0)
    http_response_count: int = Field(..., ge=0)
    protocol_counts: list[ProtocolCount] = Field(default_factory=list)
    application_protocol_counts: list[ProtocolCount] = Field(default_factory=list)
    http_status_counts: list[HttpStatusCount] = Field(default_factory=list)
    top_hosts: list[HostEntry] = Field(default_factory=list)
    conversations: list[ConversationEntry] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    timeline: list[TimelineBucket] = Field(
        default_factory=list,
        description="Traffic over time, computed over the whole capture (contract v1.2)",
    )
    size_distribution: list[SizeBucket] = Field(
        default_factory=list,
        description="Frame size ranges, computed over the whole capture (contract v1.2)",
    )


class PacketPage(BaseModel):
    items: list[NormalizedPacket]
    total: int = Field(..., ge=0)
    limit: int = Field(..., ge=1)
    offset: int = Field(..., ge=0)


class ProtocolPage(BaseModel):
    items: list[ProtocolCount]
    total: int = Field(..., ge=0)
    transport_items: list[ProtocolCount] = Field(
        default_factory=list,
        description="Transport-layer distribution (TCP/UDP/ICMP/...); items holds the application view",
    )


class HostPage(BaseModel):
    items: list[HostEntry]
    total: int = Field(..., ge=0)


class AnalysisUploadResult(BaseModel):
    analysis_id: str
    status: Literal["complete", "partial"]
    source_file: str
    source_kind: str
    packet_count: int = Field(..., ge=0)
    total_bytes: int = Field(..., ge=0)
    warnings: list[str] = Field(default_factory=list)
    created_at: str


class SampleInfo(BaseModel):
    """One sample capture that ships with the project."""

    name: str
    description: str = ""
    size_bytes: int = Field(..., ge=0)
    kind: str = "pcap"


class SamplePage(BaseModel):
    samples: list[SampleInfo] = Field(default_factory=list)
    count: int = Field(..., ge=0)


class TSharkInfo(BaseModel):
    available: bool
    path: Optional[str] = None
    version: Optional[str] = None


class HealthResponse(BaseModel):
    status: Literal["ok", "degraded"]
    contract_version: str
    app_version: str
    tshark: TSharkInfo
    python: str
    uptime_seconds: float = Field(..., ge=0)


class CaptureStatus(BaseModel):
    running: bool = False
    capture_id: Optional[str] = None
    interface: Optional[str] = None
    started_at: Optional[str] = None
    stopped_at: Optional[str] = None
    packets_captured: int = 0
    packets_filtered: int = 0
    capture_file: Optional[str] = None
    filter: Optional[str] = None
    last_error: Optional[str] = None
    tshark_available: bool = False


class CaptureInterface(BaseModel):
    index: Optional[int] = None
    name: str
    description: Optional[str] = None
    is_loopback: bool = False
    addresses: list[str] = Field(default_factory=list)


class CaptureInterfacesResponse(BaseModel):
    source: Literal["tshark", "dumpcap", "none"]
    tshark_available: bool = False
    interfaces: list[CaptureInterface] = Field(default_factory=list)
    message: Optional[str] = Field(
        default=None,
        description="Why the list is empty or degraded, phrased for a beginner",
    )


class CaptureStartRequest(BaseModel):
    interface: str = Field(..., min_length=1, max_length=128)
    duration_seconds: Optional[int] = Field(default=None, ge=1, le=3600)
    filter: Optional[str] = Field(default=None, max_length=512)
    display_filter: Optional[str] = Field(default=None, max_length=512)


class CaptureStartResponse(BaseModel):
    status: Literal["running"] = "running"
    capture_id: str
    interface: str
    started_at: str
    filter: Optional[str] = None
    message: str


class CaptureStopRequest(BaseModel):
    capture_id: Optional[str] = None


class CaptureStopResponse(BaseModel):
    status: Literal["stopped"]
    capture_id: str
    packets_captured: int = 0
    capture_file: Optional[str] = None
    analysis_id: Optional[str] = None
    message: str
    error: Optional[str] = Field(
        default=None, description="Why the capture could not be analysed, if that happened"
    )


class ErrorBody(BaseModel):
    code: str
    message: str
    detail: dict = Field(default_factory=dict)


class ErrorResponse(BaseModel):
    error: ErrorBody
