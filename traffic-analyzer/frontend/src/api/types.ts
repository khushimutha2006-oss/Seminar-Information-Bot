/**
 * TypeScript mirrors of the canonical Pydantic models in
 * `traffic-analyzer/backend/app/models/packet.py` (contract v1).
 *
 * Rules taken from `docs/SCHEMA.md`:
 *  - a field the capture does not contain is `null` (never 0, never "null");
 *  - `captured_frame_length` is the byte count used for every byte total;
 *  - protocol labels are the exact case-sensitive strings from SCHEMA.md §3.
 *
 * Do not rename fields without the lead's approval — this file is a contract mirror.
 */

export type TransportProtocol =
  | 'TCP'
  | 'UDP'
  | 'ICMP'
  | 'ICMPv6'
  | 'ARP'
  | 'SCTP'
  | 'OTHER';

export type ApplicationProtocol =
  | 'HTTP'
  | 'TLS'
  | 'QUIC'
  | 'DNS'
  | 'TCP'
  | 'UDP'
  | 'ICMP'
  | 'ICMPv6'
  | 'ARP'
  | 'SCTP'
  | 'OTHER';

export type DirectionHint = 'outbound' | 'inbound' | 'unknown';

/** How certain the classifier is about the application protocol (contract v1.1). */
export type ProtocolConfidence = 'high' | 'medium' | 'low' | 'unknown' | string;

export type ErrorCode =
  | 'invalid_request'
  | 'not_found'
  | 'conflict'
  | 'unsupported_media_type'
  | 'payload_too_large'
  | 'validation_error'
  | 'internal_error'
  | 'unavailable'
  | 'http_error'
  | 'network_error'
  | 'aborted'
  | 'invalid_response'
  | 'empty_response';

/** Body of the contract's error envelope: `{"error": {...}}`. */
export interface ErrorBody {
  code: ErrorCode | string;
  message: string;
  detail: Record<string, unknown>;
}

export interface ErrorResponse {
  error: ErrorBody;
}

export interface TSharkInfo {
  available: boolean;
  path: string | null;
  version: string | null;
}

export interface HealthResponse {
  status: 'ok' | 'degraded';
  contract_version: string;
  app_version: string;
  tshark: TSharkInfo;
  python: string;
  uptime_seconds: number;
}

export interface NormalizedPacket {
  frame_number: number;
  timestamp: string;
  timestamp_epoch: number;
  source_ip: string | null;
  destination_ip: string | null;
  source_port: number | null;
  destination_port: number | null;
  transport_protocol: TransportProtocol | string | null;
  application_protocol: ApplicationProtocol | string | null;
  /** Bytes on the wire for the whole frame (link header included). */
  captured_frame_length: number;
  /** IP datagram size only; null for non-IP frames. */
  ip_packet_length: number | null;
  tcp_flags: string | null;
  tcp_stream_id: number | null;
  http_method: string | null;
  http_status_code: number | null;
  tls_version: string | null;
  server_name: string | null;
  inter_packet_interval_seconds: number | null;
  is_encrypted: boolean;
  protocols: string[];
  info: string | null;
  source_file: string | null;
  ip_version: 4 | 6 | null;
  direction_hint: DirectionHint;

  /* Optional honesty extras (contract v1.1). A server may omit them entirely. */
  /** Raw protocol name reported by the dissector, if any. */
  detected_protocol?: string | null;
  /** How certain the application protocol is: high | medium | low | unknown. */
  protocol_confidence?: ProtocolConfidence | null;
  /** Short reasons that produced the application protocol. */
  protocol_evidence?: string[];
  /** QUIC version, when observed. */
  quic_version?: string | null;
  /** False when the source only carried a time of day, so no date was invented. */
  timestamp_has_date?: boolean;
}

export interface ProtocolCount {
  protocol: string;
  packets: number;
  bytes: number;
  percentage: number;
}

export interface HttpStatusCount {
  status_code: number;
  packets: number;
  percentage: number;
}

export interface HostEntry {
  ip: string;
  packets: number;
  bytes_sent: number;
  bytes_received: number;
  total_bytes: number;
  protocols: string[];
}

export interface ConversationEntry {
  source_ip: string | null;
  source_port: number | null;
  destination_ip: string | null;
  destination_port: number | null;
  transport_protocol: string | null;
  packets: number;
  bytes: number;
}

export interface TimelineBucket {
  timestamp: string;
  packets: number;
  bytes: number;
}

export interface SizeBucket {
  label: string;
  min_bytes: number | null;
  max_bytes: number | null;
  packets: number;
  bytes: number;
}

export interface SampleInfo {
  name: string;
  description: string;
  size_bytes: number;
  kind: string;
}

export interface SamplePage {
  samples: SampleInfo[];
  count: number;
}

export interface CaptureSummary {
  analysis_id: string;
  source_file: string;
  source_kind: string;
  created_at: string;
  packet_count: number;
  total_bytes: number;
  duration_seconds: number;
  first_timestamp: string | null;
  last_timestamp: string | null;
  unique_hosts: number;
  encrypted_packet_count: number;
  http_request_count: number;
  http_response_count: number;
  protocol_counts: ProtocolCount[];
  application_protocol_counts: ProtocolCount[];
  http_status_counts: HttpStatusCount[];
  top_hosts: HostEntry[];
  conversations: ConversationEntry[];
  warnings: string[];
  timeline: TimelineBucket[];
  size_distribution: SizeBucket[];
}

export interface PacketPage {
  items: NormalizedPacket[];
  total: number;
  limit: number;
  offset: number;
}

export interface ProtocolPage {
  items: ProtocolCount[];
  total: number;
}

export interface HostPage {
  items: HostEntry[];
  total: number;
}

export interface AnalysisUploadResult {
  analysis_id: string;
  status: 'complete' | 'partial';
  source_file: string;
  source_kind: string;
  packet_count: number;
  total_bytes: number;
  warnings: string[];
  created_at: string;
}

export interface CaptureStatus {
  running: boolean;
  capture_id: string | null;
  interface: string | null;
  started_at: string | null;
  stopped_at: string | null;
  packets_captured: number;
  packets_filtered: number;
  capture_file: string | null;
  filter: string | null;
  last_error: string | null;
  tshark_available: boolean;
}

export interface CaptureInterface {
  index: number | null;
  name: string;
  description: string | null;
  is_loopback: boolean;
  addresses: string[];
}

export interface CaptureInterfacesResponse {
  source: 'tshark' | 'dumpcap' | 'none';
  tshark_available: boolean;
  interfaces: CaptureInterface[];
  /** Plain-language reason when the list is unavailable or only a fallback. */
  message: string | null;
}

export interface CaptureStartRequest {
  interface: string;
  duration_seconds?: number | null;
  filter?: string | null;
  display_filter?: string | null;
}

export interface CaptureStartResponse {
  status: 'running';
  capture_id: string;
  interface: string;
  started_at: string;
  filter: string | null;
  message: string;
}

export interface CaptureStopRequest {
  capture_id?: string | null;
}

export interface CaptureStopResponse {
  status: 'stopped';
  capture_id: string;
  packets_captured: number;
  capture_file: string | null;
  analysis_id: string | null;
  message: string;
}
