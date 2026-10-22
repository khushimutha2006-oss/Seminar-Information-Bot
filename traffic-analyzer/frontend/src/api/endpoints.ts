/**
 * Typed wrappers around every route of the contract (`docs/API.md` §4).
 * The app calls only these functions.
 */

import { apiUrl, postJson, requestJson, uploadFile } from './client';
import type { UploadProgress } from './client';
import { buildExportQuery, buildPacketQuery } from './params';
import type { PacketFilters, QueryOptions } from './params';
import type {
  AnalysisUploadResult,
  CaptureInterfacesResponse,
  CaptureStartRequest,
  CaptureStartResponse,
  CaptureStatus,
  CaptureStopRequest,
  CaptureStopResponse,
  HealthResponse,
  HostPage,
  PacketPage,
  ProtocolPage,
  CaptureSummary,
  SamplePage,
} from './types';

export function getHealth(): Promise<HealthResponse> {
  return requestJson<HealthResponse>('/api/health');
}

export function getCaptureStatus(): Promise<CaptureStatus> {
  return requestJson<CaptureStatus>('/api/capture/status');
}

export function getCaptureInterfaces(): Promise<CaptureInterfacesResponse> {
  return requestJson<CaptureInterfacesResponse>('/api/capture/interfaces');
}

export function startCapture(body: CaptureStartRequest): Promise<CaptureStartResponse> {
  return postJson<CaptureStartResponse>('/api/capture/start', body);
}

export function stopCapture(body: CaptureStopRequest): Promise<CaptureStopResponse> {
  return postJson<CaptureStopResponse>('/api/capture/stop', body);
}

export function uploadAnalysisFile(
  file: File,
  onProgress: (progress: UploadProgress) => void,
): Promise<AnalysisUploadResult> {
  return uploadFile<AnalysisUploadResult>('/api/analysis/upload', file, onProgress);
}

export function getSamples(): Promise<SamplePage> {
  return requestJson<SamplePage>('/api/analysis/samples');
}

export function analyseSample(name: string): Promise<AnalysisUploadResult> {
  return postJson<AnalysisUploadResult>(`/api/analysis/samples/${encodeURIComponent(name)}`, {});
}

export function getSummary(analysisId: string): Promise<CaptureSummary> {
  return requestJson<CaptureSummary>(`/api/analysis/${encodeURIComponent(analysisId)}/summary`);
}

export function getPackets(
  analysisId: string,
  filters: PacketFilters,
  options: QueryOptions = {},
): Promise<PacketPage> {
  const query = buildPacketQuery(filters, options);
  return requestJson<PacketPage>(
    `/api/analysis/${encodeURIComponent(analysisId)}/packets${query}`,
  );
}

export function getProtocols(analysisId: string): Promise<ProtocolPage> {
  return requestJson<ProtocolPage>(`/api/analysis/${encodeURIComponent(analysisId)}/protocols`);
}

export function getHosts(analysisId: string): Promise<HostPage> {
  return requestJson<HostPage>(`/api/analysis/${encodeURIComponent(analysisId)}/hosts`);
}

export type ExportKind = 'packets.csv' | 'summary.json';

/**
 * URL for the export endpoints. The browser handles the download; the query
 * string carries the filters that are currently applied in the packet explorer.
 */
export function exportUrl(analysisId: string, kind: ExportKind, filters: PacketFilters): string {
  const query = buildExportQuery(filters);
  return apiUrl(`/api/analysis/${encodeURIComponent(analysisId)}/export/${kind}${query}`);
}
