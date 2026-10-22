/** Presentation helpers. All of them are honest about missing data. */

/** The placeholder used wherever the capture did not provide a value. */
export const DASH = '—';

/** `null`/`undefined`/empty string become an em dash; a real 0 stays 0. */
export function dash(value: string | number | null | undefined): string {
  if (value === null || value === undefined) return DASH;
  if (typeof value === 'string' && value.trim().length === 0) return DASH;
  return String(value);
}

const BYTE_UNITS = ['B', 'KB', 'MB', 'GB', 'TB'];

export function formatBytes(bytes: number | null | undefined): string {
  if (bytes === null || bytes === undefined || !Number.isFinite(bytes)) return DASH;
  if (bytes === 0) return '0 B';
  const sign = bytes < 0 ? '-' : '';
  let value = Math.abs(bytes);
  let unit = 0;
  while (value >= 1024 && unit < BYTE_UNITS.length - 1) {
    value /= 1024;
    unit += 1;
  }
  const decimals = value >= 100 || unit === 0 ? 0 : 1;
  return `${sign}${value.toFixed(decimals)} ${BYTE_UNITS[unit]}`;
}

/** Exact byte count with a thousands separator, for the "bytes on the wire" card. */
export function formatExactBytes(bytes: number | null | undefined): string {
  if (bytes === null || bytes === undefined || !Number.isFinite(bytes)) return DASH;
  return `${bytes.toLocaleString('en-US')} bytes`;
}

export function formatDuration(seconds: number | null | undefined): string {
  if (seconds === null || seconds === undefined || !Number.isFinite(seconds)) return DASH;
  if (seconds < 1) return `${(seconds * 1000).toFixed(0)} ms`;
  if (seconds < 60) return `${seconds.toFixed(3)} s`;
  const minutes = Math.floor(seconds / 60);
  const rest = seconds - minutes * 60;
  if (minutes < 60) return `${minutes} min ${rest.toFixed(1)} s`;
  const hours = Math.floor(minutes / 60);
  return `${hours} h ${String(minutes % 60).padStart(2, '0')} min`;
}

export function formatPercent(value: number | null | undefined): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return DASH;
  return `${value.toFixed(2)}%`;
}

/**
 * Render an ISO-8601 UTC timestamp. The table is narrow, so the visible part is
 * the time of day; the full value stays available in the `title` attribute.
 */
export function formatTimestamp(iso: string | null | undefined): string {
  if (!iso) return DASH;
  const match = /T(\d{2}:\d{2}:\d{2}(?:\.\d+)?)/.exec(iso);
  return match ? (match[1] ?? iso) : iso;
}

export function formatFullTimestamp(iso: string | null | undefined): string {
  if (!iso) return DASH;
  return iso.replace('T', ' ').replace('Z', ' UTC');
}

/** `ip:port`, keeping a missing part visible instead of inventing one. */
export function formatEndpoint(ip: string | null | undefined, port: number | null | undefined): string {
  const hasIp = typeof ip === 'string' && ip.trim().length > 0;
  const hasPort = port !== null && port !== undefined;
  if (!hasIp && !hasPort) return DASH;
  if (!hasIp) return `:${port}`;
  if (!hasPort) return ip;
  return `${ip}:${port}`;
}

export function formatNumber(value: number | null | undefined): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return DASH;
  return value.toLocaleString('en-US');
}
