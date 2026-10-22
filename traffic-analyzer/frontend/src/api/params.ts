/**
 * Packet filter state and query-string building.
 *
 * The parameter names and semantics come from `docs/API.md` §3
 * ("GET /api/analysis/{analysis_id}/packets").
 */

export type OrderByField =
  | 'frame_number'
  | 'timestamp'
  | 'captured_frame_length'
  | 'source_ip'
  | 'destination_ip';

export type SortDirection = 'asc' | 'desc';

export type EncryptedChoice = '' | 'true' | 'false';

export interface PacketFilters {
  q: string;
  protocol: string;
  transport: string;
  src_ip: string;
  dst_ip: string;
  src_port: string;
  dst_port: string;
  method: string;
  status_code: string;
  min_bytes: string;
  max_bytes: string;
  /** `datetime-local` value, converted to ISO-8601 UTC before it is sent. */
  start: string;
  /** `datetime-local` value, converted to ISO-8601 UTC before it is sent. */
  end: string;
  encrypted: EncryptedChoice;
  order_by: OrderByField;
  order_dir: SortDirection;
}

export const EMPTY_FILTERS: PacketFilters = {
  q: '',
  protocol: '',
  transport: '',
  src_ip: '',
  dst_ip: '',
  src_port: '',
  dst_port: '',
  method: '',
  status_code: '',
  min_bytes: '',
  max_bytes: '',
  start: '',
  end: '',
  encrypted: '',
  order_by: 'frame_number',
  order_dir: 'asc',
};

export const DEFAULT_PAGE_SIZE = 100;

/** Filter fields the API expects as integers; the raw text is validated before it is sent. */
const INT_FIELDS = ['src_port', 'dst_port', 'status_code', 'min_bytes', 'max_bytes'] as const;

/** Convert a `datetime-local` value to an ISO-8601 UTC timestamp, or null if unusable. */
export function localDateTimeToIso(value: string): string | null {
  if (!value.trim()) return null;
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return null;
  return parsed.toISOString();
}

export interface QueryOptions {
  limit?: number | null;
  offset?: number | null;
}

/**
 * Build the query string for the packets endpoint.
 *
 * Empty fields are omitted entirely so the backend applies its own defaults
 * instead of receiving `""` (which would be an invalid value for most fields).
 */
export function buildPacketQuery(filters: PacketFilters, options: QueryOptions = {}): string {
  const params = new URLSearchParams();

  const put = (key: string, value: string | null | undefined) => {
    if (value === null || value === undefined) return;
    const trimmed = value.trim();
    if (trimmed.length === 0) return;
    params.set(key, trimmed);
  };

  put('q', filters.q);
  put('protocol', filters.protocol);
  put('transport', filters.transport);
  put('src_ip', filters.src_ip);
  put('dst_ip', filters.dst_ip);
  put('method', filters.method);

  for (const field of INT_FIELDS) {
    const raw = filters[field].trim();
    if (raw.length === 0) continue;
    if (!/^\d+$/.test(raw)) continue;
    params.set(field, raw);
  }

  put('start', localDateTimeToIso(filters.start));
  put('end', localDateTimeToIso(filters.end));

  if (filters.encrypted === 'true' || filters.encrypted === 'false') {
    params.set('encrypted', filters.encrypted);
  }

  if (filters.order_by) params.set('order_by', filters.order_by);
  if (filters.order_dir) params.set('order_dir', filters.order_dir);

  if (typeof options.limit === 'number' && Number.isFinite(options.limit)) {
    params.set('limit', String(Math.trunc(options.limit)));
  }
  if (typeof options.offset === 'number' && Number.isFinite(options.offset)) {
    params.set('offset', String(Math.trunc(options.offset)));
  }

  const query = params.toString();
  return query.length > 0 ? `?${query}` : '';
}

/** Query string for the CSV/JSON exports: the current filters, but never a page window. */
export function buildExportQuery(filters: PacketFilters): string {
  return buildPacketQuery(filters);
}
