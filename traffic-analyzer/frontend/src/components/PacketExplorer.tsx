import { useEffect, useState } from 'react';
import type { NormalizedPacket, PacketPage } from '../api/types';
import type { OrderByField, PacketFilters } from '../api/params';
import { buildPacketQuery, EMPTY_FILTERS } from '../api/params';
import {
  dash,
  formatEndpoint,
  formatFullTimestamp,
  formatNumber,
  formatTimestamp,
} from '../lib/format';
import { Card, EmptyState, ErrorNotice, Field, Spinner } from './ui';

/** Explains the timestamp in the row tooltip, including contract v1.1 honesty extras. */
function timestampTitle(packet: NormalizedPacket): string {
  const full = formatFullTimestamp(packet.timestamp);
  if (packet.timestamp_has_date === false) {
    return `${full} — the source carried a time of day only, so no date was invented.`;
  }
  return full;
}

/** Shows how the application protocol was reached (contract v1.1, optional). */
function protocolTitle(packet: NormalizedPacket): string {
  const parts: string[] = [];
  if (packet.protocol_confidence) parts.push(`confidence: ${packet.protocol_confidence}`);
  if (packet.detected_protocol) parts.push(`dissector reported: ${packet.detected_protocol}`);
  if (packet.protocol_evidence && packet.protocol_evidence.length > 0) {
    parts.push(`evidence: ${packet.protocol_evidence.join('; ')}`);
  }
  return parts.join(' · ');
}

function isLowConfidence(packet: NormalizedPacket): boolean {
  const confidence = packet.protocol_confidence;
  return confidence === 'low' || confidence === 'medium';
}

const TRANSPORT_LABELS = ['TCP', 'UDP', 'ICMP', 'ICMPv6', 'ARP', 'SCTP', 'OTHER'];
const APPLICATION_LABELS = [
  'HTTP',
  'TLS',
  'QUIC',
  'DNS',
  'TCP',
  'UDP',
  'ICMP',
  'ICMPv6',
  'ARP',
  'SCTP',
  'OTHER',
];
const HTTP_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'PATCH', 'OPTIONS'];
const ORDER_BY_OPTIONS: { value: OrderByField; label: string }[] = [
  { value: 'frame_number', label: 'Frame number' },
  { value: 'timestamp', label: 'Timestamp' },
  { value: 'captured_frame_length', label: 'Length (bytes on the wire)' },
  { value: 'source_ip', label: 'Source IP' },
  { value: 'destination_ip', label: 'Destination IP' },
];

export interface PacketExplorerProps {
  filters: PacketFilters;
  onApplyFilters: (filters: PacketFilters) => void;
  page: PacketPage | null;
  error: string | null;
  loading: boolean;
  limit: number;
  offset: number;
  onLimitChange: (limit: number) => void;
  onOffsetChange: (offset: number) => void;
  hasAnalysis: boolean;
}

function SortHeader(props: {
  field: OrderByField;
  children: string;
  filters: PacketFilters;
  onSort: (field: OrderByField) => void;
}) {
  const { field, children, filters, onSort } = props;
  const active = filters.order_by === field;
  const ariaSort = active ? (filters.order_dir === 'asc' ? 'ascending' : 'descending') : 'none';
  return (
    <th scope="col" aria-sort={ariaSort}>
      <button type="button" className="sort-button" onClick={() => onSort(field)}>
        {children}
        <span aria-hidden="true" className="sort-indicator">
          {active ? (filters.order_dir === 'asc' ? '▲' : '▼') : '↕'}
        </span>
      </button>
    </th>
  );
}

export function PacketExplorer(props: PacketExplorerProps) {
  const {
    filters,
    onApplyFilters,
    page,
    error,
    loading,
    limit,
    offset,
    onLimitChange,
    onOffsetChange,
    hasAnalysis,
  } = props;

  const [draft, setDraft] = useState<PacketFilters>(filters);

  useEffect(() => {
    setDraft(filters);
  }, [filters]);

  const update = (key: keyof PacketFilters, value: string) => {
    setDraft((current) => ({ ...current, [key]: value }));
  };

  const handleSort = (field: OrderByField) => {
    const next: PacketFilters =
      filters.order_by === field
        ? { ...filters, order_dir: filters.order_dir === 'asc' ? 'desc' : 'asc' }
        : { ...filters, order_by: field, order_dir: 'asc' };
    onApplyFilters(next);
  };

  const total = page?.total ?? 0;
  const firstRow = total === 0 ? 0 : offset + 1;
  const lastRow = Math.min(offset + (page?.items.length ?? 0), total);
  const canGoBack = offset > 0;
  const canGoForward = offset + limit < total;

  return (
    <Card
      title="Packet explorer"
      description="Server-side filters and pagination. The table never downloads the whole capture: it always requests one page of rows."
    >
      <form
        className="stack"
        onSubmit={(event) => {
          event.preventDefault();
          onApplyFilters(draft);
          onOffsetChange(0);
        }}
      >
        <details className="filters-details">
          <summary>Filters and search <span>Find a host, protocol, or packet detail</span></summary>
        <fieldset className="filterset">
          <legend>Filters</legend>

          <Field
            id="filter-q"
            label="Search"
            hint="Case-insensitive substring over IP, port, protocol, host name and HTTP method."
            className="field-wide"
          >
            <input
              id="filter-q"
              type="search"
              value={draft.q}
              onChange={(event) => update('q', event.target.value)}
              placeholder="e.g. example.com"
            />
          </Field>

          <div className="grid grid-3">
            <Field id="filter-protocol" label="Application protocol">
              <input
                id="filter-protocol"
                type="text"
                list="application-protocols"
                value={draft.protocol}
                onChange={(event) => update('protocol', event.target.value)}
                placeholder="HTTP"
              />
            </Field>
            <Field id="filter-transport" label="Transport protocol">
              <input
                id="filter-transport"
                type="text"
                list="transport-protocols"
                value={draft.transport}
                onChange={(event) => update('transport', event.target.value)}
                placeholder="TCP"
              />
            </Field>
            <Field id="filter-encrypted" label="Encrypted">
              <select
                id="filter-encrypted"
                value={draft.encrypted}
                onChange={(event) => update('encrypted', event.target.value)}
              >
                <option value="">Any</option>
                <option value="true">Encrypted only</option>
                <option value="false">Not encrypted</option>
              </select>
            </Field>

            <Field id="filter-src-ip" label="Source IP">
              <input
                id="filter-src-ip"
                type="text"
                value={draft.src_ip}
                onChange={(event) => update('src_ip', event.target.value)}
                placeholder="10.0.0.1"
              />
            </Field>
            <Field id="filter-dst-ip" label="Destination IP">
              <input
                id="filter-dst-ip"
                type="text"
                value={draft.dst_ip}
                onChange={(event) => update('dst_ip', event.target.value)}
                placeholder="10.0.0.2"
              />
            </Field>
            <Field id="filter-method" label="HTTP method">
              <input
                id="filter-method"
                type="text"
                list="http-methods"
                value={draft.method}
                onChange={(event) => update('method', event.target.value)}
                placeholder="GET"
              />
            </Field>

            <Field id="filter-src-port" label="Source port">
              <input
                id="filter-src-port"
                type="number"
                min={0}
                max={65535}
                value={draft.src_port}
                onChange={(event) => update('src_port', event.target.value)}
              />
            </Field>
            <Field id="filter-dst-port" label="Destination port">
              <input
                id="filter-dst-port"
                type="number"
                min={0}
                max={65535}
                value={draft.dst_port}
                onChange={(event) => update('dst_port', event.target.value)}
              />
            </Field>
            <Field id="filter-status" label="HTTP status code">
              <input
                id="filter-status"
                type="number"
                min={100}
                max={599}
                value={draft.status_code}
                onChange={(event) => update('status_code', event.target.value)}
                placeholder="200"
              />
            </Field>

            <Field id="filter-min-bytes" label="Min length (bytes)">
              <input
                id="filter-min-bytes"
                type="number"
                min={0}
                value={draft.min_bytes}
                onChange={(event) => update('min_bytes', event.target.value)}
              />
            </Field>
            <Field id="filter-max-bytes" label="Max length (bytes)">
              <input
                id="filter-max-bytes"
                type="number"
                min={0}
                value={draft.max_bytes}
                onChange={(event) => update('max_bytes', event.target.value)}
              />
            </Field>
            <Field id="filter-order-by" label="Sort by">
              <select
                id="filter-order-by"
                value={draft.order_by}
                onChange={(event) => update('order_by', event.target.value)}
              >
                {ORDER_BY_OPTIONS.map((option) => (
                  <option key={option.value} value={option.value}>
                    {option.label}
                  </option>
                ))}
              </select>
            </Field>

            <Field
              id="filter-start"
              label="From"
              hint="Local time; sent to the API as UTC."
            >
              <input
                id="filter-start"
                type="datetime-local"
                value={draft.start}
                onChange={(event) => update('start', event.target.value)}
              />
            </Field>
            <Field id="filter-end" label="To" hint="Local time; sent to the API as UTC.">
              <input
                id="filter-end"
                type="datetime-local"
                value={draft.end}
                onChange={(event) => update('end', event.target.value)}
              />
            </Field>
            <Field id="filter-order-dir" label="Direction">
              <select
                id="filter-order-dir"
                value={draft.order_dir}
                onChange={(event) => update('order_dir', event.target.value)}
              >
                <option value="asc">Ascending</option>
                <option value="desc">Descending</option>
              </select>
            </Field>
          </div>

          <datalist id="application-protocols">
            {APPLICATION_LABELS.map((label) => (
              <option key={label} value={label} />
            ))}
          </datalist>
          <datalist id="transport-protocols">
            {TRANSPORT_LABELS.map((label) => (
              <option key={label} value={label} />
            ))}
          </datalist>
          <datalist id="http-methods">
            {HTTP_METHODS.map((label) => (
              <option key={label} value={label} />
            ))}
          </datalist>

          <div className="row">
            <button type="submit" className="btn btn-primary" disabled={!hasAnalysis || loading}>
              Apply filters
            </button>
            <button
              type="button"
              className="btn"
              onClick={() => {
                setDraft(EMPTY_FILTERS);
                onApplyFilters(EMPTY_FILTERS);
                onOffsetChange(0);
              }}
              disabled={!hasAnalysis}
            >
              Reset
            </button>
            {loading ? <Spinner label="Loading packets…" /> : null}
          </div>
        </fieldset>
        </details>
      </form>

      <p className="query-line">
        <span className="muted small">Request query:</span>{' '}
        <code>{buildPacketQuery(filters, { limit, offset })}</code>
      </p>

      {error ? <ErrorNotice title="The packets could not be loaded" message={error} /> : null}

      {!hasAnalysis ? (
        <EmptyState
          title="No analysis loaded yet"
          message="Import a capture file or record a live capture to explore its packets."
        />
      ) : null}

      {hasAnalysis && !error ? (
        <>
          {total === 0 ? (
            <EmptyState
              title="0 packets"
              message="This analysis contains no packets. That is a valid result for an empty capture — nothing was captured, or every packet was filtered out by the current filters."
            />
          ) : (
            <>
              <div className="table-wrap">
                <table className="packet-table">
                  <caption className="sr-only">
                    Packets {firstRow} to {lastRow} of {total} matching packets. Timestamps are UTC.
                  </caption>
                  <thead>
                    <tr>
                      <SortHeader field="frame_number" filters={filters} onSort={handleSort}>
                        Frame
                      </SortHeader>
                      <SortHeader field="timestamp" filters={filters} onSort={handleSort}>
                        Timestamp (UTC)
                      </SortHeader>
                      <SortHeader field="source_ip" filters={filters} onSort={handleSort}>
                        Source
                      </SortHeader>
                      <SortHeader field="destination_ip" filters={filters} onSort={handleSort}>
                        Destination
                      </SortHeader>
                      <th scope="col">Transport</th>
                      <th scope="col">App protocol</th>
                      <SortHeader field="captured_frame_length" filters={filters} onSort={handleSort}>
                        Length
                      </SortHeader>
                      <th scope="col">HTTP method</th>
                      <th scope="col">HTTP status</th>
                      <th scope="col">TLS version</th>
                      <th scope="col">Server name</th>
                      <th scope="col">Info</th>
                    </tr>
                  </thead>
                  <tbody>
                    {page?.items.map((packet) => (
                      <tr key={packet.frame_number}>
                        <th scope="row">{packet.frame_number}</th>
                        <td title={timestampTitle(packet)}>
                          {formatTimestamp(packet.timestamp)}
                        </td>
                        <td>{formatEndpoint(packet.source_ip, packet.source_port)}</td>
                        <td>{formatEndpoint(packet.destination_ip, packet.destination_port)}</td>
                        <td>{dash(packet.transport_protocol)}</td>
                        <td title={protocolTitle(packet)}>
                          {dash(packet.application_protocol)}
                          {isLowConfidence(packet) ? (
                            <span className="confidence-tag">{packet.protocol_confidence}</span>
                          ) : null}
                        </td>
                        <td className="numeric">{formatNumber(packet.captured_frame_length)}</td>
                        <td>{dash(packet.http_method)}</td>
                        <td className="numeric">
                          {packet.http_status_code === null
                            ? dash(null)
                            : formatNumber(packet.http_status_code)}
                        </td>
                        <td>{dash(packet.tls_version)}</td>
                        <td>{dash(packet.server_name)}</td>
                        <td className="info-cell" title={packet.info ?? ''}>
                          {dash(packet.info)}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              <div className="pagination">
                <p className="pagination-summary" aria-live="polite">
                  Showing <strong>{formatNumber(firstRow)}</strong>–
                  <strong>{formatNumber(lastRow)}</strong> of{' '}
                  <strong>{formatNumber(total)}</strong> matching packets
                </p>
                <div className="row">
                  <label className="inline-label" htmlFor="page-size">
                    Rows per page
                  </label>
                  <select
                    id="page-size"
                    value={limit}
                    onChange={(event) => {
                      onLimitChange(Number(event.target.value));
                      onOffsetChange(0);
                    }}
                  >
                    <option value={50}>50</option>
                    <option value={100}>100</option>
                    <option value={200}>200</option>
                    <option value={500}>500</option>
                  </select>
                  <button
                    type="button"
                    className="btn"
                    onClick={() => onOffsetChange(Math.max(0, offset - limit))}
                    disabled={!canGoBack || loading}
                  >
                    ← Previous
                  </button>
                  <button
                    type="button"
                    className="btn"
                    onClick={() => onOffsetChange(offset + limit)}
                    disabled={!canGoForward || loading}
                  >
                    Next →
                  </button>
                </div>
              </div>
            </>
          )}
        </>
      ) : null}
    </Card>
  );
}
