import type { CaptureSummary } from '../api/types';
import { formatDuration, formatExactBytes, formatFullTimestamp, formatNumber } from '../lib/format';
import { Card, EmptyState } from './ui';

function Metric(props: { label: string; value: string; hint?: string }) {
  return (
    <div className="metric">
      <p className="metric-label">{props.label}</p>
      <p className="metric-value">{props.value}</p>
      {props.hint ? <p className="metric-hint">{props.hint}</p> : null}
    </div>
  );
}

export function SummaryView(props: { summary: CaptureSummary | null; error: string | null }) {
  const { summary, error } = props;

  return (
    <Card
      title="Summary"
      description={
        summary
          ? `Source ${summary.source_file} (${summary.source_kind}) — analysed ${formatFullTimestamp(summary.created_at)}`
          : 'Statistics for the loaded analysis.'
      }
    >
      {error ? <p className="notice notice-error" role="alert">{error}</p> : null}

      {!summary && !error ? (
        <EmptyState
          title="No analysis loaded yet"
          message="Import a capture file or record a live capture to see summary statistics."
        />
      ) : null}

      {summary ? (
        <>
          <div className="metrics">
            <Metric label="Packets" value={formatNumber(summary.packet_count)} hint="frames in the capture" />
            <Metric
              label="Bytes on the wire"
              value={formatExactBytes(summary.total_bytes)}
              hint="sum of captured frame lengths"
            />
            <Metric label="Duration" value={formatDuration(summary.duration_seconds)} hint="first to last packet" />
            <Metric label="Unique hosts" value={formatNumber(summary.unique_hosts)} hint="distinct IP addresses" />
            <Metric
              label="Encrypted packets"
              value={formatNumber(summary.encrypted_packet_count)}
              hint="payload seen inside TLS/QUIC"
            />
            <Metric
              label="HTTP requests"
              value={formatNumber(summary.http_request_count)}
              hint="request lines observed"
            />
            <Metric
              label="HTTP responses"
              value={formatNumber(summary.http_response_count)}
              hint="status lines observed"
            />
          </div>

          <dl className="kv kv-inline">
            <div>
              <dt>First packet</dt>
              <dd>{formatFullTimestamp(summary.first_timestamp)}</dd>
            </div>
            <div>
              <dt>Last packet</dt>
              <dd>{formatFullTimestamp(summary.last_timestamp)}</dd>
            </div>
            <div>
              <dt>Analysis ID</dt>
              <dd>
                <code>{summary.analysis_id}</code>
              </dd>
            </div>
          </dl>

          {summary.warnings.length > 0 ? (
            <div className="warnings-block">
              <h3 className="result-subtitle">Warnings ({summary.warnings.length})</h3>
              <ul className="warning-list">
                {summary.warnings.map((warning) => (
                  <li key={warning}>{warning}</li>
                ))}
              </ul>
            </div>
          ) : (
            <p className="muted">The backend reported no warnings for this analysis.</p>
          )}
        </>
      ) : null}
    </Card>
  );
}
