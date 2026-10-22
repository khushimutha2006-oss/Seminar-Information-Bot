import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Line,
  LineChart,
  Label,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import type { CaptureSummary, HostEntry, ProtocolCount } from '../api/types';
import { formatBytes, formatNumber, formatPercent } from '../lib/format';
import { Card, EmptyState } from './ui';

const CHART_COLORS = ['#2563eb', '#0d9488', '#b45309', '#7c3aed', '#be123c', '#0369a1', '#4d7c0f', '#9d174d'];
const TOOLTIP_STYLE = { border: '1px solid #dfe7f2', borderRadius: 12, boxShadow: '0 12px 28px rgba(30, 58, 92, 0.14)', padding: '10px 12px', background: '#ffffff', color: '#14233b' };

export function ProtocolChart(props: { protocols: ProtocolCount[]; total: number }) {
  const { protocols, total } = props;

  return (
    <figure className="chart-figure">
      <figcaption className="chart-caption">
        Counts <strong>packets per application protocol</strong> in the loaded analysis
        ({formatNumber(total)} packets in total). The API reports one row per protocol.
      </figcaption>
      {protocols.length === 0 ? (
        <EmptyState title="No protocol data" message="The analysis contains no packets to distribute." />
      ) : (
        <div className="chart-frame">
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Tooltip
                formatter={(value: unknown, name: unknown) => [formatNumber(Number(value)), String(name)]}
                contentStyle={TOOLTIP_STYLE}
              />
              <defs><linearGradient id="protocolBlue" x1="0" x2="1" y1="0" y2="1"><stop stopColor="#2685ff"/><stop offset="1" stopColor="#695bff"/></linearGradient></defs>
              <Pie data={protocols} dataKey="packets" nameKey="protocol" cx="50%" cy="50%" innerRadius="53%" outerRadius="78%" paddingAngle={3} stroke="none">
                {protocols.map((entry, index) => (
                  <Cell key={entry.protocol} fill={CHART_COLORS[index % CHART_COLORS.length]} />
                ))}
                <Label value={formatNumber(total)} position="center" className="chart-center-label" />
              </Pie>
            </PieChart>
          </ResponsiveContainer>
        </div>
      )}
      {protocols.length > 0 ? (
        <table className="mini-table">
          <caption>Application protocols (packets, bytes on the wire, share)</caption>
          <thead>
            <tr>
              <th scope="col">Protocol</th>
              <th scope="col">Packets</th>
              <th scope="col">Bytes</th>
              <th scope="col">Share</th>
            </tr>
          </thead>
          <tbody>
            {protocols.map((entry) => (
              <tr key={entry.protocol}>
                <th scope="row">{entry.protocol}</th>
                <td>{formatNumber(entry.packets)}</td>
                <td>{formatBytes(entry.bytes)}</td>
                <td>{formatPercent(entry.percentage)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : null}
    </figure>
  );
}

export function HostsChart(props: { hosts: HostEntry[]; total: number }) {
  const { hosts, total } = props;
  const data = [...hosts].sort((a, b) => b.total_bytes - a.total_bytes).slice(0, 10);

  return (
    <figure className="chart-figure">
      <figcaption className="chart-caption">
        Counts <strong>bytes on the wire per host</strong> (sent + received), top {data.length} of{' '}
        {formatNumber(total)} hosts.
      </figcaption>
      {data.length === 0 ? (
        <EmptyState title="No host data" message="The analysis contains no host activity." />
      ) : (
        <div className="chart-frame chart-frame-tall">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={data} layout="vertical" margin={{ top: 8, right: 24, bottom: 8, left: 8 }}>
              <defs><linearGradient id="hostGradient" x1="0" x2="1"><stop stopColor="#2ed39a"/><stop offset="1" stopColor="#127af5"/></linearGradient></defs>
              <CartesianGrid stroke="#edf1f6" strokeDasharray="3 5" horizontal={false} />
              <XAxis type="number" tick={{ fontSize: 12, fill: '#8491a5' }} tickLine={false} axisLine={false} />
              <YAxis type="category" dataKey="ip" tick={{ fontSize: 12, fill: '#526174' }} tickLine={false} axisLine={false} width={140} />
              <Tooltip
                formatter={(value: unknown, name: unknown) => [formatBytes(Number(value)), String(name)]}
                contentStyle={TOOLTIP_STYLE}
              />
              <Bar name="Bytes on the wire" dataKey="total_bytes" fill="url(#hostGradient)" radius={[0, 7, 7, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}
    </figure>
  );
}

export function TimelineChart(props: { summary: CaptureSummary }) {
  const { summary } = props;
  const data = summary.timeline.map((bucket) => ({
    ...bucket,
    label: new Date(bucket.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
  }));

  return (
    <figure className="chart-figure">
      <figcaption className="chart-caption">
        Shows <strong>packets over time</strong> from every timestamp in this capture.
      </figcaption>
      {data.length === 0 ? (
        <EmptyState title="No timeline data" message="The analysis contains no timestamped packets." />
      ) : (
        <div className="chart-frame">
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={data} margin={{ top: 8, right: 16, bottom: 8, left: 4 }}>
              <CartesianGrid stroke="#edf1f6" strokeDasharray="3 5" vertical={false} />
              <XAxis dataKey="label" tick={{ fontSize: 11, fill: '#8491a5' }} tickLine={false} axisLine={false} interval="preserveStartEnd" />
              <YAxis tick={{ fontSize: 12, fill: '#8491a5' }} tickLine={false} axisLine={false} allowDecimals={false} width={56} />
              <Tooltip
                formatter={(value: unknown, name: unknown) => [formatNumber(Number(value)), String(name)]}
                contentStyle={TOOLTIP_STYLE}
              />
              <Line name="Packets" type="monotone" dataKey="packets" stroke="#2563eb" strokeWidth={3} dot={false} activeDot={{ r: 5, fill: '#ffffff', stroke: '#2563eb', strokeWidth: 3 }} />
            </LineChart>
          </ResponsiveContainer>
        </div>
      )}
    </figure>
  );
}

export function SizeChart(props: { summary: CaptureSummary }) {
  const { summary } = props;
  return (
    <figure className="chart-figure">
      <figcaption className="chart-caption">Shows <strong>how large the captured packets were</strong>, using the full capture.</figcaption>
      {summary.size_distribution.length === 0 ? <EmptyState title="No size data" message="No frame sizes were available." /> : (
        <div className="chart-frame">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={summary.size_distribution} margin={{ top: 8, right: 16, bottom: 32, left: 4 }}>
              <defs><linearGradient id="sizeGradient" x1="0" x2="0" y1="0" y2="1"><stop stopColor="#9e72ff"/><stop offset="1" stopColor="#5b3ed6"/></linearGradient></defs>
              <CartesianGrid stroke="#edf1f6" strokeDasharray="3 5" vertical={false} />
              <XAxis dataKey="label" tick={{ fontSize: 11, fill: '#8491a5' }} tickLine={false} axisLine={false} interval={0} angle={-25} textAnchor="end" />
              <YAxis tick={{ fontSize: 12, fill: '#8491a5' }} tickLine={false} axisLine={false} allowDecimals={false} width={56} />
              <Tooltip formatter={(value: unknown) => [formatNumber(Number(value)), 'Packets']} contentStyle={TOOLTIP_STYLE} />
              <Bar name="Packets" dataKey="packets" fill="url(#sizeGradient)" radius={[7, 7, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}
    </figure>
  );
}

export function ChartsSection(props: {
  protocols: ProtocolCount[];
  protocolTotal: number;
  hosts: HostEntry[];
  hostTotal: number;
  summary: CaptureSummary | null;
  hasAnalysis: boolean;
}) {
  const {
    protocols,
    protocolTotal,
    hosts,
    hostTotal,
    summary,
    hasAnalysis,
  } = props;

  return (
    <Card
      title="Charts"
      description="Every chart is computed from the numbers the API returns for the loaded analysis."
    >
      {!hasAnalysis ? (
        <EmptyState
          title="No analysis loaded yet"
          message="Import a capture file or record a live capture to see the charts."
        />
      ) : (
        <div className="chart-grid">
          <ProtocolChart protocols={protocols} total={protocolTotal} />
          <HostsChart hosts={hosts} total={hostTotal} />
          {summary ? <><TimelineChart summary={summary} /><SizeChart summary={summary} /></> : null}
        </div>
      )}
    </Card>
  );
}
