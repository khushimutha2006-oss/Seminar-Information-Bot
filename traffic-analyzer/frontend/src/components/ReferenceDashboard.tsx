import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import type { CSSProperties } from 'react';
import type { CaptureSummary, ProtocolCount } from '../api/types';
import { formatBytes, formatNumber, formatPercent } from '../lib/format';

const COLORS = ['#1478ff', '#31cf82', '#a779ff', '#ff9a3e', '#ef5e70'];

function value(summary: CaptureSummary | null, metric: 'packets' | 'bytes' | 'hosts' | 'duration') {
  if (!summary) return '—';
  if (metric === 'packets') return formatNumber(summary.packet_count);
  if (metric === 'bytes') return formatBytes(summary.total_bytes);
  if (metric === 'hosts') return formatNumber(summary.unique_hosts);
  return `${summary.duration_seconds.toFixed(1)} s`;
}

export function ReferenceDashboard(props: { summary: CaptureSummary | null; protocols: ProtocolCount[]; onProtocolSelect: (protocol: string) => void }) {
  const { summary, protocols, onProtocolSelect } = props;
  const timeline = (summary?.timeline ?? []).map((item) => ({
    ...item,
    label: new Date(item.timestamp).toLocaleTimeString([], { minute: '2-digit', second: '2-digit' }),
  }));
  const pie = protocols.slice(0, 5);
  const ranking = [...protocols].sort((a, b) => b.packets - a.packets).slice(0, 5);
  const sizeBins = summary?.size_distribution ?? [];
  const highestBin = Math.max(1, ...sizeBins.map((bin) => bin.packets));
  const packetTrend = timeline.map((item) => item.packets);
  const byteTrend = timeline.map((item) => item.bytes);

  return (
    <section className="reference-dashboard" aria-label="Network traffic overview">
      <div className="reference-metrics">
        <Metric title="Original" value={value(summary, 'bytes')} color="#1677ff" trend={byteTrend} detail="Bytes on the wire" />
        <Metric title="Cumulative" value={value(summary, 'packets')} color="#31cf82" trend={packetTrend} detail="Packets observed" />
        <Metric title="Now" value={value(summary, 'hosts')} color="#a779ff" detail="Unique communicating hosts" />
        <Metric title="Sessions" value={value(summary, 'duration')} color="#ff9a3e" trend={packetTrend} detail="Traffic activity over time" />
        <div className="reference-ring-card"><div><strong>In & out</strong><span>{value(summary, 'bytes')}</span></div><div className="reference-ring">{summary ? `${Math.min(100, Math.round((summary.encrypted_packet_count / Math.max(1, summary.packet_count)) * 100))}%` : '—'}</div></div>
      </div>

      <div className="reference-main-grid">
        <article className="reference-chart-card">
          <div className="reference-card-head"><div><p>Overview of all traffic</p><h2>{value(summary, 'bytes')}</h2></div><div className="reference-legend"><span className="legend-blue">● Packets</span><span className="legend-green">● Bytes</span><button type="button">Today</button></div></div>
          <div className="reference-traffic-chart">
            {timeline.length ? <ResponsiveContainer width="100%" height="100%"><AreaChart data={timeline} margin={{ top: 14, right: 12, bottom: 0, left: 2 }}><defs><linearGradient id="packetBlue" x1="0" x2="0" y1="0" y2="1"><stop offset="0%" stopColor="#1478ff" stopOpacity=".28"/><stop offset="100%" stopColor="#1478ff" stopOpacity="0"/></linearGradient><linearGradient id="byteGreen" x1="0" x2="0" y1="0" y2="1"><stop offset="0%" stopColor="#31cf82" stopOpacity=".18"/><stop offset="100%" stopColor="#31cf82" stopOpacity="0"/></linearGradient></defs><CartesianGrid vertical stroke="#e9eef5" strokeDasharray="2 4"/><XAxis dataKey="label" tickLine={false} axisLine={false} tick={{fontSize:11,fill:'#8c98aa'}}/><YAxis yAxisId="packets" hide /><YAxis yAxisId="bytes" hide orientation="right"/><Tooltip cursor={{ stroke:'#aebbd0', strokeDasharray:'3 4' }} content={<TrafficTooltip />}/><Area yAxisId="bytes" type="monotone" dataKey="bytes" name="Bytes" stroke="#31cf82" strokeWidth={3} fill="url(#byteGreen)"/><Area yAxisId="packets" type="monotone" dataKey="packets" name="Packets" stroke="#1478ff" strokeWidth={3} fill="url(#packetBlue)"/></AreaChart></ResponsiveContainer> : <p className="reference-empty">Load a capture to draw real traffic activity.</p>}
          </div>
          <div className="reference-distribution-head"><strong>Packet size distribution</strong><span>Each cell represents the share of frames in a size range.</span></div>
          <div className="reference-heatmap">{sizeBins.length ? sizeBins.flatMap((bin) => Array.from({ length: 8 }, (_, index) => <i key={`${bin.label}-${index}`} title={`${bin.label} bytes: ${formatNumber(bin.packets)} packets`} aria-label={`${bin.label} bytes: ${formatNumber(bin.packets)} packets`} style={{ opacity: 0.16 + ((bin.packets / highestBin) * (0.84 - index * 0.025)) }} />)) : <span className="reference-empty">Size distribution appears after analysis.</span>}</div>
        </article>

        <aside className="reference-insights">
          <article className="reference-protocol-card"><h3>Protocol traffic domain</h3>{pie.length ? <div className="reference-bubble-domain">{pie.map((item, index) => <button type="button" key={item.protocol} className={`protocol-bubble bubble-${index}`} style={{ '--bubble': COLORS[index] } as CSSProperties} title={`${item.protocol}: ${formatNumber(item.packets)} packets (${formatPercent(item.percentage)})`} onClick={() => onProtocolSelect(item.protocol)}><b>{item.protocol}</b><span>{formatNumber(item.packets)}</span><small>{formatPercent(item.percentage)}</small></button>)}</div> : <p className="reference-empty">Protocol mix appears here.</p>}</article>
          <article className="reference-rank-card"><h3>Session protocol ranking</h3><div className="rank-head"><span>Protocol</span><span>Packets</span><span>Share</span></div>{ranking.length ? ranking.map((item, index) => <button type="button" className="rank-row" key={item.protocol} onClick={() => onProtocolSelect(item.protocol)}><span><i style={{ background: COLORS[index] }} />{item.protocol}</span><strong>{formatNumber(item.packets)}</strong><em>{formatPercent(item.percentage)}</em></button>) : <p className="reference-empty">Load a capture to see rankings.</p>}</article>
        </aside>
      </div>
    </section>
  );
}

function TrafficTooltip(props: { active?: boolean; payload?: Array<{ dataKey?: string; value?: number; payload?: { label: string } }> }) {
  if (!props.active || !props.payload?.length) return null;
  const item = props.payload[0]?.payload;
  return <div className="traffic-tooltip"><strong>{item?.label}</strong>{props.payload.map((row) => <span key={row.dataKey}>{row.dataKey === 'bytes' ? 'Bytes' : 'Packets'} <b>{row.dataKey === 'bytes' ? formatBytes(Number(row.value)) : formatNumber(Number(row.value))}</b></span>)}</div>;
}

function Metric(props: { title: string; value: string; color: string; trend?: number[]; detail: string }) {
  const sampled = sampleTrend(props.trend ?? []);
  const maximum = Math.max(1, ...sampled);

  return <article className="reference-metric"><div><strong>{props.title}</strong><span>{props.value}</span></div>{sampled.length ? <div className="metric-bars" style={{ color: props.color }} aria-label={`${props.title} traffic trend`}>{sampled.map((point, index) => <i key={index} style={{ height: `${20 + ((point / maximum) * 80)}%` }} />)}</div> : <small className="metric-detail">{props.detail}</small>}</article>;
}

function sampleTrend(values: number[]) {
  if (!values.length) return [];
  const count = Math.min(9, values.length);
  return Array.from({ length: count }, (_, index) => values[Math.round((index * (values.length - 1)) / Math.max(1, count - 1))] ?? 0);
}
