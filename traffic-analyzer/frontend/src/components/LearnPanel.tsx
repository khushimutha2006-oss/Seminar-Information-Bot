import type { CaptureSummary } from '../api/types';

export function LearnPanel(props: { summary: CaptureSummary | null }) {
  const { summary } = props;
  if (!summary) return null;
  const protocols = summary.application_protocol_counts.map((item) => item.protocol);
  const hasHttp = protocols.includes('HTTP');
  const hasTls = protocols.includes('TLS') || protocols.includes('QUIC');
  return (
    <section className="learn-panel" aria-labelledby="learn-title">
      <p className="eyebrow">Learn from this capture</p>
      <h2 id="learn-title">What the data is telling you</h2>
      <div className="learn-grid">
        <p><strong>Hosts</strong> are the IP addresses sending and receiving traffic. The top-host chart groups their activity by captured bytes.</p>
        <p><strong>Spikes</strong> in the timeline mean more packets were seen during that period; they do not automatically mean a problem.</p>
        <p><strong>Packet length</strong> is the amount of data captured for one network frame, including network headers.</p>
        <p>{hasHttp ? <><strong>HTTP was observed.</strong> Its requests and responses can be readable when they were captured in plaintext.</> : <><strong>HTTP was not identified.</strong> This app only labels HTTP when protocol evidence was actually observed.</>}</p>
        <p>{hasTls ? <><strong>Encrypted traffic is present.</strong> TLS/QUIC protects payload contents; names or handshake details may be visible, but encryption is not bypassed.</> : <><strong>No TLS or QUIC was identified.</strong> A port number alone is never used as proof of HTTPS.</>}</p>
      </div>
    </section>
  );
}
