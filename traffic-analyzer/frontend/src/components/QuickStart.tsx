import { useCallback, useEffect, useState } from 'react';
import { analyseSample, getSamples } from '../api/endpoints';
import { errorMessage } from '../api/client';
import type { SampleInfo } from '../api/types';

export function QuickStart(props: {
  onImport: () => void;
  onLiveCapture: () => void;
  onAnalysisReady: (id: string) => void;
}) {
  const { onImport, onLiveCapture, onAnalysisReady } = props;
  const [sample, setSample] = useState<SampleInfo | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const loadSample = useCallback(async () => {
    try {
      const page = await getSamples();
      setSample(page.samples.find((item) => item.name.includes('real_traffic')) ?? page.samples[0] ?? null);
      setError(page.samples.length === 0 ? 'No bundled samples are available on this server.' : null);
    } catch (caught) {
      setSample(null);
      setError(`The sample list is not reachable yet: ${errorMessage(caught)}`);
    }
  }, []);

  useEffect(() => {
    void loadSample();
    // The frontend can finish loading a moment before a just-started API is
    // accepting requests. Retry once so "Try sample" does not stay disabled.
    const retry = window.setTimeout(() => void loadSample(), 1500);
    return () => window.clearTimeout(retry);
  }, [loadSample]);

  const trySample = async () => {
    if (loading) return;
    if (!sample) {
      await loadSample();
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const result = await analyseSample(sample.name);
      onAnalysisReady(result.analysis_id);
    } catch (caught) {
      setError(errorMessage(caught));
    } finally {
      setLoading(false);
    }
  };

  return (
    <section className="quick-start" aria-labelledby="quick-start-title">
      <div className="quick-start-copy">
        <p className="eyebrow">Network traffic, made understandable</p>
        <h2 id="quick-start-title">Start with a capture, then follow the story in the charts.</h2>
        <p>See who communicated, which protocols appeared, and when the activity changed—without needing to know packet filters first.</p>
      </div>
      <div className="quick-actions">
        <button type="button" className="quick-action" onClick={onImport}>
          <span aria-hidden="true">↑</span><strong>Import capture</strong><small>Open a PCAP, PCAPNG, or CSV file.</small>
        </button>
        <button type="button" className="quick-action" onClick={onLiveCapture}>
          <span aria-hidden="true">◉</span><strong>Start live capture</strong><small>Record from a local network interface.</small>
        </button>
        <button type="button" className="quick-action quick-action-primary" onClick={() => void trySample()} disabled={loading}>
          <span aria-hidden="true">✦</span><strong>{loading ? 'Loading sample…' : sample ? 'Try sample' : 'Retry sample'}</strong><small>{sample ? 'Explore a ready-made real capture.' : 'Reconnect to the API sample list.'}</small>
        </button>
      </div>
      {error ? <p className="quick-error" role="alert">Could not load the sample: {error}</p> : null}
    </section>
  );
}
