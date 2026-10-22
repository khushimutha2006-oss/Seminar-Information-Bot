import { useCallback, useEffect, useRef, useState } from 'react';
import { errorMessage } from './api/client';
import { getHosts, getPackets, getProtocols, getSummary } from './api/endpoints';
import { DEFAULT_PAGE_SIZE, EMPTY_FILTERS } from './api/params';
import type { PacketFilters } from './api/params';
import type {
  CaptureSummary,
  HostEntry,
  PacketPage,
  ProtocolCount,
} from './api/types';
import { CapturePanel } from './components/CapturePanel';
import { ChartsSection } from './components/ChartsSection';
import { ExportBar } from './components/ExportBar';
import { HealthBanner } from './components/HealthBanner';
import { ImportPanel } from './components/ImportPanel';
import { PacketExplorer } from './components/PacketExplorer';
import { SummaryView } from './components/SummaryView';
import { QuickStart } from './components/QuickStart';
import { LearnPanel } from './components/LearnPanel';
import { ReferenceDashboard } from './components/ReferenceDashboard';

export default function App() {
  const [analysisId, setAnalysisId] = useState<string | null>(null);

  const [summary, setSummary] = useState<CaptureSummary | null>(null);
  const [summaryError, setSummaryError] = useState<string | null>(null);

  const [protocols, setProtocols] = useState<ProtocolCount[]>([]);
  const [protocolTotal, setProtocolTotal] = useState(0);
  const [hosts, setHosts] = useState<HostEntry[]>([]);
  const [hostTotal, setHostTotal] = useState(0);

  const [page, setPage] = useState<PacketPage | null>(null);
  const [packetsError, setPacketsError] = useState<string | null>(null);
  const [loadingPackets, setLoadingPackets] = useState(false);

  const [filters, setFilters] = useState<PacketFilters>(EMPTY_FILTERS);
  const [offset, setOffset] = useState(0);
  const [limit, setLimit] = useState(DEFAULT_PAGE_SIZE);

  const importRef = useRef<HTMLDivElement>(null);
  const captureRef = useRef<HTMLDivElement>(null);

  const loadAnalysis = useCallback((id: string) => {
    setAnalysisId(id);
    setOffset(0);
    setFilters({ ...EMPTY_FILTERS });
  }, []);

  // Summary, protocol distribution and host statistics for the loaded analysis.
  useEffect(() => {
    if (!analysisId) {
      setSummary(null);
      setSummaryError(null);
      setProtocols([]);
      setProtocolTotal(0);
      setHosts([]);
      setHostTotal(0);
      return;
    }
    let cancelled = false;

    getSummary(analysisId)
      .then((result) => {
        if (cancelled) return;
        setSummary(result);
        setSummaryError(null);
      })
      .catch((error: unknown) => {
        if (cancelled) return;
        setSummary(null);
        setSummaryError(errorMessage(error));
      });

    getProtocols(analysisId)
      .then((result) => {
        if (cancelled) return;
        setProtocols(result.items);
        setProtocolTotal(result.total);
      })
      .catch(() => {
        if (cancelled) return;
        setProtocols([]);
        setProtocolTotal(0);
      });

    getHosts(analysisId)
      .then((result) => {
        if (cancelled) return;
        setHosts(result.items);
        setHostTotal(result.total);
      })
      .catch(() => {
        if (cancelled) return;
        setHosts([]);
        setHostTotal(0);
      });

    return () => {
      cancelled = true;
    };
  }, [analysisId]);

  // One page of packets. The whole capture is never downloaded in one request.
  useEffect(() => {
    if (!analysisId) {
      setPage(null);
      setPacketsError(null);
      return;
    }
    let cancelled = false;
    setLoadingPackets(true);
    getPackets(analysisId, filters, { limit, offset })
      .then((result) => {
        if (cancelled) return;
        setPage(result);
        setPacketsError(null);
      })
      .catch((error: unknown) => {
        if (cancelled) return;
        setPage(null);
        setPacketsError(errorMessage(error));
      })
      .finally(() => {
        if (cancelled) return;
        setLoadingPackets(false);
      });
    return () => {
      cancelled = true;
    };
  }, [analysisId, filters, offset, limit]);

  const applyFilters = (next: PacketFilters) => {
    setFilters({ ...next });
  };

  return (
    <div className="app dashboard-shell">
      <div className="dashboard-titleband">
        <p>In the FlowLab traffic system</p>
        <h1>Overview of <span>network traffic</span></h1>
      </div>
      <header className="dashboard-topbar">
        <a className="brand" href="#top" aria-label="Traffic Analyzer home"><span className="brand-mark">⌁</span><span>FLOW<span>LAB</span></span></a>
        <p className="topbar-divider">Traffic Analysis Workspace</p>
        <div className="topbar-actions"><span className="topbar-search">⌕ &nbsp; Search traffic</span><span className="status-dot">● API online</span></div>
      </header>

      <main className="dashboard-layout" id="top">
        <aside className="dashboard-nav">
          <p className="nav-label">Workspace</p>
          <a className="nav-item nav-item-active" href="#overview">⌂ <span>Overview</span></a>
          <a className="nav-item" href="#charts">⌁ <span>Traffic flow</span></a>
          <a className="nav-item" href="#explorer">⌕ <span>Explore packets</span></a>
          <a className="nav-item" href="#capture">◉ <span>Live capture</span></a>
          <p className="nav-label">Analysis</p>
          <a className="nav-item" href="#learn">◌ <span>Learn</span></a>
          <a className="nav-item" href="#exports">⇩ <span>Exports</span></a>
          <div className="nav-tip"><strong>Tip</strong><span>Begin with a sample capture to explore the dashboard.</span></div>
        </aside>

        <div className="dashboard-content">
          <QuickStart
            onImport={() => importRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' })}
            onLiveCapture={() => captureRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' })}
            onAnalysisReady={loadAnalysis}
          />
          <ReferenceDashboard
            summary={summary}
            protocols={protocols}
            onProtocolSelect={(protocol) => {
              setFilters((current) => ({ ...current, protocol }));
              setOffset(0);
              document.querySelector('#explorer')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
            }}
          />
          <section id="overview"><SummaryView summary={summary} error={summaryError} /></section>
          <section id="charts"><ChartsSection protocols={protocols} protocolTotal={protocolTotal} hosts={hosts} hostTotal={hostTotal} summary={summary} hasAnalysis={analysisId !== null} /></section>
          <section id="learn"><LearnPanel summary={summary} /></section>
          <section id="explorer"><PacketExplorer filters={filters} onApplyFilters={applyFilters} page={page} error={packetsError} loading={loadingPackets} limit={limit} offset={offset} onLimitChange={setLimit} onOffsetChange={setOffset} hasAnalysis={analysisId !== null} /></section>
        </div>

        <aside className="dashboard-controls">
          <HealthBanner />
          <div ref={importRef}><ImportPanel onAnalysisReady={loadAnalysis} /></div>
          <div ref={captureRef} id="capture"><CapturePanel onAnalysisReady={loadAnalysis} /></div>
          <div id="exports"><ExportBar analysisId={analysisId} filters={filters} /></div>
        </aside>
      </main>

      <footer className="app-footer">
        <p>
          Byte totals count the bytes on the wire (whole frame, link header included). Timestamps
          are UTC. A missing value is shown as “—”, never as 0.
        </p>
      </footer>
    </div>
  );
}
