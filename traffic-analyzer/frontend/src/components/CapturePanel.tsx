import { useCallback, useEffect, useState } from 'react';
import { ApiError, errorMessage } from '../api/client';
import {
  getCaptureInterfaces,
  getCaptureStatus,
  startCapture,
  stopCapture,
} from '../api/endpoints';
import type {
  CaptureInterfacesResponse,
  CaptureStatus,
  CaptureStopResponse,
} from '../api/types';
import { formatFullTimestamp, formatNumber } from '../lib/format';
import { Card, ErrorNotice, Field, InfoNotice, Spinner, StatusPill } from './ui';

type Busy = 'idle' | 'starting' | 'stopping' | 'loading';

function titleForError(error: unknown, action: 'start' | 'stop'): string {
  if (error instanceof ApiError) {
    if (error.status === 409) {
      return action === 'start' ? 'A capture is already running' : 'No capture is running';
    }
    if (error.status === 503) {
      return 'Live capture is unavailable on this server';
    }
    if (error.status === 400) {
      return 'The capture request was rejected';
    }
  }
  return action === 'start' ? 'The capture could not be started' : 'The capture could not be stopped';
}

function hintForError(error: unknown, action: 'start' | 'stop'): string | null {
  if (error instanceof ApiError && error.status === 503) {
    return 'TShark is not installed, or the process is not permitted to capture on this host. Offline analysis of uploaded files still works.';
  }
  if (error instanceof ApiError && error.status === 409 && action === 'start') {
    return 'Stop the running capture before starting a new one.';
  }
  return null;
}

export function CapturePanel(props: { onAnalysisReady: (analysisId: string) => void }) {
  const { onAnalysisReady } = props;

  const [interfaces, setInterfaces] = useState<CaptureInterfacesResponse | null>(null);
  const [interfacesError, setInterfacesError] = useState<string | null>(null);
  const [status, setStatus] = useState<CaptureStatus | null>(null);
  const [statusError, setStatusError] = useState<string | null>(null);

  const [interfaceName, setInterfaceName] = useState('');
  const [duration, setDuration] = useState('30');
  const [filter, setFilter] = useState('');
  const [displayFilter, setDisplayFilter] = useState('');

  const [busy, setBusy] = useState<Busy>('idle');
  const [actionError, setActionError] = useState<{ title: string; message: string; hint: string | null } | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [stopped, setStopped] = useState<CaptureStopResponse | null>(null);

  const loadInterfaces = useCallback(async () => {
    setBusy((current) => (current === 'idle' ? 'loading' : current));
    try {
      const response = await getCaptureInterfaces();
      setInterfaces(response);
      setInterfacesError(null);
      setInterfaceName((current) => {
        if (current && response.interfaces.some((item) => item.name === current)) return current;
        return response.interfaces[0]?.name ?? '';
      });
    } catch (caught) {
      setInterfacesError(errorMessage(caught));
    } finally {
      setBusy('idle');
    }
  }, []);

  useEffect(() => {
    void loadInterfaces();
  }, [loadInterfaces]);

  useEffect(() => {
    let cancelled = false;
    const poll = () => {
      getCaptureStatus()
        .then((response) => {
          if (cancelled) return;
          setStatus(response);
          setStatusError(null);
        })
        .catch((caught: unknown) => {
          if (cancelled) return;
          setStatusError(errorMessage(caught));
        });
    };
    void poll();
    const timer = window.setInterval(poll, status?.running ? 2000 : 6000);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [status?.running]);

  const handleStart = async () => {
    setBusy('starting');
    setActionError(null);
    setNotice(null);
    try {
      const body: {
        interface: string;
        duration_seconds?: number;
        filter?: string;
        display_filter?: string;
      } = { interface: interfaceName };
      if (duration.trim() !== '') {
        const parsed = Number.parseInt(duration, 10);
        if (Number.isFinite(parsed)) body.duration_seconds = parsed;
      }
      if (filter.trim() !== '') body.filter = filter.trim();
      if (displayFilter.trim() !== '') body.display_filter = displayFilter.trim();
      const response = await startCapture(body);
      setNotice(response.message);
      const refreshed = await getCaptureStatus().catch(() => null);
      if (refreshed) setStatus(refreshed);
    } catch (caught) {
      setActionError({
        title: titleForError(caught, 'start'),
        message: errorMessage(caught),
        hint: hintForError(caught, 'start'),
      });
    } finally {
      setBusy('idle');
    }
  };

  const handleStop = async () => {
    setBusy('stopping');
    setActionError(null);
    setNotice(null);
    setStopped(null);
    try {
      const response = await stopCapture({ capture_id: status?.capture_id ?? null });
      setStopped(response);
      setNotice(response.message);
      const refreshed = await getCaptureStatus().catch(() => null);
      if (refreshed) setStatus(refreshed);
      if (response.analysis_id) {
        onAnalysisReady(response.analysis_id);
      }
    } catch (caught) {
      setActionError({
        title: titleForError(caught, 'stop'),
        message: errorMessage(caught),
        hint: hintForError(caught, 'stop'),
      });
    } finally {
      setBusy('idle');
    }
  };

  const running = status?.running ?? false;
  const interfaceCount = interfaces?.interfaces.length ?? 0;
  const toolMissing = interfaces !== null && !interfaces.tshark_available;
  const liveCaptureUnavailable = toolMissing || Boolean(interfaces?.message);

  return (
    <Card
      title="Live capture"
      description="Record from a local interface with TShark. Requires TShark and capture permissions on the server."
      actions={
        <button type="button" className="btn btn-ghost btn-small" onClick={() => void loadInterfaces()}>
          Refresh interfaces
        </button>
      }
    >
      {interfacesError ? (
        <ErrorNotice title="The capture interfaces could not be listed" message={interfacesError} />
      ) : null}

      {toolMissing ? (
        <InfoNotice
          tone="warn"
          title="No capture tool available"
          message="TShark was not found on the server, so live capture cannot start. Importing capture files still works."
        />
      ) : null}

      {interfaces?.message && !toolMissing ? (
        <InfoNotice
          tone="warn"
          title="Live capture needs attention"
          message={`${interfaces.message} The listed devices are only a fallback, so live capture is disabled until this is resolved.`}
        />
      ) : null}

      {interfaces && interfaceCount === 0 && !toolMissing ? (
        <InfoNotice
          tone="warn"
          title="No capture interfaces"
          message="The server reported no capture interfaces. It may need capture permissions, or the capture tool may not list any interface."
        />
      ) : null}

      <form
        className="stack"
        onSubmit={(event) => {
          event.preventDefault();
          void handleStart();
        }}
      >
        <Field id="capture-interface" label="Capture interface">
          <select
            id="capture-interface"
            value={interfaceName}
            onChange={(event) => setInterfaceName(event.target.value)}
            disabled={running || interfaceCount === 0 || liveCaptureUnavailable}
          >
            {interfaceCount === 0 ? (
              <option value="">No interfaces available</option>
            ) : null}
            {interfaces?.interfaces.map((item) => (
              <option key={item.name} value={item.name}>
                {item.name}
                {item.description ? ` — ${item.description}` : ''}
                {item.is_loopback ? ' (loopback)' : ''}
              </option>
            ))}
          </select>
        </Field>

        {interfaces && interfaces.interfaces.length > 0 ? (
          <p className="muted small">
            Source: {interfaces.source}. Selected interface addresses:{' '}
            {interfaces.interfaces.find((item) => item.name === interfaceName)?.addresses.join(', ') ||
              '—'}
          </p>
        ) : null}

        <div className="grid grid-2">
          <Field
            id="capture-duration"
            label="Duration (seconds)"
            hint="Optional auto-stop, 1–3600."
          >
            <input
              id="capture-duration"
              type="number"
              min={1}
              max={3600}
              value={duration}
              onChange={(event) => setDuration(event.target.value)}
              disabled={running || liveCaptureUnavailable}
            />
          </Field>
          <Field id="capture-filter" label="Capture filter (BPF)" hint="e.g. tcp port 80">
            <input
              id="capture-filter"
              type="text"
              value={filter}
              onChange={(event) => setFilter(event.target.value)}
              disabled={running || liveCaptureUnavailable}
              placeholder="tcp port 80"
            />
          </Field>
        </div>

        <Field id="capture-display-filter" label="Display filter" hint="e.g. http or tls.handshake">
          <input
            id="capture-display-filter"
            type="text"
            value={displayFilter}
            onChange={(event) => setDisplayFilter(event.target.value)}
            disabled={running || liveCaptureUnavailable}
            placeholder="http"
          />
        </Field>

        <div className="row">
          <button
            type="submit"
            className="btn btn-primary"
            disabled={running || busy !== 'idle' || !interfaceName || liveCaptureUnavailable}
          >
            {busy === 'starting' ? 'Starting…' : 'Start capture'}
          </button>
          <button
            type="button"
            className="btn"
            onClick={() => void handleStop()}
            disabled={busy !== 'idle'}
          >
            {busy === 'stopping' ? 'Stopping…' : 'Stop capture'}
          </button>
        </div>
      </form>

      <div aria-live="polite">
        {actionError ? (
          <ErrorNotice title={actionError.title} message={actionError.message} />
        ) : null}
        {actionError?.hint ? <p className="muted small">{actionError.hint}</p> : null}
        {notice ? <InfoNotice title="Capture" message={notice} /> : null}
      </div>

      <div className="capture-status">
        <div className="row">
          {running ? (
            <StatusPill tone="ok" label="Capture running" />
          ) : (
            <StatusPill tone="idle" label="Capture stopped" />
          )}
          {busy !== 'idle' ? <Spinner label="Working…" /> : null}
        </div>
        {statusError ? (
          <p className="muted small">The capture status could not be refreshed: {statusError}</p>
        ) : null}
        <dl className="kv kv-inline">
          <div>
            <dt>Interface</dt>
            <dd>{status?.interface ?? '—'}</dd>
          </div>
          <div>
            <dt>Capture ID</dt>
            <dd>{status?.capture_id ? <code>{status.capture_id}</code> : '—'}</dd>
          </div>
          <div>
            <dt>Started</dt>
            <dd>{formatFullTimestamp(status?.started_at ?? null)}</dd>
          </div>
          <div>
            <dt>Packets captured</dt>
            <dd>{formatNumber(status?.packets_captured ?? 0)}</dd>
          </div>
          <div>
            <dt>Packets filtered</dt>
            <dd>{formatNumber(status?.packets_filtered ?? 0)}</dd>
          </div>
          <div>
            <dt>Capture file</dt>
            <dd>{status?.capture_file ?? '—'}</dd>
          </div>
          <div>
            <dt>Last error</dt>
            <dd>{status?.last_error ?? '—'}</dd>
          </div>
        </dl>
      </div>

      {stopped ? (
        <div className="result-block">
          <h3 className="result-title">Last stopped capture</h3>
          <dl className="kv">
            <div>
              <dt>Capture ID</dt>
              <dd>
                <code>{stopped.capture_id}</code>
              </dd>
            </div>
            <div>
              <dt>Packets captured</dt>
              <dd>{formatNumber(stopped.packets_captured)}</dd>
            </div>
            <div>
              <dt>Capture file</dt>
              <dd>{stopped.capture_file ?? '—'}</dd>
            </div>
            <div>
              <dt>Analysis ID</dt>
              <dd>{stopped.analysis_id ? <code>{stopped.analysis_id}</code> : '—'}</dd>
            </div>
          </dl>
          {stopped.analysis_id ? null : (
            <p className="muted small">
              The capture file could not be analysed, so no results are available.
            </p>
          )}
        </div>
      ) : null}
    </Card>
  );
}
