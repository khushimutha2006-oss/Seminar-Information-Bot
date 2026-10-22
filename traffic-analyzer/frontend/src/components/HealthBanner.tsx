import { useEffect, useState } from 'react';
import { getHealth } from '../api/endpoints';
import { errorMessage } from '../api/client';
import type { HealthResponse } from '../api/types';
import { ErrorNotice, Spinner, StatusPill } from './ui';

type HealthState =
  | { kind: 'loading' }
  | { kind: 'ready'; health: HealthResponse }
  | { kind: 'error'; message: string };

export function HealthBanner() {
  const [state, setState] = useState<HealthState>({ kind: 'loading' });

  useEffect(() => {
    let cancelled = false;
    getHealth()
      .then((health) => {
        if (!cancelled) setState({ kind: 'ready', health });
      })
      .catch((error: unknown) => {
        if (!cancelled) setState({ kind: 'error', message: errorMessage(error) });
      });
    return () => {
      cancelled = true;
    };
  }, []);

  if (state.kind === 'loading') {
    return (
      <div className="health-banner">
        <Spinner label="Checking the analyzer API…" />
      </div>
    );
  }

  if (state.kind === 'error') {
    return (
      <div className="health-banner">
        <ErrorNotice
          title="The analyzer API is unreachable"
          message={state.message}
        />
      </div>
    );
  }

  const { health } = state;
  const tshark = health.tshark;

  return (
    <div className="health-banner">
      <div className="health-row">
        <StatusPill tone={health.status === 'ok' ? 'ok' : 'warn'} label={`API ${health.status}`} />
        <dl className="health-meta">
          <div>
            <dt>Contract</dt>
            <dd>{health.contract_version}</dd>
          </div>
          <div>
            <dt>App</dt>
            <dd>{health.app_version}</dd>
          </div>
          <div>
            <dt>Python</dt>
            <dd>{health.python}</dd>
          </div>
          <div>
            <dt>Uptime</dt>
            <dd>{Math.round(health.uptime_seconds)} s</dd>
          </div>
        </dl>
      </div>

      <div className="health-row">
        {tshark.available ? (
          <StatusPill tone="ok" label="TShark available" />
        ) : (
          <StatusPill tone="warn" label="TShark missing" />
        )}
        <span className="health-tshark">
          {tshark.path ? <code>{tshark.path}</code> : null}
          {tshark.version ? <span>{tshark.version}</span> : null}
        </span>
      </div>

      {!tshark.available ? (
        <p className="health-warning" role="status">
          TShark is not installed on the server, so protocol dissection falls back to the
          built-in pure-python reader and <strong>live capture is unavailable</strong>.
          Offline analysis of uploaded capture files still works.
        </p>
      ) : null}
    </div>
  );
}
