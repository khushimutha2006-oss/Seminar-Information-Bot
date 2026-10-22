import type { ReactNode } from 'react';

export function Card(props: {
  title: string;
  description?: string;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  const { title, description, actions, children, className } = props;
  return (
    <section className={`card${className ? ` ${className}` : ''}`}>
      <header className="card-head">
        <div>
          <h2 className="card-title">{title}</h2>
          {description ? <p className="card-description">{description}</p> : null}
        </div>
        {actions ? <div className="card-actions">{actions}</div> : null}
      </header>
      {children}
    </section>
  );
}

export function Field(props: {
  id: string;
  label: string;
  hint?: string;
  children: ReactNode;
  className?: string;
}) {
  const { id, label, hint, children, className } = props;
  return (
    <div className={`field${className ? ` ${className}` : ''}`}>
      <label htmlFor={id}>{label}</label>
      {children}
      {hint ? (
        <p className="field-hint" id={`${id}-hint`}>
          {hint}
        </p>
      ) : null}
    </div>
  );
}

/** Inline error box. The text is always the backend's own `error.message`. */
export function ErrorNotice(props: { title?: string; message: string; onDismiss?: () => void }) {
  const { title = 'Request failed', message, onDismiss } = props;
  return (
    <div className="notice notice-error" role="alert">
      <div className="notice-body">
        <strong className="notice-title">{title}</strong>
        <p className="notice-text">{message}</p>
      </div>
      {onDismiss ? (
        <button type="button" className="btn btn-ghost btn-small" onClick={onDismiss}>
          Dismiss
        </button>
      ) : null}
    </div>
  );
}

export function InfoNotice(props: { title: string; message: string; tone?: 'info' | 'warn' }) {
  const { title, message, tone = 'info' } = props;
  return (
    <div className={`notice notice-${tone}`} role="status">
      <div className="notice-body">
        <strong className="notice-title">{title}</strong>
        <p className="notice-text">{message}</p>
      </div>
    </div>
  );
}

export function EmptyState(props: { title: string; message: string; children?: ReactNode }) {
  const { title, message, children } = props;
  return (
    <div className="empty-state">
      <p className="empty-title">{title}</p>
      <p className="empty-text">{message}</p>
      {children}
    </div>
  );
}

export function Spinner(props: { label?: string }) {
  return (
    <span className="spinner" role="status" aria-live="polite">
      <span className="spinner-dot" aria-hidden="true" />
      {props.label ? <span className="spinner-label">{props.label}</span> : null}
      <span className="sr-only">Loading</span>
    </span>
  );
}

export function StatusPill(props: { tone: 'ok' | 'warn' | 'error' | 'idle'; label: string }) {
  return <span className={`pill pill-${props.tone}`}>{props.label}</span>;
}
