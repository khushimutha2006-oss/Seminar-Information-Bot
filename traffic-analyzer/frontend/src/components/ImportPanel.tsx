import { useRef, useState } from 'react';
import { ApiError, errorMessage } from '../api/client';
import { uploadAnalysisFile } from '../api/endpoints';
import type { AnalysisUploadResult } from '../api/types';
import { formatExactBytes, formatNumber } from '../lib/format';
import { Card, ErrorNotice, Field, Spinner } from './ui';

const ACCEPTED_EXTENSIONS = ['.pcap', '.pcapng', '.cap', '.csv'];

function extensionOf(name: string): string {
  const index = name.lastIndexOf('.');
  return index >= 0 ? name.slice(index).toLowerCase() : '';
}

export function ImportPanel(props: { onAnalysisReady: (analysisId: string) => void }) {
  const { onAnalysisReady } = props;
  const inputRef = useRef<HTMLInputElement>(null);
  const [file, setFile] = useState<File | null>(null);
  const [extensionWarning, setExtensionWarning] = useState<string | null>(null);
  const [uploading, setUploading] = useState(false);
  const [percent, setPercent] = useState(0);
  const [result, setResult] = useState<AnalysisUploadResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleFileChange = () => {
    const selected = inputRef.current?.files?.[0] ?? null;
    setFile(selected);
    setResult(null);
    setError(null);
    setPercent(0);
    if (!selected) {
      setExtensionWarning(null);
      return;
    }
    const extension = extensionOf(selected.name);
    if (!ACCEPTED_EXTENSIONS.includes(extension)) {
      setExtensionWarning(
        `"${selected.name}" does not use a supported extension (${ACCEPTED_EXTENSIONS.join(', ')}). ` +
          'It is still sent to the server so the API can reject it with its own reason.',
      );
    } else {
      setExtensionWarning(null);
    }
  };

  const handleUpload = async () => {
    if (!file || uploading) return;
    setUploading(true);
    setError(null);
    setResult(null);
    setPercent(0);
    try {
      const uploaded = await uploadAnalysisFile(file, (progress) => {
        setPercent(progress.percent);
      });
      setResult(uploaded);
      onAnalysisReady(uploaded.analysis_id);
    } catch (caught) {
      setError(
        caught instanceof ApiError
          ? caught.message
          : `The upload failed: ${errorMessage(caught)}`,
      );
    } finally {
      setUploading(false);
    }
  };

  return (
    <Card
      title="Import a capture file"
      description="Upload a .pcap, .pcapng, .cap or .csv capture. It is analysed on the server and the results appear below."
    >
      <form
        className="stack"
        onSubmit={(event) => {
          event.preventDefault();
          void handleUpload();
        }}
      >
        <Field
          id="capture-file"
          label="Capture file"
          hint="Accepted formats: .pcap, .pcapng, .cap, .csv (max upload size is set by the server)."
        >
          <input
            id="capture-file"
            ref={inputRef}
            type="file"
            accept=".pcap,.pcapng,.cap,.csv"
            onChange={handleFileChange}
            disabled={uploading}
          />
        </Field>

        {extensionWarning ? (
          <p className="notice notice-warn" role="status">
            <span className="notice-text">{extensionWarning}</span>
          </p>
        ) : null}

        <div className="row">
          <button type="submit" className="btn btn-primary" disabled={!file || uploading}>
            {uploading ? 'Analysing…' : 'Analyse file'}
          </button>
          {file && !uploading ? (
            <span className="muted">
              Selected: <code>{file.name}</code>
            </span>
          ) : null}
        </div>

        {uploading ? (
          <div className="progress-block">
            <progress value={percent} max={100} aria-label="Upload progress" />
            <span className="muted">{percent}% uploaded</span>
          </div>
        ) : null}
      </form>

      <div aria-live="polite">
        {error ? <ErrorNotice title="The capture could not be analysed" message={error} /> : null}

        {result ? (
          <div className="result-block">
            <h3 className="result-title">Analysis complete</h3>
            <dl className="kv">
              <div>
                <dt>Analysis ID</dt>
                <dd>
                  <code>{result.analysis_id}</code>
                </dd>
              </div>
              <div>
                <dt>Status</dt>
                <dd>{result.status}</dd>
              </div>
              <div>
                <dt>Source file</dt>
                <dd>{result.source_file}</dd>
              </div>
              <div>
                <dt>Source kind</dt>
                <dd>{result.source_kind}</dd>
              </div>
              <div>
                <dt>Packets</dt>
                <dd>{formatNumber(result.packet_count)}</dd>
              </div>
              <div>
                <dt>Bytes on the wire</dt>
                <dd>{formatExactBytes(result.total_bytes)}</dd>
              </div>
            </dl>

            {result.warnings.length > 0 ? (
              <>
                <h4 className="result-subtitle">
                  Warnings ({result.warnings.length})
                </h4>
                <ul className="warning-list">
                  {result.warnings.map((warning) => (
                    <li key={warning}>{warning}</li>
                  ))}
                </ul>
              </>
            ) : (
              <p className="muted">No warnings were reported for this file.</p>
            )}
          </div>
        ) : null}

        {uploading ? <Spinner label="Analysing the capture on the server…" /> : null}
      </div>
    </Card>
  );
}
