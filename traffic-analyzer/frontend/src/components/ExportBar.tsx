import { exportUrl } from '../api/endpoints';
import type { PacketFilters } from '../api/params';
import { Card } from './ui';

export function ExportBar(props: { analysisId: string | null; filters: PacketFilters }) {
  const { analysisId, filters } = props;

  if (!analysisId) {
    return (
      <Card title="Exports" description="Download the analysis results.">
        <p className="muted">Load an analysis first — exports are produced by the API from a stored analysis.</p>
      </Card>
    );
  }

  const csvUrl = exportUrl(analysisId, 'packets.csv', filters);
  const jsonUrl = exportUrl(analysisId, 'summary.json', filters);

  return (
    <Card title="Exports" description="Download the analysis results.">
      <div className="row">
        <a className="btn btn-primary" href={csvUrl} target="_blank" rel="noopener noreferrer">
          Packets (CSV)
        </a>
        <a className="btn" href={jsonUrl} target="_blank" rel="noopener noreferrer">
          Summary (JSON)
        </a>
      </div>
      <p className="muted small">
        The exports use the filters currently applied in the packet explorer. The CSV export
        contains every matching packet of the analysis, not only the rows on screen.
      </p>
      <p className="query-line">
        <span className="muted small">Export query:</span> <code>{csvUrl.split('?')[1] ?? ''}</code>
      </p>
    </Card>
  );
}
