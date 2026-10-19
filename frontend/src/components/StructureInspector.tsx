import type { Report } from '../lib/reportTypes'
import type { Structure } from '../lib/layoutModel'
import { bytes, display, fieldName, hex } from '../lib/formatters'

export function StructureInspector({ structure, report }: { structure: Structure | null; report: Report }) {
  return <section className="panel inspector" aria-labelledby="structure-heading">
    <p className="eyebrow">02 / STRUCTURE</p><h2 id="structure-heading">{structure?.label ?? 'Select a structure'}</h2>
    {!structure ? <p className="empty-inline">Choose a shape or a row to inspect its reported fields.</p> : <>
      <p className="subtle">{structure.locationNote}</p>
      <div className="location-card">
        <span>RAW SPAN</span><strong>{structure.span ? `[${hex(structure.span.start)}, ${hex(structure.span.end)})` : 'Not mapped'}</strong>
        <small>{structure.span ? bytes(structure.span.end - structure.span.start) : 'No verified positive-length raw span'}</small>
      </div>
      {structure.kind === 'overlay' && <p className="notice">A candidate overlay may be padding or other data. Its presence alone is not evidence of malware or packing.</p>}
      <h3>Reported fields</h3>
      <dl className="field-list">{structure.fields.map(f => <div key={f.path}><dt title={f.path}>{fieldName(f.path)}</dt><dd>{display(f.value)}</dd>{f.note && <small>{f.note}</small>}</div>)}</dl>
      {structure.fields.length === 0 && <p className="empty-inline">No fields recorded.</p>}
      {report.limitations.length > 0 && <><h3>Report limitations</h3><ul className="limitation-list">{report.limitations.filter(l => !l.subject_id || structure.fields.some(f => f.evidence_id === l.subject_id)).slice(0, 8).map(l => <li key={l.id}>{l.description}</li>)}</ul></>}
    </>}
  </section>
}
