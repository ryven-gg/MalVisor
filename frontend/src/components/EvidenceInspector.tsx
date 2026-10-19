import type { Report } from '../lib/reportTypes'
import type { Structure } from '../lib/layoutModel'
import { hex } from '../lib/formatters'

export function EvidenceInspector({ structure, report }: { structure: Structure | null; report: Report }) {
  const ids = new Set(structure?.fields.map(f => f.evidence_id) ?? [])
  const evidence = report.evidence.filter(e => ids.has(e.id))
  const observations = report.observations.filter(o => o.evidence_ids.some(id => ids.has(id)))
  return <section className="panel evidence-panel" aria-labelledby="evidence-heading">
    <p className="eyebrow">03 / PROVENANCE</p><h2 id="evidence-heading">Evidence trail</h2>
    {!structure ? <p className="empty-inline">Select a structure to trace Artifact → Evidence → Observation.</p> : evidence.length === 0 ? <p className="empty-inline">No related evidence recorded for this structure.</p> : <>
      <p className="subtle">Backend verification status is shown as reported. Browser validation checks the JSON shape and references only.</p>
      <p className="trail">Artifact <code>{report.artifact.id}</code> → {evidence.length} evidence → {observations.length} observations</p>
      <div className="evidence-list">{evidence.map(e => {
        const loc = e.location
        const related = observations.filter(o => o.evidence_ids.includes(e.id))
        return <article key={e.id} className="evidence-card">
          <div className="evidence-head"><span className={`status ${e.verification_status}`}>{e.verification_status}</span><code>{e.id}</code></div>
          <dl>
            <div><dt>Artifact</dt><dd>{e.artifact_id}</dd></div>
            <div><dt>Parser / source</dt><dd>{e.source}</dd></div>
            <div><dt>Method</dt><dd>{e.method}</dd></div>
            {loc.header_field && <div><dt>Header field</dt><dd>{loc.header_field}</dd></div>}
            {loc.file_offset !== null && <div><dt>File offset</dt><dd>{hex(loc.file_offset)}</dd></div>}
            {loc.byte_range && <div><dt>Byte range</dt><dd>[{hex(loc.byte_range[0])}, {hex(loc.byte_range[1])})</dd></div>}
            {loc.rva !== null && <div><dt>RVA</dt><dd>{hex(loc.rva)}</dd></div>}
            {loc.va !== null && <div><dt>VA</dt><dd>{hex(loc.va)}</dd></div>}
          </dl>
          {e.excerpt_hex && <div className="excerpt"><span>HEX EXCERPT</span><code>{e.excerpt_hex}</code></div>}
          {related.map(o => <p className="observation" key={o.id}><span>Observation <code>{o.id}</code></span>{o.description}</p>)}
        </article>
      })}</div>
    </>}
  </section>
}
