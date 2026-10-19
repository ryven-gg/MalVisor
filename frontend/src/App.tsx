import { useMemo, useState, type ChangeEvent } from 'react'
import phase1 from './examples/phase1-report.json'
import phase0 from '../../examples/example-report.json'
import { parseReport, MAX_REPORT_BYTES } from './lib/reportValidation'
import { buildLayout } from './lib/layoutModel'
import type { Report } from './lib/reportTypes'
import { bytes } from './lib/formatters'
import { PEFileMap } from './components/PEFileMap'
import { StructureInspector } from './components/StructureInspector'
import { EvidenceInspector } from './components/EvidenceInspector'

type LoadState = 'empty' | 'loading' | 'loaded' | 'error'

function readLocalFile(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader()
    reader.onload = () => typeof reader.result === 'string' ? resolve(reader.result) : reject(new Error('non-text result'))
    reader.onerror = () => reject(reader.error)
    reader.readAsText(file)
  })
}

export function App() {
  const [report, setReport] = useState<Report | null>(null)
  const [sourceName, setSourceName] = useState('')
  const [state, setState] = useState<LoadState>('empty')
  const [error, setError] = useState('')
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const layout = useMemo(() => report ? buildLayout(report) : null, [report])
  const selected = layout?.structures.find(s => s.id === selectedId) ?? null

  function loadText(text: string, label: string) {
    const result = parseReport(text)
    setSelectedId(null)
    if (!result.ok) {
      setReport(null); setState('error'); setError(result.message); setSourceName(label)
      return
    }
    setReport(result.report); setSourceName(label); setError(''); setState('loaded')
  }

  async function loadFile(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0]
    event.target.value = ''
    if (!file) return
    setState('loading'); setError(''); setReport(null); setSelectedId(null)
    if (file.size > MAX_REPORT_BYTES) {
      setSourceName(file.name); setState('error'); setError('Report exceeds the 8 MiB local limit.'); return
    }
    try { loadText(await readLocalFile(file), file.name) }
    catch { setSourceName(file.name); setState('error'); setError('Could not read this local file.') }
  }

  const sha = report?.input_sha256 ? `${report.input_sha256.slice(0, 12)}…${report.input_sha256.slice(-8)}` : '—'
  const architecture = report?.pe_facts?.find(f => f.path === 'coff.architecture')?.value ?? report?.artifact.format ?? '—'
  return <div className="app-shell">
    <header className="app-header">
      <div className="brand"><div className="brand-mark" aria-hidden="true">M<span>V</span></div><div><strong>MalVisor</strong><small>STATIC PE EXPLORER / PHASE 2A</small></div></div>
      <div className="header-meta"><span>OFFLINE / LOCAL</span><span className="header-status">{state === 'loaded' ? 'REPORT LOADED' : state === 'error' ? 'IMPORT ERROR' : state === 'loading' ? 'LOADING' : 'READY'}</span></div>
    </header>
    <main>
      <section className="intro">
        <div><p className="eyebrow">REPORT WORKSPACE</p><h1>See the bytes.<br /><em>Keep the evidence.</em></h1><p>Explore a static MalVisor JSON report. Your file stays in this browser session.</p></div>
        <div className="loader-card">
          <label className="upload-button">Open local JSON<input type="file" accept=".json,application/json" onChange={loadFile} aria-label="Open local JSON report" /></label>
          <div className="example-actions"><button type="button" onClick={() => loadText(JSON.stringify(phase1), 'Synthetic Phase 1 PE report')}>Open PE example</button><button type="button" onClick={() => loadText(JSON.stringify(phase0), 'Phase 0 report')}>Open Phase 0 example</button></div>
          <p>8 MiB maximum · Browser local · No sample upload</p>
        </div>
      </section>

      {state === 'empty' && <section className="welcome panel"><div className="welcome-icon" aria-hidden="true">⌑</div><p className="eyebrow">NO REPORT OPEN</p><h2>Start with a synthetic example or choose a report.</h2><p>Use <code>python -m malvisor analyze</code> to create a JSON report from a local PE file.</p></section>}
      {state === 'loading' && <section className="welcome panel" role="status"><p className="eyebrow">READING LOCAL FILE</p><h2>Validating report…</h2></section>}
      {state === 'error' && <section className="error-state panel" role="alert"><p className="eyebrow">REPORT REJECTED</p><h2>Could not open {sourceName}</h2><p>{error}</p><p className="subtle">The current report was cleared. Try a supported MalVisor schema 1.0.0 or 1.1.0 JSON report.</p></section>}
      {state === 'loaded' && report && layout && <>
        <section className="summary panel" aria-label="Report summary">
          <div><span>REPORT</span><strong title={sourceName}>{sourceName}</strong></div>
          <div><span>SHA-256</span><strong className="mono" title={report.input_sha256}>{sha}</strong></div>
          <div><span>FORMAT / MACHINE</span><strong>{String(architecture)}</strong></div>
          <div><span>FILE SIZE</span><strong>{bytes(report.artifact.size)}</strong></div>
          <div><span>SCHEMA</span><strong>{report.schema_version}</strong></div>
          <div><span>BACKEND EVIDENCE</span><strong>{report.evidence.filter(e => e.verification_status === 'verified').length} verified / {report.evidence.length} total</strong></div>
        </section>
        {!report.pe_facts?.length ? <section className="welcome panel" role="status"><p className="eyebrow">SCHEMA {report.schema_version}</p><h2>No PE structure data available in this report.</h2><p>Phase 0 reports remain readable, but this file contains no structural facts for the map.</p></section> :
          <div className="workspace"><PEFileMap layout={layout} fileSize={report.artifact.size} selectedId={selectedId} onSelect={setSelectedId} />
            <div className="inspector-column"><StructureInspector structure={selected} report={report} /><EvidenceInspector structure={selected} report={report} /></div></div>}
      </>}
    </main>
    <footer>MalVisor Phase 2A · Static analysis only · Report data is displayed as text</footer>
  </div>
}
