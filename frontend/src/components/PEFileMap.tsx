import { useState } from 'react'
import type { Layout, Structure } from '../lib/layoutModel'
import { bytes, hex } from '../lib/formatters'

interface Props { layout: Layout; fileSize: number; selectedId: string | null; onSelect: (id: string) => void }
const colors: Record<Structure['kind'], string> = {
  header: '#6aa5e7', section: '#61c9a7', directory: '#e6b967', overlay: '#b39ae7',
}

export function PEFileMap({ layout, fileSize, selectedId, onSelect }: Props) {
  const [zoom, setZoom] = useState(1)
  const maxTrack = Math.max(0, ...layout.structures.map(s => s.track))
  const mapped = layout.structures.filter(s => s.span)
  const unresolved = layout.structures.filter(s => !s.span)
  return <section className="panel map-panel" aria-labelledby="map-heading">
    <div className="panel-heading"><div><p className="eyebrow">01 / RAW ADDRESS SPACE</p><h2 id="map-heading">PE file layout</h2></div>
      <div className="zoom-controls" aria-label="Map zoom">
        <button type="button" onClick={() => setZoom(z => Math.max(1, z / 2))} disabled={zoom === 1} aria-label="Zoom out">−</button>
        <span>{zoom}×</span>
        <button type="button" onClick={() => setZoom(z => Math.min(8, z * 2))} disabled={zoom === 8} aria-label="Zoom in">+</button>
        <button type="button" onClick={() => setZoom(1)} disabled={zoom === 1}>Reset</button>
      </div>
    </div>
    <p className="subtle">Raw offsets · {bytes(fileSize)} · half-open spans [start, end)</p>
    {layout.overlapCount > 0 && <p className="notice" role="status">{layout.overlapCount} overlapping span pair{layout.overlapCount === 1 ? '' : 's'} shown on separate tracks.</p>}
    {fileSize > 0 && mapped.length > 0 ? <div className="map-scroll" aria-label="Scrollable file layout">
      <svg className="file-map" viewBox={`0 0 ${420 + maxTrack * 32} 1000`} height={640 * zoom} role="img" aria-label="Raw PE file layout">
        <rect x="76" y="0" width="270" height="1000" rx="5" fill="#101c2a" stroke="#344a60" />
        {[0, .25, .5, .75, 1].map(fraction => <g key={fraction}>
          <line x1="67" y1={fraction * 998 + 1} x2={350 + maxTrack * 32} y2={fraction * 998 + 1} stroke="#385065" strokeDasharray="3 5" />
          <text x="3" y={Math.min(990, fraction * 998 + 13)} fill="#a2b5c6" fontSize="12">{hex(Math.floor(fileSize * fraction))}</text>
        </g>)}
        {mapped.map(s => {
          const span = s.span!
          const y = span.start / fileSize * 1000
          const trueHeight = (span.end - span.start) / fileSize * 1000
          const height = Math.max(2.5, trueHeight)
          const x = 82 + s.track * 32
          return <g key={s.id} className="map-item" role="button" tabIndex={0} aria-label={`${s.label}, ${hex(span.start)} to ${hex(span.end)}`} aria-pressed={selectedId === s.id}
            onClick={() => onSelect(s.id)} onKeyDown={event => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); onSelect(s.id) } }}>
            <title>{`${s.label}: [${hex(span.start)}, ${hex(span.end)})${trueHeight < 2.5 ? ' · minimum visual marker' : ''}`}</title>
            <rect x={x} y={Math.min(997.5, y)} width={Math.max(42, 254 - s.track * 12)} height={height} rx="3"
              fill={colors[s.kind]} fillOpacity={selectedId === s.id ? 1 : .72} stroke={selectedId === s.id ? '#fff' : '#152331'} strokeWidth={selectedId === s.id ? 2 : 1} />
            {trueHeight >= 22 && <text x={x + 8} y={y + 16} fill="#071521" fontSize="12" fontWeight="700" pointerEvents="none">{s.label.slice(0, 31)}</text>}
          </g>
        })}
      </svg>
    </div> : <p className="empty-inline">No verified raw spans available.</p>}
    <div className="legend" aria-label="Structure legend">{Object.keys(colors).map(kind => <span key={kind}><i className={kind} />{kind}</span>)}</div>
    <h3>Structures <span className="count">{layout.structures.length}</span></h3>
    <div className="structure-list" role="list">
      {layout.structures.map(s => <div key={s.id} role="listitem"><button type="button" className={`structure-row ${selectedId === s.id ? 'selected' : ''}`} onClick={() => onSelect(s.id)}>
        <span className={`kind-tag ${s.kind}`}>{s.kind}</span><strong>{s.label}</strong>
        <small>{s.span ? `${hex(s.span.start)}–${hex(s.span.end)} · ${bytes(s.span.end - s.span.start)}` : 'Unmapped / zero raw size'}</small>
      </button></div>)}
    </div>
    {unresolved.length > 0 && <p className="subtle">{unresolved.length} item{unresolved.length === 1 ? '' : 's'} remain outside the raw map. See their inspector fields for RVA or unresolved details.</p>}
  </section>
}
