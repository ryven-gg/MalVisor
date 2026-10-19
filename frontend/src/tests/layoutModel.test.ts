import { describe, expect, it } from 'vitest'
import phase1 from '../examples/phase1-report.json'
import phase0 from '../../../examples/example-report.json'
import { buildLayout } from '../lib/layoutModel'
import { parseReport } from '../lib/reportValidation'
import type { Report } from '../lib/reportTypes'

function report(): Report { const result = parseReport(JSON.stringify(phase1)); if (!result.ok) throw Error(result.message); return result.report }
function fact(r: Report, path: string) { return r.pe_facts!.find(f => f.path === path)! }
describe('raw PE layout', () => {
  it('keeps Phase 0 empty', () => {
    const parsed = parseReport(JSON.stringify(phase0)); if (!parsed.ok) throw Error(parsed.message)
    expect(buildLayout(parsed.report).structures).toEqual([])
  })
  it('derives deterministic byte positions from backend report', () => {
    const r = report(); const a = buildLayout(r); const b = buildLayout(r)
    expect(a).toEqual(b)
    expect(a.structures.find(s => s.id === 'dos')?.span).toEqual({ start: 0, end: 64 })
    expect(a.structures.find(s => s.id === 'coff')?.span).toEqual({ start: 128, end: 152 })
    expect(a.structures.find(s => s.id === 'sections.0')?.span).toEqual({ start: 512, end: 1024 })
    expect(a.structures.find(s => s.id === 'directories.1')?.span).toBeNull()
  })
  it('does not fabricate a raw span from an RVA-only directory', () => {
    const r = report(); fact(r, 'directories.1.rva').value = 512
    expect(buildLayout(r).structures.find(s => s.id === 'directories.1')?.span).toBeNull()
  })
  it('handles zero size and invalid raw ranges without drawing them', () => {
    const r = report(); fact(r, 'sections.0.size_of_raw_data').value = 0
    expect(buildLayout(r).structures.find(s => s.id === 'sections.0')?.span).toBeNull()
    fact(r, 'sections.0.size_of_raw_data').value = 9000
    expect(buildLayout(r).structures.find(s => s.id === 'sections.0')?.span).toBeNull()
  })
  it('assigns overlapping spans separate tracks', () => {
    const r = report()
    // Layout-only fixture: mutate a verified location to overlap the raw section.
    r.pe_facts!.push({ path: 'overlay.offset', value: 600, evidence_id: fact(r, 'sections.0.pointer_to_raw_data').evidence_id, note: null })
    r.pe_facts!.push({ path: 'overlay.size', value: 50, evidence_id: fact(r, 'sections.0.size_of_raw_data').evidence_id, note: null })
    const layout = buildLayout(r)
    expect(layout.overlapCount).toBeGreaterThan(0)
    expect(layout.structures.find(s => s.id === 'overlay')?.track).not.toBe(layout.structures.find(s => s.id === 'sections.0')?.track)
  })
})
