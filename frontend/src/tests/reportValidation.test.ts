import { describe, expect, it } from 'vitest'
import phase1 from '../examples/phase1-report.json'
import phase0 from '../../../examples/example-report.json'
import { MAX_REPORT_BYTES, parseReport } from '../lib/reportValidation'

const clone = () => structuredClone(phase1) as typeof phase1
describe('untrusted report validation', () => {
  it('accepts actual backend 1.1 and Phase 0 1.0 reports', () => {
    expect(parseReport(JSON.stringify(phase1)).ok).toBe(true)
    expect(parseReport(JSON.stringify(phase0)).ok).toBe(true)
  })
  it('rejects malformed, oversized, deeply nested and unsupported input', () => {
    expect(parseReport('{').ok).toBe(false)
    expect(parseReport(' '.repeat(MAX_REPORT_BYTES + 1))).toMatchObject({ ok: false, code: 'too_large' })
    expect(parseReport('['.repeat(49) + '0' + ']'.repeat(49))).toMatchObject({ ok: false, code: 'too_deep' })
    const report = clone(); report.schema_version = '9.0.0'
    expect(parseReport(JSON.stringify(report))).toMatchObject({ ok: false, code: 'unsupported_version' })
  })
  it('rejects missing required fields, bad evidence references, and invalid raw ranges', () => {
    const missing = clone() as Partial<typeof phase1>; delete missing.artifact
    expect(parseReport(JSON.stringify(missing))).toMatchObject({ ok: false, code: 'invalid_schema' })
    const badRef = clone(); badRef.pe_facts[0].evidence_id = 'missing'
    expect(parseReport(JSON.stringify(badRef))).toMatchObject({ ok: false, code: 'invalid_references' })
    const wrongField = clone(); wrongField.pe_facts[0].evidence_id = wrongField.pe_facts[1].evidence_id
    expect(parseReport(JSON.stringify(wrongField))).toMatchObject({ ok: false, code: 'invalid_references' })
    const badRange = clone(); badRange.evidence[0].location.byte_range = [0, phase1.artifact.size + 1]
    expect(parseReport(JSON.stringify(badRange))).toMatchObject({ ok: false, code: 'invalid_references' })
  })
  it('rejects oversized collections and duplicate entity IDs', () => {
    const huge = clone(); huge.pe_facts = Array(12_001).fill(huge.pe_facts[0])
    expect(parseReport(JSON.stringify(huge)).ok).toBe(false)
    const dup = clone(); dup.evidence[1].id = dup.evidence[0].id
    expect(parseReport(JSON.stringify(dup))).toMatchObject({ ok: false, code: 'invalid_references' })
  })
})
