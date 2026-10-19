import { afterEach, describe, expect, it } from 'vitest'
import { cleanup, fireEvent, render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { App } from '../App'
import phase1 from '../examples/phase1-report.json'
import { EvidenceInspector } from '../components/EvidenceInspector'
import { PEFileMap } from '../components/PEFileMap'
import { parseReport } from '../lib/reportValidation'
import { buildLayout } from '../lib/layoutModel'

afterEach(cleanup)
describe('explorer interaction', () => {
  it('shows initial, Phase 0, and Phase 1 states', async () => {
    const user = userEvent.setup(); render(<App />)
    expect(screen.getByText(/Start with a synthetic example/)).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Open Phase 0 example' }))
    expect(screen.getByText('No PE structure data available in this report.')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Open PE example' }))
    expect(screen.getByRole('heading', { name: 'PE file layout' })).toBeInTheDocument()
    expect(screen.getByText('Synthetic Phase 1 PE report')).toBeInTheDocument()
  })
  it('selects by keyboard and traces evidence', async () => {
    const user = userEvent.setup(); render(<App />)
    await user.click(screen.getByRole('button', { name: 'Open PE example' }))
    expect(screen.getByText(/Choose a shape or a row/)).toBeInTheDocument()
    const map = screen.getByRole('img', { name: 'Raw PE file layout' })
    const section = within(map).getByRole('button', { name: /rdata.*0x200 to 0x400/i })
    section.focus(); fireEvent.keyDown(section, { key: 'Enter' })
    expect(screen.getByRole('heading', { name: /rdata · section 0/ })).toBeInTheDocument()
    expect(screen.getByText(/Artifact /)).toBeInTheDocument()
    expect(screen.getAllByText(/evidence-[a-f0-9]+/).length).toBeGreaterThan(0)
    expect(screen.getAllByText('verified', { selector: '.status' }).length).toBeGreaterThan(0)
  })
  it('renders report text as text, never as HTML', async () => {
    const report = structuredClone(phase1)
    report.pe_facts.find(f => f.path === 'sections.0.name')!.value = '<img src=x onerror=alert(1)>'
    render(<App />)
    const input = screen.getByLabelText('Open local JSON report') as HTMLInputElement
    fireEvent.change(input, { target: { files: [new File([JSON.stringify(report)], 'xss.json', { type: 'application/json' })] } })
    expect((await screen.findAllByText(/<img src=x onerror=alert\(1\)> · section 0/)).length).toBeGreaterThan(0)
    expect(document.querySelector('img')).toBeNull()
  })
  it('rejects malformed upload without a blank page', async () => {
    render(<App />)
    fireEvent.change(screen.getByLabelText('Open local JSON report'), { target: { files: [new File(['{'], 'bad.json')] } })
    expect(await screen.findByRole('alert')).toHaveTextContent('This file is not valid JSON.')
    expect(screen.getByRole('button', { name: 'Open PE example' })).toBeInTheDocument()
  })
  it('shows no-evidence and unresolved provenance states', () => {
    const parsed = parseReport(JSON.stringify(phase1)); if (!parsed.ok) throw Error(parsed.message)
    const report = parsed.report
    const structure = buildLayout(report).structures.find(s => s.id === 'sections.0')!
    const { rerender } = render(<EvidenceInspector report={report} structure={{ ...structure, fields: [] }} />)
    expect(screen.getByText('No related evidence recorded for this structure.')).toBeInTheDocument()
    const first = report.evidence.find(e => e.id === structure.fields[0].evidence_id)!
    first.verification_status = 'unresolved'
    first.location = { file_offset: null, rva: null, va: null, header_field: null, byte_range: null, instruction_range: null }
    rerender(<EvidenceInspector report={report} structure={structure} />)
    expect(screen.getByText('unresolved', { selector: '.status' })).toBeInTheDocument()
  })
  it('renders overlapping spans with an explicit warning and separate selectable shapes', () => {
    const parsed = parseReport(JSON.stringify(phase1)); if (!parsed.ok) throw Error(parsed.message)
    const section = buildLayout(parsed.report).structures.find(s => s.id === 'sections.0')!
    const overlapping = { ...section, id: 'second', label: 'second', track: 1, span: { start: 600, end: 700 } }
    render(<PEFileMap layout={{ structures: [section, overlapping], overlapCount: 1 }} fileSize={1024} selectedId={null} onSelect={() => {}} />)
    expect(screen.getByRole('status')).toHaveTextContent('1 overlapping span pair')
    const map = screen.getByRole('img', { name: 'Raw PE file layout' })
    expect(within(map).getAllByRole('button')).toHaveLength(2)
  })
})
