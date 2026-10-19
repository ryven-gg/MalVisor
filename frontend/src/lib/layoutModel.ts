import type { Evidence, Report, StructuralFact } from './reportTypes'

export interface RawSpan { start: number; end: number }
export interface Structure {
  id: string
  label: string
  kind: 'header' | 'section' | 'directory' | 'overlay'
  fields: StructuralFact[]
  span: RawSpan | null
  locationNote: string
  track: number
}

export interface Layout { structures: Structure[]; overlapCount: number }

const directoryNames = [
  'Export', 'Import', 'Resource', 'Exception', 'Certificate', 'Base relocation',
  'Debug', 'Architecture', 'Global pointer', 'TLS', 'Load config', 'Bound import',
  'Import address table', 'Delay import', 'CLR', 'Reserved',
]

export function buildLayout(report: Report): Layout {
  if (!report.pe_facts?.length) return { structures: [], overlapCount: 0 }
  const facts = new Map(report.pe_facts.map(f => [f.path, f]))
  const evidence = new Map(report.evidence.map(e => [e.id, e]))
  const fileSize = report.artifact.size
  const structures: Structure[] = []
  const validSpan = (start: unknown, length: unknown): RawSpan | null => {
    if (typeof start !== 'number' || typeof length !== 'number' ||
        !Number.isSafeInteger(start) || !Number.isSafeInteger(length) ||
        start < 0 || length <= 0 || start > fileSize || length > fileSize - start) return null
    return { start, end: start + length }
  }
  const verified = (path: string): Evidence | null => {
    const fact = facts.get(path)
    const item = fact && evidence.get(fact.evidence_id)
    return item?.verification_status === 'verified' && item.location.byte_range ? item : null
  }
  const number = (path: string): number | null => {
    const value = facts.get(path)?.value
    return verified(path) && typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 ? value : null
  }
  const fields = (prefix: string): StructuralFact[] => report.pe_facts!.filter(f => f.path.startsWith(prefix + '.'))
  const add = (id: string, label: string, kind: Structure['kind'], itemFields: StructuralFact[], span: RawSpan | null, locationNote: string) => {
    structures.push({ id, label, kind, fields: itemFields, span, locationNote, track: 0 })
  }

  const dos = verified('dos.valid')?.location.byte_range
  add('dos', 'DOS header', 'header', fields('dos'), dos ? validSpan(dos[0], dos[1] - dos[0]) : null,
    'Raw range from verified DOS header evidence')

  const signature = verified('coff.pe_signature')?.location.byte_range
  const coffEnd = verified('coff.characteristics')?.location.byte_range?.[1]
  const coffSpan = signature && coffEnd !== undefined ? validSpan(signature[0], coffEnd - signature[0]) : null
  add('coff', 'PE signature + COFF header', 'header', fields('coff'), coffSpan,
    'Raw range bounded by verified signature and COFF fields')

  const optStart = verified('optional.magic')?.location.byte_range?.[0]
  const optSize = number('coff.size_of_optional_header')
  add('optional', 'Optional header', 'header', fields('optional'),
    optStart !== undefined && optSize !== null ? validSpan(optStart, optSize) : null,
    'Uses verified optional-header start and declared COFF size')

  const sectionIndices = [...new Set(report.pe_facts.flatMap(f => {
    const match = /^sections\.(\d+)\./.exec(f.path)
    return match ? [Number(match[1])] : []
  }))].sort((a, b) => a - b)
  const rowStarts = sectionIndices.map(index => verified(`sections.${index}.name`)?.location.byte_range?.[0])
  const count = number('coff.number_of_sections')
  const contiguous = count === sectionIndices.length && rowStarts.length > 0 && rowStarts.every((start, index) =>
    start !== undefined && (index === 0 || start === rowStarts[0]! + index * 40))
  add('section-table', 'Section table', 'header', sectionIndices.flatMap(index => fields(`sections.${index}`)),
    contiguous ? validSpan(rowStarts[0], sectionIndices.length * 40) : null,
    '40-byte rows from verified section-name locations')

  for (const index of sectionIndices) {
    const prefix = `sections.${index}`
    const rawOffset = number(`${prefix}.pointer_to_raw_data`)
    const rawSize = number(`${prefix}.size_of_raw_data`)
    const bounds = facts.get(`${prefix}.raw_bounds_valid`)
    const boundsVerified = verified(`${prefix}.raw_bounds_valid`) && bounds?.value === true
    const span = boundsVerified && rawOffset !== null && rawSize !== null ? validSpan(rawOffset, rawSize) : null
    const label = String(facts.get(`${prefix}.name`)?.value ?? `Section ${index}`)
    add(prefix, `${label} · section ${index}`, 'section', fields(prefix), span,
      rawSize === 0 ? 'Zero raw bytes; no span on the file map' : span ? 'Verified raw section bounds' : 'Raw location unavailable or unresolved')
  }

  const directoryIndices = [...new Set(report.pe_facts.flatMap(f => {
    const match = /^directories\.(\d+)\./.exec(f.path)
    return match ? [Number(match[1])] : []
  }))].sort((a, b) => a - b)
  for (const index of directoryIndices) {
    const prefix = `directories.${index}`
    const size = number(`${prefix}.size`)
    const state = facts.get(`${prefix}.consistency`)?.value
    if (state === 'absent' || size === 0) continue
    const offset = index === 4 && state === 'raw' ? number(`${prefix}.file_offset`) : null
    const span = offset !== null && size !== null ? validSpan(offset, size) : null
    add(prefix, `${directoryNames[index] ?? `Directory ${index}`} directory`, 'directory', fields(prefix), span,
      index === 4 ? (span ? 'Certificate directory uses a raw file offset' : 'Raw certificate location unavailable') :
        'RVA location only; no raw span exported for this directory')
  }

  const overlayOffset = number('overlay.offset')
  const overlaySize = number('overlay.size')
  if (overlaySize !== null && overlaySize > 0) {
    add('overlay', 'Candidate overlay', 'overlay', fields('overlay'),
      overlayOffset !== null ? validSpan(overlayOffset, overlaySize) : null,
      'Backend layout estimate; overlay alone is not a security verdict')
  }

  const occupied: RawSpan[][] = []
  const mapped = structures.filter(s => s.span).sort((a, b) => a.span!.start - b.span!.start || a.span!.end - b.span!.end)
  let overlapCount = 0
  for (const [index, structure] of mapped.entries()) {
    overlapCount += mapped.slice(0, index).filter(other => other.span!.end > structure.span!.start).length
    let track = 0
    while (occupied[track]?.some(other => other.end > structure.span!.start && other.start < structure.span!.end)) track++
    structure.track = track
    ;(occupied[track] ??= []).push(structure.span!)
  }
  return { structures, overlapCount }
}
