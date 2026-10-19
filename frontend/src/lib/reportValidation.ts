import schemaCheck from './generated/validator.js'
import type { Report } from './reportTypes'

export const MAX_REPORT_BYTES = 8 * 1024 * 1024
const MAX_DEPTH = 48
const MAX_NODES = 80_000
const MAX_STRING = 4096

export type ValidationResult =
  | { ok: true; report: Report }
  | { ok: false; code: 'too_large' | 'too_deep' | 'invalid_json' | 'unsupported_version' | 'invalid_schema' | 'invalid_references'; message: string }

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function safeInteger(value: number): boolean {
  return Number.isSafeInteger(value) && value >= 0
}

function validateTextBounds(text: string): ValidationResult | null {
  if (text.length > MAX_REPORT_BYTES || new TextEncoder().encode(text).byteLength > MAX_REPORT_BYTES) {
    return { ok: false, code: 'too_large', message: 'Report exceeds the 8 MiB local limit.' }
  }
  let depth = 0
  let inString = false
  let escaped = false
  for (const character of text) {
    if (inString) {
      if (escaped) escaped = false
      else if (character === '\\') escaped = true
      else if (character === '"') inString = false
    } else if (character === '"') inString = true
    else if (character === '{' || character === '[') {
      depth += 1
      if (depth > MAX_DEPTH) return { ok: false, code: 'too_deep', message: 'Report nesting is too deep.' }
    } else if (character === '}' || character === ']') depth -= 1
  }
  return null
}

function validateObjectBounds(value: unknown): boolean {
  const stack: unknown[] = [value]
  let nodes = 0
  while (stack.length) {
    const current = stack.pop()
    nodes += 1
    if (nodes > MAX_NODES) return false
    if (typeof current === 'string' && current.length > MAX_STRING) return false
    if (Array.isArray(current)) {
      if (current.length > 2_500) return false
      stack.push(...current)
    } else if (isRecord(current)) {
      const entries = Object.entries(current)
      if (entries.length > 12_000 || entries.some(([key]) => key.length > MAX_STRING)) return false
      for (const [, item] of entries) stack.push(item)
    }
  }
  return true
}

function semanticError(report: Report): string | null {
  if (!safeInteger(report.artifact.size) || report.input_sha256 !== report.artifact.sha256) {
    return 'Artifact size or SHA-256 relationship is invalid.'
  }
  const collections = [report.evidence, report.observations, report.inferences, report.disagreements, report.limitations]
  const ids = [report.artifact.id, ...collections.flatMap(items => items.map(item => item.id))]
  if (new Set(ids).size !== ids.length) return 'Entity IDs must be unique.'
  const evidenceIds = new Set(report.evidence.map(item => item.id))
  const observationIds = new Set(report.observations.map(item => item.id))
  for (const item of report.evidence) {
    if (item.artifact_id !== report.artifact.id) return 'Evidence has an unknown artifact reference.'
    const loc = item.location
    for (const address of [loc.file_offset, loc.rva, loc.va]) {
      if (address !== null && !safeInteger(address)) return 'A location contains an unsafe address.'
    }
    for (const range of [loc.byte_range, loc.instruction_range]) {
      if (range && (!safeInteger(range[0]) || !safeInteger(range[1]) || range[1] <= range[0])) {
        return 'A location contains an invalid half-open range.'
      }
    }
    if (loc.byte_range && loc.byte_range[1] > report.artifact.size) return 'A byte range exceeds the artifact.'
    if (loc.file_offset !== null && loc.file_offset >= report.artifact.size) return 'A file offset exceeds the artifact.'
    if (loc.file_offset !== null && loc.byte_range &&
        !(loc.byte_range[0] <= loc.file_offset && loc.file_offset < loc.byte_range[1])) {
      return 'A file offset lies outside its byte range.'
    }
    const hasLocation = Object.values(loc).some(part => part !== null)
    if (item.verification_status === 'verified' && !hasLocation) return 'Verified evidence has no location.'
    if (report.schema_version === '1.1.0' && item.verification_status === 'verified' && !loc.byte_range) {
      return 'Phase 1 verified evidence needs a raw byte range.'
    }
    if (item.verification_status === 'unresolved' && hasLocation) return 'Unresolved evidence claims a location.'
  }
  for (const item of report.observations) {
    if (item.evidence_ids.some(id => !evidenceIds.has(id))) return 'Observation has a missing evidence reference.'
  }
  for (const item of report.inferences) {
    if (item.observation_ids.some(id => !observationIds.has(id))) return 'Inference has a missing observation reference.'
  }
  for (const item of report.disagreements) {
    if (item.evidence_ids.some(id => !evidenceIds.has(id))) return 'Disagreement has a missing evidence reference.'
  }
  for (const item of report.limitations) {
    if (item.subject_id !== null && !ids.includes(item.subject_id)) return 'Limitation has a missing subject reference.'
  }
  if (report.pe_facts) {
    const paths = report.pe_facts.map(item => item.path)
    if (new Set(paths).size !== paths.length) return 'PE fact paths must be unique.'
    if (report.pe_facts.some(item => !evidenceIds.has(item.evidence_id))) return 'PE fact has a missing evidence reference.'
    const evidenceById = new Map(report.evidence.map(item => [item.id, item]))
    if (report.pe_facts.some(item => {
      const source = evidenceById.get(item.evidence_id)!
      return source.verification_status === 'verified' && source.location.header_field !== item.path
    })) return 'Verified PE fact evidence points to a different field.'
    if (report.pe_facts.some(item => typeof item.value === 'number' && !Number.isFinite(item.value))) {
      return 'PE fact contains a non-finite number.'
    }
  }
  if (report.comparison && report.comparison.disagreement_count !== report.disagreements.length) {
    return 'Comparison count disagrees with the report.'
  }
  return null
}

export function parseReport(text: string): ValidationResult {
  const bounds = validateTextBounds(text)
  if (bounds) return bounds
  let value: unknown
  try {
    value = JSON.parse(text)
  } catch {
    return { ok: false, code: 'invalid_json', message: 'This file is not valid JSON.' }
  }
  if (!validateObjectBounds(value)) {
    return { ok: false, code: 'too_large', message: 'Report contains too many or overly long values.' }
  }
  if (isRecord(value) && typeof value.schema_version === 'string' &&
      value.schema_version !== '1.0.0' && value.schema_version !== '1.1.0') {
    return { ok: false, code: 'unsupported_version', message: `Unsupported schema version: ${value.schema_version}` }
  }
  if (!schemaCheck(value)) {
    const issue = schemaCheck.errors?.[0]
    return { ok: false, code: 'invalid_schema', message: `Report does not match the MalVisor schema${issue ? ` at ${issue.instancePath || 'root'}` : ''}.` }
  }
  const report = value as unknown as Report
  const error = semanticError(report)
  if (error) return { ok: false, code: 'invalid_references', message: error }
  return { ok: true, report }
}
