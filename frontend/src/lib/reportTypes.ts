export type VerificationStatus = 'verified' | 'pending' | 'unresolved'
export type Confidence = 'high' | 'medium' | 'low' | 'unknown'

export interface Location {
  file_offset: number | null
  rva: number | null
  va: number | null
  header_field: string | null
  byte_range: [number, number] | null
  instruction_range: [number, number] | null
}

export interface Evidence {
  id: string
  artifact_id: string
  source: string
  method: string
  verification_status: VerificationStatus
  location: Location
  excerpt_hex?: string | null
}

export interface Observation {
  id: string
  description: string
  evidence_ids: string[]
  observation_confidence: Confidence
}

export interface StructuralFact {
  path: string
  value: string | number | boolean | null
  evidence_id: string
  note: string | null
}

export interface Limitation {
  id: string
  code: string
  description: string
  subject_id: string | null
}

export interface Report {
  schema_version: '1.0.0' | '1.1.0'
  input_sha256: string
  engine_version: string
  parser_versions: Record<string, string>
  analysis_config: Record<string, string | number | boolean | null>
  artifact: {
    id: string
    sha256: string
    size: number
    format: string
    origin: string | null
  }
  evidence: Evidence[]
  observations: Observation[]
  inferences: Array<{ id: string; observation_ids: string[]; description: string }>
  disagreements: Array<{ id: string; evidence_ids: string[]; category: string; description: string }>
  limitations: Limitation[]
  warnings: Array<{ code: string; message: string }>
  errors: Array<{ code: string; message: string }>
  pe_facts?: StructuralFact[]
  comparison?: { parser_a: string; parser_b: string; equivalent_count: number; disagreement_count: number }
}
