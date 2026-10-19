# Data contract

Schema version `1.0.0` uses JSON Schema Draft 2020-12. `schemas/report-v1.schema.json` checks required fields, primitive types, and enums. Python constructors, `validate_references`, and `validate_payload_references` check relationships and invariants that JSON Schema cannot express conveniently. Consumers of external JSON must run **both** schema and payload semantic checks before trusting a report; Phase 0 does not yet provide a JSON ingestion API.

`Artifact` has a stable ID, SHA-256, byte count, format label, and optional safe origin label. Do not place an absolute user path in `origin`. `Evidence` points to an artifact, records source and extraction method, and may have an offset, RVA, VA, header field, byte range, or instruction range. Ranges are half-open `[start, end)` and must have `end > start`. `verified` requires a recorded location; `unresolved` cannot claim one; `pending` permits a proposed location that still needs verification. A recorded location alone is **not** proof that its bytes or mapping were independently verified. The future parser owns that check.

`Observation` states an extracted fact and references one or more evidence IDs. It must not claim runtime behavior from a static import. `Inference` states a possible interpretation, references observations, and separately records strength, alternative explanations, and limitations. `Disagreement` records parser divergence as `equivalent`, `semantic_difference`, `unsupported`, `malformed_input`, or `suspected_parser_defect`; divergence is not automatically a defect. `Limitation` and `Issue` are structured for CLI and future UI use.

Qualitative levels are `high`, `medium`, `low`, `unknown`. `observation_confidence` concerns extraction reliability; `inference_strength` concerns how strongly observations support an interpretation. Neither is a probability of malware or proof of runtime activity.

Entity IDs use letters followed by up to 127 ASCII letters, digits, `.`, `_`, `:`, or `-`. IDs are unique across the report. An inference must resolve to observations, each observation to evidence, and each evidence to the report artifact. A limitation subject may point to any entity. Schema shape alone does not enforce these links; Python semantic validation does.

Canonical serialization sorts object keys and entity arrays by ID; warnings/errors by code then message. It uses UTF-8 compatible JSON text, compact separators, a trailing newline, and rejects NaN/Infinity. It contains no timestamp, host name, or absolute path. `parser_versions` records only parsers actually run. Future environment diagnostics must live outside the canonical analysis payload. The example report is entirely synthetic and makes no claim about a real PE.

