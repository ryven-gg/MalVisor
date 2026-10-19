# Architecture

Current implementation has five boundaries:

1. `cli` reads authorized regular files with size and file-type checks; it writes a new output only after successful analysis.
2. `parsers.pefile_parser` extracts bounded PE fields from bytes. `parsers.locations` maps RVA/VA conservatively, including virtual-only and ambiguous results. `parsers.limits` is the resource budget.
3. `parsers.report_builder` binds facts to byte ranges, evidence, and observations.
4. `core.models`, `core.evidence`, and `reporting.json_report` validate and serialize the report.
5. `parsers.lief_parser` and `differential.compare` optionally normalize and compare a second interpretation.

The flow is authorized input → bounded static parser → verified locations and structural facts → validated canonical JSON. Comparison adds an explicitly requested LIEF pass and normalized field comparison. `parser_versions` lists only parsers that ran. `pefile` is required; LIEF is optional; Capstone and UI dependencies are absent.

The Phase 0 `ParserAdapter` placeholder now describes the common `bytes + Limits → ParsedPE` function shape; both parser functions use it. No inference engine exists, so `inferences` is empty for actual PE reports. A parser failure is a controlled error and does not produce a fabricated report. The latest architectural priorities come from `Research_Report/research-report2.md`.

