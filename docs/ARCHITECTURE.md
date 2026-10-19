# Architecture

Phase 0 contains four boundaries:

1. `cli` exposes version/help and an unsupported `analyze` command.
2. `parsers.base` defines a future adapter signature, without a parser implementation.
3. `core.models`, `core.evidence`, and `core.reproducibility` define entities, provenance checks, and canonical JSON rules.
4. `reporting.json_report` assembles and serializes a validated report.

The future flow is authorized input → bounded static parser → normalized observations/evidence → inference/differential analysis → validated report → offline viewer. Only the report contract exists today. A parser adapter must report its actual name/version if and only if used; an empty `parser_versions` object means none ran. The package does not import `pefile`, LIEF, or Capstone.

The research documents mention more advanced parsing and UI features. Those are plans, not current capabilities. The latest architectural priorities come from `Research_Report/research-report2.md`.

