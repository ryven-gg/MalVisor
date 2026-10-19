# Roadmap

Based on [Research Report 2](../Research_Report/research-report2.md); this is a plan, not a list of delivered features.

- **Phase 0 — foundation (done):** data contracts, provenance validation, schema, synthetic example, CLI skeleton, tests, documentation.
- **Phase 1A–1C (current):** bounded PE32/PE32+ extraction with `pefile`, verified evidence where raw locations are available, optional LIEF comparison, and deterministic synthetic regression fixtures. Broader format coverage, parser isolation, and empirical validation remain open.
- **Phase 2 — PE visualization and explanation:** local/offline PE layout and evidence views; partial CFG only after its coverage semantics are defined. Cytoscape and Capstone are potential dependencies, not Phase 0 requirements.
- **Phase 3 — learning mode and synthetic research kit:** evidence-backed lessons and controlled nonfunctional fixtures; evaluate learning claims empirically.
- **Phase 4 — integrations:** consider capa, ATT&CK Navigator, SARIF, STIX, and YARA only when semantic mappings can be tested.

No phase includes executing malware. Each later phase requires an explicit new task and its own review.

