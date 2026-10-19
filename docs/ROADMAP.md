# Roadmap

Based on [Research Report 2](../Research_Report/research-report2.md); this is a plan, not a list of delivered features.

- **Phase 0 — foundation (done):** data contracts, provenance validation, schema, synthetic example, CLI skeleton, tests, documentation.
- **Phase 1A–1C (done):** bounded PE32/PE32+ extraction with `pefile`, verified evidence where raw locations are available, optional LIEF comparison, and deterministic synthetic regression fixtures. Broader format coverage, parser isolation, and empirical validation remain open.
- **Phase 2A (done):** local/offline JSON report viewer with raw-offset PE layout, structure/evidence inspectors, input validation, and keyboard access.
- **Later Phase 2 work (not started):** graph features only after their coverage semantics are defined. Cytoscape and Capstone are possible future dependencies, not Phase 2A requirements.
- **Phase 3 — learning mode and synthetic research kit:** evidence-backed lessons and controlled nonfunctional fixtures; evaluate learning claims empirically.
- **Phase 4 — integrations:** consider capa, ATT&CK Navigator, SARIF, STIX, and YARA only when semantic mappings can be tested.

No phase includes executing malware. Each later phase requires an explicit new task and its own review.

