# Contributing

Use Python 3.11+, create a virtual environment, install `.[test]`, and run `python -m pytest`. Keep runtime dependencies minimal and record any new dependency and license.

All analysis must remain static and offline. Never execute, instrument, unpack, download, or upload a sample as part of this project. Tests should use synthetic nonfunctional data or benign artifacts with documented redistribution rights. Do not commit malware binaries, large datasets, private paths, or secrets.

For schema changes, update the Python models, JSON Schema, example report, tests, and `docs/DATA_CONTRACT.md` together. Reviewers should check provenance links, uncertainty wording, deterministic output, malformed-input behavior, and whether claims exceed the evidence. Research reports are source material and should not be edited casually.

