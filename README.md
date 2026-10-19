# MalVisor

MalVisor is an offline, static, evidence-first environment for learning how Windows Portable Executable (PE) structures support, or fail to support, an interpretation. It aims to show **what was observed, where the evidence lives, why an inference was made, and what remains unknown**. It is not a replacement for Ghidra, radare2, or capa.

## Current status: Phase 2A

MalVisor now parses PE32/x86 and PE32+/x86-64 EXE or DLL structure from local bytes using `pefile`. It records typed structural facts, bounded byte evidence, and observations in a deterministic JSON report. Optional LIEF comparison is explicit opt-in. The software does **not** disassemble code, execute samples, classify malware, or infer runtime behavior from imports.

The Phase 2A browser viewer opens these JSON reports locally. It shows a raw-offset PE layout, selected structure fields, and the artifact → evidence → observation trail. [Frontend instructions](frontend/README.md) cover setup, import, offline use, address spaces, and limitations. The CLI never starts from the browser.

The architecture follows [Research Report 2](Research_Report/research-report2.md). [Research Report 1](Research_Report/research-report1.md) provides earlier safety and terminology context. Both are research/planning documents, not evidence that novelty claims were validated.

## Setup and commands

Python 3.11 or later:

```powershell
python -m venv .venv
.venv\Scripts\python -m pip install -e '.[test]'
.venv\Scripts\python -m pytest
.venv\Scripts\python -m malvisor --help
.venv\Scripts\python -m malvisor version
.venv\Scripts\python -m malvisor analyze authorized.pe --output report.json
.venv\Scripts\python -m pip install -e '.[compare]'
.venv\Scripts\python -m malvisor analyze authorized.pe --compare-parsers --output comparison.json
```

`pefile` is the only required runtime dependency. `pytest` and `jsonschema` are test extras; LIEF is optional and is never loaded in default analysis. No normal analysis command uses the network. Input must be a regular file, not a symlink or device. Output is created only after analysis succeeds and is never overwritten. Without `--output`, the report goes to standard output. `--max-input-size` overrides the default 16 MiB cap; other budgets are defined in `Limits`.

CLI exit codes: `0` success, `2` invalid/unsupported PE or primary parser failure, `3` resource limit, `4` reference parser unavailable/failure, `5` input/output path error. Errors go to standard error as `ERROR <code>: <message>`. The input is never executed or changed.

The synthetic fixtures in `tests/fixtures/build_pe.py` are inert structures with entry point zero and no executable section. They are contract tests, not a representative corpus of real-world PEs. Imports mean **statically declared imports**, not observed calls. Section entropy measures raw byte distribution; it cannot prove packing. Parser differences require review and are not automatically parser bugs.

## Design principles

- Static only, offline first, no sample download or hidden telemetry.
- Separate extracted observations from interpretations; no malware probability or verdict from a single static indicator.
- Trace inferences to observations, evidence, and one artifact.
- Represent unknown locations and parser disagreement explicitly.
- Record versions/configuration and produce deterministic JSON.

See [architecture](docs/ARCHITECTURE.md), [data contract](docs/DATA_CONTRACT.md), [security model](docs/SECURITY_MODEL.md), and [roadmap](docs/ROADMAP.md) for scope and remaining limitations.
