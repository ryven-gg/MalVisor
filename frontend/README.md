# MalVisor PE Structure Explorer (Phase 2A)

React, TypeScript, Vite, CSS, and SVG viewer for **local JSON reports**. It does not read or execute PE bytes. The CLI remains the only analyzer.

## Run

```powershell
cd C:\MalVisor\frontend
npm ci
npm run dev
```

Open the localhost URL printed by Vite. Its development server serves UI assets only. To use the production build locally:

```powershell
npm run build
npm run preview
```

Open the localhost URL printed by preview. All runtime assets are bundled locally; neither workflow needs a cloud service or CDN. The build is not claimed to work through `file://`.

From the project root, create a report first:

```powershell
.venv\Scripts\python -m malvisor analyze authorized.pe --output report.json
```

In the browser choose **Open local JSON** or one of the bundled synthetic examples. The Phase 1 example was generated from `tests/fixtures/build_pe.py` using `parse_pe` and `build_report`; it contains JSON facts and evidence only, not the PE bytes. The Phase 0 example has no PE facts and shows the explicit no-data state.

## Reading the map

The vertical axis spans raw file offsets from `0` to the artifact's reported byte size. A colored shape represents a half-open `[start, end)` raw span. Empty background is a file gap; separate tracks preserve overlap. Very short spans receive a minimum visual marker while the inspector retains their exact size. The list below the map includes zero-length and unmapped items. Select a shape with click, Enter, or Space, or choose a list row with the keyboard. Zoom controls enlarge the map without changing coordinates.

**Raw offset** is a position in the input file. **RVA** is relative to the image base after loading. **VA** is a process virtual address. They are distinct address spaces. Ordinary data-directory entries export an RVA and are listed without a raw shape; the certificate directory is the PE exception whose address is a raw file offset. The viewer does not infer an RVA-to-raw mapping that the report did not export.

The structure inspector shows actual `pe_facts` and the reported candidate overlay caveat. The evidence inspector follows `artifact.id → evidence.id → observation.id`, showing parser, method, verification status, locations, and bounded hex text. “Verified” is the backend's provenance claim; the browser checks JSON shape and links, not the original binary. A static import, entropy value, or overlay is not a malware verdict.

## Input and limits

Schema `1.0.0` and `1.1.0` are validated using a standalone validator generated from the repository's `schemas/report-v1.schema.json` before development, tests, and builds. This avoids browser runtime code generation and schema drift. Extra browser checks cover references, ranges, and size. A local report is capped at 8 MiB, 48 nesting levels, 80,000 nodes, 2,500 entries per array, and 4,096 characters per string. Invalid input gives a visible error. Data is rendered as text and kept only in page memory; no analytics, storage, report upload, or automatic backend execution exists.

Tests: `npm run typecheck`, `npm test`, `npm run build`. The browser validation is a defensive display boundary, not a replacement for backend provenance verification or a sandbox. More limits are in [security model](../docs/SECURITY_MODEL.md).
