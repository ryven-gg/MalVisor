# Security model

MalVisor's intended core is strictly static. Phase 0 does not open the `analyze` argument. No analyzed file is executed through a subprocess, interpreter, loader, instrumentation, or sandbox. Normal operation has no network requirement, automatic sample download, dynamic analysis, hidden telemetry, or automatic upload.

Future parser work must treat every byte and metadata field as untrusted. Before parsing, enforce a documented maximum input size, explicit limits on sections/imports/strings/warnings, checked offsets and lengths, time/memory bounds where practical, and controlled failures for malformed input. Use safe path handling and avoid embedding absolute local paths in canonical reports. A future viewer must insert untrusted strings as text, never executable HTML.

Static parsing still exposes parser libraries to hostile inputs; malformed files can trigger bugs or resource exhaustion. These controls reduce risk but do not promise absolute safety. Phase 1 should test malformed synthetic fixtures and consider process isolation before accepting arbitrary external files.

