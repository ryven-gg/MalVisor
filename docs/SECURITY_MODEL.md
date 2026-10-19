# Security model

MalVisor's core is strictly static. `analyze` reads file bytes and never executes the target through a subprocess, interpreter, loader, instrumentation, or sandbox. Normal operation has no network requirement, automatic sample download, dynamic analysis, hidden telemetry, or automatic upload.

Input is limited to regular files; symlinks and special files are rejected. The default input cap is 16 MiB and is configurable by CLI. Section count, import descriptors, imported symbols, data directories, field strings, observations, and issues are bounded. Headers, section ranges, and directory counts are checked before extraction. Import descriptors and thunks are iterated with caps. Output is created exclusively, never silently overwritten, and contains no local absolute path. A future viewer must insert untrusted strings as text, never executable HTML.

Static parsing still exposes Python, pefile, and optional native LIEF to hostile bytes. LIEF may parse internal collections before Python can apply every item cap. This is **not a sandbox**; malformed files could trigger library bugs, memory exhaustion, or a process crash. The current parser is suitable for controlled local analysis, not a public upload service. Process isolation and stricter time/memory budgets remain future hardening work. The controls reduce risk but do not promise absolute safety.

