"""Bounded local file IO. Target bytes are never executed."""

import os
from pathlib import Path
import stat

from malvisor.parsers.errors import ParseError


def read_input(path: Path, maximum: int) -> bytes:
    try:
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or path.is_symlink():
            raise ParseError("invalid_input_type", "input must be a regular file, not a symlink or device")
        if before.st_size > maximum:
            raise ParseError("input_too_large", f"input exceeds {maximum} bytes")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags)
        with os.fdopen(fd, "rb") as stream:
            opened = os.fstat(stream.fileno())
            if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                raise ParseError("input_changed", "input changed during opening")
            if opened.st_size > maximum:
                raise ParseError("input_too_large", f"input exceeds {maximum} bytes")
            data = stream.read(maximum + 1)
        if len(data) > maximum:
            raise ParseError("input_too_large", f"input exceeds {maximum} bytes")
        return data
    except ParseError:
        raise
    except OSError as exc:
        raise ParseError("input_io", f"cannot read input: {exc.strerror or type(exc).__name__}") from exc


def write_new_output(path: Path, content: str) -> None:
    created = False
    try:
        with path.open("x", encoding="utf-8", newline="\n") as stream:
            created = True
            stream.write(content)
    except FileExistsError as exc:
        raise ParseError("output_exists", "output exists; choose a new path") from exc
    except OSError as exc:
        if created:
            path.unlink(missing_ok=True)
        raise ParseError("output_io", f"cannot write output: {exc.strerror or type(exc).__name__}") from exc
