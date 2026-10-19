"""Generate inert PE structures for tests. No executable code or entry point."""

import struct


def synthetic_pe(*, pe_plus: bool = False, import_kind: str | None = None,
                 dll: bool = False) -> bytes:
    if import_kind not in (None, "name", "ordinal"):
        raise ValueError(import_kind)
    data = bytearray(0x400)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    machine = 0x8664 if pe_plus else 0x14C
    optional_size = 240 if pe_plus else 224
    struct.pack_into("<HHIIIHH", data, 0x84, machine, 1, 0, 0, 0, optional_size,
                     0x0102 | (0x2000 if dll else 0))
    opt = 0x98
    struct.pack_into("<H", data, opt, 0x20B if pe_plus else 0x10B)
    struct.pack_into("<I", data, opt + 16, 0)  # inert entry point
    if pe_plus:
        struct.pack_into("<Q", data, opt + 24, 0x140000000)
    else:
        struct.pack_into("<I", data, opt + 28, 0x400000)
    struct.pack_into("<II", data, opt + 32, 0x1000, 0x200)
    struct.pack_into("<II", data, opt + 56, 0x2000, 0x200)
    directory_base = opt + (112 if pe_plus else 96)
    struct.pack_into("<I", data, opt + (108 if pe_plus else 92), 16)
    section = opt + optional_size
    data[section:section + 8] = b".rdata\0\0"
    struct.pack_into("<IIII", data, section + 8, 0x200, 0x1000, 0x200, 0x200)
    struct.pack_into("<I", data, section + 36, 0x40000040)  # read-only initialized data
    if import_kind:
        struct.pack_into("<II", data, directory_base + 8, 0x1040, 40)
        struct.pack_into("<IIIII", data, 0x240, 0x10A0, 0, 0, 0x1080, 0x10A0)
        data[0x280:0x28D] = b"EXAMPLE.dll\0\0"
        thunk = ((1 << (63 if pe_plus else 31)) | 5) if import_kind == "ordinal" else 0x10C0
        struct.pack_into("<Q" if pe_plus else "<I", data, 0x2A0, thunk)
        struct.pack_into("<H", data, 0x2C0, 0)
        data[0x2C2:0x2CE] = b"ExampleFunc\0"
    return bytes(data)
