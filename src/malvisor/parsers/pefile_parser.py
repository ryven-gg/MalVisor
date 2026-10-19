"""Bounded static PE extraction backed by pefile's header parser."""

from collections import Counter
import math
import struct

import pefile

from malvisor.parsers.errors import ParseError
from malvisor.parsers.limits import Limits
from malvisor.parsers.locations import MappingStatus, SectionRange, map_rva, raw_range
from malvisor.parsers.normalized import Fact, ParsedPE

_MACHINES = {0x14C: "x86", 0x8664: "x86-64"}
_DIRECTORIES = (
    "export", "import", "resource", "exception", "certificate", "base_relocation",
    "debug", "architecture", "global_ptr", "tls", "load_config", "bound_import",
    "iat", "delay_import", "clr_runtime", "reserved",
)


def _u16(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def _u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def _display(raw: bytes, limit: int) -> str:
    return "".join(chr(ch) if 32 <= ch < 127 else f"\\x{ch:02x}" for ch in raw[:limit])


def _entropy(raw: bytes) -> float:
    if not raw:
        return 0.0
    counts = Counter(raw)
    return round(-sum((n / len(raw)) * math.log2(n / len(raw)) for n in counts.values()), 6)


def parse_pe(data: bytes, limits: Limits = Limits()) -> ParsedPE:
    """Convert unexpected parser-library errors to controlled failures."""
    try:
        return _parse_pe(data, limits)
    except ParseError:
        raise
    except Exception as exc:
        raise ParseError("parser_failure", f"PE extraction failed: {type(exc).__name__}") from exc


def _parse_pe(data: bytes, limits: Limits) -> ParsedPE:
    """Parse bytes as PE. Never loads, invokes, or executes the target file."""
    if len(data) > limits.max_input_size:
        raise ParseError("input_too_large", f"input exceeds {limits.max_input_size} bytes")
    if len(data) < 64 or data[:2] != b"MZ":
        raise ParseError("invalid_dos_header", "missing or truncated MZ header")
    pe_offset = _u32(data, 0x3C)
    if not raw_range(pe_offset, 24, len(data)) or data[pe_offset:pe_offset + 4] != b"PE\0\0":
        raise ParseError("invalid_pe_signature", "PE signature missing or out of bounds")
    machine = _u16(data, pe_offset + 4)
    count = _u16(data, pe_offset + 6)
    optional_size = _u16(data, pe_offset + 20)
    if machine not in _MACHINES:
        raise ParseError("unsupported_machine", f"unsupported machine 0x{machine:04x}")
    if count < 1 or count > limits.max_sections:
        raise ParseError("section_limit", f"section count {count} outside 1..{limits.max_sections}")
    opt = pe_offset + 24
    if not raw_range(opt, optional_size, len(data)) or optional_size < 96:
        raise ParseError("truncated_optional_header", "optional header is truncated")
    magic = _u16(data, opt)
    if magic not in (0x10B, 0x20B) or (magic == 0x10B and machine != 0x14C) or (magic == 0x20B and machine != 0x8664):
        raise ParseError("unsupported_pe_type", "PE magic and machine are unsupported or inconsistent")
    if optional_size < (96 if magic == 0x10B else 112):
        raise ParseError("truncated_optional_header", "optional header is truncated")
    section_table = opt + optional_size
    if not raw_range(section_table, count * 40, len(data)):
        raise ParseError("truncated_sections", "section table extends beyond input")
    dir_count_offset = opt + (92 if magic == 0x10B else 108)
    dir_count = _u32(data, dir_count_offset)
    if dir_count > limits.max_data_directories:
        raise ParseError("directory_limit", f"directory count {dir_count} exceeds {limits.max_data_directories}")
    dir_start = opt + (96 if magic == 0x10B else 112)
    if dir_start + dir_count * 8 > section_table:
        raise ParseError("truncated_directories", "directory table exceeds optional header")

    try:
        pe = pefile.PE(data=data, fast_load=True)
    except pefile.PEFormatError as exc:
        raise ParseError("malformed_pe", f"pefile rejected input: {exc}") from exc
    except Exception as exc:
        raise ParseError("parser_failure", f"pefile failed: {type(exc).__name__}") from exc

    facts: list[Fact] = []
    limitations: list[str] = []

    def add(path: str, value: str | int | float | bool | None, offset: int | None,
            size: int | None, *, rva: int | None = None, note: str | None = None) -> None:
        if len(facts) >= limits.max_observations:
            raise ParseError("observation_limit", f"more than {limits.max_observations} facts")
        if isinstance(value, str) and len(value) > limits.max_field_size * 4:
            raise ParseError("field_limit", f"field {path} is too long")
        facts.append(Fact(path, value, offset, size, rva, note))

    add("dos.mz_signature", "MZ", 0, 2)
    add("dos.e_lfanew", pe_offset, 0x3C, 4)
    add("dos.valid", True, 0, 64)
    add("coff.pe_signature", "PE\\x00\\x00", pe_offset, 4)
    for path, value, rel, size in (
        ("machine", machine, 4, 2), ("number_of_sections", count, 6, 2),
        ("time_date_stamp_raw", int(pe.FILE_HEADER.TimeDateStamp), 8, 4),
        ("size_of_optional_header", optional_size, 20, 2),
        ("characteristics", int(pe.FILE_HEADER.Characteristics), 22, 2),
    ):
        add("coff." + path, value, pe_offset + rel, size,
            note="raw COFF timestamp; not trusted compilation time" if path == "time_date_stamp_raw" else None)
    add("coff.architecture", _MACHINES[machine], pe_offset + 4, 2)
    add("coff.file_kind", "DLL" if int(pe.FILE_HEADER.Characteristics) & 0x2000 else "EXE",
        pe_offset + 22, 2)
    pe_type = "PE32" if magic == 0x10B else "PE32+"
    add("optional.pe_type", pe_type, opt, 2)
    add("optional.magic", magic, opt, 2)
    image_base_rel = 28 if magic == 0x10B else 24
    image_base_size = 4 if magic == 0x10B else 8
    for path, rel, size in (
        ("image_base", image_base_rel, image_base_size),
        ("address_of_entry_point", 16, 4), ("section_alignment", 32, 4),
        ("file_alignment", 36, 4), ("size_of_image", 56, 4),
        ("size_of_headers", 60, 4), ("number_of_rva_and_sizes", 92 if magic == 0x10B else 108, 4),
    ):
        value = int(getattr(pe.OPTIONAL_HEADER, {
            "image_base": "ImageBase", "address_of_entry_point": "AddressOfEntryPoint",
            "section_alignment": "SectionAlignment", "file_alignment": "FileAlignment",
            "size_of_image": "SizeOfImage", "size_of_headers": "SizeOfHeaders",
            "number_of_rva_and_sizes": "NumberOfRvaAndSizes",
        }[path]))
        add("optional." + path, value, opt + rel, size)
    section_ranges: list[SectionRange] = []
    raw_ends = [min(len(data), int(pe.OPTIONAL_HEADER.SizeOfHeaders))]
    for index in range(count):
        section = pe.sections[index]
        start = section_table + index * 40
        raw_name = data[start:start + 8]
        raw_offset = int(section.PointerToRawData)
        raw_size = int(section.SizeOfRawData)
        virtual_address = int(section.VirtualAddress)
        virtual_size = int(section.Misc_VirtualSize)
        if raw_size and not raw_range(raw_offset, raw_size, len(data)):
            raise ParseError("invalid_section_bounds", f"section {index} raw data exceeds file")
        if raw_size:
            raw_ends.append(raw_offset + raw_size)
        section_ranges.append(SectionRange(virtual_address, virtual_size, raw_offset, raw_size))
        prefix = f"sections.{index}"
        add(prefix + ".name_raw_hex", raw_name.hex(), start, 8)
        add(prefix + ".name", _display(raw_name.split(b"\0", 1)[0], limits.max_field_size), start, 8)
        for name, value, rel in (
            ("virtual_size", virtual_size, 8), ("virtual_address", virtual_address, 12),
            ("size_of_raw_data", raw_size, 16), ("pointer_to_raw_data", raw_offset, 20),
            ("characteristics", int(section.Characteristics), 36),
        ):
            add(prefix + "." + name, value, start + rel, 4)
        add(prefix + ".raw_bounds_valid", True, start + 16, 8)
        if raw_size:
            add(prefix + ".raw_entropy", _entropy(data[raw_offset:raw_offset + raw_size]), raw_offset, raw_size,
                note="Shannon entropy of raw section bytes; not a packing verdict")
        else:
            add(prefix + ".raw_entropy", 0.0, start + 16, 4, note="no raw bytes")
    ranges = tuple(section_ranges)
    headers_size = int(pe.OPTIONAL_HEADER.SizeOfHeaders)
    certificate_end = 0
    for index in range(dir_count):
        entry_offset = dir_start + index * 8
        address = _u32(data, entry_offset)
        size = _u32(data, entry_offset + 4)
        prefix = f"directories.{index}"
        add(prefix + ".name", _DIRECTORIES[index] if index < len(_DIRECTORIES) else f"unknown_{index}", entry_offset, 8)
        add(prefix + (".file_offset" if index == 4 else ".rva"), address, entry_offset, 4,
            note="certificate table uses file offset" if index == 4 else None)
        add(prefix + ".size", size, entry_offset + 4, 4)
        if address == 0 and size == 0:
            status = "absent"
        elif index == 4:
            status = "raw" if raw_range(address, size, len(data)) and size > 0 else "invalid"
            if status == "raw":
                certificate_end = address + size
        elif size == 0:
            status = "invalid"
        else:
            status = map_rva(address, size, file_size=len(data), size_of_headers=headers_size,
                             sections=ranges).status.value
        add(prefix + ".consistency", status, entry_offset, 8)
        if status in ("invalid", "ambiguous", "virtual_only"):
            if len(limitations) >= limits.max_issues:
                raise ParseError("issue_limit", "too many limitations")
            limitations.append(f"directory {index} location is {status}")

    if dir_count > 1:
        import_rva = _u32(data, dir_start + 8)
        import_size = _u32(data, dir_start + 12)
        if import_rva and import_size:
            _read_imports(data, import_rva, import_size, magic, ranges, headers_size, limits, add)

    overlay_start = max(raw_ends)
    if certificate_end > overlay_start:
        overlay_start = certificate_end
    if overlay_start < len(data):
        add("overlay.offset", overlay_start, overlay_start, len(data) - overlay_start,
            note="candidate overlay; padding and certificate layout may affect interpretation")
        add("overlay.size", len(data) - overlay_start, overlay_start, len(data) - overlay_start,
            note="candidate overlay, not evidence of packing or malware")
        if len(limitations) >= limits.max_issues:
            raise ParseError("issue_limit", "too many limitations")
        limitations.append("overlay is a layout estimate; certificate/padding semantics need separate review")
    else:
        add("overlay.size", 0, None, None)
    return ParsedPE("pefile", pefile.__version__, pe_type, tuple(facts), tuple(limitations))


def _read_imports(data: bytes, directory_rva: int, directory_size: int, magic: int,
                  sections: tuple[SectionRange, ...], headers_size: int, limits: Limits,
                  add: object) -> None:
    def mapped(rva: int, size: int) -> int:
        result = map_rva(rva, size, file_size=len(data), size_of_headers=headers_size, sections=sections)
        if result.status is not MappingStatus.RAW or result.file_offset is None:
            raise ParseError("invalid_import_location", f"import RVA 0x{rva:x} is {result.status}")
        return result.file_offset

    def cstring(rva: int) -> tuple[str, int, int]:
        offset = mapped(rva, 1)
        end = data.find(b"\0", offset, min(len(data), offset + limits.max_field_size + 1))
        if end < 0:
            raise ParseError("field_limit", "import string missing terminator within limit")
        return _display(data[offset:end], limits.max_field_size), offset, end - offset + 1

    total_functions = 0
    entry_size = 4 if magic == 0x10B else 8
    ordinal_flag = 1 << (31 if magic == 0x10B else 63)
    if directory_size < 20:
        raise ParseError("invalid_import_location", "import directory is too short")
    for descriptor_index in range(min(limits.max_import_descriptors + 1, directory_size // 20)):
        descriptor_rva = directory_rva + descriptor_index * 20
        offset = mapped(descriptor_rva, 20)
        original_thunk, timestamp, forwarder, name_rva, first_thunk = struct.unpack_from("<IIIII", data, offset)
        if (original_thunk, timestamp, forwarder, name_rva, first_thunk) == (0, 0, 0, 0, 0):
            return
        if descriptor_index >= limits.max_import_descriptors:
            raise ParseError("import_descriptor_limit", "too many import descriptors")
        if not name_rva or not (original_thunk or first_thunk):
            raise ParseError("invalid_import_location", "import descriptor has no name or thunk")
        dll, name_offset, name_size = cstring(name_rva)
        prefix = f"imports.{descriptor_index}"
        add(prefix + ".dll", dll, name_offset, name_size, rva=name_rva)
        add(prefix + ".descriptor_rva", descriptor_rva, offset, 20)
        add(prefix + ".thunk_rva", original_thunk or first_thunk, offset + (0 if original_thunk else 16), 4)
        thunk_rva = original_thunk or first_thunk
        for function_index in range(limits.max_imported_functions - total_functions + 1):
            if total_functions >= limits.max_imported_functions:
                raise ParseError("import_function_limit", "too many imported functions")
            thunk_offset = mapped(thunk_rva + function_index * entry_size, entry_size)
            thunk = struct.unpack_from("<I" if entry_size == 4 else "<Q", data, thunk_offset)[0]
            if thunk == 0:
                break
            item_prefix = f"{prefix}.symbols.{function_index}"
            add(item_prefix + ".thunk_value", thunk, thunk_offset, entry_size,
                rva=thunk_rva + function_index * entry_size)
            if thunk & ordinal_flag:
                add(item_prefix + ".ordinal", thunk & 0xFFFF, thunk_offset, entry_size)
            else:
                name_rva = thunk & (ordinal_flag - 1)
                hint_offset = mapped(name_rva, 2)
                add(item_prefix + ".hint", _u16(data, hint_offset), hint_offset, 2, rva=name_rva)
                name, function_offset, function_size = cstring(name_rva + 2)
                add(item_prefix + ".name", name, function_offset, function_size, rva=name_rva + 2)
            total_functions += 1
        else:
            raise ParseError("import_function_limit", "unterminated import thunk table")
    raise ParseError("import_descriptor_limit", "unterminated import descriptor table within limit")
