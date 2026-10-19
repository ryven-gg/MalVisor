"""Optional LIEF reference adapter, used only on explicit request."""

from malvisor.parsers.errors import ParseError
from malvisor.parsers.limits import Limits
from malvisor.parsers.locations import MappingStatus, SectionRange, map_rva, raw_range
from malvisor.parsers.normalized import Fact, ParsedPE
from malvisor.parsers.pefile_parser import _DIRECTORIES, _entropy


def parse_lief(data: bytes, limits: Limits) -> ParsedPE:
    try:
        import lief
    except ImportError as exc:
        raise ParseError("reference_unavailable", "LIEF is not installed; install malvisor[compare] to opt in") from exc
    if len(data) > limits.max_input_size:
        raise ParseError("input_too_large", "input exceeds configured size limit")
    try:
        binary = lief.PE.parse(list(data))
    except Exception as exc:
        raise ParseError("reference_parser_failure", f"LIEF failed: {type(exc).__name__}") from exc
    if binary is None:
        raise ParseError("reference_parser_failure", "LIEF returned no PE object")
    try:
        facts: list[Fact] = []

        def add(path: str, value: str | int | float | bool | None) -> None:
            if len(facts) >= limits.max_observations:
                raise ParseError("observation_limit", "LIEF emitted too many facts")
            if isinstance(value, str) and len(value) > limits.max_field_size * 4:
                raise ParseError("field_limit", f"LIEF field {path} is too long")
            facts.append(Fact(path, value))

        h = binary.header
        o = binary.optional_header
        machine = int(h.machine)
        if machine not in (0x14C, 0x8664):
            raise ParseError("unsupported_machine", f"LIEF machine 0x{machine:x} unsupported")
        pe_type = "PE32" if int(o.magic) == 0x10B else "PE32+" if int(o.magic) == 0x20B else None
        if pe_type is None:
            raise ParseError("unsupported_pe_type", "LIEF PE magic unsupported")
        add("dos.mz_signature", "MZ")
        add("dos.e_lfanew", int(binary.dos_header.addressof_new_exeheader))
        add("coff.machine", machine)
        add("coff.architecture", "x86" if machine == 0x14C else "x86-64")
        add("coff.number_of_sections", int(h.numberof_sections))
        add("coff.time_date_stamp_raw", int(h.time_date_stamps))
        add("coff.size_of_optional_header", int(h.sizeof_optional_header))
        add("coff.characteristics", int(h.characteristics))
        add("coff.file_kind", "DLL" if int(h.characteristics) & 0x2000 else "EXE")
        add("optional.pe_type", pe_type)
        add("optional.magic", int(o.magic))
        for name, attr in (
            ("image_base", "imagebase"), ("address_of_entry_point", "addressof_entrypoint"),
            ("section_alignment", "section_alignment"), ("file_alignment", "file_alignment"),
            ("size_of_image", "sizeof_image"), ("size_of_headers", "sizeof_headers"),
            ("number_of_rva_and_sizes", "numberof_rva_and_size"),
        ):
            add("optional." + name, int(getattr(o, attr)))
        sections = binary.sections
        if len(sections) > limits.max_sections:
            raise ParseError("section_limit", "LIEF section count exceeds configured limit")
        ranges: list[SectionRange] = []
        for index, section in enumerate(sections):
            prefix = f"sections.{index}"
            raw_offset = int(section.pointerto_raw_data)
            raw_size = int(section.sizeof_raw_data)
            add(prefix + ".name", section.name)
            add(prefix + ".virtual_size", int(section.virtual_size))
            add(prefix + ".virtual_address", int(section.virtual_address))
            add(prefix + ".size_of_raw_data", raw_size)
            add(prefix + ".pointer_to_raw_data", raw_offset)
            add(prefix + ".characteristics", int(section.characteristics))
            bounds_valid = raw_range(raw_offset, raw_size, len(data))
            add(prefix + ".raw_bounds_valid", bounds_valid)
            if bounds_valid:
                add(prefix + ".raw_entropy", _entropy(data[raw_offset:raw_offset + raw_size]))
            ranges.append(SectionRange(int(section.virtual_address), int(section.virtual_size), raw_offset, raw_size))
        directories = binary.data_directories
        if len(directories) > limits.max_data_directories:
            raise ParseError("directory_limit", "LIEF directory count exceeds configured limit")
        for index, directory in enumerate(directories):
            prefix = f"directories.{index}"
            address = int(directory.rva)
            size = int(directory.size)
            add(prefix + ".name", _DIRECTORIES[index] if index < len(_DIRECTORIES) else f"unknown_{index}")
            add(prefix + (".file_offset" if index == 4 else ".rva"), address)
            add(prefix + ".size", size)
            if not address and not size:
                status = "absent"
            elif index == 4:
                status = "raw" if size > 0 and raw_range(address, size, len(data)) else "invalid"
            elif size == 0:
                status = "invalid"
            else:
                status = map_rva(address, size, file_size=len(data), size_of_headers=int(o.sizeof_headers),
                                 sections=tuple(ranges)).status.value
            add(prefix + ".consistency", status)
        descriptors = binary.imports
        if len(descriptors) > limits.max_import_descriptors:
            raise ParseError("import_descriptor_limit", "LIEF import descriptors exceed configured limit")
        total_symbols = 0
        for index, descriptor in enumerate(descriptors):
            prefix = f"imports.{index}"
            add(prefix + ".dll", descriptor.name)
            for symbol_index, entry in enumerate(descriptor.entries):
                total_symbols += 1
                if total_symbols > limits.max_imported_functions:
                    raise ParseError("import_function_limit", "LIEF import symbols exceed configured limit")
                if entry.is_ordinal:
                    add(f"{prefix}.symbols.{symbol_index}.ordinal", int(entry.ordinal))
                else:
                    add(f"{prefix}.symbols.{symbol_index}.name", entry.name)
        add("overlay.size", len(binary.overlay))
        return ParsedPE("lief", lief.__version__, pe_type, tuple(facts))
    except ParseError:
        raise
    except Exception as exc:
        raise ParseError("reference_parser_failure", f"LIEF field extraction failed: {type(exc).__name__}") from exc
