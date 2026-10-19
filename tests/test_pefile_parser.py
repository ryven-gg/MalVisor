"""Phase 1A synthetic, inert parser fixtures."""

import struct

import pytest

from fixtures.build_pe import synthetic_pe
from malvisor.parsers.errors import ParseError
from malvisor.parsers.limits import Limits
from malvisor.parsers.pefile_parser import parse_pe


def values(data: bytes) -> dict[str, object]:
    return {fact.path: fact.value for fact in parse_pe(data).facts}


@pytest.mark.parametrize("pe_plus,kind,expected", [
    (False, None, "PE32"), (True, None, "PE32+"),
    (False, "name", "PE32"), (True, "ordinal", "PE32+"),
])
def test_supported_formats_and_imports(pe_plus, kind, expected):
    data = synthetic_pe(pe_plus=pe_plus, import_kind=kind)
    before = bytes(data)
    parsed = parse_pe(data)
    facts = {fact.path: fact.value for fact in parsed.facts}
    assert parsed.pe_type == expected
    assert facts["coff.architecture"] == ("x86-64" if pe_plus else "x86")
    assert facts["dos.mz_signature"] == "MZ"
    assert facts["sections.0.raw_bounds_valid"] is True
    assert ("imports.0.dll" in facts) == (kind is not None)
    if kind == "name":
        assert facts["imports.0.symbols.0.name"] == "ExampleFunc"
    if kind == "ordinal":
        assert facts["imports.0.symbols.0.ordinal"] == 5
    assert data == before


def test_dll_classification_comes_from_coff_flag():
    data = synthetic_pe(dll=True)
    assert values(data)["coff.file_kind"] == "DLL"
    assert values(synthetic_pe())["coff.file_kind"] == "EXE"


@pytest.mark.parametrize("data,code", [
    (b"", "invalid_dos_header"),
    (b"not a PE" * 12, "invalid_dos_header"),
    (b"NZ" + b"\0" * 100, "invalid_dos_header"),
    (b"MZ" + b"\0" * 10, "invalid_dos_header"),
])
def test_bad_input_is_controlled(data, code):
    with pytest.raises(ParseError) as exc:
        parse_pe(data)
    assert exc.value.code == code


def test_invalid_pe_signature():
    data = bytearray(synthetic_pe())
    data[0x80:0x84] = b"NOPE"
    with pytest.raises(ParseError, match="signature"):
        parse_pe(bytes(data))


def test_truncated_optional_header_and_sections():
    data = synthetic_pe()
    with pytest.raises(ParseError):
        parse_pe(data[:0x100])


def test_invalid_section_bounds():
    data = bytearray(synthetic_pe())
    section = 0x98 + 224
    struct.pack_into("<I", data, section + 20, 0xF000)
    with pytest.raises(ParseError) as exc:
        parse_pe(bytes(data))
    assert exc.value.code == "invalid_section_bounds"


def test_invalid_import_directory_location():
    data = bytearray(synthetic_pe(import_kind="name"))
    struct.pack_into("<I", data, 0x98 + 96 + 8, 0x9000)
    with pytest.raises(ParseError) as exc:
        parse_pe(bytes(data))
    assert exc.value.code == "invalid_import_location"


def test_size_section_and_directory_limits():
    data = synthetic_pe()
    with pytest.raises(ParseError) as exc:
        parse_pe(data, Limits(max_input_size=128))
    assert exc.value.code == "input_too_large"
    two_sections = bytearray(data)
    struct.pack_into("<H", two_sections, 0x86, 2)
    with pytest.raises(ParseError) as exc:
        parse_pe(bytes(two_sections), Limits(max_sections=1))
    assert exc.value.code == "section_limit"
    with pytest.raises(ParseError) as exc:
        parse_pe(data, Limits(max_data_directories=4))
    assert exc.value.code == "directory_limit"


def test_observation_and_field_limits():
    with pytest.raises(ParseError, match="facts"):
        parse_pe(synthetic_pe(), Limits(max_observations=4))
    with pytest.raises(ParseError) as exc:
        parse_pe(synthetic_pe(import_kind="name"), Limits(max_field_size=4))
    assert exc.value.code == "field_limit"


def test_import_descriptor_limit_allows_exactly_one():
    data = synthetic_pe(import_kind="name")
    assert values(data)["imports.0.dll"] == "EXAMPLE.dll"
    assert parse_pe(data, Limits(max_import_descriptors=1)).pe_type == "PE32"


def test_import_descriptor_and_symbol_caps():
    data = bytearray(synthetic_pe(import_kind="ordinal"))
    struct.pack_into("<IIIII", data, 0x254, 0x10A0, 0, 0, 0x1080, 0x10A0)
    with pytest.raises(ParseError) as exc:
        parse_pe(bytes(data), Limits(max_import_descriptors=1))
    assert exc.value.code == "import_descriptor_limit"
    data = bytearray(synthetic_pe(import_kind="ordinal"))
    struct.pack_into("<I", data, 0x2A4, (1 << 31) | 7)
    with pytest.raises(ParseError) as exc:
        parse_pe(bytes(data), Limits(max_imported_functions=1))
    assert exc.value.code == "import_function_limit"


def test_certificate_directory_uses_file_offset_and_overlay_is_structural():
    data = bytearray(synthetic_pe())
    directory_base = 0x98 + 96
    struct.pack_into("<II", data, directory_base + 4 * 8, 0x420, 16)
    data.extend(b"\0" * 0x20)
    data.extend(b"CERTIFICATEBYTES")
    parsed = parse_pe(bytes(data))
    facts = {fact.path: fact.value for fact in parsed.facts}
    assert facts["directories.4.file_offset"] == 0x420
    assert facts["directories.4.consistency"] == "raw"
    assert facts["overlay.size"] >= 0


def test_parser_exception_converted(monkeypatch):
    def broken(*args, **kwargs):
        raise RuntimeError("synthetic parser failure")

    monkeypatch.setattr("malvisor.parsers.pefile_parser.pefile.PE", broken)
    with pytest.raises(ParseError) as exc:
        parse_pe(synthetic_pe())
    assert exc.value.code == "parser_failure"


def test_deterministic_parsing():
    data = synthetic_pe(import_kind="ordinal")
    assert parse_pe(data) == parse_pe(data)
