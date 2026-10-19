"""Mock parser comparison and optional real LIEF integration."""

from dataclasses import replace
import json
from pathlib import Path
import re

from jsonschema import Draft202012Validator
import pytest

from fixtures.build_pe import synthetic_pe
from malvisor.core.evidence import validate_payload_references
from malvisor.core.uncertainty import DisagreementCategory
from malvisor.differential.compare import attach_comparison, compare, normalize
from malvisor.parsers.errors import ParseError
from malvisor.parsers.lief_parser import parse_lief
from malvisor.parsers.limits import Limits
from malvisor.parsers.normalized import Fact, ParsedPE
from malvisor.parsers.pefile_parser import parse_pe
from malvisor.parsers.report_builder import build_report


def mock(data: bytes) -> tuple[ParsedPE, ParsedPE]:
    primary = parse_pe(data)
    return primary, replace(primary, parser_name="mock-reference", parser_version="mock-1")


@pytest.mark.parametrize("pe_plus", [False, True])
def test_equivalent_synthetic_pe(pe_plus):
    primary, reference = mock(synthetic_pe(pe_plus=pe_plus))
    result = compare(primary, reference)
    assert result.disagreements == ()
    assert result.equivalent_count > 0


def test_normalized_section_name_and_order_do_not_diverge():
    primary, reference = mock(synthetic_pe(import_kind="name"))
    facts = tuple(replace(fact, value=".rdata\\x00") if fact.path == "sections.0.name" else fact
                  for fact in reversed(reference.facts))
    result = compare(primary, replace(reference, facts=facts))
    assert result.disagreements == ()


def test_section_collection_order_does_not_create_false_divergence():
    primary, reference = mock(synthetic_pe())
    section_facts = tuple(f for f in primary.facts if f.path.startswith("sections.0."))
    second = tuple(
        replace(f, path=f.path.replace("sections.0.", "sections.1."),
                value=(0x2000 if f.path.endswith(".virtual_address") else
                       0x400 if f.path.endswith(".pointer_to_raw_data") else
                       ".second" if f.path.endswith(".name") else f.value))
        for f in section_facts
    )
    primary = replace(primary, facts=primary.facts + second)
    swapped = tuple(
        replace(f, path=re.sub(r"sections\.([01])\.",
                               lambda m: f"sections.{1-int(m.group(1))}.", f.path))
        if f.path.startswith("sections.") else f
        for f in primary.facts
    )
    reference = replace(reference, facts=swapped)
    assert compare(primary, reference).disagreements == ()


def test_import_ordinal_and_missing_optional_field():
    primary, reference = mock(synthetic_pe(import_kind="ordinal"))
    assert not compare(primary, reference).disagreements
    removed = tuple(fact for fact in reference.facts if fact.path != "optional.file_alignment")
    result = compare(primary, replace(reference, facts=removed))
    assert len(result.disagreements) == 1
    assert result.disagreements[0].category is DisagreementCategory.UNSUPPORTED


def test_changed_ordinal_and_section_pointer_are_semantic_differences():
    primary, reference = mock(synthetic_pe(import_kind="ordinal"))
    changed = tuple(
        replace(fact, value=7) if fact.path == "imports.0.symbols.0.ordinal"
        else replace(fact, value=0x300) if fact.path == "sections.0.pointer_to_raw_data"
        else fact for fact in reference.facts
    )
    result = compare(primary, replace(reference, facts=changed))
    assert len(result.disagreements) == 2
    assert all(item.category is DisagreementCategory.SEMANTIC_DIFFERENCE
               for item in result.disagreements)


def test_explicit_malformed_field_is_not_called_parser_defect():
    primary, reference = mock(synthetic_pe())
    altered = tuple(replace(fact, value=0xDEAD) if fact.path == "optional.size_of_image" else fact
                    for fact in reference.facts)
    result = compare(primary, replace(reference, facts=altered,
                                        malformed_fields=("optional.size_of_image",)))
    assert len(result.disagreements) == 1
    assert result.disagreements[0].category is DisagreementCategory.MALFORMED_INPUT


def test_two_parsers_missing_same_malformed_field_are_not_equivalent():
    primary, reference = mock(synthetic_pe())
    key = "optional.size_of_image"
    primary = replace(primary, facts=tuple(f for f in primary.facts if f.path != key),
                      malformed_fields=(key,))
    reference = replace(reference, facts=tuple(f for f in reference.facts if f.path != key),
                        malformed_fields=(key,))
    result = compare(primary, reference)
    assert len(result.disagreements) == 1
    assert result.disagreements[0].category is DisagreementCategory.MALFORMED_INPUT


def test_semantic_difference_has_evidence_and_valid_report():
    data = synthetic_pe()
    primary, reference = mock(data)
    altered = tuple(replace(fact, value=999) if fact.path == "optional.size_of_image" else fact
                    for fact in reference.facts)
    reference = replace(reference, facts=altered)
    report = build_report(data, primary, Limits())
    result = compare(primary, reference, report.evidence)
    assert len(result.disagreements) == 1
    assert result.disagreements[0].category is DisagreementCategory.SEMANTIC_DIFFERENCE
    assert result.disagreements[0].evidence_ids
    combined = attach_comparison(report, reference, result)
    schema = json.loads((Path(__file__).resolve().parents[1] / "schemas/report-v1.schema.json").read_text())
    Draft202012Validator(schema).validate(combined.to_dict())
    validate_payload_references(combined.to_dict())
    assert combined.to_json() == attach_comparison(report, reference, result).to_json()


def test_missing_optional_dependency(monkeypatch):
    import sys

    monkeypatch.setitem(sys.modules, "lief", None)
    with pytest.raises(ParseError) as exc:
        parse_lief(synthetic_pe(), Limits())
    assert exc.value.code == "reference_unavailable"


def test_reference_parser_exception(monkeypatch):
    import sys
    from types import SimpleNamespace

    monkeypatch.setitem(sys.modules, "lief", SimpleNamespace(PE=SimpleNamespace(parse=lambda data: (_ for _ in ()).throw(RuntimeError()))))
    with pytest.raises(ParseError) as exc:
        parse_lief(synthetic_pe(), Limits())
    assert exc.value.code == "reference_parser_failure"


@pytest.mark.parametrize("pe_plus,kind", [(False, "name"), (True, "ordinal")])
def test_real_lief_comparison_if_installed(pe_plus, kind):
    pytest.importorskip("lief")
    data = synthetic_pe(pe_plus=pe_plus, import_kind=kind)
    primary = parse_pe(data)
    reference = parse_lief(data, Limits())
    result = compare(primary, reference)
    assert result.equivalent_count > 0
    assert not result.disagreements
    assert data == synthetic_pe(pe_plus=pe_plus, import_kind=kind)
