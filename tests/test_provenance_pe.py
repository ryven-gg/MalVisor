"""Phase 1B location and provenance checks."""

import json
from dataclasses import replace
from pathlib import Path

from jsonschema import Draft202012Validator
import pytest

from fixtures.build_pe import synthetic_pe
from malvisor.core.evidence import validate_payload_references
from malvisor.core.exceptions import ContractError
from malvisor.core.models import Location
from malvisor.core.uncertainty import VerificationStatus
from malvisor.parsers.limits import Limits
from malvisor.parsers.errors import ParseError
from malvisor.parsers.locations import MappingStatus, SectionRange, bounded_excerpt, map_rva, map_va
from malvisor.parsers.pefile_parser import parse_pe
from malvisor.parsers.report_builder import build_report


def report_for(data: bytes):
    return build_report(data, parse_pe(data), Limits())


@pytest.mark.parametrize("path,expected_offset", [
    ("dos.mz_signature", 0), ("coff.machine", 0x84),
    ("sections.0.name", 0x98 + 224), ("imports.0.symbols.0.name", 0x2C2),
])
def test_verified_fields_point_to_input(path, expected_offset):
    data = synthetic_pe(import_kind="name")
    report = report_for(data)
    fact = next(item for item in report.pe_facts if item.path == path)
    evidence = next(item for item in report.evidence if item.id == fact.evidence_id)
    assert evidence.verification_status is VerificationStatus.VERIFIED
    assert evidence.location.file_offset == expected_offset
    assert evidence.excerpt_hex == bounded_excerpt(data, *(
        evidence.location.file_offset,
        evidence.location.byte_range[1] - evidence.location.byte_range[0],
    ))
    observation = next(item for item in report.observations if evidence.id in item.evidence_ids)
    assert observation.id
    assert evidence.artifact_id == report.artifact.id


def test_header_virtual_and_invalid_rva_mapping():
    section = SectionRange(0x1000, 0x300, 0x200, 0x100)
    args = dict(file_size=0x400, size_of_headers=0x200, sections=(section,))
    assert map_rva(0x40, 4, **args).file_offset == 0x40
    assert map_rva(0x1080, 4, **args).file_offset == 0x280
    assert map_rva(0x1200, 4, **args).status is MappingStatus.VIRTUAL_ONLY
    assert map_rva(0x9000, 4, **args).status is MappingStatus.INVALID
    assert map_va(0x400000 + 0x1080, 0x400000, size=4, **args).file_offset == 0x280
    assert map_va(0x3FFFFF, 0x400000, size=4, **args).status is MappingStatus.INVALID


def test_overlapping_section_mapping_is_ambiguous():
    sections = (SectionRange(0x1000, 0x200, 0x200, 0x200),
                SectionRange(0x1080, 0x200, 0x400, 0x200))
    result = map_rva(0x1100, 4, file_size=0x800, size_of_headers=0x200, sections=sections)
    assert result.status is MappingStatus.AMBIGUOUS
    assert result.file_offset is None


def test_invalid_verified_range_and_dangling_reference_rejected():
    report = report_for(synthetic_pe())
    item = next(ev for ev in report.evidence if ev.verification_status is VerificationStatus.VERIFIED)
    bad = replace(item, location=Location(file_offset=report.artifact.size - 1,
                                           byte_range=(report.artifact.size - 1, report.artifact.size + 1)))
    with pytest.raises(ContractError, match="exceeds artifact"):
        replace(report, evidence=tuple(bad if ev.id == item.id else ev for ev in report.evidence))
    payload = report.to_dict()
    payload["pe_facts"][0]["evidence_id"] = "missing"
    with pytest.raises(ContractError, match="dangling evidence"):
        validate_payload_references(payload)


def test_report_is_deterministic_and_schema_valid():
    data = synthetic_pe(import_kind="ordinal")
    a = report_for(data)
    b = report_for(bytes(data))
    assert a.to_json() == b.to_json()
    schema = json.loads((Path(__file__).resolve().parents[1] / "schemas/report-v1.schema.json").read_text())
    Draft202012Validator(schema).validate(a.to_dict())
    validate_payload_references(a.to_dict())
    assert all(item.location.byte_range[1] <= len(data) for item in a.evidence
               if item.verification_status is VerificationStatus.VERIFIED)


def test_raw_field_value_mismatch_is_rejected():
    data = synthetic_pe()
    parsed = parse_pe(data)
    altered = tuple(replace(fact, value=999) if fact.path == "coff.machine" else fact
                    for fact in parsed.facts)
    with pytest.raises(ParseError, match="coff.machine"):
        build_report(data, replace(parsed, facts=altered), Limits())
