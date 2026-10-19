"""Turn parser-neutral facts into verified report evidence and observations."""

import hashlib
import re

from malvisor.core.models import Artifact, Evidence, Limitation, Location, Observation, StructuralFact
from malvisor.core.uncertainty import Level, VerificationStatus
from malvisor.parsers.limits import Limits
from malvisor.parsers.errors import ParseError
from malvisor.parsers.locations import bounded_excerpt, raw_range
from malvisor.parsers.normalized import ParsedPE
from malvisor.reporting.json_report import Report


def _stable_id(prefix: str, value: str) -> str:
    return prefix + "-" + hashlib.sha256(value.encode("utf-8")).hexdigest()[:20]


_DIRECT_INTEGER = re.compile(
    r"(?:dos\.e_lfanew|coff\.(?:machine|number_of_sections|time_date_stamp_raw|"
    r"size_of_optional_header|characteristics)|optional\.(?:magic|image_base|"
    r"address_of_entry_point|section_alignment|file_alignment|size_of_image|"
    r"size_of_headers|number_of_rva_and_sizes)|sections\.\d+\.(?:virtual_size|"
    r"virtual_address|size_of_raw_data|pointer_to_raw_data|characteristics)|"
    r"directories\.\d+\.(?:rva|file_offset|size)|"
    r"imports\.\d+\.symbols\.\d+\.(?:hint|thunk_value))"
)


def _check_raw_value(data: bytes, path: str, value: object, offset: int | None,
                     size: int | None) -> None:
    if _DIRECT_INTEGER.fullmatch(path):
        if (offset is None or size not in (2, 4, 8) or type(value) is not int or
                not raw_range(offset, size, len(data)) or
                int.from_bytes(data[offset:offset + size], "little") != value):
            raise ParseError("evidence_mismatch", f"raw bytes do not match {path}")


def build_report(data: bytes, parsed: ParsedPE, limits: Limits) -> Report:
    artifact = Artifact("artifact-1", hashlib.sha256(data).hexdigest(), len(data), parsed.pe_type)
    evidence: list[Evidence] = []
    observations: list[Observation] = []
    structural: list[StructuralFact] = []
    for fact in sorted(parsed.facts, key=lambda item: item.path):
        _check_raw_value(data, fact.path, fact.value, fact.offset, fact.size)
        evidence_id = _stable_id("evidence", fact.path)
        if fact.offset is not None and fact.size is not None and fact.size > 0 and raw_range(fact.offset, fact.size, len(data)):
            location = Location(file_offset=fact.offset, rva=fact.rva,
                                header_field=fact.path, byte_range=(fact.offset, fact.offset + fact.size))
            status = VerificationStatus.VERIFIED
            excerpt = bounded_excerpt(data, fact.offset, fact.size)
        else:
            location = Location()
            status = VerificationStatus.UNRESOLVED
            excerpt = None
        evidence.append(Evidence(evidence_id, artifact.id, parsed.parser_name,
                                 "bounded static field extraction", status, location, excerpt))
        observations.append(Observation(_stable_id("observation", fact.path),
                                        f"{fact.path} = {fact.value}", (evidence_id,),
                                        Level.HIGH if status is VerificationStatus.VERIFIED else Level.UNKNOWN))
        structural.append(StructuralFact(fact.path, fact.value, evidence_id, fact.note))
    limitations = tuple(
        Limitation(_stable_id("limitation", f"{index}:{description}"), "extraction_limit", description)
        for index, description in enumerate(parsed.limitations[:limits.max_issues])
    )
    return Report(
        artifact=artifact, analysis_config=limits.config(),
        evidence=tuple(evidence), observations=tuple(observations),
        pe_facts=tuple(structural), limitations=limitations,
        parser_versions={parsed.parser_name: parsed.parser_version}, schema_version="1.1.0",
    )
