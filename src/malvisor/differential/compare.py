"""Normalize semantic fields before identifying parser divergences."""

from dataclasses import dataclass, replace
import hashlib
import re

from malvisor.core.models import Disagreement, Evidence
from malvisor.core.uncertainty import DisagreementCategory, VerificationStatus
from malvisor.parsers.normalized import ParsedPE
from malvisor.reporting.json_report import Report


@dataclass(frozen=True)
class NormalizedField:
    value: str | int | float | bool | None
    source_path: str


@dataclass(frozen=True)
class Comparison:
    parser_names: tuple[str, str]
    equivalent_count: int
    disagreements: tuple[Disagreement, ...]


def _token(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:20]


def _section_name(value: str) -> str:
    return value.rstrip("\x00").removesuffix("\\x00")


def normalize(parsed: ParsedPE) -> dict[str, NormalizedField]:
    raw = {fact.path: fact for fact in parsed.facts}
    result: dict[str, NormalizedField] = {}
    section_indices = {int(match.group(1)) for path in raw
                       if (match := re.fullmatch(r"sections\.(\d+)\.virtual_address", path))}
    ordered_sections = sorted(
        section_indices,
        key=lambda index: (
            int(raw[f"sections.{index}.virtual_address"].value),
            int(raw[f"sections.{index}.pointer_to_raw_data"].value)
            if f"sections.{index}.pointer_to_raw_data" in raw else -1,
            _section_name(str(raw[f"sections.{index}.name"].value))
            if f"sections.{index}.name" in raw else "",
        ),
    )
    for rank, index in enumerate(ordered_sections):
        prefix = f"sections.{index}"
        key = f"sections.normalized.{rank}"
        for path, fact in raw.items():
            if path.startswith(prefix + ".") and not path.endswith(".name_raw_hex"):
                suffix = path[len(prefix):]
                value = fact.value
                if suffix == ".name" and isinstance(value, str):
                    value = _section_name(value)
                result[key + suffix] = NormalizedField(value, path)
    import_indices = sorted({int(match.group(1)) for path in raw
                             if (match := re.fullmatch(r"imports\.(\d+)\.dll", path))})
    import_groups: dict[str, list[tuple[str, str]]] = {}
    for index in import_indices:
        prefix = f"imports.{index}"
        dll = raw[prefix + ".dll"]
        dll_name = str(dll.value).casefold()
        import_groups.setdefault(dll_name, [])
        result[f"imports.dll.{_token(dll_name)}"] = NormalizedField(dll_name, dll.path)
        symbol_indices = sorted({int(match.group(1)) for path in raw
                                 if (match := re.fullmatch(re.escape(prefix) + r"\.symbols\.(\d+)\.(?:name|ordinal)", path))})
        for symbol_index in symbol_indices:
            for kind in ("name", "ordinal"):
                item = raw.get(f"{prefix}.symbols.{symbol_index}.{kind}")
                if item is not None:
                    symbol = f"{dll_name}!{kind}:{item.value}"
                    import_groups[dll_name].append((symbol, item.path))
    for dll_name, symbols in import_groups.items():
        for symbol_index, (symbol, source_path) in enumerate(sorted(symbols)):
            result[f"imports.by_dll.{_token(dll_name)}.symbols.{symbol_index}"] = NormalizedField(symbol, source_path)
    for path, fact in raw.items():
        if path.startswith(("sections.", "imports.")):
            continue
        if path in ("dos.valid", "coff.pe_signature"):
            continue
        result[path] = NormalizedField(fact.value, path)
    return result


def compare(primary: ParsedPE, reference: ParsedPE,
            evidence: tuple[Evidence, ...] = ()) -> Comparison:
    a = normalize(primary)
    b = normalize(reference)
    evidence_by_path = {item.location.header_field: item for item in evidence
                        if item.location.header_field is not None}
    differences: list[Disagreement] = []
    equal = 0
    malformed = set(primary.malformed_fields) | set(reference.malformed_fields)
    for path in sorted(a.keys() | b.keys() | malformed):
        left = a.get(path)
        right = b.get(path)
        if path not in malformed and left is not None and right is not None and left.value == right.value:
            equal += 1
            continue
        if path in malformed:
            category = DisagreementCategory.MALFORMED_INPUT
        elif left is None or right is None:
            category = DisagreementCategory.UNSUPPORTED
        else:
            category = DisagreementCategory.SEMANTIC_DIFFERENCE
        source = evidence_by_path.get(left.source_path) if left is not None else None
        verified = source is not None and source.verification_status is VerificationStatus.VERIFIED
        evidence_ids = (source.id,) if source is not None else ()
        explanation = (
            "Parser marked this field as malformed; compare raw bytes and parser rules manually."
            if category is DisagreementCategory.MALFORMED_INPUT else
            "Field is available from only one parser; support or extraction may differ."
            if category is DisagreementCategory.UNSUPPORTED else
            "Normalized field values differ; manual review is needed before attributing a parser defect."
        )
        differences.append(Disagreement(
            id="disagreement-" + _token(path), category=category, description=explanation,
            parser_names=(primary.parser_name, reference.parser_name), evidence_ids=evidence_ids,
            field_path=path, value_a=left.value if left else None, value_b=right.value if right else None,
            verification_status=VerificationStatus.VERIFIED if verified else VerificationStatus.UNRESOLVED,
            limitations=("Reference location is not independently verified by this comparison.",),
        ))
    return Comparison((primary.parser_name, reference.parser_name), equal, tuple(differences))


def attach_comparison(report: Report, reference: ParsedPE, comparison: Comparison) -> Report:
    versions = {**report.parser_versions, reference.parser_name: reference.parser_version}
    return replace(
        report, parser_versions=versions, disagreements=comparison.disagreements,
        comparison={
            "parser_a": comparison.parser_names[0],
            "parser_b": comparison.parser_names[1],
            "equivalent_count": comparison.equivalent_count,
            "disagreement_count": len(comparison.disagreements),
        },
    )
