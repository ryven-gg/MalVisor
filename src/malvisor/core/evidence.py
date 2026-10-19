"""Semantic validation of the provenance graph."""

from collections.abc import Iterable
from typing import Any

from malvisor.core.exceptions import ContractError
from malvisor.core.models import Artifact, Disagreement, Evidence, Inference, Limitation, Observation, StructuralFact


def validate_references(
    artifact: Artifact,
    evidence: Iterable[Evidence],
    observations: Iterable[Observation],
    inferences: Iterable[Inference],
    disagreements: Iterable[Disagreement],
    limitations: Iterable[Limitation],
    pe_facts: Iterable[StructuralFact] = (),
) -> None:
    evidence = tuple(evidence)
    observations = tuple(observations)
    inferences = tuple(inferences)
    disagreements = tuple(disagreements)
    limitations = tuple(limitations)
    pe_facts = tuple(pe_facts)
    entities = (artifact, *evidence, *observations, *inferences, *disagreements, *limitations)
    ids = [entity.id for entity in entities]
    if len(ids) != len(set(ids)):
        raise ContractError("entity IDs must be globally unique")
    evidence_ids = {item.id for item in evidence}
    observation_ids = {item.id for item in observations}
    for item in evidence:
        if item.artifact_id != artifact.id:
            raise ContractError(f"evidence {item.id} refers to an unknown artifact")
        if item.verification_status.value == "verified":
            location = item.location
            if location.byte_range is not None and location.byte_range[1] > artifact.size:
                raise ContractError(f"verified evidence {item.id} exceeds artifact size")
            if location.file_offset is not None and location.file_offset >= artifact.size:
                raise ContractError(f"verified evidence {item.id} has an invalid file offset")
    for item in observations:
        if not set(item.evidence_ids) <= evidence_ids:
            raise ContractError(f"observation {item.id} has dangling evidence references")
    for item in inferences:
        if not set(item.observation_ids) <= observation_ids:
            raise ContractError(f"inference {item.id} has dangling observation references")
    for item in disagreements:
        if not set(item.evidence_ids) <= evidence_ids:
            raise ContractError(f"disagreement {item.id} has dangling evidence references")
    for item in limitations:
        if item.subject_id is not None and item.subject_id not in ids:
            raise ContractError(f"limitation {item.id} has a dangling subject reference")
    paths = [item.path for item in pe_facts]
    if len(paths) != len(set(paths)):
        raise ContractError("structural fact paths must be unique")
    for item in pe_facts:
        if item.evidence_id not in evidence_ids:
            raise ContractError(f"structural fact {item.path} has dangling evidence reference")


def validate_payload_references(payload: dict[str, Any]) -> None:
    """Check links in a JSON payload after JSON Schema shape validation."""
    artifact = payload["artifact"]
    if payload["input_sha256"] != artifact["sha256"]:
        raise ContractError("input_sha256 differs from artifact.sha256")
    collections = ("evidence", "observations", "inferences", "disagreements", "limitations")
    ids = [artifact["id"], *(item["id"] for name in collections for item in payload[name])]
    if len(ids) != len(set(ids)):
        raise ContractError("entity IDs must be globally unique")
    evidence_ids = {item["id"] for item in payload["evidence"]}
    observation_ids = {item["id"] for item in payload["observations"]}
    for item in payload["evidence"]:
        if item["artifact_id"] != artifact["id"]:
            raise ContractError(f"evidence {item['id']} refers to an unknown artifact")
        location = item["location"]
        has_location = any(value is not None for value in location.values())
        if item["verification_status"] == "verified" and not has_location:
            raise ContractError(f"verified evidence {item['id']} has no location")
        if item["verification_status"] == "verified":
            if location["byte_range"] is not None and location["byte_range"][1] > artifact["size"]:
                raise ContractError(f"verified evidence {item['id']} exceeds artifact size")
            if location["file_offset"] is not None and location["file_offset"] >= artifact["size"]:
                raise ContractError(f"verified evidence {item['id']} has an invalid file offset")
        if item["verification_status"] == "unresolved" and has_location:
            raise ContractError(f"unresolved evidence {item['id']} claims a location")
        for name in ("byte_range", "instruction_range"):
            value = location[name]
            if value is not None and value[1] <= value[0]:
                raise ContractError(f"invalid {name} on evidence {item['id']}")
        if location["file_offset"] is not None and location["byte_range"] is not None:
            start, end = location["byte_range"]
            if not start <= location["file_offset"] < end:
                raise ContractError(f"file offset outside byte range on evidence {item['id']}")
    for item in payload["observations"]:
        if not set(item["evidence_ids"]) <= evidence_ids:
            raise ContractError(f"observation {item['id']} has dangling evidence references")
    for item in payload["inferences"]:
        if not set(item["observation_ids"]) <= observation_ids:
            raise ContractError(f"inference {item['id']} has dangling observation references")
    for item in payload["disagreements"]:
        if not set(item["evidence_ids"]) <= evidence_ids:
            raise ContractError(f"disagreement {item['id']} has dangling evidence references")
    for item in payload["limitations"]:
        if item["subject_id"] is not None and item["subject_id"] not in ids:
            raise ContractError(f"limitation {item['id']} has a dangling subject reference")
    if "pe_facts" in payload:
        paths = [item["path"] for item in payload["pe_facts"]]
        if len(paths) != len(set(paths)):
            raise ContractError("structural fact paths must be unique")
        for item in payload["pe_facts"]:
            if item["evidence_id"] not in evidence_ids:
                raise ContractError(f"structural fact {item['path']} has dangling evidence reference")

