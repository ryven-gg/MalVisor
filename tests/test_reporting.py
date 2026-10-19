import json
from dataclasses import replace

from jsonschema import Draft202012Validator
import pytest

from conftest import ROOT
from malvisor.core.evidence import validate_payload_references
from malvisor.core.exceptions import ContractError
from malvisor.core.models import Evidence, Observation
from malvisor.core.reproducibility import canonical_json
from malvisor.core.uncertainty import Level, VerificationStatus


SCHEMA = json.loads((ROOT / "schemas/report-v1.schema.json").read_text(encoding="utf-8"))
VALIDATOR = Draft202012Validator(SCHEMA)


def test_example_report_is_schema_valid():
    Draft202012Validator.check_schema(SCHEMA)
    payload = json.loads((ROOT / "examples/example-report.json").read_text(encoding="utf-8"))
    VALIDATOR.validate(payload)
    validate_payload_references(payload)


def test_model_report_is_schema_valid(report):
    VALIDATOR.validate(report.to_dict())


def test_required_field_rejected(report):
    payload = report.to_dict()
    del payload["input_sha256"]
    assert list(VALIDATOR.iter_errors(payload))


def test_invalid_confidence_rejected_by_schema(report):
    payload = report.to_dict()
    payload["observations"][0]["observation_confidence"] = "certain"
    assert list(VALIDATOR.iter_errors(payload))


def test_json_reference_semantics_are_separate_from_schema(report):
    payload = report.to_dict()
    payload["observations"][0]["evidence_ids"] = ["missing"]
    VALIDATOR.validate(payload)
    with pytest.raises(ContractError, match="dangling evidence"):
        validate_payload_references(payload)


def test_json_input_hash_must_match_artifact(report):
    payload = report.to_dict()
    payload["input_sha256"] = "1" * 64
    VALIDATOR.validate(payload)
    with pytest.raises(ContractError, match="input_sha256"):
        validate_payload_references(payload)


def test_inconsistent_version_rejected(report):
    with pytest.raises(ContractError):
        replace(report, schema_version="2.0.0")
    payload = report.to_dict()
    payload["schema_version"] = "2.0.0"
    assert list(VALIDATOR.iter_errors(payload))


def test_deterministic_json(report):
    second_evidence = Evidence("evidence-2", report.artifact.id, "second synthetic field",
                               "manual fixture", VerificationStatus.PENDING)
    second_observation = Observation("observation-2", "Second synthetic marker",
                                     (second_evidence.id,), Level.UNKNOWN)
    first = replace(report, evidence=(second_evidence, *report.evidence),
                    observations=(second_observation, *report.observations),
                    parser_versions={"z-parser": "1", "a-parser": "2"})
    reversed_report = replace(first, evidence=tuple(reversed(first.evidence)),
                              observations=tuple(reversed(first.observations)),
                              parser_versions={"a-parser": "2", "z-parser": "1"})
    assert first.to_json() == reversed_report.to_json()
    assert [item["id"] for item in first.to_dict()["evidence"]] == ["evidence-1", "evidence-2"]
    assert first.to_json().endswith("\n")


def test_nonfinite_rejected():
    with pytest.raises(ContractError):
        canonical_json({"bad": float("nan")})

