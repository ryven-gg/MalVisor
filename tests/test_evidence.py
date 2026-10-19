from dataclasses import replace

import pytest

from malvisor.core.exceptions import ContractError
from malvisor.core.models import Evidence, Location
from malvisor.core.uncertainty import VerificationStatus


def test_verified_evidence_needs_location(report):
    item = report.evidence[0]
    with pytest.raises(ContractError):
        replace(item, verification_status=VerificationStatus.VERIFIED)
    verified = replace(item, verification_status=VerificationStatus.VERIFIED,
                       location=Location(header_field="DOS.e_lfanew"))
    assert verified.location.has_location()


def test_unresolved_evidence_cannot_claim_location(report):
    item = report.evidence[0]
    with pytest.raises(ContractError):
        replace(item, verification_status=VerificationStatus.UNRESOLVED,
                location=Location(file_offset=0))


def test_dangling_evidence_reference_rejected(report):
    observation = replace(report.observations[0], evidence_ids=("missing",))
    with pytest.raises(ContractError, match="dangling evidence"):
        replace(report, observations=(observation,))


def test_dangling_artifact_and_observation_rejected(report):
    with pytest.raises(ContractError, match="unknown artifact"):
        replace(report, evidence=(replace(report.evidence[0], artifact_id="other"),))
    with pytest.raises(ContractError, match="dangling observation"):
        replace(report, inferences=(replace(report.inferences[0], observation_ids=("other",)),))


def test_duplicate_ids_rejected(report):
    with pytest.raises(ContractError, match="globally unique"):
        replace(report, evidence=(Evidence("artifact-1", "artifact-1", "synthetic", "fixture", VerificationStatus.PENDING),))

