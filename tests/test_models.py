import pytest

from malvisor.core.exceptions import ContractError
from malvisor.core.models import Artifact, Inference, Location, Observation
from malvisor.core.uncertainty import Level


def test_valid_model_creation(report):
    assert report.artifact.size == 0
    assert report.inferences[0].inference_strength is Level.LOW
    assert report.observations[0].observation_confidence is Level.HIGH


@pytest.mark.parametrize("kwargs", [
    {"id": "bad id"}, {"sha256": "z" * 64}, {"size": -1}, {"size": True},
])
def test_invalid_artifact_rejected(kwargs):
    values = {"id": "artifact-1", "sha256": "0" * 64, "size": 0, "format": "synthetic"}
    values.update(kwargs)
    with pytest.raises(ContractError):
        Artifact(**values)


def test_invalid_location_range_rejected():
    with pytest.raises(ContractError):
        Location(byte_range=(8, 8))


def test_invalid_confidence_rejected():
    with pytest.raises(ContractError):
        Observation("observation-1", "fact", ("evidence-1",), "certain")


def test_inference_needs_observation():
    with pytest.raises(ContractError):
        Inference("inference-1", "meaning", (), Level.LOW)

