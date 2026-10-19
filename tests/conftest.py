from pathlib import Path

import pytest

from malvisor.core.models import Artifact, Evidence, Inference, Limitation, Location, Observation
from malvisor.core.uncertainty import Level, VerificationStatus
from malvisor.reporting.json_report import Report


ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def report() -> Report:
    """A synthetic teaching example, unrelated to any executable."""
    artifact = Artifact("artifact-1", "0" * 64, 0, "synthetic-placeholder", "synthetic test metadata")
    evidence = Evidence("evidence-1", artifact.id, "synthetic field", "manual fixture", VerificationStatus.PENDING, Location())
    observation = Observation("observation-1", "Synthetic marker is declared in fixture metadata", (evidence.id,), Level.HIGH)
    inference = Inference("inference-1", "Marker may illustrate provenance links", (observation.id,), Level.LOW,
                          ("It may be arbitrary text",), ("No PE file was parsed",))
    limitation = Limitation("limitation-1", "no_parser", "No parser ran; location is pending", evidence.id)
    return Report(artifact, {"static_only": True, "target_format": "synthetic"},
                  (evidence,), (observation,), (inference,), limitations=(limitation,))

