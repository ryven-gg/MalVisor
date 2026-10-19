"""Validated report assembly and serialization."""

from dataclasses import asdict, dataclass, field
import re
from typing import Any

from malvisor import __version__
from malvisor.core.evidence import validate_references
from malvisor.core.exceptions import ContractError
from malvisor.core.models import (
    SCHEMA_VERSION, Artifact, Disagreement, Evidence, Inference, Issue,
    Limitation, Observation,
)
from malvisor.core.reproducibility import canonical_json


@dataclass(frozen=True)
class Report:
    artifact: Artifact
    analysis_config: dict[str, Any]
    evidence: tuple[Evidence, ...] = ()
    observations: tuple[Observation, ...] = ()
    inferences: tuple[Inference, ...] = ()
    disagreements: tuple[Disagreement, ...] = ()
    limitations: tuple[Limitation, ...] = ()
    warnings: tuple[Issue, ...] = ()
    errors: tuple[Issue, ...] = ()
    parser_versions: dict[str, str] = field(default_factory=dict)
    schema_version: str = SCHEMA_VERSION
    engine_version: str = __version__

    def __post_init__(self) -> None:
        if not isinstance(self.artifact, Artifact):
            raise ContractError("artifact must be an Artifact")
        if self.schema_version != SCHEMA_VERSION:
            raise ContractError(f"unsupported schema version: {self.schema_version}")
        if not isinstance(self.engine_version, str) or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", self.engine_version):
            raise ContractError("engine_version must be a semantic version")
        if not isinstance(self.parser_versions, dict) or any(
            not isinstance(k, str) or not k or not isinstance(v, str) or not v
            for k, v in self.parser_versions.items()
        ):
            raise ContractError("parser_versions must map parser names to nonempty versions")
        if not isinstance(self.analysis_config, dict) or self.analysis_config.get("static_only") is not True:
            raise ContractError("analysis_config.static_only must be true")
        if any(not isinstance(key, str) or not key or
               not (value is None or type(value) in (str, int, bool))
               for key, value in self.analysis_config.items()):
            raise ContractError("analysis_config must contain named scalar values")
        if any(not isinstance(value, tuple) for value in (
            self.evidence, self.observations, self.inferences, self.disagreements,
            self.limitations, self.warnings, self.errors,
        )):
            raise ContractError("report collections must be tuples")
        validate_references(self.artifact, self.evidence, self.observations,
                            self.inferences, self.disagreements, self.limitations)
        for collection, kind in ((self.warnings, Issue), (self.errors, Issue)):
            if any(not isinstance(item, kind) for item in collection):
                raise ContractError("warnings and errors must contain Issue objects")
        canonical_json(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        """Build the canonical payload; entity lists are sorted by stable ID."""
        validate_references(self.artifact, self.evidence, self.observations,
                            self.inferences, self.disagreements, self.limitations)
        def sorted_entities(items: tuple[Any, ...]) -> list[dict[str, Any]]:
            return [_json_value(asdict(item)) for item in sorted(items, key=lambda item: item.id)]

        return {
            "schema_version": self.schema_version,
            "input_sha256": self.artifact.sha256,
            "engine_version": self.engine_version,
            "parser_versions": dict(self.parser_versions),
            "analysis_config": dict(self.analysis_config),
            "artifact": _json_value(asdict(self.artifact)),
            "observations": sorted_entities(self.observations),
            "evidence": sorted_entities(self.evidence),
            "inferences": sorted_entities(self.inferences),
            "disagreements": sorted_entities(self.disagreements),
            "limitations": sorted_entities(self.limitations),
            "warnings": [_json_value(asdict(item)) for item in sorted(self.warnings, key=lambda item: (item.code, item.message))],
            "errors": [_json_value(asdict(item)) for item in sorted(self.errors, key=lambda item: (item.code, item.message))],
        }

    def to_json(self) -> str:
        return canonical_json(self.to_dict())


def _json_value(value: Any) -> Any:
    """Convert immutable Python sequences into JSON arrays."""
    if isinstance(value, dict):
        return {key: _json_value(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_json_value(item) for item in value]
    return value

