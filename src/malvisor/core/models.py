"""Immutable, explicitly validated report entities."""

from dataclasses import dataclass, field
import re

from malvisor.core.exceptions import ContractError
from malvisor.core.uncertainty import DisagreementCategory, Level, VerificationStatus

SCHEMA_VERSION = "1.0.0"
_ID = re.compile(r"^[A-Za-z][A-Za-z0-9._:-]{0,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _string(value: object, name: str) -> None:
    if not isinstance(value, str) or not value or value != value.strip() or any(ord(c) < 32 for c in value):
        raise ContractError(f"{name} must be a nonempty, trimmed string without control characters")


def _id(value: str) -> None:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ContractError(f"invalid ID: {value!r}")


def _refs(values: tuple[str, ...], name: str) -> None:
    if not isinstance(values, tuple) or len(set(values)) != len(values):
        raise ContractError(f"{name} must be a tuple of unique IDs")
    for value in values:
        _id(value)


def _level(value: Level, name: str) -> None:
    if not isinstance(value, Level):
        raise ContractError(f"{name} must be a Level")


@dataclass(frozen=True)
class Artifact:
    id: str
    sha256: str
    size: int
    format: str
    origin: str | None = None

    def __post_init__(self) -> None:
        _id(self.id)
        if not isinstance(self.sha256, str) or not _SHA256.fullmatch(self.sha256):
            raise ContractError("sha256 must be 64 lowercase hexadecimal characters")
        if type(self.size) is not int or self.size < 0:
            raise ContractError("size must be a nonnegative integer")
        _string(self.format, "format")
        if self.origin is not None:
            _string(self.origin, "origin")


@dataclass(frozen=True)
class Location:
    file_offset: int | None = None
    rva: int | None = None
    va: int | None = None
    header_field: str | None = None
    byte_range: tuple[int, int] | None = None
    instruction_range: tuple[int, int] | None = None

    def __post_init__(self) -> None:
        for name in ("file_offset", "rva", "va"):
            value = getattr(self, name)
            if value is not None and (type(value) is not int or value < 0):
                raise ContractError(f"{name} must be a nonnegative integer or null")
        if self.header_field is not None:
            _string(self.header_field, "header_field")
        for name in ("byte_range", "instruction_range"):
            value = getattr(self, name)
            if value is not None and (not isinstance(value, tuple) or len(value) != 2 or
                                      any(type(n) is not int for n in value) or value[0] < 0 or value[1] <= value[0]):
                raise ContractError(f"{name} must be a nonempty half-open range")
        if self.file_offset is not None and self.byte_range is not None and not self.byte_range[0] <= self.file_offset < self.byte_range[1]:
            raise ContractError("file_offset must fall within byte_range")

    def has_location(self) -> bool:
        return any(getattr(self, name) is not None for name in
                   ("file_offset", "rva", "va", "header_field", "byte_range", "instruction_range"))


@dataclass(frozen=True)
class Evidence:
    id: str
    artifact_id: str
    source: str
    method: str
    verification_status: VerificationStatus
    location: Location = field(default_factory=Location)

    def __post_init__(self) -> None:
        _id(self.id)
        _id(self.artifact_id)
        _string(self.source, "source")
        _string(self.method, "method")
        if not isinstance(self.verification_status, VerificationStatus):
            raise ContractError("invalid verification_status")
        if not isinstance(self.location, Location):
            raise ContractError("location must be a Location")
        if self.verification_status is VerificationStatus.VERIFIED and not self.location.has_location():
            raise ContractError("verified evidence requires a resolved location")
        if self.verification_status is VerificationStatus.UNRESOLVED and self.location.has_location():
            raise ContractError("unresolved evidence cannot claim a location")


@dataclass(frozen=True)
class Observation:
    id: str
    description: str
    evidence_ids: tuple[str, ...]
    observation_confidence: Level

    def __post_init__(self) -> None:
        _id(self.id)
        _string(self.description, "description")
        _refs(self.evidence_ids, "evidence_ids")
        if not self.evidence_ids:
            raise ContractError("observation needs at least one evidence reference")
        _level(self.observation_confidence, "observation_confidence")


@dataclass(frozen=True)
class Inference:
    id: str
    description: str
    observation_ids: tuple[str, ...]
    inference_strength: Level
    alternative_explanations: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _id(self.id)
        _string(self.description, "description")
        _refs(self.observation_ids, "observation_ids")
        if not self.observation_ids:
            raise ContractError("inference needs at least one observation")
        _level(self.inference_strength, "inference_strength")
        for value in (*self.alternative_explanations, *self.limitations):
            _string(value, "explanation/limitation")


@dataclass(frozen=True)
class Disagreement:
    id: str
    category: DisagreementCategory
    description: str
    parser_names: tuple[str, ...]
    evidence_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _id(self.id)
        if not isinstance(self.category, DisagreementCategory):
            raise ContractError("invalid disagreement category")
        _string(self.description, "description")
        if not isinstance(self.parser_names, tuple) or len(self.parser_names) < 2 or len(set(self.parser_names)) != len(self.parser_names):
            raise ContractError("disagreement needs at least two distinct parser names")
        for name in self.parser_names:
            _string(name, "parser name")
        _refs(self.evidence_ids, "evidence_ids")


@dataclass(frozen=True)
class Limitation:
    id: str
    code: str
    description: str
    subject_id: str | None = None

    def __post_init__(self) -> None:
        _id(self.id)
        _id(self.code)
        _string(self.description, "description")
        if self.subject_id is not None:
            _id(self.subject_id)


@dataclass(frozen=True)
class Issue:
    code: str
    message: str

    def __post_init__(self) -> None:
        _id(self.code)
        _string(self.message, "message")
