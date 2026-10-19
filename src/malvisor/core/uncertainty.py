"""Qualitative uncertainty categories, never malware probabilities."""

from enum import StrEnum


class Level(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class VerificationStatus(StrEnum):
    VERIFIED = "verified"
    PENDING = "pending"
    UNRESOLVED = "unresolved"


class DisagreementCategory(StrEnum):
    EQUIVALENT = "equivalent"
    SEMANTIC_DIFFERENCE = "semantic_difference"
    UNSUPPORTED = "unsupported"
    MALFORMED_INPUT = "malformed_input"
    SUSPECTED_PARSER_DEFECT = "suspected_parser_defect"

