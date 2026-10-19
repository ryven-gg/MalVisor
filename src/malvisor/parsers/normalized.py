"""Parser-neutral static PE facts. No fact implies execution."""

from dataclasses import dataclass


@dataclass(frozen=True)
class Fact:
    path: str
    value: str | int | float | bool | None
    offset: int | None = None
    size: int | None = None
    rva: int | None = None
    note: str | None = None


@dataclass(frozen=True)
class ParsedPE:
    parser_name: str
    parser_version: str
    pe_type: str
    facts: tuple[Fact, ...]
    limitations: tuple[str, ...] = ()
    malformed_fields: tuple[str, ...] = ()

