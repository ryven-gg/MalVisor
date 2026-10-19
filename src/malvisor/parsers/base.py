"""Shared function signature for static parser adapters."""

from typing import Protocol

from malvisor.parsers.limits import Limits
from malvisor.parsers.normalized import ParsedPE


class ParserAdapter(Protocol):
    def __call__(self, data: bytes, limits: Limits) -> ParsedPE: ...

