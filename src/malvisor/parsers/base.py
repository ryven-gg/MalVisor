"""Future parser adapter contract only."""

from typing import Protocol

from malvisor.core.models import Artifact, Evidence, Observation


class ParserAdapter(Protocol):
    @property
    def name(self) -> str: ...

    @property
    def version(self) -> str: ...

    def parse(self, data: bytes, artifact: Artifact) -> tuple[tuple[Observation, ...], tuple[Evidence, ...]]: ...

