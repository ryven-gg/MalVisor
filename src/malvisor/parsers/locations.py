"""Conservative PE address mapping independent of pefile's permissive lookup."""

from dataclasses import dataclass
from enum import StrEnum


class MappingStatus(StrEnum):
    RAW = "raw"
    VIRTUAL_ONLY = "virtual_only"
    AMBIGUOUS = "ambiguous"
    INVALID = "invalid"


@dataclass(frozen=True)
class SectionRange:
    virtual_address: int
    virtual_size: int
    raw_offset: int
    raw_size: int


@dataclass(frozen=True)
class Mapping:
    status: MappingStatus
    file_offset: int | None = None


def raw_range(offset: int, size: int, file_size: int) -> bool:
    return offset >= 0 and size >= 0 and offset <= file_size and size <= file_size - offset


def map_rva(rva: int, size: int, *, file_size: int, size_of_headers: int,
            sections: tuple[SectionRange, ...]) -> Mapping:
    if rva < 0 or size < 1 or rva + size > 0x100000000:
        return Mapping(MappingStatus.INVALID)
    candidates: list[Mapping] = []
    if rva < size_of_headers and raw_range(rva, size, min(size_of_headers, file_size)):
        candidates.append(Mapping(MappingStatus.RAW, rva))
    for section in sections:
        span = max(section.virtual_size, section.raw_size)
        if section.virtual_address <= rva and rva + size <= section.virtual_address + span:
            relative = rva - section.virtual_address
            if relative + size <= section.raw_size and raw_range(section.raw_offset + relative, size, file_size):
                candidates.append(Mapping(MappingStatus.RAW, section.raw_offset + relative))
            elif relative < section.virtual_size and relative + size <= section.virtual_size:
                candidates.append(Mapping(MappingStatus.VIRTUAL_ONLY))
            else:
                candidates.append(Mapping(MappingStatus.INVALID))
    if len(candidates) > 1:
        return Mapping(MappingStatus.AMBIGUOUS)
    return candidates[0] if candidates else Mapping(MappingStatus.INVALID)


def map_va(va: int, image_base: int, *, size: int, file_size: int,
           size_of_headers: int, sections: tuple[SectionRange, ...]) -> Mapping:
    if va < image_base:
        return Mapping(MappingStatus.INVALID)
    return map_rva(va - image_base, size, file_size=file_size,
                   size_of_headers=size_of_headers, sections=sections)


def bounded_excerpt(data: bytes, offset: int, size: int, *, maximum: int = 32) -> str:
    if maximum < 1 or not raw_range(offset, size, len(data)):
        raise ValueError("invalid excerpt range")
    return data[offset:offset + min(size, maximum)].hex()

