"""Finite resource budgets used before and during PE extraction."""

from dataclasses import dataclass

from malvisor.core.exceptions import ContractError


@dataclass(frozen=True)
class Limits:
    max_input_size: int = 16 * 1024 * 1024
    max_sections: int = 96
    max_import_descriptors: int = 256
    max_imported_functions: int = 4096
    max_data_directories: int = 32
    max_field_size: int = 256
    max_observations: int = 10000
    max_issues: int = 256

    def __post_init__(self) -> None:
        for name, value in vars(self).items():
            if type(value) is not int or value < 1:
                raise ContractError(f"{name} must be a positive integer")

    def config(self) -> dict[str, int | bool | str]:
        return {"static_only": True, "target_format": "PE", **vars(self)}

