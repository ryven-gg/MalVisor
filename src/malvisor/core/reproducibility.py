"""Canonical JSON rules for report payloads."""

import json
from typing import Any

from malvisor.core.exceptions import ContractError


def canonical_json(payload: dict[str, Any]) -> str:
    """Serialize with stable key order, compact separators, and no NaN/Infinity."""
    try:
        return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n"
    except (TypeError, ValueError) as exc:
        raise ContractError(f"cannot serialize canonical report: {exc}") from exc

