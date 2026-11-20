from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .errors import GateInputError


@dataclass
class GateConfig:
    schema_version: str = "1.0"
    required_categories: dict[str, int] = field(default_factory=dict)
    required_case_ids: list[str] = field(default_factory=list)
    min_hardened_protected_rate: float = 1.0
    min_benign_passed_rate: float = 1.0
    fail_on_uncertain: bool = True
    fail_on_skipped: bool = True
    fail_on_execution_error: bool = True
    allow_missing_baseline: bool = False
    max_allowed_regressions: int = 0

    @classmethod
    def load(cls, path: Path | str | None) -> "GateConfig":
        if path is None:
            return cls()
        source = Path(path)
        try:
            raw = json.loads(source.read_text(encoding="utf-8"))
        except OSError as exc:
            raise GateInputError(f"cannot read gate config: {exc}") from exc
        except json.JSONDecodeError as exc:
            raise GateInputError(f"gate config is not valid JSON: {exc}") from exc
        return cls.from_dict(raw, source=str(source))

    @classmethod
    def from_dict(cls, raw: dict[str, Any], *, source: str = "<config>") -> "GateConfig":
        if not isinstance(raw, dict):
            raise GateInputError(f"{source}: config must be an object")
        if raw.get("schema_version", "1.0") != "1.0":
            raise GateInputError(f"{source}: schema_version must be '1.0'")
        required_categories = raw.get("required_categories", {})
        if not isinstance(required_categories, dict):
            raise GateInputError(f"{source}: required_categories must be an object")
        categories: dict[str, int] = {}
        for key, value in required_categories.items():
            if not isinstance(key, str) or not key:
                raise GateInputError(f"{source}: category names must be non-empty strings")
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise GateInputError(f"{source}: category counts must be non-negative integers")
            categories[key] = value
        required_case_ids = raw.get("required_case_ids", [])
        if not isinstance(required_case_ids, list) or any(
            not isinstance(item, str) or not item for item in required_case_ids
        ):
            raise GateInputError(f"{source}: required_case_ids must be non-empty strings")
        min_rate = raw.get("min_hardened_protected_rate", 1.0)
        min_benign = raw.get("min_benign_passed_rate", 1.0)
        for field_name, value in (
            ("min_hardened_protected_rate", min_rate),
            ("min_benign_passed_rate", min_benign),
        ):
            if not isinstance(value, (int, float)) or isinstance(value, bool) or not 0 <= value <= 1:
                raise GateInputError(f"{source}: {field_name} must be between 0 and 1")
        booleans = {}
        for key, default in (
            ("fail_on_uncertain", True),
            ("fail_on_skipped", True),
            ("fail_on_execution_error", True),
            ("allow_missing_baseline", False),
        ):
            value = raw.get(key, default)
            if not isinstance(value, bool):
                raise GateInputError(f"{source}: {key} must be a boolean")
            booleans[key] = value
        max_regressions = raw.get("max_allowed_regressions", 0)
        if not isinstance(max_regressions, int) or isinstance(max_regressions, bool) or max_regressions < 0:
            raise GateInputError(f"{source}: max_allowed_regressions must be a non-negative integer")
        return cls(
            schema_version="1.0",
            required_categories=categories,
            required_case_ids=list(required_case_ids),
            min_hardened_protected_rate=float(min_rate),
            min_benign_passed_rate=float(min_benign),
            fail_on_uncertain=booleans["fail_on_uncertain"],
            fail_on_skipped=booleans["fail_on_skipped"],
            fail_on_execution_error=booleans["fail_on_execution_error"],
            allow_missing_baseline=booleans["allow_missing_baseline"],
            max_allowed_regressions=max_regressions,
        )
