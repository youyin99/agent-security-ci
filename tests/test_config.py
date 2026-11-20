from __future__ import annotations

import pytest

from agent_security_ci.config import GateConfig
from agent_security_ci.errors import GateInputError
from agent_security_ci.gate import parse_report


def test_default_config_is_strict():
    config = GateConfig()
    assert config.fail_on_uncertain is True
    assert config.fail_on_skipped is True
    assert config.fail_on_execution_error is True
    assert config.allow_missing_baseline is False


@pytest.mark.parametrize(
    "raw",
    [
        {"schema_version": "2.0"},
        {"min_hardened_protected_rate": 1.5},
        {"fail_on_uncertain": "yes"},
        {"required_categories": {"x": -1}},
        {"required_case_ids": [1]},
        {"max_allowed_regressions": -1},
    ],
)
def test_invalid_config_is_rejected(raw):
    with pytest.raises(GateInputError):
        GateConfig.from_dict(raw)


def test_invalid_report_schema_is_rejected():
    with pytest.raises(GateInputError, match="schema_version"):
        parse_report({"schema_version": "2.0", "report_type": "agentprobe", "cases": []})
    with pytest.raises(GateInputError, match="report_type"):
        parse_report({"schema_version": "1.0", "report_type": "other", "cases": []})
    with pytest.raises(GateInputError, match="duplicate"):
        parse_report(
            {
                "schema_version": "1.0",
                "report_type": "agentprobe",
                "cases": [
                    {
                        "id": "x",
                        "kind": "benign",
                        "category": "benign",
                        "profiles": {
                            "baseline": {"verdict": "passed"},
                            "hardened": {"verdict": "passed"},
                        },
                    },
                    {
                        "id": "x",
                        "kind": "benign",
                        "category": "benign",
                        "profiles": {
                            "baseline": {"verdict": "passed"},
                            "hardened": {"verdict": "passed"},
                        },
                    },
                ],
            }
        )
