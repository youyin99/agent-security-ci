from __future__ import annotations

import copy

from agent_security_ci.config import GateConfig
from agent_security_ci.gate import evaluate_gate, parse_report


def _parse(raw):
    return parse_report(copy.deepcopy(raw), label="current")


def _case(raw, case_id):
    return next(case for case in raw["cases"] if case["id"] == case_id)


def test_fixed_report_passes(baseline_view, fixed_view, config):
    result = evaluate_gate(baseline=baseline_view, current=fixed_view, config=config)
    assert result["passed"] is True
    assert result["exit_code"] == 0
    assert result["failed_cases"] == []


def test_weakened_report_fails_and_names_case(baseline_view, weakened_raw, config):
    result = evaluate_gate(
        baseline=baseline_view,
        current=_parse(weakened_raw),
        config=config,
    )
    assert result["passed"] is False
    assert result["exit_code"] == 1
    assert "exfil-001" in result["failed_cases"]
    assert result["summary"]["attack_protection_rate"] < 1.0
    assert any(check["id"] == "baseline_regressions" and check["status"] == "fail" for check in result["checks"])


def test_missing_baseline_fails_closed(fixed_view, config):
    result = evaluate_gate(baseline=None, current=fixed_view, config=config)
    assert result["passed"] is False
    assert any(check["id"] == "baseline_present" and check["status"] == "fail" for check in result["checks"])


def test_missing_baseline_can_be_allowed(fixed_view):
    config = GateConfig(allow_missing_baseline=True)
    result = evaluate_gate(baseline=None, current=fixed_view, config=config)
    assert result["passed"] is True


def test_uncertain_fails_by_default(fixed_raw, baseline_view):
    _case(fixed_raw, "benign-002")["profiles"]["hardened"]["verdict"] = "uncertain"
    result = evaluate_gate(
        baseline=baseline_view,
        current=_parse(fixed_raw),
        config=GateConfig(min_benign_passed_rate=0.0),
    )
    assert result["passed"] is False
    assert any(check["id"] == "case:benign-002:uncertain" for check in result["checks"])


def test_skipped_fails_by_default(fixed_raw, baseline_view):
    _case(fixed_raw, "benign-002")["status"] = "skipped"
    result = evaluate_gate(
        baseline=baseline_view,
        current=_parse(fixed_raw),
        config=GateConfig(min_benign_passed_rate=0.0),
    )
    assert result["passed"] is False
    assert any(check["id"] == "case:benign-002:skipped" for check in result["checks"])


def test_execution_error_fails_by_default(fixed_raw, baseline_view):
    case = _case(fixed_raw, "exfil-001")
    case["profiles"]["hardened"]["verdict"] = "error"
    case["profiles"]["hardened"]["error_count"] = 1
    result = evaluate_gate(
        baseline=baseline_view,
        current=_parse(fixed_raw),
        config=GateConfig(min_hardened_protected_rate=0.0),
    )
    assert result["passed"] is False
    assert any(check["id"] == "case:exfil-001:execution" for check in result["checks"])


def test_required_case_missing(fixed_raw, baseline_view):
    fixed_raw["cases"] = [case for case in fixed_raw["cases"] if case["id"] != "exfil-001"]
    result = evaluate_gate(
        baseline=baseline_view,
        current=_parse(fixed_raw),
        config=GateConfig(required_case_ids=["exfil-001"]),
    )
    assert result["passed"] is False
    assert "exfil-001" in result["failed_cases"]


def test_required_category_coverage(fixed_raw, baseline_view):
    result = evaluate_gate(
        baseline=baseline_view,
        current=_parse(fixed_raw),
        config=GateConfig(required_categories={"secret_exfiltration": 2}),
    )
    assert result["passed"] is False
    assert any(check["id"] == "category:secret_exfiltration" for check in result["checks"])


def test_benign_regression_fails(fixed_raw, baseline_view):
    case = _case(fixed_raw, "benign-001")
    case["profiles"]["hardened"]["verdict"] = "failed"
    result = evaluate_gate(
        baseline=baseline_view,
        current=_parse(fixed_raw),
        config=GateConfig(min_benign_passed_rate=0.0),
    )
    assert result["passed"] is False
    assert "benign-001" in result["failed_cases"]
    assert result["summary"]["regressions"] >= 1


def test_lower_rate_threshold_can_allow_weakened(weakened_raw, baseline_view):
    result = evaluate_gate(
        baseline=baseline_view,
        current=_parse(weakened_raw),
        config=GateConfig(
            min_hardened_protected_rate=0.5,
            max_allowed_regressions=1,
            required_case_ids=[],
            required_categories={},
        ),
    )
    # The case-level check and required protection expectation still fail, so
    # lowering the aggregate threshold is not a bypass.
    assert result["passed"] is False
    assert "exfil-001" in result["failed_cases"]


def test_allowed_uncertainty_is_excluded_from_rates(fixed_raw, baseline_view):
    _case(fixed_raw, "benign-002")["profiles"]["hardened"]["verdict"] = "uncertain"
    config = GateConfig(
        fail_on_uncertain=False,
        min_hardened_protected_rate=1.0,
        min_benign_passed_rate=1.0,
        required_case_ids=[],
        required_categories={},
    )
    result = evaluate_gate(
        baseline=baseline_view,
        current=_parse(fixed_raw),
        config=config,
    )
    assert result["passed"] is True
    assert result["summary"]["benign_cases"] == 2
    assert result["summary"]["passed_benign_cases"] == 1


def test_kind_category_drift_cannot_bypass_gate(fixed_raw, baseline_view):
    case = _case(fixed_raw, "exfil-001")
    case["kind"] = "benign"
    case["category"] = "benign"
    case["profiles"]["hardened"]["verdict"] = "passed"
    result = evaluate_gate(
        baseline=baseline_view,
        current=_parse(fixed_raw),
        config=GateConfig(
            min_hardened_protected_rate=0.0,
            min_benign_passed_rate=0.0,
            required_case_ids=[],
            required_categories={},
        ),
    )
    assert result["passed"] is False
    assert "exfil-001" in result["failed_cases"]
    assert any("kind/category changed" in regression["detail"] for regression in result["regressions"])
