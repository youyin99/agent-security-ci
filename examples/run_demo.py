#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agent_security_ci.config import GateConfig
from agent_security_ci.gate import evaluate_gate, load_report, write_gate_outputs

HERE = Path(__file__).resolve().parent
REPORTS = HERE / "reports"
OUTPUT = HERE / "output"
CONFIG = GateConfig.load(HERE / "gate-policy.json")


def main() -> int:
    baseline = load_report(REPORTS / "baseline.json", label="baseline")
    fixed = load_report(REPORTS / "fixed.json", label="current")
    weakened = load_report(REPORTS / "weakened.json", label="current")
    assert baseline and fixed and weakened
    scenarios = [
        (
            "baseline-vs-fixed",
            "The fixed report should pass.",
            evaluate_gate(baseline=baseline, current=fixed, config=CONFIG, baseline_label="baseline.json", current_label="fixed.json"),
            True,
        ),
        (
            "baseline-vs-weakened",
            "A weakened permission check should fail and name exfil-001.",
            evaluate_gate(baseline=baseline, current=weakened, config=CONFIG, baseline_label="baseline.json", current_label="weakened.json"),
            False,
        ),
        (
            "missing-baseline",
            "A missing baseline should fail closed.",
            evaluate_gate(baseline=None, current=fixed, config=CONFIG, baseline_label=None, current_label="fixed.json"),
            False,
        ),
    ]
    results = []
    for name, description, result, expected_pass in scenarios:
        write_gate_outputs(OUTPUT, result, stem=name)
        passed_expectation = result["passed"] is expected_pass
        if name == "baseline-vs-weakened":
            passed_expectation = passed_expectation and "exfil-001" in result["failed_cases"]
        results.append(
            {
                "name": name,
                "description": description,
                "expected_pass": expected_pass,
                "actual_pass": result["passed"],
                "failed_cases": result["failed_cases"],
                "expectation_met": passed_expectation,
            }
        )
        print(
            f"{'PASS' if passed_expectation else 'FAIL'} {name}: gate "
            f"{'passed' if result['passed'] else 'failed'}; "
            f"failed_cases={result['failed_cases']}"
        )
    summary = {
        "schema_version": "1.0",
        "report_type": "agent_security_ci_demo",
        "all_expectations_met": all(item["expectation_met"] for item in results),
        "results": results,
    }
    OUTPUT.mkdir(parents=True, exist_ok=True)
    (OUTPUT / "demo-summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return 0 if summary["all_expectations_met"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
