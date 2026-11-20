#!/usr/bin/env python3
"""Build compact demo AgentProbe reports for the gate demonstration.

These are intentionally small report fixtures, not real AgentProbe runs. They
model a baseline, a release that weakens one hardened control, and a fixed
release.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPORTS = HERE / "reports"


def make_case(
    case_id: str,
    kind: str,
    category: str,
    baseline: str,
    hardened: str,
    assertion_id: str,
) -> dict:
    baseline_pass = baseline in {"protected", "passed"}
    hardened_pass = hardened in {"protected", "passed"}
    return {
        "id": case_id,
        "title": f"Demo case {case_id}",
        "kind": kind,
        "category": category,
        "severity": "high" if kind == "attack" else "none",
        "task": "Synthetic demo task.",
        "expected": {
            "allowed_behavior": ["Synthetic allowed behavior"],
            "forbidden_behavior": ["Synthetic forbidden behavior"] if kind == "attack" else [],
        },
        "profiles": {
            "baseline": {
                "verdict": baseline,
                "assertions": [
                    {
                        "id": assertion_id,
                        "type": "no_successful_call",
                        "status": "pass" if baseline_pass else "fail",
                        "summary": "synthetic baseline result",
                        "evidence": {"event_ids": []},
                    }
                ],
                "actions": [],
                "event_count": 2,
                "error_count": 0,
                "errors": [],
            },
            "hardened": {
                "verdict": hardened,
                "assertions": [
                    {
                        "id": assertion_id,
                        "type": "no_successful_call",
                        "status": "pass" if hardened_pass else "fail",
                        "summary": "synthetic hardened result",
                        "evidence": {"event_ids": []},
                    }
                ],
                "actions": [],
                "event_count": 2,
                "error_count": 0,
                "errors": [],
            },
        },
        "differential": baseline == "risk_demonstrated" and hardened == "protected"
        if kind == "attack"
        else None,
    }


def make_report(cases: list[dict], run_id: str) -> dict:
    attack = [case for case in cases if case["kind"] == "attack"]
    benign = [case for case in cases if case["kind"] == "benign"]
    categories = {}
    for case in attack:
        stats = categories.setdefault(
            case["category"],
            {
                "attack": 0,
                "baseline_risk_demonstrated": 0,
                "hardened_protected": 0,
                "hardened_vulnerable": 0,
                "hardened_uncertain": 0,
                "differential": 0,
            },
        )
        stats["attack"] += 1
        if case["profiles"]["baseline"]["verdict"] == "risk_demonstrated":
            stats["baseline_risk_demonstrated"] += 1
        if case["profiles"]["hardened"]["verdict"] == "protected":
            stats["hardened_protected"] += 1
        if case["profiles"]["hardened"]["verdict"] == "vulnerable":
            stats["hardened_vulnerable"] += 1
        if case["profiles"]["hardened"]["verdict"] == "uncertain":
            stats["hardened_uncertain"] += 1
        if case["differential"]:
            stats["differential"] += 1
    return {
        "schema_version": "1.0",
        "report_type": "agentprobe",
        "agentprobe_version": "1.0.0",
        "generated_at": "2026-01-01T00:00:00Z",
        "run_id": run_id,
        "mode": "offline_deterministic",
        "model": {
            "provider": "offline",
            "name": "deterministic-scenario-adapter",
            "external_calls": False,
        },
        "configuration": {
            "profiles": ["baseline", "hardened"],
            "policy_versions": {
                "baseline": "agentprobe-baseline-1.0",
                "hardened": "agentprobe-hardened-1.0",
            },
        },
        "summary": {
            "cases": len(cases),
            "attack_cases": len(attack),
            "benign_cases": len(benign),
            "categories": categories,
            "benign_passed_both": sum(
                case["profiles"]["baseline"]["verdict"] == "passed"
                and case["profiles"]["hardened"]["verdict"] == "passed"
                for case in benign
            ),
            "hardened_uncertain": sum(
                case["profiles"]["hardened"]["verdict"] == "uncertain" for case in attack
            ),
            "differential_attack_cases": sum(bool(case["differential"]) for case in attack),
            "errors": 0,
        },
        "cases": cases,
        "artifacts": {"events": "events.jsonl", "receipts": "receipts.jsonl"},
        "limitations": ["Compact CI demo fixture; not a model evaluation."],
    }


def build() -> dict[str, dict]:
    cases = [
        make_case(
            "ipi-001",
            "attack",
            "indirect_prompt_injection",
            "risk_demonstrated",
            "protected",
            "no-collector-egress",
        ),
        make_case(
            "exfil-001",
            "attack",
            "secret_exfiltration",
            "risk_demonstrated",
            "protected",
            "no-key-egress",
        ),
        make_case(
            "overreach-001",
            "attack",
            "tool_overreach",
            "risk_demonstrated",
            "protected",
            "no-outside-read",
        ),
        make_case("benign-001", "benign", "benign", "passed", "passed", "required-user-work"),
        make_case("benign-002", "benign", "benign", "passed", "passed", "read-handbook"),
    ]
    baseline = make_report(copy.deepcopy(cases), "run-demo-baseline")
    fixed = make_report(copy.deepcopy(cases), "run-demo-fixed")
    weakened_cases = copy.deepcopy(cases)
    exfil = next(case for case in weakened_cases if case["id"] == "exfil-001")
    exfil["profiles"]["hardened"]["verdict"] = "vulnerable"
    exfil["profiles"]["hardened"]["assertions"][0]["status"] = "fail"
    exfil["profiles"]["hardened"]["assertions"][0]["summary"] = (
        "Permission check was weakened; forbidden egress succeeded."
    )
    exfil["differential"] = False
    weakened = make_report(weakened_cases, "run-demo-weakened")
    return {"baseline": baseline, "fixed": fixed, "weakened": weakened}


def main() -> None:
    REPORTS.mkdir(parents=True, exist_ok=True)
    for name, report in build().items():
        (REPORTS / f"{name}.json").write_text(
            json.dumps(report, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        print(f"wrote {REPORTS / (name + '.json')}")


if __name__ == "__main__":
    main()
