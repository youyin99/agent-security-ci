from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Sequence

from .config import GateConfig
from .errors import GateInputError
from .gate import evaluate_gate, load_report, write_gate_outputs


def command_gate(args: argparse.Namespace) -> int:
    config = GateConfig.load(args.config)
    baseline_path = Path(args.baseline) if args.baseline else None
    current_path = Path(args.current)
    if not current_path.exists():
        raise GateInputError(f"current report does not exist: {args.current}")
    baseline = load_report(baseline_path, label="baseline")
    current = load_report(current_path, label="current")
    assert current is not None
    result = evaluate_gate(
        baseline=baseline,
        current=current,
        config=config,
        baseline_label=baseline_path.name if baseline_path else None,
        current_label=current_path.name,
    )
    json_path, _ = write_gate_outputs(args.out, result, stem=args.name)
    if args.github_annotations:
        for case_id in result["failed_cases"]:
            reasons = "; ".join(result["failed_case_details"].get(case_id, []))
            print(f"::error title=Agent security gate: {case_id}::{reasons}")
        for check in result["checks"]:
            if check["status"] == "fail" and not check["id"].startswith("case:"):
                print(f"::error title=Agent security gate::{check['id']}: {check['detail']}")
    status = "PASS" if result["passed"] else "FAIL"
    print(
        f"{status} gate={result['exit_code']} protected={result['summary']['protected_attack_cases']}/"
        f"{result['summary']['attack_cases']} failed_cases={len(result['failed_cases'])} "
        f"report={json_path}"
    )
    if result["failed_cases"]:
        print("failed cases: " + ", ".join(result["failed_cases"]))
    return result["exit_code"]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agent-security-ci",
        description="Compare AgentProbe reports and enforce release gates",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    gate = sub.add_parser("gate", help="evaluate the current report against a baseline")
    gate.add_argument("--baseline", default=None, help="baseline AgentProbe report")
    gate.add_argument("--current", required=True, help="current AgentProbe report")
    gate.add_argument("--config", default=None, help="gate policy JSON")
    gate.add_argument("--out", default="reports", help="output directory")
    gate.add_argument("--name", default="gate-report", help="output file stem")
    gate.add_argument("--github-annotations", action="store_true")
    gate.set_defaults(func=command_gate)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except (GateInputError, ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
