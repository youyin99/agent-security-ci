from __future__ import annotations

import html
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import __version__
from .config import GateConfig
from .errors import GateInputError

VERDICTS = {
    "protected",
    "passed",
    "risk_demonstrated",
    "vulnerable",
    "failed",
    "uncertain",
    "skipped",
    "error",
}
KINDS = {"attack", "benign"}
ACCEPTABLE = {"attack": "protected", "benign": "passed"}


@dataclass(frozen=True)
class CaseView:
    id: str
    kind: str
    category: str
    baseline_verdict: str
    hardened_verdict: str
    error_count: int
    status: str | None


@dataclass(frozen=True)
class ReportView:
    schema_version: str
    report_type: str
    cases: dict[str, CaseView]


def load_report(path: Path | str | None, *, label: str) -> ReportView | None:
    if path is None:
        return None
    source = Path(path)
    if not source.exists():
        return None
    try:
        raw = json.loads(source.read_text(encoding="utf-8"))
    except OSError as exc:
        raise GateInputError(f"{label} report cannot be read: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise GateInputError(f"{label} report is not valid JSON: {exc}") from exc
    return parse_report(raw, source=str(source), label=label)


def parse_report(raw: dict[str, Any], *, source: str = "<report>", label: str = "agentprobe") -> ReportView:
    if not isinstance(raw, dict):
        raise GateInputError(f"{label} report must be an object")
    if raw.get("schema_version") != "1.0":
        raise GateInputError(f"{label} report schema_version must be '1.0'")
    if raw.get("report_type") != "agentprobe":
        raise GateInputError(f"{label} report_type must be 'agentprobe'")
    cases_raw = raw.get("cases")
    if not isinstance(cases_raw, list):
        raise GateInputError(f"{label} report cases must be a list")
    cases: dict[str, CaseView] = {}
    for index, item in enumerate(cases_raw):
        if not isinstance(item, dict):
            raise GateInputError(f"{label} case[{index}] must be an object")
        case_id = item.get("id")
        if not isinstance(case_id, str) or not case_id:
            raise GateInputError(f"{label} case[{index}] has no id")
        if case_id in cases:
            raise GateInputError(f"{label} report has duplicate case id '{case_id}'")
        kind = item.get("kind")
        if kind not in KINDS:
            raise GateInputError(f"{label} case '{case_id}' has invalid kind")
        category = item.get("category")
        if not isinstance(category, str) or not category:
            raise GateInputError(f"{label} case '{case_id}' has no category")
        profiles = item.get("profiles")
        if not isinstance(profiles, dict):
            raise GateInputError(f"{label} case '{case_id}' has no profiles object")
        hardened = profiles.get("hardened")
        baseline_profile = profiles.get("baseline")
        if not isinstance(hardened, dict) or not isinstance(baseline_profile, dict):
            raise GateInputError(f"{label} case '{case_id}' requires baseline and hardened profiles")
        hardened_verdict = hardened.get("verdict")
        baseline_verdict = baseline_profile.get("verdict")
        if hardened_verdict not in VERDICTS or baseline_verdict not in VERDICTS:
            raise GateInputError(f"{label} case '{case_id}' has an unknown verdict")
        error_count = hardened.get("error_count", 0)
        if not isinstance(error_count, int) or isinstance(error_count, bool) or error_count < 0:
            raise GateInputError(f"{label} case '{case_id}' has invalid error_count")
        case_status = item.get("status")
        if case_status is not None and not isinstance(case_status, str):
            raise GateInputError(f"{label} case '{case_id}' has invalid status")
        cases[case_id] = CaseView(
            id=case_id,
            kind=kind,
            category=category,
            baseline_verdict=baseline_verdict,
            hardened_verdict=hardened_verdict,
            error_count=error_count,
            status=case_status,
        )
    return ReportView(
        schema_version="1.0",
        report_type="agentprobe",
        cases=cases,
    )


def evaluate_gate(
    *,
    baseline: ReportView | None,
    current: ReportView,
    config: GateConfig,
    baseline_label: str | None = None,
    current_label: str | None = None,
) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    failed_cases: set[str] = set()
    failed_reasons: dict[str, list[str]] = {}

    def add_check(
        check_id: str,
        ok: bool,
        detail: str,
        *,
        case_id: str | None = None,
    ) -> None:
        checks.append(
            {
                "id": check_id,
                "status": "pass" if ok else "fail",
                "detail": detail,
            }
        )
        if not ok and case_id:
            failed_cases.add(case_id)
            failed_reasons.setdefault(case_id, []).append(detail)

    baseline_present = baseline is not None
    if baseline_present:
        add_check("baseline_present", True, "baseline report was loaded")
    elif config.allow_missing_baseline:
        add_check("baseline_present", True, "baseline missing and explicitly allowed")
    else:
        add_check("baseline_present", False, "baseline report is missing")

    excluded_from_rates: set[str] = set()
    for case_id in sorted(current.cases):
        case = current.cases[case_id]
        if case.status == "skipped" or case.hardened_verdict == "skipped":
            add_check(
                f"case:{case_id}:skipped",
                not config.fail_on_skipped,
                "case was skipped" if config.fail_on_skipped else "skipped case allowed by config",
                case_id=case_id,
            )
            if not config.fail_on_skipped:
                excluded_from_rates.add(case_id)
            continue
        if case.error_count > 0 or case.hardened_verdict == "error":
            add_check(
                f"case:{case_id}:execution",
                not config.fail_on_execution_error,
                f"execution error(s): {case.error_count}",
                case_id=case_id,
            )
            if config.fail_on_execution_error:
                continue
            excluded_from_rates.add(case_id)
            continue
        if case.hardened_verdict == "uncertain":
            add_check(
                f"case:{case_id}:uncertain",
                not config.fail_on_uncertain,
                "insufficient evidence produced an uncertain result",
                case_id=case_id,
            )
            if config.fail_on_uncertain:
                continue
            excluded_from_rates.add(case_id)
            continue
        expected = ACCEPTABLE[case.kind]
        ok = case.hardened_verdict == expected
        add_check(
            f"case:{case_id}",
            ok,
            f"{case.kind} case hardened verdict is '{case.hardened_verdict}', expected '{expected}'",
            case_id=case_id,
        )

    for case_id in config.required_case_ids:
        if case_id not in current.cases:
            add_check(
                f"required_case:{case_id}",
                False,
                "required case is missing from the current report",
                case_id=case_id,
            )
            continue
        case = current.cases[case_id]
        expected = ACCEPTABLE[case.kind]
        add_check(
            f"required_case:{case_id}",
            case.hardened_verdict == expected,
            f"required case hardened verdict is '{case.hardened_verdict}', expected '{expected}'",
            case_id=case_id,
        )

    attack_cases = [case for case in current.cases.values() if case.kind == "attack"]
    benign_cases = [case for case in current.cases.values() if case.kind == "benign"]
    rate_attack_cases = [case for case in attack_cases if case.id not in excluded_from_rates]
    rate_benign_cases = [case for case in benign_cases if case.id not in excluded_from_rates]
    protected = [case for case in rate_attack_cases if case.hardened_verdict == "protected"]
    passed_benign = [case for case in rate_benign_cases if case.hardened_verdict == "passed"]
    attack_rate = len(protected) / len(rate_attack_cases) if rate_attack_cases else 0.0
    benign_rate = len(passed_benign) / len(rate_benign_cases) if rate_benign_cases else 1.0
    add_check(
        "hardened_protection_rate",
        attack_rate >= config.min_hardened_protected_rate,
        f"{len(protected)}/{len(rate_attack_cases)} rate-eligible attack cases protected "
        f"(rate {attack_rate:.3f}, required {config.min_hardened_protected_rate:.3f})",
    )
    add_check(
        "benign_pass_rate",
        benign_rate >= config.min_benign_passed_rate,
        f"{len(passed_benign)}/{len(rate_benign_cases)} rate-eligible benign cases passed "
        f"(rate {benign_rate:.3f}, required {config.min_benign_passed_rate:.3f})",
    )

    for category, minimum in sorted(config.required_categories.items()):
        count = sum(
            1
            for case in attack_cases
            if case.category == category and case.hardened_verdict != "skipped"
        )
        add_check(
            f"category:{category}",
            count >= minimum,
            f"category has {count} non-skipped attack cases; required {minimum}",
        )

    regressions: list[dict[str, str]] = []
    if baseline is not None:
        for case_id, baseline_case in sorted(baseline.cases.items()):
            if baseline_case.hardened_verdict != ACCEPTABLE[baseline_case.kind]:
                continue
            current_case = current.cases.get(case_id)
            if current_case is None:
                regressions.append(
                    {"case_id": case_id, "detail": "case missing from current report"}
                )
                failed_cases.add(case_id)
                failed_reasons.setdefault(case_id, []).append("case missing from current report")
                continue
            if (
                current_case.kind != baseline_case.kind
                or current_case.category != baseline_case.category
            ):
                detail = (
                    "case kind/category changed from "
                    f"'{baseline_case.kind}/{baseline_case.category}' to "
                    f"'{current_case.kind}/{current_case.category}'"
                )
                regressions.append({"case_id": case_id, "detail": detail})
                failed_cases.add(case_id)
                failed_reasons.setdefault(case_id, []).append(detail)
                continue
            if case_id in excluded_from_rates:
                continue
            if current_case.hardened_verdict != ACCEPTABLE[current_case.kind]:
                detail = (
                    f"regressed from '{baseline_case.hardened_verdict}' to "
                    f"'{current_case.hardened_verdict}'"
                )
                regressions.append({"case_id": case_id, "detail": detail})
                failed_cases.add(case_id)
                failed_reasons.setdefault(case_id, []).append(detail)
        add_check(
            "baseline_regressions",
            len(regressions) <= config.max_allowed_regressions,
            f"{len(regressions)} regression(s); allowed {config.max_allowed_regressions}",
        )

    passed = all(check["status"] == "pass" for check in checks)
    result = {
        "schema_version": "1.0",
        "report_type": "agent_security_ci_gate",
        "tool_version": __version__,
        "passed": passed,
        "exit_code": 0 if passed else 1,
        "baseline": baseline_label,
        "current": current_label,
        "config": {
            "required_categories": dict(config.required_categories),
            "required_case_ids": list(config.required_case_ids),
            "min_hardened_protected_rate": config.min_hardened_protected_rate,
            "min_benign_passed_rate": config.min_benign_passed_rate,
            "fail_on_uncertain": config.fail_on_uncertain,
            "fail_on_skipped": config.fail_on_skipped,
            "fail_on_execution_error": config.fail_on_execution_error,
            "allow_missing_baseline": config.allow_missing_baseline,
            "max_allowed_regressions": config.max_allowed_regressions,
        },
        "summary": {
            "attack_cases": len(attack_cases),
            "protected_attack_cases": len(protected),
            "attack_protection_rate": attack_rate,
            "benign_cases": len(benign_cases),
            "passed_benign_cases": len(passed_benign),
            "benign_pass_rate": benign_rate,
            "regressions": len(regressions),
            "failed_cases": len(failed_cases),
        },
        "failed_cases": sorted(failed_cases),
        "failed_case_details": {
            case_id: failed_reasons[case_id] for case_id in sorted(failed_reasons)
        },
        "regressions": regressions,
        "checks": checks,
    }
    return result


def write_gate_outputs(output_dir: Path | str, result: dict[str, Any], stem: str = "gate-report") -> tuple[Path, Path]:
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    json_path = output / f"{stem}.json"
    html_path = output / f"{stem}.html"
    json_path.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    html_path.write_text(render_html(result), encoding="utf-8")
    return json_path, html_path


def render_html(result: dict[str, Any]) -> str:
    check_rows = []
    for check in result["checks"]:
        cls = "pass" if check["status"] == "pass" else "fail"
        check_rows.append(
            "<tr>"
            f"<td><code>{html.escape(check['id'])}</code></td>"
            f"<td><span class='badge {cls}'>{html.escape(check['status'])}</span></td>"
            f"<td>{html.escape(check['detail'])}</td>"
            "</tr>"
        )
    failed_items = "".join(
        f"<li><code>{html.escape(case_id)}</code>: "
        f"{html.escape('; '.join(result['failed_case_details'].get(case_id, [])))}</li>"
        for case_id in result["failed_cases"]
    ) or "<li>None</li>"
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Agent Security Gate</title>
<style>
:root {{ color-scheme:light; --bg:#f5f2ec; --panel:#fffdf8; --ink:#1f2523; --muted:#68706d; --line:#dad5ca; --accent:#173b56; --pass:#1f673d; --pass-bg:#e2f1e7; --fail:#982f2f; --fail-bg:#f8e2df; }}
* {{ box-sizing:border-box; }}
body {{ margin:0; background:var(--bg); color:var(--ink); font:15px/1.55 "Segoe UI",system-ui,sans-serif; }}
header {{ background:var(--accent); color:#fff; padding:34px max(20px,6vw) 28px; }}
header .eyebrow {{ opacity:.72; font-size:12px; letter-spacing:.12em; text-transform:uppercase; }}
h1 {{ margin:6px 0; font-size:clamp(28px,4vw,44px); }}
main {{ max-width:1100px; margin:0 auto; padding:24px; }}
section {{ background:var(--panel); border:1px solid var(--line); border-radius:12px; padding:20px; margin:16px 0; }}
.banner {{ border-left:6px solid; padding:14px 16px; border-radius:8px; font-weight:600; }}
.banner.pass {{ background:var(--pass-bg); color:var(--pass); border-color:var(--pass); }}
.banner.fail {{ background:var(--fail-bg); color:var(--fail); border-color:var(--fail); }}
table {{ width:100%; border-collapse:collapse; display:block; overflow-x:auto; }}
th,td {{ text-align:left; padding:8px 10px; border-bottom:1px solid var(--line); vertical-align:top; }}
th {{ color:var(--muted); font-size:11px; text-transform:uppercase; letter-spacing:.05em; }}
code {{ background:#eee9de; padding:1px 4px; border-radius:4px; font-size:.9em; }}
.badge {{ display:inline-block; padding:2px 8px; border-radius:999px; font-size:11px; font-weight:700; }}
.pass {{ color:var(--pass); background:var(--pass-bg); }}
.fail {{ color:var(--fail); background:var(--fail-bg); }}
.muted {{ color:var(--muted); }}
footer {{ color:var(--muted); font-size:12px; margin:18px 0 36px; }}
@media (max-width:620px) {{ main {{ padding:16px; }} header {{ padding:26px 18px; }} }}
</style>
</head>
<body>
<header>
  <div class="eyebrow">Offline release gate</div>
  <h1>Agent Security Gate</h1>
  <p>Current report is compared with the approved baseline. The gate never re-judges an attack; it enforces coverage, regressions, and evidence quality.</p>
</header>
<main>
  <div class="banner {'pass' if result['passed'] else 'fail'}">
    {'PASS' if result['passed'] else 'FAIL'} · exit code {result['exit_code']} · {result['summary']['failed_cases']} failed case(s)
  </div>
  <section>
    <h2>Summary</h2>
    <p>Attack protection: {result['summary']['protected_attack_cases']} / {result['summary']['attack_cases']}
    · Benign pass: {result['summary']['passed_benign_cases']} / {result['summary']['benign_cases']}
    · Regressions: {result['summary']['regressions']}</p>
    <h3>Failed cases</h3>
    <ul>{failed_items}</ul>
  </section>
  <section>
    <h2>Checks</h2>
    <table>
      <thead><tr><th>Check</th><th>Status</th><th>Detail</th></tr></thead>
      <tbody>{''.join(check_rows)}</tbody>
    </table>
  </section>
  <footer>agent-security-ci {html.escape(result['tool_version'])} · baseline: {html.escape(str(result.get('baseline')))} · current: {html.escape(str(result.get('current')))}</footer>
</main>
</body>
</html>
"""
