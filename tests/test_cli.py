from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from tests.conftest import CONFIG_PATH, REPORTS, REPO_ROOT


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(REPO_ROOT)
    return subprocess.run(
        [sys.executable, "-m", "agent_security_ci", *args],
        cwd=REPO_ROOT,
        env=env,
        text=True,
        capture_output=True,
        timeout=60,
    )


def test_cli_fixed_passes(tmp_path):
    result = _run(
        "gate",
        "--baseline",
        str(REPORTS / "baseline.json"),
        "--current",
        str(REPORTS / "fixed.json"),
        "--config",
        str(CONFIG_PATH),
        "--out",
        str(tmp_path),
    )
    assert result.returncode == 0, result.stderr
    assert "PASS" in result.stdout
    report = json.loads((tmp_path / "gate-report.json").read_text(encoding="utf-8"))
    assert report["passed"] is True
    assert (tmp_path / "gate-report.html").is_file()


def test_cli_weakened_fails_with_annotations(tmp_path):
    result = _run(
        "gate",
        "--baseline",
        str(REPORTS / "baseline.json"),
        "--current",
        str(REPORTS / "weakened.json"),
        "--config",
        str(CONFIG_PATH),
        "--out",
        str(tmp_path),
        "--github-annotations",
    )
    assert result.returncode == 1
    assert "::error title=Agent security gate: exfil-001::" in result.stdout
    report = json.loads((tmp_path / "gate-report.json").read_text(encoding="utf-8"))
    assert report["passed"] is False


def test_cli_missing_baseline_fails(tmp_path):
    result = _run(
        "gate",
        "--baseline",
        str(tmp_path / "missing.json"),
        "--current",
        str(REPORTS / "fixed.json"),
        "--config",
        str(CONFIG_PATH),
        "--out",
        str(tmp_path / "out"),
    )
    assert result.returncode == 1
    report = json.loads((tmp_path / "out" / "gate-report.json").read_text(encoding="utf-8"))
    assert any(check["id"] == "baseline_present" for check in report["checks"])


def test_cli_invalid_current_returns_2(tmp_path):
    current = tmp_path / "bad.json"
    current.write_text("{not json", encoding="utf-8")
    result = _run(
        "gate",
        "--current",
        str(current),
        "--out",
        str(tmp_path / "out"),
    )
    assert result.returncode == 2
    assert "not valid JSON" in result.stderr


def test_cli_missing_current_returns_2(tmp_path):
    result = _run("gate", "--current", str(tmp_path / "missing.json"), "--out", str(tmp_path))
    assert result.returncode == 2
