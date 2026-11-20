from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from agent_security_ci.config import GateConfig
from agent_security_ci.gate import load_report

REPO_ROOT = Path(__file__).resolve().parents[1]
REPORTS = REPO_ROOT / "examples" / "reports"
CONFIG_PATH = REPO_ROOT / "examples" / "gate-policy.json"


@pytest.fixture()
def config() -> GateConfig:
    return GateConfig.load(CONFIG_PATH)


def _raw(name: str) -> dict:
    return json.loads((REPORTS / name).read_text(encoding="utf-8"))


@pytest.fixture()
def baseline_raw():
    return _raw("baseline.json")


@pytest.fixture()
def fixed_raw():
    return copy.deepcopy(_raw("fixed.json"))


@pytest.fixture()
def weakened_raw():
    return _raw("weakened.json")


@pytest.fixture()
def baseline_view():
    return load_report(REPORTS / "baseline.json", label="baseline")


@pytest.fixture()
def fixed_view():
    return load_report(REPORTS / "fixed.json", label="current")
