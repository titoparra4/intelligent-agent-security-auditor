"""Shared test helpers. The suite never needs network access or credentials."""

from __future__ import annotations

import datetime as dt
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / "skills/intelligent-agent-security-auditor"
sys.path.insert(0, str(SKILL / "src"))

from agent_security_auditor.core.engine import run_audit  # noqa: E402
from agent_security_auditor.models.assessment import Mode  # noqa: E402
from agent_security_auditor.policies import load_policy  # noqa: E402

EXAMPLES = ROOT / "examples"
FIXTURES = ROOT / "tests" / "fixtures"
LAB = EXAMPLES / "vulnerable-agent-lab"
SECURE = EXAMPLES / "secure-agent"
TODAY = dt.date(2026, 11, 17)


def audit(target, policy: str | None = None, mode: Mode = Mode.STATIC, **kw):
    return run_audit(str(target), mode, load_policy(policy), assessment_id=kw.pop("assessment_id", "ASSESS-TEST"),
                     today=kw.pop("today", TODAY), **kw)


def rules(assessment) -> set[str]:
    return {f.rule_id for f in assessment.findings}


def by_rule(assessment, rule_id: str):
    return [f for f in assessment.findings if f.rule_id == rule_id]


def control(assessment, cid: str):
    return next(c for c in assessment.controls if c.control_id == cid)


@pytest.fixture(scope="session")
def lab_assessment():
    return audit(LAB)


@pytest.fixture(scope="session")
def secure_assessment():
    return audit(SECURE)


def secret_value(kind: str = "openai") -> str:
    """Assemble a credential-shaped value at runtime so no secret-like literal exists in the repo."""
    body = "Q7xV2mN9pL4kR8sT1wY6zB3cD5fG0hJ"
    if kind == "openai":
        return "sk-" + "proj-" + body + "aB9"
    if kind == "aws":
        return "AK" + "IA" + "Z7Q2M4N6P8R0T3V5"
    if kind == "github":
        return "gh" + "p_" + body + "Xy12AB"
    raise ValueError(kind)
