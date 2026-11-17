"""End-to-end static audits of the vulnerable lab and the secure reference agent."""

from __future__ import annotations

import json
import re

import pytest

from agent_security_auditor.core.schema import load_schema, validate
from agent_security_auditor.models.assessment import Readiness
from agent_security_auditor.reporters import render_html, render_json, render_markdown, render_sarif
from conftest import EXAMPLES, LAB, SECURE, audit, by_rule, control, rules

LAB_REQUIRED = {"PERM-001", "EXF-001", "PI-001"}
#: rules that fire on the lab because of its intentional flaws and MUST NOT fire on the fixed agent
LAB_ONLY = {"PERM-001", "EXF-001", "PI-001", "PI-003", "PI-004", "MCP-005", "MCP-001", "MCP-008", "AUTO-001",
            "AUTO-002", "AUTO-006", "ARCH-001", "DATA-002", "DATA-003", "DATA-005", "MEM-001", "MEM-003", "MEM-004"}


# --- vulnerable lab -------------------------------------------------------------------------

def test_lab_mandatory_vulnerabilities_are_detected(lab_assessment):
    a = lab_assessment
    assert LAB_REQUIRED <= rules(a)
    perm = by_rule(a, "PERM-001")[0]
    assert perm.status.value == "CONFIRMED" and perm.severity.value == "HIGH"
    assert perm.asset == "tool:drive_search" and "https://www.googleapis.com/auth/drive" in perm.affected_permissions
    assert perm.source_file == "src/agent.py" and perm.evidence[0].snippet and "DRIVE_SCOPES" in perm.evidence[0].snippet
    exf = by_rule(a, "EXF-001")[0]
    assert exf.status.value == "CONFIRMED" and exf.asset == "destination:metrics-collector.lab.invalid"
    pi = [f for f in by_rule(a, "PI-001") if f.asset == "tool:gmail_read_inbox"][0]
    assert pi.status.value == "POTENTIAL" and pi.severity.value == "MEDIUM"  # exposure, not demonstrated exploitation


def test_lab_additional_scenarios(lab_assessment):
    assert {"MCP-005", "MEM-001", "MEM-004", "AUTO-001", "ARCH-001", "PI-003", "PI-004"} <= rules(lab_assessment)


def test_lab_readiness_not_ready_and_reasoned(lab_assessment):
    r = lab_assessment.readiness
    assert r.verdict == Readiness.NOT_READY
    assert r.blocking_findings and r.failed_mandatory_controls
    assert lab_assessment.score["score"] < 50


def test_every_finding_is_auditable(lab_assessment):
    for f in lab_assessment.findings:
        assert f.evidence, f.rule_id
        assert f.remediation and f.verification_steps and f.attack_preconditions
        assert f.display_id.startswith("SEC-") and f.finding_id.startswith("ASA-")
        if f.status.value == "CONFIRMED":
            assert f.confidence.value != "LOW"


def test_reports_are_valid(lab_assessment):
    data = json.loads(render_json(lab_assessment))
    assert validate(data, load_schema("assessment")) == []
    jsonschema = pytest.importorskip("jsonschema")
    jsonschema.validate(data, load_schema("assessment"))
    for f in data["findings"]:
        jsonschema.validate(f, load_schema("finding"))
    md = render_markdown(lab_assessment)
    for n in range(1, 20):
        assert re.search(rf"^## {n}\. ", md, re.M), f"section {n} missing"
    sarif = render_sarif(lab_assessment)
    assert sarif["version"] == "2.1.0" and len(sarif["runs"][0]["results"]) == len(lab_assessment.findings)
    html = render_html(lab_assessment)
    assert not re.search(r"""(src|href)\s*=\s*["']?https?:""", html), "HTML must not load remote resources"
    assert "<script" not in html


def test_audits_are_repeatable(lab_assessment):
    again = audit(LAB)
    assert [f.finding_id for f in again.findings] == [f.finding_id for f in lab_assessment.findings]
    assert [f.to_dict()["evidence"] for f in again.findings] == [f.to_dict()["evidence"] for f in lab_assessment.findings]


# --- secure reference agent -------------------------------------------------------------------

def test_secure_agent_has_no_lab_false_positives(secure_assessment):
    hits = rules(secure_assessment) & LAB_ONLY
    assert not hits, f"secure reference agent should not trigger: {hits}"


def test_secure_agent_ready_under_basic_policy(secure_assessment):
    a = secure_assessment
    assert a.readiness.verdict == Readiness.READY, a.readiness.reasons
    assert control(a, "CTRL-AUTO-01").status.value == "PASSED"
    assert "code" in control(a, "CTRL-AUTO-01").rationale  # approval corroborated in code, not just declared
    assert control(a, "CTRL-PI-B1").status.value == "NOT_VERIFIED"  # behavioral: honest in static mode


def test_secure_agent_ready_with_risks_with_accepted_exception():
    a = audit(SECURE, str(EXAMPLES / "policies" / "enterprise-secure-agent.yaml"))
    assert a.readiness.verdict == Readiness.READY_WITH_RISKS
    assert a.readiness.accepted_risks and a.readiness.accepted_risks[0]["owner"].startswith("platform-team")


def test_high_risk_profile_refuses_static_only_approval():
    a = audit(SECURE, "high-risk-autonomous-agent")
    assert a.readiness.verdict != Readiness.READY
    assert "CTRL-ADV-01" in a.readiness.unverified_mandatory_controls or a.readiness.verdict == Readiness.NOT_READY


def test_threat_model_mode_never_issues_ready():
    from agent_security_auditor.models.assessment import Mode
    a = audit(SECURE, mode=Mode.THREAT_MODEL)
    assert a.readiness.verdict == Readiness.INSUFFICIENT_EVIDENCE
    assert a.threat_model["threats"] and not [c for c in a.controls if c.module == "M05"]


# --- other examples ---------------------------------------------------------------------------

def test_mcp_example_rules():
    a = audit(EXAMPLES / "mcp-security", "mcp-integrated-agent")
    expected = {"MCP-001", "MCP-002", "MCP-003", "MCP-004", "MCP-005", "MCP-006", "MCP-007", "MCP-009", "MCP-010"}
    assert expected <= rules(a)
    # HTTP auth rules must never be applied to STDIO servers
    assert all(not f.asset.startswith(("mcp:notes", "mcp:proxy", "mcp:pinned-python")) for f in by_rule(a, "MCP-003"))
    assert not [f for f in by_rule(a, "MCP-001") if f.asset == "mcp:pinned-python"]


def test_multi_agent_example_rules():
    a = audit(EXAMPLES / "multi-agent")
    assert {"MA-001", "MA-002", "MA-003", "MA-004", "AUTO-001"} <= rules(a)
    assert any(f.severity.value == "CRITICAL" for f in by_rule(a, "AUTO-001"))
    assert a.delegation_graph["cycles"]


def test_empty_target_is_insufficient_evidence(tmp_path):
    (tmp_path / "README.md").write_text("# nothing here\n")
    a = audit(tmp_path)
    assert a.readiness.verdict == Readiness.INSUFFICIENT_EVIDENCE and "ARCH-002" in rules(a)
