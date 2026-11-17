"""Finding model, classification, policy validation, scoring and readiness rules."""

from __future__ import annotations

import datetime as dt
import json

import pytest

from agent_security_auditor.core.classify import classify_host, host_matches, infer_operations, scope_info
from agent_security_auditor.core.readiness import decide
from agent_security_auditor.core.schema import load_schema, validate
from agent_security_auditor.core.scoring import compute_score
from agent_security_auditor.models.assessment import Readiness
from agent_security_auditor.models.finding import (
    Confidence,
    ControlResult,
    ControlStatus,
    Evidence,
    EvidenceType,
    Finding,
    FindingStatus,
    Severity,
    stable_finding_id,
)
from agent_security_auditor.policies import BUILTIN_PROFILES, PolicyError, load_policy
from agent_security_auditor.rules import make_finding
from conftest import EXAMPLES, ROOT


def _f(rule="PERM-001", sev=Severity.HIGH, status=FindingStatus.CONFIRMED, conf=Confidence.HIGH, asset="tool:x"):
    return make_finding(rule, asset, [Evidence(EvidenceType.CODE, "a.py", 3)], status, conf, severity=sev)


def _c(cid, status):
    return ControlResult(cid, cid, "M05", status, "test")


# --- model ------------------------------------------------------------------------------------

def test_finding_id_is_stable_and_line_independent():
    a = make_finding("EXF-001", "destination:h", [Evidence(EvidenceType.CODE, "a.py", 10)], FindingStatus.CONFIRMED, Confidence.HIGH)
    b = make_finding("EXF-001", "destination:h", [Evidence(EvidenceType.CODE, "a.py", 99)], FindingStatus.CONFIRMED, Confidence.HIGH)
    assert a.finding_id == b.finding_id == stable_finding_id("EXF-001", "destination:h", "a.py")
    assert a.finding_id != _f(asset="destination:other").finding_id


def test_low_confidence_is_never_confirmed():
    f = make_finding("MCP-006", "file:x", [], FindingStatus.CONFIRMED, Confidence.LOW)
    assert f.status == FindingStatus.POTENTIAL


def test_finding_roundtrip_and_schema():
    f = _f()
    f.display_id, f.first_seen, f.assessment_id = "SEC-001", "2026-11-17T00:00:00Z", "A"
    d = f.to_dict()
    assert Finding.from_dict(json.loads(json.dumps(d))).to_dict() == d
    assert validate(d, load_schema("finding")) == []
    d["severity"] = "SEVERE"
    assert validate(d, load_schema("finding"))


# --- classification ---------------------------------------------------------------------------

def test_operation_inference():
    assert "delete" in infer_operations("delete_record")
    assert "send" in infer_operations("sendEmail")
    assert infer_operations("budget_summary") == []
    assert "read" in infer_operations("search_documents")


def test_scope_catalog():
    full = scope_info("https://www.googleapis.com/auth/drive")
    assert full.broad and "delete" in full.operations
    assert not scope_info("https://www.googleapis.com/auth/gmail.readonly").broad
    assert scope_info("db_owner").admin and scope_info("*").admin
    assert scope_info("crm.customers:read-own-tenant") is None


def test_host_classification_and_allowlist():
    assert classify_host("http://127.0.0.1:8080/x")[1] == "loopback"
    assert classify_host("https://webhook.site/abc")[1] == "exfil_service"
    assert classify_host("https://api.openai.com/v1")[1] == "model_provider"
    assert classify_host("https://collector.lab.invalid/x")[1] == "reserved"
    assert classify_host("http://169.254.169.254/latest")[1] == "metadata_service"
    assert host_matches("a.googleapis.com", ["*.googleapis.com"])
    assert not host_matches("googleapis.com.evil.invalid", ["*.googleapis.com"])


# --- policy -----------------------------------------------------------------------------------

@pytest.mark.parametrize("name", BUILTIN_PROFILES)
def test_builtin_profiles_valid_and_mirrored_in_examples(name):
    p = load_policy(name)
    assert p.mandatory_controls
    builtin = (ROOT / "src" / "agent_security_auditor" / "policies" / "profiles" / f"{name}.yaml").read_text()
    assert (EXAMPLES / "policies" / f"{name}.yaml").read_text() == builtin


def test_invalid_policy_is_rejected_with_errors():
    with pytest.raises(PolicyError) as exc:
        load_policy(str(EXAMPLES / "policies" / "invalid-policy.yaml"))
    joined = " ".join(exc.value.errors)
    assert "policy_version" in joined and "SEVERE" in joined and "expires" in joined


def test_bundled_schemas_match_assets():
    for name in ("finding", "assessment", "policy", "agent-manifest"):
        a = (ROOT / "assets" / "schemas" / f"{name}.schema.json").read_text()
        b = (ROOT / "src" / "agent_security_auditor" / "schemas" / f"{name}.schema.json").read_text()
        assert a == b, name


# --- readiness ----------------------------------------------------------------------------------

def _decide(findings, controls, policy="basic-agent", components=True, today=dt.date(2026, 11, 17)):
    p = load_policy(policy)
    return decide(findings, controls, p, components, "t", "static", today), p


def test_confirmed_critical_blocks_regardless_of_everything_else():
    controls = [_c(c, ControlStatus.PASSED) for c in load_policy("basic-agent").mandatory_controls]
    d, _ = _decide([_f(sev=Severity.CRITICAL)], controls)
    assert d.verdict == Readiness.NOT_READY


def test_unverified_mandatory_control_is_not_approved():
    p = load_policy("basic-agent")
    controls = [_c(c, ControlStatus.PASSED) for c in p.mandatory_controls]
    controls[0].status = ControlStatus.NOT_VERIFIED
    d, _ = _decide([], controls)
    assert d.verdict == Readiness.INSUFFICIENT_EVIDENCE and controls[0].control_id in d.unverified_mandatory_controls


def test_not_applicable_is_distinct_from_not_verified():
    p = load_policy("basic-agent")
    controls = [_c(c, ControlStatus.NOT_APPLICABLE) for c in p.mandatory_controls]
    d, _ = _decide([], controls)
    assert d.verdict == Readiness.READY


def test_missing_mandatory_control_counts_as_unverified():
    d, _ = _decide([], [])
    assert d.verdict == Readiness.INSUFFICIENT_EVIDENCE


def test_no_components_is_insufficient_evidence():
    d, _ = _decide([], [_c(c, ControlStatus.PASSED) for c in load_policy("basic-agent").mandatory_controls], components=False)
    assert d.verdict == Readiness.INSUFFICIENT_EVIDENCE


def test_accepted_risk_gives_ready_with_risks_and_expired_does_not(tmp_path):
    med = _f(rule="SUP-002", sev=Severity.MEDIUM, asset="dependencies")
    pol = tmp_path / "p.yaml"
    base = (EXAMPLES / "policies" / "basic-agent.yaml").read_text()
    pol.write_text(base + "exceptions:\n  - rule_id: SUP-002\n    owner: team-a\n    approved_by: lead-b\n"
                          "    justification: tracked in a synthetic ticket\n    expires: '2027-01-01'\n")
    controls = [_c(c, ControlStatus.PASSED) for c in load_policy("basic-agent").mandatory_controls]
    p = load_policy(str(pol))
    d = decide([med], controls, p, True, "t", "static", dt.date(2026, 11, 17))
    assert d.verdict == Readiness.READY_WITH_RISKS and med.accepted_risk["owner"] == "team-a"
    med2 = _f(rule="SUP-002", sev=Severity.MEDIUM, asset="dependencies")
    d2 = decide([med2], controls, p, True, "t", "static", dt.date(2027, 6, 1))
    assert d2.verdict == Readiness.NOT_READY and d2.expired_exceptions


def test_potential_high_blocks_only_where_policy_says_so():
    pot = _f(sev=Severity.HIGH, status=FindingStatus.POTENTIAL)
    assert not load_policy("basic-agent").is_blocking(pot)
    assert load_policy("enterprise-agent").is_blocking(pot)


# --- scoring ------------------------------------------------------------------------------------

def test_score_critical_cap_and_coverage():
    controls = [_c("CTRL-A-1", ControlStatus.PASSED), _c("CTRL-A-2", ControlStatus.NOT_VERIFIED),
                _c("CTRL-A-3", ControlStatus.NOT_APPLICABLE)]
    s = compute_score([_f(sev=Severity.CRITICAL, rule="AUTO-003")], controls)
    assert s["score"] <= 30 and s["critical_cap_applied"] and s["coverage_percent"] == 50.0
    clean = compute_score([], controls)
    assert clean["score"] == 100 and clean["grade"] == "A"
