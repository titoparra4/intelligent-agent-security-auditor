"""SARIF 2.1.0 output (for GitHub code scanning and other SARIF consumers).

Mapping: CRITICAL/HIGH -> error, MEDIUM -> warning, LOW/INFO -> note. ``security-severity``
uses the conventional numeric bands (9.0/7.5/5.0/2.0/0.0). Findings without a file location are
attached to the assessed root so they are not dropped.
"""

from __future__ import annotations

from typing import Any

from agent_security_auditor import __version__
from agent_security_auditor.models.assessment import Assessment
from agent_security_auditor.rules.catalog import RULES

LEVEL = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note", "INFO": "note"}
SEC_SEV = {"CRITICAL": "9.0", "HIGH": "7.5", "MEDIUM": "5.0", "LOW": "2.0", "INFO": "0.0"}


def _note(f) -> str:
    return (f.evidence[0].note or "") if f.evidence else ""


def render_sarif(a: Assessment) -> dict[str, Any]:
    used = sorted({f.rule_id for f in a.findings})
    rules = []
    for rid in used:
        r = RULES[rid]
        rules.append({
            "id": rid, "name": "".join(w.capitalize() for w in rid.replace("-", " ").split()),
            "shortDescription": {"text": r.title}, "fullDescription": {"text": r.description},
            "help": {"text": r.remediation, "markdown": f"**Remediation:** {r.remediation}"},
            "defaultConfiguration": {"level": LEVEL[r.severity]},
            "properties": {"tags": ["security", "ai-agent", r.module, r.category] + [o.split(" ")[0] for o in r.owasp],
                           "security-severity": SEC_SEV[r.severity]},
        })
    results = []
    for f in a.findings:
        loc_file = f.source_file or "."
        region = {"startLine": f.source_line} if f.source_line else None
        phys: dict[str, Any] = {"artifactLocation": {"uri": loc_file, "uriBaseId": "%SRCROOT%"}}
        if region:
            phys["region"] = region
        results.append({
            "ruleId": f.rule_id,
            "level": LEVEL[f.severity.value],
            "message": {"text": f"[{f.status.value}/{f.confidence.value}] {f.title} — {f.asset}. {_note(f)}".strip()},
            "locations": [{"physicalLocation": phys}],
            "partialFingerprints": {"agentSecurityFindingId/v1": f.finding_id},
            "properties": {"severity": f.severity.value, "status": f.status.value, "confidence": f.confidence.value,
                           "security-severity": SEC_SEV[f.severity.value], "owasp": f.owasp_references,
                           "displayId": f.display_id, "acceptedRisk": bool(f.accepted_risk)},
        } | ({"suppressions": [{"kind": "external", "justification": f.accepted_risk["justification"]}]} if f.accepted_risk else {}))
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "intelligent-agent-security-auditor", "version": __version__,
                                "informationUri": "https://github.com/titoparra4/intelligent-agent-security-auditor",
                                "rules": rules}},
            "automationDetails": {"id": f"agent-security/{a.assessment_id}"},
            "invocations": [{"executionSuccessful": not a.errors,
                             "toolExecutionNotifications": [{"level": "error", "message": {"text": e["error"]}} for e in a.errors]}],
            "results": results,
            "properties": {"readiness": a.readiness.verdict.value if a.readiness else None, "score": a.score.get("score"),
                           "coverage": a.score.get("coverage_percent")},
        }],
    }
