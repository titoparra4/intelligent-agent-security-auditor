"""Agent Security Readiness decision engine.

Rules (evaluated in this order, first match wins):

1. **NOT_READY** - any open blocking finding (policy ``blocking`` severities for CONFIRMED,
   ``potential_severities`` for POTENTIAL), any mandatory control FAILED, or any open
   CONFIRMED/POTENTIAL finding at or above ``require_acceptance_at`` that has no valid,
   unexpired, owner-approved exception.
2. **INSUFFICIENT_EVIDENCE** - no agent component could be analysed, or a mandatory control is
   NOT_VERIFIED / INSUFFICIENT_EVIDENCE (a control without evidence is never "passed").
3. **READY_WITH_RISKS** - residual risks exist and every one is explicitly accepted (owner,
   justification, approver, expiry).
4. **READY** - none of the above.

A favorable score never compensates a blocking finding. NOT_APPLICABLE mandatory controls are
not counted as missing (they are distinct from NOT_VERIFIED). The verdict applies only to the
evaluated scope.
"""

from __future__ import annotations

import datetime as _dt

from agent_security_auditor.models.assessment import Readiness, ReadinessDecision
from agent_security_auditor.models.finding import ControlResult, ControlStatus, Finding


def apply_exceptions(findings: list[Finding], policy, today: _dt.date) -> tuple[list[dict], list[dict]]:
    accepted, expired = [], []
    for exc in policy.exceptions:
        hits = [f for f in findings if exc.matches(f)]
        if exc.expired(today):
            expired.append({**exc.to_dict(), "matched_findings": [f.finding_id for f in hits]})
            continue
        for f in hits:
            f.accepted_risk = exc.to_dict()
            accepted.append({"finding_id": f.finding_id, "rule_id": f.rule_id, **exc.to_dict()})
    return accepted, expired


def decide(findings: list[Finding], controls: list[ControlResult], policy, has_components: bool,
           target: str, mode: str, today: _dt.date | None = None) -> ReadinessDecision:
    today = today or _dt.date.today()
    accepted, expired = apply_exceptions(findings, policy, today)
    mandatory = set(policy.mandatory_controls)
    for c in controls:
        c.mandatory = c.control_id in mandatory
    present = {c.control_id for c in controls}
    missing_mandatory = sorted(mandatory - present)

    reasons: list[str] = []
    blocking = [f for f in findings if f.is_open and policy.is_blocking(f)]
    unaccepted = [f for f in findings if f.is_open and policy.needs_acceptance(f) and f not in blocking]
    by_id = {f.finding_id: f for f in findings}

    def failed_only_by_accepted(c: ControlResult) -> bool:
        rel = [by_id[i] for i in c.related_findings if i in by_id]
        return bool(rel) and all(not f.is_open for f in rel)

    failed_m = [c.control_id for c in controls
                if c.mandatory and c.status == ControlStatus.FAILED and not failed_only_by_accepted(c)]
    accepted_controls = [c.control_id for c in controls
                         if c.mandatory and c.status == ControlStatus.FAILED and failed_only_by_accepted(c)]
    unverified_m = [c.control_id for c in controls if c.mandatory and c.status in (ControlStatus.NOT_VERIFIED, ControlStatus.INSUFFICIENT_EVIDENCE)]
    unverified_m += missing_mandatory
    scope = (f"Verdict applies only to the evaluated scope: target '{target}', mode '{mode}', policy "
             f"'{policy.name}' v{policy.policy_version}. It is not a certification.")

    if blocking or failed_m or unaccepted:
        if blocking:
            reasons.append(f"{len(blocking)} open blocking finding(s): " + ", ".join(
                f"{f.display_id or f.finding_id} {f.rule_id} {f.severity.value}/{f.status.value}" for f in blocking[:8]))
        if failed_m:
            reasons.append(f"mandatory control(s) failed: {', '.join(failed_m)}")
        if unaccepted:
            reasons.append(f"{len(unaccepted)} residual risk(s) at or above {policy.require_acceptance_at.value} "
                           "without an approved exception")
        verdict = Readiness.NOT_READY
    elif not has_components:
        reasons.append("no agent components could be analysed")
        verdict = Readiness.INSUFFICIENT_EVIDENCE
    elif unverified_m:
        reasons.append(f"mandatory control(s) without sufficient evidence: {', '.join(unverified_m)}")
        verdict = Readiness.INSUFFICIENT_EVIDENCE
    elif accepted:
        reasons.append(f"{len(accepted)} residual risk(s) explicitly accepted with expiry"
                       + (f" (mandatory control(s) failing only on accepted risks: {', '.join(accepted_controls)})"
                          if accepted_controls else ""))
        verdict = Readiness.READY_WITH_RISKS
    else:
        reasons.append("all mandatory controls verified; no open blocking or unaccepted residual risks")
        verdict = Readiness.READY
    if expired:
        reasons.append(f"{len(expired)} expired exception(s) ignored")
    return ReadinessDecision(
        verdict=verdict, reasons=reasons,
        blocking_findings=[f.finding_id for f in blocking] + [f.finding_id for f in unaccepted],
        unverified_mandatory_controls=unverified_m, failed_mandatory_controls=failed_m,
        accepted_risks=accepted, expired_exceptions=expired, scope_statement=scope)
