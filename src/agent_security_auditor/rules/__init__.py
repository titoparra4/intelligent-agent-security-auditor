"""Detection rules: catalog + finding factory."""

from __future__ import annotations

from agent_security_auditor.models.finding import (
    Confidence,
    Evidence,
    Finding,
    FindingStatus,
    Likelihood,
    Severity,
)
from agent_security_auditor.rules.catalog import DIMENSIONS, MODULES, RULES, Rule, rule


def make_finding(
    rule_id: str,
    asset: str,
    evidence: list[Evidence],
    status: FindingStatus,
    confidence: Confidence,
    *,
    severity: Severity | None = None,
    detail: str = "",
    preconditions: list[str] | None = None,
    impact: str | None = None,
    likelihood: Likelihood | None = None,
    affected_permissions: list[str] | None = None,
    trust_boundary: str | None = None,
    discriminator: str = "",
    title: str | None = None,
) -> Finding:
    r = RULES[rule_id]
    if status == FindingStatus.CONFIRMED and confidence == Confidence.LOW:
        # a low-confidence signal can never be presented as confirmed
        status = FindingStatus.POTENTIAL
    if likelihood is None:
        likelihood = {
            FindingStatus.CONFIRMED: Likelihood.MEDIUM,
            FindingStatus.POTENTIAL: Likelihood.MEDIUM if confidence != Confidence.LOW else Likelihood.LOW,
            FindingStatus.OBSERVATION: Likelihood.LOW,
            FindingStatus.NOT_VERIFIED: Likelihood.UNKNOWN,
        }[status]
    description = r.description + (f" {detail}" if detail else "")
    return Finding(
        rule_id=rule_id,
        title=title or r.title,
        description=description,
        module=r.module,
        category=r.category,
        severity=severity or Severity(r.severity),
        confidence=confidence,
        status=status,
        asset=asset,
        evidence=evidence,
        attack_preconditions=list(preconditions or r.preconditions),
        impact=impact or r.impact,
        likelihood=likelihood,
        remediation=r.remediation,
        verification_steps=list(r.verification),
        owasp_references=list(r.owasp),
        nist_references=list(r.nist),
        other_references=list(r.other),
        affected_permissions=list(affected_permissions or []),
        trust_boundary=trust_boundary,
        discriminator=discriminator,
        requires_specialized_review=r.specialized_review,
    )


__all__ = ["DIMENSIONS", "MODULES", "RULES", "Rule", "rule", "make_finding"]
