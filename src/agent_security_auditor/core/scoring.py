"""Security Score (0-100) and assessment coverage.

The score is an *indicator*, not a certification, and never overrides the readiness verdict.

Method (published in docs/architecture.md):

* start at 100;
* subtract, per open finding, ``weight[severity] x status_factor x confidence_factor``
  (CONFIRMED 1.0, POTENTIAL 0.5, OBSERVATION 0.1; confidence HIGH 1.0, MEDIUM 0.75, LOW 0.5);
* deductions per module are capped (``module_cap``) so one noisy module cannot dominate, but
  a confirmed CRITICAL caps the whole score at ``critical_cap`` (no compensation by other areas);
* accepted risks deduct at 50 %;
* the score is reported in bands of 5 to avoid false precision, together with *coverage*:
  the share of applicable controls that could be verified (PASSED or FAILED).
"""

from __future__ import annotations

from typing import Any

from agent_security_auditor.models.finding import ControlResult, ControlStatus, Finding, FindingStatus, Severity

DEFAULT_WEIGHTS = {"CRITICAL": 40.0, "HIGH": 15.0, "MEDIUM": 6.0, "LOW": 2.0, "INFO": 0.0,
                   "module_cap": 35.0, "critical_cap": 30.0}
STATUS_FACTOR = {FindingStatus.CONFIRMED: 1.0, FindingStatus.POTENTIAL: 0.5, FindingStatus.OBSERVATION: 0.1,
                 FindingStatus.NOT_VERIFIED: 0.0}


def compute_score(findings: list[Finding], controls: list[ControlResult], weights: dict[str, float] | None = None) -> dict[str, Any]:
    w = dict(DEFAULT_WEIGHTS)
    w.update(weights or {})
    per_module: dict[str, float] = {}
    for f in findings:
        d = w[f.severity.value] * STATUS_FACTOR[f.status] * f.confidence.factor
        if f.accepted_risk:
            d *= 0.5
        per_module[f.module] = per_module.get(f.module, 0.0) + d
    deductions = {m: round(min(v, w["module_cap"]), 2) for m, v in per_module.items()}
    raw = max(0.0, 100.0 - sum(deductions.values()))
    capped = False
    if any(f.severity == Severity.CRITICAL and f.status == FindingStatus.CONFIRMED and not f.accepted_risk for f in findings):
        if raw > w["critical_cap"]:
            raw = w["critical_cap"]
            capped = True
    band = int(raw // 5 * 5)
    applicable = [c for c in controls if c.status != ControlStatus.NOT_APPLICABLE]
    verified = [c for c in applicable if c.status in (ControlStatus.PASSED, ControlStatus.FAILED)]
    coverage = round(100.0 * len(verified) / len(applicable), 1) if applicable else 0.0
    grade = "A" if band >= 90 else "B" if band >= 75 else "C" if band >= 60 else "D" if band >= 40 else "E"
    return {
        "score": band,
        "score_band": f"{band}-{min(100, band + 4)}",
        "grade": grade,
        "coverage_percent": coverage,
        "controls_applicable": len(applicable),
        "controls_verified": len(verified),
        "deductions_by_module": deductions,
        "critical_cap_applied": capped,
        "weights": w,
        "note": "Indicator only. Not a certification; does not override the readiness verdict. "
                "Low coverage means the score describes only part of the agent.",
    }
