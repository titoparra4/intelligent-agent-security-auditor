"""Analyzer protocol and helpers shared by the 12 modules.

To add a detector without touching the core, implement :class:`Analyzer` and register it via
the ``agent_security_auditor.analyzers`` entry-point group (loaded only with ``--plugins``).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Protocol, runtime_checkable

from agent_security_auditor.core.context import AuditContext
from agent_security_auditor.core.redaction import line_snippet
from agent_security_auditor.models.finding import (
    ControlResult,
    ControlStatus,
    Evidence,
    EvidenceType,
    Finding,
    FindingStatus,
)


@dataclass
class AnalyzerResult:
    findings: list[Finding] = field(default_factory=list)
    controls: list[ControlResult] = field(default_factory=list)
    artifacts: dict[str, Any] = field(default_factory=dict)
    limitations: list[str] = field(default_factory=list)


@runtime_checkable
class Analyzer(Protocol):
    module_id: str
    name: str
    #: "implemented" | "partial" - declared honestly in the report's module status table
    implementation: str

    def analyze(self, ctx: AuditContext) -> AnalyzerResult: ...


def evidence_at(ctx: AuditContext, rel: str | None, line: int | None, etype: EvidenceType,
                note: str | None = None, context: int = 0) -> Evidence:
    snippet = None
    if rel:
        sf = ctx.discovery.get(rel)
        if sf is not None and line:
            snippet = line_snippet(sf.lines(), line, context)
    return Evidence(type=etype, file=rel, line=line, snippet=snippet, note=note)


def control(cid: str, title: str, module: str, status: ControlStatus, rationale: str,
            evidence: list[Evidence] | None = None, related: Iterable[Finding] = (), owasp: list[str] | None = None,
            kind: str = "design") -> ControlResult:
    return ControlResult(cid, title, module, status, rationale, list(evidence or []),
                         [f.finding_id for f in related], list(owasp or []), kind)


def related(findings: list[Finding], *rule_ids: str) -> list[Finding]:
    return [f for f in findings if f.rule_id in rule_ids]


def status_from(findings: list[Finding], potential_fails: bool = True) -> ControlStatus | None:
    """CONFIRMED -> FAILED; POTENTIAL -> FAILED or NOT_VERIFIED; otherwise None (caller decides)."""
    if any(f.status == FindingStatus.CONFIRMED for f in findings):
        return ControlStatus.FAILED
    if any(f.status == FindingStatus.POTENTIAL for f in findings):
        return ControlStatus.FAILED if potential_fails else ControlStatus.NOT_VERIFIED
    return None


def declared_ok(ctx: AuditContext, provenance: str | None) -> bool:
    """Whether a positive fact with this provenance counts as evidence under the active policy."""
    if provenance in ("code", "configured", "verified"):
        return True
    if provenance == "declared":
        return bool(getattr(ctx.policy, "accept_declared_evidence", True))
    return False
