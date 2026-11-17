"""Assessment: the complete, serializable result of one audit run."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any

from agent_security_auditor.models.finding import ControlResult, Finding


class Readiness(str, enum.Enum):
    READY = "READY"
    READY_WITH_RISKS = "READY_WITH_RISKS"
    NOT_READY = "NOT_READY"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"


class Mode(str, enum.Enum):
    STATIC = "static"
    THREAT_MODEL = "threat-model"
    DYNAMIC = "dynamic"
    CI = "ci"


@dataclass
class ReadinessDecision:
    verdict: Readiness
    reasons: list[str]
    blocking_findings: list[str] = field(default_factory=list)
    unverified_mandatory_controls: list[str] = field(default_factory=list)
    failed_mandatory_controls: list[str] = field(default_factory=list)
    accepted_risks: list[dict[str, Any]] = field(default_factory=list)
    expired_exceptions: list[dict[str, Any]] = field(default_factory=list)
    scope_statement: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict.value,
            "reasons": self.reasons,
            "blocking_findings": self.blocking_findings,
            "failed_mandatory_controls": self.failed_mandatory_controls,
            "unverified_mandatory_controls": self.unverified_mandatory_controls,
            "accepted_risks": self.accepted_risks,
            "expired_exceptions": self.expired_exceptions,
            "scope_statement": self.scope_statement,
        }


@dataclass
class Assessment:
    assessment_id: str
    schema_version: str
    tool_version: str
    target: str
    target_name: str
    mode: Mode
    started_at: str
    finished_at: str = ""
    policy: dict[str, Any] = field(default_factory=dict)
    scope: dict[str, Any] = field(default_factory=dict)
    inventory: dict[str, Any] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    controls: list[ControlResult] = field(default_factory=list)
    permission_matrix: list[dict[str, Any]] = field(default_factory=list)
    data_flows: list[dict[str, Any]] = field(default_factory=list)
    delegation_graph: dict[str, Any] = field(default_factory=dict)
    threat_model: dict[str, Any] = field(default_factory=dict)
    test_plan: list[dict[str, Any]] = field(default_factory=list)
    test_results: list[dict[str, Any]] = field(default_factory=list)
    module_status: list[dict[str, Any]] = field(default_factory=list)
    dimension_coverage: list[dict[str, Any]] = field(default_factory=list)
    score: dict[str, Any] = field(default_factory=dict)
    readiness: ReadinessDecision | None = None
    errors: list[dict[str, Any]] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    disclaimer: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "assessment_id": self.assessment_id,
            "tool": {"name": "intelligent-agent-security-auditor", "version": self.tool_version},
            "target": self.target,
            "target_name": self.target_name,
            "mode": self.mode.value,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "policy": self.policy,
            "scope": self.scope,
            "readiness": self.readiness.to_dict() if self.readiness else None,
            "score": self.score,
            "summary": self.summary(),
            "findings": [f.to_dict() for f in self.findings],
            "controls": [c.to_dict() for c in self.controls],
            "inventory": self.inventory,
            "permission_matrix": self.permission_matrix,
            "data_flows": self.data_flows,
            "delegation_graph": self.delegation_graph,
            "threat_model": self.threat_model,
            "test_plan": self.test_plan,
            "test_results": self.test_results,
            "module_status": self.module_status,
            "dimension_coverage": self.dimension_coverage,
            "errors": self.errors,
            "limitations": self.limitations,
            "disclaimer": self.disclaimer,
        }

    def summary(self) -> dict[str, Any]:
        by_sev: dict[str, int] = {s: 0 for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")}
        by_status: dict[str, int] = {s: 0 for s in ("CONFIRMED", "POTENTIAL", "OBSERVATION", "NOT_VERIFIED")}
        for f in self.findings:
            by_sev[f.severity.value] += 1
            by_status[f.status.value] += 1
        ctrl: dict[str, int] = {}
        for c in self.controls:
            ctrl[c.status.value] = ctrl.get(c.status.value, 0) + 1
        return {
            "total_findings": len(self.findings),
            "by_severity": by_sev,
            "by_status": by_status,
            "controls": ctrl,
            "accepted_risks": sum(1 for f in self.findings if f.accepted_risk),
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Assessment":
        rd = d.get("readiness")
        readiness = None
        if rd:
            readiness = ReadinessDecision(
                verdict=Readiness(rd["verdict"]),
                reasons=list(rd.get("reasons", [])),
                blocking_findings=list(rd.get("blocking_findings", [])),
                unverified_mandatory_controls=list(rd.get("unverified_mandatory_controls", [])),
                failed_mandatory_controls=list(rd.get("failed_mandatory_controls", [])),
                accepted_risks=list(rd.get("accepted_risks", [])),
                expired_exceptions=list(rd.get("expired_exceptions", [])),
                scope_statement=rd.get("scope_statement", ""),
            )
        return cls(
            assessment_id=d["assessment_id"],
            schema_version=d["schema_version"],
            tool_version=d.get("tool", {}).get("version", ""),
            target=d["target"],
            target_name=d.get("target_name", d["target"]),
            mode=Mode(d["mode"]),
            started_at=d.get("started_at", ""),
            finished_at=d.get("finished_at", ""),
            policy=d.get("policy", {}),
            scope=d.get("scope", {}),
            inventory=d.get("inventory", {}),
            findings=[Finding.from_dict(f) for f in d.get("findings", [])],
            controls=[ControlResult.from_dict(c) for c in d.get("controls", [])],
            permission_matrix=d.get("permission_matrix", []),
            data_flows=d.get("data_flows", []),
            delegation_graph=d.get("delegation_graph", {}),
            threat_model=d.get("threat_model", {}),
            test_plan=d.get("test_plan", []),
            test_results=d.get("test_results", []),
            module_status=d.get("module_status", []),
            dimension_coverage=d.get("dimension_coverage", []),
            score=d.get("score", {}),
            readiness=readiness,
            errors=d.get("errors", []),
            limitations=d.get("limitations", []),
            disclaimer=d.get("disclaimer", ""),
        )
