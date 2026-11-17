"""Normalized finding and control model shared by every analyzer.

Severity, confidence and status are deliberately independent axes:

* ``severity``   - how bad it is if the issue is real and exploited.
* ``confidence`` - how sure the detector is that the evidence means what it says.
* ``status``     - what kind of claim this is (confirmed vs potential vs observation).

A heuristic detection must never be emitted as ``CONFIRMED``.
"""

from __future__ import annotations

import enum
import hashlib
from dataclasses import dataclass, field
from typing import Any


class Severity(str, enum.Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        return _SEV_RANK[self.value]

    @classmethod
    def parse(cls, value: str) -> "Severity":
        return cls(str(value).upper())


_SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


class Confidence(str, enum.Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

    @property
    def factor(self) -> float:
        return {"HIGH": 1.0, "MEDIUM": 0.75, "LOW": 0.5}[self.value]


class FindingStatus(str, enum.Enum):
    CONFIRMED = "CONFIRMED"
    POTENTIAL = "POTENTIAL"
    OBSERVATION = "OBSERVATION"
    NOT_VERIFIED = "NOT_VERIFIED"


class Likelihood(str, enum.Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


class EvidenceType(str, enum.Enum):
    CODE = "code"
    CONFIGURATION = "configuration"
    DECLARATION = "declaration"
    DEPENDENCY_METADATA = "dependency_metadata"
    CONTENT = "content"
    ABSENCE = "absence"
    INFERENCE = "inference"
    POLICY = "policy"
    DYNAMIC_TRACE = "dynamic_trace"


class ControlStatus(str, enum.Enum):
    PASSED = "PASSED"
    FAILED = "FAILED"
    NOT_VERIFIED = "NOT_VERIFIED"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    NOT_APPLICABLE = "NOT_APPLICABLE"


@dataclass
class Evidence:
    type: EvidenceType
    file: str | None = None
    line: int | None = None
    snippet: str | None = None  # MUST already be redacted by the producer
    note: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.type.value,
            "file": self.file,
            "line": self.line,
            "snippet": self.snippet,
            "note": self.note,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Evidence":
        return cls(
            type=EvidenceType(d["type"]),
            file=d.get("file"),
            line=d.get("line"),
            snippet=d.get("snippet"),
            note=d.get("note"),
        )


@dataclass
class Finding:
    rule_id: str
    title: str
    description: str
    module: str
    category: str
    severity: Severity
    confidence: Confidence
    status: FindingStatus
    asset: str
    evidence: list[Evidence]
    attack_preconditions: list[str]
    impact: str
    likelihood: Likelihood
    remediation: str
    verification_steps: list[str]
    owasp_references: list[str] = field(default_factory=list)
    nist_references: list[str] = field(default_factory=list)
    other_references: list[str] = field(default_factory=list)
    affected_permissions: list[str] = field(default_factory=list)
    trust_boundary: str | None = None
    #: extra discriminator so two different issues of the same rule on the same asset get distinct ids
    discriminator: str = ""
    finding_id: str = ""
    display_id: str = ""
    first_seen: str = ""
    assessment_id: str = ""
    requires_specialized_review: bool = False
    accepted_risk: dict[str, Any] | None = None

    def __post_init__(self) -> None:
        if not self.finding_id:
            self.finding_id = stable_finding_id(self.rule_id, self.asset, self.source_file, self.discriminator)

    @property
    def source_file(self) -> str | None:
        for ev in self.evidence:
            if ev.file:
                return ev.file
        return None

    @property
    def source_line(self) -> int | None:
        for ev in self.evidence:
            if ev.file:
                return ev.line
        return None

    @property
    def evidence_type(self) -> str:
        return self.evidence[0].type.value if self.evidence else EvidenceType.ABSENCE.value

    @property
    def is_open(self) -> bool:
        return self.accepted_risk is None

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "display_id": self.display_id,
            "rule_id": self.rule_id,
            "title": self.title,
            "description": self.description,
            "module": self.module,
            "category": self.category,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "status": self.status.value,
            "asset": self.asset,
            "source_file": self.source_file,
            "source_line": self.source_line,
            "evidence": [e.to_dict() for e in self.evidence],
            "evidence_type": self.evidence_type,
            "attack_preconditions": list(self.attack_preconditions),
            "impact": self.impact,
            "likelihood": self.likelihood.value,
            "affected_permissions": list(self.affected_permissions),
            "trust_boundary": self.trust_boundary,
            "owasp_references": list(self.owasp_references),
            "nist_references": list(self.nist_references),
            "other_references": list(self.other_references),
            "remediation": self.remediation,
            "verification_steps": list(self.verification_steps),
            "requires_specialized_review": self.requires_specialized_review,
            "accepted_risk": self.accepted_risk,
            "first_seen": self.first_seen,
            "assessment_id": self.assessment_id,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Finding":
        return cls(
            rule_id=d["rule_id"],
            title=d["title"],
            description=d["description"],
            module=d["module"],
            category=d["category"],
            severity=Severity(d["severity"]),
            confidence=Confidence(d["confidence"]),
            status=FindingStatus(d["status"]),
            asset=d["asset"],
            evidence=[Evidence.from_dict(e) for e in d.get("evidence", [])],
            attack_preconditions=list(d.get("attack_preconditions", [])),
            impact=d.get("impact", ""),
            likelihood=Likelihood(d.get("likelihood", "UNKNOWN")),
            remediation=d.get("remediation", ""),
            verification_steps=list(d.get("verification_steps", [])),
            owasp_references=list(d.get("owasp_references", [])),
            nist_references=list(d.get("nist_references", [])),
            other_references=list(d.get("other_references", [])),
            affected_permissions=list(d.get("affected_permissions", [])),
            trust_boundary=d.get("trust_boundary"),
            finding_id=d["finding_id"],
            display_id=d.get("display_id", ""),
            first_seen=d.get("first_seen", ""),
            assessment_id=d.get("assessment_id", ""),
            requires_specialized_review=bool(d.get("requires_specialized_review", False)),
            accepted_risk=d.get("accepted_risk"),
        )


def stable_finding_id(rule_id: str, asset: str, source_file: str | None, discriminator: str = "") -> str:
    """Deterministic id: the same issue in the same place keeps its id across audits.

    Line numbers are intentionally excluded so that unrelated edits that shift lines do not
    turn an existing finding into a "new" one in ``compare``.
    """
    raw = "|".join([rule_id, asset.strip().lower(), (source_file or "").replace("\\", "/"), discriminator])
    return "ASA-" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12].upper()


@dataclass
class ControlResult:
    control_id: str
    title: str
    module: str
    status: ControlStatus
    rationale: str
    evidence: list[Evidence] = field(default_factory=list)
    related_findings: list[str] = field(default_factory=list)
    owasp_references: list[str] = field(default_factory=list)
    #: "design" controls are statically verifiable; "behavioral" ones need controlled dynamic tests
    kind: str = "design"
    mandatory: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "control_id": self.control_id,
            "title": self.title,
            "module": self.module,
            "kind": self.kind,
            "status": self.status.value,
            "mandatory": self.mandatory,
            "rationale": self.rationale,
            "evidence": [e.to_dict() for e in self.evidence],
            "related_findings": list(self.related_findings),
            "owasp_references": list(self.owasp_references),
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "ControlResult":
        return cls(
            control_id=d["control_id"],
            title=d["title"],
            module=d["module"],
            status=ControlStatus(d["status"]),
            rationale=d.get("rationale", ""),
            evidence=[Evidence.from_dict(e) for e in d.get("evidence", [])],
            related_findings=list(d.get("related_findings", [])),
            owasp_references=list(d.get("owasp_references", [])),
            kind=d.get("kind", "design"),
            mandatory=bool(d.get("mandatory", False)),
        )
