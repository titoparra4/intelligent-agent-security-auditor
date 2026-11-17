"""Declarative security policy: load, validate, evaluate exceptions.

Policies are YAML/JSON files versioned with the agent (see ``assets/schemas/policy.schema.json``
and ``examples/policies``). A policy is validated against its schema *before* any audit runs;
an invalid policy aborts the audit with exit code 78 instead of silently using defaults.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any

from agent_security_auditor.core.parsing import parse_json, parse_yaml
from agent_security_auditor.core.schema import load_schema, validate
from agent_security_auditor.models.finding import Finding, FindingStatus, Severity

BUILTIN_PROFILES = ("basic-agent", "enterprise-agent", "mcp-integrated-agent", "high-risk-autonomous-agent")
DEFAULT_PROFILE = "basic-agent"


class PolicyError(Exception):
    def __init__(self, message: str, errors: list[str] | None = None) -> None:
        super().__init__(message)
        self.errors = errors or []


@dataclass
class PolicyException:
    owner: str
    justification: str
    approved_by: str
    expires: _dt.date
    finding_id: str | None = None
    rule_id: str | None = None
    asset: str | None = None

    def matches(self, f: Finding) -> bool:
        if self.finding_id:
            return f.finding_id == self.finding_id
        if self.rule_id and f.rule_id != self.rule_id:
            return False
        if self.asset and f.asset != self.asset:
            return False
        return bool(self.rule_id)

    def expired(self, today: _dt.date) -> bool:
        return self.expires < today

    def to_dict(self) -> dict[str, Any]:
        return {"finding_id": self.finding_id, "rule_id": self.rule_id, "asset": self.asset, "owner": self.owner,
                "justification": self.justification, "approved_by": self.approved_by,
                "expires": self.expires.isoformat()}


@dataclass
class Policy:
    name: str
    policy_version: str
    description: str = ""
    authorized_tools: list[str] | None = None
    forbidden_tools: list[str] = field(default_factory=list)
    forbidden_operations: list[str] = field(default_factory=list)
    denied_scopes: list[str] = field(default_factory=list)
    allow_admin_permissions: bool = False
    allowed_network_destinations: list[str] = field(default_factory=list)
    restricted_data: list[str] = field(default_factory=list)
    approval_required_for: list[str] = field(default_factory=lambda: ["send", "delete", "financial", "infra", "execute"])
    require_per_user_memory: bool = True
    require_sandboxed_code_execution: bool = True
    require_max_iterations: bool = True
    trusted_mcp_servers: list[str] = field(default_factory=list)
    blocking_severities: list[Severity] = field(default_factory=lambda: [Severity.CRITICAL, Severity.HIGH])
    blocking_potential_severities: list[Severity] = field(default_factory=lambda: [Severity.CRITICAL])
    require_acceptance_at: Severity = Severity.MEDIUM
    accept_declared_evidence: bool = True
    mandatory_controls: list[str] = field(default_factory=list)
    exceptions: list[PolicyException] = field(default_factory=list)
    scoring_weights: dict[str, float] = field(default_factory=dict)
    source: str = "builtin"
    sha256: str = ""

    # -- helpers ----------------------------------------------------------------------------
    def is_blocking(self, f: Finding) -> bool:
        if f.status == FindingStatus.CONFIRMED:
            return f.severity in self.blocking_severities
        if f.status == FindingStatus.POTENTIAL:
            return f.severity in self.blocking_potential_severities
        return False

    def needs_acceptance(self, f: Finding) -> bool:
        if f.status not in (FindingStatus.CONFIRMED, FindingStatus.POTENTIAL):
            return False
        return f.severity.rank >= self.require_acceptance_at.rank

    def describe(self) -> dict[str, Any]:
        return {"name": self.name, "policy_version": self.policy_version, "source": self.source,
                "sha256": self.sha256, "mandatory_controls": list(self.mandatory_controls),
                "blocking_severities": [s.value for s in self.blocking_severities],
                "blocking_potential_severities": [s.value for s in self.blocking_potential_severities],
                "require_acceptance_at": self.require_acceptance_at.value,
                "accept_declared_evidence": self.accept_declared_evidence,
                "exceptions": len(self.exceptions)}


def _sev_list(v: Any) -> list[Severity]:
    return [Severity.parse(x) for x in (v or [])]


def policy_from_dict(d: dict[str, Any], source: str, raw: bytes) -> Policy:
    errors = validate(d, load_schema("policy"))
    if errors:
        raise PolicyError(f"policy {source} is invalid", errors)
    tools = d.get("tools", {}) or {}
    perms = d.get("permissions", {}) or {}
    net = d.get("network", {}) or {}
    data = d.get("data", {}) or {}
    appr = d.get("human_approval", {}) or {}
    iso = d.get("isolation", {}) or {}
    autonomy = d.get("autonomy", {}) or {}
    mcp = d.get("mcp", {}) or {}
    block = d.get("blocking", {}) or {}
    ev = d.get("evidence", {}) or {}
    exceptions = []
    for e in d.get("exceptions", []) or []:
        exceptions.append(PolicyException(
            owner=e["owner"], justification=e["justification"], approved_by=e["approved_by"],
            expires=_dt.date.fromisoformat(str(e["expires"])), finding_id=e.get("finding_id"),
            rule_id=e.get("rule_id"), asset=e.get("asset")))
    return Policy(
        name=d["name"],
        policy_version=str(d["policy_version"]),
        description=d.get("description", ""),
        authorized_tools=tools.get("authorized"),
        forbidden_tools=list(tools.get("forbidden", []) or []),
        forbidden_operations=list(d.get("forbidden_operations", []) or []),
        denied_scopes=list(perms.get("denied_scopes", []) or []),
        allow_admin_permissions=bool(perms.get("allow_admin", False)),
        allowed_network_destinations=list(net.get("allowed_destinations", []) or []),
        restricted_data=list(data.get("restricted", []) or []),
        approval_required_for=list(appr.get("required_for", ["send", "delete", "financial", "infra", "execute"])),
        require_per_user_memory=bool(iso.get("require_per_user_memory", True)),
        require_sandboxed_code_execution=bool(iso.get("require_sandboxed_code_execution", True)),
        require_max_iterations=bool(autonomy.get("require_max_iterations", True)),
        trusted_mcp_servers=list(mcp.get("trusted_servers", []) or []),
        blocking_severities=_sev_list(block.get("severities", ["CRITICAL", "HIGH"])),
        blocking_potential_severities=_sev_list(block.get("potential_severities", ["CRITICAL"])),
        require_acceptance_at=Severity.parse(block.get("require_acceptance_at", "MEDIUM")),
        accept_declared_evidence=bool(ev.get("accept_declared", True)),
        mandatory_controls=list(d.get("mandatory_controls", []) or []),
        exceptions=exceptions,
        scoring_weights=dict(d.get("scoring", {}).get("weights", {}) or {}) if isinstance(d.get("scoring"), dict) else {},
        source=source,
        sha256=hashlib.sha256(raw).hexdigest(),
    )


def load_policy(ref: str | None) -> Policy:
    """Load a builtin profile by name, or a policy file by path."""
    ref = ref or DEFAULT_PROFILE
    if ref in BUILTIN_PROFILES:
        raw = resources.files("agent_security_auditor").joinpath("policies", "profiles", f"{ref}.yaml").read_bytes()
        source = f"builtin:{ref}"
    else:
        p = Path(ref)
        if not p.is_file():
            raise PolicyError(f"policy not found: {ref} (builtin profiles: {', '.join(BUILTIN_PROFILES)})")
        if p.stat().st_size > 512 * 1024:
            raise PolicyError("policy file too large (> 512 KiB)")
        raw = p.read_bytes()
        source = str(p)
    text = raw.decode("utf-8", errors="replace")
    res = parse_json(text) if ref.endswith(".json") else parse_yaml(text)
    if not res.ok or not isinstance(res.value, dict):
        raise PolicyError(f"policy {source} could not be parsed: {res.error or 'not a mapping'}")
    return policy_from_dict(res.value, source, raw)


def validate_policy_file(path: str) -> list[str]:
    try:
        load_policy(path)
    except PolicyError as exc:
        return [str(exc)] + exc.errors
    return []


def policy_to_json(p: Policy) -> str:
    return json.dumps(p.describe(), indent=2)
