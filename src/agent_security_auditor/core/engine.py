"""Audit engine: discovery -> parsing -> adapters -> analyzers -> evidence -> scoring -> policy -> readiness."""

from __future__ import annotations

import datetime as _dt
import hashlib
import traceback
from dataclasses import asdict
from pathlib import Path
from typing import Any

from agent_security_auditor import DISCLAIMER, SCHEMA_VERSION, __version__
from agent_security_auditor.adapters import default_adapters
from agent_security_auditor.analyzers import default_analyzers, plugin_analyzers
from agent_security_auditor.core.context import AuditContext
from agent_security_auditor.core.discovery import DiscoveryLimits, discover
from agent_security_auditor.core.readiness import decide
from agent_security_auditor.core.scoring import compute_score
from agent_security_auditor.models.assessment import Assessment, Mode, Readiness
from agent_security_auditor.models.finding import ControlStatus, Finding, FindingStatus
from agent_security_auditor.policies import Policy, load_policy
from agent_security_auditor.rules.catalog import MODULES
from agent_security_auditor.rules.dimensions import DIMENSION_SPECS, RELEVANCE

STATUS_ORDER = {FindingStatus.CONFIRMED: 0, FindingStatus.POTENTIAL: 1, FindingStatus.OBSERVATION: 2, FindingStatus.NOT_VERIFIED: 3}
THREAT_MODEL_MODULES = ("M01", "M11")
BASE_LIMITATIONS = [
    "Static analysis reads files only; it never imports, installs or executes the audited agent.",
    "Absence of findings is not evidence of security; see Controls Not Verified and coverage.",
    "Framework detection is partial (see docs/limitations.md); undeclared dynamic constructs may be missed.",
]


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def run_audit(target: str, mode: Mode = Mode.STATIC, policy: Policy | None = None, *,
              exclude: list[str] | None = None, limits: DiscoveryLimits | None = None,
              options: dict[str, Any] | None = None, assessment_id: str | None = None,
              baseline: Assessment | None = None, plugins: bool = False,
              today: _dt.date | None = None) -> Assessment:
    policy = policy or load_policy(None)
    options = dict(options or {})
    started = _now()
    root = Path(target)
    target_name = options.get("target_name") or root.resolve().name
    aid = assessment_id or "ASSESS-" + started.replace("-", "").replace(":", "")[:15] + "-" + hashlib.sha256(
        (str(root.resolve()) + started).encode()).hexdigest()[:6].upper()
    discovery = discover(target, limits, exclude)
    ctx = AuditContext(discovery=discovery, mode=mode, policy=policy, options=options)
    errors: list[dict[str, Any]] = []

    for adapter in default_adapters():
        try:
            if adapter.applies(ctx):
                adapter.populate(ctx)
                ctx.inventory.adapters_used.append(adapter.name)
        except Exception as exc:  # an adapter bug must surface, never be silently ignored
            errors.append({"component": f"adapter:{adapter.name}", "error": f"{type(exc).__name__}: {exc}",
                           "trace": traceback.format_exc(limit=2)[-400:]})

    analyzers = default_analyzers() + (plugin_analyzers() if plugins else [])
    findings: list[Finding] = []
    controls = []
    limitations = list(BASE_LIMITATIONS)
    module_runs: dict[str, dict[str, Any]] = {}
    for an in analyzers:
        if mode == Mode.THREAT_MODEL and an.module_id not in THREAT_MODEL_MODULES:
            module_runs[an.module_id] = {"ran": False, "reason": "not part of THREAT MODEL mode"}
            continue
        try:
            r = an.analyze(ctx)
        except Exception as exc:
            errors.append({"component": f"analyzer:{an.module_id}", "error": f"{type(exc).__name__}: {exc}",
                           "trace": traceback.format_exc(limit=3)[-600:]})
            module_runs[an.module_id] = {"ran": False, "reason": f"error: {type(exc).__name__}"}
            continue
        ctx.artifacts.update(r.artifacts)
        findings.extend(r.findings)
        controls.extend(r.controls)
        limitations.extend(r.limitations)
        module_runs[an.module_id] = {"ran": True, "findings": len(r.findings), "controls": len(r.controls),
                                     "implementation": an.implementation, "limitations": r.limitations}

    findings = _dedupe(findings)
    findings.sort(key=lambda f: (-f.severity.rank, STATUS_ORDER[f.status], f.module, f.rule_id, f.asset))
    prev_seen = {f.finding_id: f.first_seen for f in baseline.findings} if baseline else {}
    for i, f in enumerate(findings, 1):
        f.display_id = f"SEC-{i:03d}"
        f.assessment_id = aid
        f.first_seen = prev_seen.get(f.finding_id) or started

    inv = ctx.inventory
    has_components = bool(inv.agents or inv.tools or inv.mcp_servers)
    decision = decide(findings, controls, policy, has_components, target_name, mode.value, today)
    if errors and decision.verdict in (Readiness.READY, Readiness.READY_WITH_RISKS):
        decision.verdict = Readiness.INSUFFICIENT_EVIDENCE
        decision.reasons.insert(0, f"{len(errors)} scanner error(s): an incomplete audit cannot be approved")
    if mode == Mode.THREAT_MODEL:
        decision.verdict = Readiness.INSUFFICIENT_EVIDENCE
        decision.reasons.insert(0, "THREAT MODEL mode does not evaluate controls; no readiness verdict is issued")
    score = compute_score(findings, controls, policy.scoring_weights)

    module_status = []
    for mid, name in MODULES.items():
        run = module_runs.get(mid, {})
        if mid == "M12":
            module_status.append({"module": mid, "name": name, "implementation": "implemented", "ran": True,
                                  "findings": 0, "controls": 0, "note": "report generation (Markdown, JSON, SARIF, HTML, console)"})
            continue
        module_status.append({"module": mid, "name": name, "implementation": run.get("implementation", "implemented"),
                              "ran": run.get("ran", False), "findings": run.get("findings", 0),
                              "controls": run.get("controls", 0), "note": run.get("reason", "")})

    ctrl_by_id = {c.control_id: c for c in controls}
    dims = []
    for spec in DIMENSION_SPECS:
        level, why = RELEVANCE[spec["name"]](inv)
        dfind = [f for f in findings if f.category == spec["name"]]
        cstat = {cid: ctrl_by_id[cid].status.value for cid in spec["controls"] if cid in ctrl_by_id}
        dims.append({**{k: spec[k] for k in ("name", "modules", "risks", "assets", "methods", "tests", "evidence",
                                             "limitations", "recommendation")},
                     "expected_controls": spec["controls"], "control_status": cstat, "relevance": level,
                     "relevance_reason": why, "findings": len(dfind),
                     "open_high_or_critical": sum(1 for f in dfind if f.severity.rank >= 3 and f.is_open)})

    scope = {
        "root": str(discovery.root.name),
        "files_scanned": len(discovery.files),
        "files_skipped": len(discovery.skipped),
        "skipped_samples": [asdict(s) for s in discovery.skipped[:25]],
        "discovery_truncated": discovery.truncated,
        "parse_errors": ctx.parse_errors[:50],
        "adapters": [{"name": a.name, "used": a.name in inv.adapters_used, "coverage": a.coverage} for a in default_adapters()],
        "frameworks_detected": inv.frameworks,
        "manifest": inv.manifest_file,
        "network_access": "none (offline analysis)",
        "executed_target_code": mode == Mode.DYNAMIC,
        "dynamic_isolation": options.get("isolation_report"),
        "vulnerability_database": "offline OSV directory" if options.get("vuln_db") else "NOT_ASSESSED",
        "host_capabilities_declared": ["static file analysis", "offline", "no credentials"] +
                                      (["controlled dynamic sandbox"] if mode == Mode.DYNAMIC else []),
    }
    if ctx.parse_errors:
        limitations.append(f"{len(ctx.parse_errors)} file(s) could not be parsed and were analysed as text only or skipped.")
    if discovery.truncated:
        limitations.append("Discovery limits were reached; part of the tree was not analysed.")

    inv_dict = inv.to_dict()
    return Assessment(
        assessment_id=aid, schema_version=SCHEMA_VERSION, tool_version=__version__, target=str(target),
        target_name=target_name, mode=mode, started_at=started, finished_at=_now(), policy=policy.describe(),
        scope=scope, inventory=inv_dict, findings=findings, controls=controls,
        permission_matrix=ctx.artifacts.get("permission_matrix", []), data_flows=ctx.artifacts.get("data_flows", []),
        delegation_graph=ctx.artifacts.get("delegation_graph", {}),
        threat_model={**ctx.artifacts.get("threat_model", {}), "dataflow_mermaid": ctx.artifacts.get("dataflow_mermaid", ""),
                      "egress_inventory": ctx.artifacts.get("egress_inventory", [])},
        test_plan=ctx.artifacts.get("test_plan", []), test_results=ctx.artifacts.get("test_results", []),
        module_status=module_status, dimension_coverage=dims, score=score, readiness=decision,
        errors=errors, limitations=list(dict.fromkeys(limitations)), disclaimer=DISCLAIMER,
    )


def _dedupe(findings: list[Finding]) -> list[Finding]:
    by_id: dict[str, Finding] = {}
    for f in findings:
        if f.finding_id in by_id:
            keep = by_id[f.finding_id]
            if f.severity.rank > keep.severity.rank:
                keep.severity = f.severity
            for ev in f.evidence:
                if len(keep.evidence) < 5 and ev not in keep.evidence:
                    keep.evidence.append(ev)
        else:
            by_id[f.finding_id] = f
    return list(by_id.values())


def controls_not_verified(a: Assessment) -> list:
    return [c for c in a.controls if c.status in (ControlStatus.NOT_VERIFIED, ControlStatus.INSUFFICIENT_EVIDENCE)]
