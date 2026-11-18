"""Baseline comparison for CI/CD SECURITY GATE mode (MODE D).

Detects new permissions, tools, MCP servers, network destinations, data-access surfaces,
dependencies, introduced/resolved findings and controls that stopped being verified.
Finding identity relies on stable ``finding_id`` values (rule + asset + file + discriminator).
"""

from __future__ import annotations

from typing import Any

from agent_security_auditor.models.assessment import Assessment
from agent_security_auditor.models.finding import ControlStatus

REGRESSING = {ControlStatus.PASSED.value}


def _set(inv: dict[str, Any], key: str, fn) -> set:
    return {fn(x) for x in inv.get(key, []) or []}


def compare(prev: Assessment, curr: Assessment) -> dict[str, Any]:
    pi, ci = prev.inventory, curr.inventory
    prev_tools = {t["name"]: t for t in pi.get("tools", [])}
    curr_tools = {t["name"]: t for t in ci.get("tools", [])}
    new_permissions = []
    for name, t in curr_tools.items():
        before = set(prev_tools.get(name, {}).get("permissions", []))
        added = sorted(set(t.get("permissions", [])) - before)
        if added and name in prev_tools:
            new_permissions.append({"tool": name, "added": added})
        new_ops = sorted(set(t.get("operations", [])) - set(prev_tools.get(name, {}).get("operations", [])))
        if new_ops and name in prev_tools:
            new_permissions.append({"tool": name, "added_operations": new_ops})
    new_data = []
    for name, t in curr_tools.items():
        added = sorted(set(t.get("data_access", [])) - set(prev_tools.get(name, {}).get("data_access", [])))
        if added:
            new_data.append({"tool": name, "added": added})

    pf = {f.finding_id: f for f in prev.findings}
    cf = {f.finding_id: f for f in curr.findings}
    introduced = [cf[k] for k in cf if k not in pf]
    resolved = [pf[k] for k in pf if k not in cf]
    pc = {c.control_id: c.status.value for c in prev.controls}
    cc = {c.control_id: c.status.value for c in curr.controls}
    regressed_controls = [{"control_id": k, "before": pc[k], "after": v} for k, v in cc.items()
                          if pc.get(k) in REGRESSING and v != ControlStatus.PASSED.value and v != ControlStatus.NOT_APPLICABLE.value]
    regressed_controls += [{"control_id": k, "before": pc[k], "after": "MISSING"} for k in pc if k not in cc and pc[k] in REGRESSING]

    def dep(d: dict[str, Any]) -> str:
        return f"{d.get('ecosystem')}:{d.get('name')}"

    return {
        "baseline": prev.assessment_id,
        "current": curr.assessment_id,
        "readiness": {"before": prev.readiness.verdict.value if prev.readiness else None,
                      "after": curr.readiness.verdict.value if curr.readiness else None},
        "score": {"before": prev.score.get("score"), "after": curr.score.get("score"),
                  "coverage_before": prev.score.get("coverage_percent"), "coverage_after": curr.score.get("coverage_percent")},
        "new_tools": sorted(set(curr_tools) - set(prev_tools)),
        "removed_tools": sorted(set(prev_tools) - set(curr_tools)),
        "new_permissions": new_permissions,
        "new_mcp_servers": sorted(_set(ci, "mcp_servers", lambda s: s["name"]) - _set(pi, "mcp_servers", lambda s: s["name"])),
        "new_network_destinations": sorted(_set(ci, "network", lambda d: d["host"]) - _set(pi, "network", lambda d: d["host"])),
        "new_data_access": new_data,
        "new_dependencies": sorted(_set(ci, "dependencies", dep) - _set(pi, "dependencies", dep)),
        "new_agents": sorted(_set(ci, "agents", lambda a: a["name"]) - _set(pi, "agents", lambda a: a["name"])),
        "introduced_findings": [{"finding_id": f.finding_id, "rule_id": f.rule_id, "severity": f.severity.value,
                                 "status": f.status.value, "title": f.title, "asset": f.asset} for f in introduced],
        "resolved_findings": [{"finding_id": f.finding_id, "rule_id": f.rule_id, "severity": f.severity.value,
                               "title": f.title, "asset": f.asset} for f in resolved],
        "controls_no_longer_verified": regressed_controls,
        "_introduced_objs": introduced,
    }


def has_regression(diff: dict[str, Any], fail_on: str = "high") -> bool:
    """Gate decision. ``fail_on``: any | low | medium | high | critical | never."""
    if fail_on == "never":
        return False
    threshold = {"any": -1, "info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}[fail_on]
    if any(f.severity.rank >= threshold for f in diff["_introduced_objs"]) and diff["_introduced_objs"]:
        return True
    if diff["controls_no_longer_verified"]:
        return True
    if fail_on == "any" and (diff["new_tools"] or diff["new_permissions"] or diff["new_mcp_servers"]
                             or diff["new_network_destinations"] or diff["new_data_access"] or diff["new_dependencies"]):
        return True
    before, after = diff["readiness"]["before"], diff["readiness"]["after"]
    rank = {"READY": 0, "READY_WITH_RISKS": 1, "INSUFFICIENT_EVIDENCE": 2, "NOT_READY": 3, None: 0}
    return rank[after] > rank[before]


def public(diff: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in diff.items() if not k.startswith("_")}

