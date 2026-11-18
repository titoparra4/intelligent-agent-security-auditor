"""MODULE 10 - Multi-Agent Security: delegation graph, trust, privilege propagation."""

from __future__ import annotations

from typing import Any

from agent_security_auditor.analyzers.base import AnalyzerResult, control, evidence_at, related, status_from
from agent_security_auditor.core.context import AuditContext
from agent_security_auditor.models.finding import Confidence, ControlStatus, EvidenceType, FindingStatus, Severity
from agent_security_auditor.models.inventory import Inventory
from agent_security_auditor.rules import make_finding
from agent_security_auditor.rules.references import ASI

NETWORK_CHANNELS = ("http", "https", "grpc", "a2a", "queue", "websocket", "pubsub", "network")


def delegation_graph(inv: Inventory) -> dict[str, Any]:
    nodes = []
    for a in inv.agents:
        tools = [inv.tool(t) for t in a.tools]
        privileged = sorted({t.name for t in tools if t and (t.is_irreversible or t.is_destructive)})
        untrusted = a.exposed_to_untrusted_input or any(t and t.reads_untrusted for t in tools)
        nodes.append({"agent": a.name, "framework": a.framework, "identity": a.identity, "privileged_tools": privileged,
                      "exposed_to_untrusted_input": bool(untrusted), "max_iterations": a.max_iterations})
    edges = [{"from": d.from_agent, "to": d.to_agent, "channel": d.channel, "authenticated": d.authenticated,
              "inherit_permissions": d.inherit_permissions, "provenance": d.provenance} for d in inv.delegations]
    return {"nodes": nodes, "edges": edges, "cycles": find_cycles(inv)}


def find_cycles(inv: Inventory) -> list[list[str]]:
    adj: dict[str, list[str]] = {}
    for d in inv.delegations:
        adj.setdefault(d.from_agent, []).append(d.to_agent)
    cycles: list[list[str]] = []
    seen_keys: set[tuple[str, ...]] = set()

    def dfs(node: str, path: list[str]) -> None:
        for nxt in adj.get(node, []):
            if nxt in path:
                cyc = path[path.index(nxt):]
                key = tuple(sorted(cyc))
                if key not in seen_keys:
                    seen_keys.add(key)
                    cycles.append(cyc + [nxt])
            elif len(path) < 20:
                dfs(nxt, path + [nxt])

    for start in sorted(adj):
        dfs(start, [start])
    return cycles


class MultiAgentAnalyzer:
    module_id = "M10"
    name = "Multi-Agent Security"
    implementation = "implemented"

    def analyze(self, ctx: AuditContext) -> AnalyzerResult:
        res = AnalyzerResult()
        inv = ctx.inventory
        graph = delegation_graph(inv)
        res.artifacts["delegation_graph"] = graph
        nodes = {n["agent"]: n for n in graph["nodes"]}
        for d in inv.delegations:
            asset = f"delegation:{d.from_agent}->{d.to_agent}"
            et = EvidenceType.DECLARATION if d.provenance == "declared" else EvidenceType.CODE
            src = inv.agent(d.from_agent)
            dst = inv.agent(d.to_agent)
            shared = bool(src and dst and set(src.tools) & set(dst.tools))
            if d.inherit_permissions is True or (d.inherit_permissions is None and shared):
                res.findings.append(make_finding(
                    "MA-001", asset, [evidence_at(ctx, d.file, d.line, et, f"inherit_permissions={d.inherit_permissions}; shared tools={shared}")],
                    FindingStatus.CONFIRMED if d.inherit_permissions else FindingStatus.POTENTIAL,
                    Confidence.HIGH if d.inherit_permissions else Confidence.MEDIUM))
            net = (d.channel or "").lower() in NETWORK_CHANNELS
            if d.authenticated is False or (net and d.authenticated is None):
                res.findings.append(make_finding(
                    "MA-002", asset, [evidence_at(ctx, d.file, d.line, et, f"channel={d.channel}; authenticated={d.authenticated}")],
                    FindingStatus.CONFIRMED if d.authenticated is False else FindingStatus.POTENTIAL, Confidence.HIGH,
                    severity=Severity.HIGH if net else Severity.MEDIUM))
            sn, dn = nodes.get(d.from_agent), nodes.get(d.to_agent)
            if sn and dn and sn["exposed_to_untrusted_input"] and dn["privileged_tools"]:
                dst_tools = [inv.tool(t) for t in dn["privileged_tools"]]
                if not all(t and t.requires_approval for t in dst_tools):
                    res.findings.append(make_finding(
                        "MA-004", asset,
                        [evidence_at(ctx, d.file, d.line, et,
                                     f"{d.from_agent} reads untrusted input; {d.to_agent} holds {', '.join(dn['privileged_tools'])}")],
                        FindingStatus.POTENTIAL, Confidence.MEDIUM, trust_boundary="TB-AGENTS"))
        for cyc in graph["cycles"]:
            limited = all((inv.agent(a) and inv.agent(a).max_iterations) for a in cyc[:-1])
            if not limited:
                res.findings.append(make_finding(
                    "MA-003", "delegation-cycle:" + "->".join(cyc),
                    [evidence_at(ctx, inv.agent(cyc[0]).file if inv.agent(cyc[0]) else None, None, EvidenceType.CODE,
                                 "cycle: " + " -> ".join(cyc))],
                    FindingStatus.CONFIRMED, Confidence.MEDIUM, discriminator="->".join(cyc)))

        na = (ControlStatus.NOT_APPLICABLE, "Single-agent architecture (no delegations detected).")
        m1 = related(res.findings, "MA-001", "MA-002", "MA-004")
        if not inv.delegations:
            c1 = na
        elif m1:
            c1 = (status_from(m1) or ControlStatus.FAILED, f"{len(m1)} delegation issue(s).")
        elif all(d.authenticated is not None and d.inherit_permissions is False for d in inv.delegations):
            c1 = (ControlStatus.PASSED, "Delegations authenticated/declared and do not inherit permissions.")
        else:
            c1 = (ControlStatus.NOT_VERIFIED, "Authentication / permission inheritance not declared for every delegation.")
        res.controls.append(control("CTRL-MA-01", "Authenticated delegation with scoped permissions", "M10", c1[0], c1[1],
                                    related=m1, owasp=[ASI["ASI07"], ASI["ASI03"]]))
        m2 = related(res.findings, "MA-003")
        res.controls.append(control("CTRL-MA-02", "Delegation bounded (no unbounded cycles)", "M10",
                                    *((status_from(m2) or ControlStatus.PASSED, f"{len(graph['cycles'])} cycle(s).")
                                      if inv.delegations else na), related=m2, owasp=[ASI["ASI08"]]))
        res.limitations.append("Delegations are detected from handoffs/as_tool (OpenAI Agents), Crew/GroupChat membership "
                               "and the manifest; delegations decided at runtime or over external queues need declaration.")
        return res
