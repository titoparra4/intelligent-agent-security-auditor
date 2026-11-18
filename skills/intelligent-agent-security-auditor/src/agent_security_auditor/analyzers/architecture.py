"""MODULE 01 - Agent Architecture Analyzer.

Builds the component inventory (via adapters, already run by the engine), the relationship
map, trust boundaries, permission matrix, data-flow graph and an initial threat model, and
flags architectural risk combinations.
"""

from __future__ import annotations

from typing import Any

from agent_security_auditor.analyzers.base import AnalyzerResult, control, evidence_at, related
from agent_security_auditor.core.context import AuditContext
from agent_security_auditor.models.finding import Confidence, ControlStatus, Evidence, EvidenceType, FindingStatus
from agent_security_auditor.models.inventory import SENSITIVE_DATA, Inventory, Tool
from agent_security_auditor.rules import make_finding
from agent_security_auditor.rules.references import ASI

EGRESS_CLASSES = ("external", "exfil_service", "model_provider", "reserved")


def trust_boundaries(inv: Inventory) -> list[dict[str, Any]]:
    tb = [{"id": "TB-USER", "name": "End user -> agent", "crosses": "user prompts enter model context"}]
    if any(t.reads_untrusted for t in inv.tools):
        tb.append({"id": "TB-CONTENT", "name": "External content -> agent context",
                   "crosses": "tool output from " + ", ".join(sorted({d for t in inv.tools if t.reads_untrusted for d in t.data_access}))})
    if inv.tools:
        tb.append({"id": "TB-TOOLS", "name": "Model decision -> tool execution",
                   "crosses": f"{len(inv.tools)} tool(s) act on external systems with their own identities"})
    if inv.mcp_servers:
        tb.append({"id": "TB-MCP", "name": "MCP client <-> MCP servers",
                   "crosses": ", ".join(f"{s.name} ({s.transport})" for s in inv.mcp_servers)})
    if inv.memory:
        tb.append({"id": "TB-MEMORY", "name": "Session -> persistent memory",
                   "crosses": ", ".join(f"{m.name} [{m.scope}]" for m in inv.memory)})
    if inv.delegations:
        tb.append({"id": "TB-AGENTS", "name": "Agent -> agent delegation",
                   "crosses": f"{len(inv.delegations)} delegation edge(s)"})
    if any(d.classification in EGRESS_CLASSES for d in inv.network):
        tb.append({"id": "TB-NETWORK", "name": "Agent runtime -> external network",
                   "crosses": ", ".join(sorted({d.host for d in inv.network if d.classification in EGRESS_CLASSES}))})
    if inv.code_execution:
        tb.append({"id": "TB-EXEC", "name": "Model output -> code execution",
                   "crosses": f"{len(inv.code_execution)} execution site(s)"})
    return tb


def permission_matrix(inv: Inventory) -> list[dict[str, Any]]:
    from agent_security_auditor.core.classify import scope_info

    rows = []
    for t in sorted(inv.tools, key=lambda t: t.name):
        risk = _tool_risk(t, scope_info)
        rows.append({
            "tool": t.name,
            "agents": t.agents,
            "identity": t.identity or "UNKNOWN",
            "permissions": t.permissions or ["UNKNOWN"],
            "permission_provenance": t.permission_provenance,
            "data_access": t.data_access,
            "sensitivity": t.sensitivity,
            "operations": t.operations,
            "risk": risk,
            "required_approval": "YES" if t.requires_approval else ("NO" if t.requires_approval is False else "UNKNOWN"),
            "approval_provenance": t.approval_provenance,
            "source": t.source,
            "file": t.file,
            "line": t.line,
        })
    return rows


def _tool_risk(t: Tool, scope_info) -> str:
    ops = set(t.operations)
    broad = any((i := scope_info(p)) and (i.broad or i.admin) for p in t.permissions)
    admin = any((i := scope_info(p)) and i.admin for p in t.permissions)
    if admin or "execute" in ops or "financial" in ops or "infra" in ops:
        return "CRITICAL" if not t.requires_approval else "HIGH"
    if ops & {"delete", "send"} or (broad and t.touches_sensitive):
        return "HIGH" if not t.requires_approval else "MEDIUM"
    if ops & {"write"} or t.touches_sensitive:
        return "MEDIUM"
    return "LOW"


def data_flows(inv: Inventory, allowlist: list[str]) -> list[dict[str, Any]]:
    """Source -> agent context -> sink flows.

    Conservative assumption (documented): everything in one agent's context can reach any of
    that agent's sinks, because the model decides what to pass to which tool.
    """
    from agent_security_auditor.core.classify import host_matches

    flows = []
    sources = [t for t in inv.tools if "read" in t.operations and (t.touches_sensitive or t.data_access)]
    sinks: list[dict[str, Any]] = []
    for t in inv.tools:
        if t.is_egress:
            dests = t.network_destinations or ["(tool-defined)"]
            for d in dests:
                from agent_security_auditor.core.classify import classify_host
                host, cls = classify_host(d) if d != "(tool-defined)" else ("", "unknown")
                sinks.append({"sink": t.name, "kind": "tool", "destination": d, "host": host, "class": cls,
                              "approval": t.requires_approval, "agents": set(t.agents)})
    for s in sources:
        for k in sinks:
            if s.name == k["sink"]:
                continue
            if s.agents and k["agents"] and not (set(s.agents) & k["agents"]):
                continue
            allowed = bool(k["host"]) and host_matches(k["host"], allowlist)
            controls = []
            if k["approval"]:
                controls.append("human approval")
            if allowed:
                controls.append("destination allowlisted")
            flows.append({
                "source": s.name, "source_data": s.data_access, "sensitivity": s.sensitivity,
                "via": "agent context", "sink": k["sink"], "destination": k["destination"],
                "destination_class": k["class"], "controls": controls,
                "risk": "HIGH" if (s.touches_sensitive and not controls) else "MEDIUM" if not controls else "LOW",
            })
    flows.sort(key=lambda f: ({"HIGH": 0, "MEDIUM": 1, "LOW": 2}[f["risk"]], f["source"], f["sink"]))
    return flows


def threat_model(inv: Inventory) -> dict[str, Any]:
    assets = []
    for t in inv.tools:
        if t.data_access or t.sensitivity:
            assets.append({"asset": t.name, "type": "data via tool", "data": t.data_access, "sensitivity": t.sensitivity})
    for m in inv.memory:
        assets.append({"asset": m.name, "type": "memory", "data": [m.kind], "sensitivity": ["pii"] if m.kind != "short_term" else []})
    for t in inv.tools:
        if t.identity:
            assets.append({"asset": t.identity, "type": "credential/identity", "data": ["credentials"], "sensitivity": ["credentials"]})
    actors = [
        {"actor": "Legitimate user", "trust": "authenticated, partially trusted"},
        {"actor": "External content author", "trust": "untrusted (emails, documents, web pages, tickets)"},
        {"actor": "Third-party tool / MCP server provider", "trust": "semi-trusted supply chain"},
        {"actor": "Other agents", "trust": "trust depends on authentication of the channel"},
        {"actor": "Insider with repository/config access", "trust": "trusted, but can alter tools and prompts"},
    ]
    threats = []

    def add(tid: str, title: str, asi: str, surface: str, scenario: str, applies: bool) -> None:
        if applies:
            threats.append({"id": tid, "title": title, "owasp": ASI[asi], "surface": surface, "scenario": scenario})

    untrusted = [t.name for t in inv.tools if t.reads_untrusted]
    egress = [t.name for t in inv.tools if t.is_egress]
    destructive = [t.name for t in inv.tools if t.is_irreversible]
    add("TM-01", "Goal hijack through retrieved content", "ASI01", ", ".join(untrusted) or "-",
        "Attacker plants instructions in content returned by a tool; the agent follows them.", bool(untrusted))
    add("TM-02", "Tool misuse to exfiltrate data", "ASI02", ", ".join(egress) or "-",
        "Injected or erroneous plan passes sensitive context to an egress tool.", bool(egress))
    add("TM-03", "Privilege abuse through over-scoped credentials", "ASI03",
        ", ".join(t.name for t in inv.tools if t.permissions) or "-",
        "A tool credential grants more than the task needs; misuse inherits the excess.", any(t.permissions for t in inv.tools))
    add("TM-04", "Compromised MCP server / dependency", "ASI04", ", ".join(s.name for s in inv.mcp_servers) or "dependencies",
        "Upstream package or server changes tool definitions or code (rug pull, typosquat).",
        bool(inv.mcp_servers or inv.dependencies))
    add("TM-05", "Unexpected code execution", "ASI05", ", ".join(sorted({c.kind for c in inv.code_execution})) or "-",
        "Model-generated code runs on the host or with credentials.", bool(inv.code_execution))
    add("TM-06", "Memory / context poisoning", "ASI06", ", ".join(m.name for m in inv.memory) or "-",
        "Untrusted content is persisted and re-injected into future sessions.", bool(inv.memory))
    add("TM-07", "Agent impersonation / message tampering", "ASI07", f"{len(inv.delegations)} delegation(s)",
        "A message from a compromised or spoofed agent is trusted as authoritative.", bool(inv.delegations))
    add("TM-08", "Cascading failure", "ASI08", "agent loop" + (" + delegations" if inv.delegations else ""),
        "Errors or loops propagate across tools/agents without bounds.", bool(inv.agents))
    add("TM-09", "Human approval manipulation", "ASI09", ", ".join(destructive) or "-",
        "The agent presents a misleading summary so a human approves a harmful action.", bool(destructive))
    add("TM-10", "Rogue behavior / undeclared capability", "ASI10", "runtime",
        "The agent or a component performs actions beyond its declared purpose (hidden collection, persistence).", True)
    return {"assets": assets, "actors": actors, "trust_boundaries": trust_boundaries(inv), "threats": threats}


def mermaid_dataflow(inv: Inventory) -> str:
    def nid(prefix: str, name: str) -> str:
        return prefix + "_" + "".join(ch if ch.isalnum() else "_" for ch in name)[:40]

    lines = ["flowchart LR", "  user([User]) --> agentctx"]
    agent_label = ", ".join(a.name for a in inv.agents[:3]) or "agent"
    lines.append(f'  agentctx["Agent context: {agent_label}"]')
    for t in inv.tools:
        tid = nid("tool", t.name)
        label = f"{t.name}<br/>{'/'.join(t.operations) or '?'}"
        lines.append(f'  {tid}["{label}"]')
        if "read" in t.operations or not t.operations:
            lines.append(f"  {tid} -->|{'UNTRUSTED ' if t.reads_untrusted else ''}output| agentctx")
        if t.is_destructive or t.is_egress:
            lines.append(f"  agentctx -->|call{' (approval)' if t.requires_approval else ''}| {tid}")
        for d in t.network_destinations[:3]:
            from agent_security_auditor.core.classify import classify_host
            host, _ = classify_host(d)
            lines.append(f'  {tid} --> {nid("net", host)}(("{host}"))')
    for m in inv.memory:
        mid = nid("mem", m.name)
        lines.append(f'  {mid}[("{m.name} [{m.scope}]")] <--> agentctx')
    for s in inv.mcp_servers:
        sid = nid("mcp", s.name)
        lines.append(f'  {sid}{{{{"MCP {s.name} ({s.transport})"}}}} -.tools.-> agentctx')
    return "\n".join(lines)


class ArchitectureAnalyzer:
    module_id = "M01"
    name = "Agent Architecture Analyzer"
    implementation = "implemented"

    def analyze(self, ctx: AuditContext) -> AnalyzerResult:
        inv = ctx.inventory
        res = AnalyzerResult()
        nothing = not (inv.agents or inv.tools or inv.mcp_servers)
        if nothing:
            res.findings.append(make_finding(
                "ARCH-002", "target", [Evidence(EvidenceType.ABSENCE, note=f"{len(ctx.files)} files scanned; adapters: {', '.join(inv.adapters_used)}")],
                FindingStatus.OBSERVATION, Confidence.HIGH))
        elif not inv.manifest_file:
            res.findings.append(make_finding(
                "ARCH-003", "agent-manifest", [Evidence(EvidenceType.ABSENCE, note="no agent-manifest.yaml found")],
                FindingStatus.OBSERVATION, Confidence.HIGH))

        # --- lethal combination per agent (or whole project if agents unknown) -------------
        groups: dict[str, list[Tool]] = {}
        for t in inv.tools:
            for a in t.agents or ["(unassigned)"]:
                groups.setdefault(a, []).append(t)
        if len(groups) > 1 and "(unassigned)" in groups:
            # unassigned tools may belong to any agent: conservative merge into each group
            for a in list(groups):
                if a != "(unassigned)":
                    groups[a].extend(groups["(unassigned)"])
            groups.pop("(unassigned)")
        allow = list(ctx.policy.allowed_network_destinations) + list(inv.declared_allowed_destinations)
        from agent_security_auditor.core.classify import host_matches
        undeclared_egress = [d for d in inv.network if d.in_http_call and d.carries_data
                             and d.classification in EGRESS_CLASSES and not host_matches(d.host, allow)]
        for agent, tools in sorted(groups.items()):
            sensitive = [t for t in tools if set(t.sensitivity) & SENSITIVE_DATA]
            untrusted = [t for t in tools if t.reads_untrusted]
            egress = [t for t in tools if t.is_egress and not t.requires_approval]
            if sensitive and untrusted and (egress or undeclared_egress):
                legs = (f"sensitive: {', '.join(t.name for t in sensitive)}; untrusted input: "
                        f"{', '.join(t.name for t in untrusted)}; egress: "
                        f"{', '.join([t.name for t in egress] + [d.host for d in undeclared_egress]) }")
                ev = [evidence_at(ctx, t.file, t.line, EvidenceType.INFERENCE, f"leg: {t.name}") for t in (sensitive[:1] + untrusted[:1] + egress[:1])]
                res.findings.append(make_finding(
                    "ARCH-001", f"agent:{agent}", ev, FindingStatus.POTENTIAL, Confidence.MEDIUM, detail=legs,
                    trust_boundary="TB-CONTENT -> TB-NETWORK", discriminator=agent,
                    affected_permissions=sorted({p for t in sensitive for p in t.permissions})))

        # --- controls -------------------------------------------------------------------------
        if nothing:
            res.controls.append(control("CTRL-ARCH-01", "Agent architecture inventoried", "M01",
                                        ControlStatus.INSUFFICIENT_EVIDENCE, "No agent components detected.",
                                        owasp=[ASI["ASI10"]]))
        else:
            res.controls.append(control(
                "CTRL-ARCH-01", "Agent architecture inventoried", "M01", ControlStatus.PASSED,
                f"{len(inv.agents)} agent(s), {len(inv.tools)} tool(s), {len(inv.mcp_servers)} MCP server(s), "
                f"{len(inv.memory)} memory store(s) inventoried" + ("" if inv.manifest_file else " (no manifest: inferred)"),
                [Evidence(EvidenceType.DECLARATION if inv.manifest_file else EvidenceType.INFERENCE, inv.manifest_file)]))
        trif = related(res.findings, "ARCH-001")
        if not inv.tools:
            st, why = ControlStatus.NOT_APPLICABLE, "No tools."
        elif trif:
            st, why = ControlStatus.FAILED, "Private data, untrusted content and egress coexist in one context."
        else:
            st, why = ControlStatus.PASSED, "No agent context combines sensitive data, untrusted content and uncontrolled egress."
        res.controls.append(control("CTRL-ARCH-02", "No uncontrolled private-data/untrusted-content/egress combination",
                                    "M01", st, why, related=trif, owasp=[ASI["ASI01"], ASI["ASI02"]]))

        res.artifacts["trust_boundaries"] = trust_boundaries(inv)
        res.artifacts["permission_matrix"] = permission_matrix(inv)
        res.artifacts["data_flows"] = data_flows(inv, allow)
        res.artifacts["threat_model"] = threat_model(inv)
        res.artifacts["dataflow_mermaid"] = mermaid_dataflow(inv)
        res.limitations.append("Data flows assume every source in an agent context can reach every sink of that agent "
                               "(the model chooses arguments); actual flows may be narrower.")
        return res
