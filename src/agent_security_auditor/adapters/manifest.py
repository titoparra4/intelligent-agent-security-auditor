"""Agent manifest adapter (``agent-manifest.yaml`` / ``.yml`` / ``.json``).

The manifest is the project's own, framework-neutral way for an agent owner to *declare*
architecture facts that static analysis cannot infer reliably (identities, OAuth scopes,
approval rules, memory scope, allowed destinations ...). Everything read here has
provenance ``declared`` unless it can be corroborated in code (e.g. ``approval_enforced_by``
pointing at a function that exists and is called by the tool), in which case it is
upgraded to ``code``.

Schema: ``assets/schemas/agent-manifest.schema.json``.
"""

from __future__ import annotations

import ast
from typing import Any

from agent_security_auditor.core.classify import classify_host, infer_data_access, infer_operations, sensitivity_for
from agent_security_auditor.core.context import AuditContext
from agent_security_auditor.core.parsing import call_name
from agent_security_auditor.core.redaction import redact
from agent_security_auditor.models.inventory import (
    Agent,
    DataSource,
    Delegation,
    MemoryStore,
    NetworkDestination,
    Tool,
)

MANIFEST_NAMES = ("agent-manifest.yaml", "agent-manifest.yml", "agent-manifest.json")


def _bool(v: Any) -> bool | None:
    if isinstance(v, bool):
        return v
    if isinstance(v, str) and v.lower() in ("true", "yes"):
        return True
    if isinstance(v, str) and v.lower() in ("false", "no"):
        return False
    return None


def _list(v: Any) -> list[str]:
    if v is None:
        return []
    if isinstance(v, (str, int, float)):
        return [str(v)]
    if isinstance(v, list):
        return [str(x) for x in v if isinstance(x, (str, int, float))]
    return []


class ManifestAdapter:
    name = "agent-manifest"
    coverage = (
        "Full support for the project's agent-manifest format (agents, tools, permissions, identities, "
        "approval rules, memory, data sources, network allowlist, delegations, MCP tool pins). "
        "Declarations are recorded as 'declared' evidence, not as proof of enforcement."
    )

    def _find(self, ctx: AuditContext):
        found = [f for f in ctx.files if f.rel.rsplit("/", 1)[-1] in MANIFEST_NAMES]
        found.sort(key=lambda f: (f.rel.count("/"), f.rel))
        return found

    def applies(self, ctx: AuditContext) -> bool:
        return bool(self._find(ctx))

    def populate(self, ctx: AuditContext) -> None:
        for f in self._find(ctx):
            res = ctx.parsed(f)
            if not res.ok or not isinstance(res.value, dict):
                continue
            ctx.inventory.manifest_file = ctx.inventory.manifest_file or f.rel
            self._lines = f.lines()
            self._apply(ctx, f.rel, res.value)

    _lines: list[str] = []

    def _line(self, name: object) -> int | None:
        needle = str(name)
        for i, ln in enumerate(self._lines, 1):
            stripped = ln.strip().lstrip("- ").strip()
            if stripped.startswith("name:") and stripped[5:].strip().strip("'\"") == needle:
                return i
        return None

    # ------------------------------------------------------------------------------------
    def _apply(self, ctx: AuditContext, rel: str, m: dict[str, Any]) -> None:
        inv = ctx.inventory
        agents_raw: list[dict[str, Any]] = []
        if isinstance(m.get("agent"), dict):
            agents_raw.append(m["agent"])
        if isinstance(m.get("agents"), list):
            agents_raw.extend(a for a in m["agents"] if isinstance(a, dict))
        primary = None
        for a in agents_raw:
            if not a.get("name"):
                continue
            limits = a.get("limits") if isinstance(a.get("limits"), dict) else {}
            oversight = a.get("human_oversight") if isinstance(a.get("human_oversight"), dict) else {}
            ce = a.get("code_execution") if isinstance(a.get("code_execution"), dict) else {}
            max_it = limits.get("max_iterations")
            agent = Agent(
                name=str(a["name"]),
                framework=str(a.get("framework", "custom")),
                file=rel,
                line=self._line(a["name"]),
                model=a.get("model"),
                provider=a.get("provider"),
                identity=a.get("identity"),
                tools=_list(a.get("tools")),
                sub_agents=_list(a.get("sub_agents")),
                max_iterations=int(max_it) if isinstance(max_it, int) else None,
                max_iterations_source="declared" if isinstance(max_it, int) else None,
                budget_limit=str(limits["budget"]) if limits.get("budget") else None,
                kill_switch=oversight.get("kill_switch"),
                human_oversight=oversight.get("approval_channel") or oversight.get("mode"),
                code_execution=bool(ce.get("enabled", False)),
                code_execution_sandboxed=_bool(ce.get("sandboxed")),
                allow_delegation=_bool(a.get("allow_delegation")),
                exposed_to_untrusted_input=bool(_list(a.get("exposed_to"))) or None,
                provenance="declared",
            )
            instr_file = a.get("instructions_file")
            if isinstance(instr_file, str):
                sf = ctx.discovery.get(_join(rel, instr_file))
                if sf is not None:
                    text = sf.text()
                    agent.instructions_excerpt = redact(text[:400])
                    low = text.lower()
                    agent.instructions_mentions_approval = any(
                        k in low for k in ("approval", "approve", "confirm with the user", "ask the user", "permission before")
                    )
            if primary is None:
                primary = agent.name
            inv.add_agent(agent)
            if agent.framework not in inv.frameworks:
                inv.frameworks.append(agent.framework)

        for t in m.get("tools", []) or []:
            if not isinstance(t, dict) or not t.get("name"):
                continue
            name = str(t["name"])
            desc = str(t.get("description", ""))
            ops = _list(t.get("operations")) or infer_operations(name, desc)
            data = _list(t.get("data_access")) or infer_data_access(name, desc)
            sens = _list(t.get("data_classification")) or sensitivity_for(data)
            tool = Tool(
                name=name,
                source="manifest",
                file=rel,
                line=self._line(name),
                description=desc,
                agents=_list(t.get("agents")) or ([primary] if primary else []),
                operations=ops,
                data_access=data,
                sensitivity=sens,
                permissions=_list(t.get("permissions")),
                permission_provenance="declared" if t.get("permissions") is not None else "inferred",
                identity=t.get("identity"),
                requires_approval=_bool(t.get("requires_approval")),
                approval_provenance="declared" if _bool(t.get("requires_approval")) is not None else None,
                approval_enforced_by=t.get("approval_enforced_by"),
                returns_untrusted_content=_bool(t.get("returns_untrusted_content")),
                output_handling=t.get("output_handling"),
                network_destinations=_list(t.get("network_destinations")),
                mcp_server=t.get("mcp_server"),
                production_target=str(t.get("environment", "")).lower() in ("prod", "production"),
                tenant_scoped=_bool(t.get("tenant_scoped")),
            )
            if tool.approval_enforced_by and tool.requires_approval:
                if _verify_enforcement(ctx, rel, tool.approval_enforced_by, name):
                    tool.approval_provenance = "code"
            inv.add_tool(tool)
            for dest in tool.network_destinations:
                host, cls = classify_host(dest)
                inv.network.append(NetworkDestination(dest, host, rel, None, None, False, "send" in ops, cls, True))

        for mem in m.get("memory", []) or []:
            if not isinstance(mem, dict) or not mem.get("name"):
                continue
            inv.memory.append(MemoryStore(
                name=str(mem["name"]),
                kind=str(mem.get("kind", "long_term")),
                file=rel,
                line=self._line(mem["name"]),
                scope=str(mem.get("scope", "unknown")),
                ttl=str(mem["ttl"]) if mem.get("ttl") not in (None, "", False) else None,
                provenance_tracking=_bool(mem.get("provenance_tracking")),
                write_sources=_list(mem.get("write_sources")),
                injected_into=mem.get("injected_into"),
                deletion_supported=_bool(mem.get("deletion_supported")),
                provenance="declared",
            ))

        for ds in m.get("data_sources", []) or []:
            if isinstance(ds, dict) and ds.get("name"):
                inv.data_sources.append(DataSource(
                    str(ds["name"]), str(ds.get("kind", "unknown")), _list(ds.get("classification")), rel))

        dep = m.get("deployment") if isinstance(m.get("deployment"), dict) else {}
        if _bool(dep.get("multi_user")) is not None:
            inv.multi_user = _bool(dep.get("multi_user"))
        for t in _list(m.get("telemetry")):
            inv.telemetry_declared.append(t)
        mcp_trust = m.get("mcp_servers") if isinstance(m.get("mcp_servers"), dict) else {}
        ctx.artifacts.setdefault("mcp_trust", {}).update({str(k): v for k, v in mcp_trust.items() if isinstance(v, dict)})

        net = m.get("network") if isinstance(m.get("network"), dict) else {}
        for d in _list(net.get("allowed_destinations")):
            if d not in inv.declared_allowed_destinations:
                inv.declared_allowed_destinations.append(d)

        for d in m.get("delegations", []) or []:
            if isinstance(d, dict) and d.get("from") and d.get("to"):
                src, dst = str(d["from"]), str(d["to"])
                line = next((i for i, ln in enumerate(self._lines, 1)
                             if ln.strip().lstrip("- ").strip() == f"from: {src}"
                             and i < len(self._lines) and self._lines[i].strip() == f"to: {dst}"), None)
                existing = next((x for x in inv.delegations if x.from_agent == src and x.to_agent == dst), None)
                if existing is None:
                    inv.delegations.append(Delegation(src, dst, _bool(d.get("inherit_permissions")),
                                                      _bool(d.get("authenticated")), d.get("channel"), rel, line, "declared"))
                else:  # the declaration enriches the edge found in code
                    existing.inherit_permissions = _bool(d.get("inherit_permissions"))
                    existing.authenticated = _bool(d.get("authenticated"))
                    existing.channel = d.get("channel") or existing.channel
                    existing.file, existing.line, existing.provenance = rel, line, "declared"

        pins = m.get("mcp_tool_pins")
        if isinstance(pins, dict):
            ctx.artifacts.setdefault("mcp_tool_pins", {}).update(
                {str(k): {str(tk): str(tv) for tk, tv in v.items()} for k, v in pins.items() if isinstance(v, dict)})


def _join(manifest_rel: str, target: str) -> str:
    base = manifest_rel.rsplit("/", 1)[0] if "/" in manifest_rel else ""
    target = target.lstrip("./")
    return f"{base}/{target}" if base else target


def _verify_enforcement(ctx: AuditContext, manifest_rel: str, ref: str, tool_name: str) -> bool:
    """``path/to/file.py::func`` must define ``func`` AND the tool function must call it."""
    if "::" not in ref:
        return False
    path, func = ref.split("::", 1)
    sf = ctx.discovery.get(_join(manifest_rel, path))
    if sf is None or sf.kind != "python":
        return False
    res = ctx.parsed(sf)
    if not res.ok:
        return False
    tree = res.value
    defined = any(isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == func for n in ast.walk(tree))
    if not defined:
        return False
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == tool_name:
            for c in ast.walk(n):
                if isinstance(c, ast.Call) and call_name(c).split(".")[-1] == func:
                    return True
    return False
