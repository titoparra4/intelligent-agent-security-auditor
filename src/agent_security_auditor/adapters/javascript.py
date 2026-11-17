"""Regex-based JavaScript / TypeScript adapter (partial).

Detects HTTP egress (``fetch`` / ``axios`` / ``got``), agent declarations from the OpenAI Agents
JS SDK (``new Agent({ name: ... })``) and Vercel AI SDK ``tool({ description })`` definitions.
It does not build an AST, resolve imports or follow variables across files.
"""

from __future__ import annotations

import re

from agent_security_auditor.core.classify import classify_host, infer_data_access, infer_operations, is_documentation_url, sensitivity_for
from agent_security_auditor.core.context import AuditContext
from agent_security_auditor.models.inventory import Agent, NetworkDestination, Tool

FETCH = re.compile(
    r"""(?:fetch|axios(?:\.(get|post|put|patch|delete|request))?|got(?:\.(get|post|put|patch|delete))?|ky(?:\.(get|post|put|patch|delete))?)\s*\(\s*[`"'](https?://[^`"'\s]+)[`"']\s*(,\s*\{[^)]{0,400})?""",
    re.S,
)
NEW_AGENT = re.compile(r"new\s+Agent\s*\(\s*\{[^}]*?name\s*:\s*[`\"']([^`\"']+)[`\"']", re.S)
AI_TOOL = re.compile(r"(\w+)\s*[:=]\s*tool\s*\(\s*\{\s*description\s*:\s*[`\"']([^`\"']{0,400})[`\"']", re.S)


class JavaScriptAdapter:
    name = "javascript-regex"
    coverage = (
        "Partial, regex-based: literal-URL fetch/axios/got/ky calls, `new Agent({name})` (OpenAI Agents JS) and "
        "Vercel AI SDK `tool({description})`. No AST, no import/variable resolution."
    )

    def applies(self, ctx: AuditContext) -> bool:
        return bool(ctx.discovery.by_kind("javascript", "typescript"))

    def populate(self, ctx: AuditContext) -> None:
        inv = ctx.inventory
        for f in ctx.discovery.by_kind("javascript", "typescript"):
            text = f.text()
            for m in FETCH.finditer(text):
                url = m.group(4)
                if is_documentation_url(url):
                    continue
                method = (m.group(1) or m.group(2) or m.group(3) or "").upper() or None
                opts = m.group(5) or ""
                om = re.search(r"method\s*:\s*[`\"'](\w+)", opts)
                if om:
                    method = om.group(1).upper()
                carries = bool(re.search(r"\bbody\s*:|\bdata\s*:|\bjson\s*:", opts)) or method in ("POST", "PUT", "PATCH")
                host, cls = classify_host(url)
                inv.network.append(NetworkDestination(url, host, f.rel, text.count("\n", 0, m.start()) + 1,
                                                      method or "GET", True, carries, cls))
            for m in NEW_AGENT.finditer(text):
                inv.add_agent(Agent(name=m.group(1), framework="openai-agents-js", file=f.rel,
                                    line=text.count("\n", 0, m.start()) + 1))
                if "openai-agents-js" not in inv.frameworks:
                    inv.frameworks.append("openai-agents-js")
            for m in AI_TOOL.finditer(text):
                name, desc = m.group(1), m.group(2)
                data = infer_data_access(name, desc)
                inv.add_tool(Tool(name=name, source="code:javascript", file=f.rel,
                                  line=text.count("\n", 0, m.start()) + 1, description=desc,
                                  operations=infer_operations(name, desc), data_access=data,
                                  sensitivity=sensitivity_for(data)))
