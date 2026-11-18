"""MCP client configuration + MCP server source adapter.

Client configs recognized (JSON / JSONC / YAML):
``mcpServers`` (Claude Desktop / Claude Code ``.mcp.json`` / Cursor), ``servers`` (VS Code
``.vscode/mcp.json``) and ``mcp.servers``.

Server source recognized (static, never imported):
* Python: functions decorated with ``@<x>.tool(...)`` when the module imports ``mcp`` / ``fastmcp``.
* JS/TS: ``server.tool("name", "description", ...)``, ``registerTool("name", {description: ...})``.

Transports: ``stdio`` (command), ``http`` (streamable HTTP url), ``sse`` (legacy SSE url).
HTTP authorization requirements are only evaluated for HTTP/SSE transports; per the MCP
specification, STDIO servers obtain credentials from the environment.
"""

from __future__ import annotations

import ast
import hashlib
import re
from typing import Any

from agent_security_auditor.core.classify import infer_data_access, infer_operations, sensitivity_for
from agent_security_auditor.core.context import AuditContext
from agent_security_auditor.core.parsing import call_name, kwarg, literal
from agent_security_auditor.core.redaction import find_secrets
from agent_security_auditor.models.inventory import McpServer, McpTool, Tool

CONFIG_NAME_HINTS = ("mcp", "claude_desktop_config", "cline_mcp_settings", "settings")
SECRETISH_KEY = re.compile(r"(?i)(key|token|secret|password|passwd|credential|auth|bearer|pat)\b|_key$|_token$")
VAR_REF = re.compile(r"^\s*(\$\{[^}]+\}|\$[A-Z_][A-Z0-9_]*|\{env:[^}]+\}|env:[A-Z_]+|\$\{input:[^}]+\})\s*$")
JS_TOOL = re.compile(
    r"""(?:server|mcp|app)\s*\.\s*(?:tool|registerTool)\s*\(\s*["'`]([\w\-.]+)["'`]\s*,\s*(?:["'`]((?:[^"'`\\]|\\.){0,2000})["'`]|\{[^}]*?description\s*:\s*["'`]((?:[^"'`\\]|\\.){0,2000})["'`])""",
    re.S,
)


def description_hash(description: str) -> str:
    return "sha256:" + hashlib.sha256(description.strip().encode("utf-8")).hexdigest()


def _servers_from(doc: Any) -> dict[str, Any] | None:
    if not isinstance(doc, dict):
        return None
    for key in ("mcpServers", "servers", "mcp_servers"):
        v = doc.get(key)
        if isinstance(v, dict) and v and all(isinstance(x, dict) for x in v.values()):
            if key == "servers" and not any(("command" in x or "url" in x) for x in v.values()):
                continue
            return v
    mcp = doc.get("mcp")
    if isinstance(mcp, dict):
        return _servers_from(mcp)
    return None


def _package_and_pin(command: str, args: list[str]) -> tuple[str | None, bool | None]:
    cmd = command.rsplit("/", 1)[-1].lower()
    rest = [a for a in args if isinstance(a, str)]
    if cmd in ("npx", "bunx", "pnpx") or (cmd in ("pnpm", "yarn", "npm") and rest[:1] in (["dlx"], ["exec"])):
        pkgs = [a for a in rest if not a.startswith("-") and a not in ("dlx", "exec")]
        if not pkgs:
            return None, None
        pkg = pkgs[0]
        name_part = pkg[1:] if pkg.startswith("@") else pkg
        pinned = "@" in name_part and re.search(r"@\d+\.\d+\.\d+", pkg) is not None
        return pkg, pinned
    if cmd in ("uvx", "pipx"):
        if "--from" in rest:
            i = rest.index("--from")
            pkg = rest[i + 1] if i + 1 < len(rest) else None
        else:
            pkgs = [a for a in rest if not a.startswith("-") and a != "run"]
            pkg = pkgs[0] if pkgs else None
        if pkg is None:
            return None, None
        return pkg, ("==" in pkg)
    if cmd in ("sh", "bash", "zsh", "cmd", "cmd.exe") and len(rest) >= 2 and rest[0] in ("-c", "/c"):
        # shell wrapper: look for a package launcher inside the command string (not executed)
        import shlex
        try:
            tokens = shlex.split(rest[1])
        except ValueError:
            return None, None
        for i, tok in enumerate(tokens):
            if tok.rsplit("/", 1)[-1] in ("npx", "bunx", "pnpx", "uvx", "pipx", "docker", "podman"):
                return _package_and_pin(tok, tokens[i + 1:])
        return None, None
    if cmd in ("docker", "podman"):
        imgs = [a for a in rest if not a.startswith("-") and a not in ("run", "--rm", "-i") and ("/" in a or ":" in a)]
        if not imgs:
            return None, None
        img = imgs[-1]
        if "@sha256:" in img:
            return img, True
        tag = img.rsplit(":", 1)[-1] if ":" in img.rsplit("/", 1)[-1] else "latest"
        return img, tag not in ("latest", "")
    return None, None  # local script (python server.py, node index.js): pinning not applicable


class McpConfigAdapter:
    name = "mcp"
    coverage = (
        "MCP client configs (mcpServers / servers keys: Claude Desktop, Claude Code .mcp.json, Cursor, VS Code); "
        "stdio/http/sse transports; package pinning for npx/uvx/pipx/docker; inline secrets; auth headers. "
        "MCP server source: Python decorator-based tools (FastMCP / mcp SDK) and JS/TS server.tool/registerTool. "
        "Dynamic tool lists (tools generated at runtime) are not discovered statically."
    )

    def applies(self, ctx: AuditContext) -> bool:
        return True

    def populate(self, ctx: AuditContext) -> None:
        self._configs(ctx)
        self._python_servers(ctx)
        self._js_servers(ctx)
        self._pins(ctx)
        for s in ctx.inventory.mcp_servers:
            for t in s.tools:
                # infer from the name + first description line only: a poisoned description must not
                # be able to change how its own tool is classified
                first = t.description.strip().splitlines()[0] if t.description.strip() else ""
                ops = infer_operations(t.name, first)
                data = infer_data_access(t.name, first)
                ctx.inventory.add_tool(Tool(
                    name=t.name, source=f"mcp:{s.name}", file=t.file, line=t.line, description=t.description,
                    operations=ops, data_access=data, sensitivity=sensitivity_for(data),
                    permission_provenance="inferred", mcp_server=s.name))
        if ctx.inventory.mcp_servers and "mcp" not in ctx.inventory.frameworks:
            ctx.inventory.frameworks.append("mcp")

    # -- client configuration ------------------------------------------------------------
    def _configs(self, ctx: AuditContext) -> None:
        for f, doc in ctx.structured("json", "yaml"):
            name = f.rel.rsplit("/", 1)[-1].lower()
            if not any(h in name for h in CONFIG_NAME_HINTS) and "mcpServers" not in f.text():
                continue
            servers = _servers_from(doc)
            if not servers:
                continue
            lines = f.lines()
            for sname, cfg in servers.items():
                line = _line_of(lines, f'"{sname}"') or _line_of(lines, f"{sname}:")
                ctx.inventory.mcp_servers.append(self._server(f.rel, line, str(sname), cfg))

    def _server(self, rel: str, line: int | None, name: str, cfg: dict[str, Any]) -> McpServer:
        url = cfg.get("url") or cfg.get("serverUrl")
        typ = str(cfg.get("type") or cfg.get("transport") or "").lower()
        if url:
            transport = "sse" if typ == "sse" or str(url).rstrip("/").endswith("/sse") else "http"
        elif cfg.get("command"):
            transport = "stdio"
        else:
            transport = "unknown"
        command = cfg.get("command")
        args = [str(a) for a in cfg.get("args", []) if isinstance(a, (str, int, float))] if isinstance(cfg.get("args"), list) else []
        env = cfg.get("env") if isinstance(cfg.get("env"), dict) else {}
        headers = cfg.get("headers") if isinstance(cfg.get("headers"), dict) else {}
        inline: list[str] = []
        for k, v in list(env.items()) + list(headers.items()):
            if not isinstance(v, str) or not v.strip() or VAR_REF.match(v):
                continue
            # header values like "Bearer ${TOKEN}" are references, not secrets
            if "${" in v or "$env" in v or "{env:" in v:
                continue
            if SECRETISH_KEY.search(str(k)) or find_secrets(f'{k}="{v}"'):
                inline.append(str(k))
        auth = "not_applicable" if transport == "stdio" else "none"
        if transport in ("http", "sse"):
            hk = {str(k).lower() for k in headers}
            if cfg.get("oauth") or cfg.get("auth") or cfg.get("authorization"):
                auth = "oauth"
            elif "authorization" in hk:
                auth = "bearer"
            elif any("key" in k or "token" in k for k in hk):
                auth = "api_key"
        pkg, pinned = _package_and_pin(str(command or ""), args) if command else (None, None)
        return McpServer(
            name=name, transport=transport, file=rel, line=line, command=str(command) if command else None,
            args=args, url=str(url) if url else None, package=pkg, version_pinned=pinned,
            env_keys=sorted(str(k) for k in env), inline_secret_keys=sorted(inline),
            header_keys=sorted(str(k) for k in headers), auth=auth,
            trusted=cfg.get("trusted") if isinstance(cfg.get("trusted"), bool) else None,
        )

    # -- server source --------------------------------------------------------------------
    def _python_servers(self, ctx: AuditContext) -> None:
        for f, tree in ctx.python_trees():
            imports = _imports(tree)
            if not any(m == "mcp" or m.startswith("mcp.") or m.startswith("fastmcp") for m in imports):
                continue
            tools: list[McpTool] = []
            for node in ast.walk(tree):
                if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                for dec in node.decorator_list:
                    cn = call_name(dec)
                    if cn.endswith(".tool") or cn.endswith(".tool()"):
                        desc = None
                        if isinstance(dec, ast.Call):
                            desc = literal(kwarg(dec, "description"))
                            tname = literal(kwarg(dec, "name")) or node.name
                        else:
                            tname = node.name
                        desc = desc or ast.get_docstring(node) or ""
                        tools.append(McpTool(str(tname), str(desc), f.rel, node.lineno))
            if not tools:
                continue
            server = self._match_server(ctx, f.rel)
            server.tools.extend(tools)

    def _js_servers(self, ctx: AuditContext) -> None:
        for f in ctx.discovery.by_kind("javascript", "typescript"):
            text = f.text()
            if "modelcontextprotocol" not in text and "McpServer" not in text and "fastmcp" not in text.lower():
                continue
            tools = []
            for m in JS_TOOL.finditer(text):
                desc = (m.group(2) or m.group(3) or "").encode("utf-8").decode("unicode_escape", errors="ignore")
                tools.append(McpTool(m.group(1), desc, f.rel, text.count("\n", 0, m.start()) + 1))
            if tools:
                self._match_server(ctx, f.rel).tools.extend(tools)

    def _match_server(self, ctx: AuditContext, rel: str) -> McpServer:
        base = rel.rsplit("/", 1)[-1]
        for s in ctx.inventory.mcp_servers:
            if any(a.endswith(rel) or a.endswith(base) for a in s.args) or (s.command or "").endswith(base):
                if s.file != rel:
                    return s
        stem = base.rsplit(".", 1)[0]
        srv = McpServer(name=f"{stem} (source)", transport="unknown", file=rel, line=1, auth="unknown")
        ctx.inventory.mcp_servers.append(srv)
        return srv

    def _pins(self, ctx: AuditContext) -> None:
        pins: dict[str, dict[str, str]] = dict(ctx.artifacts.get("mcp_tool_pins", {}))
        for f, doc in ctx.structured("json"):
            if f.rel.rsplit("/", 1)[-1] in ("mcp-tools.lock.json", ".mcp-tools.lock.json") and isinstance(doc, dict):
                servers = doc.get("servers", doc)
                for k, v in servers.items():
                    if isinstance(v, dict):
                        pins.setdefault(str(k), {}).update({str(a): str(b) for a, b in v.items()})
        ctx.artifacts["mcp_tool_pins"] = pins
        for s in ctx.inventory.mcp_servers:
            if s.name in pins:
                s.tool_hashes = pins[s.name]


def _imports(tree: ast.Module) -> list[str]:
    out = []
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            out.extend(a.name for a in n.names)
        elif isinstance(n, ast.ImportFrom) and n.module:
            out.append(n.module)
    return out


def _line_of(lines: list[str], needle: str) -> int | None:
    for i, ln in enumerate(lines, 1):
        if needle in ln:
            return i
    return None
