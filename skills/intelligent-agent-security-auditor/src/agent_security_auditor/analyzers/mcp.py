"""MODULE 06 - MCP Security Auditor.

Rules are transport-aware: HTTP authorization requirements (MCP-002/003, token audience) are
applied only to ``http``/``sse`` servers. For ``stdio`` servers the MCP specification says
credentials come from the environment, so the relevant checks are local-execution ones
(pinning, shell wrappers, filesystem scope, inline secrets).
"""

from __future__ import annotations

import re

from agent_security_auditor.adapters.mcp_config import description_hash
from agent_security_auditor.analyzers.base import AnalyzerResult, control, evidence_at, related, status_from
from agent_security_auditor.analyzers.prompt_injection import scan_hidden, scan_text
from agent_security_auditor.core.classify import classify_host
from agent_security_auditor.core.context import AuditContext
from agent_security_auditor.core.redaction import line_snippet
from agent_security_auditor.models.finding import Confidence, ControlStatus, Evidence, EvidenceType, FindingStatus, Severity
from agent_security_auditor.rules import make_finding
from agent_security_auditor.rules.references import ASI

POISON = (
    ("reads_sensitive_files", re.compile(r"(?i)(~/\.ssh|id_rsa|\.env\b|\.aws/credentials|mcp\.json|\.cursor/|passwd|private key)")),
    ("cross_tool_instruction", re.compile(r"(?i)\b(?:before|after|when)\s+(?:using|calling)\b[^.\n]{0,40}\b(?:tool|function)\b|\b(?:also|always|first)\s+(?:call|use|invoke|send)\b")),
    ("concealment", re.compile(r"(?i)\b(?:do not|don't|never)\s+(?:tell|inform|mention|reveal|show|notify)\b|\bwithout (?:telling|informing|notifying)\b|\bsilently\b")),
    ("hidden_tag", re.compile(r"(?i)<\s*(?:important|system|secret|hidden|instructions?|admin)\s*>")),
    ("parameter_smuggling", re.compile(r"(?i)\b(?:pass|include|put|add)\b[^.\n]{0,50}\b(?:in|into|as)\b[^.\n]{0,20}\b(?:the )?(?:sidenote|note|comment|metadata|parameter|argument)\b")),
)
BROAD_ROOTS = ("/", "~", "$HOME", "${HOME}", "C:\\", "C:/", "%USERPROFILE%", "/Users", "/home")
SHELLS = ("sh", "bash", "zsh", "cmd", "cmd.exe", "powershell", "pwsh")
FETCH_SERVERS = ("server-fetch", "mcp-server-fetch", "fetch-mcp", "puppeteer", "playwright", "browser")
TOKEN_FWD = re.compile(
    r"""(?is)(?:headers|request\.headers|req\.headers)\s*(?:\.get\s*\(|\[)\s*["']authorization["'].{0,400}?(?:requests|httpx|fetch|axios|session|client)\s*\.?\s*(?:get|post|put|patch|request|\()""")


class McpAnalyzer:
    module_id = "M06"
    name = "MCP Security Auditor"
    implementation = "implemented"

    def analyze(self, ctx: AuditContext) -> AnalyzerResult:
        res = AnalyzerResult()
        inv = ctx.inventory
        trust = ctx.artifacts.get("mcp_trust", {})
        trusted_names = set(ctx.policy.trusted_mcp_servers) | {k for k, v in trust.items() if v.get("trusted") is True}

        for s in inv.mcp_servers:
            ev_loc = evidence_at(ctx, s.file, s.line, EvidenceType.CONFIGURATION)
            asset = f"mcp:{s.name}"
            if s.version_pinned is False:
                res.findings.append(make_finding(
                    "MCP-001", asset, [_with_note(ev_loc, f"launch: {s.command} {' '.join(s.args)[:120]}; package={s.package}")],
                    FindingStatus.CONFIRMED, Confidence.HIGH))
            if s.transport in ("http", "sse") and s.url:
                host, cls = classify_host(s.url)
                if s.url.lower().startswith("http://") and cls not in ("loopback",):
                    res.findings.append(make_finding("MCP-002", asset, [_with_note(ev_loc, f"url host={host}")],
                                                     FindingStatus.CONFIRMED, Confidence.HIGH))
                if s.auth == "none":
                    res.findings.append(make_finding(
                        "MCP-003", asset, [_with_note(ev_loc, f"transport={s.transport}; no oauth/authorization/api-key configured")],
                        FindingStatus.POTENTIAL, Confidence.MEDIUM,
                        severity=Severity.LOW if cls == "loopback" else Severity.MEDIUM))
            for k in s.inline_secret_keys:
                res.findings.append(make_finding(
                    # no snippet: the value may not match any secret pattern, so it cannot be redacted reliably
                    "MCP-004", asset, [Evidence(EvidenceType.CONFIGURATION, s.file, _line(ctx, s.file, k), None,
                                                f"key {k} holds a literal value (value not shown)")],
                    FindingStatus.CONFIRMED, Confidence.HIGH, discriminator=k))
            # filesystem / fetch scope
            if s.transport == "stdio":
                pkg = (s.package or "") + " " + " ".join(s.args)
                if "filesystem" in pkg:
                    roots = [a for a in s.args if a in BROAD_ROOTS or a.rstrip("/") in ("/Users", "/home") or a in ("~/", "$HOME/")]
                    if roots:
                        res.findings.append(make_finding(
                            "MCP-008", asset, [_with_note(ev_loc, f"filesystem roots: {roots}")],
                            FindingStatus.CONFIRMED, Confidence.HIGH, discriminator="fs"))
                if any(fs in pkg for fs in FETCH_SERVERS):
                    res.findings.append(make_finding(
                        "MCP-008", asset, [_with_note(ev_loc, "unrestricted fetch/browser server")],
                        FindingStatus.POTENTIAL, Confidence.MEDIUM, severity=Severity.MEDIUM, discriminator="fetch"))
                cmd = (s.command or "").rsplit("/", 1)[-1].lower()
                if cmd in SHELLS and any(a in ("-c", "/c", "-Command") for a in s.args):
                    res.findings.append(make_finding("MCP-009", asset, [_with_note(ev_loc, f"{cmd} -c wrapper")],
                                                     FindingStatus.CONFIRMED, Confidence.HIGH))
            if s.name not in trusted_names and s.trusted is not True and s.transport != "unknown":
                res.findings.append(make_finding(
                    "MCP-011", asset, [_with_note(ev_loc, "server not marked trusted in policy/manifest")],
                    FindingStatus.OBSERVATION, Confidence.HIGH))
            # tool definitions
            for tool in s.tools:
                text = f"{tool.name}\n{tool.description}"
                techs = sorted({h[0] for h in scan_text(text)} | {h[0] for h in scan_hidden(text)} |
                               {name for name, pat in POISON if pat.search(tool.description)})
                if techs:
                    sf = ctx.discovery.get(tool.file) if tool.file else None
                    res.findings.append(make_finding(
                        "MCP-005", f"mcp-tool:{s.name}/{tool.name}",
                        [Evidence(EvidenceType.CODE, tool.file, tool.line, line_snippet(sf.lines(), tool.line, 1) if sf else None,
                                  f"indicators: {', '.join(techs)}")],
                        FindingStatus.POTENTIAL, Confidence.HIGH if len(techs) >= 2 else Confidence.MEDIUM,
                        detail=f"Indicators: {', '.join(techs)}.", trust_boundary="TB-MCP", discriminator=tool.name))
                pinned = s.tool_hashes.get(tool.name)
                if pinned and pinned != description_hash(tool.description):
                    res.findings.append(make_finding(
                        "MCP-007", f"mcp-tool:{s.name}/{tool.name}",
                        [Evidence(EvidenceType.CODE, tool.file, tool.line, None,
                                  f"pinned {pinned[:19]}…, current {description_hash(tool.description)[:19]}…")],
                        FindingStatus.CONFIRMED, Confidence.HIGH, trust_boundary="TB-MCP", discriminator=tool.name))

        # server source code checks: token passthrough, bind address
        for f in ctx.discovery.by_kind("python", "javascript", "typescript"):
            text = f.text()
            if "mcp" not in text.lower():
                continue
            m = TOKEN_FWD.search(text)
            if m:
                line = text.count("\n", 0, m.start()) + 1
                res.findings.append(make_finding(
                    "MCP-006", f"file:{f.rel}", [Evidence(EvidenceType.CODE, f.rel, line, line_snippet(f.lines(), line),
                                                          "incoming Authorization header reused in outbound request")],
                    FindingStatus.POTENTIAL, Confidence.LOW))
            m = re.search(r"""(?:host\s*=\s*|listen\(\s*\d+\s*,\s*|--host[\s=]+)["']?0\.0\.0\.0""", text)
            if m:
                line = text.count("\n", 0, m.start()) + 1
                res.findings.append(make_finding(
                    "MCP-010", f"file:{f.rel}", [Evidence(EvidenceType.CODE, f.rel, line, line_snippet(f.lines(), line), "bind 0.0.0.0")],
                    FindingStatus.CONFIRMED, Confidence.MEDIUM))

        # --- controls ---------------------------------------------------------------------
        servers = inv.mcp_servers
        na = (ControlStatus.NOT_APPLICABLE, "No MCP servers.")
        m1 = related(res.findings, "MCP-001", "MCP-007")
        res.controls.append(control("CTRL-MCP-01", "MCP servers version-pinned and definitions unchanged", "M06",
                                    *(_c(m1, servers, "All MCP servers pinned or local.") if servers else na),
                                    related=m1, owasp=[ASI["ASI04"]]))
        http = [s for s in servers if s.transport in ("http", "sse")]
        m2 = related(res.findings, "MCP-002", "MCP-003", "MCP-006", "MCP-010")
        res.controls.append(control(
            "CTRL-MCP-02", "Remote MCP transport secured and authenticated", "M06",
            *(_c(m2, http, f"{len(http)} remote server(s) use TLS and configured auth.") if http else
              (ControlStatus.NOT_APPLICABLE, "No HTTP/SSE servers (STDIO credentials come from the environment).")),
            related=m2, owasp=[ASI["ASI03"]]))
        m3 = related(res.findings, "MCP-004")
        res.controls.append(control("CTRL-MCP-03", "MCP credentials referenced, not inline", "M06",
                                    *(_c(m3, servers, "Only environment/secret references found.") if servers else na),
                                    related=m3, owasp=[ASI["ASI03"]]))
        m4 = related(res.findings, "MCP-005")
        defined = [s for s in servers if s.tools]
        if not servers:
            c4 = na
        elif m4:
            c4 = (ControlStatus.FAILED, f"{len(m4)} tool description(s) contain poisoning indicators.")
        elif len(defined) == len(servers):
            c4 = (ControlStatus.PASSED, f"{sum(len(s.tools) for s in servers)} tool definition(s) scanned.")
        else:
            missing = [s.name for s in servers if not s.tools]
            c4 = (ControlStatus.NOT_VERIFIED, f"Tool definitions not available statically for: {', '.join(missing)} "
                                               "(package/remote servers). Pin descriptions in mcp-tools.lock.json.")
        res.controls.append(control("CTRL-MCP-04", "MCP tool definitions free of poisoning", "M06", c4[0], c4[1],
                                    related=m4, owasp=[ASI["ASI04"], ASI["ASI01"]]))
        m5 = related(res.findings, "MCP-008", "MCP-009")
        res.controls.append(control("CTRL-MCP-05", "MCP server scope and launch restricted", "M06",
                                    *(_c(m5, servers, "No broad roots, fetch servers or shell wrappers.") if servers else na),
                                    related=m5, owasp=[ASI["ASI02"]]))
        res.limitations.append("Tool definitions of package-based or remote MCP servers are not fetched (no network, no "
                               "execution); poisoning checks for them require a pinned description lock file.")
        return res


def _c(findings, items, ok: str) -> tuple[ControlStatus, str]:
    st = status_from(findings)
    if st:
        return st, f"{len(findings)} issue(s)."
    return ControlStatus.PASSED, ok


def _with_note(ev: Evidence, note: str) -> Evidence:
    return Evidence(ev.type, ev.file, ev.line, ev.snippet, note)


def _line(ctx: AuditContext, rel: str | None, needle: str) -> int | None:
    if not rel:
        return None
    sf = ctx.discovery.get(rel)
    if not sf:
        return None
    for i, ln in enumerate(sf.lines(), 1):
        if needle in ln:
            return i
    return None
