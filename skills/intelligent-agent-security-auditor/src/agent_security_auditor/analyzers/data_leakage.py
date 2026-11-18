"""MODULE 03 - Data Leakage Auditor.

Secrets (redacted), sensitive logging, uncontrolled source->sink flows, committed env files
and cross-tenant access. Secret values are never stored: only type, location and length.
"""

from __future__ import annotations

import ast
import re

from agent_security_auditor.analyzers.base import AnalyzerResult, control, related, status_from
from agent_security_auditor.core.classify import host_matches
from agent_security_auditor.core.context import AuditContext
from agent_security_auditor.core.parsing import call_name
from agent_security_auditor.core.redaction import find_secrets, line_snippet
from agent_security_auditor.models.finding import (
    Confidence,
    ControlStatus,
    Evidence,
    EvidenceType,
    FindingStatus,
    Severity,
)
from agent_security_auditor.rules import make_finding
from agent_security_auditor.rules.references import ASI

LOG_CALLS = {"debug", "info", "warning", "warn", "error", "exception", "critical", "log", "print"}
SENSITIVE_NAME = re.compile(r"(?i)(password|passwd|secret|token|api_?key|credential|ssn|card|iban|"
                            r"prompt|messages|history|memory|tool_result|tool_output|response_body|email_body|"
                            r"document_text|payload|pii|personal)")
#: wrappers whose result is metadata, not content: logging len(messages) does not leak messages
METADATA_CALLS = {"len", "type", "id", "hash", "bool", "sum", "count", "isinstance", "sha256", "hexdigest", "redact", "mask"}


def _logged_names(node: ast.AST, out: set[str]) -> None:
    if isinstance(node, ast.Call) and call_name(node).split(".")[-1] in METADATA_CALLS:
        return
    if isinstance(node, ast.Name):
        out.add(node.id)
    elif isinstance(node, ast.Attribute):
        out.add(node.attr)
    for child in ast.iter_child_nodes(node):
        _logged_names(child, out)


ENV_ASSIGN = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+?)\s*$")


class DataLeakageAnalyzer:
    module_id = "M03"
    name = "Data Leakage Auditor"
    implementation = "implemented"

    def analyze(self, ctx: AuditContext) -> AnalyzerResult:
        res = AnalyzerResult()
        inv = ctx.inventory

        # DATA-001 secrets in any text file
        secret_files = 0
        for f in ctx.files:
            if f.kind == "env":
                continue  # handled by DATA-004
            text = f.text()
            matches = find_secrets(text)
            if not matches:
                continue
            secret_files += 1
            lines = f.lines()
            for m in matches:
                line = text.count("\n", 0, m.start) + 1
                sev = Severity(m.severity)
                res.findings.append(make_finding(
                    "DATA-001", f"file:{f.rel}",
                    [Evidence(EvidenceType.CODE if f.kind in ("python", "javascript", "typescript") else EvidenceType.CONFIGURATION,
                              f.rel, line, line_snippet(lines, line), f"type={m.kind}, length={m.value_len} (value redacted)")],
                    FindingStatus.CONFIRMED, Confidence.HIGH if m.kind != "generic_assignment" else Confidence.MEDIUM,
                    severity=sev, detail=f"Secret type: {m.kind}.", discriminator=f"{m.kind}:{line}"))

        # DATA-004 env files with real-looking values
        for f in ctx.discovery.by_kind("env"):
            name = f.rel.rsplit("/", 1)[-1]
            if name.endswith((".example", ".sample", ".template", ".dist")):
                continue
            filled = []
            for i, ln in enumerate(f.lines(), 1):
                m = ENV_ASSIGN.match(ln)
                if m and not ln.lstrip().startswith("#"):
                    val = m.group(2).strip("'\"")
                    from agent_security_auditor.core.redaction import is_placeholder
                    if val and not is_placeholder(val):
                        filled.append((i, m.group(1)))
            if filled:
                sens = [k for _, k in filled if re.search(r"(?i)key|token|secret|pass|cred", k)]
                res.findings.append(make_finding(
                    "DATA-004", f"file:{f.rel}",
                    [Evidence(EvidenceType.CONFIGURATION, f.rel, filled[0][0], None,
                              f"{len(filled)} assigned variable(s): {', '.join(k for _, k in filled[:8])} (values not shown)")],
                    FindingStatus.CONFIRMED, Confidence.HIGH,
                    severity=Severity.HIGH if sens else Severity.MEDIUM))

        # DATA-002 sensitive logging (AST)
        for f, tree in ctx.python_trees():
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                cn = call_name(node)
                last = cn.split(".")[-1]
                if last not in LOG_CALLS or (last == "log" and "logger" not in cn and "logging" not in cn):
                    continue
                if last != "print" and not any(x in cn.lower() for x in ("log", "logger", "logging")):
                    continue
                names: set[str] = set()
                for arg in node.args:
                    _logged_names(arg, names)
                hits = sorted(n for n in names if SENSITIVE_NAME.search(n))
                if hits:
                    res.findings.append(make_finding(
                        "DATA-002", f"file:{f.rel}",
                        [Evidence(EvidenceType.CODE, f.rel, node.lineno, line_snippet(f.lines(), node.lineno),
                                  f"logged variables: {', '.join(hits)}")],
                        FindingStatus.POTENTIAL, Confidence.MEDIUM, discriminator=f"{node.lineno}"))

        # DATA-003 uncontrolled sensitive -> egress flows (uses M01 data-flow artifact)
        allow = list(ctx.policy.allowed_network_destinations) + list(inv.declared_allowed_destinations)
        flows = ctx.artifacts.get("data_flows", [])
        uncontrolled = [fl for fl in flows if fl["sensitivity"] and not fl["controls"]]
        by_sink: dict[str, list[dict]] = {}
        for fl in uncontrolled:
            by_sink.setdefault(fl["sink"], []).append(fl)
        for sink, fls in sorted(by_sink.items()):
            t = inv.tool(sink)
            srcs = sorted({fl["source"] for fl in fls})
            restricted = set(ctx.policy.restricted_data)
            touches_restricted = any(set(fl["sensitivity"]) & restricted for fl in fls)
            res.findings.append(make_finding(
                "DATA-003", f"tool:{sink}",
                [Evidence(EvidenceType.INFERENCE, t.file if t else None, t.line if t else None, None,
                          f"sources: {', '.join(srcs)} -> sink: {sink} -> {fls[0]['destination']}; no approval, not allowlisted")],
                FindingStatus.POTENTIAL, Confidence.MEDIUM,
                severity=Severity.HIGH if touches_restricted or not restricted else Severity.MEDIUM,
                detail=f"Sensitive sources: {', '.join(srcs)}.", trust_boundary="TB-TOOLS -> TB-NETWORK",
                discriminator=sink))

        # DATA-005 cross-tenant
        if inv.multi_user:
            for t in inv.tools:
                if "database" in t.data_access and t.tenant_scoped is not True:
                    res.findings.append(make_finding(
                        "DATA-005", f"tool:{t.name}",
                        [Evidence(EvidenceType.DECLARATION, t.file, t.line, None,
                                  f"deployment.multi_user=true; tool tenant_scoped={t.tenant_scoped}")],
                        FindingStatus.CONFIRMED if t.tenant_scoped is False else FindingStatus.POTENTIAL,
                        Confidence.HIGH if t.tenant_scoped is False else Confidence.MEDIUM, discriminator=t.name))

        # --- controls ---------------------------------------------------------------------
        sec = related(res.findings, "DATA-001", "DATA-004")
        res.controls.append(control(
            "CTRL-DATA-01", "No hard-coded secrets in agent code or configuration", "M03",
            status_from(sec) or ControlStatus.PASSED,
            f"{len(ctx.files)} file(s) scanned with {len(sec)} secret finding(s)." if sec else
            f"No secret patterns in {len(ctx.files)} scanned file(s) (pattern-based; see limitations).",
            [Evidence(EvidenceType.ABSENCE, note=f"{len(ctx.files)} files scanned")] if not sec else [],
            related=sec, owasp=[ASI["ASI03"]]))
        d3 = related(res.findings, "DATA-003")
        has_flow = bool(flows)
        res.controls.append(control(
            "CTRL-DATA-02", "Sensitive data egress controlled (approval or allowlist)", "M03",
            status_from(d3) or (ControlStatus.PASSED if has_flow else ControlStatus.NOT_APPLICABLE),
            f"{len(uncontrolled)} uncontrolled sensitive flow(s) of {len(flows)}." if has_flow else "No source->egress flows.",
            related=d3, owasp=[ASI["ASI02"]]))
        d2 = related(res.findings, "DATA-002")
        res.controls.append(control(
            "CTRL-DATA-03", "Sensitive content not written to logs", "M03",
            status_from(d2) or ControlStatus.NOT_VERIFIED,
            "Sensitive variables logged." if d2 else "No indicator found by heuristic; log content can only be verified "
                                                    "by a dynamic canary test.", related=d2))
        d5 = related(res.findings, "DATA-005")
        dbt = [t for t in inv.tools if "database" in t.data_access]
        if not dbt or inv.multi_user is False:
            c5 = (ControlStatus.NOT_APPLICABLE, "No shared data stores or single-user deployment declared.")
        elif d5:
            c5 = (status_from(d5) or ControlStatus.FAILED, "Data tools are not tenant-scoped in a multi-user deployment.")
        elif inv.multi_user and all(t.tenant_scoped for t in dbt):
            c5 = (ControlStatus.PASSED, "All data tools declare tenant scoping.")
        else:
            c5 = (ControlStatus.NOT_VERIFIED, "Deployment model (multi-user) or tenant scoping not declared.")
        res.controls.append(control("CTRL-DATA-04", "User/tenant isolation for data access", "M03", c5[0], c5[1],
                                    related=d5, owasp=[ASI["ASI03"]]))
        res.limitations.append("Secret detection is pattern/entropy based; custom formats and secrets split across lines "
                               "are missed. Values containing placeholder markers (e.g. 'example', 'test') are ignored.")
        return res
