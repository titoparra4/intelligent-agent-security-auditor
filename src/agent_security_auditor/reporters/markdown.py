"""Markdown report (MODULE 12) - the 19 mandated sections."""

from __future__ import annotations

from typing import Any

from agent_security_auditor.models.assessment import Assessment
from agent_security_auditor.models.finding import ControlStatus, FindingStatus

SEV_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


def _esc(v: Any) -> str:
    s = "" if v is None else str(v)
    return s.replace("|", "\\|").replace("\n", " ").replace("`", "'")


def _code(v: Any) -> str:
    s = "" if v is None else str(v).replace("`", "'")
    return f"`{s}`" if s else ""


def _table(headers: list[str], rows: list[list[Any]]) -> list[str]:
    out = ["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
    for r in rows:
        out.append("| " + " | ".join(_esc(c) for c in r) + " |")
    if not rows:
        out.append("| " + " | ".join(["—"] * len(headers)) + " |")
    return out


def render_markdown(a: Assessment) -> str:
    r = a.readiness
    s = a.summary()
    inv = a.inventory
    L: list[str] = []
    L += [f"# Agent Security Assessment — {a.target_name}", ""]
    L += [f"> {a.disclaimer}", ""]
    L += _table(["Field", "Value"], [
        ["Assessment ID", a.assessment_id], ["Target", a.target_name], ["Mode", a.mode.value.upper()],
        ["Readiness", r.verdict.value if r else "—"],
        ["Security score", f"{a.score.get('score')} (band {a.score.get('score_band')}, grade {a.score.get('grade')})"],
        ["Assessment coverage", f"{a.score.get('coverage_percent')}% of applicable controls verified "
                                f"({a.score.get('controls_verified')}/{a.score.get('controls_applicable')})"],
        ["Policy", f"{a.policy.get('name')} v{a.policy.get('policy_version')} ({a.policy.get('source')})"],
        ["Tool", f"intelligent-agent-security-auditor {a.tool_version} (schema {a.schema_version})"],
        ["Started / finished", f"{a.started_at} / {a.finished_at}"],
    ])
    L.append("")

    # 1
    L += ["## 1. Executive Security Summary", ""]
    L.append(f"**Readiness: `{r.verdict.value}`** — " + "; ".join(r.reasons) if r else "")
    L.append("")
    L.append(f"Findings: **{s['total_findings']}** — " + ", ".join(f"{k} {v}" for k, v in s["by_severity"].items() if v)
             + " · by status: " + ", ".join(f"{k} {v}" for k, v in s["by_status"].items() if v))
    L.append("")
    top = [f for f in a.findings if f.status in (FindingStatus.CONFIRMED, FindingStatus.POTENTIAL)][:5]
    if top:
        L.append("Top risks:")
        for f in top:
            L.append(f"- **{f.display_id} — {f.title} — {f.severity.value}** ({f.status.value}, confidence {f.confidence.value}) — {_esc(f.asset)}")
        L.append("")
    L.append(f"_Score is an indicator only. {r.scope_statement if r else ''}_")
    L.append("")

    # 2
    L += ["## 2. Agent Architecture Overview", ""]
    L += _table(["Agent", "Framework", "Model", "Tools", "Sub-agents", "Max iterations", "Source"], [
        [ag["name"], ag["framework"], ag.get("model") or "UNKNOWN", ", ".join(ag.get("tools", [])) or "—",
         ", ".join(ag.get("sub_agents", [])) or "—", ag.get("max_iterations") or "not set",
         f"{ag.get('file') or ''}:{ag.get('line') or ''}"] for ag in inv.get("agents", [])])
    L.append("")
    L.append(f"Frameworks: {', '.join(inv.get('frameworks', [])) or 'none detected'} · Manifest: {inv.get('manifest_file') or 'none'} · "
             f"MCP servers: {len(inv.get('mcp_servers', []))} · Memory stores: {len(inv.get('memory', []))} · "
             f"Network destinations: {len({d['host'] for d in inv.get('network', [])})}")
    L.append("")
    if a.threat_model.get("dataflow_mermaid"):
        L += ["Data-flow diagram:", "", "```mermaid", a.threat_model["dataflow_mermaid"], "```", ""]

    # 3
    sc = a.scope
    L += ["## 3. Evaluated Scope", ""]
    L += _table(["Item", "Value"], [
        ["Files analysed", sc.get("files_scanned")], ["Files skipped", sc.get("files_skipped")],
        ["Parse errors", len(sc.get("parse_errors", []))], ["Network access", sc.get("network_access")],
        ["Executed target code", sc.get("executed_target_code")], ["Vulnerability DB", sc.get("vulnerability_database")],
        ["Frameworks", ", ".join(sc.get("frameworks_detected", [])) or "—"],
        ["Host capabilities", ", ".join(sc.get("host_capabilities_declared", []))],
    ])
    L.append("")
    L += _table(["Adapter", "Used", "Coverage"], [[ad["name"], ad["used"], ad["coverage"]] for ad in sc.get("adapters", [])])
    L.append("")
    L += _table(["Module", "Name", "Ran", "Findings", "Controls", "Implementation / note"],
                [[m["module"], m["name"], m["ran"], m["findings"], m["controls"], m.get("note") or m["implementation"]]
                 for m in a.module_status])
    L.append("")

    # 4
    L += ["## 4. Asset & Permission Inventory", ""]
    L += _table(["Tool", "Identity", "Permissions", "Data Access", "Operations", "Risk", "Required Approval", "Provenance"], [
        [p["tool"], p["identity"], ", ".join(p["permissions"]), ", ".join(p["data_access"]) or "—",
         ", ".join(p["operations"]) or "—", p["risk"], p["required_approval"] + (f" ({p['approval_provenance']})" if p.get("approval_provenance") else ""),
         p["permission_provenance"]] for p in a.permission_matrix])
    L.append("")
    if inv.get("mcp_servers"):
        L += _table(["MCP server", "Transport", "Launch / URL", "Pinned", "Auth", "Tools", "Source"], [
            [m["name"], m["transport"], (m.get("url") or f"{m.get('command') or ''} {' '.join(m.get('args', []))}")[:80],
             m.get("version_pinned"), m.get("auth"), len(m.get("tools", [])), f"{m.get('file')}:{m.get('line')}"]
            for m in inv["mcp_servers"]])
        L.append("")
    if inv.get("memory"):
        L += _table(["Memory", "Kind", "Scope", "TTL", "Provenance tracking", "Injected into"], [
            [m["name"], m["kind"], m["scope"], m.get("ttl") or "none", m.get("provenance_tracking"), m.get("injected_into") or "—"]
            for m in inv["memory"]])
        L.append("")

    # 5
    tm = a.threat_model
    L += ["## 5. Threat Model", ""]
    L += _table(["Trust boundary", "Crossing"], [[f"{t['id']} {t['name']}", t["crosses"]] for t in tm.get("trust_boundaries", [])])
    L.append("")
    L += _table(["Actor", "Trust"], [[x["actor"], x["trust"]] for x in tm.get("actors", [])])
    L.append("")
    L += _table(["ID", "Threat", "OWASP", "Surface", "Scenario"],
                [[t["id"], t["title"], t["owasp"], t["surface"], t["scenario"]] for t in tm.get("threats", [])])
    L.append("")

    # 6
    L += ["## 6. OWASP Risk Coverage Matrix", ""]
    rows = []
    from agent_security_auditor.rules.references import ASI
    for key, name in ASI.items():
        fs = [f for f in a.findings if name in f.owasp_references]
        cs = [c for c in a.controls if name in c.owasp_references]
        rows.append([name, len(fs), ", ".join(sorted({f.severity.value for f in fs})) or "—",
                     ", ".join(f"{c.control_id}={c.status.value}" for c in cs) or "no mapped control"])
    L += _table(["OWASP Agentic 2026", "Findings", "Severities", "Controls"], rows)
    L.append("")
    L += ["15-dimension coverage:", ""]
    L += _table(["Dimension", "Relevance", "Findings", "Open HIGH+", "Controls", "Modules"], [
        [d["name"], f"{d['relevance']} — {d['relevance_reason']}", d["findings"], d["open_high_or_critical"],
         ", ".join(f"{k}={v}" for k, v in d["control_status"].items()) or "—", ", ".join(d["modules"])]
        for d in a.dimension_coverage])
    L.append("")

    # 7
    L += ["## 7. Findings by Severity", ""]
    if not a.findings:
        L.append("No findings. This does **not** mean the agent is secure — see sections 10 and 18.")
    for sev in SEV_ORDER:
        group = [f for f in a.findings if f.severity.value == sev]
        if not group:
            continue
        L += [f"### {sev}", ""]
        for f in group:
            L += [f"#### {f.display_id} — {f.title} — {f.severity.value}", ""]
            L += _table(["Field", "Value"], [
                ["Finding ID (stable)", f.finding_id], ["Rule / module", f"{f.rule_id} / {f.module}"],
                ["Status / confidence", f"{f.status.value} / {f.confidence.value}"], ["Likelihood", f.likelihood.value],
                ["Category", f.category], ["Asset", f.asset],
                ["Location", f"{f.source_file}:{f.source_line}" if f.source_file else "—"],
                ["Trust boundary", f.trust_boundary or "—"],
                ["Affected permissions", ", ".join(f.affected_permissions) or "—"],
                ["OWASP", "; ".join(f.owasp_references) or "—"], ["NIST", "; ".join(f.nist_references) or "—"],
                ["Other", "; ".join(f.other_references) or "—"],
                ["Accepted risk", f"by {f.accepted_risk['owner']} until {f.accepted_risk['expires']}" if f.accepted_risk else "no"],
            ])
            L += ["", f"**Description.** {f.description}", ""]
            L += ["**Evidence.**", ""]
            for ev in f.evidence:
                loc = f"{ev.file}:{ev.line}" if ev.file else "(no file)"
                L.append(f"- `{ev.type.value}` {loc}" + (f" — {ev.note}" if ev.note else ""))
                if ev.snippet:
                    L += ["", "  ```", "  " + ev.snippet.replace("\n", "\n  "), "  ```"]
            L += ["", "**Exploitation preconditions.**", ""] + [f"- {p}" for p in f.attack_preconditions]
            L += ["", f"**Impact.** {f.impact}", "", f"**Remediation.** {f.remediation}", ""]
            L += ["**Verification after fix.**", ""] + [f"- {v}" for v in f.verification_steps]
            if f.requires_specialized_review:
                L += ["", "_Recommend a specialized code review (e.g. secure-code-reviewer) for this finding._"]
            L.append("")

    # 8
    L += ["## 8. Evidence Register", ""]
    rows = []
    for f in a.findings:
        for ev in f.evidence:
            rows.append([f.display_id, f.rule_id, ev.type.value, f"{ev.file or '—'}:{ev.line or ''}", _esc(ev.note)[:140]])
    L += _table(["Finding", "Rule", "Evidence type", "Location", "Note (sanitized)"], rows)
    L.append("")

    # 9 / 10
    passed = [c for c in a.controls if c.status in (ControlStatus.PASSED, ControlStatus.FAILED)]
    L += ["## 9. Controls Verified", ""]
    L += _table(["Control", "Title", "Kind", "Mandatory", "Status", "Rationale"],
                [[c.control_id, c.title, c.kind, "yes" if c.mandatory else "", c.status.value, c.rationale] for c in passed])
    L.append("")
    nv = [c for c in a.controls if c.status not in (ControlStatus.PASSED, ControlStatus.FAILED)]
    L += ["## 10. Controls Not Verified", "",
          "`NOT_VERIFIED`/`INSUFFICIENT_EVIDENCE` controls are **not** approved. `NOT_APPLICABLE` means the capability does not exist.", ""]
    L += _table(["Control", "Title", "Kind", "Mandatory", "Status", "Why"],
                [[c.control_id, c.title, c.kind, "yes" if c.mandatory else "", c.status.value, c.rationale] for c in nv])
    L.append("")

    # 11
    L += ["## 11. Data Exfiltration Risk Analysis", ""]
    L += _table(["Source", "Data", "Sensitivity", "Sink", "Destination", "Class", "Controls", "Risk"], [
        [fl["source"], ", ".join(fl["source_data"]), ", ".join(fl["sensitivity"]) or "—", fl["sink"], fl["destination"],
         fl["destination_class"], ", ".join(fl["controls"]) or "NONE", fl["risk"]] for fl in a.data_flows[:40]])
    L.append("")
    L += _table(["Host", "Class", "Method", "Payload", "Allowlisted", "Location"], [
        [e["host"], e["class"], e.get("method") or "—", e["payload"], e["allowlisted"], f"{e.get('file')}:{e.get('line')}"]
        for e in a.threat_model.get("egress_inventory", [])[:40]])
    L.append("")

    # 12
    L += ["## 12. MCP Security Assessment", ""]
    mcp_c = [c for c in a.controls if c.module == "M06"]
    mcp_f = [f for f in a.findings if f.module == "M06"]
    if not inv.get("mcp_servers"):
        L.append("No MCP clients/servers detected (controls NOT_APPLICABLE).")
    L += _table(["Control", "Status", "Rationale"], [[c.control_id + " " + c.title, c.status.value, c.rationale] for c in mcp_c])
    L.append("")
    L += _table(["Finding", "Title", "Severity", "Asset"], [[f.display_id, f.title, f.severity.value, f.asset] for f in mcp_f])
    L.append("")

    # 13
    L += ["## 13. Autonomous Action Assessment", ""]
    L += _table(["Control", "Status", "Rationale"],
                [[c.control_id + " " + c.title, c.status.value, c.rationale] for c in a.controls if c.module == "M09"])
    L.append("")
    L += _table(["Finding", "Title", "Severity", "Status", "Asset"],
                [[f.display_id, f.title, f.severity.value, f.status.value, f.asset] for f in a.findings if f.module == "M09"])
    L.append("")

    # 14
    sc2 = a.score
    L += ["## 14. Security Score", ""]
    L.append(f"**{sc2.get('score')} / 100** (band {sc2.get('score_band')}, grade {sc2.get('grade')}) · coverage "
             f"**{sc2.get('coverage_percent')}%**" + (" · critical cap applied" if sc2.get("critical_cap_applied") else ""))
    L.append("")
    L += _table(["Module", "Deduction"], [[m, d] for m, d in sorted(sc2.get("deductions_by_module", {}).items())])
    L += ["", f"_{sc2.get('note')}_", ""]

    # 15
    L += ["## 15. Agent Security Readiness Assessment", ""]
    if r:
        L += _table(["Item", "Value"], [
            ["Verdict", r.verdict.value], ["Reasons", "; ".join(r.reasons)],
            ["Blocking / unaccepted findings", ", ".join(_disp(a, i) for i in r.blocking_findings) or "none"],
            ["Failed mandatory controls", ", ".join(r.failed_mandatory_controls) or "none"],
            ["Unverified mandatory controls", ", ".join(r.unverified_mandatory_controls) or "none"],
            ["Accepted risks", len(r.accepted_risks)], ["Expired exceptions (ignored)", len(r.expired_exceptions)],
            ["Scope", r.scope_statement]])
    L.append("")

    # 16
    L += ["## 16. Prioritized Remediation Plan", ""]
    prio = [f for f in a.findings if f.status in (FindingStatus.CONFIRMED, FindingStatus.POTENTIAL) and f.is_open]
    blocking = set(r.blocking_findings) if r else set()
    L += _table(["Priority", "Finding", "Title", "Severity", "Status", "Action"], [
        ["P1 (blocking)" if f.finding_id in blocking and f.severity.rank >= 3 else "P1" if f.severity.rank >= 4 else
         "P2" if f.severity.rank >= 3 or f.finding_id in blocking else "P3",
         f.display_id, f.title, f.severity.value, f.status.value, f.remediation[:180]] for f in prio])
    L.append("")

    # 17
    L += ["## 17. Retest Plan", ""]
    L.append("Re-run: `agent-security-auditor audit <target> --policy <policy> --baseline <this-report>.json` and verify:")
    L.append("")
    for f in prio[:25]:
        L.append(f"- **{f.display_id}** ({f.rule_id}): " + " / ".join(f.verification_steps))
    applicable = [t for t in a.test_plan if t["applicable"]]
    if applicable:
        L += ["", "Controlled dynamic scenarios to execute in an isolated sandbox:", ""]
        L += _table(["Test ID", "Objective", "Preconditions", "Synthetic Input", "Expected Behavior", "Evidence", "Result"], [
            [t["test_id"], t["objective"], t["preconditions"], t["synthetic_input"], t["expected_behavior"], t["evidence"],
             t["result"] + (f" — {t['observed']}" if t.get("observed") else "")] for t in a.test_plan])
    L.append("")

    # 18
    L += ["## 18. Residual Risks", ""]
    resid = [f for f in a.findings if f.accepted_risk]
    if resid:
        L += _table(["Finding", "Title", "Owner", "Approved by", "Justification", "Expires"], [
            [f.display_id, f.title, f.accepted_risk["owner"], f.accepted_risk["approved_by"], f.accepted_risk["justification"],
             f.accepted_risk["expires"]] for f in resid])
    else:
        L.append("No explicitly accepted risks.")
    L += ["", "Assessment limitations (risk that remains unassessed):", ""] + [f"- {x}" for x in a.limitations]
    L.append("")

    # 19
    L += ["## 19. Technical Appendix", ""]
    L += ["### Delegation graph", ""]
    dg = a.delegation_graph or {}
    L += _table(["From", "To", "Channel", "Authenticated", "Inherits permissions"], [
        [e["from"], e["to"], e.get("channel"), e.get("authenticated"), e.get("inherit_permissions")] for e in dg.get("edges", [])])
    L += ["", "### Scanner errors", ""]
    L += [f"- {e['component']}: {e['error']}" for e in a.errors] or ["None."]
    L += ["", "### Skipped paths (sample)", ""]
    L += [f"- {x['rel']}: {x['reason']}" for x in a.scope.get("skipped_samples", [])] or ["None."]
    L += ["", "### Parse errors", ""]
    L += [f"- {x['file']}: {x['error']}" for x in a.scope.get("parse_errors", [])] or ["None."]
    L += ["", f"Policy SHA-256: `{a.policy.get('sha256')}`", "", f"_{a.disclaimer}_", ""]
    return "\n".join(L)


def _disp(a: Assessment, fid: str) -> str:
    for f in a.findings:
        if f.finding_id == fid:
            return f.display_id
    return fid
