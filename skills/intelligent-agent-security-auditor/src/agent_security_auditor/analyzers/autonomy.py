"""MODULE 09 - Autonomous Action Auditor.

Approval must be enforced independently of the model. A prompt that asks the model to
"confirm with the user" is reported as advisory (AUTO-006), never as an approval control.
"""

from __future__ import annotations

from agent_security_auditor.analyzers.base import AnalyzerResult, control, declared_ok, evidence_at, related, status_from
from agent_security_auditor.core.context import AuditContext
from agent_security_auditor.models.finding import Confidence, ControlStatus, Evidence, EvidenceType, FindingStatus, Severity
from agent_security_auditor.rules import make_finding
from agent_security_auditor.rules.references import ASI


class AutonomyAnalyzer:
    module_id = "M09"
    name = "Autonomous Action Auditor"
    implementation = "implemented"

    def analyze(self, ctx: AuditContext) -> AnalyzerResult:
        res = AnalyzerResult()
        inv = ctx.inventory
        pol = ctx.policy
        need = set(pol.approval_required_for)
        gated_tools = [t for t in inv.tools if set(t.operations) & need]
        prompt_only_agents = {a.name for a in inv.agents if a.instructions_mentions_approval}

        for t in gated_tools:
            ops = sorted(set(t.operations) & need)
            enforced = t.requires_approval is True and declared_ok(ctx, t.approval_provenance)
            if enforced:
                continue
            et = EvidenceType.DECLARATION if t.requires_approval is False else (
                EvidenceType.CODE if t.source.startswith("code") else EvidenceType.INFERENCE)
            if t.requires_approval is True:
                # declared but the policy refuses declared evidence
                continue
            status = FindingStatus.CONFIRMED if (t.requires_approval is False or t.permission_provenance in ("code", "declared")) else FindingStatus.POTENTIAL
            sev = Severity.CRITICAL if set(ops) & {"financial", "infra"} else Severity.HIGH if set(ops) & {"send", "delete", "execute"} else Severity.MEDIUM
            res.findings.append(make_finding(
                "AUTO-001", f"tool:{t.name}",
                [evidence_at(ctx, t.file, t.line, et, f"operations {ops}; requires_approval={t.requires_approval}")],
                status, Confidence.HIGH if status == FindingStatus.CONFIRMED else Confidence.MEDIUM, severity=sev,
                detail=f"Operations requiring approval by policy: {', '.join(ops)}.", trust_boundary="TB-TOOLS",
                discriminator=t.name))
            if set(t.agents) & prompt_only_agents:
                res.findings.append(make_finding(
                    "AUTO-006", f"tool:{t.name}",
                    [evidence_at(ctx, t.file, t.line, et, "approval requested in instructions, not enforced in the tool")],
                    FindingStatus.CONFIRMED if t.requires_approval is False else FindingStatus.POTENTIAL, Confidence.MEDIUM,
                    discriminator=t.name))
            if t.production_target and t.is_destructive:
                res.findings.append(make_finding("AUTO-007", f"tool:{t.name}",
                                                 [evidence_at(ctx, t.file, t.line, EvidenceType.DECLARATION, "environment=production")],
                                                 FindingStatus.CONFIRMED, Confidence.HIGH))

        for a in inv.agents:
            if a.max_iterations is None:
                res.findings.append(make_finding(
                    "AUTO-002", f"agent:{a.name}",
                    [evidence_at(ctx, a.file, a.line, EvidenceType.ABSENCE, "no explicit max turns/iterations/recursion limit; framework default applies")],
                    FindingStatus.POTENTIAL, Confidence.MEDIUM, severity=Severity.MEDIUM if a.tools else Severity.LOW,
                    discriminator=a.name))
            elif a.max_iterations > 100:
                res.findings.append(make_finding(
                    "AUTO-002", f"agent:{a.name}",
                    [evidence_at(ctx, a.file, a.line, EvidenceType.CODE, f"limit={a.max_iterations}")],
                    FindingStatus.OBSERVATION, Confidence.HIGH, severity=Severity.LOW, discriminator=a.name))
            if a.provenance == "declared" or inv.manifest_file:
                if not a.budget_limit:
                    res.findings.append(make_finding("AUTO-004", f"agent:{a.name}",
                                                     [Evidence(EvidenceType.ABSENCE, inv.manifest_file, None, None, "limits.budget not declared")],
                                                     FindingStatus.OBSERVATION, Confidence.HIGH, discriminator=a.name))
                if not a.kill_switch:
                    res.findings.append(make_finding("AUTO-005", f"agent:{a.name}",
                                                     [Evidence(EvidenceType.ABSENCE, inv.manifest_file, None, None, "human_oversight.kill_switch not declared")],
                                                     FindingStatus.OBSERVATION, Confidence.HIGH, discriminator=a.name))

        seen_sites = set()
        for c in inv.code_execution:
            if c.sandboxed is True:
                continue
            key = (c.file, c.line)
            if key in seen_sites:
                continue
            seen_sites.add(key)
            agent_ctx = c.within_tool is not None or c.kind in ("python_repl", "shell", "autogen_executor", "crewai_code_execution")
            if not agent_ctx and c.kind == "subprocess":
                continue  # plain subprocess outside tools: not model-driven by itself
            res.findings.append(make_finding(
                "AUTO-003", f"exec:{c.kind}@{c.file}",
                [evidence_at(ctx, c.file, c.line, EvidenceType.CODE, f"{c.kind}; sandboxed={c.sandboxed}; {c.note}")],
                FindingStatus.CONFIRMED if c.sandboxed is False and agent_ctx else FindingStatus.POTENTIAL,
                Confidence.HIGH if c.sandboxed is False else Confidence.MEDIUM,
                severity=Severity.CRITICAL if c.sandboxed is False else Severity.HIGH,
                trust_boundary="TB-EXEC", discriminator=f"{c.kind}:{c.line}"))
        for a in inv.agents:
            if a.code_execution and a.code_execution_sandboxed is False and not any(c.file == a.file for c in inv.code_execution):
                res.findings.append(make_finding(
                    "AUTO-003", f"agent:{a.name}", [evidence_at(ctx, a.file, a.line, EvidenceType.DECLARATION, "code_execution.sandboxed=false")],
                    FindingStatus.CONFIRMED, Confidence.HIGH, trust_boundary="TB-EXEC", discriminator=a.name))

        # --- controls ---------------------------------------------------------------------
        a1 = related(res.findings, "AUTO-001", "AUTO-006")
        undeclared = [t.name for t in gated_tools if not (t.requires_approval and declared_ok(ctx, t.approval_provenance))
                      and t.requires_approval is not False]
        if not gated_tools:
            c1 = (ControlStatus.NOT_APPLICABLE, "No tools perform operations that the policy gates.")
        elif a1:
            c1 = (status_from(a1) or ControlStatus.FAILED, f"{len(related(a1, 'AUTO-001'))} gated tool(s) without enforced approval.")
        elif undeclared:
            c1 = (ControlStatus.NOT_VERIFIED, f"Approval not evidenced for: {', '.join(undeclared)}.")
        else:
            prov = sorted({t.approval_provenance or '?' for t in gated_tools})
            c1 = (ControlStatus.PASSED, f"All {len(gated_tools)} gated tool(s) require approval (evidence: {', '.join(prov)}).")
        res.controls.append(control("CTRL-AUTO-01", "Human approval enforced outside the model for irreversible actions",
                                    "M09", c1[0], c1[1], related=a1, owasp=[ASI["ASI02"], ASI["ASI09"]]))
        a2 = related(res.findings, "AUTO-002")
        if not inv.agents:
            c2 = (ControlStatus.NOT_APPLICABLE, "No agents.")
        elif [f for f in a2 if f.status != FindingStatus.OBSERVATION]:
            c2 = (ControlStatus.FAILED if pol.require_max_iterations else ControlStatus.NOT_VERIFIED,
                  "Agents without an explicit iteration limit.")
        else:
            c2 = (ControlStatus.PASSED, "Every agent has an explicit iteration limit.")
        res.controls.append(control("CTRL-AUTO-02", "Explicit iteration / step limits", "M09", c2[0], c2[1],
                                    related=a2, owasp=[ASI["ASI08"]]))
        a3 = related(res.findings, "AUTO-003")
        if not inv.code_execution and not any(a.code_execution for a in inv.agents):
            c3 = (ControlStatus.NOT_APPLICABLE, "No code-execution capability detected.")
        elif a3:
            c3 = (status_from(a3) or ControlStatus.FAILED, "Unsandboxed or unverified code execution.")
        else:
            c3 = (ControlStatus.PASSED, "All code execution runs in a sandboxed executor.")
        res.controls.append(control("CTRL-AUTO-03", "Code execution sandboxed", "M09", c3[0], c3[1],
                                    related=a3, owasp=[ASI["ASI05"]]))
        a4 = related(res.findings, "AUTO-004", "AUTO-005")
        if not inv.agents:
            c4 = (ControlStatus.NOT_APPLICABLE, "No agents.")
        elif a4:
            c4 = (ControlStatus.NOT_VERIFIED, "Budget and/or kill switch not declared.")
        elif all(a.budget_limit and a.kill_switch for a in inv.agents):
            c4 = (ControlStatus.PASSED, "Budget and kill switch declared for every agent (declared evidence).")
        else:
            c4 = (ControlStatus.NOT_VERIFIED, "Budget/kill switch not declared (no manifest).")
        res.controls.append(control("CTRL-AUTO-04", "Consumption budget and kill switch", "M09", c4[0], c4[1],
                                    related=a4, owasp=[ASI["ASI08"], ASI["ASI10"]]))
        res.limitations.append("Approval enforcement is verified statically only when the manifest points to an "
                               "approval function that the tool calls (approval_enforced_by) or the tool body calls an "
                               "approval/confirm/interrupt function; runtime behavior needs dynamic tests.")
        return res
