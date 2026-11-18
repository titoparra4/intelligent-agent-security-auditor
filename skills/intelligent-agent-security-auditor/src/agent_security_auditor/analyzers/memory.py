"""MODULE 07 - Agent Memory Security (isolation, poisoning, retention, deletion)."""

from __future__ import annotations

from agent_security_auditor.analyzers.base import AnalyzerResult, control, declared_ok, evidence_at, related, status_from
from agent_security_auditor.core.context import AuditContext
from agent_security_auditor.models.finding import Confidence, ControlStatus, EvidenceType, FindingStatus, Severity
from agent_security_auditor.rules import make_finding
from agent_security_auditor.rules.references import ASI

ISOLATED = ("per_user", "per_tenant", "per_session")
UNTRUSTED_WRITERS = ("tool_output", "tool", "external", "documents", "email", "web", "rag", "untrusted", "agent")


class MemoryAnalyzer:
    module_id = "M07"
    name = "Agent Memory Security"
    implementation = "implemented"

    def analyze(self, ctx: AuditContext) -> AnalyzerResult:
        res = AnalyzerResult()
        inv = ctx.inventory
        persistent = [m for m in inv.memory if m.kind != "short_term"]
        for m in inv.memory:
            et = EvidenceType.DECLARATION if m.provenance == "declared" else EvidenceType.CODE
            asset = f"memory:{m.name}"
            if m.kind != "short_term":
                if m.scope == "shared":
                    res.findings.append(make_finding(
                        "MEM-001", asset, [evidence_at(ctx, m.file, m.line, et, "scope=shared")],
                        FindingStatus.CONFIRMED, Confidence.HIGH if m.provenance == "declared" else Confidence.MEDIUM,
                        severity=Severity.HIGH if inv.multi_user is not False else Severity.LOW))
                elif m.scope == "unknown" and inv.multi_user is not False:
                    res.findings.append(make_finding(
                        "MEM-001", asset, [evidence_at(ctx, m.file, m.line, et, "no user/tenant partition detected")],
                        FindingStatus.POTENTIAL, Confidence.LOW, severity=Severity.MEDIUM))
                if not m.ttl and m.provenance == "declared":
                    res.findings.append(make_finding("MEM-002", asset, [evidence_at(ctx, m.file, m.line, et, "ttl not set")],
                                                     FindingStatus.CONFIRMED, Confidence.HIGH))
                untrusted_writes = [w for w in m.write_sources if w.lower() in UNTRUSTED_WRITERS]
                if untrusted_writes and m.provenance_tracking is not True:
                    res.findings.append(make_finding(
                        "MEM-003", asset, [evidence_at(ctx, m.file, m.line, et,
                                                       f"write_sources={m.write_sources}; provenance_tracking={m.provenance_tracking}")],
                        FindingStatus.CONFIRMED if m.provenance_tracking is False else FindingStatus.POTENTIAL,
                        Confidence.HIGH if m.provenance_tracking is False else Confidence.MEDIUM))
                if m.deletion_supported is False:
                    res.findings.append(make_finding("MEM-005", asset, [evidence_at(ctx, m.file, m.line, et, "deletion_supported=false")],
                                                     FindingStatus.CONFIRMED, Confidence.HIGH))
            if m.injected_into == "system_prompt":
                res.findings.append(make_finding("MEM-004", asset, [evidence_at(ctx, m.file, m.line, et, "injected_into=system_prompt")],
                                                 FindingStatus.CONFIRMED, Confidence.HIGH))
        for a in inv.agents:
            if a.instructions_include_untrusted_input and a.instructions_excerpt and "memor" in (a.instructions_excerpt or "").lower():
                res.findings.append(make_finding("MEM-004", f"agent:{a.name}",
                                                 [evidence_at(ctx, a.file, a.line, EvidenceType.CODE, "memory interpolated into instructions")],
                                                 FindingStatus.POTENTIAL, Confidence.MEDIUM, discriminator=a.name))

        na = (ControlStatus.NOT_APPLICABLE, "No persistent memory detected.")
        f1 = related(res.findings, "MEM-001")
        if not persistent:
            c1 = na
        elif f1:
            c1 = (status_from(f1, potential_fails=False) or ControlStatus.FAILED,
                  "Shared or unpartitioned persistent memory." if status_from(f1) == ControlStatus.FAILED else
                  "Partitioning could not be established.")
        elif all(m.scope in ISOLATED and declared_ok(ctx, m.provenance if m.provenance == "declared" else "code") for m in persistent):
            c1 = (ControlStatus.PASSED, "All persistent memory is partitioned per user/tenant/session.")
        else:
            c1 = (ControlStatus.NOT_VERIFIED, "Memory scope not established for every store.")
        res.controls.append(control("CTRL-MEM-01", "Persistent memory isolated per user/tenant", "M07", c1[0], c1[1],
                                    related=f1, owasp=[ASI["ASI06"]]))
        f2 = related(res.findings, "MEM-003", "MEM-004")
        if not inv.memory:
            c2 = na
        elif f2:
            c2 = (status_from(f2) or ControlStatus.FAILED, "Untrusted writes without provenance or memory in system prompt.")
        elif persistent and all(m.provenance_tracking is True for m in persistent):
            c2 = (ControlStatus.PASSED, "Memory writes carry provenance; memory not injected as instructions.")
        elif not persistent:
            c2 = (ControlStatus.PASSED, "Only short-term memory; not injected as instructions.")
        else:
            c2 = (ControlStatus.NOT_VERIFIED, "Provenance tracking not declared.")
        res.controls.append(control("CTRL-MEM-02", "Memory protected against poisoning (provenance, placement)", "M07",
                                    c2[0], c2[1], related=f2, owasp=[ASI["ASI06"]]))
        f3 = related(res.findings, "MEM-002", "MEM-005")
        if not persistent:
            c3 = na
        elif f3:
            c3 = (ControlStatus.FAILED, "Retention or deletion missing.")
        elif all(m.ttl and m.deletion_supported for m in persistent):
            c3 = (ControlStatus.PASSED, "TTL and deletion declared for all persistent memory.")
        else:
            c3 = (ControlStatus.NOT_VERIFIED, "Retention/deletion not declared.")
        res.controls.append(control("CTRL-MEM-03", "Memory retention and deletion defined", "M07", c3[0], c3[1],
                                    related=f3, owasp=[ASI["ASI06"]]))
        res.limitations.append("Memory detected from code is limited to known vector-store / memory classes; scope "
                               "and retention are only reliable when declared in the manifest.")
        return res
