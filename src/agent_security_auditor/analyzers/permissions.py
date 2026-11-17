"""MODULE 05 - Tool Permission Auditor.

Builds the matrix ``Tool | Identity | Permissions | Data Access | Operations | Risk | Required
Approval`` and checks least privilege. Every permission keeps its provenance:
``declared`` (manifest), ``configured``/``code`` (requested in code/config), ``inferred``
(names only) or ``verified`` (observed in a controlled test). Authorization stated only in
a prompt is never counted as enforcement.
"""

from __future__ import annotations

from agent_security_auditor.analyzers.base import AnalyzerResult, control, declared_ok, evidence_at, related, status_from
from agent_security_auditor.core.classify import scope_info
from agent_security_auditor.core.context import AuditContext
from agent_security_auditor.models.finding import Confidence, ControlStatus, Evidence, EvidenceType, FindingStatus
from agent_security_auditor.rules import make_finding
from agent_security_auditor.rules.references import ASI


class PermissionAnalyzer:
    module_id = "M05"
    name = "Tool Permission Auditor"
    implementation = "implemented"

    def analyze(self, ctx: AuditContext) -> AnalyzerResult:
        res = AnalyzerResult()
        inv = ctx.inventory
        pol = ctx.policy

        for t in inv.tools:
            etype = EvidenceType.CODE if t.permission_provenance in ("code", "configured") else (
                EvidenceType.DECLARATION if t.permission_provenance == "declared" else EvidenceType.INFERENCE)
            status = FindingStatus.CONFIRMED if t.permission_provenance in ("code", "configured", "declared") else FindingStatus.POTENTIAL
            conf = Confidence.HIGH if t.permission_provenance in ("code", "configured") else Confidence.MEDIUM
            line = _perm_line(ctx, t)
            denied_norm = {_norm_scope(d) for d in pol.denied_scopes}
            for p in t.permissions:
                info = scope_info(p)
                if info is None:
                    # unknown scopes are not guessed, but a policy denial applies regardless of the catalog
                    if _norm_scope(p) in denied_norm:
                        res.findings.append(make_finding(
                            "PERM-001", f"tool:{t.name}",
                            [evidence_at(ctx, t.file, line, etype, f"scope '{p}' is denied by policy {pol.name}")],
                            status, conf, detail=f"Scope '{p}' is denied by policy.",
                            affected_permissions=[p], trust_boundary="TB-TOOLS", discriminator=p))
                    continue
                if info.admin and not pol.allow_admin_permissions:
                    res.findings.append(make_finding(
                        "PERM-002", f"tool:{t.name}", [evidence_at(ctx, t.file, line, etype, f"permission: {p}")],
                        status, conf, affected_permissions=[p], trust_boundary="TB-TOOLS", discriminator=p))
                    continue
                ops = set(t.operations) - {"network"}
                excess = set(info.operations) - ops
                denied = _norm_scope(p) in denied_norm
                if denied or (info.broad and excess):
                    alt = f" Narrower alternative: {info.narrower_alternative}." if info.narrower_alternative else ""
                    res.findings.append(make_finding(
                        "PERM-001", f"tool:{t.name}",
                        [evidence_at(ctx, t.file, line, etype,
                                     f"scope '{p}' grants {sorted(info.operations)}; tool performs {sorted(ops) or ['unknown']}")],
                        status, conf,
                        detail=(f"Tool '{t.name}' performs {', '.join(sorted(ops)) or 'unknown'} but holds '{p}' which also "
                                f"allows {', '.join(sorted(excess)) or 'broad access'}.{alt}" + (" Scope denied by policy." if denied else "")),
                        affected_permissions=[p], trust_boundary="TB-TOOLS", discriminator=p))

        # PERM-003 shared identities
        by_identity: dict[str, list] = {}
        for t in inv.tools:
            if t.identity:
                by_identity.setdefault(t.identity, []).append(t)
        for ident, tools in sorted(by_identity.items()):
            op_sets = {frozenset(t.operations) for t in tools}
            if len(tools) > 1 and len(op_sets) > 1:
                res.findings.append(make_finding(
                    "PERM-003", f"identity:{ident}",
                    [evidence_at(ctx, tools[0].file, tools[0].line, EvidenceType.DECLARATION,
                                 f"used by: {', '.join(t.name for t in tools)}")],
                    FindingStatus.CONFIRMED, Confidence.HIGH, discriminator=ident))

        # PERM-004 / PERM-005 policy conformance
        for t in inv.tools:
            if t.name in pol.forbidden_tools or (pol.authorized_tools is not None and t.name not in pol.authorized_tools):
                why = "forbidden by policy" if t.name in pol.forbidden_tools else "not in the authorized tool list"
                res.findings.append(make_finding(
                    "PERM-004", f"tool:{t.name}", [evidence_at(ctx, t.file, t.line, EvidenceType.POLICY, why)],
                    FindingStatus.CONFIRMED, Confidence.HIGH, detail=f"Tool is {why} ({pol.name})."))
            bad = sorted(set(t.operations) & set(pol.forbidden_operations))
            if bad:
                res.findings.append(make_finding(
                    "PERM-005", f"tool:{t.name}",
                    [evidence_at(ctx, t.file, t.line, EvidenceType.POLICY, f"operations {bad} forbidden by policy {pol.name}")],
                    FindingStatus.CONFIRMED if t.permission_provenance != "inferred" else FindingStatus.POTENTIAL,
                    Confidence.HIGH if t.permission_provenance != "inferred" else Confidence.MEDIUM,
                    detail=f"Forbidden operations: {', '.join(bad)}.", discriminator=",".join(bad)))

        # --- controls ---------------------------------------------------------------------
        p1 = related(res.findings, "PERM-001", "PERM-002")
        unknown = [t.name for t in inv.tools if not t.permissions]
        declared_only = [t.name for t in inv.tools if t.permissions and not declared_ok(ctx, t.permission_provenance)]
        if not inv.tools:
            c1 = (ControlStatus.NOT_APPLICABLE, "No tools.")
        elif p1:
            c1 = (status_from(p1) or ControlStatus.FAILED, f"{len(p1)} over-privileged permission(s).")
        elif unknown:
            c1 = (ControlStatus.NOT_VERIFIED, f"Permissions unknown for: {', '.join(sorted(unknown))}. Declare them in the manifest.")
        elif declared_only:
            c1 = (ControlStatus.NOT_VERIFIED, f"Only declared (unverified) permissions for: {', '.join(declared_only)}.")
        else:
            c1 = (ControlStatus.PASSED, f"All {len(inv.tools)} tool(s) hold scopes consistent with their operations.")
        res.controls.append(control("CTRL-PERM-01", "Least privilege for tool credentials", "M05", c1[0], c1[1],
                                    related=p1, owasp=[ASI["ASI03"]]))
        p3 = related(res.findings, "PERM-003")
        no_ident = [t.name for t in inv.tools if not t.identity]
        if not inv.tools:
            c3 = (ControlStatus.NOT_APPLICABLE, "No tools.")
        elif p3:
            c3 = (ControlStatus.FAILED, "Identities shared between tools with different operations.")
        elif no_ident:
            c3 = (ControlStatus.NOT_VERIFIED, f"Identity unknown for: {', '.join(sorted(no_ident))}.")
        else:
            c3 = (ControlStatus.PASSED, "Each tool has an identity consistent with its operations.")
        res.controls.append(control("CTRL-PERM-02", "Distinct, attributable identity per tool", "M05", c3[0], c3[1],
                                    related=p3, owasp=[ASI["ASI03"]]))
        p4 = related(res.findings, "PERM-004", "PERM-005")
        res.controls.append(control(
            "CTRL-PERM-03", "Tools and operations conform to the security policy", "M05",
            status_from(p4) or (ControlStatus.PASSED if inv.tools else ControlStatus.NOT_APPLICABLE),
            f"Evaluated against policy '{pol.name}'." + (f" {len(p4)} violation(s)." if p4 else ""), related=p4))
        res.limitations.append("Effective permissions are not tested against live identity providers; 'verified' "
                               "provenance requires controlled dynamic testing with synthetic credentials.")
        return res


def _norm_scope(s: str) -> str:
    """Normalise scopes identically on both sides (case, whitespace, trailing slash) to avoid bypasses."""
    return s.strip().casefold().rstrip("/")


def _perm_line(ctx: AuditContext, t) -> int | None:
    """Prefer the line where the permission literal appears (manifest or code)."""
    if t.file and t.permissions:
        sf = ctx.discovery.get(t.file)
        if sf:
            for i, ln in enumerate(sf.lines(), 1):
                if any(p in ln for p in t.permissions):
                    return i
    return t.line
