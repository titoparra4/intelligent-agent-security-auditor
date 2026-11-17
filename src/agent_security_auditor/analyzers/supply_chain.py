"""MODULE 08 - Dependency & Supply Chain Scanner.

Offline by default. Known-vulnerability matching only runs against a local OSV-format
advisory directory passed with ``--vuln-db``; without it the control is reported as
``NOT_ASSESSED`` (never "no vulnerabilities"). No install script is ever executed.
"""

from __future__ import annotations

import ast
import json
import re
from pathlib import Path

from agent_security_auditor.analyzers.base import AnalyzerResult, control, related, status_from
from agent_security_auditor.core.context import AuditContext
from agent_security_auditor.core.parsing import call_name, literal
from agent_security_auditor.core.redaction import line_snippet
from agent_security_auditor.models.finding import Confidence, ControlStatus, Evidence, EvidenceType, FindingStatus, Severity
from agent_security_auditor.rules import make_finding
from agent_security_auditor.rules.references import ASI

RUNTIME_INSTALL = re.compile(r"""(?:pip|pip3|uv|npm|pnpm|yarn)["',\s]+(?:install|add)\b|\bnpx\s+-y\b""")


def load_osv(path: str) -> list[dict]:
    """Load OSV JSON advisories from a directory (offline). Files > 1 MiB are ignored."""
    out = []
    root = Path(path)
    if not root.is_dir():
        raise ValueError(f"vulnerability database directory not found: {path}")
    for p in sorted(root.rglob("*.json")):
        if p.is_symlink() or p.stat().st_size > 1024 * 1024:
            continue
        try:
            doc = json.loads(p.read_text("utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(doc, dict) and doc.get("id") and isinstance(doc.get("affected"), list):
            out.append(doc)
    return out


def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


class SupplyChainAnalyzer:
    module_id = "M08"
    name = "Dependency & Supply Chain Scanner"
    implementation = "implemented"

    def analyze(self, ctx: AuditContext) -> AnalyzerResult:
        res = AnalyzerResult()
        inv = ctx.inventory
        deps = inv.dependencies
        for d in deps:
            ev = Evidence(EvidenceType.DEPENDENCY_METADATA, d.file, d.line, f"{d.name} {d.version_spec or ''}".strip())
            if d.source in ("vcs", "url"):
                res.findings.append(make_finding("SUP-004", f"dependency:{d.ecosystem}/{d.name}", [ev],
                                                 FindingStatus.CONFIRMED, Confidence.HIGH, discriminator=d.file or ""))
            elif not d.pinned and d.source == "registry":
                res.findings.append(make_finding("SUP-001", f"dependency:{d.ecosystem}/{d.name}", [ev],
                                                 FindingStatus.CONFIRMED, Confidence.HIGH, discriminator=d.file or ""))
        if deps and not inv.lockfiles:
            files = sorted({d.file for d in deps if d.file})
            res.findings.append(make_finding("SUP-002", "dependencies",
                                             [Evidence(EvidenceType.ABSENCE, files[0] if files else None, None, None,
                                                       f"manifests: {', '.join(files)}; no lockfile")],
                                             FindingStatus.CONFIRMED, Confidence.HIGH))
        for h in ctx.artifacts.get("install_scripts", []):
            res.findings.append(make_finding("SUP-003", f"file:{h['file']}",
                                             [Evidence(EvidenceType.DEPENDENCY_METADATA, h["file"], h.get("line"), None,
                                                       f"{h['hook']}: {h['command'][:120]}")],
                                             FindingStatus.CONFIRMED, Confidence.HIGH, discriminator=h["hook"]))
        # SUP-005 runtime install / dynamic import from non-literal names
        for f, tree in ctx.python_trees():
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                cn = call_name(node)
                if cn in ("importlib.import_module", "__import__", "import_module") and node.args and literal(node.args[0]) is None:
                    res.findings.append(make_finding(
                        "SUP-005", f"file:{f.rel}", [Evidence(EvidenceType.CODE, f.rel, node.lineno, line_snippet(f.lines(), node.lineno),
                                                              "dynamic import with non-literal module name")],
                        FindingStatus.POTENTIAL, Confidence.MEDIUM, severity=Severity.MEDIUM, discriminator=f"imp:{node.lineno}"))
                if cn.startswith("subprocess.") or cn in ("os.system", "os.popen"):
                    seg = ast.get_source_segment(f.text(), node) or ""
                    if RUNTIME_INSTALL.search(seg):
                        res.findings.append(make_finding(
                            "SUP-005", f"file:{f.rel}", [Evidence(EvidenceType.CODE, f.rel, node.lineno, line_snippet(f.lines(), node.lineno),
                                                                  "package installation at runtime")],
                            FindingStatus.CONFIRMED, Confidence.HIGH, discriminator=f"inst:{node.lineno}"))

        # SUP-006 offline advisories
        vuln_db = ctx.options.get("vuln_db")
        assessed = False
        if vuln_db:
            advisories = load_osv(vuln_db)
            assessed = True
            ctx.artifacts["vuln_db_advisories"] = len(advisories)
            eco_map = {"pypi": "PyPI", "npm": "npm"}
            for d in deps:
                if not d.pinned or not d.version_spec:
                    continue
                version = re.sub(r"^[=~^v ]+", "", d.version_spec).strip()
                for adv in advisories:
                    for aff in adv.get("affected", []):
                        pkg = aff.get("package", {})
                        if pkg.get("ecosystem") != eco_map.get(d.ecosystem) or _norm(pkg.get("name", "")) != _norm(d.name):
                            continue
                        if version in [str(v) for v in aff.get("versions", [])]:
                            res.findings.append(make_finding(
                                "SUP-006", f"dependency:{d.ecosystem}/{d.name}",
                                [Evidence(EvidenceType.DEPENDENCY_METADATA, d.file, d.line, f"{d.name}=={version}",
                                          f"advisory {adv['id']}: {str(adv.get('summary', ''))[:120]}")],
                                FindingStatus.CONFIRMED, Confidence.HIGH, discriminator=adv["id"],
                                detail=f"Advisory: {adv['id']}."))

        # --- controls ---------------------------------------------------------------------
        s1 = related(res.findings, "SUP-001", "SUP-002", "SUP-004")
        res.controls.append(control(
            "CTRL-SUP-01", "Dependencies pinned and locked", "M08",
            (status_from(s1) or ControlStatus.PASSED) if deps else ControlStatus.NOT_APPLICABLE,
            f"{len(deps)} dependency declaration(s); {len(s1)} issue(s)." if deps else "No dependency manifests.",
            related=s1, owasp=[ASI["ASI04"]]))
        s2 = related(res.findings, "SUP-003", "SUP-005")
        res.controls.append(control(
            "CTRL-SUP-02", "No install hooks or runtime code installation", "M08",
            status_from(s2) or ControlStatus.PASSED, f"{len(s2)} issue(s)." if s2 else "None detected.",
            related=s2, owasp=[ASI["ASI04"], ASI["ASI05"]]))
        s3 = related(res.findings, "SUP-006")
        if not deps:
            c3 = (ControlStatus.NOT_APPLICABLE, "No dependencies.")
        elif not assessed:
            c3 = (ControlStatus.NOT_VERIFIED, "NOT_ASSESSED: no offline vulnerability database configured (--vuln-db). "
                                              "No CVE claims are made.")
        elif s3:
            c3 = (ControlStatus.FAILED, f"{len(s3)} vulnerable dependency version(s).")
        else:
            c3 = (ControlStatus.PASSED, f"No pinned version matched {ctx.artifacts.get('vuln_db_advisories', 0)} advisories "
                                        "(unpinned ranges cannot be assessed).")
        res.controls.append(control("CTRL-SUP-03", "Known-vulnerable dependency check", "M08", c3[0], c3[1],
                                    related=s3, owasp=[ASI["ASI04"]]))
        if not assessed:
            res.limitations.append("Known-vulnerability matching NOT_ASSESSED (no --vuln-db). External scanners "
                                   "(pip-audit, osv-scanner, npm audit) are opt-in and run by the user, not by this tool.")
        res.limitations.append("Transitive dependencies are not resolved; lockfile contents are not parsed for versions.")
        return res
