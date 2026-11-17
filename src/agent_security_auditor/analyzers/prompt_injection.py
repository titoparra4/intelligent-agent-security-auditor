"""MODULE 02 - Prompt Injection Detector (static surfaces + content scanning).

Static analysis can show *exposure* (untrusted content reaching the instruction channel)
and *payload presence*; it cannot show exploitation. Exploitation is only established by the
controlled dynamic scenarios of MODULE 11.
"""

from __future__ import annotations

import base64
import re

from agent_security_auditor.analyzers.base import AnalyzerResult, control, declared_ok, evidence_at, related, status_from
from agent_security_auditor.core.context import AuditContext
from agent_security_auditor.models.finding import Confidence, ControlStatus, Evidence, EvidenceType, FindingStatus
from agent_security_auditor.rules import make_finding
from agent_security_auditor.rules.references import ASI

INJECTION_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("override", re.compile(r"(?i)\b(ignore|disregard|forget|override)\b[^.\n]{0,40}\b(previous|prior|above|earlier|all|system|developer)\b[^.\n]{0,20}\b(instructions?|prompts?|rules|guidelines|directives)\b")),
    ("role_spoof", re.compile(r"(?im)^\s*(?:#+\s*)?(?:system|assistant|developer)\s*(?:message|prompt)?\s*[:>]\s*\S|<\|?(?:im_start|system|endoftext)\|?>|\[/?(?:INST|SYS)\]")),
    ("new_identity", re.compile(r"(?i)\byou are now\b|\bfrom now on,? you (?:are|will|must)\b|\bact as (?:an? )?(?:unrestricted|jailbroken|dan)\b|\bdeveloper mode\b")),
    ("tool_trigger", re.compile(r"(?i)\b(?:call|use|invoke|run|execute)\b[^.\n]{0,30}\b(?:tool|function)\b[^.\n]{0,60}\b(?:send|forward|email|upload|post|delete|transfer)\b|\b(?:forward|send|email|upload|post)\b[^.\n]{0,60}\b(?:all|every|the entire|full)\b[^.\n]{0,40}\b(?:emails?|documents?|files?|records?|data|contacts|conversation|history)\b[^.\n]{0,40}\b(?:to|at)\b")),
    ("concealment", re.compile(r"(?i)\b(?:do not|don't|never)\s+(?:tell|inform|mention|reveal|show|notify)\b[^.\n]{0,30}\b(?:the )?(?:user|human|operator)\b")),
    ("hidden_tag", re.compile(r"(?i)<\s*(?:important|system|secret|hidden|instructions?|admin)\s*>")),
)
INVISIBLE = re.compile("[\u200b\u200c\u200d\u2060\ufeff\u202a-\u202e\u2066-\u2069\U000e0000-\U000e007f]")
HTML_COMMENT = re.compile(r"<!--(.{0,600}?)-->", re.S)
B64 = re.compile(r"\b[A-Za-z0-9+/]{40,}={0,2}")
CONTENT_KINDS = ("markdown", "text", "email", "html", "json", "jsonl", "yaml", "xml")
SAFE_HANDLING = {"isolated", "delimited", "spotlighted", "spotlighting", "quarantined", "sanitized", "dual-llm", "structured"}
#: project documentation describing attacks is not agent-reachable content
DOC_PATH_HINTS = ("readme", "changelog", "contributing", "security.md", "license", "docs/", "references/", "skill.md")


def scan_text(text: str) -> list[tuple[str, int, str]]:
    """Return (technique, line, matched-text) for instruction-like content."""
    hits: list[tuple[str, int, str]] = []
    for tech, pat in INJECTION_PATTERNS:
        for m in pat.finditer(text):
            hits.append((tech, text.count("\n", 0, m.start()) + 1, m.group(0)))
    return hits


def scan_hidden(text: str) -> list[tuple[str, int, str]]:
    hits: list[tuple[str, int, str]] = []
    for m in INVISIBLE.finditer(text):
        hits.append(("invisible_characters", text.count("\n", 0, m.start()) + 1, f"U+{ord(m.group(0)):04X}"))
        break
    for m in HTML_COMMENT.finditer(text):
        inner = m.group(1)
        if scan_text(inner):
            hits.append(("html_comment_instruction", text.count("\n", 0, m.start()) + 1, inner.strip()[:80]))
    for m in B64.finditer(text):
        try:
            decoded = base64.b64decode(m.group(0) + "=" * (-len(m.group(0)) % 4), validate=True).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue
        if decoded.isprintable() and scan_text(decoded):
            hits.append(("base64_instruction", text.count("\n", 0, m.start()) + 1, decoded[:80]))
    return hits


class PromptInjectionAnalyzer:
    module_id = "M02"
    name = "Prompt Injection Detector"
    implementation = "implemented"

    def analyze(self, ctx: AuditContext) -> AnalyzerResult:
        inv = ctx.inventory
        res = AnalyzerResult()

        # PI-001: untrusted tool output without isolation
        untrusted = [t for t in inv.tools if t.reads_untrusted]
        for t in untrusted:
            handling = (t.output_handling or "").lower()
            if handling in SAFE_HANDLING:
                continue
            explicit = t.returns_untrusted_content is True
            res.findings.append(make_finding(
                "PI-001", f"tool:{t.name}",
                [evidence_at(ctx, t.file, t.line, EvidenceType.CODE if t.source.startswith("code") else EvidenceType.DECLARATION,
                             f"returns {', '.join(t.data_access)} content; output_handling={t.output_handling or 'not declared'}")],
                FindingStatus.POTENTIAL, Confidence.HIGH if explicit else Confidence.MEDIUM,
                detail=f"Tool '{t.name}' reads {', '.join(t.data_access) or 'external'} content.",
                trust_boundary="TB-CONTENT", discriminator=t.name))

        # PI-002: untrusted interpolation into instructions
        for a in inv.agents:
            if a.instructions_include_untrusted_input:
                res.findings.append(make_finding(
                    "PI-002", f"agent:{a.name}", [evidence_at(ctx, a.file, a.line, EvidenceType.CODE, "instructions built with f-string/format")],
                    FindingStatus.POTENTIAL, Confidence.MEDIUM, trust_boundary="TB-USER", discriminator=a.name))

        # PI-003 / PI-004: payloads in agent-reachable content and tool descriptions
        scanned = 0
        for f in ctx.discovery.by_kind(*CONTENT_KINDS):
            low = f.rel.lower()
            if any(h in low for h in DOC_PATH_HINTS) or "/tests/" in "/" + low or low.startswith("tests/"):
                continue
            if f.rel.rsplit("/", 1)[-1] in ("agent-manifest.yaml", "agent-manifest.yml", "package.json", "package-lock.json"):
                continue
            scanned += 1
            text = f.text()
            hits = scan_text(text)
            if hits:
                techs = sorted({h[0] for h in hits})
                first = hits[0]
                res.findings.append(make_finding(
                    "PI-003", f"content:{f.rel}",
                    [evidence_at(ctx, f.rel, first[1], EvidenceType.CONTENT, f"techniques: {', '.join(techs)}")],
                    FindingStatus.POTENTIAL, Confidence.MEDIUM if len(techs) > 1 else Confidence.LOW,
                    detail=f"Detected techniques: {', '.join(techs)}.", trust_boundary="TB-CONTENT"))
            hidden = scan_hidden(text)
            if hidden:
                h = hidden[0]
                res.findings.append(make_finding(
                    "PI-004", f"content:{f.rel}",
                    [Evidence(EvidenceType.CONTENT, f.rel, h[1], None, f"{h[0]}: {h[2][:60]!r}")],
                    FindingStatus.POTENTIAL, Confidence.MEDIUM, detail=f"Technique: {h[0]}.",
                    trust_boundary="TB-CONTENT"))
        res.artifacts["content_files_scanned"] = scanned

        # --- controls ---------------------------------------------------------------------
        f1 = related(res.findings, "PI-001")
        if not untrusted:
            c1 = (ControlStatus.NOT_APPLICABLE, "No tool returning untrusted content was identified.")
        elif f1:
            c1 = (ControlStatus.FAILED, f"{len(f1)} tool(s) return untrusted content without declared isolation.")
        elif all(declared_ok(ctx, "declared") for _ in untrusted):
            c1 = (ControlStatus.PASSED, "All untrusted-content tools declare an isolation mechanism (declared evidence; "
                                        "behavior verified only by dynamic tests).")
        else:
            c1 = (ControlStatus.NOT_VERIFIED, "Isolation is declared but the policy does not accept declared evidence.")
        res.controls.append(control("CTRL-PI-01", "Untrusted tool output isolated from the instruction channel", "M02",
                                    c1[0], c1[1], related=f1, owasp=[ASI["ASI01"]]))
        f2 = related(res.findings, "PI-002")
        with_instr = [a for a in inv.agents if a.instructions_excerpt]
        if not inv.agents:
            c2 = (ControlStatus.NOT_APPLICABLE, "No agents detected.")
        elif f2:
            c2 = (ControlStatus.FAILED, "Instructions interpolate untrusted variables.")
        elif with_instr:
            c2 = (ControlStatus.PASSED, f"{len(with_instr)} agent instruction set(s) are static.")
        else:
            c2 = (ControlStatus.NOT_VERIFIED, "Agent instructions could not be located statically.")
        res.controls.append(control("CTRL-PI-02", "System instructions free of untrusted interpolation", "M02",
                                    c2[0], c2[1], related=f2, owasp=[ASI["ASI01"]]))
        f3 = related(res.findings, "PI-003", "PI-004")
        st = status_from(f3)
        if st is None:
            st = ControlStatus.PASSED if scanned else ControlStatus.NOT_APPLICABLE
        res.controls.append(control(
            "CTRL-PI-03", "Agent-reachable content free of injection payloads", "M02", st,
            f"{scanned} content file(s) scanned; {len(f3)} with instruction-like payloads." if scanned else "No content files.",
            related=f3, owasp=[ASI["ASI01"], ASI["ASI06"]]))
        res.limitations.append("Pattern-based payload detection: novel or paraphrased injections are missed; matches are "
                               "indicators, not proof. Exploitability requires controlled dynamic tests (M11).")
        return res
