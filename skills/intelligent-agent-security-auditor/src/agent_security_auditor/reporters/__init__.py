"""MODULE 12 - Security Risk Reporting: Markdown, JSON, SARIF, HTML and console outputs."""

from __future__ import annotations

import json
from pathlib import Path

from agent_security_auditor.models.assessment import Assessment
from agent_security_auditor.reporters.html import render_html
from agent_security_auditor.reporters.markdown import render_markdown
from agent_security_auditor.reporters.sarif import render_sarif

FORMATS = ("json", "markdown", "sarif", "html")


def render_json(a: Assessment) -> str:
    return json.dumps(a.to_dict(), indent=2, ensure_ascii=False, default=str) + "\n"


def write_reports(a: Assessment, out_dir: str, formats: list[str], basename: str = "agent-security-assessment") -> list[str]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    written = []
    for fmt in formats:
        if fmt == "json":
            path, text = out / f"{basename}.json", render_json(a)
        elif fmt in ("markdown", "md"):
            path, text = out / f"{basename}.md", render_markdown(a)
        elif fmt == "sarif":
            path, text = out / f"{basename}.sarif", json.dumps(render_sarif(a), indent=2) + "\n"
        elif fmt == "html":
            path, text = out / f"{basename}.html", render_html(a)
        else:
            raise ValueError(f"unknown format: {fmt}")
        path.write_text(text, encoding="utf-8")
        written.append(str(path))
    return written


def console_summary(a: Assessment, color: bool = False) -> str:
    r = a.readiness
    s = a.summary()
    lines = [
        f"Agent Security Assessment  {a.assessment_id}",
        f"Target: {a.target_name}   Mode: {a.mode.value.upper()}   Policy: {a.policy.get('name')}",
        f"Readiness: {r.verdict.value if r else '-'}",
    ]
    if r:
        lines += [f"  - {x}" for x in r.reasons]
    lines.append(f"Score: {a.score.get('score')}/100 (grade {a.score.get('grade')})   Coverage: {a.score.get('coverage_percent')}% "
                 f"of applicable controls verified")
    lines.append("Findings: " + ", ".join(f"{k}={v}" for k, v in s["by_severity"].items()) +
                 "   [" + ", ".join(f"{k}={v}" for k, v in s["by_status"].items() if v) + "]")
    for f in a.findings[:15]:
        loc = f" {f.source_file}:{f.source_line}" if f.source_file else ""
        lines.append(f"  {f.display_id}  {f.severity.value:<8} {f.status.value:<11} {f.rule_id:<9} {f.title} — {f.asset}{loc}")
    if len(a.findings) > 15:
        lines.append(f"  ... {len(a.findings) - 15} more (see report)")
    nv = [c for c in a.controls if c.status.value in ("NOT_VERIFIED", "INSUFFICIENT_EVIDENCE")]
    if nv:
        lines.append(f"Controls not verified: {len(nv)} (" + ", ".join(c.control_id for c in nv[:8]) + (", ..." if len(nv) > 8 else "") + ")")
    if a.errors:
        lines.append(f"SCANNER ERRORS: {len(a.errors)} — the audit is incomplete")
    lines.append(a.disclaimer)
    return "\n".join(lines)


__all__ = ["FORMATS", "console_summary", "render_html", "render_json", "render_markdown", "render_sarif", "write_reports"]
