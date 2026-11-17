"""Render docs/detection-rules.md from the rule catalog (single source of truth)."""

from __future__ import annotations

from agent_security_auditor.rules.catalog import MODULES, RULES


def render_rules_markdown() -> str:
    lines = [
        "# Detection rules", "",
        "Generated from `src/agent_security_auditor/rules/catalog.py` (do not edit by hand; "
        "`tests/unit/test_docs.py` checks it is in sync). Regenerate with "
        "`python -c \"from agent_security_auditor.rules.docs import write; write()\"`.", "",
        "Default severity is the rule's starting point; analyzers adjust severity, confidence and status per "
        "occurrence (e.g. a heuristic match is POTENTIAL, a configuration fact is CONFIRMED). Rules marked "
        "*specialized review* recommend a code-level security review (e.g. with a secure code review skill).", "",
    ]
    for mid, mname in MODULES.items():
        rules = [r for r in RULES.values() if r.module == mid]
        if not rules:
            continue
        lines += [f"## {mid} — {mname}", "",
                  "| Rule | Title | Dimension | Default severity | OWASP | NIST | Other |",
                  "|---|---|---|---|---|---|---|"]
        for r in rules:
            title = r.title + (" *(specialized review)*" if r.specialized_review else "")
            owasp = "; ".join(o.split(" ")[0] for o in r.owasp) or "—"
            nist = "; ".join(n.replace("NIST AI RMF ", "").split(" (")[0] for n in r.nist) or "—"
            other = "; ".join(x.split(":")[0] for x in r.other) or "—"
            lines.append(f"| {r.rule_id} | {title} | {r.category} | {r.severity} | {owasp} | {nist} | {other} |")
        lines.append("")
        for r in rules:
            lines += [f"### {r.rule_id} — {r.title}", "", r.description, "",
                      f"- **Impact:** {r.impact}", "- **Preconditions:** " + "; ".join(r.preconditions),
                      f"- **Remediation:** {r.remediation}", "- **Verification:** " + "; ".join(r.verification), ""]
    return "\n".join(lines)


def write(path: str = "docs/detection-rules.md") -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(render_rules_markdown())
