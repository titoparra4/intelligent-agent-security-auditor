"""Self-contained HTML report (no remote scripts, fonts or styles; everything escaped)."""

from __future__ import annotations

import html

from agent_security_auditor.models.assessment import Assessment
from agent_security_auditor.models.finding import ControlStatus

CSS = """
:root{--bg:#fff;--fg:#1d2330;--muted:#5d6675;--line:#e3e6eb;--card:#f7f8fa;--crit:#b3261e;--high:#d0471c;--med:#b7791f;--low:#2b6cb0;--info:#5d6675;--ok:#22863a}
@media (prefers-color-scheme:dark){:root{--bg:#14171c;--fg:#e6e8eb;--muted:#9aa3ae;--line:#2c323b;--card:#1b1f26}}
body{background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;margin:0;padding:24px 16px}
main{max-width:1100px;margin:0 auto}h1{font-size:1.6rem}h2{margin-top:2rem;border-bottom:1px solid var(--line);padding-bottom:.3rem}
table{border-collapse:collapse;width:100%;margin:.5rem 0 1rem;font-size:.9rem;display:block;overflow-x:auto}
th,td{border:1px solid var(--line);padding:.35rem .5rem;text-align:left;vertical-align:top}th{background:var(--card)}
.badge{display:inline-block;padding:.1rem .5rem;border-radius:999px;color:#fff;font-weight:600;font-size:.8rem}
.CRITICAL{background:var(--crit)}.HIGH{background:var(--high)}.MEDIUM{background:var(--med)}.LOW{background:var(--low)}.INFO{background:var(--info)}
.verdict{font-size:1.2rem;padding:.6rem 1rem;border-radius:8px;background:var(--card);border-left:6px solid var(--high)}
.READY{border-color:var(--ok)}.READY_WITH_RISKS{border-color:var(--med)}.INSUFFICIENT_EVIDENCE{border-color:var(--info)}
pre{background:var(--card);padding:.5rem;overflow-x:auto;font-size:.82rem}.muted{color:var(--muted)}
details{background:var(--card);border:1px solid var(--line);border-radius:6px;padding:.5rem .8rem;margin:.5rem 0}
"""


def _e(v: object) -> str:
    return html.escape("" if v is None else str(v), quote=True)


def render_html(a: Assessment) -> str:
    r = a.readiness
    p: list[str] = ["<!doctype html><html lang='en'><head><meta charset='utf-8'>",
                    "<meta name='viewport' content='width=device-width,initial-scale=1'>",
                    f"<title>Agent Security Assessment</title><style>{CSS}</style></head><body><main>"]
    p.append(f"<h1>Agent Security Assessment — {_e(a.target_name)}</h1>")
    p.append(f"<p class='muted'>{_e(a.assessment_id)} · mode {_e(a.mode.value.upper())} · policy {_e(a.policy.get('name'))} · {_e(a.finished_at)}</p>")
    if r:
        p.append(f"<div class='verdict {_e(r.verdict.value)}'><strong>Readiness: {_e(r.verdict.value)}</strong><br>{_e('; '.join(r.reasons))}</div>")
    p.append(f"<p>Score <strong>{_e(a.score.get('score'))}</strong>/100 (grade {_e(a.score.get('grade'))}) · coverage "
             f"<strong>{_e(a.score.get('coverage_percent'))}%</strong> <span class='muted'>— indicator only, not a certification</span></p>")
    p.append("<h2>Findings</h2><table><tr><th>ID</th><th>Severity</th><th>Status</th><th>Title</th><th>Asset</th><th>Location</th></tr>")
    for f in a.findings:
        loc = f"{f.source_file}:{f.source_line}" if f.source_file else "—"
        p.append(f"<tr><td>{_e(f.display_id)}</td><td><span class='badge {_e(f.severity.value)}'>{_e(f.severity.value)}</span></td>"
                 f"<td>{_e(f.status.value)} / {_e(f.confidence.value)}</td><td>{_e(f.title)}</td><td>{_e(f.asset)}</td><td>{_e(loc)}</td></tr>")
    p.append("</table>")
    for f in a.findings:
        p.append(f"<details><summary><strong>{_e(f.display_id)}</strong> {_e(f.title)} — {_e(f.severity.value)}</summary>")
        p.append(f"<p>{_e(f.description)}</p><p><strong>Remediation.</strong> {_e(f.remediation)}</p>")
        for ev in f.evidence:
            p.append(f"<p class='muted'>{_e(ev.type.value)} {_e(ev.file)}:{_e(ev.line)} — {_e(ev.note)}</p>")
            if ev.snippet:
                p.append(f"<pre>{_e(ev.snippet)}</pre>")
        p.append(f"<p class='muted'>{_e('; '.join(f.owasp_references))}</p></details>")
    p.append("<h2>Controls</h2><table><tr><th>Control</th><th>Kind</th><th>Mandatory</th><th>Status</th><th>Rationale</th></tr>")
    for c in sorted(a.controls, key=lambda c: (c.status != ControlStatus.FAILED, c.control_id)):
        p.append(f"<tr><td>{_e(c.control_id)} {_e(c.title)}</td><td>{_e(c.kind)}</td><td>{'yes' if c.mandatory else ''}</td>"
                 f"<td>{_e(c.status.value)}</td><td>{_e(c.rationale)}</td></tr>")
    p.append("</table><h2>Tool permission matrix</h2><table><tr><th>Tool</th><th>Identity</th><th>Permissions</th><th>Operations</th><th>Risk</th><th>Approval</th></tr>")
    for row in a.permission_matrix:
        p.append(f"<tr><td>{_e(row['tool'])}</td><td>{_e(row['identity'])}</td><td>{_e(', '.join(row['permissions']))}</td>"
                 f"<td>{_e(', '.join(row['operations']))}</td><td>{_e(row['risk'])}</td><td>{_e(row['required_approval'])}</td></tr>")
    p.append("</table><h2>Limitations</h2><ul>" + "".join(f"<li>{_e(x)}</li>" for x in a.limitations) + "</ul>")
    p.append(f"<p class='muted'><em>{_e(a.disclaimer)}</em></p></main></body></html>")
    return "\n".join(p)
