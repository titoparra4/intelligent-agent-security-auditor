"""MODULE 04 - Spyware & Exfiltration Risk Analyzer (static).

Separates *capabilities* (network/file access, which most agents legitimately need) from
*indicators* (covert collection, hidden execution, persistence, undeclared destinations).
Nothing here concludes "spyware": findings are indicators for review. Dynamic analysis, if
authorized, runs only in the isolated sandbox (MODULE 11) without network or real data.
"""

from __future__ import annotations

import ast
import re

from agent_security_auditor.analyzers.base import AnalyzerResult, control, related, status_from
from agent_security_auditor.core.classify import host_matches
from agent_security_auditor.core.context import AuditContext
from agent_security_auditor.core.parsing import call_name, literal
from agent_security_auditor.core.redaction import line_snippet
from agent_security_auditor.models.finding import Confidence, ControlStatus, Evidence, EvidenceType, FindingStatus, Severity
from agent_security_auditor.rules import make_finding
from agent_security_auditor.rules.references import ASI

COLLECTION = {
    "clipboard": (re.compile(r"\b(pyperclip\.paste|pbpaste|xclip\s+-o|Get-Clipboard|clipboard\.read(?:Text)?|ImageGrab\.grabclipboard)\b"), Severity.MEDIUM),
    "camera": (re.compile(r"\b(cv2\.VideoCapture|getUserMedia|imagesnap|ffmpeg[^\n]{0,40}avfoundation)\b"), Severity.HIGH),
    "microphone": (re.compile(r"\b(sounddevice\.rec|pyaudio\.PyAudio|speech_recognition\.Microphone|sr\.Microphone)\b"), Severity.HIGH),
    "keystrokes": (re.compile(r"\b(pynput\.keyboard|keyboard\.on_press|keyboard\.hook|GetAsyncKeyState|SetWindowsHookEx)\b"), Severity.HIGH),
    "screenshots": (re.compile(r"\b(ImageGrab\.grab|mss\.mss|pyautogui\.screenshot|screencapture\s)"), Severity.MEDIUM),
    "credential_stores": (re.compile(r"""["'](?:~|\$HOME|%USERPROFILE%)?/?\.(?:ssh|aws|kube|docker|gnupg|netrc|git-credentials|npmrc|pypirc)\b|id_rsa|\.aws/credentials|Login Data|Cookies\b.*Chrome|keychain|security find-generic-password"""), Severity.HIGH),
    "browser_data": (re.compile(r"(?i)(Google/Chrome/Default|Mozilla/Firefox/Profiles|Library/Safari|Local State\b|browser_cookie3)"), Severity.HIGH),
    "host_fingerprinting": (re.compile(r"\b(getpass\.getuser\(\).{0,80}platform\.|platform\.uname\(\).{0,80}(?:requests|httpx|urlopen)|uuid\.getnode\(\)|os\.environ\.copy\(\)|dict\(os\.environ\))", re.S), Severity.MEDIUM),
}
PERSISTENCE = re.compile(
    r"(crontab\s+-|/etc/cron|LaunchAgents|LaunchDaemons|launchctl\s+load|systemctl\s+(?:enable|--user\s+enable)|/etc/systemd|"
    r"CurrentVersion\\\\?Run|schtasks\s+/create|\.bashrc|\.zshrc|\.bash_profile|\.profile['\"]|Startup\\\\?|autostart/)"
)
TELEMETRY_IMPORTS = {
    "sentry_sdk": "Sentry", "posthog": "PostHog", "mixpanel": "Mixpanel", "segment": "Segment", "analytics": "Segment",
    "amplitude": "Amplitude", "datadog": "Datadog", "ddtrace": "Datadog", "newrelic": "New Relic",
    "langsmith": "LangSmith", "langfuse": "Langfuse", "opentelemetry": "OpenTelemetry", "logfire": "Logfire",
    "helicone": "Helicone", "wandb": "Weights & Biases", "rollbar": "Rollbar", "bugsnag": "Bugsnag",
}


class ExfiltrationAnalyzer:
    module_id = "M04"
    name = "Spyware & Exfiltration Risk Analyzer"
    implementation = "implemented"

    def analyze(self, ctx: AuditContext) -> AnalyzerResult:
        res = AnalyzerResult()
        inv = ctx.inventory
        allow = list(ctx.policy.allowed_network_destinations) + list(inv.declared_allowed_destinations)

        # EXF-001 / EXF-002 destinations
        seen: set[tuple[str, str | None]] = set()
        for d in inv.network:
            if d.classification in ("loopback", "private"):
                continue
            if host_matches(d.host, allow):
                continue
            key = (d.host, d.file)
            if key in seen:
                continue
            seen.add(key)
            ev = [Evidence(EvidenceType.CODE if d.in_http_call else EvidenceType.DECLARATION, d.file, d.line,
                           _snip(ctx, d.file, d.line),
                           f"{d.method or 'request'} {d.url} [{d.classification}]" + (" with payload" if d.carries_data else ""))]
            if d.classification == "exfil_service":
                res.findings.append(make_finding(
                    "EXF-002", f"destination:{d.host}", ev,
                    FindingStatus.CONFIRMED if d.in_http_call else FindingStatus.POTENTIAL, Confidence.HIGH,
                    trust_boundary="TB-NETWORK", discriminator=d.host))
            elif d.classification == "metadata_service":
                res.findings.append(make_finding(
                    "EXF-001", f"destination:{d.host}", ev, FindingStatus.POTENTIAL, Confidence.MEDIUM,
                    severity=Severity.HIGH, detail="Cloud metadata endpoint: credential theft / SSRF target.",
                    trust_boundary="TB-NETWORK", discriminator=d.host))
            elif d.in_http_call and d.carries_data:
                no_list = not allow
                res.findings.append(make_finding(
                    "EXF-001", f"destination:{d.host}", ev,
                    FindingStatus.CONFIRMED, Confidence.HIGH,
                    detail=("No destination allowlist is defined." if no_list else
                            f"Host '{d.host}' is not in the allowlist ({', '.join(allow)})."),
                    trust_boundary="TB-NETWORK", discriminator=d.host))
            elif d.in_http_call and d.classification != "model_provider":
                res.findings.append(make_finding(
                    "EXF-001", f"destination:{d.host}", ev, FindingStatus.OBSERVATION, Confidence.MEDIUM,
                    severity=Severity.LOW, detail="Outbound request without detected payload (read-type).",
                    trust_boundary="TB-NETWORK", discriminator=d.host))

        # EXF-003 collection indicators / EXF-004 persistence & obfuscation
        for f in ctx.discovery.by_kind("python", "javascript", "typescript", "shell"):
            text = f.text()
            lines = f.lines()
            for cap, (pat, sev) in COLLECTION.items():
                m = pat.search(text)
                if m:
                    line = text.count("\n", 0, m.start()) + 1
                    res.findings.append(make_finding(
                        "EXF-003", f"file:{f.rel}",
                        [Evidence(EvidenceType.CODE, f.rel, line, line_snippet(lines, line), f"capability: {cap}")],
                        FindingStatus.POTENTIAL, Confidence.MEDIUM, severity=sev,
                        detail=f"Capability: {cap}.", discriminator=cap))
            m = PERSISTENCE.search(text)
            if m:
                line = text.count("\n", 0, m.start()) + 1
                res.findings.append(make_finding(
                    "EXF-004", f"file:{f.rel}",
                    [Evidence(EvidenceType.CODE, f.rel, line, line_snippet(lines, line), "persistence location referenced")],
                    FindingStatus.POTENTIAL, Confidence.MEDIUM, detail="Persistence mechanism referenced.",
                    discriminator="persistence"))
        for f, tree in ctx.python_trees():
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                cn = call_name(node)
                if cn in ("exec", "eval") and node.args and _decodes(node.args[0]):
                    res.findings.append(make_finding(
                        "EXF-004", f"file:{f.rel}",
                        [Evidence(EvidenceType.CODE, f.rel, node.lineno, line_snippet(f.lines(), node.lineno),
                                  "exec/eval of decoded/decompressed data")],
                        FindingStatus.POTENTIAL, Confidence.HIGH, detail="Obfuscated execution.",
                        discriminator=f"obf:{node.lineno}"))
                if cn.startswith("subprocess.Popen") or cn == "Popen":
                    detached = any(kw.arg in ("start_new_session", "creationflags", "preexec_fn") for kw in node.keywords)
                    if detached:
                        res.findings.append(make_finding(
                            "EXF-004", f"file:{f.rel}",
                            [Evidence(EvidenceType.CODE, f.rel, node.lineno, line_snippet(f.lines(), node.lineno),
                                      "detached background process")],
                            FindingStatus.POTENTIAL, Confidence.MEDIUM, severity=Severity.MEDIUM,
                            detail="Detached process.", discriminator=f"detached:{node.lineno}"))

            # EXF-005 telemetry
            mods = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    mods |= {a.name.split(".")[0] for a in node.names}
                elif isinstance(node, ast.ImportFrom) and node.module:
                    mods.add(node.module.split(".")[0])
            declared = {t.lower() for t in inv.telemetry_declared}
            for mod in sorted(mods & set(TELEMETRY_IMPORTS)):
                vendor = TELEMETRY_IMPORTS[mod]
                if vendor.lower() in declared or mod in declared:
                    continue
                res.findings.append(make_finding(
                    "EXF-005", f"telemetry:{vendor}",
                    [Evidence(EvidenceType.CODE, f.rel, None, None, f"import {mod}")],
                    FindingStatus.OBSERVATION, Confidence.HIGH, discriminator=f.rel))

        # inventory artifact: destinations, sources, operations
        res.artifacts["egress_inventory"] = [
            {"host": d.host, "url": d.url, "class": d.classification, "method": d.method, "payload": d.carries_data,
             "allowlisted": host_matches(d.host, allow), "file": d.file, "line": d.line}
            for d in sorted(inv.network, key=lambda d: (d.host, d.file or ""))
        ]

        # --- controls ---------------------------------------------------------------------
        e1 = [f for f in related(res.findings, "EXF-001", "EXF-002") if f.status != FindingStatus.OBSERVATION]
        egress = [d for d in inv.network if d.classification not in ("loopback", "private")]
        res.controls.append(control(
            "CTRL-EXF-01", "Egress destinations restricted to an allowlist", "M04",
            status_from(e1) or (ControlStatus.PASSED if egress else ControlStatus.NOT_APPLICABLE),
            f"{len(e1)} non-allowlisted destination(s) receiving data." if e1 else
            (f"All {len(egress)} external destination(s) allowlisted." if egress else "No external destinations detected statically."),
            related=e1, owasp=[ASI["ASI02"]]))
        e2 = related(res.findings, "EXF-003", "EXF-004")
        res.controls.append(control(
            "CTRL-EXF-02", "No covert collection, hidden execution or persistence indicators", "M04",
            status_from(e2, potential_fails=False) or ControlStatus.PASSED,
            f"{len(e2)} indicator(s) require manual review." if e2 else "No indicators found by static rules.",
            related=e2, owasp=[ASI["ASI10"]]))
        e5 = related(res.findings, "EXF-005")
        res.controls.append(control(
            "CTRL-EXF-03", "Telemetry declared and disclosed", "M04",
            ControlStatus.FAILED if e5 else ControlStatus.PASSED,
            f"{len(e5)} undeclared telemetry SDK(s)." if e5 else "No undeclared telemetry SDK imports.", related=e5))
        res.limitations.append("Destinations built at runtime (from config, env or concatenation across modules) are not "
                               "resolved; only literal URLs and module constants are analysed.")
        return res


def _decodes(node: ast.AST) -> bool:
    for n in ast.walk(node):
        if isinstance(n, ast.Call):
            cn = call_name(n)
            if any(x in cn for x in ("b64decode", "decompress", "unhexlify", "fromhex", "codecs.decode", "rot13", "marshal.loads")):
                return True
    return False


def _snip(ctx: AuditContext, rel: str | None, line: int | None) -> str | None:
    if not rel or not line:
        return None
    sf = ctx.discovery.get(rel)
    return line_snippet(sf.lines(), line) if sf else None
