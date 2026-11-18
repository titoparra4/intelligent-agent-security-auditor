"""CONTROLLED DYNAMIC mode runner.

Preconditions (all mandatory, checked in this order; any failure aborts with no test run):

1. explicit authorization flag (``--authorize``) - consent;
2. a valid scope file: ``environment: sandbox``, ``synthetic_data_only: true``, authorizer, an
   unexpired date, optional scenario subset and resource limits;
3. the harness file is inside the authorized target directory and is not a symlink;
4. :func:`verify_isolation` passes (no external route, no credentials, no proxies, no docker socket).

Each scenario runs in a fresh child process with a clean environment, a temporary working
directory, resource limits and a timeout. An operation log is recorded per scenario.
"""

from __future__ import annotations

import datetime as _dt
import json
import os
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from agent_security_auditor.core.discovery import is_within
from agent_security_auditor.core.parsing import parse_yaml
from agent_security_auditor.sandbox.isolation import IsolationReport, verify_isolation
from agent_security_auditor.sandbox.scenarios import Scenario, catalog, new_canary

PACKAGE_ROOT = str(Path(__file__).resolve().parents[2])


class SandboxRefused(Exception):
    """Preconditions for dynamic testing are not met. Nothing was executed."""

    def __init__(self, message: str, details: Any = None) -> None:
        super().__init__(message)
        self.details = details


@dataclass
class Scope:
    authorized_by: str
    environment: str
    synthetic_data_only: bool
    expires: _dt.date
    scenarios: list[str] | None = None
    timeout_seconds: int = 20
    memory_mb: int = 512
    max_tool_calls: int = 50
    raw: dict[str, Any] = field(default_factory=dict)


def load_scope(path: str) -> Scope:
    p = Path(path)
    if not p.is_file() or p.stat().st_size > 64 * 1024:
        raise SandboxRefused(f"scope file not found or too large: {path}")
    res = parse_yaml(p.read_text("utf-8"))
    if not res.ok or not isinstance(res.value, dict):
        raise SandboxRefused(f"scope file invalid: {res.error}")
    d = res.value
    missing = [k for k in ("authorized_by", "environment", "synthetic_data_only", "expires") if k not in d]
    if missing:
        raise SandboxRefused(f"scope file missing: {', '.join(missing)}")
    if str(d["environment"]).lower() != "sandbox":
        raise SandboxRefused("scope.environment must be 'sandbox' (tests against real environments are not allowed)")
    if d["synthetic_data_only"] is not True:
        raise SandboxRefused("scope.synthetic_data_only must be true")
    try:
        expires = _dt.date.fromisoformat(str(d["expires"]))
    except ValueError as exc:
        raise SandboxRefused("scope.expires must be YYYY-MM-DD") from exc
    if expires < _dt.date.today():
        raise SandboxRefused(f"scope expired on {expires}")
    sc = d.get("scenarios")
    lim = d.get("limits", {}) if isinstance(d.get("limits"), dict) else {}
    return Scope(str(d["authorized_by"]), "sandbox", True, expires,
                 [str(x) for x in sc] if isinstance(sc, list) else None,
                 int(lim.get("timeout_seconds", 20)), int(lim.get("memory_mb", 512)), int(lim.get("max_tool_calls", 50)), d)


def _limits(cpu_s: int, mem_mb: int) -> Callable[[], None] | None:
    if os.name != "posix":
        return None

    def apply() -> None:
        import resource

        for lim, val in ((resource.RLIMIT_CPU, cpu_s), (resource.RLIMIT_FSIZE, 10 * 1024 * 1024),
                         (resource.RLIMIT_NOFILE, 64), (getattr(resource, "RLIMIT_AS", None), mem_mb * 1024 * 1024)):
            if lim is None:
                continue
            try:
                resource.setrlimit(lim, (val, val))
            except (ValueError, OSError):
                pass  # not supported on this platform (e.g. RLIMIT_AS on macOS); timeout still applies
        os.setsid()

    return apply


def run_scenario(s: Scenario, harness: Path, scope: Scope) -> dict[str, Any]:
    canary = new_canary(s.test_id)
    fixture = s.build(canary)
    started = time.time()
    with tempfile.TemporaryDirectory(prefix="asa-sbx-") as work:
        request = {"package_root": PACKAGE_ROOT, "harness": str(harness), "fixture": fixture, "workdir": work,
                   "user": "user-a", "max_tool_calls": scope.max_tool_calls}
        env = {"PATH": "/usr/bin:/bin", "HOME": work, "TMPDIR": work, "PYTHONDONTWRITEBYTECODE": "1",
               "PYTHONHASHSEED": "0", "LANG": "C.UTF-8", "ASA_SANDBOX": "1"}
        try:
            proc = subprocess.run(  # noqa: S603 - fixed argv, no shell; harness authorized by scope
                [sys.executable, "-I", "-c",
                 "import sys; sys.path.insert(0, sys.argv[1]); from agent_security_auditor.sandbox.child import main; raise SystemExit(main())",
                 PACKAGE_ROOT],
                input=json.dumps(request), capture_output=True, text=True, cwd=work, env=env,
                timeout=scope.timeout_seconds, preexec_fn=_limits(scope.timeout_seconds, scope.memory_mb),
            )
        except subprocess.TimeoutExpired:
            return _row(s, "ERROR", f"timeout after {scope.timeout_seconds}s (process killed)", started, canary, {})
        line = next((ln for ln in proc.stdout.splitlines() if ln.startswith("ASA-RESULT:")), None)
        if line is None:
            return _row(s, "ERROR", f"no result from child (exit {proc.returncode}): {proc.stderr[-300:]}", started, canary, {})
        out = json.loads(line[len("ASA-RESULT:"):])
    passed, note = s.evaluate(out, fixture, canary)
    if out.get("status") == "AGENT_ERROR" and passed:
        note += f"; agent raised {out.get('error')}"
    if out.get("blocked_operations"):
        note += f"; sandbox blocked: {', '.join(out['blocked_operations'][:3])}"
    return _row(s, "PASS" if passed else "FAIL", note, started, canary, out)


def _row(s: Scenario, result: str, note: str, started: float, canary: str, out: dict[str, Any]) -> dict[str, Any]:
    row = s.plan_row(True)
    row.update({"result": result, "observed": note, "duration_ms": int((time.time() - started) * 1000),
                "canary": canary[:14] + "…", "tool_calls": len(out.get("trace", [])),
                "approvals_requested": len(out.get("approvals", [])),
                "operation_log": [{"tool": c.get("tool"), "args": str(c.get("args"))[:160]} for c in out.get("trace", [])][:20]})
    return row


def run_dynamic(target: str, harness: str, scope_path: str, authorized: bool,
                isolation_check: Callable[[], IsolationReport] = verify_isolation,
                only: list[str] | None = None) -> tuple[list[dict[str, Any]], IsolationReport, Scope]:
    if not authorized:
        raise SandboxRefused("dynamic testing requires explicit authorization (--authorize)")
    scope = load_scope(scope_path)
    root = Path(target).resolve()
    hp = Path(harness)
    if not hp.is_absolute():
        hp = (root / hp) if (root / hp).exists() else hp
    if hp.is_symlink():
        raise SandboxRefused("harness must not be a symlink")
    hp = hp.resolve()
    if not hp.is_file() or not is_within(root if root.is_dir() else root.parent, hp):
        raise SandboxRefused("harness must be a file inside the authorized target directory")
    report = isolation_check()
    if not report.ok:
        raise SandboxRefused("sandbox isolation verification failed; no test was executed", report.to_dict())
    wanted = set(only or scope.scenarios or [])
    results = []
    for s in catalog():
        if wanted and s.test_id not in wanted:
            continue
        results.append(run_scenario(s, hp, scope))
    return results, report, scope
