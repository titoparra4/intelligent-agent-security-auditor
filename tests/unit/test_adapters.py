"""Framework adapters: normalization of components from code and configuration."""

from __future__ import annotations

from conftest import FIXTURES, audit, by_rule, rules

FW = FIXTURES / "frameworks"


def test_langchain_detection(tmp_path):
    a = audit(FW / "langchain_agent.py")
    inv = a.inventory
    names = {t["name"] for t in inv["tools"]}
    assert {"delete_ticket", "PythonREPLTool", "terminal"} <= names
    delete = next(t for t in inv["tools"] if t["name"] == "delete_ticket")
    assert "delete" in delete["operations"] and delete["permission_provenance"] == "code"
    assert "langchain" in inv["frameworks"]
    ex = [ag for ag in inv["agents"] if ag["max_iterations"] == 6]
    assert ex, "AgentExecutor(max_iterations=6) must be detected"
    assert by_rule(a, "AUTO-003"), "PythonREPLTool / terminal must be flagged as unsandboxed execution"


def test_langgraph_interrupt_counts_as_oversight_and_recursion_limit():
    a = audit(FW / "langgraph_agent.py")
    ag = a.inventory["agents"][0]
    assert ag["framework"] == "langgraph" and ag["human_oversight"].startswith("interrupt_before")
    assert ag["max_iterations"] == 12


def test_crewai_unsafe_code_execution_and_delegation():
    a = audit(FW / "crewai_agent.py")
    assert any(f.severity.value == "CRITICAL" for f in by_rule(a, "AUTO-003"))
    edges = {(d["from_agent"], d["to_agent"]) for d in a.inventory["delegations"]}
    assert ("analyst", "writer") in edges and ("writer", "analyst") in edges


def test_autogen_local_executor_without_docker():
    a = audit(FW / "autogen_agent.py")
    ags = {ag["name"]: ag for ag in a.inventory["agents"]}
    assert ags["user_proxy"]["code_execution_sandboxed"] is False
    assert ags["user_proxy"]["max_iterations"] == 10 and ags["user_proxy"]["human_oversight"] is None
    assert by_rule(a, "AUTO-003")


def test_openai_agents_tools_turns_destinations_and_interpolation():
    a = audit(FW / "openai_agents_app.py")
    inv = a.inventory
    helper = next(ag for ag in inv["agents"] if ag["name"] == "helper")
    assert helper["max_iterations"] == 4 and helper["tools"] == ["export_contacts"]
    exporter = next(ag for ag in inv["agents"] if ag["name"] == "exporter")
    assert exporter["instructions_include_untrusted_input"] is True
    assert "PI-002" in rules(a)
    exf = by_rule(a, "EXF-002")
    assert exf and exf[0].status.value == "CONFIRMED"


def test_mcp_config_transports_pins_and_secrets():
    a = audit(FIXTURES.parent.parent / "examples" / "mcp-security")
    servers = {s["name"]: s for s in a.inventory["mcp_servers"]}
    assert servers["partner-plaintext"]["transport"] == "http" and servers["partner-plaintext"]["auth"] == "none"
    assert servers["partner-tls"]["auth"] == "bearer" and servers["partner-tls"]["inline_secret_keys"] == []
    assert servers["legacy-sse"]["transport"] == "sse" and servers["legacy-sse"]["inline_secret_keys"] == ["X-API-Key"]
    assert servers["container"]["version_pinned"] is False
    assert servers["pinned-python"]["version_pinned"] is True
    assert servers["notes"]["auth"] == "not_applicable"  # stdio: HTTP auth rules do not apply
    assert {t["name"] for t in servers["notes"]["tools"]} == {"search_notes", "add_note"}


def test_dependency_parsing(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests==2.32.5\nhttpx>=0.27\n-e git+https://example.invalid/x.git#egg=x\n# c\n")
    (tmp_path / "package.json").write_text('{"dependencies": {"left-pad": "^1.3.0", "exact": "1.0.0"}, '
                                           '"scripts": {"postinstall": "node setup.js"}}')
    a = audit(tmp_path)
    deps = {d["name"]: d for d in a.inventory["dependencies"]}
    assert deps["requests"]["pinned"] and not deps["httpx"]["pinned"]
    assert deps["x"]["source"] == "vcs" and deps["exact"]["pinned"] and not deps["left-pad"]["pinned"]
    assert {"SUP-001", "SUP-002", "SUP-003", "SUP-004"} <= rules(a)
