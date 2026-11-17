"""Repository, SKILL.md and documentation consistency checks."""

from __future__ import annotations

import json
import re

import yaml

from agent_security_auditor.rules.catalog import RULES
from agent_security_auditor.rules.docs import render_rules_markdown
from conftest import EXAMPLES, ROOT, audit

SKILL_NAME = "intelligent-agent-security-auditor"
REQUIRED = [
    "SKILL.md", "README.md", "LICENSE", "SECURITY.md", "CONTRIBUTING.md", "CHANGELOG.md", "pyproject.toml", ".gitignore",
    ".github/workflows/tests.yml", ".github/workflows/security.yml",
    *[f"references/{n}.md" for n in ("owasp-agentic-security", "owasp-llm-security", "nist-ai-rmf", "threat-modeling",
                                      "prompt-injection", "data-exfiltration", "spyware-risk", "agent-permissions",
                                      "mcp-security", "memory-security", "multi-agent-security", "autonomous-actions",
                                      "security-controls")],
    "src/agent_security_auditor/__init__.py", "src/agent_security_auditor/cli.py",
    *[f"scripts/{n}.py" for n in ("analyze_agent_config", "scan_secrets", "audit_permissions", "audit_mcp", "generate_report")],
    *[f"assets/templates/{n}" for n in ("security-assessment.md", "executive-summary.md", "risk-register.json",
                                         "threat-model.md", "remediation-plan.md")],
    *[f"assets/schemas/{n}.schema.json" for n in ("finding", "assessment", "policy")],
    *[f"docs/{n}.md" for n in ("architecture", "installation", "usage", "detection-rules", "threat-model", "limitations")],
]
SKIP_PARTS = {".git", ".venv", "__pycache__", ".pytest_cache", "build", "dist"}


def _frontmatter() -> tuple[dict, str]:
    text = (ROOT / "SKILL.md").read_text()
    assert text.startswith("---\n")
    fm, body = text[4:].split("\n---\n", 1)
    return yaml.safe_load(fm), body


def test_required_structure_exists_and_is_not_empty():
    for rel in REQUIRED:
        p = ROOT / rel
        assert p.is_file(), rel
        assert p.stat().st_size > 50, f"{rel} looks empty"


def test_no_empty_placeholder_files():
    empty = [str(p.relative_to(ROOT)) for p in ROOT.rglob("*")
             if p.is_file() and not (set(p.relative_to(ROOT).parts) & SKIP_PARTS) and p.stat().st_size == 0]
    assert not empty, empty


def test_skill_frontmatter_follows_agent_skills_spec():
    fm, body = _frontmatter()
    assert set(fm) <= {"name", "description", "license", "compatibility", "metadata", "allowed-tools"}
    assert fm["name"] == SKILL_NAME and re.fullmatch(r"[a-z0-9]+(-[a-z0-9]+)*", fm["name"]) and len(fm["name"]) <= 64
    assert 50 < len(fm["description"]) <= 1024
    assert len(fm["compatibility"]) <= 500
    assert all(isinstance(k, str) and isinstance(v, str) for k, v in fm["metadata"].items())
    for n, title in enumerate(["Role", "Purpose", "Activation triggers", "Supported inputs", "Security boundaries",
                               "Analysis workflow", "Module selection", "Evidence requirements", "Risk classification",
                               "Output contract", "Readiness decision", "Error handling", "References"], 1):
        assert re.search(rf"^## {n}\. {title}", body, re.M | re.I), title
    assert len(body.splitlines()) < 500, "keep SKILL.md concise (progressive disclosure)"


def test_relative_links_resolve():
    for doc in ["SKILL.md", "README.md", *[str(p.relative_to(ROOT)) for p in (ROOT / "docs").glob("*.md")]]:
        text = (ROOT / doc).read_text()
        base = (ROOT / doc).parent
        for target in re.findall(r"\]\(([^)#\s]+)(?:#[^)]*)?\)", text):
            if target.startswith(("http://", "https://", "mailto:")):
                continue
            assert (base / target).exists(), f"{doc}: broken link {target}"


def test_detection_rules_doc_in_sync():
    assert (ROOT / "docs" / "detection-rules.md").read_text() == render_rules_markdown()
    text = (ROOT / "docs" / "detection-rules.md").read_text()
    for rid in RULES:
        assert f"### {rid} " in text


def test_sample_reports_match_current_output():
    sample = json.loads((EXAMPLES / "sample-reports" / "vulnerable-agent-lab.json").read_text())
    current = audit(EXAMPLES / "vulnerable-agent-lab", assessment_id="ASSESSMENT-EXAMPLE",
                    options={"target_name": "enterprise-assistant-demo"})
    assert sample["readiness"]["verdict"] == current.readiness.verdict.value
    assert [f["finding_id"] for f in sample["findings"]] == [f.finding_id for f in current.findings], \
        "sample reports are stale: regenerate them (see examples/sample-reports/README.md)"
    secure = json.loads((EXAMPLES / "sample-reports" / "secure-agent.json").read_text())
    assert secure["readiness"]["verdict"] == "READY"
