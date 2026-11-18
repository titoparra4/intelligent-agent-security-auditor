"""Repository, SKILL.md and documentation consistency checks."""

from __future__ import annotations

import json
import re

import yaml

from agent_security_auditor.rules.catalog import RULES
from agent_security_auditor.rules.docs import render_rules_markdown
from conftest import EXAMPLES, ROOT, SKILL, audit

SKILL_NAME = "intelligent-agent-security-auditor"
SKILL_REL = f"skills/{SKILL_NAME}"
SKILL_FILES = [
    "SKILL.md", "LICENSE",
    *[f"references/{n}.md" for n in ("owasp-agentic-security", "owasp-llm-security", "nist-ai-rmf", "threat-modeling",
                                      "prompt-injection", "data-exfiltration", "spyware-risk", "agent-permissions",
                                      "mcp-security", "memory-security", "multi-agent-security", "autonomous-actions",
                                      "security-controls", "detection-rules", "limitations")],
    "src/agent_security_auditor/__init__.py", "src/agent_security_auditor/cli.py",
    *[f"scripts/{n}.py" for n in ("analyze_agent_config", "scan_secrets", "audit_permissions", "audit_mcp", "generate_report")],
    *[f"assets/templates/{n}" for n in ("security-assessment.md", "executive-summary.md", "risk-register.json",
                                         "threat-model.md", "remediation-plan.md")],
    *[f"assets/schemas/{n}.schema.json" for n in ("finding", "assessment", "policy")],
]
REQUIRED = [
    *[f"{SKILL_REL}/{n}" for n in SKILL_FILES],
    "README.md", "LICENSE", "SECURITY.md", "CONTRIBUTING.md", "CHANGELOG.md", "pyproject.toml", ".gitignore",
    ".github/workflows/tests.yml", ".github/workflows/security.yml",
    *[f"docs/{n}.md" for n in ("architecture", "installation", "usage", "threat-model")],
]
# Skill scanners analyse the whole skill folder: install instructions and download URLs for this
# repository belong in the repo-level README/docs, never inside the skill (Snyk W012).
FORBIDDEN_IN_SKILL = ("git clone", "npx skills", "git+https", "pip install -e")
SKIP_PARTS = {".git", ".venv", "__pycache__", ".pytest_cache", "build", "dist"}


def _frontmatter() -> tuple[dict, str]:
    text = (SKILL / "SKILL.md").read_text()
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


def test_skill_folder_is_self_contained_and_has_no_install_instructions():
    allowed_top = {"SKILL.md", "LICENSE", "references", "scripts", "assets", "src"}
    present = {p.name for p in SKILL.iterdir() if p.name not in SKIP_PARTS}
    assert present <= allowed_top, f"unexpected entries in the skill folder: {present - allowed_top}"
    assert not (ROOT / "SKILL.md").exists(), "SKILL.md must live only in the skill folder"
    for p in SKILL.rglob("*"):
        if not p.is_file() or set(p.parts) & SKIP_PARTS or p.suffix not in {".md", ".py", ".json", ".yaml", ".yml"}:
            continue
        text = p.read_text(errors="ignore")
        for bad in FORBIDDEN_IN_SKILL:
            assert bad not in text, f"{p.relative_to(ROOT)} contains install/download reference {bad!r}"


def test_relative_links_resolve():
    docs = [f"{SKILL_REL}/SKILL.md", "README.md", *[str(p.relative_to(ROOT)) for p in (ROOT / "docs").glob("*.md")],
            *[str(p.relative_to(ROOT)) for p in (SKILL / "references").glob("*.md")]]
    for doc in docs:
        text = (ROOT / doc).read_text()
        base = (ROOT / doc).parent
        for target in re.findall(r"\]\(([^)#\s]+)(?:#[^)]*)?\)", text):
            if target.startswith(("http://", "https://", "mailto:")):
                continue
            assert (base / target).exists(), f"{doc}: broken link {target}"


def test_detection_rules_doc_in_sync():
    text = (SKILL / "references" / "detection-rules.md").read_text()
    assert text == render_rules_markdown()
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
