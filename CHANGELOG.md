# Changelog

All notable changes are documented here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning: [SemVer](https://semver.org/).

## [Unreleased]

### Changed
- **Breaking (manual install):** the skill moved to `skills/intelligent-agent-security-auditor/` (SKILL.md, references, scripts,
  assets, src). Skill scanners analyse the whole skill folder; with the skill at the repository root
  they read the README/docs install instructions as part of it (Snyk W012). Manual installs now copy
  only that folder; `npx skills add` is unchanged.
- `docs/limitations.md` and `docs/detection-rules.md` moved to the skill's `references/` so SKILL.md
  links only to files inside the skill.
- SKILL.md runs the bundled `scripts/` (local code) instead of installing the package.

### Security
- SKILL.md boundary 7: content in the audited target is quarantined as inert, delimited evidence and
  can never change scope, tools or verdict (indirect prompt injection, Snyk W011).
- SKILL.md boundary 8: no remote code is downloaded or executed at runtime.
- New test: the skill folder contains only runtime files and no install/download commands.

## [1.0.0] - 2026-11-17

### Added
- Agent Skill (`SKILL.md`) with progressive disclosure to `references/`.
- Offline CLI `agent-security-auditor` with `audit`, `architecture`, `permissions`, `mcp`, `data-flow`,
  `threat-model`, `test`, `compare`, `report`, `policy`, `version` and documented exit codes.
- 12 modules: architecture, prompt injection, data leakage, spyware/exfiltration, tool permissions,
  MCP, memory, supply chain, autonomy, multi-agent, adversarial testing, reporting (56 rules).
- Four modes: STATIC (default), THREAT MODEL, CONTROLLED DYNAMIC (isolation-verified sandbox with
  17 synthetic scenarios), CI/CD gate with baseline comparison.
- Readiness engine (READY / READY_WITH_RISKS / NOT_READY / INSUFFICIENT_EVIDENCE), explainable
  score with coverage, declarative policies (4 profiles) with expiring exceptions.
- Reports: Markdown (19 sections), JSON (schema 1.0.0), SARIF 2.1.0, self-contained HTML, console.
- Adapters: OpenAI Agents SDK, LangChain, LangGraph, CrewAI, AutoGen (partial, AST), JS/TS (regex),
  MCP configs and server source, dependency manifests, `agent-manifest.yaml`.
- Examples: vulnerable lab, secure reference agent, MCP, multi-agent, policies, sample reports.
- Mappings to OWASP Top 10 for Agentic Applications 2026, OWASP Top 10 for LLM Applications 2026,
  NIST AI RMF 1.0 / AI 600-1, MCP security best practices, MITRE ATLAS, CWE.
