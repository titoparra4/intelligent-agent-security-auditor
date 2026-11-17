# Architecture

```
target (untrusted files)
   │
   ▼
1 File Discovery ── core/discovery.py   no symlinks, root containment, size/count/depth limits, binary skip
   │
   ▼
2 Safe Parsing ──── core/parsing.py     SafeLoader + alias/expansion limits, JSON depth, tomllib, AST only (never exec)
   │
   ▼
3 Framework Adapters ─ adapters/*        python AST (OpenAI Agents, LangChain, LangGraph, CrewAI, AutoGen),
   │                                      JS/TS regex, MCP configs + server source, dependencies, agent-manifest
   ▼                                      → normalized Inventory (models/inventory.py) with provenance
4 Detection Rules ── analyzers/* (M01–M11) + rules/catalog.py
   │                 each analyzer returns findings + controls + artifacts + limitations
   ▼
5 Threat Modeling ── analyzers/architecture.py  trust boundaries, data flows, threats, Mermaid
6 Evidence Collection  Evidence objects (type, file, line, redacted snippet, note) — core/redaction.py
7 Risk Scoring ───── core/scoring.py     score bands + coverage, critical cap, configurable weights
8 Policy Evaluation ─ policies/model.py  schema-validated policy, exceptions with expiry
9 Readiness ──────── core/readiness.py   READY / READY_WITH_RISKS / NOT_READY / INSUFFICIENT_EVIDENCE
   │
   ▼
10 Report Generation ─ reporters/*       Markdown (19 sections), JSON (schema), SARIF 2.1.0, HTML, console
11 CLI ────────────── cli.py             audit, architecture, permissions, mcp, data-flow, threat-model,
                                          test, compare, report, policy, version
   (MODE C) sandbox/  isolation check → per-scenario child process with audit-hook guards → results
   (MODE D) core/compare.py  baseline diff → CI gate
```

## Directory purposes

| Path | Purpose |
|---|---|
| `src/agent_security_auditor/core` | engine, discovery, parsing, redaction, classification, schema validator, scoring, readiness, compare |
| `src/agent_security_auditor/adapters` | framework/config adapters → normalized inventory |
| `src/agent_security_auditor/analyzers` | modules M01–M11 (one file each) |
| `src/agent_security_auditor/rules` | rule catalog, reference identifiers, 15-dimension matrix |
| `src/agent_security_auditor/models` | finding / control / inventory / assessment data model |
| `src/agent_security_auditor/policies` | policy loader + builtin profiles |
| `src/agent_security_auditor/reporters` | M12 report formats |
| `src/agent_security_auditor/sandbox` | MODE C: isolation verification, runner, child guard, simulated toolkit, scenarios |
| `src/agent_security_auditor/schemas` | bundled copies of `assets/schemas` (kept identical by a test) |
| `assets/templates` | report templates for manual / agent-written reports |
| `assets/schemas` | JSON Schemas: finding, assessment, policy, agent-manifest |
| `scripts/` | no-install entry points used by the skill |
| `references/` | standards mappings and deep guidance (progressive disclosure from SKILL.md) |
| `examples/` | vulnerable lab, secure reference, MCP, multi-agent, policies, sample reports |
| `tests/` | unit, integration, security tests and fixtures |

## Extension points

- **Analyzer plugins**: implement the `Analyzer` protocol (`module_id`, `name`, `implementation`,
  `analyze(ctx) -> AnalyzerResult`) and register it under the entry-point group
  `agent_security_auditor.analyzers`; enable with `--plugins`. The core is not modified.
- **Adapters**: implement `Adapter` (`name`, `coverage`, `applies`, `populate`) and add to
  `adapters.default_adapters()`; declare coverage honestly — it is printed in every report.
- **Rules**: add to `rules/catalog.py` (title, dimension, severity, references, remediation,
  verification); regenerate `docs/detection-rules.md`.

## Finding identity

`finding_id = "ASA-" + sha256(rule_id | asset | file | discriminator)[:12]`. Line numbers are
excluded so unrelated edits do not create "new" findings in `compare`; `display_id` (SEC-NNN) is
positional per report. `first_seen` is carried over from the baseline when provided.

## Determinism

Discovery is sorted; findings are sorted by severity, status, module, rule and asset; ids are
content-derived. With `--assessment-id` fixed, two runs on the same tree produce identical
findings (timestamps aside).

## Security of the auditor itself

Path traversal and symlink escape (no following, realpath containment) · oversized files and
trees (limits) · malformed/binary input (binary skip, parse results instead of exceptions) ·
unsafe deserialization (SafeLoader only, `!!python` tags rejected) · alias bombs (alias count and
expanded-size limits) · deep nesting (depth limits, RecursionError caught) · secret exposure
(redaction before storage) · command construction (the static path never spawns processes; the
sandbox uses a fixed argv without a shell) · prompt injection against the auditor (audited text is
only ever data; the tool has no model in the loop).
