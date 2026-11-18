# Intelligent Agent Security Auditor

**An open-source Agent Skill and offline CLI that assesses the security of AI agents — not just their prompts, but the combination of agent + tools + permissions + data + memory + network + autonomy + trust boundaries — and issues an evidence-based deployment readiness verdict.**

[![tests](https://github.com/titoparra4/intelligent-agent-security-auditor/actions/workflows/tests.yml/badge.svg)](https://github.com/titoparra4/intelligent-agent-security-auditor/actions/workflows/tests.yml)
[![security](https://github.com/titoparra4/intelligent-agent-security-auditor/actions/workflows/security.yml/badge.svg)](https://github.com/titoparra4/intelligent-agent-security-auditor/actions/workflows/security.yml)
![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)
![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)

> This tool provides a security assessment based on available evidence. It does not guarantee that an AI agent is secure or constitute a formal security certification. It is not affiliated with or certified by OWASP, NIST, MITRE or the MCP project.

📘 **User manual (PDF):** [English](docs/User-manual.pdf) · [Español](docs/Manual-de-usuario.pdf)

**Quick install (skills.sh):** `npx skills add titoparra4/intelligent-agent-security-auditor` · **CLI:** `pip install -e .` → `agent-security-auditor audit ./my-agent`

---

## Contents

[Problem](#the-problem) · [Capabilities](#capabilities) · [Architecture](#architecture) · [Requirements](#requirements) · [Installation](#installation) · [Configuration](#configuration) · [Usage](#usage) · [Examples](#examples) · [Example report](#example-report) · [OWASP mapping](#owasp-mapping) · [Limitations](#limitations) · [Security policy](#security-policy) · [Contributing](#contributing) · [License](#license)

## The problem

An agent with impeccable instructions can still leak your data — because of what it is *connected
to*. A search tool holding a full Drive scope, an e-mail reader that pours attacker-written text
into the same context that can call an HTTP tool, a memory store shared across tenants, an
unpinned MCP server whose tool description tells the model to read `~/.ssh`: none of these show
up in a prompt review, and most are invisible to classic SAST.

This project makes those risks **reproducible to assess** before deployment, and **re-assessable**
whenever tools, permissions, models, dependencies or configuration change.

## Capabilities

- **12 modules / 56 rules**: architecture & threat model, prompt injection, data leakage,
  spyware & exfiltration indicators, tool permissions (OAuth scope catalog), MCP (transport-aware),
  memory/RAG, supply chain, autonomous actions, multi-agent delegation, adversarial testing, reporting.
- **Evidence-based findings**: stable ids, file:line, redacted evidence, exploitation preconditions,
  impact, OWASP/NIST/CWE/ATLAS references, remediation and a verification step — with severity,
  confidence and status (`CONFIRMED`/`POTENTIAL`/`OBSERVATION`/`NOT_VERIFIED`) kept independent.
- **Fail-closed readiness**: `READY`, `READY_WITH_RISKS` (explicit, expiring acceptance),
  `NOT_READY`, `INSUFFICIENT_EVIDENCE`. Controls without evidence are never "passed"; scores never
  compensate blocking findings; scanner errors never pass.
- **Four modes**: STATIC (default, offline, read-only) · THREAT MODEL · CONTROLLED DYNAMIC (17
  synthetic scenarios, only in a verified network-less sandbox) · CI/CD gate with baseline diff.
- **Declarative policies** (4 profiles + your own, schema-validated, Git-versioned).
- **Reports**: Markdown (19 sections), JSON (JSON Schema), SARIF 2.1.0, self-contained HTML, console.
- **Safe by construction**: never executes or installs the target, no network, symlink/traversal
  protection, parser limits (alias bombs, deep nesting), secret redaction everywhere.

## Architecture

```
discovery → safe parsing → framework adapters → normalized inventory (with provenance)
   → analyzers M01–M11 → findings + controls → score + policy → readiness → reporters (M12) → CLI
```

Details, directory purposes and extension points: [docs/architecture.md](docs/architecture.md).

**Repository layout.** The skill itself lives in [`skills/intelligent-agent-security-auditor/`](skills/intelligent-agent-security-auditor/) — `SKILL.md`, `references/`,
`scripts/`, `assets/` and the auditor package `src/`, i.e. only what the agent loads or runs.
Installation docs, CI, tests and the deliberately vulnerable `examples/` stay at the repository root,
outside the skill folder.
Supported frameworks (partial static detection): OpenAI Agents SDK, LangChain, LangGraph, CrewAI,
AutoGen, custom Python; JS/TS (regex); MCP configs and servers; `agent-manifest.yaml` for anything
dynamic. See [limitations](skills/intelligent-agent-security-auditor/references/limitations.md).

## Requirements

Python **3.11+** and PyYAML. No network access, credentials or services are needed for static
audits. Controlled dynamic tests additionally need a network-less sandbox (e.g. `docker run --network none`).

## Installation

> **Verify the release.** Tag `v1.1.0` must resolve to commit
> `d02fad2ad6572f1481090c7b535bf7ec7d8182ae` (also listed on the
> [v1.1.0 release page](https://github.com/titoparra4/intelligent-agent-security-auditor/releases/tag/v1.1.0)).
> Check the clone with `git rev-parse 'v1.1.0^{commit}'` before installing; if the hashes differ, do not install.

**From GitHub**

```bash
git clone --branch v1.1.0 https://github.com/titoparra4/intelligent-agent-security-auditor.git
cd intelligent-agent-security-auditor
git rev-parse 'v1.1.0^{commit}'   # must print d02fad2ad6572f1481090c7b535bf7ec7d8182ae
python3.11 -m venv .venv && . .venv/bin/activate
pip install -e .
agent-security-auditor version
```

**As an Agent Skill with [skills.sh](https://skills.sh/)**

```bash
npx skills add titoparra4/intelligent-agent-security-auditor
```

**As an Agent Skill, manually** — copy only the skill folder:

```bash
git clone --depth 1 --branch v1.1.0 https://github.com/titoparra4/intelligent-agent-security-auditor.git /tmp/iasa
git -C /tmp/iasa rev-parse 'v1.1.0^{commit}'   # must print d02fad2ad6572f1481090c7b535bf7ec7d8182ae
cp -R /tmp/iasa/skills/intelligent-agent-security-auditor ~/.claude/skills/
```

Installation behavior depends on your skills CLI version and host (Claude Code, Codex and other
Agent Skills hosts). Manual installation and hosts without skill directories are covered in
[docs/installation.md](docs/installation.md), including what has actually been verified.

## Configuration

- **Policy** — builtin profiles `basic-agent` (default), `enterprise-agent`, `mcp-integrated-agent`,
  `high-risk-autonomous-agent`, or a YAML file ([schema](skills/intelligent-agent-security-auditor/assets/schemas/policy.schema.json),
  [examples](examples/policies/)): authorized/forbidden tools, forbidden operations, denied scopes,
  allowed destinations, restricted data, approval rules, isolation requirements, blocking
  severities, mandatory controls, exceptions with owner and expiry, scoring weights.
- **Agent manifest** — `agent-manifest.yaml` in the target declares what static analysis cannot
  infer (identities, scopes, approvals, memory scope, allowlists, delegations, MCP pins)
  ([schema](skills/intelligent-agent-security-auditor/assets/schemas/agent-manifest.schema.json), [example](examples/secure-agent/agent-manifest.yaml)).

## Usage

```bash
agent-security-auditor audit ./my-agent --mode static
agent-security-auditor audit ./my-agent --format json --output ./reports
agent-security-auditor audit ./my-agent --policy enterprise-agent --format markdown,json,sarif,html -o ./reports
agent-security-auditor permissions ./my-agent
agent-security-auditor mcp ./my-agent
agent-security-auditor data-flow ./my-agent
agent-security-auditor threat-model ./my-agent
agent-security-auditor test ./my-agent                       # test plan; nothing runs
agent-security-auditor compare ./previous.json ./current.json
agent-security-auditor audit ./my-agent --mode ci --baseline ./previous.json
agent-security-auditor policy validate ./security-policy.yaml
```

Exit codes: `0` READY · `10` READY_WITH_RISKS · `20` NOT_READY / regression · `30`
INSUFFICIENT_EVIDENCE · `64` usage · `65` bad input · `70` scanner error (never a pass) · `75`
dynamic preconditions unmet (nothing executed) · `78` invalid policy. Full reference:
[docs/usage.md](docs/usage.md).

As a skill, the assistant follows [SKILL.md](skills/intelligent-agent-security-auditor/SKILL.md): runs the tool, triages findings against
the cited code, adds clearly-labelled analyst judgment and answers with the output contract.

## Examples

| Example | What it shows | Result |
|---|---|---|
| [vulnerable-agent-lab](examples/vulnerable-agent-lab/) | simulated Gmail, Drive, CRM DB and local MCP server with documented flaws | `NOT_READY` (exit 20) |
| [secure-agent](examples/secure-agent/) | same agent with controls applied | `READY` (basic) · `READY_WITH_RISKS` (enterprise + accepted exception) |
| [mcp-security](examples/mcp-security/) | STDIO vs HTTP, poisoning, drift, passthrough, shell wrappers | MCP-001…010 |
| [multi-agent](examples/multi-agent/) | delegation escalation, unauthenticated channel, cycles | MA-001…004 |
| [policies](examples/policies/) | profiles, exception workflow, invalid policy | — |
| [sample-reports](examples/sample-reports/) | generated Markdown/JSON/SARIF/HTML | — |

## Example report

`agent-security-auditor audit examples/vulnerable-agent-lab` (excerpt of the real output; the console lists the first 15 findings, the reports list all 32):

```
Readiness: NOT_READY
  - 6 open blocking finding(s): SEC-001 DATA-005 HIGH/CONFIRMED, SEC-002 EXF-001 HIGH/CONFIRMED, SEC-003 PERM-001 HIGH/CONFIRMED, ...
  - mandatory control(s) failed: CTRL-PI-01, CTRL-EXF-01, CTRL-PERM-01, CTRL-AUTO-01
Score: 0/100 (grade E)   Coverage: 72.7% of applicable controls verified
  SEC-002  HIGH     CONFIRMED   EXF-001   Unrestricted external destination — destination:metrics-collector.lab.invalid src/agent.py:57
  SEC-003  HIGH     CONFIRMED   PERM-001  Excessive data permissions — tool:drive_search src/agent.py:22
  ...
  SEC-017  MEDIUM   POTENTIAL   PI-001    Indirect prompt injection exposure via tool output — tool:gmail_read_inbox src/agent.py:28   (in the reports)
```

Each finding in the Markdown report carries evidence such as:

```
#### SEC-003 — Excessive data permissions — HIGH
Status / confidence: CONFIRMED / HIGH · Location: src/agent.py:22 · OWASP: ASI03:2026, ASI02:2026, LLM03:2026
Evidence: `code` src/agent.py:22 — scope 'https://www.googleapis.com/auth/drive' grants ['delete', 'read', 'send', 'write']; tool performs ['read']
Remediation: request the narrowest scope (drive.file or drive.readonly) ...
```

Full samples: [examples/sample-reports/](examples/sample-reports/).

## OWASP mapping

| OWASP Agentic 2026 | Main rules | Behavioral tests |
|---|---|---|
| ASI01 Agent Goal Hijack | PI-001…004, ARCH-001, MEM-004 | ADV-PI-001…005 |
| ASI02 Tool Misuse and Exploitation | EXF-001/002, DATA-003, PERM-001, AUTO-001 | ADV-EXF-001, ADV-AUTO-001 |
| ASI03 Identity and Privilege Abuse | PERM-001…003, DATA-005, MCP-003/004/006 | ADV-PRIV-001 |
| ASI04 Agentic Supply Chain Vulnerabilities | MCP-001/005/007/011, SUP-001…006 | ADV-MCP-001 |
| ASI05 Unexpected Code Execution | AUTO-003, EXF-004, MCP-009 | ADV-EXEC-001 |
| ASI06 Memory & Context Poisoning | MEM-001…005, PI-003 | ADV-MEM-001/002 |
| ASI07 Insecure Inter-Agent Communication | MA-001/002/004 | ADV-MA-001 |
| ASI08 Cascading Failures | AUTO-002/004, MA-003 | ADV-ERR-001 |
| ASI09 Human-Agent Trust Exploitation | AUTO-001, AUTO-006 | ADV-APPR-001, ADV-ID-001 |
| ASI10 Rogue Agents | EXF-002/003/004, AUTO-005 | — |

Also mapped: OWASP Top 10 for LLM Applications 2026, NIST AI RMF 1.0 and AI 600-1, MCP security
best practices, MITRE ATLAS and CWE — see [references/](skills/intelligent-agent-security-auditor/references/) and the generated
[rule catalog](skills/intelligent-agent-security-auditor/references/detection-rules.md).

## Limitations

Static analysis shows exposure and configuration facts, not exploitation; framework detection is
partial; runtime-built destinations and tools need the manifest; remote MCP tool lists are not
fetched; vulnerability matching is offline and opt-in; dynamic results are as faithful as the
harness. Read [limitations](skills/intelligent-agent-security-auditor/references/limitations.md) before relying on a verdict.

## Security policy

Report vulnerabilities in the auditor privately — see [SECURITY.md](SECURITY.md). The auditor's
own threat model is in [docs/threat-model.md](docs/threat-model.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Key rules: offline and safe by default, honest coverage,
status discipline, official references only, tests for every rule.

## License

[MIT](LICENSE) © 2026 titoparra4 and contributors.
