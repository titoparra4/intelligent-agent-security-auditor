# Installation

Requirements: Python **3.11+**, PyYAML. No other runtime dependency, no network at audit time.

## As an Agent Skill

### skills.sh (Claude Code, Codex and other Agent Skills hosts supported by the `skills` CLI)

```bash
npx skills add titoparra4/intelligent-agent-security-auditor
```

The `skills` CLI copies the skill directory (`skills/intelligent-agent-security-auditor/`, with `SKILL.md`) into the skills folder of the
detected agent(s). Supported hosts and target folders depend on the CLI version — check
`npx skills --help`. The skill's scripts still need Python 3.11+ on the machine.

### Manual (any host that reads `SKILL.md` directories)

```bash
git clone --depth 1 --branch v1.1.0 https://github.com/titoparra4/intelligent-agent-security-auditor.git /tmp/iasa
git -C /tmp/iasa rev-parse 'v1.1.0^{commit}'   # must print d02fad2ad6572f1481090c7b535bf7ec7d8182ae
cp -R /tmp/iasa/skills/intelligent-agent-security-auditor ~/.claude/skills/          # Claude Code (user scope)
# project scope: cp -R /tmp/iasa/skills/intelligent-agent-security-auditor <repo>/.claude/skills/
```

Copy only the skill folder: the repository root also holds tests, CI and deliberately vulnerable
example agents that are not part of the skill.

For other hosts, place the directory where that host loads skills (e.g. Codex: `~/.codex/skills/`
— verify with your Codex version's documentation). The directory name must equal the skill
`name` (`intelligent-agent-security-auditor`).

### Hosts without filesystem skills

Chat interfaces that do not load skill directories (or that only accept uploaded skill archives)
can use the skill by uploading a zip of `skills/intelligent-agent-security-auditor/` where supported, or by pasting `SKILL.md`
plus the relevant `references/*.md` as context; in that case the bundled tool cannot run and the
assistant must state that the assessment was performed manually.

## As a CLI / Python package

```bash
git clone https://github.com/titoparra4/intelligent-agent-security-auditor.git
cd intelligent-agent-security-auditor
python3.11 -m venv .venv && . .venv/bin/activate
pip install -e .            # or: pip install -e '.[dev]' to run the tests
agent-security-auditor version
```

Without installing: `python3 skills/intelligent-agent-security-auditor/scripts/generate_report.py <target>` (needs PyYAML).

## Verified integrations (this release)

| Integration | Status |
|---|---|
| CLI on macOS (Python 3.12) | verified locally |
| GitHub Actions ubuntu-latest, Python 3.11/3.12/3.13 | workflow provided (`.github/workflows/tests.yml`) |
| Dynamic sandbox inside `docker --network none` | workflow job provided (`sandbox-isolated`) |
| `npx skills add` | command documented; verify on your host — behavior depends on the skills CLI version |
| SKILL.md format | validated with the bundled validator test and, when available, the `skills-ref` reference validator |

Nothing else is claimed. Report other working hosts through an issue.
