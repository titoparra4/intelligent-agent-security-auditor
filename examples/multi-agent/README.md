# Multi-agent example

Synthetic OpenAI-Agents-style system: `triage-agent` reads an external support inbox and can hand
off to `finance-agent`, which holds `transfer_funds` without approval; `research-agent` and
`writer-agent` hand off to each other without turn limits. The manifest declares the HTTP channel
to the finance agent as unauthenticated and inheriting permissions.

| Rule | Why |
|---|---|
| AUTO-001 (CRITICAL) | `transfer_funds` (financial) without enforced approval |
| MA-004 | untrusted-input agent → privileged agent escalation path |
| MA-002, MA-001 | unauthenticated channel, inherited permissions (declared) |
| MA-003 | `research-agent ⇄ writer-agent` cycle without limits |

`research_agent.handoffs = [...]` is a runtime assignment the static adapter does not resolve —
which is why the manifest declares that edge (see skills/intelligent-agent-security-auditor/references/limitations.md).

```bash
agent-security-auditor architecture examples/multi-agent --format json   # delegation graph
agent-security-auditor audit examples/multi-agent
```
