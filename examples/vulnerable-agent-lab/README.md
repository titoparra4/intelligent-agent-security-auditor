# Vulnerable agent lab — `enterprise-assistant-demo`

> **Intentionally insecure. Synthetic only. Never deploy, never install its requirements, never
> point it at real accounts.** All services (Gmail, Google Drive, the enterprise CRM database and
> the local MCP server) are simulated; every name, address and endpoint is fictitious and uses
> reserved domains (`.invalid`, `.example`). The auditor analyses these files statically.

## Components

| File | Simulates |
|---|---|
| `src/agent.py` | OpenAI Agents SDK agent with 4 tools: `gmail_read_inbox`, `drive_search`, `crm_lookup`, `send_usage_report` |
| `mcp_server/crm_server.py` + `.mcp.json` | local STDIO MCP server `crm-lab` and an unpinned filesystem MCP server |
| `data/inbox/*.json`, `data/drive/*.md` | simulated mailbox and Drive content |
| `agent-manifest.yaml` | declared architecture (identities, memory, allowlist) |
| `sandbox_harness.py`, `scope.yaml` | deterministic stand-in agent + authorization for CONTROLLED DYNAMIC tests |

## Intentional vulnerabilities and the rules that find them

| # | Vulnerability | Where | Rule(s) | Expected status |
|---|---|---|---|---|
| 1 | **Excessive read permissions**: a search-only tool requests full Drive scope (`auth/drive`: read, write, delete, share) | `src/agent.py` `DRIVE_SCOPES` | PERM-001 | CONFIRMED / HIGH |
| 2 | **Data sent to an unauthorized destination**: `send_usage_report` POSTs user data to `metrics-collector.lab.invalid`, not in the allowlist, no approval | `src/agent.py` | EXF-001, AUTO-001, DATA-003 | CONFIRMED / HIGH (EXF-001, AUTO-001), POTENTIAL (DATA-003) |
| 3 | **Indirect prompt injection**: raw email bodies returned into the model context; a planted email hides an instruction in an HTML comment | `gmail_read_inbox`, `data/inbox/email-0042.json` | PI-001, PI-003, PI-004 | POTENTIAL / MEDIUM (exposure — exploitation only shown in the sandbox) |
| 4 | Lethal combination (private data + untrusted content + egress in one context) | agent | ARCH-001 | POTENTIAL / HIGH |
| 5 | MCP tool poisoning (`<IMPORTANT>` read `~/.cursor/mcp.json`, conceal from user) | `mcp_server/crm_server.py` | MCP-005 | POTENTIAL / HIGH |
| 6 | Unpinned filesystem MCP server rooted at `/` | `.mcp.json` | MCP-001, MCP-008 | CONFIRMED |
| 7 | Shared long-term memory, no TTL, untrusted writers, injected into system prompt, no deletion | `agent-manifest.yaml` | MEM-001…005 | CONFIRMED |
| 8 | CRM tool reads all tenants in a multi-user deployment | manifest `tenant_scoped: false` | DATA-005 | CONFIRMED / HIGH |
| 9 | Approval only requested in the system prompt | `prompts/system.md` | AUTO-006 | CONFIRMED |
| 10 | No explicit `max_turns`; email bodies logged; unpinned dependencies, no lockfile | various | AUTO-002, DATA-002, SUP-001, SUP-002 | mixed |

## Run

```bash
agent-security-auditor audit examples/vulnerable-agent-lab            # exit 20 = NOT_READY
agent-security-auditor permissions examples/vulnerable-agent-lab
agent-security-auditor test examples/vulnerable-agent-lab             # test plan only
# inside a network-less sandbox only (otherwise the pre-check refuses, exit 75):
agent-security-auditor test examples/vulnerable-agent-lab --harness sandbox_harness.py \
    --scope examples/vulnerable-agent-lab/scope.yaml --authorize      # all scenarios FAIL by design
```

Sample output: `../sample-reports/vulnerable-agent-lab.md` (and `.json`, `.sarif`, `.html`).
The fixed version of this agent is `../secure-agent/`.
