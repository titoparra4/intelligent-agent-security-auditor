# Secure reference agent — `enterprise-assistant-secure`

The same assistant as the vulnerable lab with controls applied. Synthetic; backends simulated.

| Lab flaw | Control here | Evidence the auditor credits |
|---|---|---|
| full Drive scope | `drive.readonly`, `gmail.readonly` | scopes requested in code (provenance `code`) |
| egress to undeclared collector | internal `reports.internal.example`, allowlisted in manifest | `network.allowed_destinations` |
| send without approval | `require_approval(...)` called inside the tool | `approval_enforced_by: src/agent.py::require_approval`, verified in the AST |
| raw email into context | `wrap_untrusted()` spotlighting | `output_handling: spotlighted` (declared; behavior covered by dynamic tests) |
| all-tenant CRM query | query bound to `current_user().tenant_id` | `tenant_scoped: true` |
| shared memory in system prompt | per-user memory, TTL 30d, provenance, deletion, injected as context | manifest `memory` |
| unpinned / poisoned MCP | local reviewed server, description pinned by hash | `mcp_servers.crm-lab.trusted`, `mcp_tool_pins` |
| no turn limit | `max_turns=8`, budget, kill switch | code + manifest |

Expected results:

```bash
agent-security-auditor audit examples/secure-agent                       # READY (basic-agent), exit 0
agent-security-auditor audit examples/secure-agent \
   --policy examples/policies/enterprise-secure-agent.yaml               # READY_WITH_RISKS, exit 10
agent-security-auditor audit examples/secure-agent --policy high-risk-autonomous-agent   # not READY: needs dynamic evidence + lockfile
```

Remaining honest gaps: no hashed lockfile (SUP-002, accepted with expiry in the enterprise example
policy), behavioral controls NOT_VERIFIED until the sandbox scenarios are run, log content not
verifiable statically (CTRL-DATA-03).
