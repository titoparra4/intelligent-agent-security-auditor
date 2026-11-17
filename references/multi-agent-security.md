# Multi-agent security (MODULE 10)

## Delegation graph

Nodes: agents with identity, privileged tools, exposure to untrusted input and iteration limit.
Edges: delegations with channel, authentication and permission inheritance. Sources:

- OpenAI Agents SDK `handoffs=[...]` and `agent.as_tool(...)` inside another agent's tools;
- CrewAI `Crew(agents=[...])` members with `allow_delegation=True`;
- AutoGen `GroupChat` / `RoundRobinGroupChat` / `SelectorGroupChat` / `Swarm` participants;
- manifest `delegations:` (required for delegations decided at runtime or over queues/HTTP).

Manifest declarations enrich code-detected edges (same from/to) instead of duplicating them.

## Rules

| Rule | Detects |
|---|---|
| MA-001 | delegate inherits the delegator's permissions/credentials (declared, or shared tools) |
| MA-002 | channel without authentication (declared false; undeclared for network channels) |
| MA-003 | delegation cycle without iteration limit on every agent in the cycle |
| MA-004 | agent exposed to untrusted input can delegate to an agent with privileged tools lacking approval (escalation path) |

## Controls

Per-agent identities and scopes (delegate tasks, not credentials) · authenticated, integrity-
protected messages with schema validation · the privileged agent re-validates delegated requests
against policy and approval rules · global step budget and maximum delegation depth · supervision
of sub-agents (logs attributable to agent identity).

Behavioral test: ADV-MA-001 (a delegate reply impersonates a supervisor and requests egress).
