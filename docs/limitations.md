# Limitations

This tool provides a security assessment based on available evidence. It does not guarantee that
an AI agent is secure or constitute a formal security certification. It is not certified or
endorsed by OWASP, NIST, MITRE or the MCP project.

## Detection coverage

| Area | Supported | Not supported |
|---|---|---|
| OpenAI Agents SDK (Python) | `Agent(...)`, `@function_tool`, handoffs, `as_tool`, `Runner.run*(max_turns=)` | agents/tools built in loops or factories; guardrails semantics |
| LangChain | `@tool`, `Tool(...)`, `StructuredTool.from_function`, `AgentExecutor(max_iterations=)`, `load_tools`, REPL/shell tools, vector stores, memory classes | LCEL graph semantics, custom tool classes subclassing `BaseTool` |
| LangGraph | `create_react_agent(..., interrupt_before=)`, `recursion_limit` in invoke config | custom `StateGraph` node semantics |
| CrewAI | `Agent(role=, tools=, allow_delegation=, allow_code_execution=, code_execution_mode=, max_iter=)`, `Crew(agents=)` | YAML-configured crews (`agents.yaml`) |
| AutoGen | `AssistantAgent`/`UserProxyAgent`/`ConversableAgent`, `code_execution_config`, `human_input_mode`, group chats, local vs Docker executors | AutoGen Studio JSON |
| JavaScript / TypeScript | regex: literal-URL `fetch`/`axios`/`got`/`ky`, `new Agent({name})`, AI SDK `tool({description})`, MCP `server.tool`/`registerTool` | AST analysis, imports, variables |
| MCP | client configs (`mcpServers`, `servers`), stdio/http/sse, pinning, inline secrets, server source tools (Python decorators, JS/TS) | fetching tool lists of remote/package servers (would require execution or network) |
| Dependencies | requirements, pyproject (PEP 621, Poetry), Pipfile, package.json, lockfile presence, install hooks | transitive resolution; lockfile version parsing; live CVE lookup |

"Partial" is the honest description for every framework: anything constructed dynamically must be
declared in `agent-manifest.yaml`.

## Analysis limits

- Static analysis shows **exposure and configuration facts**, not exploitation. Prompt-injection
  and exfiltration exploitability are only established by controlled dynamic tests.
- Data-flow analysis is intra-agent and conservative; cross-module dataflow is not tracked.
- Destinations built at runtime (config, env, string building across modules) are not resolved.
- Secret detection is pattern/entropy based; values with placeholder markers ("example", "test",
  "demo", …) are ignored by design to limit false positives.
- Effective permissions are not tested against live identity providers.
- Manifest declarations are intent, not enforcement; only approval gates referenced in code are
  corroborated statically.
- The score is a heuristic indicator with configurable weights; compare scores only under the same
  policy and coverage.

## Dynamic testing limits

- Requires a network-less sandbox; on a normal workstation the pre-check refuses to run (by design).
- Harness fidelity bounds validity: deterministic harnesses validate test mechanics and design; a
  harness wrapping the real agent with a *local* model is needed to measure model behavior.
- The in-process audit-hook guard is defense in depth; the container/VM is the security boundary.

## Verification status of this release

- Reference titles (OWASP Agentic 2026, OWASP LLM 2026) were checked against the official PDFs on
  2026-11-17. MCP specification links point to the 2025-06-18 revision and were not re-fetched for
  this release. MITRE ATLAS technique names change between releases; IDs are the stable key.
- The dynamic isolation pre-check was exercised locally only in its refusal path (the development
  host had network access); the isolated path runs in the CI job `sandbox-isolated`.
