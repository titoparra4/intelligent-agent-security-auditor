# MCP security example

Synthetic MCP client configurations and server source covering transport-aware checks.

| Item | File | Expected rule |
|---|---|---|
| remote server over `http://` without auth | `.vscode/mcp.json` `partner-plaintext` | MCP-002, MCP-003 |
| remote server over TLS with `Bearer ${input:…}` reference | `partner-tls` | none (correct) |
| SSE server with a literal API key header (**fake value, intentionally committed**) | `legacy-sse` | MCP-004 |
| STDIO server via `bash -c "… npx -y pkg"` | `claude_desktop_config.json` `shell-wrapped` | MCP-009, MCP-001 |
| container image `:latest` | `container` | MCP-001 |
| `uvx pkg==x.y.z` | `pinned-python` | none (pinned) |
| poisoned tool description (TypeScript server) | `server/notes_server.ts` `add_note` | MCP-005 |
| description drift vs pin | `mcp-tools.lock.json` `search_notes` | MCP-007 |
| token passthrough + `0.0.0.0` bind | `server/proxy_server.py` | MCP-006 (POTENTIAL, low confidence), MCP-010 |

STDIO servers never receive HTTP authorization findings (MCP-002/003), per the MCP specification.

```bash
agent-security-auditor mcp examples/mcp-security
agent-security-auditor audit examples/mcp-security --policy mcp-integrated-agent
```
