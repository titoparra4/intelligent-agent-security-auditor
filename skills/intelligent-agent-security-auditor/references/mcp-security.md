# MCP security (MODULE 06)

| Reference | Version | Link |
|---|---|---|
| Model Context Protocol specification | 2025-06-18 (later revisions keep the same security sections; check the current one) | https://modelcontextprotocol.io/specification/2025-06-18 |
| MCP Authorization (HTTP transports) | 2025-06-18 | https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization |
| MCP Security Best Practices | 2025-06-18 | https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices |

## Transport matters

| Concern | STDIO (local process) | Streamable HTTP / SSE (remote) |
|---|---|---|
| Authentication | Spec: credentials come from the environment; HTTP authorization does **not** apply | OAuth 2.1 authorization; tokens bound to the MCP server (audience / resource indicators) |
| Main risks | running unpinned third-party code locally, shell-wrapped launches, broad filesystem roots, inline secrets in config | plaintext transport, missing auth, token passthrough, confused deputy, SSRF, exposed listeners |
| Rules | MCP-001, MCP-004, MCP-008, MCP-009, MCP-011 | MCP-002, MCP-003, MCP-004, MCP-006, MCP-010 |

The auditor never applies MCP-002/MCP-003 to STDIO servers.

## Rules

| Rule | Check | Basis |
|---|---|---|
| MCP-001 | `npx pkg` / `uvx pkg` / `image:latest` without exact version or digest (also inside `sh -c`) | supply chain / rug pull |
| MCP-002 | `http://` URL for non-loopback host | transport security |
| MCP-003 | HTTP/SSE entry without OAuth/Authorization/API-key config | MCP Authorization |
| MCP-004 | literal secret in `env`/`headers` (references like `${VAR}` / `${input:x}` are fine) | credential protection |
| MCP-005 | tool description with model-directed instructions: hidden tags, sensitive file paths, cross-tool directives, concealment, parameter smuggling | tool poisoning |
| MCP-006 | server reuses incoming `Authorization` header for outbound calls | Best Practices: token passthrough is forbidden; confused deputy |
| MCP-007 | tool description hash differs from pin (`mcp_tool_pins` in manifest or `mcp-tools.lock.json`) | definition drift |
| MCP-008 | filesystem server rooted at `/`, `~`, home; unrestricted fetch/browser servers | least privilege, SSRF |
| MCP-009 | STDIO launched via `sh -c` / `bash -c` / `cmd /c` | command injection surface |
| MCP-010 | server source binds `0.0.0.0` | local exposure, DNS rebinding |
| MCP-011 | server not marked trusted (policy `mcp.trusted_servers` or manifest `mcp_servers.<n>.trusted`) | provenance |

## Pinning tool definitions

```json
{"servers": {"crm-lab": {"lookup_customer": "sha256:<sha256 of the stripped description>"}}}
```
Save as `mcp-tools.lock.json` (or `mcp_tool_pins` in the manifest). The hash is computed as
`sha256(description.strip())`. Re-pin only after reviewing a changed description.

## Limits

Tools of package-based or remote servers are not fetched (no execution, no network): poisoning
checks for them stay NOT_VERIFIED unless their definitions are available in the repository.
