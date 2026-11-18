# Threat Model — {{target_name}}

## Assets
| Asset | Type | Data classification | Owner |
|---|---|---|---|
| {{tool / memory / credential}} | {{data via tool / memory / identity}} | {{pii, confidential, …}} | {{team}} |

## Actors and trust
| Actor | Trust level | Entry points |
|---|---|---|
| Legitimate user | authenticated, partially trusted | chat / API |
| External content author | untrusted | emails, documents, web pages, tickets |
| Tool / MCP server provider | semi-trusted supply chain | tool descriptions, tool output |
| Other agents | depends on channel authentication | delegation messages |

## Trust boundaries
TB-USER · TB-CONTENT · TB-TOOLS · TB-MCP · TB-MEMORY · TB-AGENTS · TB-NETWORK · TB-EXEC — {{which exist and what crosses them}}

## Data flows
| Source | Data | Sink | Destination | Controls (enforced outside the model) | Risk |
|---|---|---|---|---|---|

## Threats (OWASP Agentic 2026)
| ID | Threat | ASI | Surface | Scenario | Existing controls | Residual risk |
|---|---|---|---|---|---|---|
| TM-01 | Goal hijack through retrieved content | ASI01 | {{tools}} | {{…}} | {{…}} | {{…}} |

## Diagram
```mermaid
{{output of: agent-security-auditor architecture <target>}}
```
