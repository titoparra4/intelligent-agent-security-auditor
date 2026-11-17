# Data leakage and exfiltration (MODULES 03 and 04)

## Sources, transformations, sinks

The auditor builds `source → agent context → sink` flows from the inventory:

- **Sources**: tools with `read` operations and data access (email, documents, database,
  payments, secrets, files), memory stores, RAG corpora.
- **Sinks**: tools with `send`/`network` operations, HTTP calls with payloads, logs, telemetry
  SDKs, other agents.
- **Controls credited on a flow**: human approval enforced on the sink, destination allowlisted
  (policy or manifest). Anything else (prompt instructions, "the model will not do that") is not
  a control.

Report section 11 lists every flow with its controls and risk.

## Rules

| Rule | Detects | Status logic |
|---|---|---|
| DATA-001 | hard-coded secrets (provider key formats, private keys, JWT, connection strings, high-entropy assignments) | CONFIRMED (presence), value redacted |
| DATA-002 | logging/print of variables named like secrets, prompts, messages, tool results, memory | POTENTIAL; `len()`/`type()`/hash wrappers are ignored |
| DATA-003 | sensitive source and uncontrolled egress in the same agent | POTENTIAL |
| DATA-004 | committed `.env` with real-looking values | CONFIRMED |
| DATA-005 | data tools not tenant-scoped in a multi-user deployment | CONFIRMED if declared `tenant_scoped: false` |
| EXF-001 | data sent to non-allowlisted destination | CONFIRMED for literal URL + payload in code |
| EXF-002 | request bins, webhooks, tunnels, paste sites, OAST | CONFIRMED when called |

## Privacy by design of the auditor

- Secret values are never stored: only type, location and length; snippets pass through
  redaction (provider formats, bearer tokens, Luhn-valid card numbers, e-mail local parts).
- Reports contain no full personal data; the tool needs no credentials and opens no connections.
- Dynamic tests use random canary tokens; a leaked canary is reported truncated.

## GDPR as a technical reference

Retention (Art. 5(1)(e)) → MEM-002; erasure (Art. 17) → MEM-005; minimisation → PERM-001,
DATA-003. These are technical control references only — **no legal compliance determination**.

## Recommended controls

Egress proxy with allowlist (enforced by network policy, not code convention) · DLP on outbound
payloads · per-tool identities · approval on any send to new recipients · metadata-only logs ·
row-level security bound to the end user.
