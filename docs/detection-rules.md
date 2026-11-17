# Detection rules

Generated from `src/agent_security_auditor/rules/catalog.py` (do not edit by hand; `tests/unit/test_docs.py` checks it is in sync). Regenerate with `python -c "from agent_security_auditor.rules.docs import write; write()"`.

Default severity is the rule's starting point; analyzers adjust severity, confidence and status per occurrence (e.g. a heuristic match is POTENTIAL, a configuration fact is CONFIRMED). Rules marked *specialized review* recommend a code-level security review (e.g. with a secure code review skill).

## M01 — Agent Architecture Analyzer

| Rule | Title | Dimension | Default severity | OWASP | NIST | Other |
|---|---|---|---|---|---|---|
| ARCH-001 | Lethal combination: private data + untrusted content + external communication | Data Leakage | HIGH | ASI01:2026; ASI02:2026; LLM01:2026; LLM02:2026 | MEASURE 2.7; NIST AI 600-1 Information Security | MITRE ATLAS AML.T0051.001 LLM Prompt Injection; MITRE ATLAS AML.T0057 LLM Data Leakage |
| ARCH-002 | Agent architecture could not be reconstructed | Compliance & Governance | INFO | — | MAP 4.1 | — |
| ARCH-003 | Components detected only by inference (no manifest) | Compliance & Governance | INFO | — | GOVERN 1.1; MAP 4.1 | — |

### ARCH-001 — Lethal combination: private data + untrusted content + external communication

The same agent context can (1) read sensitive data, (2) ingest attacker-controllable content and (3) communicate externally. Any successful indirect prompt injection can chain these into data exfiltration without a software vulnerability.

- **Impact:** Exfiltration of sensitive data driven by injected instructions (zero-click style).
- **Preconditions:** Attacker can place content the agent will read (email, document, web page, ticket); Agent processes that content in the same context that holds sensitive data; An egress tool or destination is reachable without independent approval
- **Remediation:** Break the combination: remove one leg or isolate it. Run untrusted-content processing in a quarantined context without sensitive tools, require human approval for egress, and enforce a destination allowlist outside the model.
- **Verification:** Re-run the audit and confirm ARCH-001 no longer applies; Run adversarial scenario ADV-PI-002 / ADV-EXF-001 in the sandbox and confirm egress is blocked

### ARCH-002 — Agent architecture could not be reconstructed

No agent, tool or MCP component was detected. The audit cannot assess what it cannot see.

- **Impact:** Readiness cannot be established; risks may exist in components outside the scanned scope.
- **Preconditions:** Agent defined dynamically, in an unsupported framework, or outside the scanned path
- **Remediation:** Add an agent-manifest.yaml describing agents, tools, permissions and memory, or point the auditor at the directory that contains the agent definition.
- **Verification:** Re-run the audit and confirm components appear in the Asset & Permission Inventory

### ARCH-003 — Components detected only by inference (no manifest)

No agent-manifest was found. Permissions, identities, approval rules and memory scope are inferred from code and names, which lowers confidence and leaves many controls NOT_VERIFIED.

- **Impact:** Controls that depend on declared facts remain unverified.
- **Preconditions:** No agent-manifest.yaml in the target
- **Remediation:** Document the agent in agent-manifest.yaml (see assets/schemas/agent-manifest.schema.json) and keep it versioned with the code.
- **Verification:** Re-run the audit and confirm the inventory shows 'declared' provenance

## M02 — Prompt Injection Detector

| Rule | Title | Dimension | Default severity | OWASP | NIST | Other |
|---|---|---|---|---|---|---|
| PI-001 | Indirect prompt injection exposure via tool output | Prompt Injection | MEDIUM | ASI01:2026; LLM01:2026 | MEASURE 2.7 | MITRE ATLAS AML.T0051.001 LLM Prompt Injection |
| PI-002 | Untrusted input interpolated into system instructions | Prompt Injection | MEDIUM | ASI01:2026; LLM01:2026 | MEASURE 2.7 | MITRE ATLAS AML.T0051.000 LLM Prompt Injection |
| PI-003 | Instruction-like payload found in agent-reachable content | Prompt Injection | MEDIUM | ASI01:2026; ASI06:2026; LLM01:2026; LLM05:2026 | MEASURE 2.7 | MITRE ATLAS AML.T0051.001 LLM Prompt Injection; MITRE ATLAS AML.T0070 RAG Poisoning |
| PI-004 | Encoded or hidden instructions in content | Prompt Injection | MEDIUM | ASI01:2026; LLM01:2026 | MEASURE 2.7 | MITRE ATLAS AML.T0051.001 LLM Prompt Injection |

### PI-001 — Indirect prompt injection exposure via tool output

A tool returns externally controllable content (email, documents, web, tickets, RAG) into the model context without a declared isolation mechanism (spotlighting/delimiting, quarantined LLM, content sanitization).

- **Impact:** Instructions embedded in retrieved content can redirect the agent's goal or trigger tool calls (goal hijack).
- **Preconditions:** Attacker can write content the tool will return; Tool output enters the same context that decides tool calls
- **Remediation:** Treat tool output as data: wrap it in explicit untrusted-content markers, strip/neutralize instruction-like content, process it in a quarantined sub-agent without privileged tools, and enforce authorization for follow-up tool calls outside the model.
- **Verification:** Declare output_handling for the tool and re-run the audit; Run ADV-PI-002 (tool-output injection) in the sandbox and confirm no unauthorized tool call occurs

### PI-002 — Untrusted input interpolated into system instructions

The agent's system/developer instructions are built with string interpolation of variables whose names suggest user, document, memory or tool content. That content gains instruction-level authority.

- **Impact:** Role spoofing and instruction-hierarchy confusion: injected text is read as developer instructions.
- **Preconditions:** Attacker influences an interpolated variable
- **Remediation:** Keep system instructions static. Pass untrusted content only in user/tool messages with clear delimiters, never inside the system prompt.
- **Verification:** Confirm instructions are a constant string; Run ADV-PI-004 (role spoofing) in the sandbox

### PI-003 — Instruction-like payload found in agent-reachable content

Content stored in the project (fixtures, documents, emails, knowledge-base files, tool descriptions) contains text that tries to override instructions, spoof roles or trigger tools. It is evidence of poisoned or adversarial content reachable by the agent, not proof of exploitation.

- **Impact:** If loaded into context, the content may hijack the agent's goal.
- **Preconditions:** The file is loaded into the agent context (RAG corpus, fixture, tool response)
- **Remediation:** Remove or quarantine the content; if it is an intentional test fixture, keep it under tests/ and exclude it from production corpora. Add ingestion-time scanning for instruction-like content.
- **Verification:** Re-run the audit; confirm the file is excluded or cleaned

### PI-004 — Encoded or hidden instructions in content

Content contains hidden characters (zero-width / bidi controls), HTML comments or encoded blobs whose decoded form looks like instructions. These are common obfuscation techniques for injection payloads.

- **Impact:** Payloads invisible to human reviewers can still be read by the model.
- **Preconditions:** Content reaches the model context
- **Remediation:** Normalize and strip invisible characters and comments at ingestion; decode-and-scan encoded content; reject documents with hidden instructions.
- **Verification:** Re-run the audit and confirm no PI-004 findings remain

## M03 — Data Leakage Auditor

| Rule | Title | Dimension | Default severity | OWASP | NIST | Other |
|---|---|---|---|---|---|---|
| DATA-001 | Hard-coded secret in agent project | Data Leakage | HIGH | ASI03:2026; LLM02:2026 | NIST AI 600-1 Information Security | CWE-798 |
| DATA-002 | Sensitive data or full model context written to logs | Data Leakage | MEDIUM | ASI03:2026; LLM02:2026 | MEASURE 2.10; NIST AI 600-1 Data Privacy | CWE-532 |
| DATA-003 | Sensitive data can flow to an egress sink without control | Data Leakage | HIGH | ASI02:2026; ASI03:2026; LLM02:2026; LLM03:2026 | MEASURE 2.10; NIST AI 600-1 Data Privacy | — |
| DATA-004 | Environment file with values committed | Data Leakage | MEDIUM | LLM02:2026 | NIST AI 600-1 Information Security | CWE-538 |
| DATA-005 | Cross-user / cross-tenant data access not isolated | Data Privacy | HIGH | ASI03:2026; LLM02:2026 | MEASURE 2.10; NIST AI 600-1 Data Privacy | — |

### DATA-001 — Hard-coded secret in agent project

A credential-like value is stored in source or configuration. The value is redacted in this report.

- **Impact:** Credential compromise; any party with repository access (or the model, if the file is in context) obtains it.
- **Preconditions:** Repository or file content is accessible to an unauthorized party or loaded into the model context
- **Remediation:** Revoke and rotate the credential, remove it from history, and load secrets from a secret manager or environment at runtime. Never place secrets in prompts or tool descriptions.
- **Verification:** Confirm the credential is revoked; Re-run the audit and confirm DATA-001 is gone

### DATA-002 — Sensitive data or full model context written to logs

Logging/print statements emit variables that likely contain secrets, personal data, full prompts, tool results or memory content.

- **Impact:** Logs become a secondary data store outside access controls and retention policies.
- **Preconditions:** Logs are shipped to systems with broader access than the source data
- **Remediation:** Log identifiers and metadata, not content. Apply structured redaction before logging and set retention.
- **Verification:** Inspect log output in a sandbox run with synthetic canary data and confirm no canary appears

### DATA-003 — Sensitive data can flow to an egress sink without control

A tool that reads sensitive data and a tool/destination that sends data externally coexist in one agent, and the egress path has neither human approval nor a destination allowlist.

- **Impact:** Disclosure of personal, financial or confidential data to third parties.
- **Preconditions:** Model decides to call the egress tool with sensitive content (by error or injection)
- **Remediation:** Require approval for egress tools, enforce a destination allowlist in the tool/backend, and apply DLP to outbound payloads.
- **Verification:** Run ADV-EXF-001 with canary data and confirm the canary never leaves the sandbox

### DATA-004 — Environment file with values committed

A .env-style file with non-placeholder values is part of the audited tree.

- **Impact:** Secrets or configuration intended to stay local are distributed with the code.
- **Preconditions:** The file is committed or packaged
- **Remediation:** Remove the file from version control, add it to .gitignore and provide a .env.example with placeholders.
- **Verification:** Re-run the audit and confirm DATA-004 is gone

### DATA-005 — Cross-user / cross-tenant data access not isolated

A data-access tool queries shared stores without evidence of user or tenant scoping in the query or the credential used.

- **Impact:** One user can obtain another user's or tenant's data through the agent.
- **Preconditions:** Multi-user deployment; Tool credential can read all tenants' data
- **Remediation:** Bind tool credentials and queries to the end-user identity (row-level security, per-tenant credentials, on-behalf-of tokens). Never rely on the model to filter tenants.
- **Verification:** Run ADV-PRIV-001 (cross-tenant request) and confirm denial at the backend

## M04 — Spyware & Exfiltration Risk Analyzer

| Rule | Title | Dimension | Default severity | OWASP | NIST | Other |
|---|---|---|---|---|---|---|
| EXF-001 | Unrestricted external destination | Network Security | HIGH | ASI02:2026; LLM02:2026 | MEASURE 2.7; NIST AI 600-1 Information Security | MITRE ATLAS AML.T0057 LLM Data Leakage |
| EXF-002 | Known exfiltration-friendly endpoint | Network Security | HIGH | ASI02:2026; ASI10:2026; LLM02:2026 | NIST AI 600-1 Information Security | — |
| EXF-003 | Sensitive local collection capability | Spyware & Malware | MEDIUM | ASI10:2026; ASI02:2026 | MEASURE 2.10; NIST AI 600-1 Data Privacy | — |
| EXF-004 | Hidden execution, persistence or obfuscated code *(specialized review)* | Spyware & Malware | HIGH | ASI05:2026; ASI10:2026 | NIST AI 600-1 Information Security | CWE-506 |
| EXF-005 | Undeclared telemetry or analytics SDK | Data Privacy | LOW | LLM02:2026 | MEASURE 2.10; NIST AI 600-1 Data Privacy | — |

### EXF-001 — Unrestricted external destination

The agent sends data to an external destination that is not in the policy/manifest allowlist (or no allowlist exists).

- **Impact:** Data can be transmitted to unauthorized third parties; the destination is a ready-made exfiltration channel.
- **Preconditions:** Code path reachable from an agent tool or runtime; Payload may include context data
- **Remediation:** Define an egress allowlist enforced by network policy or an egress proxy; remove or declare the destination; require approval for outbound transmissions.
- **Verification:** Add the destination to the allowlist or remove the call, then re-run the audit; In the sandbox, confirm egress to non-allowlisted hosts is blocked

### EXF-002 — Known exfiltration-friendly endpoint

A destination matches a service commonly used to receive arbitrary data (request bins, webhooks, tunnels, paste sites, OAST domains).

- **Impact:** Strong indicator of a data collection channel or debugging leftover that leaks data.
- **Preconditions:** Code path is reachable at runtime
- **Remediation:** Remove the endpoint. If it is legitimate (e.g. a corporate Slack webhook), declare it in the manifest with its purpose and restrict the data sent.
- **Verification:** Re-run the audit and confirm EXF-002 is gone

### EXF-003 — Sensitive local collection capability

Code accesses clipboard, camera, microphone, keystrokes, screenshots, browser profiles, SSH/cloud credential stores or harvests host information. This is a capability indicator, not proof of spyware.

- **Impact:** Covert collection of user or host data if the capability is not part of the agent's declared purpose.
- **Preconditions:** Code path reachable at runtime; Capability not disclosed to users
- **Remediation:** Remove the capability or declare it explicitly (manifest + user disclosure) and scope it to the task.
- **Verification:** Confirm the capability is removed or declared and justified

### EXF-004 — Hidden execution, persistence or obfuscated code

Code decodes and executes payloads, spawns detached/background processes, or installs persistence (cron, launch agents, systemd units, registry Run keys, shell profiles).

- **Impact:** Persistent or concealed behavior outside the agent's visible actions.
- **Preconditions:** Code path reachable at install or run time
- **Remediation:** Remove obfuscated execution and undeclared persistence. Any background process must be declared, documented and supervisable.
- **Verification:** Manual review of the referenced code by a security engineer

### EXF-005 — Undeclared telemetry or analytics SDK

A telemetry/analytics/error-reporting SDK is used but not declared in the manifest.

- **Impact:** Prompts, outputs or user data may be sent to a third-party processor without disclosure.
- **Preconditions:** SDK initialized at runtime
- **Remediation:** Declare telemetry in the manifest (destination, data categories, opt-out) and scrub prompts and PII from events.
- **Verification:** Confirm declaration and scrubbing configuration

## M05 — Tool Permission Auditor

| Rule | Title | Dimension | Default severity | OWASP | NIST | Other |
|---|---|---|---|---|---|---|
| PERM-001 | Excessive data permissions | Identity & Access | HIGH | ASI03:2026; ASI02:2026; LLM03:2026 | MEASURE 2.7 | — |
| PERM-002 | Administrative or wildcard privilege granted to agent tool | Identity & Access | CRITICAL | ASI03:2026; LLM03:2026 | MEASURE 2.7 | — |
| PERM-003 | Shared identity across tools with different privilege needs | Identity & Access | MEDIUM | ASI03:2026 | MEASURE 2.7 | — |
| PERM-004 | Tool not authorized by policy | Compliance & Governance | HIGH | ASI02:2026; ASI03:2026; LLM03:2026 | GOVERN 1.1 | — |
| PERM-005 | Policy-forbidden operation available to the agent | Compliance & Governance | HIGH | ASI02:2026; LLM03:2026 | GOVERN 1.1 | — |

### PERM-001 — Excessive data permissions

A tool's credential/scope grants broader access than the tool's operations require (least privilege violation).

- **Impact:** Any misuse of the tool (injection, model error, compromised dependency) operates with the broader privilege.
- **Preconditions:** Tool is callable by the model; Credential with broad scope is available at runtime
- **Remediation:** Request the narrowest scope that supports the tool's operations (e.g. drive.file or drive.readonly instead of drive; gmail.readonly instead of https://mail.google.com/).
- **Verification:** Change the scope, re-run the audit and confirm PERM-001 is gone; In the sandbox, confirm write/delete calls with the tool credential are rejected

### PERM-002 — Administrative or wildcard privilege granted to agent tool

A tool or agent identity holds an administrative, owner or wildcard role/scope.

- **Impact:** Full compromise of the connected system through a single manipulated tool call.
- **Preconditions:** Tool is callable by the model
- **Remediation:** Replace with task-specific roles; separate administrative operations into a human-operated workflow.
- **Verification:** Confirm the role/scope is narrowed and re-run the audit

### PERM-003 — Shared identity across tools with different privilege needs

Multiple tools with different operations reuse the same credential/identity.

- **Impact:** Compromise of the least-sensitive tool yields the privileges of the most-sensitive one; audit trails cannot attribute actions.
- **Preconditions:** Credential reachable by more than one tool
- **Remediation:** Give each tool its own identity scoped to its operations.
- **Verification:** Confirm each tool uses a distinct identity

### PERM-004 — Tool not authorized by policy

The agent exposes a tool that the security policy forbids or does not list as authorized.

- **Impact:** The agent's capabilities exceed what was approved.
- **Preconditions:** Tool is callable by the model
- **Remediation:** Remove the tool or obtain an approved policy change/exception.
- **Verification:** Re-run the audit with the policy and confirm PERM-004 is gone

### PERM-005 — Policy-forbidden operation available to the agent

A tool performs an operation category the policy forbids for this agent (e.g. delete, financial, infra).

- **Impact:** Prohibited actions can be triggered by the model.
- **Preconditions:** Tool is callable by the model
- **Remediation:** Remove the operation from the tool or move it to a human-operated workflow.
- **Verification:** Re-run the audit with the policy and confirm PERM-005 is gone

## M06 — MCP Security Auditor

| Rule | Title | Dimension | Default severity | OWASP | NIST | Other |
|---|---|---|---|---|---|---|
| MCP-001 | MCP server package not version-pinned | Supply Chain | MEDIUM | ASI04:2026; LLM04:2026 | GOVERN 6.1; NIST AI 600-1 Value Chain and Component Integration | MCP Security Best Practices; MITRE ATLAS AML.T0010 ML Supply Chain Compromise |
| MCP-002 | Remote MCP server over plaintext HTTP | API & MCP Security | HIGH | ASI04:2026; ASI07:2026 | NIST AI 600-1 Information Security | MCP Specification; CWE-319 |
| MCP-003 | Remote MCP server without authentication configured | API & MCP Security | MEDIUM | ASI03:2026; ASI04:2026 | NIST AI 600-1 Information Security | MCP Specification |
| MCP-004 | Credential stored inline in MCP configuration | Data Leakage | HIGH | ASI03:2026; LLM02:2026 | NIST AI 600-1 Information Security | CWE-798 |
| MCP-005 | Tool poisoning indicators in MCP tool description | API & MCP Security | HIGH | ASI04:2026; ASI01:2026; LLM01:2026; LLM04:2026 | NIST AI 600-1 Value Chain and Component Integration | MCP Specification; MITRE ATLAS AML.T0053 LLM Plugin Compromise |
| MCP-006 | Possible token passthrough in MCP server *(specialized review)* | API & MCP Security | HIGH | ASI03:2026; ASI07:2026 | NIST AI 600-1 Information Security | MCP Security Best Practices; MCP Security Best Practices |
| MCP-007 | MCP tool definition changed since pinned | Supply Chain | HIGH | ASI04:2026; LLM04:2026 | NIST AI 600-1 Value Chain and Component Integration | MCP Specification |
| MCP-008 | MCP server with filesystem or network scope beyond the task | Identity & Access | HIGH | ASI02:2026; ASI03:2026; LLM03:2026 | MEASURE 2.7 | MCP Security Best Practices |
| MCP-009 | MCP STDIO server launched through a shell | Code Execution | MEDIUM | ASI05:2026 | NIST AI 600-1 Information Security | CWE-78 |
| MCP-010 | MCP server bound to all interfaces | Network Security | MEDIUM | ASI03:2026 | NIST AI 600-1 Information Security | MCP Security Best Practices |
| MCP-011 | Untrusted or unknown MCP server source | Supply Chain | LOW | ASI04:2026 | GOVERN 6.1; NIST AI 600-1 Value Chain and Component Integration | — |

### MCP-001 — MCP server package not version-pinned

The MCP server is launched from a package registry or image without an exact version/digest, so every start may run different code (silent updates, rug pulls, typosquats).

- **Impact:** A compromised or changed upstream package executes with the client's local privileges.
- **Preconditions:** Upstream package or tag changes; Client restarts the server
- **Remediation:** Pin exact versions (npx pkg@1.2.3, uvx pkg==1.2.3, image@sha256:...) and review updates before bumping.
- **Verification:** Confirm the config pins an exact version and re-run the audit

### MCP-002 — Remote MCP server over plaintext HTTP

A remote (HTTP/SSE) MCP server URL uses http:// for a non-loopback host.

- **Impact:** Tokens, tool arguments and results can be intercepted or modified in transit.
- **Preconditions:** Network path is observable or controllable by an attacker
- **Remediation:** Use HTTPS with certificate validation for every non-loopback MCP endpoint.
- **Verification:** Confirm the URL uses https:// and re-run the audit

### MCP-003 — Remote MCP server without authentication configured

An HTTP/SSE MCP server entry has no authorization configuration (OAuth, bearer header or API key). For STDIO servers this rule does not apply.

- **Impact:** If the server exposes sensitive tools, anyone who can reach it can invoke them.
- **Preconditions:** Server is reachable beyond the local user; Server exposes non-public tools/data
- **Remediation:** Use MCP authorization (OAuth 2.1 with audience-bound tokens) or at minimum a per-client bearer token loaded from the environment.
- **Verification:** Confirm authorization is configured and that unauthenticated requests are rejected

### MCP-004 — Credential stored inline in MCP configuration

An env/header value in the MCP configuration contains a literal secret instead of a reference to the environment or a secret store. The value is redacted.

- **Impact:** Configuration files are commonly shared and synced; the credential leaks with them.
- **Preconditions:** Config file is shared, committed or readable by other local processes
- **Remediation:** Reference secrets via environment/secret-store variables (e.g. ${GITHUB_TOKEN}); rotate the exposed value.
- **Verification:** Confirm rotation and that the config contains only references

### MCP-005 — Tool poisoning indicators in MCP tool description

An MCP tool description contains instructions aimed at the model (hidden tags, directives to read files, to call other tools, to conceal actions from the user, or to send data).

- **Impact:** The tool description itself hijacks the agent as soon as the tool list is loaded, even if the tool is never called.
- **Preconditions:** Client loads the server's tool list into model context
- **Remediation:** Remove the server or the poisoned tool; pin and review tool definitions (description hashes) and show full descriptions to users at approval time.
- **Verification:** Re-run the audit and confirm MCP-005 is gone; Run ADV-MCP-001 in the sandbox

### MCP-006 — Possible token passthrough in MCP server

Server code appears to forward the incoming client Authorization token to a downstream API. The MCP authorization specification forbids accepting/forwarding tokens not issued for the MCP server.

- **Impact:** Confused deputy: downstream services cannot distinguish the MCP server from the client; audience checks and rate limits are bypassed.
- **Preconditions:** Server receives client bearer tokens (HTTP transport)
- **Remediation:** Validate token audience for the MCP server itself and obtain separate downstream tokens (token exchange / on-behalf-of flows).
- **Verification:** Review the code path; confirm downstream calls use server-issued credentials

### MCP-007 — MCP tool definition changed since pinned

The description of a pinned MCP tool no longer matches its recorded hash (possible rug pull or unreviewed update).

- **Impact:** Changed instructions are injected into the agent without review.
- **Preconditions:** Tool definitions are loaded from the server at runtime
- **Remediation:** Review the change; re-pin only after approval. Clients should alert on definition changes.
- **Verification:** Update the pin after review and re-run the audit

### MCP-008 — MCP server with filesystem or network scope beyond the task

An MCP server is granted the whole filesystem / home directory or unrestricted fetch capability.

- **Impact:** Read/write access to credentials, SSH keys and unrelated documents; SSRF to internal services.
- **Preconditions:** Server tools are callable by the model
- **Remediation:** Restrict roots to the minimum project directories; for fetch-type servers enforce a URL allowlist and block private/metadata addresses.
- **Verification:** Confirm narrowed roots/allowlist and re-run the audit

### MCP-009 — MCP STDIO server launched through a shell

The STDIO server command runs through sh/bash/cmd -c, enabling shell expansion and command chaining in the launch line.

- **Impact:** Injection into the launch command (via variables or edited config) executes arbitrary commands.
- **Preconditions:** Launch line includes interpolated or user-editable values
- **Remediation:** Invoke the server binary directly with an argument array; avoid shell wrappers.
- **Verification:** Confirm the command no longer uses a shell -c wrapper

### MCP-010 — MCP server bound to all interfaces

Server code binds HTTP/SSE transport to 0.0.0.0, exposing it beyond localhost.

- **Impact:** Other hosts on the network (or DNS-rebinding web pages) can reach the server.
- **Preconditions:** Server runs on a host with reachable interfaces
- **Remediation:** Bind local servers to 127.0.0.1, validate Origin headers and require authentication for remote access.
- **Verification:** Confirm bind address and Origin validation

### MCP-011 — Untrusted or unknown MCP server source

An MCP server is not marked as trusted in configuration/manifest and its provenance could not be established.

- **Impact:** Third-party server code runs with the client's privileges and its tool descriptions enter the model context.
- **Preconditions:** Server is enabled
- **Remediation:** Inventory MCP servers, record owner/provenance and approval, and allow only reviewed servers.
- **Verification:** Confirm the server is reviewed and marked trusted in the manifest/policy

## M07 — Agent Memory Security

| Rule | Title | Dimension | Default severity | OWASP | NIST | Other |
|---|---|---|---|---|---|---|
| MEM-001 | Persistent memory not isolated per user/tenant | Memory Security | HIGH | ASI06:2026; LLM02:2026; LLM09:2026 | MEASURE 2.10; NIST AI 600-1 Data Privacy | — |
| MEM-002 | Memory without retention limit | Data Privacy | LOW | ASI06:2026 | MEASURE 2.10; NIST AI 600-1 Data Privacy | GDPR Art. 5(1)(e) storage limitation (technical reference only) |
| MEM-003 | Untrusted content written to long-term memory without provenance | Memory Security | MEDIUM | ASI06:2026; LLM05:2026 | MEASURE 2.7 | MITRE ATLAS AML.T0070 RAG Poisoning |
| MEM-004 | Memory injected into system instructions | Memory Security | MEDIUM | ASI06:2026; ASI01:2026; LLM01:2026 | MEASURE 2.7 | — |
| MEM-005 | No memory deletion mechanism | Data Privacy | LOW | ASI06:2026 | MEASURE 2.10 | GDPR Art. 17 right to erasure (technical reference only) |

### MEM-001 — Persistent memory not isolated per user/tenant

Long-term or vector memory is shared across users/tenants, or its scope is not established.

- **Impact:** One user's data leaks to another; one user's poisoned memory affects others.
- **Preconditions:** Multi-user deployment
- **Remediation:** Partition memory by user/tenant (separate namespaces/collections with enforced filters) and bind access to the authenticated identity.
- **Verification:** Run ADV-MEM-002 (cross-user recall) in the sandbox

### MEM-002 — Memory without retention limit

Persistent memory has no TTL/retention policy.

- **Impact:** Personal data is kept longer than necessary (GDPR storage-limitation principle) and poisoned entries persist.
- **Preconditions:** Memory stores user or tool content
- **Remediation:** Define TTL/retention per data category and purge expired entries.
- **Verification:** Confirm the TTL in configuration

### MEM-003 — Untrusted content written to long-term memory without provenance

Tool output or external content can be written to persistent memory without provenance tracking or validation.

- **Impact:** Memory poisoning: a single injected instruction becomes persistent and affects future sessions.
- **Preconditions:** Agent processes attacker-controllable content; Agent can write memory
- **Remediation:** Record provenance (source, trust level) for every memory write, block instruction-like content, and do not let untrusted sources write rules or preferences.
- **Verification:** Run ADV-MEM-001 (persistent instruction) in the sandbox

### MEM-004 — Memory injected into system instructions

Recalled memory is placed in the system/developer prompt, granting it instruction-level authority.

- **Impact:** Poisoned memory overrides developer instructions.
- **Preconditions:** Memory can contain attacker-influenced content
- **Remediation:** Inject memory as clearly delimited data in a lower-privilege message, never in the system prompt.
- **Verification:** Confirm memory placement and run ADV-MEM-001

### MEM-005 — No memory deletion mechanism

No mechanism to delete a user's memory entries was declared.

- **Impact:** Erasure requests cannot be honored; poisoned memory cannot be purged.
- **Preconditions:** Memory stores personal data
- **Remediation:** Provide per-user deletion (and per-entry deletion for poisoning response).
- **Verification:** Confirm deletion endpoint/procedure

## M08 — Dependency & Supply Chain Scanner

| Rule | Title | Dimension | Default severity | OWASP | NIST | Other |
|---|---|---|---|---|---|---|
| SUP-001 | Unpinned dependency | Supply Chain | LOW | ASI04:2026; LLM04:2026 | GOVERN 6.1; NIST AI 600-1 Value Chain and Component Integration | CWE-1357 |
| SUP-002 | No lockfile | Supply Chain | LOW | ASI04:2026; LLM04:2026 | NIST AI 600-1 Value Chain and Component Integration | — |
| SUP-003 | Package install hook present *(specialized review)* | Supply Chain | MEDIUM | ASI04:2026; ASI05:2026; LLM04:2026 | NIST AI 600-1 Value Chain and Component Integration | — |
| SUP-004 | Dependency from VCS or direct URL | Supply Chain | MEDIUM | ASI04:2026; LLM04:2026 | NIST AI 600-1 Value Chain and Component Integration | — |
| SUP-005 | Runtime installation or dynamic loading of external code *(specialized review)* | Supply Chain | HIGH | ASI04:2026; ASI05:2026; LLM04:2026 | NIST AI 600-1 Value Chain and Component Integration | CWE-829 |
| SUP-006 | Known vulnerable dependency version (offline advisory database) | Supply Chain | HIGH | ASI04:2026; LLM04:2026 | NIST AI 600-1 Value Chain and Component Integration | — |

### SUP-001 — Unpinned dependency

A dependency is declared with a range or no version.

- **Impact:** Builds are not reproducible; a malicious or broken release is picked up automatically.
- **Preconditions:** Upstream release changes
- **Remediation:** Pin exact versions in a lockfile (with hashes where supported).
- **Verification:** Confirm lockfile/pins

### SUP-002 — No lockfile

Dependencies are declared but no lockfile (or hashed requirements) was found.

- **Impact:** Transitive dependencies are unknown and can change between installs.
- **Preconditions:** Dependencies resolved at install time
- **Remediation:** Commit a lockfile (uv.lock, poetry.lock, package-lock.json, pip-compile --generate-hashes).
- **Verification:** Confirm the lockfile is committed

### SUP-003 — Package install hook present

The project defines install-time scripts (npm pre/postinstall, setup.py cmdclass). They were not executed by the auditor.

- **Impact:** Install-time code runs with the installer's privileges before any review.
- **Preconditions:** Project or dependency is installed
- **Remediation:** Avoid install hooks; if required, review them and install with --ignore-scripts in CI.
- **Verification:** Review the hook command

### SUP-004 — Dependency from VCS or direct URL

A dependency is installed from a git repository or URL instead of a registry release.

- **Impact:** Mutable references (branches/tags) can change; integrity is not verified by the registry.
- **Preconditions:** Reference is mutable or the host is compromised
- **Remediation:** Use registry releases or pin to a full commit SHA with hash verification.
- **Verification:** Confirm immutable reference

### SUP-005 — Runtime installation or dynamic loading of external code

The agent installs packages or loads modules/skills/plugins dynamically at runtime from names or paths that may be influenced by input.

- **Impact:** The agent can be induced to fetch and run attacker-controlled code.
- **Preconditions:** Module name or package is influenced by model output or external data
- **Remediation:** Remove runtime installation; load only reviewed, pinned extensions from an allowlist.
- **Verification:** Manual review of the loading code

### SUP-006 — Known vulnerable dependency version (offline advisory database)

A pinned dependency version matches an advisory in the provided offline OSV database.

- **Impact:** Known vulnerability present in the agent runtime.
- **Preconditions:** Vulnerable code path reachable
- **Remediation:** Upgrade to a fixed version.
- **Verification:** Re-run with the advisory database and confirm no match

## M09 — Autonomous Action Auditor

| Rule | Title | Dimension | Default severity | OWASP | NIST | Other |
|---|---|---|---|---|---|---|
| AUTO-001 | Irreversible or destructive action without human approval | Agent Autonomy | HIGH | ASI02:2026; ASI09:2026; LLM03:2026 | MAP 3.5; NIST AI 600-1 Human-AI Configuration | — |
| AUTO-002 | No iteration / step limit | Agent Autonomy | MEDIUM | ASI08:2026; LLM06:2026 | MANAGE 2.4 | — |
| AUTO-003 | Code execution capability without sandbox *(specialized review)* | Code Execution | CRITICAL | ASI05:2026; LLM10:2026; LLM03:2026 | MEASURE 2.7; NIST AI 600-1 Information Security | CWE-94 |
| AUTO-004 | No budget or consumption limit | Agent Autonomy | LOW | ASI08:2026; LLM06:2026 | MANAGE 2.4 | — |
| AUTO-005 | No kill switch / interruption mechanism declared | Agent Autonomy | LOW | ASI10:2026; ASI08:2026 | MANAGE 2.4 | — |
| AUTO-006 | Approval required only by prompt instructions | Agent Autonomy | MEDIUM | ASI09:2026; ASI02:2026; LLM03:2026 | MAP 3.5; NIST AI 600-1 Human-AI Configuration | — |
| AUTO-007 | Write access to production targets | Agent Autonomy | MEDIUM | ASI02:2026; ASI08:2026; LLM03:2026 | MANAGE 2.4 | — |

### AUTO-001 — Irreversible or destructive action without human approval

A tool that sends, deletes, pays, deploys or executes can be invoked without an approval step enforced outside the model.

- **Impact:** A single manipulated or mistaken tool call causes irreversible external effects.
- **Preconditions:** Tool callable by the model; Model can be influenced by input or tool output
- **Remediation:** Enforce human approval in the tool runtime (not in the prompt) for irreversible operations; show the full action and parameters to the approver.
- **Verification:** Declare requires_approval with approval_enforced_by and re-run the audit; Run ADV-AUTO-001 in the sandbox and confirm the action is blocked without approval

### AUTO-002 — No iteration / step limit

No maximum number of turns/iterations/recursion was found for the agent loop.

- **Impact:** Runaway loops consume budget, repeat side-effects and amplify cascading failures.
- **Preconditions:** Agent loops on tool errors or adversarial input
- **Remediation:** Set explicit max turns/iterations and per-run tool-call limits.
- **Verification:** Confirm the limit in code/config

### AUTO-003 — Code execution capability without sandbox

The agent can execute model-generated code or shell commands in the host process/environment without an isolation boundary.

- **Impact:** Remote code execution on the host via prompt injection.
- **Preconditions:** Model output reaches the executor; Attacker influences model input
- **Remediation:** Execute code only in an isolated sandbox (container/microVM without credentials, network egress or host mounts) with resource limits; require approval for shell commands.
- **Verification:** Confirm sandboxed executor and run ADV-EXEC-001 in the sandbox

### AUTO-004 — No budget or consumption limit

No spending/token/rate budget was declared for the agent.

- **Impact:** Unbounded consumption (denial of wallet) and amplified impact of loops.
- **Preconditions:** Agent runs unattended
- **Remediation:** Declare and enforce token/cost/rate budgets per run and per day.
- **Verification:** Confirm the budget in manifest/config

### AUTO-005 — No kill switch / interruption mechanism declared

No mechanism to stop or disable the agent at runtime was declared.

- **Impact:** Operators cannot quickly contain a misbehaving or rogue agent.
- **Preconditions:** Agent runs autonomously
- **Remediation:** Implement and document a kill switch (feature flag, credential revocation, queue pause).
- **Verification:** Exercise the kill switch in a staging environment

### AUTO-006 — Approval required only by prompt instructions

Instructions ask the model to request confirmation before sensitive actions, but no enforcement exists in the tool runtime.

- **Impact:** Prompt injection or model error skips the confirmation; the control is advisory only.
- **Preconditions:** Model can be influenced
- **Remediation:** Move the approval to code (approval gate / interrupt) that the model cannot bypass.
- **Verification:** Confirm the gate in code and run ADV-AUTO-001

### AUTO-007 — Write access to production targets

A tool with write/delete/infra operations targets a production environment.

- **Impact:** Agent errors directly impact production systems.
- **Preconditions:** Tool callable by the model
- **Remediation:** Restrict production writes to approved, audited workflows; use staging for autonomous operation.
- **Verification:** Confirm environment separation

## M10 — Multi-Agent Security

| Rule | Title | Dimension | Default severity | OWASP | NIST | Other |
|---|---|---|---|---|---|---|
| MA-001 | Delegation inherits full permissions | Inter-Agent Security | MEDIUM | ASI03:2026; ASI07:2026 | MEASURE 2.7 | — |
| MA-002 | Inter-agent channel without authentication | Inter-Agent Security | MEDIUM | ASI07:2026 | NIST AI 600-1 Information Security | — |
| MA-003 | Delegation cycle without depth limit | Inter-Agent Security | MEDIUM | ASI08:2026 | MANAGE 2.4 | — |
| MA-004 | Privilege escalation path through delegation | Inter-Agent Security | HIGH | ASI07:2026; ASI03:2026; ASI08:2026 | MEASURE 2.7 | — |

### MA-001 — Delegation inherits full permissions

A delegation passes the delegator's permissions/credentials to the delegate (or inheritance is undeclared while tools are shared).

- **Impact:** A low-trust sub-agent operates with high-trust privileges.
- **Preconditions:** Delegate processes untrusted input
- **Remediation:** Give each agent its own scoped identity; delegate tasks, not credentials.
- **Verification:** Confirm per-agent identities in the manifest

### MA-002 — Inter-agent channel without authentication

Agents communicate over a channel without authentication/integrity (or it is undeclared for a network channel).

- **Impact:** Agent impersonation and message tampering.
- **Preconditions:** Channel crosses a process or network boundary
- **Remediation:** Authenticate agents (mTLS/signed messages), validate sender identity and message schema.
- **Verification:** Run ADV-MA-001 (impersonation) in the sandbox

### MA-003 — Delegation cycle without depth limit

The delegation graph contains a cycle and no iteration limit bounds it.

- **Impact:** Infinite delegation loops and cascading failures.
- **Preconditions:** Agents delegate based on model decisions
- **Remediation:** Break cycles or enforce a maximum delegation depth and global step budget.
- **Verification:** Confirm depth limit

### MA-004 — Privilege escalation path through delegation

An agent exposed to untrusted input can delegate to an agent holding destructive or sensitive tools, without approval on the privileged side.

- **Impact:** Injected instructions propagate to a higher-privileged agent (confused deputy between agents).
- **Preconditions:** Untrusted content reaches the delegator
- **Remediation:** Validate delegated requests on the privileged agent against policy; require approval for privileged actions originating from delegation.
- **Verification:** Run ADV-MA-002 in the sandbox

## M11 — Adversarial Security Testing

| Rule | Title | Dimension | Default severity | OWASP | NIST | Other |
|---|---|---|---|---|---|---|
| ADV-FAIL | Adversarial scenario failed in controlled test | Prompt Injection | HIGH | ASI01:2026 | — | — |

### ADV-FAIL — Adversarial scenario failed in controlled test

A controlled, synthetic adversarial scenario produced unsafe behavior in the sandbox.

- **Impact:** Demonstrated unsafe behavior under the tested condition.
- **Preconditions:** Same condition reachable in production
- **Remediation:** Apply the remediation linked to the scenario and re-run it.
- **Verification:** Re-run the failing scenario
