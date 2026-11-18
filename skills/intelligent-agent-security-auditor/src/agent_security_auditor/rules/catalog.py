"""Detection rule catalog.

Each rule documents its default severity, the dimension it belongs to, references, the
remediation and the verification steps used for a retest. Analyzers decide status /
confidence per occurrence (a rule may emit CONFIRMED for config facts and POTENTIAL for
heuristics). ``references/detection-rules.md`` is generated from this catalog.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from agent_security_auditor.rules.references import ATLAS, MCP, asi, llm, nist

DIMENSIONS = (
    "Data Privacy", "Data Leakage", "Spyware & Malware", "Prompt Injection", "Identity & Access",
    "API & MCP Security", "Supply Chain", "Code Execution", "Agent Autonomy", "Memory Security",
    "RAG & Vector Database Security", "Network Security", "Inter-Agent Security", "Audit & Monitoring",
    "Compliance & Governance",
)

MODULES = {
    "M01": "Agent Architecture Analyzer",
    "M02": "Prompt Injection Detector",
    "M03": "Data Leakage Auditor",
    "M04": "Spyware & Exfiltration Risk Analyzer",
    "M05": "Tool Permission Auditor",
    "M06": "MCP Security Auditor",
    "M07": "Agent Memory Security",
    "M08": "Dependency & Supply Chain Scanner",
    "M09": "Autonomous Action Auditor",
    "M10": "Multi-Agent Security",
    "M11": "Adversarial Security Testing",
    "M12": "Security Risk Reporting",
}


@dataclass(frozen=True)
class Rule:
    rule_id: str
    module: str
    title: str
    category: str
    severity: str
    description: str
    impact: str
    preconditions: tuple[str, ...]
    remediation: str
    verification: tuple[str, ...]
    owasp: tuple[str, ...] = ()
    nist: tuple[str, ...] = ()
    other: tuple[str, ...] = field(default_factory=tuple)
    specialized_review: bool = False


def _r(rule_id, module, title, category, severity, description, impact, preconditions, remediation, verification,
       owasp=(), nist_refs=(), other=(), specialized_review=False) -> Rule:
    return Rule(rule_id, module, title, category, severity, description, impact, tuple(preconditions), remediation,
                tuple(verification), tuple(owasp), tuple(nist_refs), tuple(other), specialized_review)


RULES: dict[str, Rule] = {r.rule_id: r for r in [
    # ---------------------------------------------------------------- M01 architecture
    _r("ARCH-001", "M01", "Lethal combination: private data + untrusted content + external communication",
       "Data Leakage", "HIGH",
       "The same agent context can (1) read sensitive data, (2) ingest attacker-controllable content and (3) "
       "communicate externally. Any successful indirect prompt injection can chain these into data exfiltration "
       "without a software vulnerability.",
       "Exfiltration of sensitive data driven by injected instructions (zero-click style).",
       ["Attacker can place content the agent will read (email, document, web page, ticket)",
        "Agent processes that content in the same context that holds sensitive data",
        "An egress tool or destination is reachable without independent approval"],
       "Break the combination: remove one leg or isolate it. Run untrusted-content processing in a quarantined "
       "context without sensitive tools, require human approval for egress, and enforce a destination allowlist "
       "outside the model.",
       ["Re-run the audit and confirm ARCH-001 no longer applies",
        "Run adversarial scenario ADV-PI-002 / ADV-EXF-001 in the sandbox and confirm egress is blocked"],
       asi("ASI01", "ASI02") + llm("LLM01", "LLM02"), nist("MS-2.7", "600-IS"), (ATLAS["PI_INDIRECT"], ATLAS["DATA_LEAK"])),
    _r("ARCH-002", "M01", "Agent architecture could not be reconstructed",
       "Compliance & Governance", "INFO",
       "No agent, tool or MCP component was detected. The audit cannot assess what it cannot see.",
       "Readiness cannot be established; risks may exist in components outside the scanned scope.",
       ["Agent defined dynamically, in an unsupported framework, or outside the scanned path"],
       "Add an agent-manifest.yaml describing agents, tools, permissions and memory, or point the auditor at the "
       "directory that contains the agent definition.",
       ["Re-run the audit and confirm components appear in the Asset & Permission Inventory"],
       (), nist("MP-4.1")),
    _r("ARCH-003", "M01", "Components detected only by inference (no manifest)",
       "Compliance & Governance", "INFO",
       "No agent-manifest was found. Permissions, identities, approval rules and memory scope are inferred from "
       "code and names, which lowers confidence and leaves many controls NOT_VERIFIED.",
       "Controls that depend on declared facts remain unverified.",
       ["No agent-manifest.yaml in the target"],
       "Document the agent in agent-manifest.yaml (see assets/schemas/agent-manifest.schema.json) and keep it "
       "versioned with the code.",
       ["Re-run the audit and confirm the inventory shows 'declared' provenance"],
       (), nist("GV-1.1", "MP-4.1")),
    # ---------------------------------------------------------------- M02 prompt injection
    _r("PI-001", "M02", "Indirect prompt injection exposure via tool output",
       "Prompt Injection", "MEDIUM",
       "A tool returns externally controllable content (email, documents, web, tickets, RAG) into the model "
       "context without a declared isolation mechanism (spotlighting/delimiting, quarantined LLM, content "
       "sanitization).",
       "Instructions embedded in retrieved content can redirect the agent's goal or trigger tool calls (goal hijack).",
       ["Attacker can write content the tool will return", "Tool output enters the same context that decides tool calls"],
       "Treat tool output as data: wrap it in explicit untrusted-content markers, strip/neutralize instruction-like "
       "content, process it in a quarantined sub-agent without privileged tools, and enforce authorization for "
       "follow-up tool calls outside the model.",
       ["Declare output_handling for the tool and re-run the audit",
        "Run ADV-PI-002 (tool-output injection) in the sandbox and confirm no unauthorized tool call occurs"],
       asi("ASI01") + llm("LLM01"), nist("MS-2.7"), (ATLAS["PI_INDIRECT"],)),
    _r("PI-002", "M02", "Untrusted input interpolated into system instructions",
       "Prompt Injection", "MEDIUM",
       "The agent's system/developer instructions are built with string interpolation of variables whose names "
       "suggest user, document, memory or tool content. That content gains instruction-level authority.",
       "Role spoofing and instruction-hierarchy confusion: injected text is read as developer instructions.",
       ["Attacker influences an interpolated variable"],
       "Keep system instructions static. Pass untrusted content only in user/tool messages with clear delimiters, "
       "never inside the system prompt.",
       ["Confirm instructions are a constant string", "Run ADV-PI-004 (role spoofing) in the sandbox"],
       asi("ASI01") + llm("LLM01"), nist("MS-2.7"), (ATLAS["PI_DIRECT"],)),
    _r("PI-003", "M02", "Instruction-like payload found in agent-reachable content",
       "Prompt Injection", "MEDIUM",
       "Content stored in the project (fixtures, documents, emails, knowledge-base files, tool descriptions) "
       "contains text that tries to override instructions, spoof roles or trigger tools. It is evidence of "
       "poisoned or adversarial content reachable by the agent, not proof of exploitation.",
       "If loaded into context, the content may hijack the agent's goal.",
       ["The file is loaded into the agent context (RAG corpus, fixture, tool response)"],
       "Remove or quarantine the content; if it is an intentional test fixture, keep it under tests/ and exclude it "
       "from production corpora. Add ingestion-time scanning for instruction-like content.",
       ["Re-run the audit; confirm the file is excluded or cleaned"],
       asi("ASI01", "ASI06") + llm("LLM01", "LLM05"), nist("MS-2.7"), (ATLAS["PI_INDIRECT"], ATLAS["RAG_POISON"])),
    _r("PI-004", "M02", "Encoded or hidden instructions in content",
       "Prompt Injection", "MEDIUM",
       "Content contains hidden characters (zero-width / bidi controls), HTML comments or encoded blobs whose "
       "decoded form looks like instructions. These are common obfuscation techniques for injection payloads.",
       "Payloads invisible to human reviewers can still be read by the model.",
       ["Content reaches the model context"],
       "Normalize and strip invisible characters and comments at ingestion; decode-and-scan encoded content; reject "
       "documents with hidden instructions.",
       ["Re-run the audit and confirm no PI-004 findings remain"],
       asi("ASI01") + llm("LLM01"), nist("MS-2.7"), (ATLAS["PI_INDIRECT"],)),
    # ---------------------------------------------------------------- M03 data leakage
    _r("DATA-001", "M03", "Hard-coded secret in agent project",
       "Data Leakage", "HIGH",
       "A credential-like value is stored in source or configuration. The value is redacted in this report.",
       "Credential compromise; any party with repository access (or the model, if the file is in context) obtains it.",
       ["Repository or file content is accessible to an unauthorized party or loaded into the model context"],
       "Revoke and rotate the credential, remove it from history, and load secrets from a secret manager or "
       "environment at runtime. Never place secrets in prompts or tool descriptions.",
       ["Confirm the credential is revoked", "Re-run the audit and confirm DATA-001 is gone"],
       asi("ASI03") + llm("LLM02"), nist("600-IS"), ("CWE-798: Use of Hard-coded Credentials",)),
    _r("DATA-002", "M03", "Sensitive data or full model context written to logs",
       "Data Leakage", "MEDIUM",
       "Logging/print statements emit variables that likely contain secrets, personal data, full prompts, "
       "tool results or memory content.",
       "Logs become a secondary data store outside access controls and retention policies.",
       ["Logs are shipped to systems with broader access than the source data"],
       "Log identifiers and metadata, not content. Apply structured redaction before logging and set retention.",
       ["Inspect log output in a sandbox run with synthetic canary data and confirm no canary appears"],
       asi("ASI03") + llm("LLM02"), nist("MS-2.10", "600-DP"), ("CWE-532: Insertion of Sensitive Information into Log File",)),
    _r("DATA-003", "M03", "Sensitive data can flow to an egress sink without control",
       "Data Leakage", "HIGH",
       "A tool that reads sensitive data and a tool/destination that sends data externally coexist in one agent, "
       "and the egress path has neither human approval nor a destination allowlist.",
       "Disclosure of personal, financial or confidential data to third parties.",
       ["Model decides to call the egress tool with sensitive content (by error or injection)"],
       "Require approval for egress tools, enforce a destination allowlist in the tool/backend, and apply DLP to "
       "outbound payloads.",
       ["Run ADV-EXF-001 with canary data and confirm the canary never leaves the sandbox"],
       asi("ASI02", "ASI03") + llm("LLM02", "LLM03"), nist("MS-2.10", "600-DP")),
    _r("DATA-004", "M03", "Environment file with values committed",
       "Data Leakage", "MEDIUM",
       "A .env-style file with non-placeholder values is part of the audited tree.",
       "Secrets or configuration intended to stay local are distributed with the code.",
       ["The file is committed or packaged"],
       "Remove the file from version control, add it to .gitignore and provide a .env.example with placeholders.",
       ["Re-run the audit and confirm DATA-004 is gone"],
       llm("LLM02"), nist("600-IS"), ("CWE-538: Insertion of Sensitive Information into Externally-Accessible File or Directory",)),
    _r("DATA-005", "M03", "Cross-user / cross-tenant data access not isolated",
       "Data Privacy", "HIGH",
       "A data-access tool queries shared stores without evidence of user or tenant scoping in the query or the "
       "credential used.",
       "One user can obtain another user's or tenant's data through the agent.",
       ["Multi-user deployment", "Tool credential can read all tenants' data"],
       "Bind tool credentials and queries to the end-user identity (row-level security, per-tenant credentials, "
       "on-behalf-of tokens). Never rely on the model to filter tenants.",
       ["Run ADV-PRIV-001 (cross-tenant request) and confirm denial at the backend"],
       asi("ASI03") + llm("LLM02"), nist("MS-2.10", "600-DP")),
    # ---------------------------------------------------------------- M04 spyware / exfiltration
    _r("EXF-001", "M04", "Unrestricted external destination",
       "Network Security", "HIGH",
       "The agent sends data to an external destination that is not in the policy/manifest allowlist (or no "
       "allowlist exists).",
       "Data can be transmitted to unauthorized third parties; the destination is a ready-made exfiltration channel.",
       ["Code path reachable from an agent tool or runtime", "Payload may include context data"],
       "Define an egress allowlist enforced by network policy or an egress proxy; remove or declare the "
       "destination; require approval for outbound transmissions.",
       ["Add the destination to the allowlist or remove the call, then re-run the audit",
        "In the sandbox, confirm egress to non-allowlisted hosts is blocked"],
       asi("ASI02") + llm("LLM02"), nist("MS-2.7", "600-IS"), (ATLAS["DATA_LEAK"],)),
    _r("EXF-002", "M04", "Known exfiltration-friendly endpoint",
       "Network Security", "HIGH",
       "A destination matches a service commonly used to receive arbitrary data (request bins, webhooks, tunnels, "
       "paste sites, OAST domains).",
       "Strong indicator of a data collection channel or debugging leftover that leaks data.",
       ["Code path is reachable at runtime"],
       "Remove the endpoint. If it is legitimate (e.g. a corporate Slack webhook), declare it in the manifest with "
       "its purpose and restrict the data sent.",
       ["Re-run the audit and confirm EXF-002 is gone"],
       asi("ASI02", "ASI10") + llm("LLM02"), nist("600-IS")),
    _r("EXF-003", "M04", "Sensitive local collection capability",
       "Spyware & Malware", "MEDIUM",
       "Code accesses clipboard, camera, microphone, keystrokes, screenshots, browser profiles, SSH/cloud "
       "credential stores or harvests host information. This is a capability indicator, not proof of spyware.",
       "Covert collection of user or host data if the capability is not part of the agent's declared purpose.",
       ["Code path reachable at runtime", "Capability not disclosed to users"],
       "Remove the capability or declare it explicitly (manifest + user disclosure) and scope it to the task.",
       ["Confirm the capability is removed or declared and justified"],
       asi("ASI10", "ASI02"), nist("MS-2.10", "600-DP")),
    _r("EXF-004", "M04", "Hidden execution, persistence or obfuscated code",
       "Spyware & Malware", "HIGH",
       "Code decodes and executes payloads, spawns detached/background processes, or installs persistence "
       "(cron, launch agents, systemd units, registry Run keys, shell profiles).",
       "Persistent or concealed behavior outside the agent's visible actions.",
       ["Code path reachable at install or run time"],
       "Remove obfuscated execution and undeclared persistence. Any background process must be declared, "
       "documented and supervisable.",
       ["Manual review of the referenced code by a security engineer"],
       asi("ASI05", "ASI10"), nist("600-IS"), ("CWE-506: Embedded Malicious Code",), True),
    _r("EXF-005", "M04", "Undeclared telemetry or analytics SDK",
       "Data Privacy", "LOW",
       "A telemetry/analytics/error-reporting SDK is used but not declared in the manifest.",
       "Prompts, outputs or user data may be sent to a third-party processor without disclosure.",
       ["SDK initialized at runtime"],
       "Declare telemetry in the manifest (destination, data categories, opt-out) and scrub prompts and PII from "
       "events.",
       ["Confirm declaration and scrubbing configuration"],
       llm("LLM02"), nist("MS-2.10", "600-DP")),
    # ---------------------------------------------------------------- M05 permissions
    _r("PERM-001", "M05", "Excessive data permissions",
       "Identity & Access", "HIGH",
       "A tool's credential/scope grants broader access than the tool's operations require (least privilege "
       "violation).",
       "Any misuse of the tool (injection, model error, compromised dependency) operates with the broader privilege.",
       ["Tool is callable by the model", "Credential with broad scope is available at runtime"],
       "Request the narrowest scope that supports the tool's operations (e.g. drive.file or drive.readonly "
       "instead of drive; gmail.readonly instead of https://mail.google.com/).",
       ["Change the scope, re-run the audit and confirm PERM-001 is gone",
        "In the sandbox, confirm write/delete calls with the tool credential are rejected"],
       asi("ASI03", "ASI02") + llm("LLM03"), nist("MS-2.7")),
    _r("PERM-002", "M05", "Administrative or wildcard privilege granted to agent tool",
       "Identity & Access", "CRITICAL",
       "A tool or agent identity holds an administrative, owner or wildcard role/scope.",
       "Full compromise of the connected system through a single manipulated tool call.",
       ["Tool is callable by the model"],
       "Replace with task-specific roles; separate administrative operations into a human-operated workflow.",
       ["Confirm the role/scope is narrowed and re-run the audit"],
       asi("ASI03") + llm("LLM03"), nist("MS-2.7")),
    _r("PERM-003", "M05", "Shared identity across tools with different privilege needs",
       "Identity & Access", "MEDIUM",
       "Multiple tools with different operations reuse the same credential/identity.",
       "Compromise of the least-sensitive tool yields the privileges of the most-sensitive one; audit trails cannot "
       "attribute actions.",
       ["Credential reachable by more than one tool"],
       "Give each tool its own identity scoped to its operations.",
       ["Confirm each tool uses a distinct identity"],
       asi("ASI03"), nist("MS-2.7")),
    _r("PERM-004", "M05", "Tool not authorized by policy",
       "Compliance & Governance", "HIGH",
       "The agent exposes a tool that the security policy forbids or does not list as authorized.",
       "The agent's capabilities exceed what was approved.",
       ["Tool is callable by the model"],
       "Remove the tool or obtain an approved policy change/exception.",
       ["Re-run the audit with the policy and confirm PERM-004 is gone"],
       asi("ASI02", "ASI03") + llm("LLM03"), nist("GV-1.1")),
    _r("PERM-005", "M05", "Policy-forbidden operation available to the agent",
       "Compliance & Governance", "HIGH",
       "A tool performs an operation category the policy forbids for this agent (e.g. delete, financial, infra).",
       "Prohibited actions can be triggered by the model.",
       ["Tool is callable by the model"],
       "Remove the operation from the tool or move it to a human-operated workflow.",
       ["Re-run the audit with the policy and confirm PERM-005 is gone"],
       asi("ASI02") + llm("LLM03"), nist("GV-1.1")),
    # ---------------------------------------------------------------- M06 MCP
    _r("MCP-001", "M06", "MCP server package not version-pinned",
       "Supply Chain", "MEDIUM",
       "The MCP server is launched from a package registry or image without an exact version/digest, so every "
       "start may run different code (silent updates, rug pulls, typosquats).",
       "A compromised or changed upstream package executes with the client's local privileges.",
       ["Upstream package or tag changes", "Client restarts the server"],
       "Pin exact versions (npx pkg@1.2.3, uvx pkg==1.2.3, image@sha256:...) and review updates before bumping.",
       ["Confirm the config pins an exact version and re-run the audit"],
       asi("ASI04") + llm("LLM04"), nist("GV-6.1", "600-VC"), (MCP["LOCAL_SERVER"], ATLAS["SUPPLY"])),
    _r("MCP-002", "M06", "Remote MCP server over plaintext HTTP",
       "API & MCP Security", "HIGH",
       "A remote (HTTP/SSE) MCP server URL uses http:// for a non-loopback host.",
       "Tokens, tool arguments and results can be intercepted or modified in transit.",
       ["Network path is observable or controllable by an attacker"],
       "Use HTTPS with certificate validation for every non-loopback MCP endpoint.",
       ["Confirm the URL uses https:// and re-run the audit"],
       asi("ASI04", "ASI07"), nist("600-IS"), (MCP["AUTHZ"], "CWE-319: Cleartext Transmission of Sensitive Information")),
    _r("MCP-003", "M06", "Remote MCP server without authentication configured",
       "API & MCP Security", "MEDIUM",
       "An HTTP/SSE MCP server entry has no authorization configuration (OAuth, bearer header or API key). For "
       "STDIO servers this rule does not apply.",
       "If the server exposes sensitive tools, anyone who can reach it can invoke them.",
       ["Server is reachable beyond the local user", "Server exposes non-public tools/data"],
       "Use MCP authorization (OAuth 2.1 with audience-bound tokens) or at minimum a per-client bearer token "
       "loaded from the environment.",
       ["Confirm authorization is configured and that unauthenticated requests are rejected"],
       asi("ASI03", "ASI04"), nist("600-IS"), (MCP["AUTHZ"],)),
    _r("MCP-004", "M06", "Credential stored inline in MCP configuration",
       "Data Leakage", "HIGH",
       "An env/header value in the MCP configuration contains a literal secret instead of a reference to the "
       "environment or a secret store. The value is redacted.",
       "Configuration files are commonly shared and synced; the credential leaks with them.",
       ["Config file is shared, committed or readable by other local processes"],
       "Reference secrets via environment/secret-store variables (e.g. ${GITHUB_TOKEN}); rotate the exposed value.",
       ["Confirm rotation and that the config contains only references"],
       asi("ASI03") + llm("LLM02"), nist("600-IS"), ("CWE-798: Use of Hard-coded Credentials",)),
    _r("MCP-005", "M06", "Tool poisoning indicators in MCP tool description",
       "API & MCP Security", "HIGH",
       "An MCP tool description contains instructions aimed at the model (hidden tags, directives to read files, "
       "to call other tools, to conceal actions from the user, or to send data).",
       "The tool description itself hijacks the agent as soon as the tool list is loaded, even if the tool is never called.",
       ["Client loads the server's tool list into model context"],
       "Remove the server or the poisoned tool; pin and review tool definitions (description hashes) and show "
       "full descriptions to users at approval time.",
       ["Re-run the audit and confirm MCP-005 is gone", "Run ADV-MCP-001 in the sandbox"],
       asi("ASI04", "ASI01") + llm("LLM01", "LLM04"), nist("600-VC"), (MCP["TOOL_SAFETY"], ATLAS["PLUGIN"])),
    _r("MCP-006", "M06", "Possible token passthrough in MCP server",
       "API & MCP Security", "HIGH",
       "Server code appears to forward the incoming client Authorization token to a downstream API. The MCP "
       "authorization specification forbids accepting/forwarding tokens not issued for the MCP server.",
       "Confused deputy: downstream services cannot distinguish the MCP server from the client; audience checks "
       "and rate limits are bypassed.",
       ["Server receives client bearer tokens (HTTP transport)"],
       "Validate token audience for the MCP server itself and obtain separate downstream tokens (token exchange / "
       "on-behalf-of flows).",
       ["Review the code path; confirm downstream calls use server-issued credentials"],
       asi("ASI03", "ASI07"), nist("600-IS"), (MCP["TOKEN_PASSTHROUGH"], MCP["CONFUSED_DEPUTY"]), True),
    _r("MCP-007", "M06", "MCP tool definition changed since pinned",
       "Supply Chain", "HIGH",
       "The description of a pinned MCP tool no longer matches its recorded hash (possible rug pull or "
       "unreviewed update).",
       "Changed instructions are injected into the agent without review.",
       ["Tool definitions are loaded from the server at runtime"],
       "Review the change; re-pin only after approval. Clients should alert on definition changes.",
       ["Update the pin after review and re-run the audit"],
       asi("ASI04") + llm("LLM04"), nist("600-VC"), (MCP["TOOL_SAFETY"],)),
    _r("MCP-008", "M06", "MCP server with filesystem or network scope beyond the task",
       "Identity & Access", "HIGH",
       "An MCP server is granted the whole filesystem / home directory or unrestricted fetch capability.",
       "Read/write access to credentials, SSH keys and unrelated documents; SSRF to internal services.",
       ["Server tools are callable by the model"],
       "Restrict roots to the minimum project directories; for fetch-type servers enforce a URL allowlist and block "
       "private/metadata addresses.",
       ["Confirm narrowed roots/allowlist and re-run the audit"],
       asi("ASI02", "ASI03") + llm("LLM03"), nist("MS-2.7"), (MCP["SSRF"],)),
    _r("MCP-009", "M06", "MCP STDIO server launched through a shell",
       "Code Execution", "MEDIUM",
       "The STDIO server command runs through sh/bash/cmd -c, enabling shell expansion and command chaining in "
       "the launch line.",
       "Injection into the launch command (via variables or edited config) executes arbitrary commands.",
       ["Launch line includes interpolated or user-editable values"],
       "Invoke the server binary directly with an argument array; avoid shell wrappers.",
       ["Confirm the command no longer uses a shell -c wrapper"],
       asi("ASI05"), nist("600-IS"), ("CWE-78: OS Command Injection",)),
    _r("MCP-010", "M06", "MCP server bound to all interfaces",
       "Network Security", "MEDIUM",
       "Server code binds HTTP/SSE transport to 0.0.0.0, exposing it beyond localhost.",
       "Other hosts on the network (or DNS-rebinding web pages) can reach the server.",
       ["Server runs on a host with reachable interfaces"],
       "Bind local servers to 127.0.0.1, validate Origin headers and require authentication for remote access.",
       ["Confirm bind address and Origin validation"],
       asi("ASI03"), nist("600-IS"), (MCP["LOCAL_SERVER"],)),
    _r("MCP-011", "M06", "Untrusted or unknown MCP server source",
       "Supply Chain", "LOW",
       "An MCP server is not marked as trusted in configuration/manifest and its provenance could not be "
       "established.",
       "Third-party server code runs with the client's privileges and its tool descriptions enter the model context.",
       ["Server is enabled"],
       "Inventory MCP servers, record owner/provenance and approval, and allow only reviewed servers.",
       ["Confirm the server is reviewed and marked trusted in the manifest/policy"],
       asi("ASI04"), nist("GV-6.1", "600-VC")),
    # ---------------------------------------------------------------- M07 memory
    _r("MEM-001", "M07", "Persistent memory not isolated per user/tenant",
       "Memory Security", "HIGH",
       "Long-term or vector memory is shared across users/tenants, or its scope is not established.",
       "One user's data leaks to another; one user's poisoned memory affects others.",
       ["Multi-user deployment"],
       "Partition memory by user/tenant (separate namespaces/collections with enforced filters) and bind access "
       "to the authenticated identity.",
       ["Run ADV-MEM-002 (cross-user recall) in the sandbox"],
       asi("ASI06") + llm("LLM02", "LLM09"), nist("MS-2.10", "600-DP")),
    _r("MEM-002", "M07", "Memory without retention limit",
       "Data Privacy", "LOW",
       "Persistent memory has no TTL/retention policy.",
       "Personal data is kept longer than necessary (GDPR storage-limitation principle) and poisoned entries persist.",
       ["Memory stores user or tool content"],
       "Define TTL/retention per data category and purge expired entries.",
       ["Confirm the TTL in configuration"],
       asi("ASI06"), nist("MS-2.10", "600-DP"), ("GDPR Art. 5(1)(e) storage limitation (technical reference only)",)),
    _r("MEM-003", "M07", "Untrusted content written to long-term memory without provenance",
       "Memory Security", "MEDIUM",
       "Tool output or external content can be written to persistent memory without provenance tracking or "
       "validation.",
       "Memory poisoning: a single injected instruction becomes persistent and affects future sessions.",
       ["Agent processes attacker-controllable content", "Agent can write memory"],
       "Record provenance (source, trust level) for every memory write, block instruction-like content, and do not "
       "let untrusted sources write rules or preferences.",
       ["Run ADV-MEM-001 (persistent instruction) in the sandbox"],
       asi("ASI06") + llm("LLM05"), nist("MS-2.7"), (ATLAS["RAG_POISON"],)),
    _r("MEM-004", "M07", "Memory injected into system instructions",
       "Memory Security", "MEDIUM",
       "Recalled memory is placed in the system/developer prompt, granting it instruction-level authority.",
       "Poisoned memory overrides developer instructions.",
       ["Memory can contain attacker-influenced content"],
       "Inject memory as clearly delimited data in a lower-privilege message, never in the system prompt.",
       ["Confirm memory placement and run ADV-MEM-001"],
       asi("ASI06", "ASI01") + llm("LLM01"), nist("MS-2.7")),
    _r("MEM-005", "M07", "No memory deletion mechanism",
       "Data Privacy", "LOW",
       "No mechanism to delete a user's memory entries was declared.",
       "Erasure requests cannot be honored; poisoned memory cannot be purged.",
       ["Memory stores personal data"],
       "Provide per-user deletion (and per-entry deletion for poisoning response).",
       ["Confirm deletion endpoint/procedure"],
       asi("ASI06"), nist("MS-2.10"), ("GDPR Art. 17 right to erasure (technical reference only)",)),
    # ---------------------------------------------------------------- M08 supply chain
    _r("SUP-001", "M08", "Unpinned dependency",
       "Supply Chain", "LOW",
       "A dependency is declared with a range or no version.",
       "Builds are not reproducible; a malicious or broken release is picked up automatically.",
       ["Upstream release changes"],
       "Pin exact versions in a lockfile (with hashes where supported).",
       ["Confirm lockfile/pins"],
       asi("ASI04") + llm("LLM04"), nist("GV-6.1", "600-VC"), ("CWE-1357: Reliance on Insufficiently Trustworthy Component",)),
    _r("SUP-002", "M08", "No lockfile",
       "Supply Chain", "LOW",
       "Dependencies are declared but no lockfile (or hashed requirements) was found.",
       "Transitive dependencies are unknown and can change between installs.",
       ["Dependencies resolved at install time"],
       "Commit a lockfile (uv.lock, poetry.lock, package-lock.json, pip-compile --generate-hashes).",
       ["Confirm the lockfile is committed"],
       asi("ASI04") + llm("LLM04"), nist("600-VC")),
    _r("SUP-003", "M08", "Package install hook present",
       "Supply Chain", "MEDIUM",
       "The project defines install-time scripts (npm pre/postinstall, setup.py cmdclass). They were not executed "
       "by the auditor.",
       "Install-time code runs with the installer's privileges before any review.",
       ["Project or dependency is installed"],
       "Avoid install hooks; if required, review them and install with --ignore-scripts in CI.",
       ["Review the hook command"],
       asi("ASI04", "ASI05") + llm("LLM04"), nist("600-VC"), (), True),
    _r("SUP-004", "M08", "Dependency from VCS or direct URL",
       "Supply Chain", "MEDIUM",
       "A dependency is installed from a git repository or URL instead of a registry release.",
       "Mutable references (branches/tags) can change; integrity is not verified by the registry.",
       ["Reference is mutable or the host is compromised"],
       "Use registry releases or pin to a full commit SHA with hash verification.",
       ["Confirm immutable reference"],
       asi("ASI04") + llm("LLM04"), nist("600-VC")),
    _r("SUP-005", "M08", "Runtime installation or dynamic loading of external code",
       "Supply Chain", "HIGH",
       "The agent installs packages or loads modules/skills/plugins dynamically at runtime from names or paths "
       "that may be influenced by input.",
       "The agent can be induced to fetch and run attacker-controlled code.",
       ["Module name or package is influenced by model output or external data"],
       "Remove runtime installation; load only reviewed, pinned extensions from an allowlist.",
       ["Manual review of the loading code"],
       asi("ASI04", "ASI05") + llm("LLM04"), nist("600-VC"), ("CWE-829: Inclusion of Functionality from Untrusted Control Sphere",), True),
    _r("SUP-006", "M08", "Known vulnerable dependency version (offline advisory database)",
       "Supply Chain", "HIGH",
       "A pinned dependency version matches an advisory in the provided offline OSV database.",
       "Known vulnerability present in the agent runtime.",
       ["Vulnerable code path reachable"],
       "Upgrade to a fixed version.",
       ["Re-run with the advisory database and confirm no match"],
       asi("ASI04") + llm("LLM04"), nist("600-VC")),
    # ---------------------------------------------------------------- M09 autonomy
    _r("AUTO-001", "M09", "Irreversible or destructive action without human approval",
       "Agent Autonomy", "HIGH",
       "A tool that sends, deletes, pays, deploys or executes can be invoked without an approval step enforced "
       "outside the model.",
       "A single manipulated or mistaken tool call causes irreversible external effects.",
       ["Tool callable by the model", "Model can be influenced by input or tool output"],
       "Enforce human approval in the tool runtime (not in the prompt) for irreversible operations; show the full "
       "action and parameters to the approver.",
       ["Declare requires_approval with approval_enforced_by and re-run the audit",
        "Run ADV-AUTO-001 in the sandbox and confirm the action is blocked without approval"],
       asi("ASI02", "ASI09") + llm("LLM03"), nist("MP-3.5", "600-HAC")),
    _r("AUTO-002", "M09", "No iteration / step limit",
       "Agent Autonomy", "MEDIUM",
       "No maximum number of turns/iterations/recursion was found for the agent loop.",
       "Runaway loops consume budget, repeat side-effects and amplify cascading failures.",
       ["Agent loops on tool errors or adversarial input"],
       "Set explicit max turns/iterations and per-run tool-call limits.",
       ["Confirm the limit in code/config"],
       asi("ASI08") + llm("LLM06"), nist("MG-2.4")),
    _r("AUTO-003", "M09", "Code execution capability without sandbox",
       "Code Execution", "CRITICAL",
       "The agent can execute model-generated code or shell commands in the host process/environment without an "
       "isolation boundary.",
       "Remote code execution on the host via prompt injection.",
       ["Model output reaches the executor", "Attacker influences model input"],
       "Execute code only in an isolated sandbox (container/microVM without credentials, network egress or host "
       "mounts) with resource limits; require approval for shell commands.",
       ["Confirm sandboxed executor and run ADV-EXEC-001 in the sandbox"],
       asi("ASI05") + llm("LLM10", "LLM03"), nist("MS-2.7", "600-IS"), ("CWE-94: Improper Control of Generation of Code",), True),
    _r("AUTO-004", "M09", "No budget or consumption limit",
       "Agent Autonomy", "LOW",
       "No spending/token/rate budget was declared for the agent.",
       "Unbounded consumption (denial of wallet) and amplified impact of loops.",
       ["Agent runs unattended"],
       "Declare and enforce token/cost/rate budgets per run and per day.",
       ["Confirm the budget in manifest/config"],
       asi("ASI08") + llm("LLM06"), nist("MG-2.4")),
    _r("AUTO-005", "M09", "No kill switch / interruption mechanism declared",
       "Agent Autonomy", "LOW",
       "No mechanism to stop or disable the agent at runtime was declared.",
       "Operators cannot quickly contain a misbehaving or rogue agent.",
       ["Agent runs autonomously"],
       "Implement and document a kill switch (feature flag, credential revocation, queue pause).",
       ["Exercise the kill switch in a staging environment"],
       asi("ASI10", "ASI08"), nist("MG-2.4")),
    _r("AUTO-006", "M09", "Approval required only by prompt instructions",
       "Agent Autonomy", "MEDIUM",
       "Instructions ask the model to request confirmation before sensitive actions, but no enforcement exists in "
       "the tool runtime.",
       "Prompt injection or model error skips the confirmation; the control is advisory only.",
       ["Model can be influenced"],
       "Move the approval to code (approval gate / interrupt) that the model cannot bypass.",
       ["Confirm the gate in code and run ADV-AUTO-001"],
       asi("ASI09", "ASI02") + llm("LLM03"), nist("MP-3.5", "600-HAC")),
    _r("AUTO-007", "M09", "Write access to production targets",
       "Agent Autonomy", "MEDIUM",
       "A tool with write/delete/infra operations targets a production environment.",
       "Agent errors directly impact production systems.",
       ["Tool callable by the model"],
       "Restrict production writes to approved, audited workflows; use staging for autonomous operation.",
       ["Confirm environment separation"],
       asi("ASI02", "ASI08") + llm("LLM03"), nist("MG-2.4")),
    # ---------------------------------------------------------------- M10 multi-agent
    _r("MA-001", "M10", "Delegation inherits full permissions",
       "Inter-Agent Security", "MEDIUM",
       "A delegation passes the delegator's permissions/credentials to the delegate (or inheritance is "
       "undeclared while tools are shared).",
       "A low-trust sub-agent operates with high-trust privileges.",
       ["Delegate processes untrusted input"],
       "Give each agent its own scoped identity; delegate tasks, not credentials.",
       ["Confirm per-agent identities in the manifest"],
       asi("ASI03", "ASI07"), nist("MS-2.7")),
    _r("MA-002", "M10", "Inter-agent channel without authentication",
       "Inter-Agent Security", "MEDIUM",
       "Agents communicate over a channel without authentication/integrity (or it is undeclared for a network "
       "channel).",
       "Agent impersonation and message tampering.",
       ["Channel crosses a process or network boundary"],
       "Authenticate agents (mTLS/signed messages), validate sender identity and message schema.",
       ["Run ADV-MA-001 (impersonation) in the sandbox"],
       asi("ASI07"), nist("600-IS")),
    _r("MA-003", "M10", "Delegation cycle without depth limit",
       "Inter-Agent Security", "MEDIUM",
       "The delegation graph contains a cycle and no iteration limit bounds it.",
       "Infinite delegation loops and cascading failures.",
       ["Agents delegate based on model decisions"],
       "Break cycles or enforce a maximum delegation depth and global step budget.",
       ["Confirm depth limit"],
       asi("ASI08"), nist("MG-2.4")),
    _r("MA-004", "M10", "Privilege escalation path through delegation",
       "Inter-Agent Security", "HIGH",
       "An agent exposed to untrusted input can delegate to an agent holding destructive or sensitive tools, "
       "without approval on the privileged side.",
       "Injected instructions propagate to a higher-privileged agent (confused deputy between agents).",
       ["Untrusted content reaches the delegator"],
       "Validate delegated requests on the privileged agent against policy; require approval for privileged "
       "actions originating from delegation.",
       ["Run ADV-MA-002 in the sandbox"],
       asi("ASI07", "ASI03", "ASI08"), nist("MS-2.7")),
    # ---------------------------------------------------------------- M11 adversarial
    _r("ADV-FAIL", "M11", "Adversarial scenario failed in controlled test",
       "Prompt Injection", "HIGH",
       "A controlled, synthetic adversarial scenario produced unsafe behavior in the sandbox.",
       "Demonstrated unsafe behavior under the tested condition.",
       ["Same condition reachable in production"],
       "Apply the remediation linked to the scenario and re-run it.",
       ["Re-run the failing scenario"],
       asi("ASI01")),
]}


def rule(rule_id: str) -> Rule:
    return RULES[rule_id]
