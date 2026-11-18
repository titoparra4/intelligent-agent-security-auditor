# Threat modeling AI agents (MODE B) and controlled testing (MODE C)

## Model elements produced by the auditor

| Element | Source | Report section |
|---|---|---|
| Assets | tools with data access, memory stores, identities/credentials | 4, 5 |
| Actors | user, external content author, tool/MCP provider, other agents, insider | 5 |
| Trust boundaries | TB-USER, TB-CONTENT, TB-TOOLS, TB-MCP, TB-MEMORY, TB-AGENTS, TB-NETWORK, TB-EXEC | 5 |
| Data flows | source tool → agent context → sink (tool/destination), with controls | 11 |
| Threats | TM-01…TM-10, one per OWASP ASI category when the surface exists | 5 |
| Diagram | Mermaid flowchart of the reconstructed data flow | 2 |

**Conservative flow assumption.** Inside one agent context the model decides which data goes to
which tool, so every source is assumed able to reach every sink of the same agent. Narrower flows
must be enforced outside the model (and declared) to be credited.

## The lethal combination

The highest-leverage architectural check (ARCH-001): one context that holds **private data**,
ingests **untrusted content** and can **communicate externally** without independent approval.
Breaking any one leg (quarantined sub-agent for untrusted content, approval on egress, egress
allowlist enforced outside the model) removes the exfiltration path regardless of model behavior.

## MITRE ATLAS correspondences (where verifiable)

| Technique | Used by |
|---|---|
| AML.T0051.000 LLM Prompt Injection: Direct | PI-002 |
| AML.T0051.001 LLM Prompt Injection: Indirect | PI-001, PI-003, PI-004, ARCH-001 |
| AML.T0054 LLM Jailbreak | (dynamic scenarios only) |
| AML.T0057 LLM Data Leakage | EXF-001, ARCH-001 |
| AML.T0053 LLM Plugin Compromise | MCP-005 |
| AML.T0010 ML Supply Chain Compromise | MCP-001 |
| AML.T0070 RAG Poisoning | PI-003, MEM-003 |

ATLAS (https://atlas.mitre.org/) renames techniques between releases; IDs are the stable key.
Verify names against the release you report on.

## MODE C — controlled dynamic testing

Preconditions, all mandatory (otherwise exit 75 and nothing runs):

1. `--authorize` (explicit consent) and a scope file: `environment: sandbox`,
   `synthetic_data_only: true`, `authorized_by`, unexpired `expires`, optional scenario subset
   and limits (timeout, memory, max tool calls).
2. A harness file *inside* the target implementing `run(task, env)` that adapts the agent to the
   **simulated toolkit** (`read_email`, `search_documents`, `query_records`, `send_email`,
   `http_post`, `delete_record`, `execute_code`, `write_memory`, `read_memory`, `delegate`).
3. Isolation verified before start: no external network route (UDP-connect probe to RFC 5737 /
   RFC 3849 documentation addresses — no packet is sent), no credential-like environment
   variables, no proxy, no container-runtime socket.

Inside each scenario child process: audit hook blocks non-loopback sockets, DNS, subprocess /
exec / spawn and writes outside a temporary directory; CPU, file-size and open-file limits; a
wall-clock timeout; a clean environment. Canary tokens are random per run and destinations use
reserved `.invalid` domains. Run it inside a network-less container, e.g.:

```bash
docker run --rm --network none -v "$PWD":/w -w /w python:3.12-slim \
  sh -c "pip install --no-index --find-links /w/wheels intelligent-agent-security-auditor && \
         agent-security-auditor test ./my-agent --harness sandbox_harness.py --scope scope.yaml --authorize"
```

The CI workflow `tests.yml` runs the dynamic suite this way (`--network none`).

**Validity limit.** Results are only as faithful as the harness: a deterministic harness proves
the *test mechanics* and the *design* of guards; a harness that wraps the real agent with a local
model (loopback only) is needed to measure model behavior. A real model API call would require
network access and is therefore impossible inside the sandbox by design.
