# Usage

```bash
agent-security-auditor audit ./my-agent                                   # STATIC, basic-agent policy, console summary
agent-security-auditor audit ./my-agent --mode static --policy enterprise-agent \
    --format markdown,json,sarif,html --output ./reports
agent-security-auditor audit ./my-agent --format json --output ./reports
agent-security-auditor architecture ./my-agent [--format json|markdown]   # inventory, trust boundaries, Mermaid
agent-security-auditor permissions ./my-agent                             # permission matrix
agent-security-auditor mcp ./my-agent                                     # MCP servers, tools, findings, controls
agent-security-auditor data-flow ./my-agent                               # source → sink flows, egress inventory
agent-security-auditor threat-model ./my-agent                            # MODE B (no verdict)
agent-security-auditor test ./my-agent                                    # applicable synthetic test plan (nothing runs)
agent-security-auditor test --list ./my-agent                             # all scenarios
agent-security-auditor test ./my-agent --harness sandbox_harness.py --scope scope.yaml --authorize   # MODE C
agent-security-auditor compare ./previous.json ./current.json [--fail-on high]
agent-security-auditor audit ./my-agent --mode ci --baseline ./previous.json --fail-on-new medium   # MODE D
agent-security-auditor report ./reports/agent-security-assessment.json -o ./out --format html,sarif
agent-security-auditor policy validate ./security-policy.yaml
agent-security-auditor policy show enterprise-agent | policy list
agent-security-auditor version
```

Common options: `--policy <profile|file>`, `--exclude GLOB` (repeatable), `--max-file-bytes N`.
`audit` options: `--assessment-id` (reproducible ids), `--target-name`, `--vuln-db DIR` (offline
OSV advisories, opt-in), `--plugins`, `--allow-risks`, `-q`.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | READY (or success for informational commands; `compare` without regression) |
| 10 | READY_WITH_RISKS (0 with `--allow-risks`) |
| 20 | NOT_READY; regression in `compare` / `--mode ci`; failing scenario in `test` |
| 30 | INSUFFICIENT_EVIDENCE |
| 64 | usage error |
| 65 | invalid input (unreadable target, malformed assessment JSON) |
| 70 | scanner error — the audit is incomplete and must not be treated as passed |
| 75 | dynamic preconditions not met (authorization, scope, harness location, isolation) — nothing executed |
| 78 | invalid policy |

## CI example (GitHub Actions)

```yaml
- run: pip install "git+https://github.com/titoparra4/intelligent-agent-security-auditor@v1.1.0"   # pin a tag or commit
- run: agent-security-auditor audit ./agent --policy ./security-policy.yaml --format sarif,json -o reports
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with: { sarif_file: reports/agent-security-assessment.sarif }
- run: agent-security-auditor audit ./agent --mode ci --baseline baseline/agent-security-assessment.json -q
```

The workflow must never run code from the audited repository outside an isolated job; static
mode does not execute it.

## Agent manifest

`agent-manifest.yaml` declares what static analysis cannot infer. Minimal example:

```yaml
manifest_version: "1.0"
agent: {name: support-bot, framework: langgraph, limits: {max_iterations: 10, budget: "1 USD/run"},
        human_oversight: {kill_switch: "feature flag"}}
deployment: {multi_user: true}
tools:
  - {name: read_ticket, operations: [read], data_access: [tickets], returns_untrusted_content: true,
     output_handling: spotlighted, identity: svc-tickets-ro, permissions: ["tickets:read"]}
  - {name: refund, operations: [financial], requires_approval: true,
     approval_enforced_by: "src/tools.py::require_approval", identity: svc-payments, permissions: ["payments:refund<=50EUR"]}
memory:
  - {name: prefs, kind: long_term, scope: per_user, ttl: 30d, provenance_tracking: true,
     write_sources: [user], injected_into: context, deletion_supported: true}
network: {allowed_destinations: ["api.internal.example"]}
```
Full schema: `assets/schemas/agent-manifest.schema.json`.

## Writing a sandbox harness

```python
def run(task, env):           # env: simulated toolkit, see sandbox/env.py
    mails = env.call_tool("read_email")
    ...                        # drive your agent with a local/stub model; call env.call_tool(...) for actions
    if env.request_approval("send_email", {"to": addr}):
        env.call_tool("send_email", to=addr, subject="...", body="...")
    env.respond(answer)
```
See `examples/vulnerable-agent-lab/sandbox_harness.py` and `examples/secure-agent/sandbox_harness.py`.
