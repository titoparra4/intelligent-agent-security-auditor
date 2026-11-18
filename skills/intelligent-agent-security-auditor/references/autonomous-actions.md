# Autonomous actions, approvals and code execution (MODULE 09)

## Operation classes

`read` · `write` · `delete` · `send` · `execute` · `financial` · `infra` · `network` · `admin`.
Irreversible: `delete`, `send`, `financial`, `infra`. The policy decides which classes require
approval (`human_approval.required_for`).

## What counts as an enforced approval

| Evidence | Credited? |
|---|---|
| Tool body calls an approval/confirm/interrupt function | yes — provenance `code` |
| Manifest `requires_approval: true` + `approval_enforced_by: path::func`, and the tool calls `func` | yes — provenance `code` (verified statically) |
| LangGraph `interrupt_before=[...]`, AutoGen `human_input_mode` ≠ NEVER | recorded as oversight on the agent |
| Manifest `requires_approval: true` alone | only if the policy accepts declared evidence |
| System prompt: "ask the user before sending" | **never** — reported as AUTO-006 |

## Rules

AUTO-001 irreversible/destructive action without enforced approval (CRITICAL for financial/infra) ·
AUTO-002 no explicit iteration/turn/recursion limit · AUTO-003 code execution without sandbox
(Python REPL, shell tools, AutoGen local executor / `use_docker: False`, CrewAI
`code_execution_mode="unsafe"`, `exec`/`eval` in tools) · AUTO-004 no budget · AUTO-005 no kill
switch · AUTO-006 approval only in the prompt · AUTO-007 write access to production targets.

## Designing approvals that resist manipulation (ASI09)

Show the approver the **exact** action and parameters (recipient, destination, amount, record),
not a model-written summary; require re-approval when parameters change; rate-limit approval
requests; log who approved what. ADV-APPR-001 checks that the recipient appears in the approval.

## Testing safely

ADV-AUTO-001, ADV-ID-001, ADV-EXEC-001 run in the sandbox with simulated tools only and
approvals denied by default; no destructive operation is ever executed for real.
