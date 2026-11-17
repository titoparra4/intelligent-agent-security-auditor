# OWASP Top 10 for LLM Applications 2026 — mapping

| Reference | Version / date | Link |
|---|---|---|
| OWASP Top 10 for LLM Applications | 2026 edition; OWASP resource page dated 2026-08-03 (secondary sources report 2026-08-04; formally announced 2026-09-01) | https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/ |

Entry titles below were checked against the official PDF on 2026-11-17. The 2026 edition
renumbered most entries relative to 2025 (e.g. Excessive Agency moved from LLM06 to LLM03;
System Prompt Leakage was broadened and renamed Hidden Context Exposure).

| ID | Title | Where it appears in this tool |
|---|---|---|
| LLM01:2026 | Prompt Injection | PI-001…004, ARCH-001, MCP-005, MEM-004, ADV-PI-* |
| LLM02:2026 | Sensitive Information Disclosure | DATA-001…005, EXF-001/002/005, MEM-001, MCP-004, ADV-DATA-001, ADV-PRIV-001 |
| LLM03:2026 | Excessive Agency | PERM-001/002/004/005, AUTO-001/003/006/007, DATA-003, MCP-008 |
| LLM04:2026 | Supply Chain | SUP-001…006, MCP-001/005/007 |
| LLM05:2026 | Data and Model Poisoning | PI-003, MEM-003 |
| LLM06:2026 | Unbounded Consumption | AUTO-002, AUTO-004 |
| LLM07:2026 | Misinformation | not assessed (requires output evaluation, out of scope) |
| LLM08:2026 | Hidden Context Exposure | partially: PI-002 / MEM-004 (untrusted or memory content placed in hidden instructions) |
| LLM09:2026 | Vector and Embedding Weaknesses | MEM-001 (vector stores), PI-003 (poisoned corpora) |
| LLM10:2026 | Improper Output Handling | AUTO-003 (model output executed as code) |

## Agentic vs LLM taxonomy

The LLM Top 10 treats the model as a component inside an application; agent-specific risks
(goal hijack, tool misuse, delegation, rogue agents) belong to the Agentic Top 10. Findings carry
both identifiers when both apply, so reports can be read from either perspective.

## Not covered (by design)

- Model-level risks requiring evaluation of model outputs (misinformation, bias, jailbreak
  robustness of a specific model) — use model evaluation tooling.
- Training-data poisoning of foundation models — outside an agent repository.
