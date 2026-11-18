<!-- Template for an analyst-written Agent Security Assessment. The CLI renders the full 19-section
     report automatically (reporters/markdown.py); use this when the tool cannot run or to wrap its
     output with analyst judgment. Replace every {{placeholder}}; keep evidence redacted. -->
# Agent Security Assessment — {{target_name}}

> This tool provides a security assessment based on available evidence. It does not guarantee that an AI agent is secure or constitute a formal security certification.

| Field | Value |
|---|---|
| Assessment ID | {{assessment_id}} |
| Target / version | {{target}} @ {{commit_or_version}} |
| Mode | {{STATIC / THREAT MODEL / CONTROLLED DYNAMIC / CI}} |
| Policy | {{policy_name}} v{{policy_version}} |
| Readiness | {{READY / READY_WITH_RISKS / NOT_READY / INSUFFICIENT_EVIDENCE}} |
| Score / coverage | {{score}}/100 · {{coverage}}% of applicable controls verified |
| Tool executed? | {{yes, version X / no — manual review, reason}} |

1. Executive Security Summary — verdict, reasons, top 5 risks.
2. Agent Architecture Overview — agents, models, frameworks, tools, MCP, memory, sub-agents, diagram.
3. Evaluated Scope — files, adapters, modules run, what was NOT evaluated.
4. Asset & Permission Inventory — Tool | Identity | Permissions | Data Access | Operations | Risk | Required Approval (+ provenance).
5. Threat Model — trust boundaries, actors, threats (see threat-model.md template).
6. OWASP Risk Coverage Matrix — ASI01–ASI10 with findings and controls; 15-dimension relevance.
7. Findings by Severity — per finding:

   ### {{SEC-NNN}} — {{title}} — {{SEVERITY}}
   - Finding ID / rule / module: {{ASA-…}} / {{RULE}} / {{Mxx}}
   - Status / confidence: {{CONFIRMED|POTENTIAL|OBSERVATION|NOT_VERIFIED}} / {{HIGH|MEDIUM|LOW}}
   - Asset · location: {{asset}} · {{file}}:{{line}}
   - Evidence (sanitized): {{snippet / note}}
   - Exploitation preconditions: {{…}}
   - Impact: {{…}}
   - References: {{ASIxx:2026 …; LLMxx:2026 …; NIST …}}
   - Remediation: {{…}}
   - Verification after fix: {{…}}

8. Evidence Register · 9. Controls Verified · 10. Controls Not Verified (with reason)
11. Data Exfiltration Risk Analysis · 12. MCP Security Assessment · 13. Autonomous Action Assessment
14. Security Score (method + coverage) · 15. Agent Security Readiness Assessment
16. Prioritized Remediation Plan · 17. Retest Plan · 18. Residual Risks · 19. Technical Appendix

**Analyst assessment** (clearly separated from tool evidence): {{context, compensating controls, disagreements with tool output and why}}
