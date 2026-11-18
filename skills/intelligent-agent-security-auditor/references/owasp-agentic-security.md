# OWASP Top 10 for Agentic Applications 2026 — mapping

| Reference | Version / date | Link | Status in this build |
|---|---|---|---|
| OWASP Top 10 for Agentic Applications | 2026 edition, published 2025-12-09 | https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/ | Titles checked against the official PDF on 2026-11-17 |
| OWASP Agentic Security Initiative (ASI) | living project | https://genai.owasp.org/ | Project home; initiative pages move frequently |
| OWASP Agent Control Standard (ACS) | preview (v0.1 reported by secondary sources), OWASP page dated 2026-09-01 | https://genai.owasp.org/resource/agent-control-standard/ | Used only as design guidance for runtime hooks; no ACS conformance is claimed |

> This project is **not** affiliated with, endorsed or certified by OWASP. Identifiers are used
> to map findings to the public taxonomy. "Mandatory" in this repository means *mandatory in a
> policy profile of this tool*, never a normative OWASP requirement.

## Category → rules → controls → tests

| ID | Official title | Detection rules | Design controls | Behavioral tests |
|---|---|---|---|---|
| ASI01 | Agent Goal Hijack | PI-001, PI-002, PI-003, PI-004, ARCH-001, MEM-004 | CTRL-PI-01, CTRL-PI-02, CTRL-PI-03, CTRL-ARCH-02 | ADV-PI-001…005 |
| ASI02 | Tool Misuse and Exploitation | EXF-001, EXF-002, DATA-003, PERM-001, PERM-004/005, AUTO-001, MCP-008 | CTRL-EXF-01, CTRL-DATA-02, CTRL-AUTO-01, CTRL-PERM-03 | ADV-EXF-001, ADV-AUTO-001 |
| ASI03 | Identity and Privilege Abuse | PERM-001/002/003, DATA-005, MCP-003/004/006, MA-001 | CTRL-PERM-01, CTRL-PERM-02, CTRL-DATA-04, CTRL-MCP-02/03 | ADV-PRIV-001, ADV-DATA-001 |
| ASI04 | Agentic Supply Chain Vulnerabilities | MCP-001, MCP-005, MCP-007, MCP-011, SUP-001…006 | CTRL-MCP-01, CTRL-MCP-04, CTRL-SUP-01/02/03 | ADV-MCP-001 |
| ASI05 | Unexpected Code Execution | AUTO-003, EXF-004, MCP-009, SUP-003, SUP-005 | CTRL-AUTO-03, CTRL-SUP-02 | ADV-EXEC-001 |
| ASI06 | Memory & Context Poisoning | MEM-001…005, PI-003 | CTRL-MEM-01/02/03 | ADV-MEM-001, ADV-MEM-002 |
| ASI07 | Insecure Inter-Agent Communication | MA-001, MA-002, MA-004, MCP-002, MCP-006 | CTRL-MA-01 | ADV-MA-001 |
| ASI08 | Cascading Failures | AUTO-002, AUTO-004, MA-003, MA-004 | CTRL-AUTO-02, CTRL-MA-02 | ADV-ERR-001 |
| ASI09 | Human-Agent Trust Exploitation | AUTO-001, AUTO-006 | CTRL-AUTO-01 | ADV-APPR-001, ADV-ID-001 |
| ASI10 | Rogue Agents | EXF-002, EXF-003, EXF-004, AUTO-005 | CTRL-EXF-02, CTRL-AUTO-04 | — (indicators only) |

The machine-readable version of this matrix is section 6 of every report ("OWASP Risk Coverage
Matrix"), computed from the findings and controls of that audit.

## How to read coverage honestly

- A category with **no findings and no verified control** is *unassessed*, not safe.
- ASI10 (rogue agents) can only be approached statically through capability indicators; runtime
  monitoring is outside the scope of a repository audit.
- ASI09 depends on approval UX quality; static analysis verifies that an approval gate exists in
  code, the *content* shown to approvers is only checked by ADV-APPR-001 in the sandbox.

## Agent Control Standard (ACS) relationship

ACS (preview) standardises runtime hooks through which an agent platform lets a guardian
allow/deny/modify actions. This auditor checks the *design preconditions* those hooks rely on
(approval gates outside the model, egress allowlists, identity per tool) and reports them as
controls. It does not implement or certify ACS hooks.
