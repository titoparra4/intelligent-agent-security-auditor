# NIST AI RMF 1.0 and NIST AI 600-1 — mapping

| Reference | Version / date | Link |
|---|---|---|
| NIST AI Risk Management Framework (AI RMF 1.0), NIST AI 100-1 | January 2023 | https://doi.org/10.6028/NIST.AI.100-1 |
| NIST AI 600-1, Generative AI Profile | July 2024 | https://doi.org/10.6028/NIST.AI.600-1 |

> The AI RMF is voluntary. References here link findings to the subcategory whose *outcome* the
> evidence supports; they are not conformance claims. Subcategory identifiers are cited at the
> level that could be verified; consult the Playbook for full text.

## Subcategories used

| ID | Outcome (abridged) | Fed by |
|---|---|---|
| GOVERN 1.1 | Legal/regulatory requirements understood and managed | policy evaluation (PERM-004/005), manifest presence (ARCH-003) |
| GOVERN 6.1 | Policies address third-party / supply-chain risk | SUP-*, MCP-001, MCP-011 |
| MAP 3.5 | Processes for human oversight are defined | AUTO-001, AUTO-006 |
| MAP 4.1 | Risks of components, including third-party, are mapped | M01 inventory, ARCH-002/003 |
| MEASURE 2.7 | Security and resilience evaluated and documented | most M02/M05/M06/M09 rules; dynamic tests |
| MEASURE 2.10 | Privacy risk examined and documented | DATA-002/005, MEM-001/002/005, EXF-003/005 |
| MANAGE 2.4 | Mechanisms to supersede, disengage or deactivate | AUTO-002/004/005, MA-003 |
| MANAGE 4.1 | Post-deployment monitoring | CI mode (baseline comparison), retest plan |

## NIST AI 600-1 risk categories used

Information Security · Data Privacy · Value Chain and Component Integration · Human-AI
Configuration. Other GAI risks in the profile (e.g. confabulation, harmful bias, information
integrity) concern model outputs and are out of scope.

## Lifecycle fit

`GOVERN` → versioned policy + manifest; `MAP` → architecture/threat model (MODE B);
`MEASURE` → static + controlled dynamic assessment (MODES A/C); `MANAGE` → readiness decision,
accepted risks with expiry, CI gate (MODE D).
