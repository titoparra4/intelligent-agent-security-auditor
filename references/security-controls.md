# Security controls, policies, scoring and readiness

## Control catalog

Design controls are statically verifiable; behavioral controls need CONTROLLED DYNAMIC mode.

| Control | Kind | Module | Passed when |
|---|---|---|---|
| CTRL-ARCH-01 | design | M01 | components inventoried |
| CTRL-ARCH-02 | design | M01 | no private-data + untrusted-content + uncontrolled-egress context |
| CTRL-PI-01 | design | M02 | every untrusted-content tool declares isolation (`output_handling`) |
| CTRL-PI-02 | design | M02 | instructions are static |
| CTRL-PI-03 | design | M02 | no payloads in agent-reachable content |
| CTRL-DATA-01 | design | M03 | no secret patterns in scanned files |
| CTRL-DATA-02 | design | M03 | every sensitive→egress flow has approval or allowlist |
| CTRL-DATA-03 | design | M03 | (NOT_VERIFIED unless failed — log content needs dynamic canary test) |
| CTRL-DATA-04 | design | M03 | data tools tenant-scoped in multi-user deployments |
| CTRL-EXF-01/02/03 | design | M04 | egress allowlisted · no covert indicators · telemetry declared |
| CTRL-PERM-01/02/03 | design | M05 | least privilege known for every tool · identity per tool · policy conformance |
| CTRL-MCP-01…05 | design | M06 | pinned/unchanged · remote transport secured · no inline secrets · definitions scanned · scope restricted |
| CTRL-MEM-01/02/03 | design | M07 | partitioned · provenance + placement · retention + deletion |
| CTRL-SUP-01/02/03 | design | M08 | pinned + lockfile · no hooks/runtime installs · advisory check (NOT_ASSESSED without `--vuln-db`) |
| CTRL-AUTO-01…04 | design | M09 | approval enforced · iteration limits · sandboxed execution · budget + kill switch |
| CTRL-MA-01/02 | design | M10 | authenticated, scoped delegation · bounded delegation |
| CTRL-PI-B1, CTRL-EXF-B1, CTRL-AUTO-B1, CTRL-MEM-B1, CTRL-ADV-01 | behavioral | M02/M04/M09/M07/M11 | sandbox scenarios passed |

Statuses: PASSED · FAILED · NOT_VERIFIED · INSUFFICIENT_EVIDENCE · NOT_APPLICABLE.
A control fails on a CONFIRMED related finding; POTENTIAL findings fail or leave it unverified
depending on the control (documented per control in code).

## Requirement levels (do not confuse them)

1. **Normative requirements** — only where a standard says MUST (e.g. the MCP Authorization
   specification on token audience/passthrough). Quoted as references, not invented.
2. **Recognized good practice** — OWASP / NIST guidance cited by identifier.
3. **Project recommendations** — this tool's defaults (rule severities, profile contents,
   scoring weights). Always configurable and labelled as such.

## Policies

Schema: `assets/schemas/policy.schema.json`. Profiles: `basic-agent`, `enterprise-agent`,
`mcp-integrated-agent`, `high-risk-autonomous-agent` (copies in `examples/policies/`). A policy
defines authorized/forbidden tools, forbidden operations, denied scopes, allowed destinations,
restricted data, approval requirements, isolation requirements, blocking severities, mandatory
controls, whether declarations count as evidence, scoring weights and exceptions.

Exceptions require `owner`, `approved_by`, `justification` (≥10 chars) and `expires`; they match
by stable `finding_id` or by `rule_id` (+ optional `asset`). Expired exceptions are ignored and
reported. Policies are validated before any audit (`policy validate`, exit 78 when invalid).

## Readiness rules

See SKILL.md §11 and `core/readiness.py`. Key properties: a confirmed critical blocks; failed
mandatory controls block unless they fail *only* because of accepted risks; unverified mandatory
controls give INSUFFICIENT_EVIDENCE; scanner errors downgrade any positive verdict to
INSUFFICIENT_EVIDENCE and exit 70; THREAT MODEL mode never issues a verdict.

## Security Score

`100 − Σ min(module_cap, Σ weight[severity] × status_factor × confidence_factor)`, accepted risks
at 50 %, capped at 30 if a confirmed CRITICAL is open, reported in bands of 5 with a grade and
**coverage** (verified ÷ applicable controls). Weights are configurable per policy
(`scoring.weights`). The score is an indicator; it never overrides the verdict and is not a
certification.
