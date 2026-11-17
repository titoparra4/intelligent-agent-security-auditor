# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| 1.0.x | yes |

## Reporting a vulnerability

Please **do not open a public issue** for vulnerabilities in the auditor itself. Use GitHub's
private vulnerability reporting ("Security" tab → "Report a vulnerability") on
`titoparra4/intelligent-agent-security-auditor`. Include affected version, a minimal reproduction
(synthetic data only) and impact. We aim to acknowledge within 5 business days and to publish a
fix and advisory once resolved; reporters are credited unless they prefer otherwise.

## In scope

Issues that break the auditor's own guarantees (see `docs/threat-model.md`):
execution of audited code in static mode · reading outside the target (symlinks, traversal) ·
secrets or personal data reaching reports · network access without consent · sandbox pre-check or
guard bypasses in dynamic mode · parser denial of service · a scanner error or missing evidence
being reported as a positive verdict.

## Out of scope

Detection gaps (missed or false findings) — please open a normal issue with a synthetic sample.
Vulnerabilities in the deliberately insecure `examples/vulnerable-agent-lab` and other examples
are intentional.

## Safe use

Run dynamic tests only in a network-less, credential-free sandbox you are authorized to use. Never
point scenarios at public systems, real accounts or production. The tool provides an assessment
based on available evidence; it is not a security certification.
