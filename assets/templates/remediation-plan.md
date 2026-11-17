# Prioritized Remediation Plan — {{target_name}}

| Priority | Finding | Title | Severity / status | Action | Owner | Due | Verification (retest) |
|---|---|---|---|---|---|---|---|
| P1 (blocking) | {{SEC-NNN}} | {{…}} | {{HIGH/CONFIRMED}} | {{concrete change}} | {{team}} | {{date}} | {{rule no longer fires; sandbox scenario passes}} |
| P2 | | | | | | | |
| P3 | | | | | | | |

Priority rules: P1 = blocking under the active policy or CRITICAL; P2 = HIGH or unaccepted ≥ policy
threshold; P3 = the rest. Prefer controls enforced outside the model (identity, scopes, approval
gates, egress allowlists) over prompt changes.

## Retest
```bash
agent-security-auditor audit {{target}} --policy {{policy}} --mode ci --baseline {{previous.json}} -o reports
```
Accepted risks (owner, approver, justification, expiry) go into the policy `exceptions:` list.
