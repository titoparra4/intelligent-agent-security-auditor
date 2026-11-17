# Threat model of the auditor itself

The auditor processes hostile input by design (repositories of unknown agents) and its output
drives deployment decisions. Its own threat model:

| # | Threat | Asset | Mitigation | Verified by |
|---|---|---|---|---|
| T1 | Code execution via audited project (imports, install hooks, `conftest.py`, `sitecustomize.py`) | auditor host | static path parses only (AST, safe loaders), never imports/installs; no subprocess in static mode | `tests/security/test_auditor_safety.py::test_static_audit_never_executes_target_code` |
| T2 | Path traversal / symlink escape to read host files | host files | symlinks never followed; realpath containment; root symlink rejected | `test_core_safety.py::test_symlinks_are_never_followed` |
| T3 | Resource exhaustion (huge files, deep nesting, alias bombs, deep ASTs) | availability | size/count/depth limits; alias + expanded-size limits; RecursionError handling | `test_malformed_inputs_do_not_crash`, `test_yaml_safe_loader_rejects_python_tags_and_alias_bombs` |
| T4 | Unsafe deserialization (`!!python/object`) | host | SafeLoader subclass only | same as above |
| T5 | Secret disclosure through reports/logs | target's secrets | redaction before storage, length-only metadata | `test_secrets_never_reach_reports` |
| T6 | Network side effects / data leaving the machine | target data | no network code in the static path; vulnerability DB offline only | `test_full_lab_audit_and_reports_without_network` |
| T7 | Prompt injection against the auditing assistant | verdict integrity | tool has no model; SKILL.md mandates treating content as data; injection text becomes PI-003 findings | `test_instructions_inside_audited_files_are_data` |
| T8 | False assurance (incomplete audit read as pass) | decision quality | fail-closed controls, coverage next to score, scanner errors → exit 70 and no positive verdict | `test_scanner_error_is_never_a_pass`, readiness tests |
| T9 | Dynamic tests escaping to real systems | third parties, host | authorization + scope + harness containment + isolation pre-check; audit-hook guards; no fallback | `test_dynamic_refuses_without_preconditions`, `test_sandbox_guard_blocks_network_subprocess_and_writes`, CI `sandbox-isolated` job |
| T10 | Tampered policy weakening the gate | decision quality | schema validation before audit, policy SHA-256 in every report, policies versioned in Git | `test_invalid_policy_is_rejected_with_errors` |

Residual risks: the Python audit-hook guard is defense in depth, not a security boundary — the
real boundary for MODE C is the network-less container/VM verified by the pre-check; plugins
loaded with `--plugins` run with the auditor's privileges (they are user-installed code).
