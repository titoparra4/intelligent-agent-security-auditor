# Contributing

Thanks for helping make AI agents safer. Please keep contributions **evidence-based, offline and
safe by default**.

## Development setup

```bash
python3.11 -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'
python -m pytest -q
```

## Ground rules

1. **No execution of audited code** in static paths; no network calls; no real credentials or
   personal data anywhere (fixtures included — assemble secret-shaped strings at runtime in tests).
2. **Honest coverage**: declare what an adapter/analyzer does *not* detect (`coverage`,
   `limitations`). Never mark a feature as available before it works end-to-end.
3. **Status discipline**: heuristics are POTENTIAL/OBSERVATION; CONFIRMED only for configuration or
   code facts and failing dynamic scenarios. Severity, confidence and status stay independent.
4. **References**: use official identifiers only (OWASP ASI/LLM 2026, NIST AI RMF subcategories,
   CWE, ATLAS IDs). Do not invent normative requirements.
5. **Every rule needs**: a catalog entry (`rules/catalog.py`), a positive and a negative test, and
   a regenerated `skills/intelligent-agent-security-auditor/references/detection-rules.md`.
6. **Stable finding ids**: do not include line numbers or other volatile data in discriminators.

## Adding a rule

1. Add the `Rule` to `skills/intelligent-agent-security-auditor/src/agent_security_auditor/rules/catalog.py`.
2. Emit it from the relevant analyzer with `make_finding(...)` and redacted `Evidence`.
3. Map it to a control (or create one) so readiness can use it.
4. Add tests (vulnerable fixture fires, secure/benign fixture does not).
5. Regenerate the rules document (see `tests/unit/test_docs.py` for the generator check).

## Adding a framework adapter

Implement the `Adapter` protocol (`adapters/base.py`), add it to `default_adapters()`, write a
fixture under `tests/fixtures/frameworks/` and document coverage in `skills/intelligent-agent-security-auditor/references/limitations.md`.

## Pull requests

Small, focused PRs; describe detection impact (new findings on the examples) and false-positive
considerations. CI must pass (tests on 3.11–3.13, isolated sandbox job, security workflow).
By contributing you agree to license your work under the MIT License.
