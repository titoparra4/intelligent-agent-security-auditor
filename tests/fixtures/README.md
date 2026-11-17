# Test fixtures

Synthetic, never-executed inputs for the test-suite. Nothing here contains real credentials,
endpoints or personal data; secret-like values used by tests are assembled at runtime inside
the tests so they never exist verbatim in the repository.

- `frameworks/` - minimal agents for each supported framework adapter (detection tests).
- `benign/` - code that *looks* risky to naive scanners but is safe (false-positive tests).
- `malformed/` - broken files the parsers must survive (robustness tests).
