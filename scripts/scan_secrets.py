#!/usr/bin/env python3
"""Scan an agent project for hard-coded secrets and committed env files (values are always redacted).

Usage: python scripts/scan_secrets.py <target> [--json] [--exclude GLOB ...]

Runs from a cloned skill without installation. Exit code: 0 no secrets, 20 secrets found, 65 bad target.
"""

import json
import sys
from pathlib import Path

if sys.version_info < (3, 11):
    sys.exit(f"intelligent-agent-security-auditor requires Python 3.11+ (found {sys.version.split()[0]}). "
             "Install a newer Python or use the packaged CLI.")
try:
    import yaml  # noqa: F401
except ImportError:
    sys.exit("PyYAML is required: python3 -m pip install PyYAML  (or: pip install -e . in the skill directory)")

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from agent_security_auditor.core.discovery import DiscoveryError  # noqa: E402
from agent_security_auditor.core.engine import run_audit  # noqa: E402


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__, file=sys.stderr)
        return 64
    excludes = [argv[i + 1] for i, a in enumerate(argv[:-1]) if a == "--exclude"]
    try:
        a = run_audit(argv[0], exclude=excludes)
    except DiscoveryError as exc:
        print(f"cannot scan: {exc}", file=sys.stderr)
        return 65
    hits = [f for f in a.findings if f.rule_id in ("DATA-001", "DATA-004", "MCP-004")]
    if "--json" in argv:
        print(json.dumps([{"rule": f.rule_id, "severity": f.severity.value, "file": f.source_file, "line": f.source_line,
                           "detail": f.evidence[0].note} for f in hits], indent=2))  # location + type only, no snippets
    else:
        for f in hits:
            print(f"{f.severity.value:<8} {f.rule_id}  {f.source_file}:{f.source_line}  {f.evidence[0].note}")
        print(f"{len(hits)} secret finding(s) in {a.scope['files_scanned']} file(s). Values are redacted.")
    return 20 if hits else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
