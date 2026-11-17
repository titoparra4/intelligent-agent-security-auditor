#!/usr/bin/env python3
"""Run an audit and write reports, or re-render an existing assessment JSON.

Usage:
  python scripts/generate_report.py <target-dir> [-o reports] [--format json,markdown,sarif,html] [--policy P]
  python scripts/generate_report.py <assessment.json> -o reports [--format markdown,html,sarif]

Runs from a cloned skill without installation (adds ../src to sys.path). Read-only and offline:
the target is parsed, never imported or executed. Exit codes match agent-security-auditor.
"""

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

from agent_security_auditor.cli import main  # noqa: E402

if __name__ == "__main__":
    args = sys.argv[1:]
    if args and args[0].endswith(".json") and Path(args[0]).is_file():
        raise SystemExit(main(["report", *args]))
    if "-o" not in args and "--output" not in args:
        args += ["-o", "agent-security-reports"]
    raise SystemExit(main(["audit", *args]))
