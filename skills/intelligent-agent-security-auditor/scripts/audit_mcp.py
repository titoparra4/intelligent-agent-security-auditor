#!/usr/bin/env python3
"""Audit MCP client configs and MCP server source (transport-aware: HTTP auth rules never applied to STDIO).

Usage: python scripts/audit_mcp.py <target> [--format text|json|markdown] [--policy P]

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
    sys.exit("PyYAML is required: python3 -m pip install PyYAML")

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from agent_security_auditor.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main(["mcp", *sys.argv[1:]]))
