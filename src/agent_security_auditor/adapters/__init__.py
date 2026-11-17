"""Framework / format adapters that build the normalized inventory.

Order matters only for provenance merging: code-derived facts are collected first and
manifest declarations enrich them afterwards (``Inventory.add_tool`` merges by name).
"""

from __future__ import annotations

from agent_security_auditor.adapters.base import Adapter
from agent_security_auditor.adapters.dependencies import DependencyAdapter
from agent_security_auditor.adapters.javascript import JavaScriptAdapter
from agent_security_auditor.adapters.manifest import ManifestAdapter
from agent_security_auditor.adapters.mcp_config import McpConfigAdapter
from agent_security_auditor.adapters.python_code import PythonCodeAdapter


def default_adapters() -> list[Adapter]:
    return [PythonCodeAdapter(), JavaScriptAdapter(), McpConfigAdapter(), DependencyAdapter(), ManifestAdapter()]


__all__ = ["Adapter", "default_adapters"]
