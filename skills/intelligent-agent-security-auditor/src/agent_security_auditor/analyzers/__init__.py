"""The analysis modules (M01-M11). M12 (reporting) lives in ``reporters``.

Execution order matters: M01 publishes artifacts (data flows, permission matrix) that later
modules read from ``ctx.artifacts``.
"""

from __future__ import annotations

from importlib.metadata import entry_points

from agent_security_auditor.analyzers.adversarial import AdversarialAnalyzer
from agent_security_auditor.analyzers.architecture import ArchitectureAnalyzer
from agent_security_auditor.analyzers.autonomy import AutonomyAnalyzer
from agent_security_auditor.analyzers.base import Analyzer, AnalyzerResult
from agent_security_auditor.analyzers.data_leakage import DataLeakageAnalyzer
from agent_security_auditor.analyzers.exfiltration import ExfiltrationAnalyzer
from agent_security_auditor.analyzers.mcp import McpAnalyzer
from agent_security_auditor.analyzers.memory import MemoryAnalyzer
from agent_security_auditor.analyzers.multi_agent import MultiAgentAnalyzer
from agent_security_auditor.analyzers.permissions import PermissionAnalyzer
from agent_security_auditor.analyzers.prompt_injection import PromptInjectionAnalyzer
from agent_security_auditor.analyzers.supply_chain import SupplyChainAnalyzer

PLUGIN_GROUP = "agent_security_auditor.analyzers"


def default_analyzers() -> list[Analyzer]:
    return [
        ArchitectureAnalyzer(), PromptInjectionAnalyzer(), DataLeakageAnalyzer(), ExfiltrationAnalyzer(),
        PermissionAnalyzer(), McpAnalyzer(), MemoryAnalyzer(), SupplyChainAnalyzer(), AutonomyAnalyzer(),
        MultiAgentAnalyzer(), AdversarialAnalyzer(),
    ]


def plugin_analyzers() -> list[Analyzer]:
    """Analyzers registered by installed packages (opt-in via ``--plugins``).

    Plugins are code installed in the *auditor's* environment by the user, never code from
    the audited target.
    """
    out: list[Analyzer] = []
    for ep in entry_points(group=PLUGIN_GROUP):
        obj = ep.load()
        inst = obj() if isinstance(obj, type) else obj
        if isinstance(inst, Analyzer):
            out.append(inst)
    return out


__all__ = ["Analyzer", "AnalyzerResult", "default_analyzers", "plugin_analyzers"]
