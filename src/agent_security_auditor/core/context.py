"""Audit context shared by adapters and analyzers (one per run)."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Any

from agent_security_auditor.core.discovery import DiscoveryResult, SourceFile
from agent_security_auditor.core.parsing import ParseResult, parse_json, parse_python, parse_toml, parse_yaml
from agent_security_auditor.models.assessment import Mode
from agent_security_auditor.models.inventory import Inventory


@dataclass
class AuditContext:
    discovery: DiscoveryResult
    mode: Mode
    policy: Any  # policies.model.Policy (avoid import cycle)
    inventory: Inventory = field(default_factory=Inventory)
    options: dict[str, Any] = field(default_factory=dict)
    parse_errors: list[dict[str, str]] = field(default_factory=list)
    artifacts: dict[str, Any] = field(default_factory=dict)
    _cache: dict[str, ParseResult] = field(default_factory=dict)

    @property
    def files(self) -> list[SourceFile]:
        return self.discovery.files

    def parsed(self, f: SourceFile) -> ParseResult:
        if f.rel in self._cache:
            return self._cache[f.rel]
        text = f.text()
        if f.kind == "python":
            res = parse_python(text, f.rel)
        elif f.kind in ("json",) or f.rel.endswith(".lock") and text.lstrip().startswith("{"):
            res = parse_json(text)
        elif f.kind == "yaml":
            res = parse_yaml(text)
        elif f.kind == "toml":
            res = parse_toml(text)
        else:
            res = ParseResult(True, text)
        if not res.ok:
            self.parse_errors.append({"file": f.rel, "error": res.error or "unknown"})
        self._cache[f.rel] = res
        return res

    def python_trees(self) -> list[tuple[SourceFile, ast.Module]]:
        out = []
        for f in self.discovery.by_kind("python"):
            r = self.parsed(f)
            if r.ok and isinstance(r.value, ast.Module):
                out.append((f, r.value))
        return out

    def structured(self, *kinds: str) -> list[tuple[SourceFile, Any]]:
        out = []
        for f in self.discovery.by_kind(*kinds):
            r = self.parsed(f)
            if r.ok and r.value is not None:
                out.append((f, r.value))
        return out
