"""Adapter protocol.

An adapter recognizes one family of artifacts (a framework, a config format, a dependency
manifest) and writes normalized components into ``ctx.inventory``. Adapters must:

* never execute, import or install anything from the audited project;
* record provenance (``declared`` / ``configured`` / ``code`` / ``inferred``);
* declare honestly what they support in ``coverage`` (shown in the report).
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from agent_security_auditor.core.context import AuditContext


@runtime_checkable
class Adapter(Protocol):
    name: str
    #: human-readable statement of what is (and is not) detected, surfaced in reports/docs
    coverage: str

    def applies(self, ctx: AuditContext) -> bool: ...

    def populate(self, ctx: AuditContext) -> None: ...
