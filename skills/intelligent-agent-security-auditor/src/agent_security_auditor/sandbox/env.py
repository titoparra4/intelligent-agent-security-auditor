"""Sandbox environment exposed to a test harness (runs inside the isolated child process).

The harness adapts the agent under test to a fixed, *simulated* toolkit. Every tool returns
synthetic content defined by the scenario; nothing touches real services. All calls are
recorded in a trace that the parent process evaluates.

Toolkit contract (harness side)::

    def run(task: str, env: SandboxEnv) -> None

Simulated tools: ``read_email``, ``search_documents``, ``query_records``, ``send_email``,
``http_post``, ``delete_record``, ``execute_code``, ``write_memory``, ``read_memory``,
``delegate``. ``env.request_approval(action, details)`` returns the scenario's approval
decision (default: denied). ``env.respond(text)`` records the final answer.
"""

from __future__ import annotations

import copy
import json
from typing import Any

SIMULATED_TOOLS = ("read_email", "search_documents", "query_records", "send_email", "http_post", "delete_record",
                   "execute_code", "write_memory", "read_memory", "delegate", "get_tool_descriptions")
EGRESS_TOOLS = ("send_email", "http_post")
IRREVERSIBLE_TOOLS = ("send_email", "http_post", "delete_record", "execute_code")


class ToolBudgetExceeded(RuntimeError):
    pass


class SandboxEnv:
    def __init__(self, fixture: dict[str, Any], user: str = "user-a", max_tool_calls: int = 50) -> None:
        self._fx = copy.deepcopy(fixture)
        self.user = user
        self.trace: list[dict[str, Any]] = []
        self.responses: list[str] = []
        self.approvals: list[dict[str, Any]] = []
        self.memory: dict[str, list[dict[str, Any]]] = copy.deepcopy(self._fx.get("memory", {}))
        self.allowlist: list[str] = list(self._fx.get("allowlist", []))
        self.max_tool_calls = max_tool_calls
        self.errors: list[str] = []
        #: the task the harness must give to its agent and the tenant of the acting user
        self.task: str = str(self._fx.get("task", ""))
        self.tenant: str = str(self._fx.get("tenant", "tenant-a"))

    # -- harness API ------------------------------------------------------------------------
    @property
    def tool_names(self) -> tuple[str, ...]:
        return SIMULATED_TOOLS

    def request_approval(self, action: str, details: dict[str, Any] | str) -> bool:
        decision = bool(self._fx.get("approve", False))
        self.approvals.append({"action": action, "details": _clip(details), "granted": decision})
        return decision

    def respond(self, text: str) -> None:
        self.responses.append(str(text)[:4000])

    def call_tool(self, name: str, **kwargs: Any) -> Any:
        if len(self.trace) >= self.max_tool_calls:
            raise ToolBudgetExceeded(f"tool-call budget of {self.max_tool_calls} exceeded")
        if name not in SIMULATED_TOOLS:
            self.trace.append({"tool": name, "args": _clip(kwargs), "error": "unknown tool"})
            raise KeyError(f"unknown simulated tool: {name}")
        entry = {"tool": name, "args": _clip(kwargs), "user": self.user}
        self.trace.append(entry)
        failing = self._fx.get("failing_tools", {})
        if name in failing:
            entry["error"] = failing[name]
            raise RuntimeError(failing[name])
        handler = getattr(self, f"_t_{name}")
        result = handler(**kwargs)
        entry["result_preview"] = _clip(result, 300)
        return result

    # -- simulated tools --------------------------------------------------------------------
    def _t_read_email(self, **_: Any) -> list[dict[str, Any]]:
        return self._fx.get("emails", [])

    def _t_search_documents(self, query: str = "", **_: Any) -> list[dict[str, Any]]:
        return self._fx.get("documents", [])

    def _t_query_records(self, query: str = "", tenant: str | None = None, **_: Any) -> list[dict[str, Any]]:
        rows = self._fx.get("records", [])
        return [r for r in rows if tenant is None or r.get("tenant") == tenant]

    def _t_send_email(self, to: str = "", subject: str = "", body: str = "", **_: Any) -> dict[str, Any]:
        return {"status": "simulated-sent", "to": to}

    def _t_http_post(self, url: str = "", body: Any = None, **_: Any) -> dict[str, Any]:
        return {"status": 200, "simulated": True}

    def _t_delete_record(self, record_id: str = "", **_: Any) -> dict[str, Any]:
        return {"deleted": record_id, "simulated": True}

    def _t_execute_code(self, code: str = "", **_: Any) -> dict[str, Any]:
        return {"stdout": "", "simulated": True, "note": "code is never executed by the sandbox toolkit"}

    def _t_write_memory(self, key: str = "", value: str = "", user: str | None = None, source: str = "unknown", **_: Any) -> dict[str, Any]:
        owner = user or self.user
        self.memory.setdefault(owner, []).append({"key": key, "value": str(value)[:2000], "source": source})
        return {"ok": True}

    def _t_read_memory(self, user: str | None = None, **_: Any) -> list[dict[str, Any]]:
        return self.memory.get(user or self.user, [])

    def _t_delegate(self, agent: str = "", message: str = "", **_: Any) -> dict[str, Any]:
        return self._fx.get("delegate_reply", {"from": agent, "reply": "ok"})

    def _t_get_tool_descriptions(self, **_: Any) -> list[dict[str, str]]:
        return self._fx.get("tool_descriptions", [])

    # -- export -------------------------------------------------------------------------------
    def export(self) -> dict[str, Any]:
        return {"trace": self.trace, "responses": self.responses, "approvals": self.approvals,
                "memory": self.memory, "errors": self.errors}


def _clip(value: Any, limit: int = 2000) -> Any:
    try:
        text = json.dumps(value, default=str)
    except (TypeError, ValueError):
        text = str(value)
    if len(text) <= limit:
        return value if isinstance(value, (dict, list, str, int, float, bool)) or value is None else text
    return text[:limit] + "…"
