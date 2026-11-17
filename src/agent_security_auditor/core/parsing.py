"""Safe parsers for untrusted files.

* YAML uses ``yaml.SafeLoader`` only, with an alias-count limit (alias / "billion laughs" bombs).
* JSON is parsed with a nesting-depth limit.
* TOML uses the stdlib ``tomllib``.
* Python is parsed to an AST and **never** compiled or executed.

Every parser returns ``ParseResult`` instead of raising, so one malformed file cannot abort
an audit; the failure is recorded and surfaces in the report as reduced coverage.
"""

from __future__ import annotations

import ast
import json
import tomllib
import warnings
from dataclasses import dataclass
from typing import Any

import yaml

MAX_YAML_ALIASES = 200
MAX_NESTING = 64


@dataclass
class ParseResult:
    ok: bool
    value: Any = None
    error: str | None = None


class _LimitedSafeLoader(yaml.SafeLoader):
    """SafeLoader that refuses documents with an excessive number of alias references."""

    def __init__(self, stream: Any) -> None:
        super().__init__(stream)
        self._alias_count = 0

    def compose_node(self, parent: Any, index: Any) -> Any:  # type: ignore[override]
        if self.check_event(yaml.AliasEvent):
            self._alias_count += 1
            if self._alias_count > MAX_YAML_ALIASES:
                raise yaml.YAMLError("too many YAML aliases (possible alias bomb)")
        return super().compose_node(parent, index)


MAX_EXPANDED_NODES = 1_000_000


def _measure(obj: Any) -> tuple[int, int]:
    """(depth, expanded node count) with memoization of shared containers.

    YAML aliases share one Python object between many parents, so a naive walk of an alias bomb
    visits billions of nodes. Memoizing by ``id`` keeps this linear in the *document* size while
    still computing the *expanded* size, which is what downstream consumers would traverse.
    """
    memo: dict[int, tuple[int, int]] = {}

    def visit(o: Any, depth: int) -> tuple[int, int]:
        if not isinstance(o, (dict, list)):
            return 1, 1
        if depth > MAX_NESTING:
            return depth, 1
        key = id(o)
        if key in memo:
            return memo[key]
        children = o.values() if isinstance(o, dict) else o
        d_max, size = 1, 1
        for c in children:
            cd, cs = visit(c, depth + 1)
            d_max = max(d_max, cd + 1)
            size += cs
            if size > MAX_EXPANDED_NODES:
                break
        memo[key] = (d_max, size)
        return memo[key]

    return visit(obj, 1)


def _depth(obj: Any, limit: int = MAX_NESTING) -> int:
    depth, size = _measure(obj)
    return limit + 1 if size > MAX_EXPANDED_NODES else depth


def parse_yaml(text: str, multi: bool = False) -> ParseResult:
    # yaml.load is only ever called with _LimitedSafeLoader (a SafeLoader subclass): no python/* tags.
    try:
        if multi:
            docs = list(yaml.load_all(text, Loader=_LimitedSafeLoader))  # nosec B506
            value: Any = docs
        else:
            value = yaml.load(text, Loader=_LimitedSafeLoader)  # nosec B506
    except (yaml.YAMLError, RecursionError, ValueError) as exc:
        return ParseResult(False, error=f"yaml: {str(exc).splitlines()[0][:200]}")
    if _depth(value) > MAX_NESTING:
        return ParseResult(False, error="yaml: nesting too deep or expanded size too large (alias bomb)")
    return ParseResult(True, value)


def parse_json(text: str) -> ParseResult:
    try:
        value = json.loads(_strip_jsonc(text))
    except (json.JSONDecodeError, RecursionError, ValueError) as exc:
        return ParseResult(False, error=f"json: {str(exc)[:200]}")
    if _depth(value) > MAX_NESTING:
        return ParseResult(False, error="json: nesting too deep")
    return ParseResult(True, value)


def parse_toml(text: str) -> ParseResult:
    try:
        return ParseResult(True, tomllib.loads(text))
    except (tomllib.TOMLDecodeError, RecursionError, ValueError) as exc:
        return ParseResult(False, error=f"toml: {str(exc)[:200]}")


def parse_python(text: str, filename: str = "<audited>") -> ParseResult:
    """Parse to AST only. Never compile to bytecode, never exec."""
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")  # SyntaxWarnings from audited code are noise
            tree = ast.parse(text, filename=filename, type_comments=False)
    except (SyntaxError, RecursionError, ValueError, MemoryError) as exc:
        return ParseResult(False, error=f"python: {type(exc).__name__}: {str(exc)[:160]}")
    return ParseResult(True, tree)


def _strip_jsonc(text: str) -> str:
    """Remove // and /* */ comments outside strings (VS Code style mcp.json is JSONC)."""
    if "//" not in text and "/*" not in text:
        return text
    out: list[str] = []
    i, n = 0, len(text)
    in_str = False
    while i < n:
        c = text[i]
        if in_str:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if c == '"':
                in_str = False
            i += 1
            continue
        if c == '"':
            in_str = True
            out.append(c)
            i += 1
        elif text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j == -1 else j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            i = n if j == -1 else j + 2
        else:
            out.append(c)
            i += 1
    return "".join(out)


# --- AST helpers (pure, no evaluation) ------------------------------------------------------

def literal(node: ast.AST | None, names: dict[str, Any] | None = None) -> Any:
    """Best-effort conversion of an AST node to a Python literal WITHOUT evaluating code.

    Module-level constant names can be resolved through ``names``. Anything dynamic returns
    ``None`` (unknown), never a guess.
    """
    if node is None:
        return None
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return [literal(e, names) for e in node.elts]
    if isinstance(node, ast.Dict):
        out: dict[Any, Any] = {}
        for k, v in zip(node.keys, node.values):
            if k is None:
                continue
            kk = literal(k, names)
            if isinstance(kk, (str, int, float, bool)):
                out[kk] = literal(v, names)
        return out
    if isinstance(node, ast.Name) and names is not None:
        return names.get(node.id)
    if isinstance(node, ast.JoinedStr):
        parts = []
        for v in node.values:
            if isinstance(v, ast.Constant):
                parts.append(str(v.value))
            else:
                parts.append("{…}")
        return "".join(parts)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        a, b = literal(node.left, names), literal(node.right, names)
        if isinstance(a, str) and isinstance(b, str):
            return a + b
    return None


def call_name(node: ast.AST) -> str:
    """Dotted name of a call target: ``requests.post`` / ``Agent`` / ``self.client.send``."""
    if isinstance(node, ast.Call):
        node = node.func
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    elif isinstance(node, ast.Call):
        parts.append(call_name(node) + "()")
    return ".".join(reversed(parts))


def kwarg(call: ast.Call, name: str) -> ast.AST | None:
    for kw in call.keywords:
        if kw.arg == name:
            return kw.value
    return None


def module_constants(tree: ast.Module) -> dict[str, Any]:
    consts: dict[str, Any] = {}
    for stmt in tree.body:
        if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
            val = literal(stmt.value, consts)
            if val is not None:
                consts[stmt.targets[0].id] = val
        elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name) and stmt.value is not None:
            val = literal(stmt.value, consts)
            if val is not None:
                consts[stmt.target.id] = val
    return consts
