"""Minimal, dependency-free JSON Schema validator (Draft 2020-12 subset).

Supports the keywords used by the project's own schemas: ``type``, ``required``,
``properties``, ``additionalProperties``, ``items``, ``enum``, ``const``, ``pattern``,
``minimum``, ``maximum``, ``minLength``, ``minItems``, ``uniqueItems``, ``format: date``,
``format: date-time`` and local ``$ref`` (``#/$defs/...``). The test-suite additionally
validates outputs with the reference ``jsonschema`` package when it is installed.
"""

from __future__ import annotations

import datetime as _dt
import json
import re
from functools import lru_cache
from importlib import resources
from typing import Any

_TYPES = {
    "string": lambda v: isinstance(v, str),
    "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
    "number": lambda v: isinstance(v, (int, float)) and not isinstance(v, bool),
    "boolean": lambda v: isinstance(v, bool),
    "array": lambda v: isinstance(v, list),
    "object": lambda v: isinstance(v, dict),
    "null": lambda v: v is None,
}


def validate(instance: Any, schema: dict[str, Any], max_errors: int = 50) -> list[str]:
    errors: list[str] = []
    _validate(instance, schema, schema, "$", errors, max_errors)
    return errors


def _resolve(root: dict[str, Any], ref: str) -> dict[str, Any]:
    if not ref.startswith("#/"):
        raise ValueError(f"unsupported $ref: {ref}")
    node: Any = root
    for part in ref[2:].split("/"):
        node = node[part]
    return node


def _validate(v: Any, s: dict[str, Any], root: dict[str, Any], path: str, errors: list[str], cap: int) -> None:
    if len(errors) >= cap:
        return
    if "$ref" in s:
        _validate(v, _resolve(root, s["$ref"]), root, path, errors, cap)
        return
    t = s.get("type")
    if t is not None:
        types = t if isinstance(t, list) else [t]
        if not any(_TYPES[x](v) for x in types):
            errors.append(f"{path}: expected {'/'.join(types)}, got {type(v).__name__}")
            return
    if "const" in s and v != s["const"]:
        errors.append(f"{path}: must equal {s['const']!r}")
    if "enum" in s and v not in s["enum"]:
        errors.append(f"{path}: {v!r} not in {s['enum']}")
    if isinstance(v, str):
        if "minLength" in s and len(v) < s["minLength"]:
            errors.append(f"{path}: shorter than {s['minLength']}")
        if "pattern" in s and not re.search(s["pattern"], v):
            errors.append(f"{path}: does not match pattern {s['pattern']}")
        fmt = s.get("format")
        if fmt == "date":
            try:
                _dt.date.fromisoformat(v)
            except ValueError:
                errors.append(f"{path}: not a valid date (YYYY-MM-DD)")
        elif fmt == "date-time":
            try:
                _dt.datetime.fromisoformat(v.replace("Z", "+00:00"))
            except ValueError:
                errors.append(f"{path}: not a valid date-time")
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        if "minimum" in s and v < s["minimum"]:
            errors.append(f"{path}: below minimum {s['minimum']}")
        if "maximum" in s and v > s["maximum"]:
            errors.append(f"{path}: above maximum {s['maximum']}")
    if isinstance(v, list):
        if "minItems" in s and len(v) < s["minItems"]:
            errors.append(f"{path}: fewer than {s['minItems']} items")
        if s.get("uniqueItems"):
            seen = [json.dumps(x, sort_keys=True, default=str) for x in v]
            if len(seen) != len(set(seen)):
                errors.append(f"{path}: items not unique")
        if isinstance(s.get("items"), dict):
            for i, item in enumerate(v):
                _validate(item, s["items"], root, f"{path}[{i}]", errors, cap)
    if isinstance(v, dict):
        for req in s.get("required", []):
            if req not in v:
                errors.append(f"{path}: missing required property '{req}'")
        props = s.get("properties", {})
        for k, item in v.items():
            if k in props:
                _validate(item, props[k], root, f"{path}.{k}", errors, cap)
            else:
                ap = s.get("additionalProperties", True)
                if ap is False:
                    errors.append(f"{path}: unexpected property '{k}'")
                elif isinstance(ap, dict):
                    _validate(item, ap, root, f"{path}.{k}", errors, cap)


@lru_cache(maxsize=None)
def load_schema(name: str) -> dict[str, Any]:
    """Load a bundled schema (``finding``, ``assessment``, ``policy``, ``agent-manifest``)."""
    text = resources.files("agent_security_auditor").joinpath("schemas", f"{name}.schema.json").read_text("utf-8")
    return json.loads(text)
