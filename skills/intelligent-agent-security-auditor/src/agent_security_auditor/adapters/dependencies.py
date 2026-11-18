"""Dependency manifest adapter (read-only; install scripts are recorded, never run)."""

from __future__ import annotations

import re
from typing import Any

from agent_security_auditor.core.context import AuditContext
from agent_security_auditor.models.inventory import Dependency

LOCKFILES = ("poetry.lock", "uv.lock", "Pipfile.lock", "pdm.lock", "package-lock.json", "yarn.lock",
             "pnpm-lock.yaml", "bun.lockb", "npm-shrinkwrap.json", "requirements.lock", "conda-lock.yml")
REQ_LINE = re.compile(r"^\s*([A-Za-z0-9_.\-\[\],]+)\s*(.*)$")
NPM_INSTALL_HOOKS = ("preinstall", "install", "postinstall", "prepare", "prepublish")


class DependencyAdapter:
    name = "dependencies"
    coverage = (
        "requirements*.txt / .in, pyproject.toml (PEP 621 + Poetry), Pipfile, package.json; lockfile presence; "
        "npm install hooks. Transitive dependencies are only known when a lockfile is present and are not "
        "resolved by this adapter."
    )

    def applies(self, ctx: AuditContext) -> bool:
        return True

    def populate(self, ctx: AuditContext) -> None:
        inv = ctx.inventory
        hooks: list[dict[str, Any]] = ctx.artifacts.setdefault("install_scripts", [])
        for f in ctx.files:
            base = f.rel.rsplit("/", 1)[-1]
            if base in LOCKFILES:
                inv.lockfiles.append(f.rel)
            if f.kind == "requirements":
                hashed = "--hash=" in f.text()
                if hashed:
                    inv.lockfiles.append(f.rel)
                for i, raw in enumerate(f.lines(), 1):
                    dep = _parse_req(raw)
                    if dep:
                        name, spec, source = dep
                        inv.dependencies.append(Dependency(name, "pypi", spec, _pinned_py(spec) or hashed, source, f.rel, i))
            elif base == "pyproject.toml":
                res = ctx.parsed(f)
                if res.ok and isinstance(res.value, dict):
                    self._pyproject(ctx, f.rel, res.value, f.lines())
            elif base == "package.json":
                res = ctx.parsed(f)
                if res.ok and isinstance(res.value, dict):
                    lines = f.lines()
                    for section in ("dependencies", "optionalDependencies", "peerDependencies"):
                        deps = res.value.get(section)
                        if isinstance(deps, dict):
                            for name, spec in deps.items():
                                spec = str(spec)
                                source = "vcs" if re.match(r"^(git\+|github:|git://)", spec) or "/" in spec and not spec.startswith("@") and "://" in spec else (
                                    "url" if spec.startswith(("http://", "https://")) else "path" if spec.startswith(("file:", "link:")) else "registry")
                                pinned = bool(re.fullmatch(r"=?\d+\.\d+\.\d+(-[\w.]+)?", spec))
                                inv.dependencies.append(Dependency(str(name), "npm", spec, pinned, source, f.rel,
                                                                   _line_of(lines, f'"{name}"')))
                    scripts = res.value.get("scripts")
                    if isinstance(scripts, dict):
                        for hook in NPM_INSTALL_HOOKS:
                            if hook in scripts:
                                hooks.append({"file": f.rel, "hook": hook, "command": str(scripts[hook])[:200],
                                              "line": _line_of(lines, f'"{hook}"')})
            elif base == "setup.py":
                text = f.text()
                if re.search(r"cmdclass\s*=|class\s+\w+\((?:install|develop|egg_info)\)", text):
                    hooks.append({"file": f.rel, "hook": "setup.py cmdclass", "command": "custom install command class",
                                  "line": _line_of(f.lines(), "cmdclass")})

    def _pyproject(self, ctx: AuditContext, rel: str, doc: dict[str, Any], lines: list[str]) -> None:
        inv = ctx.inventory
        proj = doc.get("project") if isinstance(doc.get("project"), dict) else {}
        for raw in proj.get("dependencies", []) or []:
            dep = _parse_req(str(raw))
            if dep:
                name, spec, source = dep
                inv.dependencies.append(Dependency(name, "pypi", spec, _pinned_py(spec), source, rel, _line_of(lines, name)))
        poetry = (doc.get("tool") or {}).get("poetry") if isinstance(doc.get("tool"), dict) else None
        if isinstance(poetry, dict) and isinstance(poetry.get("dependencies"), dict):
            for name, spec in poetry["dependencies"].items():
                if name == "python":
                    continue
                if isinstance(spec, dict):
                    source = "vcs" if "git" in spec else "url" if "url" in spec else "path" if "path" in spec else "registry"
                    spec_s = str(spec.get("version", spec.get("rev", spec.get("tag", ""))))
                else:
                    source, spec_s = "registry", str(spec)
                if isinstance(spec, dict) and source == "vcs":
                    pinned = bool(re.fullmatch(r"[0-9a-f]{40}", str(spec.get("rev", ""))))
                else:
                    pinned = bool(re.fullmatch(r"=?=?\d+(\.\d+)*", spec_s))
                inv.dependencies.append(Dependency(name, "pypi", spec_s, pinned, source, rel, _line_of(lines, name)))


def _parse_req(raw: str) -> tuple[str, str, str] | None:
    line = raw.split(" #", 1)[0].strip()
    if not line or line.startswith(("#", "-r", "-c", "--", "-e .", "-i ", "--index")):
        return None
    if line.startswith("-e ") or line.startswith(("git+", "hg+", "svn+")) or " @ git+" in line or "@ git+" in line:
        name = re.split(r"[@#=]", line.replace("-e ", "").split("egg=")[-1])[0].strip() or line
        pinned_ref = bool(re.search(r"@[0-9a-f]{40}", line))
        return name.split("/")[-1].replace(".git", ""), ("vcs-commit" if pinned_ref else "vcs"), "vcs"
    if line.startswith(("http://", "https://")) or " @ http" in line:
        return line.split(" @ ")[0].rsplit("/", 1)[-1], "url", "url"
    m = REQ_LINE.match(line.split(";")[0])
    if not m:
        return None
    name = m.group(1).split("[")[0]
    spec = m.group(2).strip()
    return name, spec, "registry"


def _pinned_py(spec: str) -> bool:
    if spec in ("vcs-commit",):
        return True
    return bool(re.fullmatch(r"===?\s*[\w.\-+!]+", spec.strip()))


def _line_of(lines: list[str], needle: str) -> int | None:
    for i, ln in enumerate(lines, 1):
        if needle in ln:
            return i
    return None
