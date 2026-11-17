"""Safe file discovery.

Defenses implemented here (the audited tree is untrusted input):

* symlinks are never followed (files *or* directories) and are reported as skipped;
* every candidate path is resolved and must stay inside the authorized root (path traversal /
  symlink escape);
* per-file, total-size, file-count and depth limits bound memory and time;
* binary files are detected by content and skipped;
* vendored / generated directories are skipped by default.
"""

from __future__ import annotations

import fnmatch
import os
import stat
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_SKIP_DIRS = frozenset({
    ".git", ".hg", ".svn", "node_modules", ".venv", "venv", "env", "__pycache__", ".tox", ".nox",
    ".mypy_cache", ".pytest_cache", ".ruff_cache", "site-packages", "dist", "build", ".next", ".cache",
    "coverage", "htmlcov", ".idea", ".vscode-test",
})

TEXT_EXTENSIONS = {
    ".py": "python", ".pyi": "python",
    ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript", ".jsx": "javascript",
    ".ts": "typescript", ".tsx": "typescript", ".mts": "typescript",
    ".json": "json", ".jsonc": "json", ".jsonl": "jsonl",
    ".yaml": "yaml", ".yml": "yaml",
    ".toml": "toml",
    ".md": "markdown", ".mdx": "markdown", ".txt": "text", ".rst": "text",
    ".eml": "email", ".html": "html", ".htm": "html", ".xml": "xml", ".csv": "text",
    ".cfg": "ini", ".ini": "ini", ".conf": "ini", ".env": "env",
    ".sh": "shell", ".bash": "shell", ".zsh": "shell", ".ps1": "shell",
    ".lock": "lock", ".sql": "sql", ".prompt": "text", ".j2": "text", ".jinja": "text",
}
SPECIAL_NAMES = {
    "Dockerfile": "docker", "Containerfile": "docker", "Makefile": "text", "Pipfile": "toml",
    "Procfile": "text", ".env": "env", "go.mod": "text", "Gemfile": "text",
}


@dataclass(frozen=True)
class DiscoveryLimits:
    max_file_bytes: int = 2 * 1024 * 1024
    max_total_bytes: int = 256 * 1024 * 1024
    max_files: int = 20_000
    max_depth: int = 30


@dataclass
class SourceFile:
    rel: str
    path: Path
    size: int
    kind: str
    _text: str | None = field(default=None, repr=False)

    def text(self) -> str:
        if self._text is None:
            with open(self.path, "rb") as fh:
                raw = fh.read(self.size + 1)
            self._text = raw.decode("utf-8", errors="replace")
        return self._text

    def lines(self) -> list[str]:
        return self.text().splitlines()


@dataclass
class SkippedPath:
    rel: str
    reason: str


@dataclass
class DiscoveryResult:
    root: Path
    files: list[SourceFile]
    skipped: list[SkippedPath]
    truncated: bool = False

    def by_kind(self, *kinds: str) -> list[SourceFile]:
        return [f for f in self.files if f.kind in kinds]

    def get(self, rel: str) -> SourceFile | None:
        rel = rel.replace("\\", "/").lstrip("./")
        for f in self.files:
            if f.rel == rel:
                return f
        return None


class DiscoveryError(Exception):
    pass


def classify(name: str) -> str | None:
    if name in SPECIAL_NAMES:
        return SPECIAL_NAMES[name]
    if name.startswith(".env"):
        return "env"
    if name.startswith("requirements") and name.endswith((".txt", ".in")):
        return "requirements"
    lower = name.lower()
    for ext, kind in TEXT_EXTENSIONS.items():
        if lower.endswith(ext):
            return kind
    return None


def _is_binary(path: Path) -> bool:
    with open(path, "rb") as fh:
        chunk = fh.read(8192)
    return b"\x00" in chunk


def is_within(root: Path, candidate: Path) -> bool:
    try:
        candidate.relative_to(root)
        return True
    except ValueError:
        return False


def discover(
    root: str | os.PathLike[str],
    limits: DiscoveryLimits | None = None,
    exclude: list[str] | None = None,
    skip_dirs: frozenset[str] = DEFAULT_SKIP_DIRS,
) -> DiscoveryResult:
    limits = limits or DiscoveryLimits()
    exclude = exclude or []
    root_path = Path(root)
    if not root_path.exists():
        raise DiscoveryError(f"target does not exist: {root}")
    if root_path.is_symlink():
        raise DiscoveryError("target root is a symlink; pass the real directory path")
    root_real = root_path.resolve(strict=True)
    if root_real.is_file():
        # single-file audit: the authorized root is the file's directory, only that file is read
        kind = classify(root_real.name) or "text"
        size = root_real.stat().st_size
        if size > limits.max_file_bytes:
            raise DiscoveryError(f"target file exceeds max size ({size} > {limits.max_file_bytes} bytes)")
        return DiscoveryResult(root_real.parent, [SourceFile(root_real.name, root_real, size, kind)], [])

    files: list[SourceFile] = []
    skipped: list[SkippedPath] = []
    total = 0
    truncated = False

    stack: list[tuple[Path, int]] = [(root_real, 0)]
    while stack:
        current, depth = stack.pop()
        if depth > limits.max_depth:
            skipped.append(SkippedPath(_rel(root_real, current), "max depth exceeded"))
            continue
        try:
            entries = sorted(os.scandir(current), key=lambda e: e.name)
        except OSError as exc:
            skipped.append(SkippedPath(_rel(root_real, current), f"unreadable directory: {exc.strerror}"))
            continue
        for entry in entries:
            p = Path(entry.path)
            rel = _rel(root_real, p)
            if any(fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch(entry.name, pat) for pat in exclude):
                skipped.append(SkippedPath(rel, "excluded by pattern"))
                continue
            try:
                st = entry.stat(follow_symlinks=False)
            except OSError as exc:
                skipped.append(SkippedPath(rel, f"stat failed: {exc.strerror}"))
                continue
            if stat.S_ISLNK(st.st_mode):
                skipped.append(SkippedPath(rel, "symlink not followed"))
                continue
            if stat.S_ISDIR(st.st_mode):
                if entry.name in skip_dirs:
                    skipped.append(SkippedPath(rel, "vendored/generated directory skipped"))
                    continue
                stack.append((p, depth + 1))
                continue
            if not stat.S_ISREG(st.st_mode):
                skipped.append(SkippedPath(rel, "not a regular file"))
                continue
            kind = classify(entry.name)
            if kind is None:
                continue  # silently ignore unknown types (images, archives, ...)
            real = p.resolve()
            if not is_within(root_real, real):
                skipped.append(SkippedPath(rel, "resolves outside authorized root"))
                continue
            if st.st_size > limits.max_file_bytes:
                skipped.append(SkippedPath(rel, f"file too large ({st.st_size} bytes)"))
                continue
            if len(files) >= limits.max_files or total + st.st_size > limits.max_total_bytes:
                truncated = True
                skipped.append(SkippedPath(rel, "discovery limit reached"))
                continue
            try:
                if _is_binary(p):
                    skipped.append(SkippedPath(rel, "binary content"))
                    continue
            except OSError as exc:
                skipped.append(SkippedPath(rel, f"unreadable: {exc.strerror}"))
                continue
            files.append(SourceFile(rel, p, st.st_size, kind))
            total += st.st_size
    files.sort(key=lambda f: f.rel)
    return DiscoveryResult(root_real, files, skipped, truncated)


def _rel(root: Path, p: Path) -> str:
    try:
        return p.relative_to(root).as_posix() or "."
    except ValueError:
        return p.name
