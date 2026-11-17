"""Secret detection and redaction.

The auditor must never become an exfiltration channel itself: every snippet that leaves a
detector passes through :func:`redact` before it is stored in a finding, report or log.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass

MAX_SNIPPET = 220


@dataclass(frozen=True)
class SecretPattern:
    name: str
    regex: re.Pattern[str]
    group: int = 0
    severity: str = "HIGH"


SECRET_PATTERNS: tuple[SecretPattern, ...] = (
    SecretPattern("private_key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----"), 0, "CRITICAL"),
    SecretPattern("aws_access_key_id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), 0, "CRITICAL"),
    SecretPattern("github_token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b"), 0, "CRITICAL"),
    SecretPattern("anthropic_api_key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}"), 0, "CRITICAL"),
    SecretPattern("openai_api_key", re.compile(r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_\-]{32,}"), 0, "CRITICAL"),
    SecretPattern("slack_token", re.compile(r"\bxox[abprs]-[A-Za-z0-9\-]{10,}"), 0, "HIGH"),
    SecretPattern("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), 0, "HIGH"),
    SecretPattern("stripe_live_key", re.compile(r"\b(?:sk|rk)_live_[0-9a-zA-Z]{20,}"), 0, "CRITICAL"),
    SecretPattern("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"), 0, "HIGH"),
    SecretPattern(
        "connection_string_password",
        re.compile(r"\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|amqp|mssql)://[^:/\s\"']+:([^@\s\"']{4,})@"),
        1,
        "HIGH",
    ),
    SecretPattern(
        "generic_assignment",
        re.compile(
            r"""(?ix)
            \b(?:api[_\-]?key|apikey|secret(?:[_\-]?key)?|client[_\-]?secret|access[_\-]?token|auth[_\-]?token|
               bearer|password|passwd|pwd|private[_\-]?key|token)\b
            ["']?\s*[:=]\s*["']([^"'\s]{8,})["']
            """
        ),
        1,
        "HIGH",
    ),
)

PLACEHOLDER_MARKERS = (
    "example", "placeholder", "changeme", "change_me", "your_", "your-", "xxxx", "<", ">", "${", "{{", "%(",
    "dummy", "fake", "sample", "redacted", "synthetic", "canary", "not-a-real", "notreal", "replace", "todo",
    "test", "lab-", "demo", "os.environ", "getenv", "process.env", "env(", "****", "...",
)

_EMAIL = re.compile(r"\b([A-Za-z0-9._%+\-])[A-Za-z0-9._%+\-]*@([A-Za-z0-9.\-]+\.[A-Za-z]{2,})\b")
_CARD = re.compile(r"\b(?:\d[ \-]?){13,19}\b")
_BEARER = re.compile(r"(?i)(authorization[\"']?\s*[:=]\s*[\"']?(?:bearer|basic)\s+)([A-Za-z0-9._~+/\-=]{6,})")


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    freq: dict[str, int] = {}
    for ch in value:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(value)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def is_placeholder(value: str) -> bool:
    low = value.lower()
    if any(m in low for m in PLACEHOLDER_MARKERS):
        return True
    if len(set(value)) <= 2:
        return True
    return False


@dataclass
class SecretMatch:
    kind: str
    start: int
    end: int
    severity: str
    value_len: int


def find_secrets(text: str) -> list[SecretMatch]:
    """Return candidate secrets with placeholder / low-entropy values filtered out."""
    out: list[SecretMatch] = []
    taken: list[tuple[int, int]] = []
    for pat in SECRET_PATTERNS:
        for m in pat.regex.finditer(text):
            s, e = m.span(pat.group)
            value = m.group(pat.group)
            if any(s < te and e > ts for ts, te in taken):
                continue
            if pat.name != "private_key" and is_placeholder(value):
                continue
            if pat.name == "generic_assignment" and shannon_entropy(value) < 3.0:
                continue
            if pat.name == "private_key":
                window = text[e : e + 120]
                if is_placeholder(window[:60]) or len(window.strip()) < 40:
                    continue
            out.append(SecretMatch(pat.name, s, e, pat.severity, len(value)))
            taken.append((s, e))
    return out


def _mask(value: str) -> str:
    keep = 4 if len(value) >= 16 else 2 if len(value) >= 8 else 0
    return f"{value[:keep]}…[REDACTED:{len(value)}]"


def _luhn_ok(digits: str) -> bool:
    total, alt = 0, False
    for ch in reversed(digits):
        d = int(ch)
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


def redact(text: str | None, max_len: int = MAX_SNIPPET) -> str | None:
    """Mask secrets, bearer tokens, card-like numbers and e-mail local parts; then truncate."""
    if text is None:
        return None
    s = text
    for m in sorted(find_secrets(s), key=lambda m: m.start, reverse=True):
        s = s[: m.start] + _mask(s[m.start : m.end]) + s[m.end :]
    s = _BEARER.sub(lambda m: m.group(1) + _mask(m.group(2)), s)

    def _card(m: re.Match[str]) -> str:
        digits = re.sub(r"\D", "", m.group(0))
        if 13 <= len(digits) <= 19 and _luhn_ok(digits):
            return f"[REDACTED-PAN:…{digits[-4:]}]"
        return m.group(0)

    s = _CARD.sub(_card, s)
    s = _EMAIL.sub(lambda m: f"{m.group(1)}***@{m.group(2)}", s)
    s = s.replace("\r", "")
    if len(s) > max_len:
        s = s[: max_len - 1] + "…"
    return s


def line_snippet(lines: list[str], line_no: int | None, context: int = 0) -> str | None:
    if not line_no or line_no < 1 or line_no > len(lines):
        return None
    lo = max(1, line_no - context)
    hi = min(len(lines), line_no + context)
    chunk = "\n".join(lines[i - 1].rstrip() for i in range(lo, hi + 1)).strip()
    return redact(chunk)
