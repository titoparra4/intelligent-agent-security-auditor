"""Deterministic classification helpers: operations, data categories, OAuth scopes, hosts.

These heuristics only produce *inferred* facts. Analyzers must keep the provenance and
must not present an inference as confirmed.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlparse

_OP_KEYWORDS: dict[str, tuple[str, ...]] = {
    "delete": ("delete", "remove", "drop", "purge", "destroy", "erase", "truncate", "wipe", "unlink"),
    "send": ("send", "email_user", "post_message", "notify", "reply", "forward", "publish", "share",
             "upload", "webhook", "tweet", "sms", "export", "report_to", "submit"),
    "write": ("write", "update", "create", "insert", "modify", "edit", "save", "set_", "append", "patch",
              "put_", "move", "rename", "commit"),
    "execute": ("exec", "execute", "run_code", "run_command", "shell", "bash", "terminal", "python_repl",
                "eval", "subprocess", "code_interpreter", "run_script"),
    "financial": ("pay", "payment", "transfer", "refund", "charge", "invoice", "wire", "purchase",
                  "withdraw", "trade", "order"),
    "infra": ("deploy", "kubectl", "terraform", "provision", "scale", "restart", "shutdown", "iam",
              "firewall", "dns", "rollout"),
    "admin": ("admin", "grant", "revoke", "role", "privilege", "sudo", "impersonate"),
    "read": ("read", "get", "list", "search", "query", "fetch", "lookup", "find", "retrieve", "browse",
             "view", "load", "download", "inspect", "summarize", "select"),
}

_DATA_KEYWORDS: dict[str, tuple[str, ...]] = {
    "email": ("email", "gmail", "mail", "inbox", "outlook", "imap", "smtp"),
    "documents": ("drive", "document", "docs", "sharepoint", "onedrive", "pdf", "notion", "confluence", "wiki"),
    "database": ("database", "db", "sql", "postgres", "mysql", "mongo", "crm", "customer", "record", "table",
                 "erp", "salesforce", "hubspot"),
    "web": ("web", "browse", "url", "http", "scrape", "website", "internet", "search_web", "fetch_page"),
    "rag": ("rag", "retriev", "vector", "embedding", "knowledge", "kb_", "semantic_search"),
    "chat": ("slack", "teams", "discord", "chat", "message"),
    "tickets": ("ticket", "jira", "zendesk", "issue", "servicenow"),
    "payments": ("payment", "stripe", "invoice", "billing", "bank", "transfer", "card", "ledger"),
    "secrets": ("secret", "vault", "credential", "password", "token", "keychain", "kms"),
    "files": ("file", "filesystem", "directory", "folder", "disk", "path"),
    "calendar": ("calendar", "meeting", "event", "schedule"),
}

_SENSITIVITY_BY_DATA: dict[str, tuple[str, ...]] = {
    "email": ("pii", "confidential"),
    "documents": ("confidential",),
    "database": ("pii", "confidential"),
    "payments": ("financial", "pii"),
    "secrets": ("credentials",),
    "chat": ("pii", "confidential"),
    "tickets": ("pii",),
    "calendar": ("pii",),
}

_WORD_SPLIT = re.compile(r"[^a-z0-9]+")


def _tokens(*texts: str) -> str:
    joined = " ".join(t for t in texts if t)
    # camelCase -> camel_case so "sendEmail" matches "send"
    joined = re.sub(r"([a-z])([A-Z])", r"\1_\2", joined)
    return "_" + "_".join(p for p in _WORD_SPLIT.split(joined.lower()) if p) + "_"


def infer_operations(name: str, description: str = "") -> list[str]:
    name_tok = _tokens(name)
    ops: list[str] = []
    for op, words in _OP_KEYWORDS.items():
        if any(("_" + w.strip("_")) in name_tok for w in words):
            ops.append(op)
    if not ops and description:
        desc_tok = _tokens(description[:300])
        for op, words in _OP_KEYWORDS.items():
            if any(("_" + w.strip("_") + "_") in desc_tok for w in words):
                ops.append(op)
    return ops


def infer_data_access(name: str, description: str = "") -> list[str]:
    tok = _tokens(name, description[:300])
    found = []
    for kind, words in _DATA_KEYWORDS.items():
        if any(("_" + w.strip("_")) in tok for w in words):
            found.append(kind)
    return found


def sensitivity_for(data_access: list[str]) -> list[str]:
    out: list[str] = []
    for d in data_access:
        for s in _SENSITIVITY_BY_DATA.get(d, ()):
            if s not in out:
                out.append(s)
    return out


# --- OAuth scopes / roles -------------------------------------------------------------------

@dataclass(frozen=True)
class ScopeInfo:
    scope: str
    operations: tuple[str, ...]
    broad: bool
    admin: bool
    narrower_alternative: str | None = None


_SCOPE_TABLE: dict[str, ScopeInfo] = {
    # Google Workspace
    "https://mail.google.com/": ScopeInfo("https://mail.google.com/", ("read", "write", "delete", "send"), True, False,
                                          "https://www.googleapis.com/auth/gmail.readonly"),
    "https://www.googleapis.com/auth/gmail.modify": ScopeInfo("gmail.modify", ("read", "write", "send"), True, False,
                                                              "https://www.googleapis.com/auth/gmail.readonly"),
    "https://www.googleapis.com/auth/gmail.readonly": ScopeInfo("gmail.readonly", ("read",), False, False),
    "https://www.googleapis.com/auth/gmail.send": ScopeInfo("gmail.send", ("send",), False, False),
    "https://www.googleapis.com/auth/gmail.compose": ScopeInfo("gmail.compose", ("write", "send"), False, False),
    "https://www.googleapis.com/auth/drive": ScopeInfo("drive", ("read", "write", "delete", "send"), True, False,
                                                       "https://www.googleapis.com/auth/drive.file"),
    "https://www.googleapis.com/auth/drive.readonly": ScopeInfo("drive.readonly", ("read",), True, False,
                                                                "https://www.googleapis.com/auth/drive.file"),
    "https://www.googleapis.com/auth/drive.file": ScopeInfo("drive.file", ("read", "write"), False, False),
    "https://www.googleapis.com/auth/drive.metadata.readonly": ScopeInfo("drive.metadata.readonly", ("read",), False, False),
    "https://www.googleapis.com/auth/cloud-platform": ScopeInfo("cloud-platform", ("read", "write", "delete", "infra", "admin"), True, True),
    "https://www.googleapis.com/auth/admin.directory.user": ScopeInfo("admin.directory.user", ("read", "write", "delete", "admin"), True, True),
    # Microsoft Graph
    "Mail.ReadWrite": ScopeInfo("Mail.ReadWrite", ("read", "write", "delete"), True, False, "Mail.Read"),
    "Mail.Send": ScopeInfo("Mail.Send", ("send",), False, False),
    "Mail.Read": ScopeInfo("Mail.Read", ("read",), False, False),
    "Files.ReadWrite.All": ScopeInfo("Files.ReadWrite.All", ("read", "write", "delete"), True, False, "Files.Read"),
    "Files.Read.All": ScopeInfo("Files.Read.All", ("read",), True, False, "Files.Read"),
    "Sites.FullControl.All": ScopeInfo("Sites.FullControl.All", ("read", "write", "delete", "admin"), True, True, "Sites.Selected"),
    "Directory.ReadWrite.All": ScopeInfo("Directory.ReadWrite.All", ("read", "write", "delete", "admin"), True, True),
    "User.ReadWrite.All": ScopeInfo("User.ReadWrite.All", ("read", "write", "admin"), True, True),
    # GitHub
    "repo": ScopeInfo("repo", ("read", "write", "delete"), True, False, "fine-grained token scoped to one repository"),
    "admin:org": ScopeInfo("admin:org", ("admin", "write", "delete"), True, True),
    "delete_repo": ScopeInfo("delete_repo", ("delete",), True, True),
    "workflow": ScopeInfo("workflow", ("write", "execute"), True, False),
    # Slack
    "admin": ScopeInfo("admin", ("admin",), True, True),
    "chat:write": ScopeInfo("chat:write", ("send",), False, False),
}

_ADMIN_ROLE = re.compile(
    r"(?i)^(?:\*|.*:\*|all|all[_ ]privileges|admin(?:istrator)?|owner|root|superuser|db_owner|rds_superuser|"
    r"sysadmin|full[_\-]?access|full[_\-]?control|god[_\-]?mode|readwrite[_\-]?all|iam:\*|s3:\*)$"
)


def scope_info(scope: str) -> ScopeInfo | None:
    s = scope.strip()
    if s in _SCOPE_TABLE:
        return _SCOPE_TABLE[s]
    if s.startswith("https://www.googleapis.com/auth/"):
        short = s.rsplit("/", 1)[-1]
        ro = short.endswith(".readonly")
        return ScopeInfo(short, ("read",) if ro else ("read", "write"), not ro and "." not in short, False)
    if _ADMIN_ROLE.match(s):
        return ScopeInfo(s, ("read", "write", "delete", "admin"), True, True)
    low = s.lower()
    if low.endswith(".all") and "write" in low:
        return ScopeInfo(s, ("read", "write"), True, False)
    return None


def is_wildcard_or_admin(permission: str) -> bool:
    info = scope_info(permission)
    return bool(info and info.admin)


# --- network --------------------------------------------------------------------------------

KNOWN_EXFIL_SERVICES = (
    "webhook.site", "requestbin", "pipedream.net", "ngrok.io", "ngrok-free.app", "ngrok.app", "hooks.slack.com",
    "discord.com/api/webhooks", "discordapp.com/api/webhooks", "pastebin.com", "transfer.sh", "interact.sh",
    "oast.", "burpcollaborator", "requestcatcher", "beeceptor", "hookbin", "ipinfo.io", "api.telegram.org",
)
MODEL_PROVIDERS = (
    "api.openai.com", "api.anthropic.com", "generativelanguage.googleapis.com", "aiplatform.googleapis.com",
    "api.mistral.ai", "api.cohere.ai", "api.cohere.com", "openai.azure.com", "bedrock-runtime", "api.groq.com",
    "api.together.xyz", "api.deepseek.com",
)
RESERVED_TLDS = (".example", ".invalid", ".test", ".localhost", ".local", ".internal")
RESERVED_DOMAINS = ("example.com", "example.org", "example.net")
DOC_HOSTS = (
    "github.com", "www.w3.org", "json-schema.org", "schemas.", "owasp.org", "genai.owasp.org", "nist.gov",
    "atlas.mitre.org", "cwe.mitre.org", "modelcontextprotocol.io", "docs.python.org", "pypi.org",
    "npmjs.com", "www.npmjs.com", "registry.npmjs.org", "opensource.org", "creativecommons.org",
    "img.shields.io", "skills.sh", "www.skills.sh", "agentskills.io", "spdx.org", "semver.org",
    "keepachangelog.com", "readthedocs.io", "googleapis.com/auth",
)


def classify_host(url_or_host: str) -> tuple[str, str]:
    """Return (host, classification)."""
    if "://" in url_or_host:
        parsed = urlparse(url_or_host)
        host = (parsed.hostname or "").lower()
    else:
        host = url_or_host.split("/")[0].split(":")[0].lower()
    full = url_or_host.lower()
    if not host:
        return host, "unknown"
    # string comparison only (classifying a URL host), not a socket bind
    if host in ("localhost", "0.0.0.0") or host.endswith(".localhost"):  # nosec B104
        return host, "loopback"
    try:
        ip = ipaddress.ip_address(host)
        if ip.is_loopback:
            return host, "loopback"
        if ip.is_private or ip.is_link_local:
            return host, "private" if not str(ip).startswith("169.254.169.254") else "metadata_service"
        return host, "external"
    except ValueError:
        pass
    if host == "metadata.google.internal":
        return host, "metadata_service"
    if any(s in full for s in KNOWN_EXFIL_SERVICES):
        return host, "exfil_service"
    if any(host == p or host.endswith("." + p) or p in host for p in MODEL_PROVIDERS):
        return host, "model_provider"
    if host.endswith(RESERVED_TLDS) or any(host == d or host.endswith("." + d) for d in RESERVED_DOMAINS):
        return host, "reserved"
    return host, "external"


def host_matches(host: str, patterns: list[str]) -> bool:
    host = host.lower()
    for p in patterns:
        p = p.lower().strip()
        if "://" in p:
            p = urlparse(p).hostname or p
        if p.startswith("*."):
            if host == p[2:] or host.endswith(p[1:]):
                return True
        elif host == p:
            return True
    return False


def is_documentation_url(url: str) -> bool:
    low = url.lower()
    return any(h in low for h in DOC_HOSTS)
