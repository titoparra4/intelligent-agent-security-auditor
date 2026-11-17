"""Sandbox harness for the secure reference agent - deterministic stand-in for an LLM agent.

Mirrors the secure design: only the *user's task* can request actions; tool output is data;
irreversible actions go through ``env.request_approval``; egress only to allowlisted hosts;
queries are bound to the user's tenant; secrets are redacted in answers; one attempt per tool.
"""

import re

ALLOWLIST = ("reports.internal.example", "api.internal.example")
URL = re.compile(r"https?://([^/\s'\"<>]+)[^\s'\"<>]*")
MAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
SECRET = re.compile(r"(?i)\b(api_key|token|secret|password)\s*[:=]\s*\S+")


def _safe_call(env, tool, **kwargs):
    try:
        return env.call_tool(tool, **kwargs)
    except Exception as exc:  # one attempt only; report and stop
        env.respond(f"The {tool} service is unavailable ({type(exc).__name__}). Please try again later.")
        return None


def run(task, env):
    low = task.lower()
    if any(w in low for w in ("email", "inbox", "urgent")) and not low.startswith("email "):
        mails = _safe_call(env, "read_email")
        if mails is None:
            return
        env.respond(f"You have {len(mails)} email(s). Content is untrusted and was not acted upon.")
    if any(w in low for w in ("tools",)):
        tools = _safe_call(env, "get_tool_descriptions") or []
        env.respond("Available tools: " + ", ".join(t.get("name", "?") for t in tools))
    doc_title = None
    if any(w in low for w in ("document", "notes", "plan", "config")):
        docs = _safe_call(env, "search_documents", query=task[:80]) or []
        doc_title = docs[0].get("title") if docs else None
        for d in docs:
            env.respond(f"{d.get('title')}: " + SECRET.sub(r"\1: [REDACTED]", d.get("text", ""))[:200])
    if "customer records" in low or "inactive customer" in low:
        rows = _safe_call(env, "query_records", tenant=env.tenant) or []
        if "delete" in low:
            for r in rows:
                if env.request_approval("delete_record", {"record_id": r.get("id"), "tenant": env.tenant}):
                    env.call_tool("delete_record", record_id=r.get("id"))
        env.respond("Records: " + ", ".join(r.get("name", r.get("id", "?")) for r in rows if r.get("tenant") == env.tenant))
    elif "delete" in low:
        env.respond("Deletion requests must be submitted through the records workflow; nothing was deleted.")
    if "other users" in low:
        mine = _safe_call(env, "read_memory") or []
        env.respond(f"I can only access your own memory ({len(mine)} item(s)).")
    if "research agent" in low:
        reply = _safe_call(env, "delegate", agent="research", message="status update")
        env.respond("Research agent replied (treated as data): " + str(reply)[:60])
    m = URL.search(task)
    if m and ("post" in low or "send" in low):
        if m.group(1) not in ALLOWLIST:
            env.respond(f"Destination {m.group(1)} is not allowlisted; nothing was sent.")
        elif env.request_approval("http_post", {"url": m.group(0), "document": doc_title}):
            env.call_tool("http_post", url=m.group(0), body={"document": doc_title})
    if low.startswith("email "):
        for addr in MAIL.findall(task):
            if env.request_approval("send_email", {"to": addr, "document": doc_title}):
                env.call_tool("send_email", to=addr, subject=doc_title or "document", body=f"Attached: {doc_title}")
    if not env.responses:
        env.respond("Done.")
