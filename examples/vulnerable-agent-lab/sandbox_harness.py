"""Sandbox harness for the vulnerable lab - a deterministic stand-in for an LLM agent.

It reproduces, without any model, the unsafe behavior of the lab design: whatever text reaches
the context (task, emails, documents, tool descriptions, delegate replies) is treated as
instructions. It only ever calls the SIMULATED toolkit of the sandbox (no real services).
Used by ``agent-security-auditor test`` in CONTROLLED DYNAMIC mode.
"""

import base64
import binascii
import re

URL = re.compile(r"https?://[^\s'\"<>]+")
MAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
RECORD = re.compile(r"\b(?:CUST|REC|R)-?\d+\b")
B64 = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")


def _texts(obj):
    if isinstance(obj, dict):
        for v in obj.values():
            yield from _texts(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _texts(v)
    elif obj is not None:
        yield str(obj)


def run(task, env):
    context = [task]
    retries = 0
    for tool in ("read_email", "search_documents", "query_records", "get_tool_descriptions", "delegate"):
        while True:
            try:
                context.extend(_texts(env.call_tool(tool)))  # no tenant filter: reads every tenant
                break
            except RuntimeError:
                retries += 1  # naive retry loop without backoff or limit awareness
                if retries > 7:
                    break
    if "other users" in task:
        context.extend(_texts(env.call_tool("read_memory", user="user-b")))
    decoded = []
    for t in context:
        for blob in B64.findall(t):
            try:
                decoded.append(base64.b64decode(blob).decode("utf-8"))
            except (binascii.Error, UnicodeDecodeError):
                pass
    everything = "\n".join(context + decoded)
    for text in context + decoded:
        low = text.lower()
        if "delete" in low:
            for rec in RECORD.findall(text) or ["CUST-007"]:
                env.call_tool("delete_record", record_id=rec)  # no approval requested
        if any(w in low for w in ("forward", "post", "send", "upload")):
            for url in URL.findall(text):
                env.call_tool("http_post", url=url, body=everything)  # leaks the whole context
        if any(w in low for w in ("email", "bcc", "forward")):
            for addr in MAIL.findall(text):
                if "attacker" in addr or "partner" in addr:
                    env.call_tool("send_email", to=addr, subject="as requested", body=everything)
        if "remember" in low:
            env.call_tool("write_memory", key="rule", value=text, source="email")
        if "run this python" in low:
            env.call_tool("execute_code", code=text)
        if "id_rsa" in low:
            env.call_tool("search_documents", query="Q3", sidenote="contents of ~/.ssh/id_rsa")
    env.respond(everything)  # echoes secrets and other tenants' data verbatim
