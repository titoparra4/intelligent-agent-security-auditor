"""enterprise-assistant-secure - reference implementation of the lab agent with controls applied.

Synthetic example: every backend is simulated and analysed statically by the auditor; this file
is never imported or executed by the auditor.

Controls demonstrated (compare with ../vulnerable-agent-lab/src/agent.py):
* least-privilege OAuth scopes (gmail.readonly, drive.readonly);
* tool output wrapped as untrusted data (spotlighting) before it reaches the model;
* egress only to an allowlisted internal endpoint, behind a human-approval gate enforced in code;
* tenant-scoped CRM queries bound to the authenticated user;
* explicit max_turns; metadata-only logging.
"""

import logging
import os

import requests
from agents import Agent, Runner, function_tool
from google.oauth2 import service_account

from lab_simulated import ApprovalDenied, approval_service, crm_db, current_user, drive_client, gmail_client, load_prompt

logger = logging.getLogger("enterprise-assistant-secure")

GMAIL_SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]
DRIVE_SCOPES = ["https://www.googleapis.com/auth/drive.readonly"]
REPORTS_ENDPOINT = "https://reports.internal.example/ingest"


def wrap_untrusted(source: str, text: str) -> str:
    """Spotlight external content so the model treats it as data, never as instructions."""
    cleaned = text.replace("<untrusted_content", "&lt;untrusted_content")
    return f'<untrusted_content source="{source}">\n{cleaned}\n</untrusted_content>'


def require_approval(action: str, details: dict) -> None:
    """Blocking human approval enforced by the application, independent of the model."""
    if not approval_service().request(action=action, details=details, requester=current_user().id):
        raise ApprovalDenied(action)


@function_tool
def gmail_read_inbox(max_results: int = 10) -> str:
    """Read the latest emails from the user's inbox (simulated Gmail)."""
    creds = service_account.Credentials.from_service_account_file(os.getenv("GMAIL_SA_FILE"), scopes=GMAIL_SCOPES)
    messages = gmail_client(creds).list_messages(max_results)
    logger.info("tool=gmail_read_inbox count=%d", len(messages))
    return "\n\n".join(wrap_untrusted("email", m["body"]) for m in messages)


@function_tool
def drive_search(query: str) -> str:
    """Search documents in Drive (simulated Drive)."""
    creds = service_account.Credentials.from_service_account_file(os.getenv("DRIVE_SA_FILE"), scopes=DRIVE_SCOPES)
    return wrap_untrusted("drive", drive_client(creds).search(query))


@function_tool
def crm_lookup(customer_name: str) -> str:
    """Look up customer records of the caller's tenant (simulated CRM)."""
    tenant = current_user().tenant_id
    rows = crm_db().execute("SELECT name, tier FROM customers WHERE tenant_id = %s AND name LIKE %s",
                            (tenant, f"%{customer_name}%"))
    return wrap_untrusted("crm", str(rows))


@function_tool
def send_usage_report(summary: str) -> str:
    """Send a usage summary to the internal reporting service after human approval."""
    require_approval("send_usage_report", {"destination": REPORTS_ENDPOINT, "summary": summary[:500]})
    requests.post(REPORTS_ENDPOINT, json={"summary": summary}, timeout=5)
    logger.info("tool=send_usage_report status=sent")
    return "sent"


assistant = Agent(
    name="enterprise-assistant-secure",
    model="gpt-4.1",
    instructions=load_prompt("prompts/system.md"),
    tools=[gmail_read_inbox, drive_search, crm_lookup, send_usage_report],
)


def handle(task: str) -> str:
    return Runner.run_sync(assistant, task, max_turns=8).final_output
