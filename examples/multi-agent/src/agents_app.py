"""Synthetic multi-agent system (OpenAI Agents SDK style) - INTENTIONALLY INSECURE example.

Never executed by the auditor. Demonstrates: privilege escalation through delegation (an agent
exposed to untrusted email can hand off to an agent holding a payment tool), a delegation cycle
without a turn limit, and an irreversible financial tool without approval.
"""

from agents import Agent, Runner, function_tool

from demo_backends import inbox, payments, wiki  # simulated backends (not provided)


@function_tool
def read_support_inbox() -> str:
    """Read customer support emails (external, untrusted)."""
    return "\n".join(m.body for m in inbox.latest(20))


@function_tool
def transfer_funds(iban: str, amount_eur: float) -> str:
    """Transfer money to a bank account (simulated payments API)."""
    return payments.transfer(iban=iban, amount=amount_eur)


@function_tool
def search_wiki(query: str) -> str:
    """Search the internal wiki."""
    return wiki.search(query)


finance_agent = Agent(name="finance-agent", instructions="You execute refunds and payouts.", tools=[transfer_funds])
research_agent = Agent(name="research-agent", instructions="You research topics.", tools=[search_wiki])
writer_agent = Agent(name="writer-agent", instructions="You write answers.", tools=[], handoffs=[research_agent])
research_agent.handoffs = [writer_agent]  # (dynamic assignment - not resolved statically; see manifest)

triage_agent = Agent(
    name="triage-agent",
    instructions="Read the support inbox and route requests to the right specialist.",
    tools=[read_support_inbox],
    handoffs=[finance_agent, writer_agent],
)


def handle(task: str) -> str:
    return Runner.run_sync(triage_agent, task).final_output
