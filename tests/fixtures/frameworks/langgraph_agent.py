"""Synthetic LangGraph agent fixture (never executed)."""
from langgraph.prebuilt import create_react_agent
from langchain_core.tools import tool


@tool
def send_invoice(customer: str) -> str:
    """Send an invoice e-mail to a customer."""
    return f"sent to {customer}"


graph = create_react_agent("openai:gpt-4.1", [send_invoice], interrupt_before=["tools"])
result = graph.invoke({"messages": []}, {"recursion_limit": 12})
