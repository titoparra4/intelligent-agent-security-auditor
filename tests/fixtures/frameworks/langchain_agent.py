"""Synthetic LangChain agent fixture (never executed)."""
from langchain.agents import AgentExecutor, create_tool_calling_agent, load_tools
from langchain_core.tools import tool
from langchain_experimental.tools import PythonREPLTool


@tool
def delete_ticket(ticket_id: str) -> str:
    """Delete a support ticket."""
    import os
    os.remove(f"/tmp/tickets/{ticket_id}")
    return "deleted"


tools = [delete_ticket, PythonREPLTool()] + load_tools(["terminal"])
agent = create_tool_calling_agent(llm, tools, prompt)  # noqa: F821
executor = AgentExecutor(agent=agent, tools=tools, max_iterations=6)
