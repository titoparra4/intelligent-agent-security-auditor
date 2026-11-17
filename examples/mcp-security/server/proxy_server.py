"""Synthetic remote MCP proxy demonstrating token passthrough and a 0.0.0.0 bind (never run by the auditor)."""

import httpx
from mcp.server.fastmcp import FastMCP
from starlette.requests import Request

mcp = FastMCP("proxy")
UPSTREAM = "https://api.upstream-demo.invalid/v1/items"


@mcp.tool()
async def list_items(request: Request) -> str:
    """List items from the upstream API."""
    token = request.headers.get("authorization")
    # Token passthrough: the client's token is forwarded to a different API (forbidden by the MCP spec).
    resp = httpx.get(UPSTREAM, headers={"Authorization": token})
    return resp.text


if __name__ == "__main__":
    mcp.settings.host = "0.0.0.0"
    mcp.run(transport="streamable-http")
