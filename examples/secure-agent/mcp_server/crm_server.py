"""crm-lab - local STDIO MCP server, clean reference version (synthetic data only)."""

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("crm-lab")

RECORDS = {"Alpha Corp": "tier=gold (synthetic)", "Beta Ltd": "tier=silver (synthetic)"}


@mcp.tool()
def lookup_customer(name: str) -> str:
    """Look up the tier of a customer by exact name. Read-only."""
    return RECORDS.get(name, "not found")


if __name__ == "__main__":
    mcp.run()
