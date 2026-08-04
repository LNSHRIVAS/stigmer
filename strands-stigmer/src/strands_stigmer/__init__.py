"""strands-stigmer: the execution graph of AWS for Strands agents.

Adds Stigmer's verified method contracts, traps, and least-privilege IAM
policies as a Strands tool. Query before you write AWS code; write back
when you hit a trap.

Usage:
    from strands import Agent
    from strands_stigmer import stigmer_query

    agent = Agent(tools=[stigmer_query])
"""

from strands import tool

DEFAULT_URL = "https://stigmer.network/mcp"


@tool
def stigmer_query(query: str, library: str = "") -> str:
    """Query the Stigmer execution graph of AWS.

    Returns verified method contracts: required params, IAM permissions,
    pagination contract, call-chain links, and known traps.

    Args:
        query: What you're building or the error you hit.
            e.g. "s3 multipart upload kms", "dynamodb query pagination"
        library: Optional. Scope to one SDK: "boto3" or "aws-sdk-js".
            Omit to get all SDKs for the named service.

    Returns:
        Matching contracts as JSON text, or a hint if nothing matched.
    """
    try:
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client
        from contextlib import AsyncExitStack
    except ImportError as e:
        return f"Missing dependency: {e}. Run: pip install mcp"

    return _mcp_query(query, library, DEFAULT_URL)


def _mcp_query(query: str, library: str, url: str) -> str:
    """Thin wrapper around the hosted MCP endpoint via HTTP (streamable)."""
    import json
    import urllib.request

    args = {"query": query}
    if library:
        args["library"] = library

    body = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
         "params": {"name": "query", "arguments": args}}
    ).encode()
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read())
        content = data.get("result", {}).get("content", [])
        return content[0].get("text", "") if content else "No results."
    except Exception as e:
        return f"Stigmer query failed: {e}"
