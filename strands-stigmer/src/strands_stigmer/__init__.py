"""strands-stigmer: the execution graph of AWS for Strands agents.

Adds Stigmer's verified method contracts, traps, and least-privilege IAM
policies as Strands tools. Query before you write AWS code; generate a
least-privilege policy for a workflow; write back when you hit a trap.

Usage:
    from strands import Agent
    from strands_stigmer import stigmer_query, stigmer_policy

    agent = Agent(tools=[stigmer_query, stigmer_policy])
"""

from strands import tool

DEFAULT_URL = "https://stigmer.network/mcp"


def _mcp_call(tool_name: str, args: dict, url: str) -> str:
    """Call a hosted MCP tool via HTTP (streamable), return the text result."""
    import json
    import urllib.request

    body = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
         "params": {"name": tool_name, "arguments": args}}
    ).encode()
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read())
        content = data.get("result", {}).get("content", [])
        return content[0].get("text", "") if content else "No results."
    except Exception as e:
        return f"Stigmer {tool_name} failed: {e}"


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
    args = {"query": query}
    if library:
        args["library"] = library
    return _mcp_call("query", args, DEFAULT_URL)


@tool
def stigmer_policy(workflow: str = "", operations: str = "", description: str = "") -> str:
    """Generate a least-privilege IAM policy for an AWS workflow.

    Returns a paste-ready policy grouped by service, with a confidence tier
    and any unresolved operations. Pass exactly one of:

    Args:
        workflow: A named workflow (e.g. "s3-multipart-kms"). See
            stigmer_list_workflows for the valid names.
        operations: Explicit IAM actions or SDK symbols, comma-separated
            (e.g. "s3:PutObject,s3:GetObject").
        description: Describe the workflow (e.g. "upload a large file to S3
            with KMS encryption").

    Returns:
        JSON with provider, scope, confidence, operations, policy, unresolved.
    """
    args = {}
    if workflow:
        args["workflow"] = workflow
    if operations:
        args["operations"] = operations
    if description:
        args["description"] = description
    return _mcp_call("policy", args, DEFAULT_URL)


@tool
def stigmer_list_workflows() -> str:
    """List the curated named workflows that can generate least-privilege IAM policies.

    Returns:
        JSON array of workflow names (e.g. "s3-multipart-kms").
    """
    return _mcp_call("list_workflows", {}, DEFAULT_URL)
