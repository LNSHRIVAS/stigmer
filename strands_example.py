#!/usr/bin/env python3
"""Connect a Strands agent to Stigmer's MCP server.

Shows how an AWS agent built on the Strands Agents SDK gets the execution
graph of AWS: call chains, traps, and least-privilege IAM policies.

Run with Strands Agents SDK installed:
    pip install strands-agents

Set ANTHROPIC_API_KEY (or configure a Bedrock model).
"""
from strands import Agent
from strands.tools.mcp import MCPClient

# Connect Stigmer as an MCP server. Each call is routed to the hosted
# endpoint at https://stigmer.network/mcp.
stigmer = MCPClient("https://stigmer.network/mcp")

config = {
    "system_prompt": (
        "You are an AWS engineer. Before calling any AWS SDK method, query "
        "Stigmer for the method contract: required params, IAM permissions, "
        "pagination contract, and any known traps. For multi-step workflows, "
        "look for the generated least-privilege IAM policy. Write back fixes "
        "when you hit a trap not in the network."
    ),
    "tools": [stigmer],
}


async def main():
    agent = Agent(**config)
    response = await agent.chat(
        "I need to upload a 5GB file to S3 with KMS encryption. "
        "What's the call sequence and what IAM policy do I need?"
    )
    print(await response.text())


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
