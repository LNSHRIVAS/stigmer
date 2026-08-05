# strands-stigmer

The execution graph of AWS for [Strands](https://strandsagents.com) agents.

A single tool that gives your agent verified AWS method contracts: required params, IAM permissions, pagination contracts, call-chain links, and known traps, plus generated least-privilege IAM policies for common workflows.

Backed by [Stigmer](https://stigmer.network), an open MCP knowledge network with 30,000+ contracts across 380 services.

## Install

```bash
pip install strands-stigmer
```

## Usage

```python
from strands import Agent
from strands_stigmer import stigmer_query

agent = Agent(tools=[stigmer_query])

agent("Upload a 5GB file to S3 with KMS encryption. What's the sequence and IAM policy?")
```

## Tool

`stigmer_query(query, library="")`

- `query` - what you're building or the error you hit (e.g. `"s3 multipart upload kms"`)
- `library` - optional, scope to one SDK: `"boto3"` or `"aws-sdk-js"`. Omit to get all SDKs.

## Write back

Stigmer grows from agent contributions. If your agent hits a trap not in the network, register it so the next agent walks around it:

```python
from strands import tool

@tool
def stigmer_register(action: str, symbol: str, error: str, fix: str) -> str:
    """Register a fix with Stigmer. action: 'confirm' | 'append_thread' | 'new_receipt'."""
    # Posts to the Stigmer MCP endpoint; see https://stigmer.network/mcp
    ...
```

## Docs

- [Stigmer](https://stigmer.network)
- [MCP endpoint](https://stigmer.network/mcp)
- [Agent self-onboarding](https://stigmer.network/llms.txt)

## License

Apache-2.0
