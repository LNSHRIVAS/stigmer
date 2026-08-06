# strands-stigmer

The execution graph of AWS for [Strands](https://strandsagents.com) agents.

A single toolset that gives your agent verified AWS method contracts (required params, IAM permissions, pagination contracts, call-chain links, and known traps), a **least-privilege IAM policy generator** for multi-step workflows, a **pre-flight authorization check** that asks AWS's own policy simulator whether an operation is allowed before it executes, and a **pre-action authorization hook** that blocks denied tool calls before they run.

Backed by [Stigmer](https://stigmer.network), an open MCP knowledge network with 30,000+ contracts across 380 services.

## Install

```bash
pip install strands-stigmer
```

## Usage

```python
from strands import Agent
from strands_stigmer import stigmer_query, stigmer_policy, stigmer_authorize
from strands_stigmer.hooks import StigmerAuthHook

agent = Agent(
    tools=[stigmer_query, stigmer_policy, stigmer_authorize],
    hooks=[StigmerAuthHook()],
)

# Generate a least-privilege IAM policy for a workflow
agent("Generate the least-privilege policy for an S3 multipart upload with KMS encryption")

# Pre-flight check: is s3:PutObject allowed for the current role?
agent("Before you call S3, check whether I'm authorized to put objects")
```

Every `use_aws` tool call is now checked before execution. If AWS's own policy simulator reports the current identity is denied, the call is cancelled with the missing permissions listed. When the simulator cannot answer (`unknown`), the call passes through by default; pass `StigmerAuthHook(fail_closed=True)` to block unverifiable calls too.

## Tools

`stigmer_policy(workflow="", operations="", description="")`
- Generate a least-privilege IAM policy. Pass one of:
  - `workflow` - a named workflow (see `stigmer_list_workflows`)
  - `operations` - explicit IAM actions or SDK symbols, comma-separated
  - `description` - describe the workflow in plain language
- Returns: paste-ready policy grouped by service, with confidence tier and any unresolved operations

`stigmer_authorize(operations="", workflow="", principal_arn="")`
- Pre-flight authorization check. Resolves the IAM actions an operation requires, then asks AWS's own policy simulator (`SimulatePrincipalPolicy`) whether the current role (or a given principal) allows them
- Returns `resolution` (exact|partial|unresolved) and `evaluation` (allowed|denied|unknown) as separate fields, plus `missing_permissions` and the simulator's documented caveats
- `evaluation` is populated only when the calling environment has AWS credentials; otherwise it is `unknown` with the reason

`stigmer_verify(workflow="", operations="", policy="")`
- Feed a generated policy back to AWS's own evaluator (`SimulateCustomPolicy`) and confirm it grants exactly the intended operations and nothing extra
- Returns `verified` (True|False|unknown), `grants_all`, and `grants_extra`
- `verified` is populated only when the calling environment has AWS credentials

`stigmer_list_workflows()`
- List the curated named workflows available for policy generation

`stigmer_query(query, library="")`
- Search verified method contracts: required params, IAM permissions, pagination contract, call-chain links, and known traps
- `library` scopes to one SDK: `"boto3"` or `"aws-sdk-js"`

`StigmerAuthHook(fail_closed=False)`
- A `BeforeToolCallEvent` hook that authorizes AWS tool calls before they execute
- For each `use_aws` call, resolves the operation to its required IAM actions and asks AWS's own simulator whether the current identity allows them
- `evaluation: denied` cancels the call and lists the missing permissions; `allowed` passes through; `unknown` passes through by default, or blocks when `fail_closed=True`
- Covers any tool, not just `use_aws`; no upstream changes or approval required

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
