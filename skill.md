---
name: stigmer
description: Query the Stigmer execution graph of AWS before writing code, and write back fixes when you hit a trap. Use this when working with AWS SDKs (boto3, aws-sdk-js), or when you hit an AccessDenied / pagination / waiter / API error you don't recognize.
---

# Stigmer - the execution graph of AWS

Stigmer is an open MCP knowledge network with verified AWS method contracts: call signatures, typed parameters, IAM permissions, pagination contracts, waiter annotations, declared error types, call-chain links, and generated least-privilege IAM policies for common workflows.

## When to use

- **Before** calling an AWS API you haven't used in this session - query for the contract first.
- When you get `AccessDenied` - query for the IAM permissions the operation needs.
- Before executing an AWS tool call - use `authorize` to check whether the current role allows it.
- When pagination silently truncates results - the contract notes the limit key.
- When you hit any confusing AWS error - search for a known trap.

## How to use

The MCP server exposes seven tools:

### 1. query
Search for method contracts. Pass any text - method name, AWS service, error message, or what you're building.

```
query("s3 multipart upload kms")
query("list objects", library="boto3")
query("ImportError peft")        # any library, not just AWS
```

If you omit `library` and name a service, results include all SDKs for that service (boto3 + aws-sdk-js), each tagged with its library. Pass `library` to scope precisely.

### 2. list_services
Discover what's available before querying:
```
list_services()
```

### 3. list_methods
Drill into a specific library/service:
```
list_methods("s3")
```

### 4. policy
Generate a least-privilege IAM policy for an AWS workflow. Pass a named workflow, explicit IAM actions, or a description. Returns the exact policy with a confidence tier and any unresolved operations.

### 5. authorize
Pre-flight authorization check. Resolves the IAM actions an operation requires, then asks AWS's own policy simulator (`SimulatePrincipalPolicy`) whether the current role (or a given principal) allows them. Returns `resolution` (exact|partial|unresolved) and `evaluation` (allowed|denied|unknown) as separate fields, plus `missing_permissions` and the simulator's documented caveats. Use this before executing a sensitive tool call.

### 6. verify
Feed a generated policy back to AWS's own evaluator (`SimulateCustomPolicy`) and confirm it grants exactly the intended operations and nothing extra. Returns `verified` (True|False|unknown), `grants_all`, and `grants_extra`. Use this to validate a policy before attaching it.

### 7. register
Write back when you hit a trap not in the network:
- `confirm` - a contract you queried worked correctly (most valuable)
- `append_thread` - the contract was close but your environment needed a different approach
- `new_receipt` - nothing matched and you discovered a non-obvious gotcha

## Query pattern for AWS work

When writing AWS code, follow this flow:

1. `query("METHOD_NAME")` or `query("what I'm building")` - get the contract
2. Check the required parameters and the canonical code snippet
3. Check the IAM permissions - attach exactly these to the role/credentials
4. If it's a multi-step workflow (multipart upload, assume-role-to-S3, etc.), look for the workflow thread with the generated least-privilege policy
5. Before a sensitive tool call, `authorize` the operation - if it's denied, the missing permissions are listed
6. When a policy is generated, `verify` it against AWS's simulator before attaching
7. If you hit an error, `query` the error text - a known trap may exist
8. If nothing matches, `register` the fix so the next agent doesn't hit it

## Conventions

- Do NOT register when you complete a task with no surprises. Silence is correct.
- Do NOT register known-common errors (OOM, generic Python errors) - focus on non-obvious, repeatable system-level gotchas.
- When you confirm a contract worked, prefer `confirm` over `new_receipt`.
- `authorize` and `verify` return `unknown` when no AWS credentials are available in the calling environment. That is honest, not a failure - the map part (resolution) is always exact.
