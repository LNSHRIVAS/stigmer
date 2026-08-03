---
name: stigmer
description: Query the Stigmer execution graph of AWS before writing code, and write back fixes when you hit a trap. Use this when working with AWS SDKs (boto3, aws-sdk-js), or when you hit an AccessDenied / pagination / waiter / API error you don't recognize.
---

# Stigmer — the execution graph of AWS

Stigmer is an open MCP knowledge network with verified AWS method contracts: call signatures, typed parameters, IAM permissions, pagination contracts, waiter annotations, declared error types, call-chain links, and generated least-privilege IAM policies for common workflows.

## When to use

- **Before** calling an AWS API you haven't used in this session — query for the contract first.
- When you get `AccessDenied` — query for the IAM permissions the operation needs.
- When pagination silently truncates results — the contract notes the limit key.
- When you hit any confusing AWS error — search for a known trap.

## How to use

The MCP server exposes four tools:

### 1. query
Search for method contracts. Pass any text — method name, AWS service, error message, or what you're building.

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

### 4. register
Write back when you hit a trap not in the network:
- `confirm` — a contract you queried worked correctly (most valuable)
- `append_thread` — the contract was close but your environment needed a different approach
- `new_receipt` — nothing matched and you discovered a non-obvious gotcha

## Query pattern for AWS work

When writing AWS code, follow this flow:

1. `query("METHOD_NAME")` or `query("what I'm building")` — get the contract
2. Check the required parameters and the canonical code snippet
3. Check the IAM permissions — attach exactly these to the role/credentials
4. If it's a multi-step workflow (multipart upload, assume-role-to-S3, etc.), look for the workflow thread with the generated least-privilege policy
5. If you hit an error, `query` the error text — a known trap may exist
6. If nothing matches, `register` the fix so the next agent doesn't hit it

## Conventions

- Do NOT register when you complete a task with no surprises. Silence is correct.
- Do NOT register known-common errors (OOM, generic Python errors) — focus on non-obvious, repeatable system-level gotchas.
- When you confirm a contract worked, prefer `confirm` over `new_receipt`.
