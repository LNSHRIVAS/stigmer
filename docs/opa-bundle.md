# Stigmer OPA bundle: the permission map as data

Stigmer publishes the operation-to-required-IAM-action map as an **OPA bundle**.
Any OPA instance subscribes with one config entry and gets the map
automatically, refreshed on every poll. The map is data, not policy: OPA
already knows how to enforce; Stigmer supplies what it should say.

## Endpoint

```
https://stigmer.network/opa/bundle.tar.gz
```

Served per the OPA Bundle Service API: gzipped tarball, `Content-Type:
application/gzip`, `ETag` header, `304 Not Modified` on `If-None-Match`.

Public verification key (RS256):

```
https://stigmer.network/opa/signing.pub
```

## Subscribe (one config entry)

```yaml
services:
  stigmer:
    url: https://stigmer.network/opa
keys:
  stigmer_key:
    algorithm: RS256
    key: |            # from https://stigmer.network/opa/signing.pub
      -----BEGIN PUBLIC KEY-----
      ...
      -----END PUBLIC KEY-----
    scope: read
bundles:
  stigmer:
    service: stigmer
    resource: bundle.tar.gz
    signing:
      keyid: stigmer_key
      scope: read
```

OPA polls, verifies the signature, and activates the bundle. No restart
required; updates arrive on the next poll.

## What's in the bundle

```
.manifest               # revision + roots: ["stigmer"]
.signatures.json        # RS256 over each file's SHA-256
stigmer/
  operations/data.json  # { "s3.PutObject": ["s3:PutObject"], ... }  19,117 operations
  workflows/data.json   # { "s3-multipart-kms": [...], ... }         17 curated workflows
  policy.rego           # package stigmer.policy
```

## The rule

```rego
package stigmer.policy

# resolve_actions(op) -> the IAM actions an operation requires
default resolve_actions(_op) := []
resolve_actions(op) := data.stigmer.operations[op] if data.stigmer.operations[op]

# has_required(op, granted) -> true when granted covers every required action
has_required(op, granted) if {
    required := resolve_actions(op)
    count(required) > 0
    every_action_covered(required, granted)
}

every_action_covered(required, granted) if {
    action := required[_]
    granted[action]
}

# workflow_actions(name) -> the curated workflow's actions
default workflow_actions(_name) := []
workflow_actions(name) := data.stigmer.workflows[name] if data.stigmer.workflows[name]
```

## Use it as the per-invocation check

In the InfoQ agent-gateway pattern, the gateway authorizes every tool call
through OPA before execution. Feed the agent's granted actions as input and
gate on `has_required`:

```rego
import future.keywords.in

# The gateway's decision: allow the tool call only if the agent's current
# role is permitted to run the exact operation it requested.
allow if {
    input.method == "tools/call"
    operation := operation_for(input.tool)
    granted := agent_actions(input.agent_id)   # resolved by the gateway
    data.stigmer.policy.has_required(operation, granted)
}

operation_for(tool_use) := symbol if {
    some k in ["service_name", "operation_name"]
    symbol := sprintf("%s.%s", [tool_use[k], camel(tool_use[k2])])
}
```

## Verify it works

```bash
opa eval -b bundle.tar.gz \
  'data.stigmer.policy.resolve_actions("s3.PutObject")' --format=raw
# ["s3:PutObject"]

opa eval -b bundle.tar.gz \
  'data.stigmer.policy.has_required("s3.PutObject", {"s3:PutObject"})' --format=raw
# true

opa eval -b bundle.tar.gz \
  'data.stigmer.policy.has_required("s3.PutObject", {"s3:GetObject"})' --format=raw
# (empty = false)

opa eval -b bundle.tar.gz \
  'data.stigmer.policy.workflow_actions("s3-multipart-kms")' --format=raw
# ["s3:CreateMultipartUpload","s3:UploadPart","s3:CompleteMultipartUpload",...]
```

## Who this serves

- **Gatekeeper** (Kubernetes admission) - same bundle contract
- **Conftest** (evaluate Terraform plan JSON in CI) - `conftest test --policy bundle.tar.gz`
- **OPAL** - tracks a bundle server, pushes decisions to deployed agents
- **Agent gateways** - the MCP/OPA/ephemeral-runner pattern from the InfoQ
  reference architecture; this is the "what should the policy say" input
  that hand-written `allow_actor` maps leave empty

## Why operation-level

Prospective policy generation is not new. Salesforce's `policy_sentry`
creates least-privilege policies from access levels and resource ARNs, and
AWS IAM Access Analyzer infers them retrospectively from CloudTrail over a
time window (`start_policy_generation`). Both are mature tools for a human
authoring a policy ahead of time.

Neither takes an *operation* as the input. An agent knows the API call it is
about to make (`s3.PutObject`), not an abstract CRUD level it wants. Stigmer's
map is keyed to the operation, derived from machine-readable service
definitions, so it is available before the first call and stays current as
the services change.
