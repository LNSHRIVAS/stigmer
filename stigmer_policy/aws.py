"""AWS provider module: the four verbs of the Stigmer policy engine.

    resolve(operation) -> required_permissions     (Stigmer's data, offline)
    check(permissions) -> verdict                  (SimulatePrincipalPolicy)
    generate(inputs) -> policy                     (Stigmer's composition, offline)
    verify(policy, operations) -> verdict          (SimulateCustomPolicy)

resolve and generate are pure data operations that never touch AWS.
check and verify delegate to AWS's own policy evaluation engine and require
boto3 credentials. Without them they return evaluation=unknown / verified=unknown
with a reason, never a fabricated allow or deny.

Response contract (locked):
    {
      "provider": "aws",
      "format": "aws-iam-policy-v1",
      "scope": "action-only",
      "confidence": "verified" | "explicit" | "resolved",
      "operations": ["s3:PutObject"],
      "policy": { ... multi-statement, grouped by service ... },
      "unresolved": []
    }
"""
from __future__ import annotations

import json
import os
import re
import fnmatch
from collections import defaultdict

from . import contract

PROVIDER = "aws"

IAM_MAP_PATH = os.environ.get("STIGMER_IAM_MAP", "/usr/local/bin/iam_map.json")

# Documented caveats for the AWS policy simulator, cited verbatim (see
# https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_testing-policies.html).
# The evaluation:unknown state is exactly the space AWS says the simulator
# does not cover. These are returned with every check/verify result.
SIMULATOR_CAVEATS = [
    "The policy simulator results can differ from your live AWS environment.",
    "The simulator evaluates SCPs including condition keys, but does not support "
    "resource control policies (RCPs).",
    "Results can differ for VPC endpoint policies, role chaining, or multiple "
    "resource-based policies on a single resource.",
    "Resource-based policy simulation is not supported for IAM roles.",
]

# ---------------------------------------------------------------------------
# Curated workflows (verified tier) - hand-checked, golden-file snapshotted.
# Each entry: name -> {"title", "sequence": [IAM action strings]}
# ---------------------------------------------------------------------------
CURATED_WORKFLOWS = {
    "s3-multipart-upload": {
        "title": "S3 multipart upload",
        "actions": ["s3:CreateMultipartUpload", "s3:UploadPart", "s3:CompleteMultipartUpload"],
    },
    "s3-multipart-kms": {
        "title": "S3 multipart upload with KMS encryption",
        "actions": [
            "s3:CreateMultipartUpload", "s3:UploadPart", "s3:CompleteMultipartUpload",
            "kms:GenerateDataKey", "kms:Decrypt",
        ],
    },
    "lambda-create-invoke": {
        "title": "Lambda create and invoke",
        "actions": ["lambda:CreateFunction", "lambda:InvokeFunction", "iam:PassRole"],
    },
    "sqs-send-receive": {
        "title": "SQS send and receive messages",
        "actions": ["sqs:CreateQueue", "sqs:SendMessage", "sqs:ReceiveMessage", "sqs:DeleteMessage"],
    },
    "assume-role-s3": {
        "title": "Assume role then access S3",
        "actions": ["sts:AssumeRole", "s3:ListBucket"],
    },
    "dynamodb-table-crud": {
        "title": "DynamoDB create table and CRUD",
        "actions": ["dynamodb:CreateTable", "dynamodb:PutItem", "dynamodb:GetItem", "dynamodb:DescribeTable"],
    },
    "ec2-launch-describe": {
        "title": "EC2 launch and describe instances",
        "actions": ["ec2:RunInstances", "ec2:DescribeInstances", "iam:PassRole"],
    },
    "ec2-security-group-launch": {
        "title": "EC2 security group then launch instance",
        "actions": ["ec2:CreateSecurityGroup", "ec2:AuthorizeSecurityGroupIngress", "ec2:RunInstances", "ec2:DescribeInstances"],
    },
    "s3-website": {
        "title": "S3 static website hosting",
        "actions": ["s3:CreateBucket", "s3:PutBucketWebsite", "s3:PutBucketPolicy", "s3:PutObject"],
    },
    "iam-role-policy": {
        "title": "IAM create role and attach policy",
        "actions": ["iam:CreateRole", "iam:CreatePolicy", "iam:AttachRolePolicy", "iam:PassRole"],
    },
    "rds-create-db": {
        "title": "RDS create database instance",
        "actions": ["rds:CreateDBInstance", "rds:DescribeDBInstances"],
    },
    "sns-publish-topic": {
        "title": "SNS create topic and publish",
        "actions": ["sns:CreateTopic", "sns:Publish"],
    },
    "cloudwatch-metric-alarm": {
        "title": "CloudWatch metric and alarm",
        "actions": ["cloudwatch:PutMetricData", "cloudwatch:PutMetricAlarm"],
    },
    "cognito-auth-flow": {
        "title": "Cognito user signup and auth flow",
        "actions": ["cognito-idp:SignUp", "cognito-idp:AdminConfirmSignUp", "cognito-idp:AdminInitiateAuth"],
    },
    "kinesis-stream-put": {
        "title": "Kinesis create stream and put records",
        "actions": ["kinesis:CreateStream", "kinesis:DescribeStream", "kinesis:PutRecord"],
    },
    "stepfunctions-execute": {
        "title": "Step Functions create and execute state machine",
        "actions": ["states:CreateStateMachine", "states:StartExecution", "states:DescribeExecution"],
    },
    "secretsmanager-rotate": {
        "title": "Secrets Manager create and rotate secret",
        "actions": ["secretsmanager:CreateSecret", "secretsmanager:GetSecretValue", "secretsmanager:RotateSecret"],
    },
}

# High-confidence chain edges for the resolved tier. Only these edges may
# contribute actions. Anything reached otherwise goes to unresolved.
# (symbol) -> (service, operation) -> actions resolved via iam-dataset.
RESOLVED_CHAIN_EDGES = {
    "s3.CreateMultipartUpload": ["s3.UploadPart", "s3.CompleteMultipartUpload"],
    "s3.CreateBucket": ["s3.PutBucketWebsite", "s3.PutBucketPolicy", "s3.PutObject"],
    "lambda.CreateFunction": ["lambda.Invoke"],
    "sqs.CreateQueue": ["sqs.SendMessage", "sqs.ReceiveMessage", "sqs.DeleteMessage"],
    "dynamodb.CreateTable": ["dynamodb.PutItem", "dynamodb.GetItem"],
    "sts.AssumeRole": ["s3.ListObjectsV2"],
    "kinesis.CreateStream": ["kinesis.DescribeStream", "kinesis.PutRecord"],
    "stepfunctions.CreateStateMachine": ["stepfunctions.StartExecution", "stepfunctions.DescribeExecution"],
    "secretsmanager.CreateSecret": ["secretsmanager.GetSecretValue", "secretsmanager.RotateSecret"],
    "sns.CreateTopic": ["sns.Publish"],
    "cloudwatch.PutMetricData": ["cloudwatch.PutMetricAlarm"],
    "ec2.CreateSecurityGroup": ["ec2.AuthorizeSecurityGroupIngress", "ec2.RunInstances"],
    "iam.CreateRole": ["iam.CreatePolicy", "iam.AttachRolePolicy"],
    "cognito-idp.SignUp": ["cognito-idp.AdminConfirmSignUp", "cognito-idp.AdminInitiateAuth"],
}

# ---------------------------------------------------------------------------
# IAM map cache
# ---------------------------------------------------------------------------
_iam_cache = None


def _load_iam_map() -> dict:
    global _iam_cache
    if _iam_cache is not None:
        return _iam_cache
    try:
        with open(IAM_MAP_PATH) as f:
            data = json.load(f)
    except Exception:
        return {}
    _iam_cache = data
    return data


def _svc_to_iam_prefix():
    """botocore service name -> IAM SDK prefix (s3 -> S3)."""
    data = _load_iam_map()
    service_sdk = data.get("service_sdk_mappings", {})
    result = {}
    for ns, sdk_names in service_sdk.items():
        for name in sdk_names:
            result[name.lower()] = name
    # Discover SDK prefixes actually present in the operation mappings.
    for key in data.get("sdk_method_iam_mappings", {}):
        if "." in key:
            sdk_name, _ = key.split(".", 1)
            result.setdefault(sdk_name.lower(), sdk_name)
    return result


def _lookup_actions(symbol: str) -> list[str]:
    """Resolve an SDK symbol (s3.PutObject) to IAM action strings."""
    if "." not in symbol:
        return []
    svc, op = symbol.split(".", 1)
    prefixes = _svc_to_iam_prefix()
    prefix = prefixes.get(svc.lower(), svc.upper())
    mappings = _load_iam_map().get("sdk_method_iam_mappings", {})
    actions = []
    for cand in (f"{prefix}.{op}", f"{svc.upper()}.{op}"):
        for entry in mappings.get(cand, []):
            a = entry.get("action")
            if a and a not in actions:
                actions.append(a)
    return actions


def _expand_wildcards(action: str) -> list[str]:
    """Expand a wildcarded IAM action (s3:Get*) into concrete actions.

    SimulateCustomPolicy does not support wildcards in action names, so any
    wildcarded operation must be fully expanded before a check/verify call.
    Expansion uses the known action set from the iam-dataset. If the wildcard
    matches nothing known, the action is returned unchanged (callers treat it
    as unexpandable).
    """
    if "*" not in action and "?" not in action:
        return [action]
    data = _load_iam_map()
    known = set()
    for entries in data.get("sdk_method_iam_mappings", {}).values():
        for e in entries:
            a = e.get("action")
            if a:
                known.add(a)
    svc, _, pat = action.partition(":")
    if not svc or not pat:
        return [action]
    expanded = []
    for a in sorted(known):
        if a.startswith(svc + ":") and fnmatch.fnmatchcase(a.split(":", 1)[1], pat):
            expanded.append(a)
    return expanded or [action]


# ---------------------------------------------------------------------------
# Policy builder
# ---------------------------------------------------------------------------
def _normalize_actions(actions: list[str]) -> list[str]:
    return contract.normalize_actions(actions)


def _build_policy(actions: list[str]) -> dict:
    return contract.build_policy(actions)


def _success(confidence, actions, unresolved):
    return contract.success(confidence, actions, unresolved)


def _error(unresolved, message):
    return contract.error(unresolved, message)


# ---------------------------------------------------------------------------
# Public entry points
# ---------------------------------------------------------------------------
def list_workflows() -> list[str]:
    return sorted(CURATED_WORKFLOWS.keys())


def resolve(operations=None, workflow="", description="") -> dict:
    """resolve verb: operation(s) -> required IAM actions.

    Returns the exact actions plus a resolution tier. Offline, no AWS calls.
    """
    if workflow:
        if workflow not in CURATED_WORKFLOWS:
            return {
                "error": "unknown_workflow",
                "message": f"Unknown workflow '{workflow}'. Valid: {', '.join(list_workflows())}",
                "unresolved": [workflow],
            }
        return {
            "provider": PROVIDER,
            "resolution": "exact",
            "operations": contract.normalize_actions(CURATED_WORKFLOWS[workflow]["actions"]),
            "unresolved": [],
        }

    if operations:
        if isinstance(operations, str):
            ops = [o.strip() for o in operations.split(",") if o.strip()]
        else:
            ops = [o for o in operations if o]
        resolved, unresolved = [], []
        for op in ops:
            if ":" in op:
                resolved.append(op)
            else:
                actions = _lookup_actions(op)
                if actions:
                    resolved.extend(actions)
                else:
                    unresolved.append(op)
        if not resolved:
            return {
                "error": "anchor_unresolved",
                "provider": PROVIDER,
                "resolution": "unresolved",
                "operations": [],
                "unresolved": unresolved,
            }
        return {
            "provider": PROVIDER,
            "resolution": "exact" if not unresolved else "partial",
            "operations": contract.normalize_actions(resolved),
            "unresolved": unresolved,
        }

    if description:
        result = _resolve_description(description)
        return result

    return {
        "error": "missing_input",
        "provider": PROVIDER,
        "message": "Provide one of: workflow=, operations=, or description=",
        "operations": [],
        "unresolved": [],
    }


def generate(workflow: str = "", operations: str | list[str] = "", description: str = "") -> dict:
    """generate verb: compose a least-privilege IAM policy.

    Precedence: workflow > operations > description. Offline, no AWS calls.
    """
    r = resolve(operations=operations, workflow=workflow, description=description)
    if "error" in r:
        if r["error"] == "unknown_workflow":
            return r
        if r["error"] == "anchor_unresolved":
            return _error(r["unresolved"], "No operations could be resolved to IAM actions.")
        return r
    if workflow:
        confidence = "verified"
    elif operations:
        confidence = "explicit"
    else:
        confidence = "resolved"
    return _success(confidence, r["operations"], r.get("unresolved", []))


def _resolve_description(description: str) -> dict:
    """Resolve a description to operations via curated chain edges only."""
    dl = description.lower()

    anchors = []
    for sym in RESOLVED_CHAIN_EDGES:
        svc, op = sym.split(".", 1)
        op_tokens = re.split(r"(?=[A-Z])", op)
        op_tokens = [t.lower() for t in op_tokens if t]
        op_phrase = " ".join(op_tokens).strip()
        score = 0
        if op_phrase and op_phrase in dl:
            score += 5
        if op_tokens and op_tokens[-1] in dl.split():
            score += 2
        if any(t in dl for t in op_tokens):
            score += 1
        if svc in dl:
            score += 1
        anchors.append((score, sym))

    if not anchors:
        return _error([], "Could not identify the core operation for this description.")

    anchors.sort(key=lambda x: -x[0])
    best_score, anchor = anchors[0]
    if best_score < 2:
        return _error([], "Could not identify the core operation for this description.")

    actions = []
    unresolved = []
    seen = {anchor}
    queue = [anchor]
    while queue:
        cur = queue.pop(0)
        cur_actions = _lookup_actions(cur)
        actions.extend(cur_actions)
        for nxt in RESOLVED_CHAIN_EDGES.get(cur, []):
            if nxt not in seen:
                seen.add(nxt)
                queue.append(nxt)
    if not actions:
        return _error(unresolved, f"Could not resolve actions for {anchor}.")
    return {
        "provider": PROVIDER,
        "resolution": "exact",
        "operations": _normalize_actions(actions),
        "unresolved": unresolved,
    }


# ---------------------------------------------------------------------------
# check verb: delegate to SimulatePrincipalPolicy
# ---------------------------------------------------------------------------
def _simulate_client():
    try:
        import boto3
        return boto3.client("iam")
    except Exception as ex:
        raise RuntimeError(f"boto3 unavailable: {ex}")


def _has_credentials() -> tuple[bool, str]:
    """Return (True, '') if AWS credentials are available, else (False, reason)."""
    try:
        import boto3
        session = boto3.session.Session()
        creds = session.get_credentials()
        if creds is None:
            return False, "no AWS credentials found (set AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY or a profile)"
        return True, ""
    except Exception as ex:
        return False, f"could not initialize AWS session: {ex}"


def _get_principal_arn() -> str:
    """Determine the caller's IAM principal ARN via sts:GetCallerIdentity."""
    try:
        import boto3
        sts = boto3.client("sts")
        return sts.get_caller_identity()["Arn"]
    except Exception as ex:
        raise RuntimeError(f"could not determine caller principal: {ex}")


def check(operations=None, principal_arn=None, workflow="") -> dict:
    """check verb: required actions -> verdict via SimulatePrincipalPolicy.

    resolution and evaluation are separate fields. The map part (resolution)
    is exact (Stigmer's data). The role part (evaluation) is best-effort and
    carries the AWS simulator's documented gaps. Without credentials this
    returns evaluation=unknown with the reason, never a fabricated allow.
    """
    r = resolve(operations=operations, workflow=workflow)
    if "error" in r:
        r["resolution"] = r.get("resolution", "unresolved")
        r["evaluation"] = "unknown"
        r["role_checked"] = False
        r["missing_permissions"] = []
        return r

    actions = r["operations"]
    ok, reason = _has_credentials()
    if not ok:
        return {
            "provider": PROVIDER,
            "resolution": r["resolution"],
            "required_actions": actions,
            "evaluation": "unknown",
            "role_checked": False,
            "missing_permissions": [],
            "reason": reason,
            "caveats": SIMULATOR_CAVEATS,
        }

    try:
        client = _simulate_client()
        arn = principal_arn or _get_principal_arn()
        # SimulateCustomPolicy does not support wildcards; expand each action.
        expanded = []
        for a in actions:
            for e in _expand_wildcards(a):
                if e not in expanded:
                    expanded.append(e)
        if any("*" in a or "?" in a for a in expanded):
            return {
                "provider": PROVIDER,
                "resolution": r["resolution"],
                "required_actions": actions,
                "evaluation": "unknown",
                "role_checked": False,
                "missing_permissions": [],
                "reason": "one or more operations could not be expanded to concrete IAM actions for simulation",
                "caveats": SIMULATOR_CAVEATS,
            }
        results = client.simulate_principal_policy(
            PolicySourceArn=arn,
            ActionNames=expanded,
        )
        eval_results = results.get("EvaluationResults", [])
        by_action = {e["EvalActionName"]: e["EvalDecision"] for e in eval_results}
        denied = [a for a, d in by_action.items() if d != "allowed"]
        allowed = not denied and len(by_action) == len(expanded)
        return {
            "provider": PROVIDER,
            "resolution": r["resolution"],
            "required_actions": actions,
            "evaluation": "allowed" if allowed else "denied",
            "role_checked": True,
            "principal_arn": arn,
            "missing_permissions": denied,
            "decisions": by_action,
            "caveats": SIMULATOR_CAVEATS,
        }
    except Exception as ex:
        return {
            "provider": PROVIDER,
            "resolution": r["resolution"],
            "required_actions": actions,
            "evaluation": "unknown",
            "role_checked": False,
            "missing_permissions": [],
            "reason": f"{type(ex).__name__}: {ex}",
            "caveats": SIMULATOR_CAVEATS,
        }


# ---------------------------------------------------------------------------
# verify verb: delegate to SimulateCustomPolicy
# ---------------------------------------------------------------------------
def _extract_policy_actions(policy: dict) -> list[str]:
    """Collect every action string from a policy document's statements."""
    actions = []
    for st in policy.get("Statement", []):
        a = st.get("Action", [])
        if isinstance(a, str):
            a = [a]
        for x in a:
            if x and x not in actions:
                actions.append(x)
    return actions


def verify(policy: dict = None, operations=None, workflow="") -> dict:
    """verify verb: confirm a generated policy grants intended operations and
    nothing extra, using AWS's own evaluator (SimulateCustomPolicy).

    The action list passed to the simulator is fully expanded (no wildcards),
    because SimulateCustomPolicy rejects wildcards in action names.

    Returns:
        verified: True | False | "unknown"
        grants_all: True | False (every intended op allowed)
        grants_extra: [actions granted beyond intended]
        reason: present when verified == "unknown"
    """
    if workflow:
        r = resolve(workflow=workflow)
        if "error" in r:
            return {"verified": "unknown", "reason": r["message"], "provider": PROVIDER}
        policy = _build_policy(r["operations"])
        operations = r["operations"]
    elif policy is None or not operations:
        return {
            "verified": "unknown",
            "provider": PROVIDER,
            "reason": "provide either workflow= or both policy= and operations=",
        }

    intended = _normalize_actions(operations)

    ok, reason = _has_credentials()
    if not ok:
        return {
            "provider": PROVIDER,
            "verified": "unknown",
            "method": "simulate_custom_policy",
            "reason": reason,
            "intended_operations": intended,
            "caveats": SIMULATOR_CAVEATS,
        }

    try:
        client = _simulate_client()
        expanded = []
        for a in intended:
            for e in _expand_wildcards(a):
                if e not in expanded:
                    expanded.append(e)
        if any("*" in a or "?" in a for a in expanded):
            return {
                "provider": PROVIDER,
                "verified": "unknown",
                "method": "simulate_custom_policy",
                "reason": "one or more intended operations could not be expanded to concrete IAM actions",
                "intended_operations": intended,
                "caveats": SIMULATOR_CAVEATS,
            }
        results = client.simulate_custom_policy(
            PolicyInputList=[json.dumps(policy)],
            ActionNames=expanded,
        )
        eval_results = results.get("EvaluationResults", [])
        by_action = {e["EvalActionName"]: e["EvalDecision"] for e in eval_results}

        # grants_all: every intended action must be allowed.
        denied_intended = [a for a, d in by_action.items() if d != "allowed" and a in set(expanded)]
        grants_all = not denied_intended and len(by_action) >= len(set(expanded))

        # grants_extra: actions the policy grants that were not intended.
        policy_actions = _extract_policy_actions(policy)
        intended_set = set(intended)
        extra = [a for a in policy_actions if a not in intended_set]

        verified = grants_all and not extra
        return {
            "provider": PROVIDER,
            "verified": verified,
            "method": "simulate_custom_policy",
            "grants_all": grants_all,
            "grants_extra": extra,
            "denied_intended": denied_intended,
            "decisions": by_action,
            "intended_operations": intended,
            "policy": policy,
            "caveats": SIMULATOR_CAVEATS,
        }
    except Exception as ex:
        return {
            "provider": PROVIDER,
            "verified": "unknown",
            "method": "simulate_custom_policy",
            "reason": f"{type(ex).__name__}: {ex}",
            "intended_operations": intended,
            "caveats": SIMULATOR_CAVEATS,
        }
