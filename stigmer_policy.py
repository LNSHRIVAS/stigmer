"""Shared least-privilege IAM policy generator.

The single implementation of policy generation used by both the hosted and
local MCP servers. Three entry points compile down to one path:

    description -> [chain resolution] -> operations -> [IAM union] -> policy
    explicit operations enter here
    named workflow enters here

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

Error shape (anchor unresolvable):
    { "error": "anchor_unresolved", "provider": "aws",
      "message": "...", "unresolved": [...], "suggestion": "..." }
"""
from __future__ import annotations

import json
import os
from collections import defaultdict

PROVIDER = "aws"
FORMAT = "aws-iam-policy-v1"
SCOPE = "action-only"

IAM_MAP_PATH = os.environ.get("STIGMER_IAM_MAP", "/usr/local/bin/iam_map.json")

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


# ---------------------------------------------------------------------------
# Policy builder
# ---------------------------------------------------------------------------
def _normalize_actions(actions: list[str]) -> list[str]:
    """Dedupe and sort IAM action strings."""
    cleaned = []
    for a in actions:
        a = str(a).strip()
        if a and a not in cleaned:
            cleaned.append(a)
    return sorted(cleaned)


def _build_policy(actions: list[str]) -> dict:
    """Group actions by service into multiple statements."""
    groups = defaultdict(list)
    for a in _normalize_actions(actions):
        svc = a.split(":", 1)[0]
        groups[svc].append(a)
    statements = []
    for svc in sorted(groups):
        statements.append({
            "Sid": svc.capitalize() + "Access",
            "Effect": "Allow",
            "Action": sorted(groups[svc]),
            "Resource": "*",
        })
    return {
        "Version": "2012-10-17",
        "Statement": statements,
    }


def _success(confidence, actions, unresolved):
    return {
        "provider": PROVIDER,
        "format": FORMAT,
        "scope": SCOPE,
        "confidence": confidence,
        "operations": _normalize_actions(actions),
        "policy": _build_policy(actions),
        "unresolved": unresolved,
    }


def _error(unresolved, message):
    return {
        "error": "anchor_unresolved",
        "provider": PROVIDER,
        "message": message,
        "unresolved": unresolved,
        "suggestion": "Pass explicit IAM actions via operations=",
    }


# ---------------------------------------------------------------------------
# Public entry points
# ---------------------------------------------------------------------------
def list_workflows() -> list[str]:
    return sorted(CURATED_WORKFLOWS.keys())


def generate(workflow: str = "", operations: str | list[str] = "", description: str = "") -> dict:
    """Generate a least-privilege IAM policy. workflow > operations > description."""
    if workflow:
        if workflow not in CURATED_WORKFLOWS:
            return {
                "error": "unknown_workflow",
                "message": f"Unknown workflow '{workflow}'. Valid: {', '.join(list_workflows())}",
                "unresolved": [workflow],
            }
        return _success("verified", CURATED_WORKFLOWS[workflow]["actions"], [])

    if operations:
        if isinstance(operations, str):
            ops = [o.strip() for o in operations.split(",") if o.strip()]
        else:
            ops = [o for o in operations if o]
        # Explicit path: accept IAM action strings directly, else resolve symbols.
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
            return _error(unresolved, "No operations could be resolved to IAM actions.")
        return _success("explicit", resolved, unresolved)

    if description:
        # Resolve via curated chain edges only (high confidence). First op is anchor.
        return _resolve_description(description)

    return {
        "error": "missing_input",
        "message": "Provide one of: workflow=, operations=, or description=",
        "unresolved": [],
    }


def _resolve_description(description: str) -> dict:
    """Resolve a description to operations via curated chain edges only."""
    dl = description.lower()
    # Find the anchor: try matching known chain-starting symbols.
    anchor = None
    for sym in RESOLVED_CHAIN_EDGES:
        parts = sym.split(".")
        if len(parts) == 2 and parts[1].lower().replace("_", " ") in dl:
            anchor = sym
            break
    if not anchor:
        # Fall back to a keyword match over all symbols.
        for sym in RESOLVED_CHAIN_EDGES:
            svc, op = sym.split(".", 1)
            if svc in dl:
                anchor = sym
                break
    if not anchor:
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
    return _success("resolved", actions, unresolved)
