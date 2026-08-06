"""Provider-agnostic response shapes for the Stigmer policy engine.

The four verbs every provider exposes (resolve, check, generate, verify) share
these response builders. Nothing in this module knows about a specific cloud,
so GCP/Azure modules slot in behind the same contract.

The authorize response separates the two sources of uncertainty into their
own fields:

    resolution: exact | partial | unresolved   (Stigmer's data, offline)
    evaluation: allowed | denied | unknown     (the provider's native check)

They are intentionally independent. Blending them into one boolean is where a
false confident answer comes from.
"""
from __future__ import annotations

from collections import defaultdict

PROVIDER = "aws"
FORMAT = "aws-iam-policy-v1"
SCOPE = "action-only"


def normalize_actions(actions):
    """Dedupe and sort IAM action strings."""
    cleaned = []
    for a in actions:
        a = str(a).strip()
        if a and a not in cleaned:
            cleaned.append(a)
    return sorted(cleaned)


def build_policy(actions):
    """Group actions by service into multiple statements."""
    groups = defaultdict(list)
    for a in normalize_actions(actions):
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


def success(confidence, actions, unresolved):
    return {
        "provider": PROVIDER,
        "format": FORMAT,
        "scope": SCOPE,
        "confidence": confidence,
        "operations": normalize_actions(actions),
        "policy": build_policy(actions),
        "unresolved": unresolved,
    }


def error(unresolved, message):
    return {
        "error": "anchor_unresolved",
        "provider": PROVIDER,
        "message": message,
        "unresolved": unresolved,
        "suggestion": "Pass explicit IAM actions via operations=",
    }
