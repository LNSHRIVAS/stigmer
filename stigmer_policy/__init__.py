"""Stigmer policy engine: the permission map for agent tool calls.

Every provider exposes the same four verbs:

    resolve(operation) -> required_permissions     # Stigmer's data
    check(permissions) -> verdict                  # the provider's native check API
    generate(operations) -> policy                 # Stigmer's composition
    verify(policy, operations) -> verdict          # the provider's simulator

`resolve` and `generate` are the only verbs Stigmer implements from scratch.
`check` and `verify` delegate to the provider's own evaluation engine. This
keeps each provider module small and makes the provider seam the dispatch key
rather than a provider tag bolted onto AWS-shaped code.

Backward-compatible names from the pre-package module are re-exported here
so existing callers keep working unchanged.
"""
from __future__ import annotations

from . import aws as _aws
from .contract import PROVIDER, FORMAT, SCOPE
from .aws import (
    CURATED_WORKFLOWS,
    RESOLVED_CHAIN_EDGES,
    SIMULATOR_CAVEATS,
    list_workflows as _aws_list_workflows,
    generate as _aws_generate,
    resolve as _aws_resolve,
    check as _aws_check,
    verify as _aws_verify,
    _build_policy,
    _success,
    _error,
    _lookup_actions,
    _svc_to_iam_prefix,
)

# Provider registry: the dispatch seam. GCP/Azure modules slot in here with
# the same four verbs and become callable via provider=.
PROVIDERS = {
    "aws": _aws,
}


def _provider(provider: str):
    if provider not in PROVIDERS:
        raise ValueError(
            f"unknown provider '{provider}'. Available: {', '.join(sorted(PROVIDERS))}"
        )
    return PROVIDERS[provider]


def list_workflows(provider="aws") -> list[str]:
    return _provider(provider).list_workflows()


def generate(provider="aws", workflow="", operations="", description=""):
    return _provider(provider).generate(
        workflow=workflow, operations=operations, description=description
    )


def resolve(provider="aws", operations=None, workflow="", description=""):
    return _provider(provider).resolve(
        operations=operations, workflow=workflow, description=description
    )


def check(provider="aws", operations=None, principal_arn=None, workflow=""):
    return _provider(provider).check(
        operations=operations, principal_arn=principal_arn, workflow=workflow
    )


def verify(provider="aws", policy=None, operations=None, workflow=""):
    return _provider(provider).verify(
        policy=policy, operations=operations, workflow=workflow
    )


def authorize(operations=None, workflow="", description="", principal_arn=None, provider="aws") -> dict:
    """resolve + check combined, with resolution and evaluation as separate fields.

    resolution: exact | partial | unresolved   (Stigmer's data)
    evaluation: allowed | denied | unknown     (the provider's native check)

    The two are independent. evaluation=unknown means the provider's own
    engine (or its credentials) could not produce a verdict, never a guess.
    """
    mod = _provider(provider)
    r = mod.resolve(operations=operations, workflow=workflow, description=description)
    if "error" in r:
        r.setdefault("resolution", "unresolved")
        r["evaluation"] = "unknown"
        r["role_checked"] = False
        r["missing_permissions"] = []
        return r
    c = mod.check(operations=operations, workflow=workflow, principal_arn=principal_arn)
    return {
        "provider": provider,
        "operation": operations or workflow or description,
        "resolution": r["resolution"],
        "required_actions": r["operations"],
        "unresolved": r.get("unresolved", []),
        "evaluation": c.get("evaluation", "unknown"),
        "role_checked": c.get("role_checked", False),
        "principal_arn": c.get("principal_arn"),
        "missing_permissions": c.get("missing_permissions", []),
        "reason": c.get("reason"),
        "caveats": c.get("caveats", []),
    }
