"""Build the Stigmer OPA bundle: the permission map as data OPA already consumes.

OPA's Bundle Service API expects a gzipped tarball containing:

  * Rego policy files (.rego)          -> the rule that looks up required actions
  * structured data files (data.json)  -> the operation -> required-actions map
  * .manifest                          -> revision + roots
  * .signatures.json                   -> signed bundle (optional but recommended)

Stigmer's operation-to-action map is the *data*; the rule that consults it is a
few lines of Rego. Publishing it as a bundle means any OPA instance (Gatekeeper,
Conftest, OPAL, or the InfoQ agent-gateway pattern) can subscribe with one config
entry and get the map automatically, refreshed on every poll.

Bundle layout (root namespace "stigmer"):

    .manifest
    .signatures.json
    stigmer/
      operations/data.json     # { "s3.PutObject": ["s3:PutObject"], ... }
      workflows/data.json      # { "s3-multipart-kms": ["s3:CreateMultipartUpload", ...] }
      policy.rego              # package stigmer.policy

The .signatures.json is a JWT (RS256) over the SHA-256 of each file, so OPA can
verify the bundle before activating it. This makes the trust claim checkable,
the same principle as Stigmer's verify verb.

Usage:
    python -m stigmer_opa_bundle --iam-map /usr/local/bin/iam_map.json \
        --signing-key /path/to/private.pem --out /var/www/stigmer/opa/bundle.tar.gz
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
import sys
import tarfile
import time
from datetime import datetime, timezone

import sys as _sys
_sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from stigmer_policy import aws as _aws

REGO = """package stigmer.policy

# resolve_actions(op) returns the IAM actions an operation requires.
# op is the SDK symbol, e.g. "s3.PutObject" or "dynamodb.TransactWriteItems".
# Returns [] when the operation is not in the map.
default resolve_actions(_op) := []

resolve_actions(op) := data.stigmer.operations[op] if data.stigmer.operations[op]

# has_required(op, granted) is true when the granted action set covers every
# action the operation requires. Use it as the per-invocation authorization
# check: gate the tool call on this rule.
has_required(op, granted) if {
    required := resolve_actions(op)
    count(required) > 0
    every_action_covered(required, granted)
}

every_action_covered(required, granted) if {
    action := required[_]
    granted[action]
}

# workflow_actions(name) returns the curated workflow's actions.
default workflow_actions(_name) := []
workflow_actions(name) := data.stigmer.workflows[name] if data.stigmer.workflows[name]"""


def _operation_symbols_from_map(data: dict) -> dict:
    """Build { symbol: [iam actions] } from the iam-dataset.

    Keys are the SDK method mapping keys (e.g. "S3.PutObject" from
    sdk_method_iam_mappings); we normalize the service to lowercase so the
    resulting symbol matches the MCP tool convention (s3.PutObject).
    """
    out: dict[str, list[str]] = {}
    mappings = data.get("sdk_method_iam_mappings", {})
    for key, entries in mappings.items():
        if "." not in key:
            continue
        svc, op = key.split(".", 1)
        symbol = f"{svc.lower()}.{op}"
        actions = []
        for e in entries:
            a = e.get("action")
            if a and a not in actions:
                actions.append(a)
        if actions:
            out[symbol] = actions
    return out


def _build_files(iam_map: dict) -> dict[str, bytes]:
    """Build the bundle file tree as { relative_path: bytes }."""
    operations = _operation_symbols_from_map(iam_map)
    workflows = {k: v["actions"] for k, v in _aws.CURATED_WORKFLOWS.items()}

    files = {}
    files["stigmer/operations/data.json"] = json.dumps(
        operations, separators=(",", ":"), sort_keys=True
    ).encode()
    files["stigmer/workflows/data.json"] = json.dumps(
        workflows, separators=(",", ":"), sort_keys=True
    ).encode()
    files["stigmer/policy.rego"] = REGO.encode()
    return files


def _manifest(revision: str) -> dict:
    return {
        "revision": revision,
        "roots": ["stigmer"],
        "metadata": {
            "name": "stigmer",
            "description": "Operation -> required IAM action map (prospective, not log-derived)",
        },
    }


def _canonical_hash(content: bytes, name: str) -> str:
    """Hash a bundle file the way OPA verifies it.

    For structured files (.json/.yaml), OPA parses the content into a JSON
    structure, recursively orders object fields alphabetically, and hashes the
    canonical serialization. Hashing the raw bytes would produce a digest
    mismatch at verification. Unstructured files (e.g. .rego) are hashed as raw
    bytes.
    """
    if name in (".manifest",) or name.endswith((".json", ".yaml")):
        try:
            parsed = json.loads(content)
            canonical = json.dumps(
                parsed, separators=(",", ":"), sort_keys=True
            ).encode()
            return hashlib.sha256(canonical).hexdigest()
        except ValueError:
            pass
    return hashlib.sha256(content).hexdigest()


def _sign(files: dict[str, bytes], signing_key_pem: str, keyid: str = "stigmer", scope: str = "read") -> str:
    """Create the .signatures.json JWT (RS256) over each file's hash.

    Returns the JSON serialized .signatures.json content.
    """
    import base64
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding
    except ImportError as e:
        raise SystemExit(f"cryptography required for signing: {e}")

    with open(signing_key_pem, "rb") as f:
        key = serialization.load_pem_private_key(f.read(), password=None)

    payload = {
        "files": [
            {
                "name": name,
                "hash": _canonical_hash(content, name),
                "algorithm": "SHA-256",
            }
            for name, content in sorted(files.items())
        ],
        "scope": scope,
        "iat": int(time.time()),
        "iss": "stigmer.network",
    }

    def b64url(b: bytes) -> str:
        return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

    header = {"alg": "RS256", "typ": "JWT", "kid": keyid}
    signing_input = (
        b64url(json.dumps(header, separators=(",", ":")).encode())
        + "."
        + b64url(json.dumps(payload, separators=(",", ":")).encode())
    )
    signature = key.sign(signing_input.encode(), padding.PKCS1v15(), hashes.SHA256())
    return json.dumps({"signatures": [signing_input + "." + b64url(signature)]})


def _tar_gz(files: dict[str, bytes]) -> bytes:
    """Pack the file tree into a gzipped tarball (bundle.tar.gz)."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, content in files.items():
            info = tarfile.TarInfo(name=name)
            info.size = len(content)
            info.mtime = int(time.time())
            info.mode = 0o644
            tar.addfile(info, io.BytesIO(content))
    return buf.getvalue()


def build(iam_map_path: str, signing_key_pem: str, keyid: str = "stigmer") -> tuple[dict[str, bytes], str, dict]:
    """Build the bundle. Returns (files, revision, manifest)."""
    with open(iam_map_path) as f:
        iam_map = json.load(f)

    files = _build_files(iam_map)
    revision = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    manifest = _manifest(revision)
    files[".manifest"] = json.dumps(manifest, separators=(",", ":")).encode()

    if signing_key_pem:
        files[".signatures.json"] = _sign(files, signing_key_pem, keyid=keyid).encode()
    return files, revision, manifest


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Build the Stigmer OPA bundle.")
    ap.add_argument("--iam-map", default=os.environ.get("STIGMER_IAM_MAP", "/usr/local/bin/iam_map.json"))
    ap.add_argument("--signing-key", default=os.environ.get("STIGMER_SIGNING_KEY", ""))
    ap.add_argument("--out", required=True, help="output bundle.tar.gz path")
    ap.add_argument("--keyid", default="stigmer")
    args = ap.parse_args(argv)

    files, revision, manifest = build(args.iam_map, args.signing_key, keyid=args.keyid)
    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "wb") as f:
        f.write(_tar_gz(files))

    ops = len(json.loads(files["stigmer/operations/data.json"]))
    print(f"bundle written: {args.out}")
    print(f"revision:       {revision}")
    print(f"operations:     {ops}")
    print(f"workflows:      {len(_aws.CURATED_WORKFLOWS)}")
    print(f"signed:         {bool(args.signing_key)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
