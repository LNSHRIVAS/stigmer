#!/usr/bin/env python3
"""Tests for stigmer_use_aws: the scoped AWS execution tool.

Covers:
  - _scoped_client: ambient path (no scoping) vs assume_role + session_policy path
  - session_policy passed as Policy JSON to sts:assume_role
  - credentials wired into the boto3 client
  - tool returns success / error ToolResult shape
  - datetime conversion
"""
import json, os, sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))
from strands_stigmer.use_aws import _scoped_client, _convert_datetime_to_str

passed, failed = 0, 0

def check(name, cond, detail=""):
    global passed, failed
    if cond:
        passed += 1
        print(f"  [PASS] {name}")
    else:
        failed += 1
        print(f"  [FAIL] {name} {detail}")

print("=== A. _scoped_client ambient path (no scoping) ===")
import boto3 as real_boto3
calls = []
class FakeSession:
    def __init__(self, profile_name=None):
        self.profile_name = profile_name
    def client(self, **kw):
        calls.append(("session.client", kw))
        return object()

orig_client = real_boto3.client
orig_session = real_boto3.Session

def fake_client(**kw):
    calls.append(("client", kw))
    return object()

import strands_stigmer.use_aws as mod
mod.boto3.Session = FakeSession
mod.boto3.client = fake_client

try:
    r = mod._scoped_client("s3", "us-west-2", None, None, None)
    check("ambient path calls Session.client", calls[0][0] == "session.client", str(calls))
    check("ambient path no assume_role", all(c[0] != "assume_role" for c in calls))
    check("user agent tagged", calls[0][1]["config"].user_agent_extra == "strands-stigmer-use-aws",
          str(calls[0][1].get("config")))
finally:
    mod.boto3.client = orig_client
    mod.boto3.Session = orig_session
    calls.clear()

print("=== B. _scoped_client assume_role path ===")
class FakeSTS:
    def __init__(self):
        self.calls = []
    def assume_role(self, **kw):
        self.calls.append(kw)
        return {"Credentials": {
            "AccessKeyId": "AKIAFAKE",
            "SecretAccessKey": "SECRET",
            "SessionToken": "TOKEN",
        }}

fake_sts = FakeSTS()
orig_sts_client = mod.boto3.client
def fake_client(service_name, **kw):
    if service_name == "sts":
        return fake_sts
    calls.append(("client", kw))
    return object()

mod.boto3.client = fake_client
try:
    r = mod._scoped_client("s3", "us-west-2", None,
                           "arn:aws:iam::123456789012:role/exec", {"Version": "2012-10-17"})
    check("assume_role called with role arn", fake_sts.calls and "arn:aws:iam::123456789012:role/exec" in fake_sts.calls[0]["RoleArn"],
          str(fake_sts.calls))
    check("session_policy passed as Policy JSON", fake_sts.calls and "Policy" in fake_sts.calls[0],
          str(fake_sts.calls))
    pol = json.loads(fake_sts.calls[0]["Policy"])
    check("Policy is the supplied policy doc", pol.get("Version") == "2012-10-17", str(pol))
    check("role session named", fake_sts.calls[0]["RoleSessionName"] == "strands-stigmer-tool-call")
    # the s3 client got the scoped creds
    s3_kw = [c for c in calls if c[0] == "client"][0][1]
    check("s3 client gets access key", s3_kw["aws_access_key_id"] == "AKIAFAKE", str(s3_kw))
    check("s3 client gets session token", s3_kw["aws_session_token"] == "TOKEN")
finally:
    mod.boto3.client = orig_client
    calls.clear()

print("=== C. session_policy without role_arn errors clearly ===")
# assume_role needs a role; a scoping policy without a role cannot narrow the
# ambient session (which is fixed at process launch). Must error, not silently
# run unscoped.
mod.boto3.Session = FakeSession
mod.boto3.client = fake_client
try:
    try:
        mod._scoped_client("s3", "us-west-2", None, None, {"Version": "2012-10-17"})
        check("policy-only raises ValueError", False, "no exception raised")
    except ValueError as e:
        check("policy-only raises ValueError", "role_arn" in str(e), str(e))
    check("no client was built on error", calls == [], str(calls))
finally:
    mod.boto3.client = orig_client
    mod.boto3.Session = orig_session
    calls.clear()

print("=== D. datetime conversion ===")
import datetime
r = _convert_datetime_to_str({"a": datetime.datetime(2026, 8, 5, 12, 0), "b": [datetime.date(2026, 1, 1)]})
check("datetime -> iso", r == {"a": "2026-08-05T12:00:00", "b": ["2026-01-01"]}, str(r))
check("passthrough scalars", _convert_datetime_to_str(5) == 5)

print("=== E. stigmer_use_aws tool result shape ===")
from strands_stigmer.use_aws import stigmer_use_aws
r = stigmer_use_aws(service_name="", operation_name="")
check("missing service/operation -> error", r["status"] == "error", str(r))

print("=== F. no em-dashes in source ===")
src = open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "src", "strands_stigmer", "use_aws.py"), encoding="utf-8").read()
check("no em-dashes", "\u2014" not in src and "\u2013" not in src)

print(f"\n=== RESULT: {passed} passed, {failed} failed ===")
sys.exit(1 if failed else 0)
