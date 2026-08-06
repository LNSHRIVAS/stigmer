#!/usr/bin/env python3
"""Tests for StigmerAuthHook: the BeforeToolCallEvent pre-action authorization hook.

Covers the decision matrix:
  denied  -> cancel_tool with missing permissions
  allowed -> pass through
  unknown + fail_open (default)  -> pass through
  unknown + fail_closed          -> cancel_tool
  non-AWS tool  -> untouched
  missing service/operation -> untouched
  authorize error + fail_closed -> cancel_tool
"""
import json, os, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from strands_stigmer.hooks import StigmerAuthHook, _operation_to_symbol

passed, failed = 0, 0

def check(name, cond, detail=""):
    global passed, failed
    if cond:
        passed += 1
        print(f"  [PASS] {name}")
    else:
        failed += 1
        print(f"  [FAIL] {name} {detail}")

class FakeEvent:
    def __init__(self, name="use_aws", arguments=None):
        self.tool_use = {"name": name, "arguments": arguments or {}}
        self.cancel_tool = False
        self.selected_tool = None
        self.invocation_state = {}

def make_hook(authorize_response, fail_closed=False, tools=None):
    h = StigmerAuthHook(fail_closed=fail_closed, tools=tools)
    resp = json.loads(authorize_response) if isinstance(authorize_response, str) else authorize_response
    def fake(symbol, **kw):
        return resp
    h._authorize = fake
    return h

AUTHORIZE_TEXT = json.dumps({
    "provider": "aws", "resolution": "exact",
    "required_actions": ["s3:PutObject"],
    "evaluation": "allowed", "role_checked": True,
    "missing_permissions": [],
    "caveats": [],
})

print("=== A. operation -> symbol conversion ===")
check("s3 put_object -> s3.PutObject", _operation_to_symbol("s3", "put_object") == "s3.PutObject")
check("dynamodb transact_write_items -> dynamodb.TransactWriteItems",
      _operation_to_symbol("dynamodb", "transact_write_items") == "dynamodb.TransactWriteItems")
check("iam get_role -> iam.GetRole", _operation_to_symbol("iam", "get_role") == "iam.GetRole")
check("single token preserved", _operation_to_symbol("s3", "list_buckets") == "s3.ListBuckets")

print("=== B. denied -> cancel with missing permissions ===")
h = make_hook(json.dumps({
    "provider": "aws", "resolution": "exact", "evaluation": "denied",
    "missing_permissions": ["s3:PutObject"], "role_checked": True,
}))
ev = FakeEvent(arguments={"service_name": "s3", "operation_name": "put_object"})
h(ev)
check("cancel_tool set", isinstance(ev.cancel_tool, str))
check("deny names the operation", "s3.PutObject" in ev.cancel_tool)
check("deny lists missing permission", "s3:PutObject" in ev.cancel_tool)

print("=== C. allowed -> pass through ===")
h = make_hook(AUTHORIZE_TEXT)
ev = FakeEvent(arguments={"service_name": "s3", "operation_name": "put_object"})
h(ev)
check("cancel_tool untouched", ev.cancel_tool is False)

print("=== D. unknown + fail_open (default) -> pass through ===")
h = make_hook(json.dumps({
    "provider": "aws", "resolution": "exact", "evaluation": "unknown",
    "role_checked": False, "reason": "no AWS credentials",
}))
ev = FakeEvent(arguments={"service_name": "s3", "operation_name": "put_object"})
h(ev)
check("unknown+fail_open passes through", ev.cancel_tool is False)

print("=== E. unknown + fail_closed -> cancel ===")
h = make_hook(json.dumps({
    "provider": "aws", "resolution": "exact", "evaluation": "unknown",
    "role_checked": False, "reason": "no AWS credentials",
}), fail_closed=True)
ev = FakeEvent(arguments={"service_name": "s3", "operation_name": "put_object"})
h(ev)
check("unknown+fail_closed cancels", isinstance(ev.cancel_tool, str))
check("cancel mentions fail_closed", "fail_closed" in ev.cancel_tool)

print("=== F. non-AWS tool untouched ===")
h = make_hook(AUTHORIZE_TEXT)
ev = FakeEvent(name="file_read", arguments={"path": "/etc/passwd"})
h(ev)
check("file_read untouched", ev.cancel_tool is False)

print("=== G. missing service/operation -> untouched ===")
h = make_hook(AUTHORIZE_TEXT)
ev = FakeEvent(arguments={"service_name": "s3"})
h(ev)
check("missing operation untouched", ev.cancel_tool is False)

print("=== H. authorize exception + fail_closed -> cancel ===")
h = StigmerAuthHook(fail_closed=True)
def boom(symbol, **kw):
    raise RuntimeError("timeout")
h._authorize = boom
ev = FakeEvent(arguments={"service_name": "s3", "operation_name": "put_object"})
h(ev)
check("error+fail_closed cancels", isinstance(ev.cancel_tool, str))
check("cancel names the tool", "stigmer authorize" in ev.cancel_tool)

print("=== I. authorize exception + fail_open -> pass through ===")
h = StigmerAuthHook(fail_closed=False)
h._authorize = boom
ev = FakeEvent(arguments={"service_name": "s3", "operation_name": "put_object"})
h(ev)
check("error+fail_open passes through", ev.cancel_tool is False)

print("=== J. no em-dashes in hook source ===")
src = open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "src", "strands_stigmer", "hooks.py"), encoding="utf-8").read()
check("no em-dashes", "\u2014" not in src and "\u2013" not in src)

print(f"\n=== RESULT: {passed} passed, {failed} failed ===")
sys.exit(1 if failed else 0)
