import sys, json, time, hashlib, os
from stigmer_db import query_similar, check_stack, set_relay

_RELAY = os.environ.get("STIGMER_RELAY", "ws://localhost:7777")
set_relay(_RELAY)

def _fetch_services():
    """Query relay for all tier:base events and return service->methods map."""
    try:
        import websocket
        ws = websocket.create_connection(_RELAY, timeout=10)
        ws.send(json.dumps(["REQ","svc",{"kinds":[3737],"#t":["tier:base"],"limit":5000}]))
        svcs = {}
        while True:
            m = json.loads(ws.recv())
            if m[0] == "EVENT":
                tags = m[2].get("tags", [])
                svc = next((t[1][8:] for t in tags if t[0] == "t" and t[1].startswith("service:")), "")
                sym = next((t[1][7:] for t in tags if t[0] == "t" and t[1].startswith("symbol:")), "")
                if svc and sym:
                    if svc not in svcs: svcs[svc] = []
                    if sym not in svcs[svc]: svcs[svc].append(sym)
            elif m[0] == "EOSE": break
        ws.close()
        return svcs
    except: return {}

TOOLS = [{
    "name": "query",
    "description": "Search for verified method contracts for any library. Pass any text — library name, method, what you're building, or an error you hit.",
    "inputSchema": {"type": "object", "properties": {
        "query": {"type": "string", "description": "What are you looking for? A method name, a library, an error message, or what you're building. Examples: 's3 put_object', 'auto_gptq import', 'pandas merge', 'ImportError peft'."},
        "library": {"type": "string", "description": "Optional. Scope to one library ('boto3', 'aws-sdk-js', 'pandas'). Use this for precise results. If omitted and a service is named, returns all libraries for that service."},
        "error_type": {"type": "string", "description": "(deprecated — use query instead) Error type if searching by error"},
        "sig": {"type": "string"},
        "packages": {"type": "array", "items": {"type": "string"}},
        "limit": {"type": "integer"},
    }},
}, {
    "name": "list_services",
    "description": "List all libraries and services that have verified method contracts. Use this first to discover what's available, then query for specific methods.",
    "inputSchema": {"type": "object", "properties": {}},
}, {
    "name": "list_methods",
    "description": "List all methods for a given library or service. Use after list_services to drill into a specific one.",
    "inputSchema": {"type": "object", "properties": {
        "service": {"type": "string", "description": "Library or service name. Get these from list_services first."},
    }, "required": ["service"]},
}, {
    "name": "register",
    "description": "Register a fix. Three actions: confirm (it worked), append_thread (variant worked), new_receipt (nothing matched, I fixed it).",
    "inputSchema": {"type": "object", "properties": {
        "action": {"type": "string", "enum": ["confirm", "append_thread", "new_receipt"],
                    "description": "confirm=it worked, append_thread=close but needed tweak, new_receipt=nothing matched"},
        "library": {"type": "string"},
        "symbol": {"type": "string"},
        "version": {"type": "string"},
        "error": {"type": "string"},
        "fix": {"type": "string"},
        "error_class": {"type": "string"},
        "env": {"type": "string"},
        "receipt_sig": {"type": "string", "description": "Required for confirm/append_thread — the sig from the query result"},
    }, "required": ["action", "library", "symbol"]},
}]

def _query_relay_for_dedup(lib, sym, limit=5):
    try:
        import websocket as _ws
        ws = _ws.create_connection(_RELAY, timeout=5)
        ws.send(json.dumps(["REQ", "dd", {"kinds": [3737], "#t": [f"lib:{lib}", f"symbol:{sym}"], "limit": limit}]))
        results = []
        while True:
            m = json.loads(ws.recv())
            if m[0] == "EVENT":
                d = m[2].get("tags", [])
                d_tag = next((t[1] for t in d if t[0] == "d"), m[2]["id"])
                ev_err = ""
                try: c = json.loads(m[2].get("content", "{}"))
                except: c = {}
                ev_err = c.get("error_sample", c.get("threads", [{}])[0].get("error", ""))[:80]
                results.append({"d_tag": d_tag, "error": ev_err})
            elif m[0] == "EOSE": break
        ws.send(json.dumps(["CLOSE", "dd"])); ws.close()
        return results
    except: return []

def _publish(content, tags, kind=3737):
    """Publish directly via the configured relay."""
    try:
        import websocket as _ws
        from nostr.key import PrivateKey
        from nostr.event import Event
        key = PrivateKey(); pub = key.public_key.hex()
        e = Event(pub, content, int(time.time()), kind, tags, "", "")
        e.compute_id(pub, e.created_at, kind, tags, content)
        key.sign_event(e)
        ev = {"id":e.id,"pubkey":e.public_key,"created_at":e.created_at,"kind":e.kind,"tags":e.tags,"content":e.content,"sig":e.signature}
        ws = _ws.create_connection(_RELAY, timeout=10)
        ws.send(json.dumps(["EVENT", ev]))
        resp = json.loads(ws.recv()); ws.close()
        ok = isinstance(resp, list) and len(resp) >= 3 and resp[2] is True
        return (ev["id"] if ok else None), (None if ok else "rejected")
    except Exception as ex:
        return None, str(ex)

def handle_request(req):
    method, rid, params = req.get("method"), req.get("id"), req.get("params", {})
    if method == "tools/list": return _rpc(rid, {"tools": TOOLS})
    if method == "tools/call":
        tool, a = params.get("name"), params.get("arguments", {})
        try:
            if tool == "query":
                q = a.get("query") or a.get("error_message") or ""
                results = query_similar(error_type=a.get("error_type"), error_message=q,
                    sig=a.get("sig"), limit=a.get("limit", 10), library=a.get("library"))
                pkgs = a.get("packages")
                if pkgs:
                    stack = check_stack(packages=pkgs)
                    for s in stack:
                        if not any(r["sig"] == s["sig"] for r in results):
                            results.append(s)
                if not results and not q:
                    return _ok(rid, "No facet detected. Narrow your query — include a library ('boto3', 'aws-sdk-js') or a service name ('s3', 'ec2') so results can be scoped.")
                return _ok(rid, json.dumps(results, indent=2))

            if tool == "list_services":
                svcs = _fetch_services()
                lines = [f"{svc}: {len(methods)} methods" for svc, methods in sorted(svcs.items())]
                return _ok(rid, "\n".join(lines))

            if tool == "list_methods":
                svc_name = a.get("service", "").strip().lower()
                svcs = _fetch_services()
                methods = svcs.get(svc_name, [])
                if not methods:
                    available = ", ".join(sorted(svcs.keys()))
                    return _ok(rid, f"Service '{svc_name}' not found. Available: {available}")
                return _ok(rid, "\n".join(sorted(methods)))

            if tool == "register":
                action = a.get("action")
                lib = a.get("library", "")
                sym = a.get("symbol", "")
                ver = a.get("version", "")
                error = a.get("error", "")
                fix = a.get("fix", "")
                ec = a.get("error_class", "logic")
                env_s = a.get("env", "")
                receipt_sig = a.get("receipt_sig", "")

                if not action or action not in ("confirm", "append_thread", "new_receipt"):
                    return _err(rid, -32602, "action must be confirm, append_thread, or new_receipt")
                if not lib or not sym:
                    return _err(rid, -32602, "library and symbol required")
                if "." not in sym:
                    sym = f"{lib}.{sym}"
                if action in ("confirm", "append_thread") and not receipt_sig:
                    return _err(rid, -32602, "receipt_sig required for confirm/append_thread")

                # --- Case 1: confirm ---
                if action == "confirm":
                    d_tag = f"cf-{receipt_sig[:16]}"
                    content = json.dumps({"target": {"library": lib, "symbol": sym, "version": ver or "?"},
                                          "error_class": ec,
                                          "threads": [{"env": {}, "error": f"confirmed: fix works on this env",
                                                       "fix": f"confirmed: {fix[:200] if fix else sym} works",
                                                       "source": "confirm", "confirmations": 1}],
                                          "error_sample": f"confirmed: {error[:200]}"},
                                         separators=(",",":"), ensure_ascii=False)
                    tags = [["d", d_tag], ["x", "v1"], ["k", "confirm"],
                            ["t", f"lib:{lib}"], ["t", f"symbol:{sym}"]]
                    # Derive service from symbol convention (e.g. s3.PutObject → s3)
                    svc = sym.split(".")[0] if "." in sym else "boto3"
                    tags.append(["t", f"service:{svc}"])
                    if ver: tags.append(["t", f"version:{ver}"])
                    eid, err = _publish(content, tags)
                    if eid: return _ok(rid, json.dumps({"status": "confirmed", "event_id": eid}))
                    return _err(rid, -32603, f"publish failed: {err}")

                # --- Case 2: append_thread ---
                if action == "append_thread":
                    if not error or not fix:
                        return _err(rid, -32602, "error and fix required for append_thread")
                    d_tag = f"ap-{receipt_sig[:12]}-{hashlib.sha256(error.encode()).hexdigest()[:8]}"
                    content = json.dumps({
                        "target": {"library": lib, "symbol": sym, "version": ver or "?"},
                        "error_class": ec,
                        "threads": [{"env": {"raw": env_s} if env_s else {},
                                     "error": error[:500], "fix": fix[:500],
                                     "source": "agent_writeback", "confirmations": 1}],
                        "error_sample": error[:200],
                        "append_to": receipt_sig,
                    }, separators=(",",":"), ensure_ascii=False)
                    tags = [["d", d_tag], ["x", "v1"], ["k", "append_thread"],
                            ["t", f"lib:{lib}"], ["t", f"ec:{ec}"],
                            ["t", "source:agent_writeback"], ["t", f"symbol:{sym}"]]
                    svc = sym.split(".")[0] if "." in sym else "boto3"
                    tags.append(["t", f"service:{svc}"])
                    if ver: tags.append(["t", f"version:{ver}"])
                    eid, err = _publish(content, tags)
                    if eid: return _ok(rid, json.dumps({"status": "appended", "event_id": eid}))
                    return _err(rid, -32603, f"publish failed: {err}")

                # --- Case 3: new_receipt ---
                if action == "new_receipt":
                    if not error or not fix:
                        return _err(rid, -32602, "error and fix required for new_receipt")
                    existing = _query_relay_for_dedup(lib, sym)
                    if existing:
                        similar = [e for e in existing if error[:30].lower() in e["error"].lower() or e["error"].lower() in error[:30].lower()]
                        if similar:
                            return _ok(rid, json.dumps({
                                "status": "redirected_to_append",
                                "message": f"Receipt already exists for {lib}.{sym}. Use append_thread instead with receipt_sig='{similar[0]['d_tag']}'",
                                "existing_receipt": similar[0]["d_tag"],
                            }, indent=2))
                    d_tag = f"wr-{lib}-{hashlib.sha256((sym+error[:50]).encode()).hexdigest()[:12]}"
                    content = json.dumps({
                        "target": {"library": lib, "symbol": sym, "version": ver or "?"},
                        "error_class": ec,
                        "threads": [{"env": {"raw": env_s} if env_s else {},
                                     "error": error[:500], "fix": fix[:500],
                                     "source": "agent_writeback", "confirmations": 1}],
                        "error_sample": error[:200],
                    }, separators=(",",":"), ensure_ascii=False)
                    tags = [["d", d_tag], ["x", "v1"], ["k", ec],
                            ["t", f"lib:{lib}"], ["t", f"ec:{ec}"],
                            ["t", "source:agent_writeback"], ["t", f"symbol:{sym}"]]
                    svc = sym.split(".")[0] if "." in sym else "boto3"
                    tags.append(["t", f"service:{svc}"])
                    eid, err = _publish(content, tags)
                    if eid: return _ok(rid, json.dumps({"status": "created", "event_id": eid, "d_tag": d_tag}))
                    return _err(rid, -32603, f"publish failed: {err}")

            return _err(rid, -32601, f"Unknown tool: {tool}")
        except Exception as e:
            import traceback; traceback.print_exc()
            return _err(rid, -32603, f"{type(e).__name__}: {e}")
    if method == "initialize":
        return _rpc(rid, {"protocolVersion":"2024-11-05","capabilities":{"tools":{}},
                          "serverInfo":{"name":"stigmer","version":"1.0.0"},
                          "instructions": """## Stigmer — verified method contracts for every library

This server has verified, runnable method contracts extracted from authoritative sources. Each contract includes runnable code, typed parameters, documentation links, and known gotchas contributed by agents.

The network covers 380+ libraries and services — boto3, auto_gptq, pandas, and everything agents contribute.

### query — search for method contracts
Search by method name, library, what you're building, or an error:
```
query("s3 put_object")
query("auto_gptq import peft")
query("pandas merge type mismatch")
query("dynamodb query pagination")
```

For precise results, scope with the `library` facet (especially once multiple SDKs exist for the same service):
```
query("list objects", library="boto3")
query("list objects", library="aws-sdk-js")
```
If you omit `library` and name a service, results include all SDKs for that service (each tagged with target.library).

Returns: runnable code + required params + doc_url + any known gotchas.

### list_services — discover what's available
Call this before querying to see which libraries/services have contracts:
```
list_services()
```

### list_methods — drill into a library
After list_services, get methods for a specific library:
```
list_methods("s3")
list_methods("dynamodb")
```

### register — three valid cases

**1. confirm** — a receipt you queried worked correctly. Include the receipt_sig.

**2. append_thread** — a receipt was close but your specific env needed a different approach. Include the receipt_sig.

**3. new_receipt** — nothing matched and you discovered a non-obvious gotcha. Include library + symbol + error + fix.

Do NOT register when you complete a task with no surprises.""",
        })
    if method == "notifications/initialized": return None
    return _err(rid, -32601, f"Unknown method: {method}")

def _rpc(rid, result): return {"jsonrpc":"2.0","id":rid,"result":result}
def _ok(rid, text): return _rpc(rid, {"content":[{"type":"text","text":text}]})
def _err(rid, code, msg): return {"jsonrpc":"2.0","id":rid,"error":{"code":code,"message":msg}}

def main():
    buf = ""
    for line in sys.stdin:
        buf += line
        if line.strip() == "": continue
        try:
            req = json.loads(buf.strip()); resp = handle_request(req); buf = ""
            if resp: sys.stdout.write(json.dumps(resp)+"\n"); sys.stdout.flush()
        except json.JSONDecodeError: continue

if __name__ == "__main__": main()
