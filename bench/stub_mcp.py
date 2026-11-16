#!/usr/bin/env python3
"""A stdio MCP server that serves a recorded tools/list and answers every call with a fixed line.
Usage: stub_mcp.py catalogue.json   (the array openwrt-mcp's tools/list returns)"""
import json, sys

tools = json.load(open(sys.argv[1]))

def send(o):
    sys.stdout.write(json.dumps(o, separators=(",", ":")) + "\n")
    sys.stdout.flush()

for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    m = json.loads(line)
    mid, method = m.get("id"), m.get("method")
    if mid is None:
        continue  # a notification
    if method == "initialize":
        send({"jsonrpc": "2.0", "id": mid, "result": {
            "protocolVersion": m["params"]["protocolVersion"],
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "openwrt", "version": "stub"}}})
    elif method == "tools/list":
        send({"jsonrpc": "2.0", "id": mid, "result": {"tools": tools}})
    elif method == "tools/call":
        send({"jsonrpc": "2.0", "id": mid, "result": {"content": [{"type": "text", "text": "stub: nothing was run"}]}})
    elif method == "ping":
        send({"jsonrpc": "2.0", "id": mid, "result": {}})
    else:
        send({"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": "no such method"}})
