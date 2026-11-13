#!/usr/bin/env python3
"""Minimal stdio MCP server for harness captures (capture tooling only).

One tool, `echo` ({"text": string}) that returns its input. Newline-delimited
JSON-RPC 2.0 over stdin/stdout, which is what the harnesses' stdio transports use.
"""
import json
import sys

TOOL = {"name": "echo", "description": "Echo the given text back.",
        "inputSchema": {"type": "object", "properties": {"text": {"type": "string"}}, "required": ["text"]}}


def reply(msg_id, result):
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": msg_id, "result": result}) + "\n")
    sys.stdout.flush()


for line in sys.stdin:
    try:
        msg = json.loads(line)
    except Exception:
        continue
    method, msg_id = msg.get("method"), msg.get("id")
    if msg_id is None:
        continue  # notification
    if method == "initialize":
        version = (msg.get("params") or {}).get("protocolVersion", "2025-06-18")
        reply(msg_id, {"protocolVersion": version, "capabilities": {"tools": {}},
                       "serverInfo": {"name": "tthmock", "version": "0.0.1"}})
    elif method == "tools/list":
        reply(msg_id, {"tools": [TOOL]})
    elif method == "tools/call":
        text = ((msg.get("params") or {}).get("arguments") or {}).get("text", "")
        reply(msg_id, {"content": [{"type": "text", "text": f"echo: {text}"}], "isError": False})
    elif method == "ping":
        reply(msg_id, {})
    else:
        sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": msg_id,
                                     "error": {"code": -32601, "message": "method not found"}}) + "\n")
        sys.stdout.flush()
