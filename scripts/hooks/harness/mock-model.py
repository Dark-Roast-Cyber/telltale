#!/usr/bin/env python3
"""Scripted OpenAI-compatible model server for harness contract captures.

Capture tooling only: it lets a real harness (Copilot CLI BYOK, Codex custom
provider, OpenCode custom provider) run exact, repeatable tool calls without
model tokens, credentials or model-side refusals. The harness, its hooks and
its tools are real; only the model's choices are scripted.

Serves:
  POST /v1/chat/completions  (stream and non-stream)
  POST /v1/responses         (SSE stream; function_call and custom_tool_call)
  GET  /v1/models
Every request body is appended to <log> so the harness's tool schemas are
evidence too.

Script (JSON):
  {"conversations": [
     {"match": "MARKER", "steps": [
        {"tool_calls": [{"name": "bash", "arguments": {"command": "echo hi"}}]},
        {"tool_calls": [{"name": "apply_patch", "custom": true, "input": "*** Begin Patch..."}]},
        {"tool_calls": [{"name": "echo", "namespace": "mcp__srv", "arguments": {"text": "hi"}}]},
        {"text": "done"}]}],
   "default_text": "ok"}
A request is matched to the first conversation whose marker occurs in its
user/developer/system text. The step index comes from the call IDs this server
minted (call_<conv>_<step>_<n>) that appear in the request, so parallel calls
and retries stay deterministic. After the last step the server answers text.

Usage: mock-model.py <script.json> <request-log.jsonl> <port-file>
Binds 127.0.0.1 on an ephemeral port and writes the port to <port-file>.
"""
import json
import re
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SCRIPT_PATH, LOG_PATH, PORT_FILE = sys.argv[1], sys.argv[2], sys.argv[3]
CALL_RE = re.compile(r"call_(\d+)_(\d+)_(\d+)")
COUNTER = [0]


def load_script():
    with open(SCRIPT_PATH, encoding="utf-8") as f:
        return json.load(f)


def texts_of(body):
    """All non-assistant text in the request, for marker matching."""
    out = []
    for key in ("instructions", "system"):
        if isinstance(body.get(key), str):
            out.append(body[key])
    items = body.get("messages") or body.get("input") or []
    if isinstance(items, str):
        return out + [items]
    for item in items:
        if not isinstance(item, dict) or item.get("role") == "assistant":
            continue
        content = item.get("content")
        if isinstance(content, str):
            out.append(content)
        elif isinstance(content, list):
            for part in content:
                if isinstance(part, dict) and isinstance(part.get("text"), str):
                    out.append(part["text"])
    return out


def pick(body, script):
    text = "\n".join(texts_of(body))
    for idx, conv in enumerate(script.get("conversations", [])):
        if conv["match"] in text:
            return idx, conv
    return None, None


def next_step(body, conv_idx):
    raw = json.dumps(body)
    seen = [int(m.group(2)) for m in CALL_RE.finditer(raw) if int(m.group(1)) == conv_idx]
    return (max(seen) + 1) if seen else 0


def plan(body):
    script = load_script()
    idx, conv = pick(body, script)
    if conv is None:
        return {"text": script.get("default_text", "ok")}, None, None
    step_no = next_step(body, idx)
    steps = conv["steps"]
    if step_no >= len(steps):
        return {"text": conv.get("final_text", "done")}, idx, step_no
    return steps[step_no], idx, step_no


def calls_of(step, idx, step_no):
    calls = []
    for n, call in enumerate(step.get("tool_calls", [])):
        args = call.get("arguments", {})
        calls.append({
            "id": f"call_{idx}_{step_no}_{n}",
            "name": call["name"],
            "custom": bool(call.get("custom")),
            "namespace": call.get("namespace"),
            "input": call.get("input", ""),
            "arguments": args if isinstance(args, str) else json.dumps(args),
        })
    return calls


USAGE_CHAT = {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}
USAGE_RESP = {"input_tokens": 10, "input_tokens_details": {"cached_tokens": 0},
              "output_tokens": 5, "output_tokens_details": {"reasoning_tokens": 0}, "total_tokens": 15}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def _log(self, body, decision):
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps({"t": time.time(), "path": self.path, "body": body, "reply": decision}) + "\n")

    def _json(self, code, obj):
        data = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _sse_start(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True

    def _sse(self, obj, event=None):
        chunk = (f"event: {event}\n" if event else "") + f"data: {json.dumps(obj) if not isinstance(obj, str) else obj}\n\n"
        self.wfile.write(chunk.encode())
        self.wfile.flush()

    def do_GET(self):
        if self.path.rstrip("/").endswith("/models"):
            self._json(200, {"object": "list", "data": [{"id": "mock-model", "object": "model", "owned_by": "mock"}],
                             "models": []})
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except Exception:
            body = {}
        step, idx, step_no = plan(body)
        self._log(body, {"conv": idx, "step": step_no, "step_body": step})
        if self.path.endswith("/chat/completions"):
            self.chat(body, step, idx, step_no)
        elif self.path.endswith("/responses"):
            self.responses_api(body, step, idx, step_no)
        else:
            self._json(404, {"error": "unsupported path"})

    def chat(self, body, step, idx, step_no):
        COUNTER[0] += 1
        cid, model, created = f"chatcmpl-{COUNTER[0]}", body.get("model", "mock-model"), int(time.time())
        calls = calls_of(step, idx, step_no)
        tool_calls = [{"index": n, "id": c["id"], "type": "custom", "custom": {"name": c["name"], "input": c["input"]}}
                      if c["custom"] else
                      {"index": n, "id": c["id"], "type": "function",
                       "function": {"name": c["name"], "arguments": c["arguments"]}} for n, c in enumerate(calls)]
        text = step.get("text")
        finish = "tool_calls" if calls else "stop"
        if not body.get("stream"):
            msg = {"role": "assistant", "content": text}
            if tool_calls:
                msg["tool_calls"] = [{k: v for k, v in t.items() if k != "index"} for t in tool_calls]
            self._json(200, {"id": cid, "object": "chat.completion", "created": created, "model": model,
                             "choices": [{"index": 0, "message": msg, "finish_reason": finish}], "usage": USAGE_CHAT})
            return
        self._sse_start()
        base = {"id": cid, "object": "chat.completion.chunk", "created": created, "model": model}
        delta = {"role": "assistant", "content": text or ""}
        self._sse({**base, "choices": [{"index": 0, "delta": delta, "finish_reason": None}]})
        if tool_calls:
            self._sse({**base, "choices": [{"index": 0, "delta": {"tool_calls": tool_calls}, "finish_reason": None}]})
        self._sse({**base, "choices": [{"index": 0, "delta": {}, "finish_reason": finish}]})
        self._sse({**base, "choices": [], "usage": USAGE_CHAT})
        self._sse("[DONE]")

    def responses_api(self, body, step, idx, step_no):
        COUNTER[0] += 1
        rid = f"resp_{COUNTER[0]}"
        items = []
        for n, c in enumerate(calls_of(step, idx, step_no)):
            if c["custom"]:
                items.append({"type": "custom_tool_call", "id": f"ctc_{COUNTER[0]}_{n}", "call_id": c["id"],
                              "name": c["name"], "input": c["input"], "status": "completed"})
            else:
                item = {"type": "function_call", "id": f"fc_{COUNTER[0]}_{n}", "call_id": c["id"],
                        "name": c["name"], "arguments": c["arguments"], "status": "completed"}
                if c["namespace"]:
                    item["namespace"] = c["namespace"]
                items.append(item)
        if step.get("text"):
            items.append({"type": "message", "id": f"msg_{COUNTER[0]}", "role": "assistant", "status": "completed",
                          "content": [{"type": "output_text", "text": step["text"], "annotations": []}]})
        self._sse_start()
        resp = {"id": rid, "object": "response", "created_at": int(time.time()), "status": "in_progress",
                "model": body.get("model", "mock-model"), "output": []}
        self._sse({"type": "response.created", "response": resp}, "response.created")
        for n, item in enumerate(items):
            self._sse({"type": "response.output_item.added", "output_index": n, "item": item},
                      "response.output_item.added")
            if item["type"] == "message":
                self._sse({"type": "response.output_text.delta", "item_id": item["id"], "output_index": n,
                           "content_index": 0, "delta": step["text"]}, "response.output_text.delta")
            self._sse({"type": "response.output_item.done", "output_index": n, "item": item},
                      "response.output_item.done")
        done = {**resp, "status": "completed", "output": items, "usage": USAGE_RESP}
        self._sse({"type": "response.completed", "response": done}, "response.completed")


def main():
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    with open(PORT_FILE, "w") as f:
        f.write(str(server.server_address[1]))
    server.serve_forever()


if __name__ == "__main__":
    main()
