#!/usr/bin/env python3
"""Synthetic Messages API for isolated real-Claude hook qualification only."""

import importlib.util
import json
import pathlib

spec = importlib.util.spec_from_file_location(
    "scripted_model", pathlib.Path(__file__).with_name("mock-model.py")
)
model = importlib.util.module_from_spec(spec)
spec.loader.exec_module(model)


class Handler(model.Handler):
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
        if "/count_tokens" in self.path:
            self._json(200, {"input_tokens": 10})
            return
        if not self.path.split("?")[0].endswith("/messages"):
            self._json(404, {"error": "unsupported synthetic path"})
            return
        step, idx, step_no = model.plan(body)
        self._log(body, {"conv": idx, "step": step_no})
        calls = model.calls_of(step, idx, step_no)
        content = (
            [
                {
                    "type": "tool_use",
                    "id": c["id"],
                    "name": c["name"],
                    "input": json.loads(c["arguments"]),
                }
                for c in calls
            ]
            if calls
            else [{"type": "text", "text": step.get("text", "done")}]
        )
        message = {
            "id": "msg_synthetic",
            "type": "message",
            "role": "assistant",
            "model": body["model"],
            "content": content,
            "stop_reason": "tool_use" if calls else "end_turn",
            "stop_sequence": None,
            "usage": {"input_tokens": 10, "output_tokens": 5},
        }
        if not body.get("stream"):
            self._json(200, message)
            return
        self._sse_start()
        self._sse(
            {
                "type": "message_start",
                "message": {**message, "content": [], "stop_reason": None},
            },
            "message_start",
        )
        for i, block in enumerate(content):
            start = (
                {**block, "input": {}}
                if block["type"] == "tool_use"
                else {"type": "text", "text": ""}
            )
            self._sse(
                {"type": "content_block_start", "index": i, "content_block": start},
                "content_block_start",
            )
            delta = (
                {"type": "input_json_delta", "partial_json": json.dumps(block["input"])}
                if block["type"] == "tool_use"
                else {"type": "text_delta", "text": block["text"]}
            )
            self._sse(
                {"type": "content_block_delta", "index": i, "delta": delta},
                "content_block_delta",
            )
            self._sse({"type": "content_block_stop", "index": i}, "content_block_stop")
        self._sse(
            {
                "type": "message_delta",
                "delta": {"stop_reason": message["stop_reason"], "stop_sequence": None},
                "usage": {"output_tokens": 5},
            },
            "message_delta",
        )
        self._sse({"type": "message_stop"}, "message_stop")


if __name__ == "__main__":
    model.Handler = Handler
    model.main()
