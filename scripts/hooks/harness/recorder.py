#!/usr/bin/env python3
"""Records one Claude Code hook invocation: stdin payload plus transcript tail facts."""
import json, os, sys, time
raw = sys.stdin.read()
try:
    payload = json.loads(raw)
except Exception as e:
    payload = {"_unparsed": raw[:2000], "_error": str(e)}
tail = []
tp = payload.get("transcript_path") if isinstance(payload, dict) else None
if tp and os.path.exists(tp):
    lines = open(tp, encoding="utf-8", errors="replace").read().splitlines()
    for line in lines[-4:]:
        try:
            r = json.loads(line)
        except Exception:
            tail.append({"unparsed": True}); continue
        blocks = r.get("message", {}).get("content") if isinstance(r.get("message"), dict) else None
        kinds = []
        if isinstance(blocks, list):
            for b in blocks:
                if isinstance(b, dict):
                    kinds.append({"type": b.get("type"), "id": b.get("id") or b.get("tool_use_id")})
        tail.append({"type": r.get("type"), "uuid": r.get("uuid"), "blocks": kinds})
    tail_count = len(lines)
else:
    tail_count = None
rec = {"t": time.time(), "argv": sys.argv[1:], "payload": payload, "transcript_lines": tail_count, "transcript_tail": tail,
       "env": {k: v for k, v in os.environ.items() if k.startswith("CLAUDE_") and "TOKEN" not in k}}
with open(os.environ["REC_LOG"], "a") as f:
    f.write(json.dumps(rec) + "\n")
sys.exit(0)
