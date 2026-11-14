#!/usr/bin/env python3
"""Print a capture's hook records compactly: label, then payload with long strings clipped.

Usage: show-capture.py <hooks.jsonl> [label-substring ...]
"""
import json
import sys


def clip(o, n=160):
    if isinstance(o, str):
        return o if len(o) <= n else o[:n] + f"...<{len(o)} chars>"
    if isinstance(o, list):
        return [clip(x, n) for x in o]
    if isinstance(o, dict):
        return {k: clip(v, n) for k, v in o.items()}
    return o


path, filters = sys.argv[1], sys.argv[2:]
for line in open(path, encoding="utf-8"):
    r = json.loads(line)
    if filters and not any(f in r["label"] for f in filters):
        continue
    print(f"== {r['label']} mode={r['mode']}")
    print(json.dumps(clip(r["payload"]), ensure_ascii=False))
