#!/usr/bin/env python3
"""Stub command hook for harness contract captures (capture tooling, not the product).

Records the hook's stdin payload to $REC_LOG, then behaves as <mode> -- but only
when the payload contains $STUB_MATCH (default TTH_CANARY), so unrelated calls
(and post-execution events, registered with mode "noop") pass untouched.

Usage: stub-hook.py <label> <mode>
  label   free text stored with the record (for example the configured event name)
  mode    one of, or a comma-separated sequence ending in one of:
    noop          print nothing, exit 0
    deny-flat     {"permissionDecision":"deny","permissionDecisionReason":...}       (Copilot camelCase)
    ask-flat      {"permissionDecision":"ask", ...}
    allow-flat    {"permissionDecision":"allow"}
    deny-hso      {"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny",...}}
    ask-hso       same with "ask"
    allow-hso     same with "allow"
    allow-updated-hso  "allow" plus updatedInput = the payload's own tool_input (Codex's only accepted allow form)
    block-legacy  {"decision":"block","reason":...}
    exit2         reason on stderr, exit 2
    exit2-silent  exit 2 with empty stderr
    exit1         message on stderr, exit 1
    crash         abort() (SIGABRT)
    invalid       non-JSON stdout, exit 0
    sleep:N       sleep N seconds, then continue with the next mode in the sequence
Example: "sleep:20,deny-hso" (timeout test: a deny that arrives too late).
"""
import json
import os
import sys
import time

REASON = "TTH stub deny: canary command blocked by capture hook"
OUTPUTS = {
    "deny-flat": {"permissionDecision": "deny", "permissionDecisionReason": REASON},
    "ask-flat": {"permissionDecision": "ask", "permissionDecisionReason": "TTH stub ask"},
    "allow-flat": {"permissionDecision": "allow"},
    "deny-hso": {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                        "permissionDecisionReason": REASON}},
    "ask-hso": {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "ask",
                                       "permissionDecisionReason": "TTH stub ask"}},
    "allow-hso": {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "allow"}},
    "block-legacy": {"decision": "block", "reason": REASON},
}
ENV_PREFIXES = ("COPILOT_", "CODEX_", "OPENCODE", "CLAUDE_", "PLUGIN_")


def main():
    label = sys.argv[1] if len(sys.argv) > 1 else ""
    mode = sys.argv[2] if len(sys.argv) > 2 else "noop"
    raw = sys.stdin.read()
    try:
        payload = json.loads(raw)
    except Exception as e:  # keep the raw text: that is evidence too
        payload = {"_unparsed": raw[:4000], "_error": str(e)}
    match = os.environ.get("STUB_MATCH", "TTH_CANARY")
    active = match in raw
    env = {k: v for k, v in os.environ.items()
           if k.startswith(ENV_PREFIXES) and not any(s in k for s in ("TOKEN", "KEY", "SECRET", "AUTH"))}
    record = {"t": time.time(), "label": label, "mode": mode if active else "noop", "argv": sys.argv[1:],
              "cwd": os.getcwd(), "payload": payload, "env": env}
    with open(os.environ["REC_LOG"], "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")
    if not active:
        return 0
    for step in mode.split(","):
        if step.startswith("sleep:"):
            time.sleep(float(step.split(":", 1)[1]))
        elif step == "allow-updated-hso":
            tool_input = payload.get("tool_input") if isinstance(payload, dict) else None
            print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "allow",
                                                     "updatedInput": tool_input}}))
            return 0
        elif step in OUTPUTS:
            print(json.dumps(OUTPUTS[step]))
            return 0
        elif step == "exit2":
            print(REASON, file=sys.stderr)
            return 2
        elif step == "exit2-silent":
            return 2
        elif step == "exit1":
            print("TTH stub hook failure (exit 1)", file=sys.stderr)
            return 1
        elif step == "crash":
            sys.stdout.flush()
            os.abort()
        elif step == "invalid":
            print("this is not json {")
            return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
