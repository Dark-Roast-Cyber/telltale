"""Fail-closed evidence checks for the integrated command-hook canary pair.

Receipts stay private in the run directory. Return only content-free joins.
The returned record ID in the native reply links that hook invocation to the
decision; the same ID in the model's tool receipt confirms delivery.
"""

import json
import hashlib
import functools
import shutil
import subprocess


@functools.lru_cache
def executable_identity(executable):
    """Capture actual versions/digests, rather than infer them from a PATH name."""
    path = shutil.which(executable) or executable
    version = subprocess.run(
        [path, "--version"], capture_output=True, text=True, timeout=10, check=True
    )
    with open(path, "rb") as binary:
        digest = hashlib.file_digest(binary, "sha256").hexdigest()
    return {"version": version.stdout.strip(), "sha256": digest}


def command_pair_evidence(records, invocations, receipts, canary, *, denied):
    decisions = [r for r in records if r.get("kind") == "decision"]
    for invocation in invocations:
        payload = invocation.get("payload", {})
        event = payload.get("hook_event_name") or payload.get("hookName")
        if (
            event is None
            and "toolName" in payload
            and "toolResult" not in payload
            and "error" not in payload
        ):
            event = "preToolUse"
        if event not in ("PreToolUse", "preToolUse"):
            continue
        arguments = payload.get("tool_input", payload.get("toolArgs"))
        if isinstance(arguments, str):
            try:
                arguments = json.loads(arguments)
            except ValueError:
                continue
        command = (arguments or {}).get("cmd", (arguments or {}).get("command", ""))
        if canary not in command or invocation.get("exit") != 0:
            continue
        for decision in decisions:
            native_tool = payload.get("tool_name", payload.get("toolName"))
            digest = hashlib.sha256(
                json.dumps(
                    arguments, sort_keys=True, ensure_ascii=False, separators=(",", ":")
                ).encode()
            ).hexdigest()
            if decision.get("action", {}).get("input_sha256") != digest or (
                decision["action"]["tool_name"] != native_tool
            ):
                continue
            info = decision["decision"]
            record_id = decision["record_id"]
            if denied:
                matched = (
                    info["returned"]
                    and info["verdict"] == "deny"
                    and "tth.e2e.deny_marker" in info["rule_ids"]
                    and record_id in invocation["stdout"]
                    and any(record_id in str(receipt) for receipt in receipts.values())
                    and any(
                        r.get("kind") == "outcome"
                        and r["outcome"].get("decision_record_id") == record_id
                        and r["outcome"]["result"] == "not_executed"
                        and r["outcome"]["enforcement"] == "honored"
                        for r in records
                    )
                )
            else:
                # A real post result linked to this decision distinguishes a
                # working silent hook from a hook that never ran.
                matched = (
                    info["verdict"] == "allow"
                    and not invocation["stdout"].strip()
                    and any(
                        r.get("kind") == "outcome"
                        and r["outcome"].get("decision_record_id") == record_id
                        and r["outcome"]["result"] == "completed"
                        for r in records
                    )
                )
            if matched:
                return {
                    "matched": True,
                    "returned_marker": denied,
                    "settled_same_decision": True,
                }
    return {"matched": False, "returned_marker": False, "settled_same_decision": False}
