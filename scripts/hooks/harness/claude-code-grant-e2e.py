#!/usr/bin/env python3
"""Grants with the real installed Claude and a synthetic Messages provider; no live login.

Each scenario is one Claude Code session with two user prompts, sent over
`--input-format stream-json` to one running process, the second after the first
turn has ended, as a person typing the next prompt would:

1. The scripted model runs `touch <canary> && echo TTH_E2E_DENY_MARKER`. The hook
   denies it; its reason offers the grant line.
2. The person's prompt is the grant line (or, for `control`, an ordinary prompt),
   and the scripted model repeats the call.

Scenarios: `control` (no grant: the repeat is denied again), `once` (`telltale
allow`: the repeat runs, a further repeat is denied), `session` (`telltale allow
session`: the repeat and a different call with the same detection run), and
`resumed` (the grant line in a later `-p --resume` run of the same session, after
the first run ended: nothing is offered any more, so the repeat is denied).
Set CLAUDE_BIN, TTH_BIN, E2E_ROOT. Prints one JSON summary per scenario.
"""

import json
import os
import pathlib
import shlex
import shutil
import subprocess
import sys
import tempfile
import threading
import uuid
from capture_common import HERE, Run, write_telltale_config
from qualification import executable_identity

REPO = pathlib.Path(HERE).parents[2]
BIN = shutil.which(os.environ.get("CLAUDE_BIN", "claude"))
TTH = os.environ.get("TTH_BIN", str(REPO / "target/debug/telltale"))
ROOT = os.environ.get("E2E_ROOT") or tempfile.mkdtemp(prefix="claude-grant-")
MARKER = "TTH_E2E_DENY_MARKER"
FIRST = "TTHGRANT: follow the scripted steps."
PROMPTS = {
    "control": "TTHRETRY: please try again.",
    "once": "telltale allow",
    "session": "telltale allow session",
    "resumed": "telltale allow",
}


def bash(command):
    return {
        "name": "Bash",
        "arguments": {"command": command, "description": "synthetic canary"},
    }


def claude_argv(settings_file, *extra):
    return [
        BIN,
        "-p",
        *extra,
        "--model",
        "claude-sonnet-4-6",
        "--max-turns",
        "8",
        "--setting-sources",
        "project",
        "--settings",
        str(settings_file),
        "--strict-mcp-config",
        "--mcp-config",
        '{"mcpServers":{}}',
    ]


def converse(run, argv, env, prompts, timeout=120):
    """One process, one prompt per turn: the next prompt is written once the
    previous turn's `result` message has been read. Returns each turn's result."""
    results = []
    with (
        open(os.path.join(run.dir, "stdout.txt"), "a") as out,
        open(os.path.join(run.dir, "stderr.txt"), "a") as err,
    ):
        process = subprocess.Popen(
            argv,
            cwd=run.work,
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=err,
            text=True,
        )
        watchdog = threading.Timer(timeout, process.kill)
        watchdog.start()
        try:
            for prompt in prompts:
                message = {"type": "user", "message": {"role": "user", "content": prompt}}
                process.stdin.write(json.dumps(message) + "\n")
                process.stdin.flush()
                for line in process.stdout:
                    out.write(line)
                    try:
                        event = json.loads(line)
                    except ValueError:
                        continue
                    if event.get("type") == "result":
                        results.append(event)
                        break
            process.stdin.close()
            out.write(process.stdout.read())
            code = process.wait()
        finally:
            watchdog.cancel()
    return code, results


def jsonl(path):
    path = pathlib.Path(path)
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line]


def scenario(name):
    run = Run(ROOT, name)
    first = run.canary()
    second = run.canary("canary2.txt")
    config = write_telltale_config(
        run.home,
        "  mode: enforce\n  evaluator:\n    enabled: false\n"
        "  grants:\n    enabled: true\n",
        [REPO / "crates/telltale/tests/hooks/e2e-marker-rules.yaml"],
    )
    stopped = f"touch {first} && echo {MARKER}"
    then = {
        "control": [{"tool_calls": [bash(stopped)]}, {"text": "done"}],
        "once": [
            {"tool_calls": [bash(stopped)]},
            {"tool_calls": [bash(stopped)]},
            {"text": "done"},
        ],
        "session": [
            {"tool_calls": [bash(stopped)]},
            {"tool_calls": [bash(f"touch {second} && echo {MARKER}")]},
            {"text": "done"},
        ],
        "resumed": [{"tool_calls": [bash(stopped)]}, {"text": "done"}],
    }[name]
    # The mock numbers tool calls by conversation and takes the next step from the
    # highest number in the request. The second prompt's conversation comes first,
    # so it is picked once that prompt is in the request.
    run.start_mock(
        {
            "conversations": [
                {"match": PROMPTS[name], "steps": then},
                {
                    "match": "TTHGRANT",
                    "steps": [{"tool_calls": [bash(stopped)]}, {"text": "stopped"}],
                },
            ]
        },
        server=str(pathlib.Path(HERE) / "mock-anthropic.py"),
    )
    hook = shlex.join(
        [
            sys.executable,
            "-I",
            str(pathlib.Path(HERE) / "copilot-cli-e2e.py"),
            "tee",
            run.dir + "/hook-io.jsonl",
            TTH,
            "hooks",
            "claude-code",
            "hook",
            "--config-dir",
            config,
        ]
    )
    env = run.base_env(
        ANTHROPIC_BASE_URL=f"http://127.0.0.1:{run.port}",
        ANTHROPIC_API_KEY="synthetic-not-a-key",
        CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC="1",
        DISABLE_AUTOUPDATER="1",
        TELLTALE_HOOKS_STATE_DIR=run.dir + "/state",
        TELLTALE_HOOKS_EVALUATOR="0",
    )
    for key in (
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    ):
        env[key] = "http://127.0.0.1:9"
    # The settings pin the state directory of the environment they are made in.
    settings = json.loads(
        subprocess.check_output(
            [TTH, "hooks", "claude-code", "settings", hook], env=env
        )
    )
    settings["permissions"] = {"allow": ["Bash"]}
    settings_file = pathlib.Path(run.dir) / "settings.json"
    settings_file.write_text(json.dumps(settings))

    streaming = ("--input-format", "stream-json", "--output-format", "stream-json")
    try:
        if name == "resumed":
            session = str(uuid.uuid4())
            exits, results = [], []
            for prompt, where in ((FIRST, "--session-id"), (PROMPTS[name], "--resume")):
                code, turn = converse(
                    run,
                    claude_argv(settings_file, *streaming, "--verbose", where, session),
                    env,
                    [prompt],
                )
                exits.append(code)
                results += turn
        else:
            code, results = converse(
                run,
                claude_argv(settings_file, *streaming, "--verbose"),
                env,
                [FIRST, PROMPTS[name]],
            )
            exits = [code]
    finally:
        run.stop()

    io = jsonl(run.dir + "/hook-io.jsonl")
    records = jsonl(run.dir + "/state/telemetry.jsonl")
    decisions = [
        {
            "tool": (r.get("action") or {}).get("tool_name"),
            "verdict": r["decision"].get("verdict"),
            "returned": r["decision"].get("returned"),
            "basis": r["decision"].get("basis"),
            "rules": r["decision"].get("rule_ids"),
            "grant": (r["decision"].get("grant") or {}).get("scope"),
        }
        for r in records
        if r.get("kind") == "decision"
    ]
    lifecycle = [
        {
            k: v
            for k, v in r["lifecycle"].items()
            if k in ("event", "scope", "tool", "rule_ids", "cause")
        }
        for r in records
        if r.get("kind") == "lifecycle"
        and r["lifecycle"].get("event") in ("grant", "grant_refused")
    ]
    prompt_hooks = [
        {
            "prompt": i["payload"].get("prompt"),
            "exit": i["exit"],
            "output": json.loads(i["stdout"]) if i["stdout"].strip() else None,
        }
        for i in io
        if i["event"] == "UserPromptSubmit"
    ]
    denial_reasons = [
        json.loads(i["stdout"])
        .get("hookSpecificOutput", {})
        .get("permissionDecisionReason", "")
        for i in io
        if i["event"] == "PreToolUse" and i["stdout"].strip()
    ]
    requests = run.model_requests()
    prompt_context = [
        (h["output"] or {}).get("hookSpecificOutput", {}).get("additionalContext")
        for h in prompt_hooks
    ]
    context_reached_model = [
        any(text in json.dumps(r["body"]) for r in requests)
        for text in filter(None, prompt_context)
    ]
    session_ids = sorted({i["payload"].get("session_id") for i in io} - {None})
    events = [i["event"] for i in io]
    canaries = {
        "canary": os.path.exists(first),
        "canary2": os.path.exists(second),
    }
    returned = [d["returned"] for d in decisions]
    grants = [d["grant"] for d in decisions]
    lifecycle_events = [l["event"] for l in lifecycle]
    expected = {
        "control": canaries == {"canary": False, "canary2": False}
        and returned == [True, True]
        and not lifecycle,
        "once": canaries == {"canary": True, "canary2": False}
        and returned == [True, False, True]
        and grants == [None, "once", None]
        and lifecycle_events == ["grant"],
        "session": canaries == {"canary": True, "canary2": True}
        and returned == [True, False, False]
        and grants == [None, "session", "session"]
        and lifecycle_events == ["grant"],
        "resumed": canaries == {"canary": False, "canary2": False}
        and returned == [True, True]
        and [l.get("cause") for l in lifecycle] == ["no_offer"],
    }[name]
    offered = bool(denial_reasons) and all(
        "telltale allow" in reason for reason in denial_reasons
    )
    summary = {
        "identity": {
            "harness": executable_identity(BIN),
            "telltale": executable_identity(TTH),
        },
        "scenario": name,
        "pass": expected
        and offered
        and len(session_ids) == 1
        and all(code == 0 for code in exits)
        and all(context_reached_model),
        "exits": exits,
        "session_ids": len(session_ids),
        "session_ends": events.count("SessionEnd"),
        "canaries": canaries,
        "decisions": decisions,
        "grant_lifecycle": lifecycle,
        "every_denial_offers_the_line": offered,
        "prompt_hooks": prompt_hooks,
        "prompt_context_reached_model": context_reached_model,
        "harness_denials": [len(r.get("permission_denials", [])) for r in results],
        "mode": "scripted Messages provider; isolated HOME; not a live model",
    }
    (pathlib.Path(run.dir) / "summary.json").write_text(json.dumps(summary) + "\n")
    print(json.dumps(summary), flush=True)
    return summary["pass"]


if __name__ == "__main__":
    names = sys.argv[1:] or list(PROMPTS)
    if any(n not in PROMPTS for n in names):
        sys.exit(f"unknown scenario (expected one of {', '.join(PROMPTS)})")
    results = [scenario(n) for n in names]
    sys.exit(0 if all(results) else 1)
