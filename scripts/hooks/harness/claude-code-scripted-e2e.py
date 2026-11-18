#!/usr/bin/env python3
"""Real installed Claude, isolated synthetic Messages provider; no live login.

This is separate evidence from the historical real-model/pinned Claude driver.
Set CLAUDE_BIN, TTH_BIN, E2E_ROOT. Only the benign/deny canary pair is qualified.
"""

import json
import os
import pathlib
import shlex
import shutil
import subprocess
import sys
import tempfile
from capture_common import HERE, Run, write_telltale_config
from qualification import command_pair_evidence, executable_identity

REPO = pathlib.Path(HERE).parents[2]
BIN = shutil.which(os.environ.get("CLAUDE_BIN", "claude"))
TTH = os.environ.get("TTH_BIN", str(REPO / "target/debug/telltale"))
ROOT = os.environ.get("E2E_ROOT") or tempfile.mkdtemp(prefix="claude-scripted-")


def scenario(name):
    identity = {
        "harness": executable_identity(BIN),
        "telltale": executable_identity(TTH),
    }
    run = Run(ROOT, name)
    denied = name == "deny"
    command = f"touch {run.canary()} && echo " + (
        "TTH_E2E_DENY_MARKER" if denied else "benign"
    )
    run.start_mock(
        {
            "conversations": [
                {
                    "match": "TTHSCRIPTED",
                    "steps": [
                        {
                            "tool_calls": [
                                {
                                    "name": "Bash",
                                    "arguments": {
                                        "command": command,
                                        "description": "synthetic canary",
                                    },
                                }
                            ]
                        },
                        {"text": "done"},
                    ],
                }
            ]
        },
        server=str(pathlib.Path(HERE) / "mock-anthropic.py"),
    )
    config = write_telltale_config(
        run.home,
        "  mode: enforce\n  evaluator:\n    enabled: false\n",
        [REPO / "crates/telltale/tests/hooks/e2e-marker-rules.yaml"],
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
    settings = json.loads(
        subprocess.check_output([TTH, "hooks", "claude-code", "settings", hook])
    )
    settings["permissions"] = {"allow": ["Bash"]}
    settings_file = pathlib.Path(run.dir) / "settings.json"
    settings_file.write_text(json.dumps(settings))
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
    try:
        run.run(
            [
                BIN,
                "-p",
                "TTHSCRIPTED: follow the scripted steps.",
                "--output-format",
                "json",
                "--model",
                "claude-sonnet-4-6",
                "--max-turns",
                "4",
                "--setting-sources",
                "project",
                "--settings",
                str(settings_file),
                "--strict-mcp-config",
                "--mcp-config",
                '{"mcpServers":{}}',
            ],
            env,
            timeout=90,
        )
    finally:
        run.stop()
    telemetry = pathlib.Path(run.dir) / "state/telemetry.jsonl"
    records = (
        [json.loads(l) for l in telemetry.read_text().splitlines()]
        if telemetry.exists()
        else []
    )
    io_path = pathlib.Path(run.dir) / "hook-io.jsonl"
    invocations = (
        [json.loads(l) for l in io_path.read_text().splitlines()]
        if io_path.exists()
        else []
    )
    receipts = {}
    for req in run.model_requests():
        for message in req["body"].get("messages", []):
            content = message.get("content", [])
            if isinstance(content, list):
                for part in content:
                    if part.get("type") == "tool_result":
                        receipts[part["tool_use_id"]] = part.get("content")
    evidence = command_pair_evidence(
        records, invocations, receipts, run.canary(), denied=denied
    )
    present = os.path.exists(run.canary())
    summary = {
        "identity": identity,
        "scenario": name,
        "pass": run.exit == 0 and present != denied and evidence["matched"],
        "exit": run.exit,
        "canary": "present" if present else "absent",
        "qualification": evidence,
        "mode": "scripted Messages provider; isolated HOME; not a live model",
    }
    (pathlib.Path(run.dir) / "summary.json").write_text(json.dumps(summary) + "\n")
    print(json.dumps(summary), flush=True)
    return summary["pass"]


if __name__ == "__main__":
    names = sys.argv[1:] or ["benign", "deny"]
    if any(n not in ("benign", "deny") for n in names):
        sys.exit("unknown scenario (expected benign or deny)")
    results = [scenario(n) for n in names]
    sys.exit(0 if all(results) else 1)
