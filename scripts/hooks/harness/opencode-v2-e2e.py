#!/usr/bin/env python3
"""Pinned real OpenCode v2 + integrated Telltale, synthetic loopback only.

Use OPENCODE_V2_BIN, TTH_BIN and E2E_ROOT. No service attach: --standalone.
Private synthetic receipts are retained under E2E_ROOT, never copied to Git.
"""

import json
import os
import pathlib
import sys
import tempfile

from capture_common import HERE, Run, tool_results_seen_by_model, write_telltale_config
from qualification import executable_identity

REPO = pathlib.Path(HERE).parents[2]
BIN = os.environ.get("OPENCODE_V2_BIN", "opencode")
TTH = os.environ.get("TTH_BIN", str(REPO / "target/debug/telltale"))
ROOT = os.environ.get("E2E_ROOT") or tempfile.mkdtemp(prefix="opencode-v2-e2e-")
PLUGIN = REPO / "scripts/hooks/opencode-v2.mjs"
MARKERS = REPO / "crates/telltale/tests/hooks/e2e-marker-rules.yaml"


def tool(name, arguments):
    return {"name": name, "arguments": arguments}


def scenario(name):
    identity = {
        "harness": executable_identity(BIN),
        "telltale": executable_identity(TTH),
    }
    run = Run(ROOT, name)
    nested = name.startswith("nested")
    failure = "failure" in name
    native = name.startswith("native-")
    denied = not native and (
        name.endswith("deny")
        or name == "parallel"
        or (failure and not name.startswith("detect-") and name != "failure-noop")
    )
    detect = name == "detect-only" or name.startswith("detect-")
    marker = (
        "TTH_E2E_DENY_MARKER" if denied or detect or name == "init-broken" else "benign"
    )
    canary = "canary.txt"
    steps = []
    if nested:
        # Let the local MCP handshake finish before the Code Mode catalog is built.
        steps.append({"tool_calls": [tool("shell", {"command": "sleep 3"})]})
        # Construct the marker at runtime: the OUTER execute request must not
        # contain the marker matched by the deny rule.
        note = "'TTH_E2E_' + 'DENY_MARKER'" if denied else "'benign'"
        code = (
            "return await tools.tthmock.touch_canary({name:'canary.txt',note:"
            + note
            + "})"
        )
        if name == "nested-repeat-deny":
            code = (
                "return await Promise.all([1,2,3].map(async () => {try {return await "
                "tools.tthmock.touch_canary({name:'canary.txt',note:" + note + "})"
                "} catch(e) {return String(e)}}))"
            )
        steps.append({"tool_calls": [tool("execute", {"code": code})]})
    else:
        calls = [tool("shell", {"command": f"touch {run.canary()} && echo {marker}"})]
        if name == "parallel":
            calls.append(tool("shell", {"command": "touch sibling.txt"}))
        steps.append({"tool_calls": calls})
    steps.append({"text": "done"})
    run.start_mock({"conversations": [{"match": "TTHPILOT", "steps": steps}]})
    cfg = pathlib.Path(run.home) / ".config/opencode"
    (cfg / "plugins").mkdir(parents=True)
    config = {
        "model": "mock/mock-model",
        "providers": {
            "mock": {
                "name": "Mock",
                "package": "@ai-sdk/openai-compatible",
                "settings": {
                    "baseURL": f"http://127.0.0.1:{run.port}/v1",
                    "apiKey": "mock",
                },
                "models": {"mock-model": {"name": "Mock"}},
            }
        },
        "mcp": {
            "tthmock": {
                "type": "local",
                "command": ["node", str(pathlib.Path(HERE) / "mcp-canary-server.js")],
            }
        },
    }
    (cfg / "opencode.json").write_text(json.dumps(config))
    if native:
        config["permissions"] = [
            {
                "action": "shell",
                "resource": "*",
                "effect": "deny" if name == "native-deny" else "ask",
            }
        ]
        (cfg / "opencode.json").write_text(json.dumps(config))
    root = write_telltale_config(
        run.home, "  mode: enforce\n  evaluator:\n    enabled: false\n", [MARKERS]
    )
    options = {
        "executable": TTH,
        "configDirs": [root],
        "mode": "detect_only" if detect else "enforce",
    }
    if failure:
        wrapper = pathlib.Path(run.dir) / "synthetic-hook"
        if name.endswith("missing"):
            options["executable"] = str(pathlib.Path(run.dir) / "not-installed")
        else:
            if name.endswith("hang"):
                body = "import time\ntime.sleep(60)\n"
                options["timeoutMs"] = 200
            elif name.endswith("lost"):
                body = (
                    f"import subprocess,sys\nsubprocess.run([{TTH!r},*sys.argv[1:]],"
                    "input=sys.stdin.buffer.read(),stdout=subprocess.DEVNULL,check=True)\n"
                )
            else:
                body = "print('invalid reply')\n"
            wrapper.write_text(f"#!{sys.executable}\n{body}")
            wrapper.chmod(0o700)
            options["executable"] = str(wrapper)
        if name == "failure-noop":
            options["onError"] = "noop"
    # Record only synthetic native callbacks/receipts, outside the repository.
    plugin = f"""
import fs from 'node:fs';
import {{createPlugin}} from {json.dumps(PLUGIN.as_uri())};
const plugin = createPlugin({json.dumps(options)});
export default {{id:plugin.id, setup: async ctx => {{
  const hook = ctx.tool.hook.bind(ctx.tool);
  await plugin.setup({{...ctx,tool:{{...ctx.tool,hook:async (name,fn)=>hook(name,async e=>{{
    const rec = data => fs.appendFileSync(process.env.REC_LOG,JSON.stringify(data)+'\\n');
    rec({{phase:'request',id:e.id,tool:e.tool}});
    try {{await fn(e);rec({{phase:'noop',id:e.id,tool:e.tool}})}}
    catch(error){{rec({{phase:'deny',id:e.id,tool:e.tool,reason:error.message}});throw error}}
  }})}}}});
}}}};
"""
    if name == "init-broken":
        plugin = "export default {{{ invalid JS"
    (cfg / "plugins/telltale.js").write_text(plugin)
    env = run.base_env(
        E2E_WORK=run.work,
        OPENCODE_DISABLE_AUTOUPDATE="1",
        OPENCODE_DISABLE_LSP_DOWNLOAD="1",
        OPENCODE_DISABLE_DEFAULT_PLUGINS="1",
        OPENCODE_DISABLE_MODELS_FETCH="1",
        TELLTALE_HOOKS_STATE_DIR=os.path.join(run.dir, "state"),
    )
    # Do not inherit an external provider or proxy. Loopback is the only model.
    for var in (
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    ):
        env[var] = "http://127.0.0.1:9"
    try:
        run.run(
            [
                BIN,
                "run",
                "--standalone",
                "--format",
                "json",
                *(["--auto"] if name != "native-ask" else []),
                "TTHPILOT: follow the scripted steps.",
            ],
            env,
            timeout=120,
        )
    finally:
        run.stop()
    tele = pathlib.Path(run.dir) / "state/telemetry.jsonl"
    records = (
        [json.loads(line) for line in tele.read_text().splitlines()]
        if tele.exists()
        else []
    )
    decisions = [r for r in records if r["kind"] == "decision"]
    receipts = tool_results_seen_by_model(run)
    callbacks = run.records()
    matching = [
        r for r in decisions if "tth.e2e.deny_marker" in r["decision"]["rule_ids"]
    ]
    delivered = [
        r
        for r in matching
        if r["decision"]["returned"]
        and any(r["record_id"] in str(v) for v in receipts.values())
        and any(
            c["phase"] == "deny" and r["record_id"] in c["reason"] for c in callbacks
        )
    ]
    expected = not denied and not native
    present = os.path.exists(run.canary(canary))
    ok = run.exit == 0 and present == expected
    if failure:
        failures = [
            c
            for c in callbacks
            if c["phase"] == "deny"
            and c["reason"] == "Telltale: hook unavailable; tool call denied"
        ]
        ok = ok and (bool(failures) if denied else not failures)
        if name.endswith("lost"):
            ok = ok and bool(matching) and not delivered
    elif denied:
        ok = ok and bool(delivered)
        if nested:
            ok = ok and all(
                r["action"]["tool_name"] == "tthmock_touch_canary" for r in delivered
            )
    elif detect:
        ok = (
            ok
            and bool(matching)
            and all(not r["decision"]["returned"] for r in matching)
        )
    elif name == "init-broken":
        ok = ok and not decisions and not callbacks
    else:
        ok = (
            ok
            and bool(decisions)
            and all(not r["decision"]["returned"] for r in decisions)
        )
    if name == "parallel":
        ok = ok and os.path.exists(run.canary("sibling.txt"))
    if name == "nested-repeat-deny":
        ids = [r["action"]["tool_use_id"] for r in delivered]
        ok = ok and len(ids) == 3 and len(set(ids)) == 3
    summary = {
        "identity": identity,
        "scenario": name,
        "pass": bool(ok),
        "exit": run.exit,
        "canary": "present" if present else "absent",
        "marker_decisions": len(matching),
        "same_decision_receipts": len(delivered),
        "outcomes": sum(r["kind"] == "outcome" for r in records),
        "settlement": "not forwarded; unknown",
        "secs": run.elapsed,
    }
    (pathlib.Path(run.dir) / "summary.json").write_text(
        json.dumps(summary, indent=2) + "\n"
    )
    print(json.dumps(summary), flush=True)
    return ok


if __name__ == "__main__":
    names = sys.argv[1:] or [
        "ordinary-control",
        "ordinary-deny",
        "nested-control",
        "nested-deny",
        "nested-repeat-deny",
        "parallel",
        "detect-only",
        "init-broken",
    ]
    supported = {
        "ordinary-control",
        "ordinary-deny",
        "nested-control",
        "nested-deny",
        "nested-repeat-deny",
        "parallel",
        "detect-only",
        "init-broken",
        "failure-missing",
        "failure-invalid",
        "failure-hang",
        "failure-lost",
        "failure-noop",
        "detect-failure-hang",
        "detect-failure-missing",
        "native-deny",
        "native-ask",
    }
    if any(name not in supported for name in names):
        sys.exit("unknown scenario")
    results = [scenario(name) for name in names]
    sys.exit(0 if all(results) else 1)
