#!/usr/bin/env bash
# End-to-end wall time of one `telltale hooks claude-code hook` process per
# event (what Claude Code waits for), using an authentic captured payload shape.
# Usage: scripts/bench-hook.sh [iterations]
set -euo pipefail
repo=$(cd "$(dirname "$0")/../.." && pwd)
bin=${TTH_BIN:-$repo/target/release/telltale}
n=${1:-20}
state=$(mktemp -d)
template=$(grep '"PreToolUse"' "$repo/crates/telltale/tests/hooks/fixtures/claude-code/2.1.318/tool-lifecycle-subagent.jsonl" | head -1)
python3 - "$bin" "$n" "$state" "$template" <<'PY'
import json, os, statistics, subprocess, sys, time
binary, n, state, template = sys.argv[1], int(sys.argv[2]), sys.argv[3], json.loads(sys.argv[4])
env = dict(os.environ, TELLTALE_HOOKS_STATE_DIR=state)
env.pop("TELLTALE_HOOKS_CONFIG", None)
mode = os.environ.get("BENCH_EVALUATOR", "0")  # "1": long-lived evaluator, "0": in-process
env["TELLTALE_HOOKS_EVALUATOR"] = mode
daemon = None
if mode == "1":
    import socket as sk
    daemon = subprocess.Popen([binary, "hooks", "serve"], env=env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    sock = os.path.join(state, "evaluator.sock")
    for _ in range(600):
        try:
            s = sk.socket(sk.AF_UNIX); s.connect(sock); s.close(); break
        except OSError:
            time.sleep(0.05)
print(f"evaluator: {'daemon' if mode == '1' else 'in-process'}")
def run(event, command, i):
    p = dict(template, hook_event_name=event, tool_use_id=f"toolu_bench_{i}", tool_input={"command": command})
    if event == "PostToolUse":
        p["tool_response"] = {"stdout": "ok", "stderr": "", "interrupted": False}
    t = time.perf_counter()
    subprocess.run([binary, "hooks", "claude-code", "hook"], input=json.dumps(p).encode(), env=env, capture_output=True, check=True)
    return (time.perf_counter() - t) * 1000
pre, post = [], []
for i in range(n):
    pre.append(run("PreToolUse", f"ls -la src/{i}", i))
    post.append(run("PostToolUse", f"ls -la src/{i}", i))
lifecycle = []
for i in range(n):
    p = dict(template, hook_event_name="SubagentStart", agent_id="a1", agent_type="general-purpose")
    t = time.perf_counter()
    subprocess.run([binary, "hooks", "claude-code", "hook"], input=json.dumps(p).encode(), env=env, capture_output=True, check=True)
    lifecycle.append((time.perf_counter() - t) * 1000)
if daemon:
    daemon.kill()
for name, xs in (("PreToolUse", pre), ("PostToolUse", post), ("SubagentStart (no evaluation)", lifecycle)):
    xs = sorted(xs)
    print(f"{name:32} n={len(xs)} p50={statistics.median(xs):.0f}ms p95={xs[int(len(xs)*0.95)-1]:.0f}ms max={xs[-1]:.0f}ms")
PY
rm -rf "$state"
