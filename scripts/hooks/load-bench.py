#!/usr/bin/env python3
"""Drive `telltale hooks claude-code hook` under parallel load and report its time.

Each scenario (payload x session x evaluator) gets a fresh temporary hooks home:
config, rules, state, telemetry, evaluator socket and every location the binary
could fall back to (HOME, XDG_*, TMPDIR) are under one temporary directory, the
environment is not inherited beyond PATH, and the directory is removed at the
end. The user's own hooks configuration, state and journals are never read or
written.

In a scenario, `--concurrency` workers start together and each runs `--calls`
hook processes one after another, every one a PreToolUse Bash call with
synthetic input:

- small: a short command;
- projected: a short command beside 240 values of about 200 bytes, which the
  hook projects into pieces;
- past-budget: a short command beside 3,000 short values, past the projection
  budget.

`--session same` sends every call in one session (they wait for its lock);
`distinct` gives each worker a session of its own. `--evaluator on` autostarts
the long-lived evaluator with a warm-up call and waits for it before measuring;
`off` evaluates in-process. `--cpus 0,1` runs the hooks (and the evaluator they
start) under `taskset -c`, to emulate a small host.

Per call it measures the hook process's wall time and its answer (allow: exit 0
and nothing printed; ask or deny: the printed decision; anything else is no
answer). Afterwards it reads the run's hooks records for the scan phases
(`evaluation.scans`), error codes (`hook_deadline`, `state_lock_timeout`) and
decisions floored at `on_unevaluable` (basis `unevaluable_input`). The session
lock wait is not recorded by the hook, so it is reported as null.

The JSON report goes to stdout (or `--out`), a short table to stderr. It holds
counts, closed codes and times only: no payload text and no paths. `--check`
exits 1 when any call ran past the hook deadline plus the margin (25 s + 5 s by
default, the timeout tool-call hooks are installed with) or ended without an
answer.

    make hooks-load-bench ARGS="--concurrency 8 --calls 4 --check"
    python3 scripts/hooks/load-bench.py --binary target/release/telltale \\
        --payload small,projected --session same,distinct --evaluator on,off
"""

from __future__ import annotations

import argparse
import itertools
import json
import math
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
PAYLOADS = ("small", "projected", "past-budget")
SESSIONS = ("same", "distinct")
EVALUATORS = ("on", "off")
PHASES = ("whole_ms", "together_ms", "pieces_ms", "history_ms")
# A Unix socket path must fit in 108 bytes on Linux and 104 on macOS.
MAX_SOCKET_PATH = 100


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])

    def choices(allowed):
        def parse(value):
            items = value.split(",")
            for item in items:
                if item not in allowed:
                    raise argparse.ArgumentTypeError(f"{item!r} is not one of {', '.join(allowed)}")
            return items

        return parse

    parser.add_argument("--binary", type=Path, default=REPO / "target/release/telltale")
    parser.add_argument("--concurrency", type=int, default=4, help="hook processes at a time")
    parser.add_argument("--calls", type=int, default=4, help="calls per worker")
    parser.add_argument("--payload", type=choices(PAYLOADS), default=["small"])
    parser.add_argument("--session", type=choices(SESSIONS), default=["same"])
    parser.add_argument("--evaluator", type=choices(EVALUATORS), default=["on"])
    parser.add_argument("--cpus", help="run the hooks under taskset -c CPUS, such as 0,1")
    parser.add_argument("--deadline-ms", type=int, default=25_000, help="the hook deadline")
    parser.add_argument("--margin-ms", type=int, default=5_000, help="--check allows this past the deadline")
    parser.add_argument("--timeout-s", type=float, default=120.0, help="kill a hook after this long")
    parser.add_argument("--out", type=Path, help="write the JSON report here instead of stdout")
    parser.add_argument("--check", action="store_true", help="exit 1 if a call passes the limit or gets no answer")
    args = parser.parse_args(argv)
    if args.concurrency < 1 or args.calls < 1:
        parser.error("--concurrency and --calls must be at least 1")
    if args.cpus and not shutil.which("taskset"):
        parser.error("--cpus needs taskset")
    return args


def tool_input(kind: str, worker: int, call: int) -> dict:
    if kind == "small":
        return {"command": f"ls -la src/{worker}/{call}", "description": "List files"}
    if kind == "projected":
        value = " ".join(["item"] * 40)
        return {"command": "ls -la", "meta": {f"k{n:03d}": value for n in range(240)}}
    return {"command": "ls -la", "meta": {f"k{n:04d}": "x" for n in range(3000)}}


class Home:
    """One scenario's temporary hooks home and the hook command run in it."""

    def __init__(self, args: argparse.Namespace, evaluator: bool):
        self.root = Path(tempfile.mkdtemp(prefix="ttlb-"))
        self.state = self.root / "state"
        self.telemetry = self.state / "telemetry.jsonl"
        self.socket = self.root / "run" / "ev.sock"
        if len(str(self.socket)) > MAX_SOCKET_PATH:
            shutil.rmtree(self.root)
            sys.exit("load-bench: the temporary directory path is too long for a socket; set a shorter TMPDIR")
        for name in ("home", "config", "xdg-config", "xdg-state", "xdg-data", "run", "tmp", "work"):
            (self.root / name).mkdir(mode=0o700)
        settings = self.root / "config" / "settings.d"
        settings.mkdir()
        (settings / "hooks.yaml").write_text(
            "version: 1\n"
            "hooks:\n"
            "  mode: enforce\n"
            f"  state_dir: {json.dumps(str(self.state))}\n"
            f"  telemetry_path: {json.dumps(str(self.telemetry))}\n"
            "  evaluator:\n"
            f"    enabled: {'true' if evaluator else 'false'}\n"
            "    autostart: true\n"
            "    idle_timeout_secs: 300\n"
            f"    socket: {json.dumps(str(self.socket))}\n"
        )
        self.env = {
            "PATH": os.environ.get("PATH", os.defpath),
            "HOME": str(self.root / "home"),
            "XDG_CONFIG_HOME": str(self.root / "xdg-config"),
            "XDG_STATE_HOME": str(self.root / "xdg-state"),
            "XDG_DATA_HOME": str(self.root / "xdg-data"),
            "XDG_RUNTIME_DIR": str(self.root / "run"),
            "TMPDIR": str(self.root / "tmp"),
            "TELLTALE_HOOKS_STATE_DIR": str(self.state),
            "TELLTALE_HOOKS_TELEMETRY": str(self.telemetry),
            "TELLTALE_HOOKS_EVALUATOR": "1" if evaluator else "0",
        }
        prefix = ["taskset", "-c", args.cpus] if args.cpus else []
        self.command = prefix + [
            str(args.binary.resolve()), "hooks", "claude-code", "hook",
            "--config-dir", str(self.root / "config"), "--state-dir", str(self.state),
        ]
        self.timeout = args.timeout_s

    def payload(self, session: str, tool_use_id: str, tool: dict) -> bytes:
        return json.dumps({
            "session_id": session,
            "transcript_path": str(self.root / "home" / "transcripts" / f"{session}.jsonl"),
            "cwd": str(self.root / "work"),
            "permission_mode": "default",
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": tool,
            "tool_use_id": tool_use_id,
        }).encode()

    def call(self, payload: bytes) -> tuple[int, str]:
        """One hook process: its wall time in ms and its answer."""
        started = time.perf_counter()
        child = subprocess.Popen(
            self.command, env=self.env, cwd=self.root / "work",
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        )
        try:
            stdout, _ = child.communicate(payload, timeout=self.timeout)
        except subprocess.TimeoutExpired:
            child.kill()
            child.communicate()
            return round((time.perf_counter() - started) * 1000), "none"
        wall = round((time.perf_counter() - started) * 1000)
        if child.returncode != 0:
            return wall, "none"
        if not stdout.strip():
            return wall, "allow"
        try:
            decision = json.loads(stdout)["hookSpecificOutput"]["permissionDecision"]
        except (ValueError, KeyError, TypeError):
            return wall, "none"
        return wall, decision if decision in ("allow", "ask", "deny") else "none"

    def wait_for_evaluator(self) -> bool:
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            try:
                with socket.socket(socket.AF_UNIX) as probe:
                    probe.connect(str(self.socket))
                return True
            except OSError:
                time.sleep(0.1)
        return False

    def close(self) -> None:
        """Stop the evaluator this home started, then remove the home."""
        try:
            pid = int((self.state / "evaluator.pid").read_text())
            # Only a process that names this home is this home's evaluator.
            proc = Path(f"/proc/{pid}/cmdline")
            if not proc.parent.parent.is_dir() or str(self.root).encode() in proc.read_bytes():
                os.kill(pid, signal.SIGTERM)
                for _ in range(50):
                    os.kill(pid, 0)
                    time.sleep(0.1)
                os.kill(pid, signal.SIGKILL)
        except (OSError, ValueError):
            pass
        shutil.rmtree(self.root, ignore_errors=True)


def percentiles(values: list[int]) -> dict | None:
    if not values:
        return None
    ordered = sorted(values)

    def rank(p):
        return ordered[max(0, math.ceil(p / 100 * len(ordered)) - 1)]

    return {"p50": rank(50), "p95": rank(95), "p99": rank(99), "max": ordered[-1]}


def run_scenario(args, payload_kind: str, session_mode: str, evaluator: str) -> dict:
    home = Home(args, evaluator == "on")
    try:
        # A warm-up call in a session of its own: page cache, and with the
        # evaluator on, the autostart the measured calls then use.
        home.call(home.payload("ttlb-warm", "toolu_ttlb_warm", tool_input("small", 0, 0)))
        evaluator_ready = home.wait_for_evaluator() if evaluator == "on" else None
        results: dict[str, tuple[int, str]] = {}
        start = threading.Barrier(args.concurrency)

        def worker(w: int) -> None:
            session = "ttlb-session" if session_mode == "same" else f"ttlb-session-{w:03d}"
            start.wait()
            for c in range(args.calls):
                tool_use_id = f"toolu_ttlb_{w:03d}_{c:04d}"
                results[tool_use_id] = home.call(home.payload(session, tool_use_id, tool_input(payload_kind, w, c)))

        threads = [threading.Thread(target=worker, args=(w,)) for w in range(args.concurrency)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        records = read_records(home.telemetry, results.keys())
    finally:
        home.close()
    return summarize(args, f"{payload_kind}/{session_mode}/{evaluator}", results, records, evaluator_ready)


def read_records(path: Path, ids) -> list[dict]:
    wanted = set(ids)
    records = []
    try:
        lines = path.read_text().splitlines()
    except OSError:
        return records
    for line in lines:
        try:
            record = json.loads(line)
        except ValueError:
            continue
        if ((record.get("action") or {}).get("tool_use_id")) in wanted:
            records.append(record)
    return records


def summarize(args, name: str, results: dict, records: list[dict], evaluator_ready) -> dict:
    walls = [wall for wall, _ in results.values()]
    limit = args.deadline_ms + args.margin_ms
    decisions = [r for r in records if r.get("kind") == "decision"]
    errors = Counter(r.get("error_code") for r in records if r.get("kind") == "error")
    recorded = {(r.get("action") or {}).get("tool_use_id") for r in records}
    basis = Counter((r.get("decision") or {}).get("basis") for r in decisions)
    evaluations = [r.get("evaluation") or {} for r in decisions]
    scans = [e["scans"] for e in evaluations if e.get("scans")]
    return {
        "name": name,
        "calls": len(results),
        "evaluator_ready": evaluator_ready,
        "answers": dict(Counter(answer for _, answer in results.values() if answer != "none")),
        "unanswered": sum(1 for _, answer in results.values() if answer == "none"),
        "wall_ms": {
            **(percentiles(walls) or {}),
            "over_25s": sum(1 for w in walls if w > 25_000),
            "over_30s": sum(1 for w in walls if w > 30_000),
            "over_check_limit": sum(1 for w in walls if w > limit),
        },
        "lock_wait_ms": None,
        "records": {
            "decisions": len(decisions),
            "calls_without_record": sum(1 for i in results if i not in recorded),
            "basis": dict(basis),
            "floored": basis.get("unevaluable_input", 0),
            "error_codes": dict(errors),
            "hook_deadline": errors.get("hook_deadline", 0),
            "state_lock_timeout": errors.get("state_lock_timeout", 0),
            "status": dict(Counter(e.get("status") for e in evaluations)),
            "visibility_limits": dict(Counter(v for e in evaluations for v in e.get("visibility_limits") or [])),
            "evaluator": dict(Counter(e.get("evaluator") for e in evaluations)),
            "evaluator_fallback": dict(Counter(e["evaluator_fallback"] for e in evaluations if e.get("evaluator_fallback"))),
        },
        "build_ms": percentiles([e["build_ms"] for e in evaluations if e.get("build_ms") is not None]),
        "scan_ms": percentiles([e["scan_ms"] for e in evaluations if e.get("scan_ms") is not None]),
        "scans": {
            **{phase: percentiles([s.get(phase, 0) for s in scans]) for phase in PHASES},
            "pieces_scanned": sum(s.get("pieces_scanned", 0) for s in scans),
            "pieces_total": sum(s.get("pieces_total", 0) for s in scans),
            "pieces_refused": sum(s.get("pieces_refused", 0) for s in scans),
            "first_refusal": dict(Counter(s["first_refusal"] for s in scans if s.get("first_refusal"))),
            "whole": dict(Counter(str(s.get("whole") or "not_run") for s in scans)),
            "together": dict(Counter(str(s.get("together") or "not_run") for s in scans)),
        },
    }


def version(binary: Path) -> str | None:
    try:
        with tempfile.TemporaryDirectory(prefix="ttlb-") as empty:
            out = subprocess.run(
                [str(binary.resolve()), "hooks", "version"], capture_output=True, text=True, timeout=30,
                cwd=empty, env={"PATH": os.environ.get("PATH", os.defpath), "HOME": empty},
            )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return out.stdout.strip().splitlines()[0] if out.returncode == 0 and out.stdout.strip() else None


def table(report: dict) -> str:
    rows = ["scenario                       calls  p50ms  p95ms  p99ms  maxms  noans  deadl  lockto  floor  >25s  >30s"]
    for s in report["scenarios"]:
        w, r = s["wall_ms"], s["records"]
        rows.append(
            f"{s['name']:30} {s['calls']:5} {w.get('p50', 0):6} {w.get('p95', 0):6} {w.get('p99', 0):6} {w.get('max', 0):6}"
            f" {s['unanswered']:6} {r['hook_deadline']:6} {r['state_lock_timeout']:7} {r['floored']:6} {w['over_25s']:5} {w['over_30s']:5}"
        )
    check = report["check"]
    rows.append(f"check: {'passed' if check['passed'] else 'FAILED'} (limit {check['limit_ms']} ms, answer required)")
    return "\n".join(rows)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    host = {
        "cpus": os.cpu_count(),
        "affinity_cpus": len(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity") else None,
        "load_start": list(os.getloadavg()),
    }
    scenarios = [
        run_scenario(args, payload, session, evaluator)
        for payload, session, evaluator in itertools.product(args.payload, args.session, args.evaluator)
    ]
    host["load_end"] = list(os.getloadavg())
    limit = args.deadline_ms + args.margin_ms
    passed = all(s["unanswered"] == 0 and s["wall_ms"]["over_check_limit"] == 0 for s in scenarios)
    report = {
        "schema": "telltale.hooks_load_bench.v1",
        "telltale_version": version(args.binary),
        "host": host,
        "parameters": {
            "harness": "claude-code",
            "concurrency": args.concurrency,
            "calls": args.calls,
            "payload": args.payload,
            "session": args.session,
            "evaluator": args.evaluator,
            "cpus": args.cpus,
            "deadline_ms": args.deadline_ms,
            "margin_ms": args.margin_ms,
            "timeout_s": args.timeout_s,
        },
        "check": {"limit_ms": limit, "passed": passed},
        "scenarios": scenarios,
    }
    text = json.dumps(report, indent=2)
    if args.out:
        args.out.write_text(text + "\n")
    else:
        print(text)
    print(table(report), file=sys.stderr)
    if any(s["evaluator_ready"] is False for s in scenarios):
        print("warning: the evaluator did not start; those calls evaluated in-process (see evaluator_fallback)", file=sys.stderr)
    return 1 if args.check and not passed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
