"""The hooks load benchmark: its report, its isolation and its --check bound.

A stand-in executable plays `telltale` here, so these tests are fast and do not
depend on host load. `make hooks-load-bench` runs the real binary.
"""

import json
import os
import pathlib
import subprocess
import sys
import tempfile
import textwrap
import unittest

BENCH = pathlib.Path(__file__).resolve().parents[1] / "scripts/hooks/load-bench.py"

# The stand-in answers every tool call after `delay` seconds with `answer`
# ("deny", "allow" or "fail": exit 1 and print nothing), records the call's
# environment and arguments in `seen`, and writes one decision record whose
# scans took 40 ms of pieces after a 120 ms wait for the session lock, as the
# hook would.
STAND_IN = textwrap.dedent(
    """\
    #!{python}
    import json, os, sys, time
    if sys.argv[1:3] == ["hooks", "version"]:
        print("telltale 9.9.9-test (abc) rev")
        sys.exit(0)
    payload = json.load(sys.stdin)
    time.sleep({delay})
    names = ["HOME", "XDG_CONFIG_HOME", "XDG_STATE_HOME", "XDG_DATA_HOME",
             "XDG_RUNTIME_DIR", "TMPDIR", "TELLTALE_HOOKS_STATE_DIR",
             "TELLTALE_HOOKS_TELEMETRY"]
    with open({seen!r}, "a") as out:
        out.write(json.dumps({{"argv": sys.argv[1:],
                              "env": {{n: os.environ.get(n) for n in names}}}}) + "\\n")
    if {answer!r} == "fail":
        sys.exit(1)
    record = {{
        "kind": "decision",
        "action": {{"tool_use_id": payload["tool_use_id"]}},
        "evaluation": {{"status": "evaluated", "evaluator": "in_process",
                        "build_ms": 500, "scan_ms": 45, "lock_wait_ms": 120,
                        "scans": {{"variants": 0, "whole": None, "together": None,
                                   "history": "skipped_budget",
                                   "pieces_scanned": 3, "pieces_total": 4,
                                   "pieces_refused": 0, "first_refusal": None,
                                   "whole_ms": 0, "together_ms": 0,
                                   "pieces_ms": 40, "history_ms": 5}}}},
        "decision": {{"verdict": {answer!r}, "basis": "action_score"}},
    }}
    telemetry = os.environ["TELLTALE_HOOKS_TELEMETRY"]
    os.makedirs(os.path.dirname(telemetry), exist_ok=True)
    with open(telemetry, "a") as out:
        out.write(json.dumps(record) + "\\n")
    if {answer!r} == "deny":
        print(json.dumps({{"hookSpecificOutput": {{"hookEventName": "PreToolUse",
                                                  "permissionDecision": "deny"}}}}))
    """
)


class LoadBenchTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.dir.name)
        self.seen = self.root / "seen.jsonl"
        self.bench_tmp = self.root / "bench-tmp"
        self.bench_tmp.mkdir()

    def tearDown(self):
        self.dir.cleanup()

    def stand_in(self, answer, delay=0.0):
        path = self.root / "telltale"
        path.write_text(
            STAND_IN.format(
                python=sys.executable, delay=delay, seen=str(self.seen), answer=answer
            )
        )
        path.chmod(0o755)
        return path

    def bench(self, binary, *args):
        env = dict(os.environ, TMPDIR=str(self.bench_tmp))
        return subprocess.run(
            [sys.executable, str(BENCH), "--binary", str(binary), *args],
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
        )

    def test_report_counts_answers_and_scan_phases_of_every_call(self):
        run = self.bench(
            self.stand_in("deny"),
            "--concurrency", "2", "--calls", "2",
            "--payload", "small", "--session", "same", "--evaluator", "off",
            "--check",
        )
        self.assertEqual(run.returncode, 0, run.stderr)
        report = json.loads(run.stdout)
        self.assertEqual(report["telltale_version"], "telltale 9.9.9-test (abc) rev")
        self.assertTrue(report["check"]["passed"])
        [scenario] = report["scenarios"]
        self.assertEqual(scenario["name"], "small/same/off")
        self.assertEqual(scenario["calls"], 4)
        self.assertEqual(scenario["answers"], {"deny": 4})
        self.assertEqual(scenario["unanswered"], 0)
        self.assertEqual(scenario["records"]["decisions"], 4)
        self.assertEqual(scenario["records"]["calls_without_record"], 0)
        self.assertEqual(scenario["records"]["basis"], {"action_score": 4})
        self.assertEqual(scenario["records"]["floored"], 0)
        self.assertEqual(scenario["records"]["hook_deadline"], 0)
        self.assertEqual(scenario["records"]["state_lock_timeout"], 0)
        self.assertEqual(scenario["scans"]["pieces_ms"]["p50"], 40)
        self.assertEqual(
            scenario["lock_wait_ms"], {"p50": 120, "p95": 120, "p99": 120, "max": 120}
        )
        self.assertEqual(scenario["scans"]["history_ms"]["max"], 5)
        self.assertEqual(scenario["scans"]["pieces_scanned"], 12)
        self.assertEqual(scenario["scans"]["pieces_total"], 16)
        self.assertEqual(scenario["scans"]["history"], {"skipped_budget": 4})
        self.assertEqual(scenario["wall_ms"]["over_25s"], 0)
        self.assertEqual(scenario["wall_ms"]["over_30s"], 0)

    def test_report_carries_no_payload_text_and_no_paths(self):
        run = self.bench(
            self.stand_in("deny"),
            "--concurrency", "1", "--calls", "1",
            "--payload", "small,projected,past-budget", "--evaluator", "off",
        )
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertNotIn(str(self.root), run.stdout)
        self.assertNotIn("printf", run.stdout)
        self.assertNotIn("ls -la", run.stdout)
        self.assertEqual(len(json.loads(run.stdout)["scenarios"]), 3)

    def test_hook_processes_see_only_a_temporary_home(self):
        run = self.bench(
            self.stand_in("allow"),
            "--concurrency", "2", "--calls", "1", "--evaluator", "off",
        )
        self.assertEqual(run.returncode, 0, run.stderr)
        calls = [json.loads(line) for line in self.seen.read_text().splitlines()]
        self.assertEqual(len(calls), 3, "one warm-up call and two measured calls")
        for call in calls:
            for name, value in call["env"].items():
                self.assertTrue(
                    value.startswith(str(self.bench_tmp) + "/"), f"{name}={value}"
                )
            for flag in ("--config-dir", "--state-dir"):
                value = call["argv"][call["argv"].index(flag) + 1]
                self.assertTrue(value.startswith(str(self.bench_tmp) + "/"), flag)
        self.assertEqual(list(self.bench_tmp.iterdir()), [], "temporary home removed")

    def test_check_fails_when_a_call_gets_no_answer(self):
        run = self.bench(
            self.stand_in("fail"),
            "--concurrency", "1", "--calls", "2", "--evaluator", "off", "--check",
        )
        self.assertEqual(run.returncode, 1, run.stderr)
        report = json.loads(run.stdout)
        self.assertFalse(report["check"]["passed"])
        self.assertEqual(report["scenarios"][0]["unanswered"], 2)

    def test_check_fails_when_a_call_passes_the_deadline_and_margin(self):
        run = self.bench(
            self.stand_in("allow", delay=0.3),
            "--concurrency", "1", "--calls", "1", "--evaluator", "off",
            "--deadline-ms", "100", "--margin-ms", "50", "--check",
        )
        self.assertEqual(run.returncode, 1, run.stderr)
        report = json.loads(run.stdout)
        self.assertEqual(report["check"]["limit_ms"], 150)
        self.assertEqual(report["scenarios"][0]["wall_ms"]["over_check_limit"], 1)


if __name__ == "__main__":
    unittest.main()
