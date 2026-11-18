"""Qualification must reject missing, unrelated and unreceived marker denials."""

import importlib.util
import pathlib
import os
import subprocess
import sys
import tempfile
import unittest

PATH = (
    pathlib.Path(__file__).resolve().parents[1]
    / "scripts/hooks/harness/qualification.py"
)
spec = importlib.util.spec_from_file_location("qualification", PATH)
qualification = importlib.util.module_from_spec(spec)
spec.loader.exec_module(qualification)


class QualificationTests(unittest.TestCase):
    def test_opencode_driver_rejects_unrecognized_scenario_before_execution(self):
        with tempfile.TemporaryDirectory() as root:
            output = subprocess.run(
                [
                    sys.executable,
                    str(PATH.with_name("opencode-v2-e2e.py")),
                    "../outside",
                ],
                env={
                    "PATH": os.defpath,
                    "E2E_ROOT": root + "/uncreated",
                    "OPENCODE_V2_BIN": "/nonexistent/unused-client",
                },
                capture_output=True,
                text=True,
            )
            self.assertEqual(output.returncode, 1)
            self.assertEqual(output.stderr, "unknown scenario\n")
            self.assertFalse(pathlib.Path(root, "uncreated").exists())

    def test_claude_driver_rejects_unrecognized_scenario_before_execution(self):
        with tempfile.TemporaryDirectory() as root:
            output = subprocess.run(
                [
                    sys.executable,
                    str(PATH.with_name("claude-code-scripted-e2e.py")),
                    "../outside",
                ],
                env={
                    "PATH": os.defpath,
                    "E2E_ROOT": root + "/uncreated",
                    "CLAUDE_BIN": "/nonexistent/unused-client",
                },
                capture_output=True,
                text=True,
            )
            self.assertEqual(output.returncode, 1)
            self.assertEqual(
                output.stderr, "unknown scenario (expected benign or deny)\n"
            )
            self.assertFalse(pathlib.Path(root, "uncreated").exists())

    def setUp(self):
        self.decision = {
            "kind": "decision",
            "record_id": "record-one",
            "action": {
                "tool_name": "bash",
                "input_sha256": "dbd206b2172f455a91b07e2416862165e116d1336a465e6f73c27e29bc9946fe",
            },
            "decision": {
                "returned": True,
                "verdict": "deny",
                "rule_ids": ["tth.e2e.deny_marker"],
            },
        }
        self.outcome = {
            "kind": "outcome",
            "outcome": {
                "decision_record_id": "record-one",
                "result": "not_executed",
                "enforcement": "honored",
            },
        }
        self.invocation = {
            "exit": 0,
            "stdout": "deny record-one",
            "payload": {
                "toolName": "bash",
                "toolArgs": {"command": "touch /synthetic/canary"},
            },
        }

    def test_receipt_and_settlement_join_the_returned_marker(self):
        result = qualification.command_pair_evidence(
            [self.decision, self.outcome],
            [self.invocation],
            {"call-one": "blocked record-one"},
            "/synthetic/canary",
            denied=True,
        )
        self.assertTrue(result["matched"])

    def test_arguments_sent_as_a_json_string_join_on_the_hash_of_that_string(self):
        self.invocation["payload"]["toolArgs"] = (
            '{"command": "touch /synthetic/canary"}'
        )
        self.decision["action"]["input_sha256"] = (
            "c12f638317c7e861045c464f26bb13447bd19eba33768bca07b9edea3d098b99"
        )
        result = qualification.command_pair_evidence(
            [self.decision, self.outcome],
            [self.invocation],
            {"call-one": "blocked record-one"},
            "/synthetic/canary",
            denied=True,
        )
        self.assertTrue(result["matched"])

    def test_missing_attempt_is_not_prevention(self):
        self.assertFalse(
            qualification.command_pair_evidence(
                [self.decision, self.outcome],
                [],
                {"call-one": "blocked record-one"},
                "/synthetic/canary",
                denied=True,
            )["matched"]
        )

    def test_unrelated_settlement_does_not_prove_prevention(self):
        self.outcome["outcome"]["decision_record_id"] = "other"
        self.assertFalse(
            qualification.command_pair_evidence(
                [self.decision, self.outcome],
                [self.invocation],
                {"call-one": "blocked record-one"},
                "/synthetic/canary",
                denied=True,
            )["matched"]
        )

    def test_unrelated_attempt_does_not_join_a_marker_decision(self):
        self.invocation["payload"]["toolArgs"]["command"] = (
            "touch /synthetic/canary && echo other"
        )
        self.assertFalse(
            qualification.command_pair_evidence(
                [self.decision, self.outcome],
                [self.invocation],
                {"call-one": "blocked record-one"},
                "/synthetic/canary",
                denied=True,
            )["matched"]
        )

    def test_lost_reply_does_not_prove_delivery(self):
        self.assertFalse(
            qualification.command_pair_evidence(
                [self.decision, self.outcome],
                [self.invocation],
                {},
                "/synthetic/canary",
                denied=True,
            )["matched"]
        )


if __name__ == "__main__":
    unittest.main()
