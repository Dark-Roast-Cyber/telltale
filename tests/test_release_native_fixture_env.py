"""Synthetic release verifier subprocess isolation (no downloaded or live artifacts)."""

import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tarfile
import tempfile
import unittest


REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "scripts/release-native-verify"
TARGET = "x86_64-unknown-linux-gnu"


class FixtureEnvironmentTests(unittest.TestCase):
    @unittest.skipUnless(
        platform.system() == "Linux" and platform.machine() == "x86_64",
        "native Linux fixture",
    )
    def test_positive_fixture_scan_excludes_inherited_project_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            downloads = root / "downloads"
            downloads.mkdir()
            second_store = root / "second-synthetic-store"
            second_store.mkdir()
            (second_store / "synthetic-session.jsonl").write_text("synthetic\n")
            config = root / "project.yaml"
            config.write_text(f"projects:\n  - name: synthetic\n    path: {second_store}\n")
            marker = root / "second-store-visited"
            rules_marker = root / "rules-parent-env"
            payload = root / "payload"
            payload.mkdir()
            binary = payload / "telltale"
            # The fake binary models the CLI's inherited project-config input;
            # it records the second source only if the fixture child receives it.
            binary.write_text(
                "#!/usr/bin/env python3\n"
                "import json, os, pathlib, sys\n"
                "if sys.argv[1] == '--version':\n"
                " print('telltale 0.6.0-rc.3 (db9cf63434a6)')\n"
                "elif sys.argv[1] == 'rules' and os.environ.get('TELLTALE_PROJECT_CONFIG'):\n"
                " pathlib.Path(os.environ['RULES_PARENT_MARKER']).write_text(os.environ['TELLTALE_PROJECT_CONFIG'])\n"
                "elif sys.argv[1] == 'scan':\n"
                " if os.environ.get('TELLTALE_PROJECT_CONFIG'):\n"
                "  source = pathlib.Path(os.environ['TELLTALE_PROJECT_CONFIG']).read_text().split('path: ', 1)[1].strip()\n"
                "  pathlib.Path(os.environ['SECOND_SOURCE_MARKER']).write_text(pathlib.Path(source, 'synthetic-session.jsonl').read_text())\n"
                " log = pathlib.Path(sys.argv[sys.argv.index('--log-path') + 1])\n"
                " log.write_text(json.dumps({'event_type':'detection','session_id':'uc001-positive',"
                "'rule_ids':['mcp.tool_metadata.prompt_injection'],'schema_version':'3.0',"
                "'telltale_version':'0.6.0-rc.3'}) + '\\n')\n"
            )
            binary.chmod(0o755)
            pin = json.loads((REPO / "scripts/release-native-verify-rc3.json").read_text())
            archive_name = pin["targets"][TARGET]["archive"]
            archive = downloads / archive_name
            with tarfile.open(archive, "w:gz") as bundle:
                bundle.add(binary, arcname="telltale")
            digest = hashlib.sha256(archive.read_bytes()).hexdigest()
            pin["targets"][TARGET]["archive_sha256"] = digest
            pin["targets"][TARGET]["binary_sha256"] = hashlib.sha256(binary.read_bytes()).hexdigest()
            pin_path = root / "pin.json"
            pin_path.write_text(json.dumps(pin))
            (downloads / "SHA256SUMS").write_text(f"{digest}  {archive_name}\n")
            metadata = root / "release.json"
            metadata.write_text(json.dumps({
                "id": pin["release_id"], "tag_name": pin["release_tag"],
                "draft": False, "prerelease": True,
                "assets": [{"name": archive_name, "digest": f"sha256:{digest}"}],
            }))
            helper = root / "helper.py"
            helper.write_text("pass\n")
            validator = root / "validator.py"
            validator.write_text("pass\n")
            env = {**os.environ, "RUNNER_LABEL": "ubuntu-latest", "TELLTALE_PROJECT_CONFIG": str(config),
                   "SECOND_SOURCE_MARKER": str(marker), "RULES_PARENT_MARKER": str(rules_marker)}
            result = subprocess.run([
                sys.executable, str(SCRIPT), "--repo-root", str(REPO), "--pin", str(pin_path),
                "--target", TARGET, "--release-metadata", str(metadata), "--download-dir", str(downloads),
                "--manifest-helper", str(helper), "--event-validator", str(validator),
            ], env=env, text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("positive_fixture=PASS", result.stdout)
            self.assertFalse(marker.exists(), "fixture child accessed inherited second synthetic source")
            self.assertEqual(rules_marker.read_text(), str(config))
            self.assertEqual(env["TELLTALE_PROJECT_CONFIG"], str(config))
            self.assertEqual(config.read_text(), f"projects:\n  - name: synthetic\n    path: {second_store}\n")


if __name__ == "__main__":
    unittest.main()
