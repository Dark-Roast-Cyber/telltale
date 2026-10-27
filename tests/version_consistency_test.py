"""Synthetic tests of the authoritative release-version gate (Python 3.11+)."""
import copy
import json
import pathlib
import runpy
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
GATE = runpy.run_path(str(ROOT / "scripts/version-consistency-check"))


class VersionConsistency(unittest.TestCase):
    def test_stable_and_rc_exact_matching(self):
        check = GATE["validate_release"]
        check("0.6.0", ["v0.5.0"], "v0.6.0")
        check("0.6.0-rc.1", ["v0.5.0"], "v0.6.0-rc.1")
        check("0.6.0", ["v0.5.0"])

    def test_tag_mismatches_and_malformed_versions_fail(self):
        for version, tag in [
            ("0.6.0", "v0.5.0"), ("0.6.0", "v0.6.0-rc.1"),
            ("0.6.0-rc.1", "v0.7.0-rc.1"),
            ("0.6.0-rc.1", "v0.6.0-rc.2"),
            ("0.6.0", "v0.6.0+build"), ("0.6.0-rc.01", None),
        ]:
            with self.subTest(version=version, tag=tag), self.assertRaises(ValueError):
                GATE["validate_release"](version, ["v0.5.0"], tag)

    def test_published_floor_advances_without_a_ledger_edit(self):
        for version, tags in [
            ("0.5.0", ["v0.5.0"]), ("0.4.0", ["v0.5.0"]),
            ("0.6.0", ["v0.5.0", "v0.6.0"]),
            ("0.6.0-rc.1", ["v0.6.0"]), ("0.6.0", []),
            ("0.6.0-rc.1", ["v0.5.0", "v0.6.0-rc.1"]),
        ]:
            with self.subTest(version=version, tags=tags), self.assertRaises(ValueError):
                GATE["validate_release"](version, tags)
        GATE["validate_release"]("0.7.0", ["v0.5.0", "v0.6.0"])

    def test_release_tag_exclusion_requires_exact_head_identity(self):
        with self.assertRaises(ValueError):
            GATE["release_history"]({"v0.5.0": "old", "v0.6.0": "other"},
                                    "head", "v0.6.0")
        self.assertEqual(
            GATE["release_history"]({"v0.5.0": "old", "v0.6.0": "head"},
                                    "head", "v0.6.0"), ["v0.5.0"])
        self.assertEqual(
            GATE["release_history"]({"v0.6.0": "head"}, "head", None),
            ["v0.6.0"])

    def test_members_pins_lock_and_graph(self):
        packages = {
            "schema": {"version": "0.6.0", "publish": None, "manifest_path": "/schema/Cargo.toml", "dependencies": []},
            "cli": {"version": "0.6.0", "publish": None, "manifest_path": "/cli/Cargo.toml", "dependencies": [
                {"name": "schema", "req": "=0.6.0", "path": "/schema", "kind": "build"}]},
            "console": {"version": "0.6.0", "publish": [], "manifest_path": "/console/Cargo.toml", "dependencies": [
                {"name": "cli", "req": "=0.6.0", "path": "/cli", "kind": "dev"}]},
        }
        lock = {"package": [{"name": name, "version": "0.6.0"} for name in packages]}
        graph = GATE["validate_packages"]("0.6.0", packages, lock)
        self.assertEqual(GATE["publication_order"](packages, graph), ["schema", "cli"])
        GATE["validate_order"](["schema", "cli"], packages, graph)
        for order in [["cli", "schema"], ["schema"], ["schema", "cli", "console"], ["schema", "cli", "cli"]]:
            with self.subTest(order=order), self.assertRaises(ValueError):
                GATE["validate_order"](order, packages, graph)
        for mutation in ("version", "req", "path", "lock", "source"):
            p, l = copy.deepcopy(packages), copy.deepcopy(lock)
            if mutation == "version":
                p["console"]["version"] = "0.5.0"
            elif mutation in ("req", "path"):
                p["cli"]["dependencies"][0][mutation] = "wrong"
            elif mutation == "lock":
                l["package"][0]["version"] = "0.5.0"
            else:
                l["package"][0]["source"] = "registry+synthetic"
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                GATE["validate_packages"]("0.6.0", p, l)
        graph["schema"].add("cli")
        with self.assertRaises(ValueError):
            GATE["publication_order"](packages, graph)

    def test_embedding_msrv_covers_the_facade_build_graph(self):
        packages = {
            "telltale-core": {"dependencies": [
                {"name": "schema", "kind": None}, {"name": "helper", "kind": "dev"},
                {"name": "serde", "kind": None}]},
            "schema": {"dependencies": [{"name": "build-helper", "kind": "build"}]},
            "build-helper": {"dependencies": []},
            "helper": {"dependencies": []},
            "cli": {"dependencies": [{"name": "telltale-core", "kind": None}]},
        }
        self.assertEqual(GATE["embedding_members"](packages),
                         {"telltale-core", "schema", "build-helper"})
        inherit = {"workspace": True}
        declared = {"telltale-core": inherit, "schema": inherit, "build-helper": inherit}
        check = GATE["validate_embedding_msrv"]
        check("1.85", declared, packages, "1.85")
        check("1.85.0", declared, packages, "1.85.0")
        for msrv, members, consumer in [
            (None, declared, None), ("1.85.x", declared, "1.85.x"),
            ("1.85", {**declared, "build-helper": "1.85"}, "1.85"),
            ("1.85", {**declared, "schema": None}, "1.85"),
            ("1.85", declared, "1.88"), ("1.85", declared, None),
        ]:
            with self.subTest(msrv=msrv, members=members, consumer=consumer), \
                    self.assertRaises(ValueError):
                check(msrv, members, packages, consumer)
        with self.assertRaisesRegex(ValueError, "embedding member missing"):
            GATE["embedding_members"]({"cli": {"dependencies": []}})

    def test_embedding_msrv_reads_workspace_members_and_consumer(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "core").mkdir()
            (root / "tests/embedding-consumer").mkdir(parents=True)
            (root / "Cargo.toml").write_text('[workspace.package]\nrust-version = "1.85"\n')
            core = root / "core/Cargo.toml"
            consumer = root / "tests/embedding-consumer/Cargo.toml"
            packages = {"telltale-core": {"manifest_path": str(core), "dependencies": []}}
            check = GATE["check_embedding_msrv"]
            core.write_text('[package]\nrust-version.workspace = true\n')
            consumer.write_text('[package]\nrust-version = "1.85"\n')
            self.assertEqual(check(root, packages), ("1.85", ["telltale-core"]))
            consumer.write_text('[package]\nrust-version = "1.88"\n')
            with self.assertRaisesRegex(ValueError, "consumer rust-version drift"):
                check(root, packages)
            consumer.write_text('[package]\nrust-version = "1.85"\n')
            core.write_text('[package]\nrust-version = "1.85"\n')
            with self.assertRaisesRegex(ValueError, "inherit the workspace rust-version"):
                check(root, packages)

    def test_real_preflight_tag_review_rejects_drift(self):
        result = subprocess.run(
            ["make", "--silent", "release-tag-review", "PUBLIC_RELEASE_TAG=v999.0.0"],
            cwd=ROOT, capture_output=True, text=True, check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not match package", result.stdout + result.stderr)
        makefile = (ROOT / "Makefile").read_text()
        self.assertIn("release-tag-review", makefile.split("release-preflight:", 1)[1].splitlines()[0])

    def test_manifest_inheritance_and_unused_shared_pin_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            package = {"id": "synthetic", "name": "synthetic", "version": "0.6.0",
                       "manifest_path": str(root / "Cargo.toml"),
                       "dependencies": [], "publish": None}
            metadata = {"workspace_members": ["synthetic"], "packages": [package]}
            (root / "Cargo.lock").write_text(
                '[[package]]\nname = "synthetic"\nversion = "0.6.0"\n')
            base = ('[workspace.package]\nversion = "0.6.0"\n'
                    '[package]\nname = "synthetic"\nversion.workspace = true\n')
            load = GATE["load_workspace"]
            with patch.dict(load.__globals__, {"run": lambda *_: json.dumps(metadata)}):
                (root / "Cargo.toml").write_text(base)
                self.assertEqual(load(root)[0], "0.6.0")
                (root / "Cargo.toml").write_text(base.replace(
                    'version.workspace = true', 'version = "0.6.0"'))
                with self.assertRaisesRegex(ValueError, "must inherit"):
                    load(root)
                (root / "Cargo.toml").write_text(base +
                    '[workspace.dependencies]\n'
                    'synthetic = { path = ".", version = "=0.5.0" }\n')
                with self.assertRaisesRegex(ValueError, "shared internal"):
                    load(root)

    def test_shallow_history_is_not_treated_as_no_published_release(self):
        main = GATE["main"]
        with patch.object(sys, "argv", ["version-consistency-check"]), patch.dict(
            main.__globals__, {"load_workspace": lambda _: ("0.6.0", {}, {}),
                               "run": lambda *_: "true"}
        ), self.assertRaisesRegex(ValueError, "shallow history"):
            main()


if __name__ == "__main__":
    unittest.main()
