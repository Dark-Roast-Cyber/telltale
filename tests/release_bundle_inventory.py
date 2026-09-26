"""Synthetic repository-side release inventory and archive regressions."""

import importlib.machinery
import importlib.util
import io
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile
import unittest
import zipfile


ROOT = Path(__file__).resolve().parents[1]
loader = importlib.machinery.SourceFileLoader(
    "release_artifact_manifest", str(ROOT / "scripts/release-artifact-manifest")
)
helper = importlib.util.module_from_spec(importlib.util.spec_from_loader(loader.name, loader))
loader.exec_module(helper)


class BundleInventoryTests(unittest.TestCase):
    def test_canonical_identity_gate_reads_inventory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            workflow = root / ".github/workflows/release.yml"
            workflow.parent.mkdir(parents=True)
            workflow.write_text("target/synthetic/release/telltale\n")
            examples = root / "config/examples"
            examples.mkdir(parents=True)
            for name in ("telltale-scan.service", "telltale-scan.timer", "telltale-scan-task.xml"):
                (examples / name).touch()
            inventory = root / "release/bundle.tsv"
            inventory.parent.mkdir()
            canonical = "config/examples/telltale-scan.service"
            for output, source, mode, accepted in (
                (canonical, canonical, "0644", True),
                (canonical + ".extra", canonical, "0644", False),
                ("README.md", canonical, "0644", False),
                (canonical, "README.md", "0644", False),
                (canonical, canonical, "0755", False),
            ):
                with self.subTest(output=output, source=source, mode=mode):
                    inventory.write_text(f"{output}\t{source}\t{mode}\n")
                    result = subprocess.run(
                        ["make", "-f", str(ROOT / "Makefile"), "CARGO_LOCKED=--locked", "release-canonical-identity-check"],
                        cwd=root, capture_output=True,
                    )
                    self.assertEqual(result.returncode == 0, accepted, result.stderr.decode())

    def test_inventory_reconciles_standalone_installer(self):
        installer = (ROOT / "scripts/install-telltale").read_text()
        embedded = re.search(r"declare -a canonical_archive_members=\((.*?)\)", installer, re.S)
        rows = helper.load_inventory()
        self.assertEqual([row[0] for row in rows], embedded[1].split())
        self.assertEqual(len(rows), 9)
        self.assertEqual(rows[0], ("telltale", "{binary}", 0o755))
        self.assertEqual(rows[2], ("README.md", "release/README.md", 0o644))
        self.assertEqual(helper.load_inventory(windows=True)[0][0], "telltale.exe")

    def test_malformed_inventory_fails_closed(self):
        text = (ROOT / "release/bundle.tsv").read_text()
        mutations = [
            text + text.splitlines()[1] + "\n",
            text.replace("LICENSE\tLICENSE", "README.md\tLICENSE"),
            text.replace("LICENSE\tLICENSE", "../LICENSE\tLICENSE"),
            text.replace("LICENSE\tLICENSE", "LICENSE\t/absolute"),
            text.replace("LICENSE\tLICENSE", "LICENSE\tconfig/../LICENSE"),
            text.replace("LICENSE\tLICENSE", "LICENSE\tC:\\LICENSE"),
            text.replace("LICENSE\tLICENSE", "--option\tLICENSE"),
            text.replace("0644", "0777", 1),
            text.replace("{binary}", "{unknown}", 1),
            text.replace("\t", " ", 1),
            "\n".join(text.splitlines()[:-1]) + "\n",
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bundle.tsv"
            for bad in mutations:
                with self.subTest(inventory=bad):
                    path.write_text(bad)
                    with self.assertRaises(SystemExit):
                        helper.load_inventory(path)

    def test_stage_maps_release_readme_and_modes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "source"
            root.mkdir()
            binary = root / "synthetic-binary"
            binary.write_bytes(b"synthetic executable\n")
            (root / "README.md").write_text("wrong repository readme\n")
            for _, source, _ in helper.load_inventory()[1:]:
                path = root / source
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(f"synthetic {source}\n")
            for windows in (False, True):
                bundle = Path(directory) / str(windows)
                helper.stage_bundle(binary, bundle, windows=windows, root=root)
                self.assertEqual((bundle / "README.md").read_text(), "synthetic release/README.md\n")
                for name, _, mode in helper.load_inventory(windows=windows):
                    self.assertEqual((bundle / name).stat().st_mode & 0o777, mode)
                if not windows:
                    members = subprocess.check_output(
                        ["python3", str(ROOT / "scripts/release-artifact-manifest"), "--members"]
                    )
                    member_file = Path(directory) / "members"
                    member_file.write_bytes(members)
                    archive = Path(directory) / "telltale-test.tar.gz"
                    subprocess.run(["tar", "czf", str(archive), "-C", str(bundle), "-T", str(member_file)], check=True)
                    self.assertEqual(helper.validate_tar(archive), members.decode().splitlines())
                    with tarfile.open(archive) as packaged:
                        self.assertEqual(packaged.extractfile("README.md").read(), b"synthetic release/README.md\n")
                with self.assertRaises(FileExistsError):
                    helper.stage_bundle(binary, bundle, windows=windows, root=root)

    def test_stage_rejects_source_parent_escape_before_creating_bundle(self):
        for redirected in ("release", "config", "target"):
            with self.subTest(parent=redirected), tempfile.TemporaryDirectory() as directory:
                root = Path(directory) / "checkout"
                binary = root / "target/release/telltale"
                binary.parent.mkdir(parents=True)
                binary.write_bytes(b"synthetic binary\n")
                for _, source, _ in helper.load_inventory()[1:]:
                    path = root / source
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text("synthetic support file\n")
                outside = Path(directory) / "outside-checkout"
                (root / redirected).rename(outside)
                (root / redirected).symlink_to(outside, target_is_directory=True)
                bundle = Path(directory) / "bundle"
                with self.assertRaisesRegex(SystemExit, "outside the checkout"):
                    helper.stage_bundle(binary, bundle, root=root)
                self.assertFalse(bundle.exists())

    def test_archive_negative_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            for kind in ("tar.gz", "zip"):
                for defect in (None, "missing", "extra", "duplicate", "link", "traversal", "mode"):
                    with self.subTest(kind=kind, defect=defect):
                        path = Path(directory) / f"telltale-test.{kind}"
                        rows = helper.load_inventory(windows=kind == "zip")
                        names = [row[0] for row in rows]
                        if defect == "missing":
                            names.remove("README.md")
                        if defect in ("extra", "duplicate", "traversal"):
                            names.append({"extra": "extra.txt", "duplicate": "README.md", "traversal": "../escape"}[defect])
                        if kind == "tar.gz":
                            with tarfile.open(path, "w:gz") as archive:
                                for name in names:
                                    info = tarfile.TarInfo(name)
                                    info.mode = 0o755 if name == names[0] else 0o644
                                    info.size = 4
                                    if name == "README.md" and defect == "mode":
                                        info.mode = 0o600
                                    if name == "README.md" and defect == "link":
                                        info.type = tarfile.SYMTYPE
                                        info.linkname = "LICENSE"
                                        info.size = 0
                                    archive.addfile(info, io.BytesIO(b"test"))
                            validate = helper.validate_tar
                        else:
                            with zipfile.ZipFile(path, "w") as archive:
                                for name in names:
                                    info = zipfile.ZipInfo(name)
                                    mode = 0o755 if name == names[0] else 0o644
                                    file_type = 0o100000
                                    if name == "README.md" and defect == "mode":
                                        mode = 0o600
                                    if name == "README.md" and defect == "link":
                                        file_type = 0o120000
                                    info.external_attr = (file_type | mode) << 16
                                    archive.writestr(info, b"test")
                            validate = helper.validate_zip
                        if defect is None:
                            self.assertEqual(validate(path), names)
                        else:
                            with self.assertRaises(SystemExit):
                                validate(path)


if __name__ == "__main__":
    unittest.main()
