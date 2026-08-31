import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/generate-sbom.py"


def load_generator():
    spec = importlib.util.spec_from_file_location("generate_sbom", SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load SBOM generator")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class GenerateSbomTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.generator = load_generator()
        cls.document = json.loads(cls.generator.generate(ROOT))

    def test_generated_graph_has_valid_cyclonedx_relationships_and_expression_licenses(self):
        self.generator.validate_cyclonedx_subset(self.document)

        components = self.document["components"]
        dependencies = self.document["dependencies"]
        references = {component["bom-ref"] for component in components}
        self.assertGreater(len(components), 1)
        self.assertEqual(len(components), len(dependencies))
        self.assertEqual(
            references,
            {dependency["ref"] for dependency in dependencies},
        )
        self.assertEqual(
            self.document["metadata"]["component"]["bom-ref"],
            next(component["bom-ref"] for component in components if component["type"] == "application"),
        )
        hashed_components = [component for component in components if "hashes" in component]
        self.assertGreater(len(hashed_components), 100)
        self.assertTrue(all(component["hashes"][0]["alg"] == "SHA-256" for component in hashed_components))

        expressions = [
            choice["expression"]
            for component in components
            for choice in component.get("licenses", [])
            if "expression" in choice
        ]
        self.assertTrue(
            any(" WITH " in expression for expression in expressions),
            "the locked graph should exercise SPDX WITH expressions",
        )
        self.assertFalse(
            any(
                " WITH " in choice.get("license", {}).get("id", "")
                for component in components
                for choice in component.get("licenses", [])
            )
        )

    def test_license_entry_distinguishes_ids_names_and_spdx_expressions(self):
        cases = {
            "MIT": {"license": {"id": "MIT"}},
            "Apache-2.0 WITH LLVM-exception": {
                "expression": "Apache-2.0 WITH LLVM-exception"
            },
            "MIT AND Apache-2.0": {"expression": "MIT AND Apache-2.0"},
            "MIT OR Apache-2.0": {"expression": "MIT OR Apache-2.0"},
            "(MIT OR Apache-2.0) AND Unicode-3.0": {
                "expression": "(MIT OR Apache-2.0) AND Unicode-3.0"
            },
            "Apache-2.0/MIT": {"license": {"name": "Apache-2.0/MIT"}},
        }
        for value, expected in cases.items():
            with self.subTest(value=value):
                self.assertEqual(self.generator.license_entry(value), expected)

    def test_subset_rejects_mutually_exclusive_license_objects(self):
        invalid = copy.deepcopy(self.document)
        invalid["components"][0]["licenses"] = [
            {"license": {"id": "MIT"}, "expression": "Apache-2.0"}
        ]
        with self.assertRaisesRegex(SystemExit, "exactly one of license or expression"):
            self.generator.validate_cyclonedx_subset(invalid)

    def test_subset_rejects_invalid_serial_hash_property_and_refs(self):
        cases = []

        invalid_serial = copy.deepcopy(self.document)
        invalid_serial["serialNumber"] = "urn:uuid:NOT-A-UUID"
        cases.append((invalid_serial, "serialNumber"))

        invalid_property = copy.deepcopy(self.document)
        invalid_property["metadata"]["properties"][0]["value"] = "not-a-digest"
        cases.append((invalid_property, "lockfile property"))

        invalid_hash = copy.deepcopy(self.document)
        hashed = next(component for component in invalid_hash["components"] if "hashes" in component)
        hashed["hashes"][0]["content"] = hashed["hashes"][0]["content"].upper()
        cases.append((invalid_hash, "lowercase hexadecimal"))

        invalid_ref = copy.deepcopy(self.document)
        invalid_ref["dependencies"][0]["ref"] = "pkg:cargo/not-in-components@1.0.0"
        cases.append((invalid_ref, "dependency refs"))

        for document, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(SystemExit, message):
                    self.generator.validate_cyclonedx_subset(document)

    def test_generation_and_check_paths_reference_subset_validator(self):
        calls = []
        original = self.generator.validate_cyclonedx_subset

        def recording_validator(document, **kwargs):
            calls.append(document)
            return original(document, **kwargs)

        with tempfile.TemporaryDirectory() as directory:
            checked = Path(directory) / "telltale-sbom.cdx.json"
            checked.write_bytes(self.generator.generate(ROOT))
            with patch.object(self.generator, "validate_cyclonedx_subset", side_effect=recording_validator):
                with patch.object(
                    self.generator.sys,
                    "argv",
                    [str(SCRIPT), "--check", str(checked)],
                ):
                    self.assertEqual(self.generator.main(), 0)

        self.assertGreaterEqual(len(calls), 3)


if __name__ == "__main__":
    unittest.main(verbosity=2)
