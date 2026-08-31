#!/usr/bin/env python3
"""Generate a deterministic CycloneDX SBOM from the locked release graph."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path
from urllib.parse import quote


REGISTRY_SOURCE = "registry+https://github.com/rust-lang/crates.io-index"
SPDX_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]*$")
SPDX_EXPRESSION_OPERATOR = re.compile(r"\s+(?:WITH|AND|OR)\s+")
HEX_DIGEST = re.compile(r"^[0-9a-f]{64}$")
SERIAL_NUMBER = re.compile(
    r"^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
BOM_REF = re.compile(r"^pkg:cargo/[^\s@]+@[^\s]+$")


def fail(message: str) -> "NoReturn":
    raise SystemExit(message)


def cargo_metadata(root: Path) -> dict:
    cargo = os.environ.get("CARGO", "cargo")
    result = subprocess.run(
        [cargo, "metadata", "--locked", "--format-version", "1"],
        cwd=root,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if result.returncode != 0:
        fail(f"cargo metadata failed: {result.stderr.strip()}")
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as error:
        fail(f"cargo metadata returned invalid JSON: {error}")


def package_url(name: str, version: str) -> str:
    return f"pkg:cargo/{quote(name, safe='-._~')}@{quote(version, safe='-._~+')}"


def license_entry(value: str) -> dict:
    if SPDX_EXPRESSION_OPERATOR.search(value):
        return {"expression": value}
    if SPDX_ID.fullmatch(value):
        return {"license": {"id": value}}
    return {"license": {"name": value}}


def _require(condition: bool, message: str) -> None:
    if not condition:
        fail(f"SBOM fails the deterministic CycloneDX 1.6 subset: {message}")


def _validate_license_choice(choice: object) -> None:
    _require(isinstance(choice, dict), "license choices must be objects")
    _require(
        set(choice) in ({"license"}, {"expression"}),
        "each license choice must contain exactly one of license or expression",
    )
    if "expression" in choice:
        expression = choice["expression"]
        _require(
            isinstance(expression, str)
            and expression
            and expression == expression.strip()
            and (SPDX_ID.fullmatch(expression) or SPDX_EXPRESSION_OPERATOR.search(expression)),
            "license expressions must be non-empty SPDX-shaped strings",
        )
        return

    license_object = choice["license"]
    _require(isinstance(license_object, dict), "license must be an object")
    _require(
        set(license_object) in ({"id"}, {"name"}),
        "license objects must contain exactly one of id or name",
    )
    if "id" in license_object:
        _require(
            isinstance(license_object["id"], str) and SPDX_ID.fullmatch(license_object["id"]),
            "license ids must be SPDX-shaped identifiers",
        )
    else:
        _require(
            isinstance(license_object["name"], str) and bool(license_object["name"].strip()),
            "license names must be non-empty strings",
        )


def _validate_component(component_value: object) -> None:
    _require(isinstance(component_value, dict), "components must be objects")
    required = {"bom-ref", "name", "type", "version", "scope"}
    allowed = required | {"licenses", "hashes"}
    _require(required <= set(component_value) <= allowed, "component fields are not canonical")
    _require(
        isinstance(component_value["bom-ref"], str)
        and BOM_REF.fullmatch(component_value["bom-ref"]),
        "component bom-ref must be a Cargo package reference",
    )
    _require(
        isinstance(component_value["name"], str) and bool(component_value["name"]),
        "component name must be a non-empty string",
    )
    _require(
        isinstance(component_value["type"], str)
        and component_value["type"] in {"application", "library"},
        "component type must be application or library",
    )
    _require(
        isinstance(component_value["version"], str) and bool(component_value["version"]),
        "component version must be a non-empty string",
    )
    _require(component_value["scope"] == "required", "component scope must be required")

    if "licenses" in component_value:
        licenses = component_value["licenses"]
        _require(isinstance(licenses, list) and bool(licenses), "licenses must be a non-empty list")
        for choice in licenses:
            _validate_license_choice(choice)

    if "hashes" in component_value:
        hashes = component_value["hashes"]
        _require(isinstance(hashes, list) and bool(hashes), "hashes must be a non-empty list")
        for digest in hashes:
            _require(
                isinstance(digest, dict) and set(digest) == {"alg", "content"},
                "hashes must contain only alg and content",
            )
            _require(digest["alg"] == "SHA-256", "component hashes must use SHA-256")
            _require(
                isinstance(digest["content"], str) and HEX_DIGEST.fullmatch(digest["content"]),
                "component SHA-256 content must be lowercase hexadecimal",
            )


def validate_cyclonedx_subset(
    document: object,
    *,
    expected_root_ref: str | None = None,
    expected_lock_hash: str | None = None,
    expected_hashed_refs: set[str] | None = None,
) -> None:
    """Validate the deterministic CycloneDX subset emitted by this generator.

    This is intentionally a repository-owned structural/relationship check, not
    a claim of full official CycloneDX schema validation.
    """

    _require(isinstance(document, dict), "document must be an object")
    _require(
        set(document)
        == {"bomFormat", "specVersion", "serialNumber", "version", "metadata", "components", "dependencies"},
        "document fields are not canonical",
    )
    _require(document["bomFormat"] == "CycloneDX", "bomFormat must be CycloneDX")
    _require(document["specVersion"] == "1.6", "specVersion must be 1.6")
    _require(
        isinstance(document["serialNumber"], str) and SERIAL_NUMBER.fullmatch(document["serialNumber"]),
        "serialNumber must be a lowercase UUID URN",
    )
    _require(type(document["version"]) is int and document["version"] == 1, "version must be 1")

    metadata = document["metadata"]
    _require(isinstance(metadata, dict), "metadata must be an object")
    _require(set(metadata) == {"tools", "component", "properties"}, "metadata fields are not canonical")

    tools = metadata["tools"]
    _require(isinstance(tools, list) and len(tools) == 1, "metadata must contain one tool")
    _require(
        tools[0] == {"vendor": "Telltale", "name": "generate-sbom.py", "version": "1"},
        "metadata tool identity is not canonical",
    )

    properties = metadata["properties"]
    _require(isinstance(properties, list), "metadata properties must be a list")
    property_values: dict[str, str] = {}
    for property_value in properties:
        _require(
            isinstance(property_value, dict) and set(property_value) == {"name", "value"},
            "metadata properties must contain only name and value",
        )
        name = property_value["name"]
        value = property_value["value"]
        _require(
            isinstance(name, str) and isinstance(value, str) and name not in property_values,
            "metadata property names and values must be unique strings",
        )
        property_values[name] = value
    _require(
        set(property_values) == {"telltale:lockfile-sha256", "telltale:dependency-scope"},
        "metadata properties are incomplete",
    )
    _require(
        HEX_DIGEST.fullmatch(property_values["telltale:lockfile-sha256"]),
        "lockfile property must be lowercase hexadecimal",
    )
    _require(
        property_values["telltale:dependency-scope"] == "normal-and-build",
        "dependency scope property is not canonical",
    )
    if expected_lock_hash is not None:
        _require(
            property_values["telltale:lockfile-sha256"] == expected_lock_hash,
            "lockfile property does not match the source lockfile",
        )

    components = document["components"]
    _require(isinstance(components, list) and bool(components), "components must be non-empty")
    component_by_ref: dict[str, dict] = {}
    for component_value in components:
        _validate_component(component_value)
        reference = component_value["bom-ref"]
        _require(reference not in component_by_ref, "component bom-refs must be unique")
        component_by_ref[reference] = component_value
    _require(
        components
        == sorted(components, key=lambda item: (item["name"], item["version"], item["bom-ref"])),
        "components must be deterministically sorted",
    )

    root_component = metadata["component"]
    _validate_component(root_component)
    root_ref = root_component["bom-ref"]
    _require(root_ref in component_by_ref, "metadata root component must be in components")
    _require(
        root_component == component_by_ref[root_ref],
        "metadata root component must equal its component entry",
    )
    _require(root_component["type"] == "application", "metadata root component must be application")
    _require(
        sum(component_value["type"] == "application" for component_value in components) == 1,
        "the release graph must contain exactly one application component",
    )
    if expected_root_ref is not None:
        _require(root_ref == expected_root_ref, "metadata root does not match the workspace root")

    dependencies = document["dependencies"]
    _require(isinstance(dependencies, list) and len(dependencies) == len(component_by_ref), "dependency entries must cover every component")
    dependency_by_ref: dict[str, dict] = {}
    for dependency in dependencies:
        _require(
            isinstance(dependency, dict) and set(dependency) == {"ref", "dependsOn"},
            "dependency entries must contain only ref and dependsOn",
        )
        reference = dependency["ref"]
        _require(reference in component_by_ref and reference not in dependency_by_ref, "dependency refs must match components exactly once")
        depends_on = dependency["dependsOn"]
        _require(isinstance(depends_on, list), "dependsOn must be a list")
        _require(
            all(isinstance(item, str) and item in component_by_ref for item in depends_on),
            "dependsOn refs must point to components",
        )
        _require(len(depends_on) == len(set(depends_on)), "dependsOn refs must be unique")
        _require(depends_on == sorted(depends_on), "dependsOn refs must be deterministically sorted")
        dependency_by_ref[reference] = dependency
    _require(
        list(dependency_by_ref) == sorted(dependency_by_ref),
        "dependency entries must be deterministically sorted",
    )
    _require(
        set(dependency_by_ref) == set(component_by_ref),
        "dependency refs must cover the component refs exactly",
    )
    if expected_hashed_refs is not None:
        actual_hashed_refs = {
            reference for reference, component_value in component_by_ref.items() if "hashes" in component_value
        }
        _require(
            actual_hashed_refs == expected_hashed_refs,
            "component hash relationships do not match the locked registry graph",
        )


def graph_packages(metadata: dict, root: Path) -> tuple[dict[str, dict], dict[str, set[str]], str]:
    packages = {package["id"]: package for package in metadata["packages"]}
    nodes = {node["id"]: node for node in metadata["resolve"]["nodes"]}
    root_id = metadata["resolve"].get("root")
    if not isinstance(root_id, str) or root_id not in packages:
        fail("Cargo metadata did not provide a workspace root package")

    workspace_members = set(metadata.get("workspace_members", []))
    if not workspace_members or not workspace_members.issubset(packages):
        fail("Cargo metadata did not provide all workspace package metadata")
    reachable: set[str] = set()
    edges: dict[str, set[str]] = {}
    # The release publishes all six workspace packages. Include each package's
    # normal/build graph while intentionally excluding developer-only test edges.
    pending = sorted(workspace_members, reverse=True)
    while pending:
        package_id = pending.pop()
        if package_id in reachable:
            continue
        if package_id not in nodes:
            fail(f"resolved package has no dependency node: {package_id}")
        reachable.add(package_id)
        dependencies: set[str] = set()
        for dependency in nodes[package_id]["deps"]:
            kinds = {kind.get("kind") for kind in dependency.get("dep_kinds", [])}
            if not (kinds & {None, "normal", "build"}):
                continue
            dependency_id = dependency["pkg"]
            if dependency_id not in packages:
                fail(f"resolved dependency is missing package metadata: {dependency_id}")
            dependencies.add(dependency_id)
            if dependency_id not in reachable:
                pending.append(dependency_id)
        edges[package_id] = dependencies

    missing_members = workspace_members - reachable
    if missing_members:
        fail(f"release graph omitted workspace package(s): {sorted(missing_members)}")

    for package_id in reachable:
        package = packages[package_id]
        source = package.get("source")
        if source is not None and source != REGISTRY_SOURCE:
            fail(f"release graph contains a non-crates.io source: {package_id}")
        if source is None:
            manifest = Path(package["manifest_path"]).resolve()
            try:
                manifest.relative_to(root)
            except ValueError:
                fail(f"workspace package is outside the repository: {package_id}")

    return {package_id: packages[package_id] for package_id in reachable}, edges, root_id


def locked_checksums(lock_bytes: bytes) -> dict[tuple[str, str], str]:
    try:
        lockfile = tomllib.loads(lock_bytes.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        fail(f"Cargo.lock is not valid TOML: {error}")
    checksums: dict[tuple[str, str], str] = {}
    for package in lockfile.get("package", []):
        if package.get("source") != REGISTRY_SOURCE:
            continue
        key = (package.get("name", ""), package.get("version", ""))
        checksum = package.get("checksum")
        if key in checksums:
            fail(f"Cargo.lock has duplicate registry package identity: {key}")
        if not isinstance(checksum, str) or not HEX_DIGEST.fullmatch(checksum):
            fail(f"Cargo.lock has no canonical checksum for registry package: {key}")
        checksums[key] = checksum
    return checksums


def component(package: dict, root_id: str, checksums: dict[tuple[str, str], str]) -> dict:
    name = package["name"]
    version = package["version"]
    ref = package_url(name, version)
    result = {
        "bom-ref": ref,
        "name": name,
        "type": "application" if package["id"] == root_id else "library",
        "version": version,
        "scope": "required",
    }
    if package.get("license"):
        result["licenses"] = [license_entry(package["license"])]
    if package.get("source") == REGISTRY_SOURCE:
        key = (name, version)
        checksum = checksums.get(key)
        if checksum is None:
            fail(f"SBOM has no Cargo.lock checksum for registry package: {key}")
        result["hashes"] = [{"alg": "SHA-256", "content": checksum}]
    return result


def render(metadata: dict, lock_bytes: bytes, root: Path) -> bytes:
    packages, edges, root_id = graph_packages(metadata, root)
    checksums = locked_checksums(lock_bytes)
    components = [component(packages[package_id], root_id, checksums) for package_id in packages]
    components.sort(key=lambda item: (item["name"], item["version"], item["bom-ref"]))
    refs = {
        package_id: package_url(package["name"], package["version"])
        for package_id, package in packages.items()
    }
    dependencies = []
    for package_id in sorted(packages, key=lambda item: refs[item]):
        dependencies.append(
            {
                "ref": refs[package_id],
                "dependsOn": sorted(refs[dependency] for dependency in edges.get(package_id, set())),
            }
        )

    lock_hash = hashlib.sha256(lock_bytes).hexdigest()
    serial_source = hashlib.sha256(f"telltale-cyclonedx-v1:{lock_hash}".encode()).hexdigest()
    serial = (
        f"urn:uuid:{serial_source[0:8]}-{serial_source[8:12]}-"
        f"{serial_source[12:16]}-{serial_source[16:20]}-{serial_source[20:32]}"
    )
    root_component = component(packages[root_id], root_id, checksums)
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": serial,
        "version": 1,
        "metadata": {
            "tools": [{"vendor": "Telltale", "name": "generate-sbom.py", "version": "1"}],
            "component": root_component,
            "properties": [
                {"name": "telltale:lockfile-sha256", "value": lock_hash},
                {"name": "telltale:dependency-scope", "value": "normal-and-build"},
            ],
        },
        "components": components,
        "dependencies": dependencies,
    }
    validate_cyclonedx_subset(
        document,
        expected_root_ref=refs[root_id],
        expected_lock_hash=lock_hash,
        expected_hashed_refs={
            refs[package_id]
            for package_id, package in packages.items()
            if package.get("source") == REGISTRY_SOURCE
        },
    )
    encoded = (json.dumps(document, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode("utf-8")
    if str(root).encode() in encoded:
        fail("SBOM contains a host repository path")
    return encoded


def generate(root: Path) -> bytes:
    first = cargo_metadata(root)
    second = cargo_metadata(root)
    lock_bytes = (root / "Cargo.lock").read_bytes()
    first_bytes = render(first, lock_bytes, root)
    second_bytes = render(second, lock_bytes, root)
    if first_bytes != second_bytes:
        fail("SBOM generation was not reproducible across two metadata runs")
    return first_bytes


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("target/release/telltale-sbom.cdx.json"),
        help="fixed local output path (default: target/release/telltale-sbom.cdx.json)",
    )
    parser.add_argument("--check", type=Path, help="compare an existing SBOM with the generated bytes")
    args = parser.parse_args()

    root = Path(__file__).resolve().parent.parent
    encoded = generate(root)
    if args.check is not None:
        checked = args.check if args.check.is_absolute() else Path.cwd() / args.check
        if not checked.is_file() or checked.is_symlink():
            fail(f"SBOM is not a regular file: {checked}")
        checked_bytes = checked.read_bytes()
        try:
            checked_document = json.loads(checked_bytes)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            fail(f"SBOM check file is not valid JSON: {error}")
        validate_cyclonedx_subset(checked_document)
        if checked_bytes != encoded:
            fail(f"SBOM does not match the locked release graph: {checked}")
        print(f"SBOM verified: {checked} ({len(encoded)} bytes, sha256={hashlib.sha256(encoded).hexdigest()})")
        return 0

    output = args.output if args.output.is_absolute() else root / args.output
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=output.parent, prefix=f".{output.name}.", delete=False) as stream:
        temporary = Path(stream.name)
        stream.write(encoded)
    temporary.replace(output)
    print(f"SBOM generated: {output.relative_to(root)} ({len(encoded)} bytes, sha256={hashlib.sha256(encoded).hexdigest()})")
    return 0


if __name__ == "__main__":
    main()
