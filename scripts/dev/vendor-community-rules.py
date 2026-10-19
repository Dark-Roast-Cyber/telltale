#!/usr/bin/env python3
"""Vendor a community rule package into crates/telltale-rules/data/.

The embedded community package is content, not code: Telltale compiles it into
the binary beside the core rules and enables it by default. Refresh it only from
a published community release whose checksum file lists the exact package bytes.

    gh release download v0.2.0 --repo Dark-Roast-Cyber/telltale-detections \\
        --pattern '*.package.yaml' --pattern SHA256SUMS --dir "$TMPDIR/community"
    gh attestation verify "$TMPDIR/community/telltale.community-0.2.0.package.yaml" \\
        --repo Dark-Roast-Cyber/telltale-detections
    python3 scripts/dev/vendor-community-rules.py \\
        "$TMPDIR/community/telltale.community-0.2.0.package.yaml" \\
        --sha256sums "$TMPDIR/community/SHA256SUMS"
    cargo test --locked -p telltale-rules package

`--unverified-local` skips the checksum requirement for a local development
build; never vendor such a snapshot into a release.
"""

from __future__ import annotations

import argparse
import hashlib
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
OUT = REPO / "crates" / "telltale-rules" / "data" / "community.package.yaml"
HEADER = {
    "format": "telltale-rule-package/v1",
    "id": "telltale.community",
}


def header_value(text: str, key: str) -> str | None:
    match = re.search(rf'^{key}: "?([^"\n]+)"?$', text, re.MULTILINE)
    return match.group(1) if match else None


def listed_digest(sums: Path, name: str) -> str:
    for line in sums.read_text(encoding="utf-8").splitlines():
        digest, _, listed = line.partition("  ")
        if listed == name and re.fullmatch(r"[0-9a-f]{64}", digest):
            return digest
    raise SystemExit(f"error: {sums.name} does not list {name}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("package", type=Path, help="downloaded *.package.yaml")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--sha256sums", type=Path, help="release SHA256SUMS listing the package")
    group.add_argument("--unverified-local", action="store_true",
                       help="accept a local build without a release checksum")
    args = parser.parse_args()

    data = args.package.read_bytes()
    text = data.decode("utf-8")
    for key, expected in HEADER.items():
        if header_value(text, key) != expected:
            raise SystemExit(f"error: package {key} must be {expected}")
    version = header_value(text, "version")
    if args.sha256sums:
        expected = listed_digest(args.sha256sums, args.package.name)
        actual = hashlib.sha256(data).hexdigest()
        if actual != expected:
            raise SystemExit(f"error: sha256 {actual} does not match {args.sha256sums.name}")
    OUT.write_bytes(data)
    print(f"vendored telltale.community {version} -> {OUT.relative_to(REPO)}")
    print("next: cargo test --locked -p telltale-rules package && make evaluation-check")
    return 0


if __name__ == "__main__":
    sys.exit(main())
