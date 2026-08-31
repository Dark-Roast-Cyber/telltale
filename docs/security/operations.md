# Security and release operations

These commands are the repository-owned surfaces for Issue #27. Run them
from the repository root. They do not publish, tag, or mutate GitHub.

## Local security checks

Install the exact tool versions declared by the Makefile, with Cargo's locked
tool dependency resolution, then run the common gate:

```sh
make security-tools
make security-check
```

`security-check` verifies the installed versions, runs `cargo audit -D warnings`,
runs `cargo deny check all`, runs the focused SBOM generator/validator tests,
and checks every external action in all three public workflows. The audit
command fetches the RustSec advisory
database by default; do not use `--no-fetch` or `--stale` for release evidence.
An unavailable or stale advisory database is a blocked check, not a pass.

The current exact tool ownership is:

| Tool | Version | Owned by |
| --- | --- | --- |
| Rust toolchain | `1.95.0` | CI/release workflow `toolchain` input and Makefile version check |
| `cargo-audit` | `0.22.2` | `Makefile` `CARGO_AUDIT_VERSION` |
| `cargo-deny` | `0.20.2` | `Makefile` `CARGO_DENY_VERSION` |
| SBOM generator | repository `scripts/generate-sbom.py`, format revision `1` | repository |

The baseline lockfile exposed two live RustSec findings during implementation:
`RUSTSEC-2026-0190` was resolved by upgrading `anyhow` to `1.0.103`, and
`RUSTSEC-2026-0204` was resolved by upgrading `crossbeam-epoch` to `0.9.20`.
Neither advisory is ignored in `deny.toml` or the audit command.

`deny.toml` is derived from the live locked graph. Sources, wildcard
requirements, and advisories fail closed. The allow list contains only SPDX
identifiers observed in the graph. Unusual license expressions use
package/version-specific exceptions. Duplicate-version skips identify exact
locked members and their graph reason; they do not skip advisory, license, or
source checks. When Cargo.lock changes, rerun both tools, review every new
diagnostic, and update only the narrowest documented exception or dependency.
Never add a blanket advisory ignore.

## Pins and automated updates

Workflow actions use full 40-character commit SHAs. The trailing comment is
the resolved release tag for human review. To review a pin update, resolve the
tag to its commit (for example with `git ls-remote --tags`), update the SHA and
comment together, then run:

```sh
make workflow-pins-check
```

Dependabot proposes weekly updates for GitHub Actions and Cargo dependencies.
Review action diffs, tool-version changes, lockfile changes, advisory output,
and the complete security/release gates before accepting an update. A tool
version change must update the exact version in the Makefile and the CI/release
install evidence together; installation remains `cargo install --version
<exact> --locked`.

## SBOM generation and verification

The release SBOM has the fixed local and asset name
`telltale-sbom.cdx.json`. It is generated from `cargo metadata --locked`,
starting at every released workspace package and following normal/build edges.
It contains the locked crates.io or workspace package content needed by the
released workspace, not developer-only test dependencies, and omits timestamps
and host paths.

```sh
make release-sbom
python3 scripts/generate-sbom.py --check target/release/telltale-sbom.cdx.json
```

The generator invokes locked Cargo metadata twice and compares the exact JSON
bytes. It also validates the emitted deterministic CycloneDX 1.6 subset,
including license-choice shape, graph references, component hashes, required
properties, and serial format. This is not full official CycloneDX schema
validation. The release preflight uploads and attests that file. After downloading
the artifacts, the release job runs
`scripts/generate-sbom.py --check release-downloads/telltale-sbom.cdx.json`
against the tagged checkout and lockfile before generating `SHA256SUMS`. It
then requires the fixed asset, validates its CycloneDX shape through
`release-artifact-manifest`, and publishes it beside the five archives. Archive
attestations remain in place, and the SBOM has its own attestation subject.

## Release integrity verification

The tagged release path is ordered as: security gates and SBOM generation in
preflight; existing format, Clippy, tests, package, public-boundary, and
fixture gates; native archive builds and archive attestations; exact artifact
set validation; SBOM/checksum/manifest validation; then the existing immutable
Release reservation and publication. Publication cannot bypass a failed
preflight or build job.

After downloading a release, verify the complete checksum asset and the
attestations before running a binary:

```sh
sha256sum -c SHA256SUMS
gh attestation verify telltale-<tag>-x86_64-unknown-linux-gnu.tar.gz \
  --repo Dark-Roast-Cyber/telltale
gh attestation verify telltale-sbom.cdx.json \
  --repo Dark-Roast-Cyber/telltale
```

Use `make release-artifact-manifest` for local downloaded archive review. The
release workflow additionally sets `REQUIRE_SBOM=1` so a missing or substituted
SBOM fails closed.

## Independent Windows gate

Issue #23 remains a later, independent release gate while Windows is an
advertised target. It owns clean-host execution and the VC++ runtime/CRT
decision. Issue #27 does not implement or claim to solve that Windows runtime
requirement; use the native verification and release-readiness procedures when
that gate is selected.
