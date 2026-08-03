# Versioning and Releases

Telltale uses Semantic Versioning for the CLI and Cargo packages, with a
conservative policy for the `0.x` development series. Git tags, GitHub Releases,
and Cargo package versions use the same version number and the `v<version>` tag
format.

## Current Series

- `v0.1.0` is the first public binary release.
- `0.2.0` is the prior maturity release.
- `0.3.0` is the current released line for the event and scoring contract.
- `0.4.0` is the unpublished breaking API-hardening line; its packages remain
  unpublished pending separate approval.
- `0.3.x` is the current released maintenance line. After `0.4.0` is released,
  compatible follow-up fixes will use its `0.4.x` patch line.
- `0.5.0` is reserved for the next significant, coherent product milestone. It
  must represent substantial architecture, public API/schema/configuration,
  compatibility, or capability work; it is not a label for a round of routine
  tasks. Follow-up fixes after that milestone use `0.5.x`.
- The six functional Cargo packages are `telltale-schema`, `telltale-rules`,
  `telltale-sources`, `telltale-detect`, `telltale-core`, and `telltale-cli`.
  The planned publication order is schema → rules → sources → detect → core →
  cli. Recheck crates.io availability immediately before any future
  publication.
- **Crates.io name warning:** The package named `telltale` is an unrelated
  active session-types crate. It is not this project; the embedding package is
  `telltale-core` and its Rust import is `telltale_core`.
- `telltale` is the canonical executable and `telltale-*` is the canonical
  release asset naming. The compiled `adr` compatibility command and exact-copy
  `adr-*` archive aliases remain part of the current release contract. This
  migration does not schedule their removal.
- `1.0.0` waits until the public CLI, embedding APIs, event contract, and
  configuration behavior are stable enough for explicit compatibility promises.

## Rust Toolchain Policy

The current support policy is the current stable Rust toolchain used by CI. No
minimum supported Rust version (MSRV) is promised and no `rust-version` field is
set until a dedicated MSRV CI lane exists.

## SemVer Policy

Before `1.0.0`, Telltale applies a stricter policy than the minimum SemVer
allowance for `0.y.z` versions:

| Change | Version | Examples |
| --- | --- | --- |
| Compatible fix | Patch (`0.3.x`; `0.4.x` after the 0.4.0 release) | Bug fix, documentation, packaging, test-only change, or compatible detection improvement |
| Additive maturity work | Next planned minor line | New compatible capability or API that does not invalidate existing consumers |
| Breaking change | Next minor (`0.4.0`, then `0.5.0` if needed) | Removed or changed public API, incompatible CLI/config behavior, or incompatible event/rule contract |
| Stable compatibility commitment | Major (`1.0.0`) | Public interfaces are sufficiently settled for documented compatibility guarantees |

The `0.3.x` line is the compatibility path for post-`0.3.0` fixes. The
unpublished `0.4.0` line is the next breaking API-hardening line; after it is
released, its `0.4.x` series will serve as the compatibility path. Do not
accumulate unrelated maintenance tasks and call the result `0.5.0`. Starting a
`0.5.0` milestone requires explicit scope, user-visible rationale, compatibility
impact, migration notes where needed, acceptance criteria, and release review.

## Versioned Surfaces

The Cargo/package version is not the version of every data contract:

- **Package and CLI version:** the workspace root and all five library crates
  move in lockstep. Internal workspace dependency requirements must be updated
  together. The root binary and library crates use the same release version.
- **Event schema version:** `schema_version` and named schema types such as
  `NormalizedRecordV1` describe emitted data compatibility independently of the
  Cargo version. Change them only when the event contract changes.
- **Configuration version:** configuration documents such as `version: 1` have
  their own migration rules. A package release does not automatically change a
  configuration version.
- **Rule language and bundled rules:** compatible detections and rule updates
  remain on the current `0.3.x` line, then `0.4.x` after the 0.4.0 release.
  Removing syntax, changing evaluation meaning incompatibly, or invalidating
  existing rule documents belongs in the next planned minor milestone, not in a
  routine patch batch.

## Release Process

1. Release only from a reviewed commit on `main`.
2. Update the workspace package version and every internal workspace dependency
   version together.
3. Update public release notes with capabilities, fixes, compatibility impact,
   and operator impact. Internal planning history stays out of public notes.
4. Run `make release-preflight` and review the staged/public file boundary.
5. Create the matching `v<version>` tag. For example, a compatible maintenance
   release `0.3.1` requires tag `v0.3.1`; the unpublished breaking line requires
   `v0.4.0` only after its release approval.
6. Wait for the release workflow, then inspect the published artifacts and
   checksums before reporting the release complete.

For the exact 0.4.0 Rust API changes, see the
[0.4.0 migration guide](migrations/0.4.0.md).

## Crates.io Publication

Publish functional packages only after `cargo package --list`, package-boundary
checks, and a workspace-independent consumer build pass. Recheck crates.io name
availability immediately before publication. Publish dependencies first:

1. `telltale-schema`
2. `telltale-rules`
3. `telltale-sources`
4. `telltale-detect`
5. `telltale-core`
6. `telltale-cli`

If the crates have not previously been published, their first crates.io version
must equal the current workspace version. A version already published on
crates.io cannot be republished; increment the package version deliberately
instead of reusing it.

Before publication, recheck registry ownership and availability for every name.
Publish schema → rules → sources → detect → core → cli, waiting after each
publish until that prerequisite resolves from the index without a local patch.
After all six packages are available, remove every local `patch.crates-io`
override and confirm the clean consumers and CLI installation using only pinned
`=0.4.0` registry dependencies. Do not declare publication complete before
those unpatched checks pass, and do not publish credentials or local release
state.

## Pre-Releases

Use Cargo-compatible pre-release versions such as `0.4.0-alpha.1`,
`0.4.0-beta.1`, or `0.4.0-rc.1` only when external validation is useful. A
pre-release tag and package version must still match exactly, and pre-releases
do not carry stable compatibility guarantees.
