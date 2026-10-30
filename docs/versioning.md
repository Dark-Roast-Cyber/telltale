# Versioning and Releases

Telltale uses Semantic Versioning for the CLI and Cargo packages, with a
conservative policy for the `0.x` development series. Git tags, GitHub Releases,
and Cargo package versions use the same version number and the `v<version>` tag
format.

## Current Series

- `v0.7.0` is the current stable GitHub Release; `v0.6.0` is the previous stable.
  See the [migration guide](migrations/0.7.0.md) before upgrading from 0.6.x.
- The final prerelease is `v0.7.0-rc.4`. Each release's source SHA, artifacts
  and qualification results are recorded on its
  [GitHub Release](https://github.com/Dark-Roast-Cyber/telltale/releases)
  and the release qualification issue. Candidate evidence does not replace
  verification of the stable release's exact source and artifacts.
- Earlier lines: `v0.5.0`, `0.4.0` (unpublished; folded into
  `0.5.0`), `0.3.0`, `0.2.0`, and `v0.1.0` (first public binary release).
- Published tags, Releases and assets are immutable, including failed or
  superseded candidates. A further tagged candidate uses the next unused RC
  version; a candidate is never reused or mutated.
- Package version identifies the release line; the full Git SHA plus archive
  and binary SHA-256 identify an exact artifact. Neither version output nor a
  package build proves official release provenance.
- Event3 schema version stays `3.0` and Rule v1 stays version 1; neither follows
  the package version.
- The six functional Cargo packages are `telltale-schema`, `telltale-rules`,
  `telltale-sources`, `telltale-detect`, `telltale-core`, and `telltale-cli`.
  `telltale-console` also inherits the workspace version but has `publish = false`
  and is excluded from default/headless builds and release archives.
- **Crates.io name warning:** The package named `telltale` is an unrelated
  active session-types crate. It is not this project; the embedding package is
  `telltale-core` and its Rust import is `telltale_core`.
- `telltale` is the sole runtime executable and `telltale-*` is the canonical
  release asset naming. Runtime paths use `telltale-events.jsonl` and
  `telltale-state.json`; runtime configuration uses `TELLTALE_*` names only.
  Unknown inherited non-canonical variables are ignored, while explicit state
  and historical-event migration commands preserve source data and file semantics.
- `1.0.0` waits until the public CLI, embedding APIs, event contract, and
  configuration behavior are stable enough for explicit compatibility promises.

## Rust Toolchain Policy

Telltale is built, tested and released with the toolchain pinned in
`rust-toolchain.toml`. The CLI and Console promise no minimum supported Rust
version (MSRV); build them with that toolchain.

The embedding crates (`telltale-schema`, `telltale-rules`, `telltale-sources`,
`telltale-detect` and `telltale-core`) declare `rust-version = "1.88"` so their
dependency graph can use patched `time` releases (`>=0.3.47`). Every CI run checks
the independently locked external consumer, in all eight feature combinations,
on exactly Rust 1.88.0 on Linux, macOS and Windows (`make embedding-msrv-check`).
That lock holds the newest dependency releases Rust 1.88 can build
(`make embedding-lock-update`). A host on an older Rust than current stable should
resolve with Cargo's
`incompatible-rust-versions = "fallback"` (the default with resolver 3) so that
Cargo selects dependency releases its toolchain can build. Raising the embedding
MSRV is a breaking change for the next planned minor line and is recorded in the
changelog and migration guide.

## SemVer Policy

Before `1.0.0`, Telltale applies a stricter policy than the minimum SemVer
allowance for `0.y.z` versions:

| Change | Version | Examples |
| --- | --- | --- |
| Compatible fix | Patch within the applicable supported minor line | Bug fix, documentation, packaging, test-only change, or compatible detection improvement |
| Additive maturity work | Next planned minor line | New compatible capability or API that does not invalidate existing consumers |
| Breaking change | Next planned minor line | Removed or changed public API, incompatible CLI/config behavior, or incompatible event/rule contract |
| Stable compatibility commitment | Major (`1.0.0`) | Public interfaces are sufficiently settled for documented compatibility guarantees |

## Versioned Surfaces

The Cargo/package version is not the version of every data contract:

- **Package and CLI version:** the workspace root, five library crates and Console
  move in lockstep. Internal workspace dependency requirements must be updated
  together. The root binary and library crates use the same release version.
- **Event schema version:** `schema_version` and versioned identities such as
  Event 3.0 and `obs:v2` describe data compatibility independently of the Cargo
  version. Change them only when the event contract changes.
- **Configuration version:** configuration documents such as `version: 1` have
  their own migration rules. A package release does not automatically change a
  configuration version.
- **Native scanner state version:** standalone persisted state declares
  `state_schema_version: "1.0"`. Legacy unversioned state is not loaded by
  normal scanning; use `telltale migrate state --from <OLD> --to <NEW>`.
  State migration is explicit and does not migrate historical events.
- **Rule language and bundled rules:** Rule v1 content remains compatible in
  the 0.7 line. Removing syntax, changing evaluation meaning incompatibly,
  or invalidating existing rule documents requires a separately reviewed minor
  release rather than a routine patch batch.

The 0.7 embedding facade changes are listed in the
[migration guide](migrations/0.7.0.md#rust-embedding-changes-since-rc1); the
[embedding contract](embedding.md#contract-at-a-glance) is not a stable API
freeze or a promise for lower-level modules.

## Release Process

### Authoritative version gate

`make version-consistency-check` checks all Cargo workspace members, inherited
versions, exact internal requirements (including optional, target, dev and build
dependencies), and member lock entries, and tests the gate's own failure cases.

- `--pre-tag` validates a prospective candidate tag, including its required
  absence.
- Plain `--tag` is the release-workflow mode and permits its exact tag at HEAD.
- `--publication-order` and `--check-publication-order` validate the Cargo graph
  for post-publication metadata checks without requiring Git history or an
  absent tag.
- An RC tag requires the **full matching RC package version** (for example
  `v0.7.0-rc.4` with package `0.7.0-rc.4`).

Fetched immutable stable Git tags are the published-version floor; no
latest-release constant or live GitHub lookup is used. CI uses a full-history
checkout; before local release review, fetch trusted origin history and tags.
Shallow history or no prior stable tag fails closed. Development must be newer
than every stable tag, including one whose Release creation failed, and must not
reuse an already-tagged exact RC version. Offline checks cannot discover remote
tags that have not been fetched.

The same implementation runs in CI, `release-tag-review` (and therefore
`release-preflight`), and the release workflow before builds and publication.
The native verifier selects a reviewed checked-in pin for the requested
published tag and verifies existing artifacts; it never creates or modifies
them.

### Authorized release preparation

1. Release only from a reviewed commit on `main`.
2. Update the workspace package version and every internal workspace dependency
   version together. For stable promotion from an accepted RC, prepare that
   reviewed reversible stable-version commit before final preflight; it is not
   itself tagging or publication.
3. For an RC, prepare matching `0.7.0-rc.N` package metadata, then use the exact
   matching `v0.7.0-rc.N` tag only after authorization. The tag, Release
   metadata, archive names, checksums, attestations, and installer selection
   are immutable evidence; a validation-relevant change requires the next
   reviewed RC.
4. Update public release notes with capabilities, fixes, compatibility impact,
   and operator impact.
5. Run `make release-preflight` against the exact reviewed version commit while
   the matching `v<version>` tag is still absent, and review the staged/public
   file boundary.
6. Create the matching `v<version>` tag only after preflight, artifact-boundary,
   and GitHub publication-prerequisite gates pass.
7. Wait for the release workflow, then inspect the published artifacts and
   checksums before reporting the release complete.

## Crates.io Publication

Crates.io publication is a separate later distribution action from stable
GitHub tagging and GitHub binary Release. Deferring it does not block a stable
GitHub Release and does not weaken Cargo package-readiness gates. When it is
attempted, these requirements are mandatory.

Publish functional packages only after `cargo package --list`, package-boundary
checks, and a workspace-independent consumer build pass. Obtain the
authoritative graph-derived order with
`python3 scripts/version-consistency-check --publication-order`. It currently is:

1. `telltale-schema`
2. `telltale-rules`
3. `telltale-sources`
4. `telltale-detect`
5. `telltale-core`
6. `telltale-cli`

A first crates.io version must equal the current workspace version, and a
published version cannot be republished. Recheck registry ownership and name
availability immediately before publication, then publish in the gate's order,
waiting after each until it resolves from the index without a local patch.
After all six are available, remove every local `patch.crates-io` override and
confirm the clean consumers and CLI installation using only pinned
`=0.7.0` registry dependencies while that remains the workspace package
version. Advance that pin with each reviewed lockstep package version. Do not
declare publication complete before those unpatched checks pass, and do not
publish credentials or local release state.

## Pre-Releases

Candidates use `<minor>.0-rc.N` (a canonical nonnegative integer N without
leading zeros), only when external validation is useful. A pre-release tag and
package version must match exactly, and pre-releases carry no stable
compatibility guarantees. GitHub Release metadata sets `prerelease=true`; an RC
is never made the latest stable Release.

The installer keeps no-argument selection on `releases/latest`, while
`--release-tag v<minor>.0-rc.N` selects and validates one exact published
candidate before any user install or schedule mutation. `--from-source` uses that
same exact tag, validates its archive provenance, resolves its immutable commit,
and builds that source revision. Neither an RC workflow nor the stable GitHub
Release workflow publishes crates.
