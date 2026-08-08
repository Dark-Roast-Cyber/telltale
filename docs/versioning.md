# Versioning and Releases

Telltale uses Semantic Versioning for the CLI and Cargo packages, with a
conservative policy for the `0.x` development series. Git tags, GitHub Releases,
and Cargo package versions use the same version number and the `v<version>` tag
format.

## Current Series

- `v0.1.0` is the first public binary release.
- `0.2.0` is the prior maturity release.
- `0.3.0` is the current released line for the event and scoring contract.
- `0.4.0` is an unpublished API-hardening line and will not be released
  separately. Its completed work is folded into `0.5.0`.
- `0.3.x` remains the current released maintenance line until `0.5.0` ships.
- `0.5.0` is the approved coherent breaking milestone for the hard Telltale
  technical migration, embedded-triage removal, schema/configuration changes,
  and install-to-SIEM reliability proof. Follow-up compatible fixes use `0.5.x`.
- The six functional Cargo packages are `telltale-schema`, `telltale-rules`,
  `telltale-sources`, `telltale-detect`, `telltale-core`, and `telltale-cli`.
  The planned publication order is schema → rules → sources → detect → core →
  cli. Recheck crates.io availability immediately before any future
  publication.
- **Crates.io name warning:** The package named `telltale` is an unrelated
  active session-types crate. It is not this project; the embedding package is
  `telltale-core` and its Rust import is `telltale_core`.
- `telltale` is the canonical executable and `telltale-*` is the canonical
  release asset naming. The currently released `adr` compatibility command and
  `adr-*` aliases are removed by the breaking 0.5.0 migration; migration tooling
  handles supported historical state rather than retaining runtime aliases.
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
| Compatible fix | Patch (`0.3.x`; `0.5.x` after the 0.5.0 release) | Bug fix, documentation, packaging, test-only change, or compatible detection improvement |
| Additive maturity work | Next planned minor line | New compatible capability or API that does not invalidate existing consumers |
| Breaking change | Next planned minor (`0.5.0` for the approved migration) | Removed or changed public API, incompatible CLI/config behavior, or incompatible event/rule contract |
| Stable compatibility commitment | Major (`1.0.0`) | Public interfaces are sufficiently settled for documented compatibility guarantees |

The `0.3.x` line is the compatibility path for post-`0.3.0` fixes. The
unpublished `0.4.0` API-hardening work is incorporated into the explicitly
approved 0.5.0 milestone and will not create a separate release line. The 0.5.0
scope, compatibility impact, migration requirements, acceptance criteria, and
release review are maintained in the internal execution plan.

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
- **Native scanner state version:** standalone persisted state declares
  `state_schema_version: "1.0"`. Legacy unversioned state is not loaded by
  normal scanning; use `telltale migrate state --from <OLD> --to <NEW>`.
  State migration is explicit and does not migrate historical events.
- **Rule language and bundled rules:** compatible detections and rule updates
  remain on the current `0.3.x` line, then `0.5.x` after the 0.5.0 release.
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
   release `0.3.1` requires tag `v0.3.1`; the approved breaking milestone
   requires `v0.5.0` only after all migration and reliability gates pass.
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
`=0.4.0` registry dependencies while that remains the workspace package
version. Advance this pin with the lockstep package version before 0.5.0
publication. Do not declare publication complete before those unpatched checks
pass, and do not publish credentials or local release state.

## Pre-Releases

Use Cargo-compatible pre-release versions such as `0.5.0-alpha.1`,
`0.5.0-beta.1`, or `0.5.0-rc.1` only when external validation is useful. A
pre-release tag and package version must still match exactly, and pre-releases
do not carry stable compatibility guarantees.
