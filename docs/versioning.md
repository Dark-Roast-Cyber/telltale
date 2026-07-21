# Versioning and Releases

Telltale uses Semantic Versioning for the CLI and Cargo packages, with a
conservative policy for the `0.x` development series. Git tags, GitHub Releases,
and Cargo package versions use the same version number and the `v<version>` tag
format.

## Current Series

- `v0.1.0` is the first public binary release.
- `0.2.0` is the next planned maturity release.
- The project does not jump directly to `0.5.0`. Compatible follow-up releases
  use the `0.2.x` patch line.
- `1.0.0` waits until the public CLI, embedding APIs, event contract, and
  configuration behavior are stable enough for explicit compatibility promises.

## SemVer Policy

Before `1.0.0`, Telltale applies a stricter policy than the minimum SemVer
allowance for `0.y.z` versions:

| Change | Version | Examples |
| --- | --- | --- |
| Compatible fix | Patch (`0.2.x`) | Bug fix, documentation, packaging, test-only change, or compatible detection improvement |
| Additive maturity work | Minor (`0.2.0`, then a later planned minor line) | New compatible capability or API that does not invalidate existing consumers |
| Breaking change | Next minor (`0.3.0`, then `0.4.0` if needed) | Removed or changed public API, incompatible CLI/config behavior, or incompatible event/rule contract |
| Stable compatibility commitment | Major (`1.0.0`) | Public interfaces are sufficiently settled for documented compatibility guarantees |

The `0.2.x` line is the default path for post-`0.2.0` fixes and small
compatible improvements. A later `0.x` minor line requires a documented reason;
it is not a destination for routine progress or accumulated patch releases.

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
- **Rule language and bundled rules:** additive detections and compatible rule
  updates follow the package patch or minor release. Removing syntax, changing
  evaluation meaning incompatibly, or invalidating existing rule documents is
  a breaking change and requires the next planned `0.x` minor line.

## Release Process

1. Release only from a reviewed commit on `main`.
2. Update the workspace package version and every internal workspace dependency
   version together.
3. Update public release notes with capabilities, fixes, compatibility impact,
   and operator impact. Internal planning history stays out of public notes.
4. Run `make release-preflight` and review the staged/public file boundary.
5. Create the matching `v<version>` tag. For example, package version `0.2.1`
   requires tag `v0.2.1`.
6. Wait for the release workflow, then inspect the published artifacts and
   checksums before reporting the release complete.

## Crates.io Publication

Publish library crates only after `cargo package --list`, package-boundary
checks, and a workspace-independent consumer build pass. Publish dependencies
first:

1. `telltale-schema`
2. `telltale-rules`
3. `telltale-sources`
4. `telltale-detect`
5. `telltale`

If the crates have not previously been published, their first crates.io version
must equal the current workspace version. A version already published on
crates.io cannot be republished; increment the package version deliberately
instead of reusing it.

## Pre-Releases

Use Cargo-compatible pre-release versions such as `0.2.0-alpha.1`,
`0.2.0-beta.1`, or `0.2.0-rc.1` only when external validation is useful. A
pre-release tag and package version must still match exactly, and pre-releases
do not carry stable compatibility guarantees.
