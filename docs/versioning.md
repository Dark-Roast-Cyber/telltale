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
- The current preparation value is `0.5.0`. It is the stable package version
  prepared from accepted immutable `v0.5.0-rc.7`; the matching `v0.5.0` tag
  and GitHub Release remain absent until release-preflight, artifact-boundary,
  and GitHub publication-prerequisite gates pass. Crates.io publication is a
  separate later distribution action and does not block stable GitHub
  `v0.5.0`. The immutable
  `v0.5.0-rc.5` publication passed provenance checks, but its G-SERVICE gate
  failed on canonical optional `EnvironmentFile` validation. The immutable rc.6
  publication/provenance passed and repaired that defect, but G-SERVICE then
  failed on user-manager `WorkingDirectory` normalization. Immutable `rc.7`
  publication/provenance, G-SERVICE, and GitHub-hosted native gates passed.
- `v0.5.0-rc.1` is retained as immutable history at reviewed tag commit
  `8f261317022352ebc812c30814aa776964c84e6b`. Windows packaging failed, so it
  has no GitHub Release or complete five-target asset/checksum/attestation set.
  Never reuse that candidate.
- `v0.5.0-rc.2` is immutable history at reviewed commit
  `973ce825550941a824aa568a07f80036cd89f497`; do not mutate its tag, Release,
  assets, or evidence. `v0.5.0-rc.3` is immutable history at reviewed commit
  `a791ebf8894b3329030fad9e252e22d21e8b7e07` and has no GitHub Release. `rc.4`
  is historical; `rc.5` remains immutable at `e023ea91529f0731200aae1682b8d357a7b5f58c`,
  and `rc.6` is immutable at `88789d30ef34af720261e9e462e3cfd6274126e1`;
  `rc.7` is the accepted immutable candidate at
  `6696888cd5d559fa47b8252e3495524da9fbd1eb`.
- The six functional Cargo packages are `telltale-schema`, `telltale-rules`,
  `telltale-sources`, `telltale-detect`, `telltale-core`, and `telltale-cli`.
  The planned publication order is schema → rules → sources → detect → core →
  cli. Recheck crates.io availability immediately before any future
  publication.
- **Crates.io name warning:** The package named `telltale` is an unrelated
  active session-types crate. It is not this project; the embedding package is
  `telltale-core` and its Rust import is `telltale_core`.
- `telltale` is the sole runtime executable and `telltale-*` is the canonical
  release asset naming. Runtime paths use `telltale-events.jsonl` and
  `telltale-state.json`; runtime configuration uses `TELLTALE_*` names only.
  Unknown inherited non-canonical variables are ignored, while explicit state
  and historical-event migration commands preserve source data and file semantics.
  The Linux installer, canonical user units, release archives, and release workflow use
  the same Telltale-only identity.
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
   version together. For stable promotion from an accepted RC, prepare that
   reviewed reversible `0.5.0` commit before final preflight; it is not itself
   tagging or publication.
3. For an RC, use the exact matching `v0.5.0-rc.N` tag. The tag, Release
   metadata, archive names, checksums, attestations, and installer selection
   are immutable evidence; a validation-relevant change requires the next
   reviewed RC rather than reusing a tag or asset.
4. Update public release notes with capabilities, fixes, compatibility impact,
   and operator impact. Internal planning history stays out of public notes.
5. Run `make release-preflight` against the exact reviewed version commit while
   the matching `v<version>` tag is still absent, and review the staged/public
   file boundary.
6. Create the matching `v<version>` tag only after preflight, artifact-boundary,
   and GitHub publication-prerequisite gates pass. Crates.io publication is not
   part of this GitHub tagging step. For example, a compatible maintenance
   release `0.3.1` requires tag `v0.3.1`; the approved breaking milestone
   requires `v0.5.0` only after all migration and reliability gates pass.
7. Wait for the release workflow, then inspect the published artifacts and
   checksums before reporting the release complete.

The current 0.5.0 section documents the breaking package and Event 3.0
changes. The older [0.4.0 migration guide](migrations/0.4.0.md) documents the
unpublished API hardening work folded into this release.

## Crates.io Publication

Crates.io publication is a separate later distribution action from stable
GitHub tagging and GitHub binary Release. Deferring crates.io does not block
stable GitHub `v0.5.0` and does not weaken Cargo package-readiness gates.
When crates.io publication is later attempted, the registry-specific safety
requirements in this section remain mandatory.

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
`=0.5.0` registry dependencies while that remains the workspace package
version. Advance this pin with the lockstep package version before 0.5.0
publication. Do not declare publication complete before those unpatched checks
pass, and do not publish credentials or local release state.

## Pre-Releases

Use Cargo-compatible pre-release versions such as `0.5.0-alpha.1`,
`0.5.0-beta.1`, or `0.5.0-rc.N` only when external validation is useful. A
pre-release tag and package version must still match exactly, and pre-releases
do not carry stable compatibility guarantees. GitHub Release metadata must set
`prerelease=true`; an RC must never be made the normal latest stable Release.
The checked-in installer keeps no-argument selection on `releases/latest`, while
`--release-tag v0.5.0-rc.N` selects and validates one exact published candidate
before any user install or schedule mutation. `--from-source` uses that same
exact tag, validates its archive provenance, resolves its immutable commit, and
builds that source revision. Binary
GitHub Releases and later crates.io publication are separate operations;
neither an RC workflow nor the stable GitHub Release workflow publishes crates.
