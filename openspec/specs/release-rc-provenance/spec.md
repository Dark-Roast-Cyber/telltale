# release-rc-provenance Specification

## Purpose

Defines the observable release provenance contract for immutable Telltale
pre-release candidates and their later promotion to stable `0.5.0`.

## Requirements

### Requirement: Candidate package and tag lockstep

The release process SHALL accept a candidate only when the workspace package
version, all lockstep internal package requirements, and the `v<version>` tag
are the same Cargo-compatible pre-release value, and the tagged commit SHALL
already be an ancestor of reviewed `origin/main`.

#### Scenario: Valid RC candidate

- **WHEN** the reviewed main commit reports package version `0.5.0-rc.1` and is
  tagged `v0.5.0-rc.1`
- **THEN** the release preflight accepts the version/tag relationship and
  proceeds to the canonical candidate build

#### Scenario: Stable-version or branch-only mismatch

- **WHEN** a tag does not exactly match the workspace package version or its
  commit is not an ancestor of `origin/main`
- **THEN** release preflight fails before candidate artifacts or a Release are
  created

### Requirement: Explicit GitHub prerelease classification

The release process SHALL explicitly classify hyphenated candidate tags as
GitHub prereleases and the stable `v0.5.0` tag as a non-prerelease release; it
MUST NOT rely on tag-name inference or mark an RC as a normal latest release.

#### Scenario: RC Release metadata

- **WHEN** the workflow creates a Release for `v0.5.0-rc.1`
- **THEN** the Release is published with `prerelease=true` and is not eligible
  as the repository's latest stable release

#### Scenario: Stable Release metadata

- **WHEN** the workflow creates a Release for `v0.5.0`
- **THEN** the Release is published with `prerelease=false` using the normal
  stable-release semantics

### Requirement: Canonical candidate artifact evidence

For every target in the release matrix, the candidate process SHALL publish
only the canonical Telltale archive and its required public evidence: the
exact archive manifest, a matching `SHA256SUMS` entry, the archive attestation,
and the workflow/ref/source identity needed to relate the artifact to its
reviewed tag and commit.

#### Scenario: Complete target evidence

- **WHEN** the RC workflow completes successfully for a target
- **THEN** the target has a canonical `telltale-v0.5.0-rc.N-<target>` archive,
  an exact `SHA256SUMS` entry, a verified archive manifest, and an attestation
  for that exact archive subject

#### Scenario: Incomplete or noncanonical evidence

- **WHEN** an archive has a missing checksum, mismatched digest, noncanonical
  member, missing attestation, or source identity that cannot be tied to the
  reviewed tag commit
- **THEN** the candidate is not approved for downstream live validation

### Requirement: Immutable RC iteration

Published candidate tags and Release assets SHALL be immutable. A validation-
relevant code, package, installer, workflow, archive, checksum, or attestation
change SHALL use a new reviewed main commit and the next unused RC tag rather
than overwriting or reusing the published candidate.

#### Scenario: Defect requires a new candidate

- **WHEN** RC validation identifies a defect that changes candidate code or
  provenance-relevant release behavior
- **THEN** the fix is reviewed on a new main commit and released as the next
  unused `v0.5.0-rc.N` tag

#### Scenario: Unchanged artifact recheck

- **WHEN** a failure is proven to be a transient validation environment issue
  and the reviewed commit and immutable candidate artifacts are unchanged
- **THEN** the same candidate may receive a bounded recheck without changing
  its tag or assets

### Requirement: Stable promotion requires explicit gate completion

Stable `v0.5.0` promotion SHALL require explicit PASS evidence for the required
G-SERVICE, G-HEC, G-SPLUNK, native Windows, native macOS, release-preflight,
artifact-boundary, and publication-prerequisite gates. A required BLOCKED gate
MUST NOT be silently reclassified as PASS.

#### Scenario: Complete stable gate matrix

- **WHEN** all required candidate/live gates and final stable preflight pass on
  reviewed `main`
- **THEN** the package version may be promoted from the accepted RC to
  `0.5.0` and the matching stable tag may be created

#### Scenario: Required gate remains blocked

- **WHEN** any required stable gate remains BLOCKED or lacks measured evidence
- **THEN** stable `v0.5.0` tagging and publication remain prohibited
