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

- **WHEN** the reviewed main commit reports package version `0.5.0-rc.N` and is
  tagged `v0.5.0-rc.N`
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

- **WHEN** the workflow creates a Release for `v0.5.0-rc.N`
- **THEN** the Release is published with `prerelease=true` and is not eligible
  as the repository's latest stable release

#### Scenario: Stable Release metadata

- **WHEN** the workflow creates a Release for `v0.5.0`
- **THEN** the Release is published with `prerelease=false` using the normal
  stable-release semantics

### Requirement: Canonical candidate artifact evidence

For every target in the release matrix, the candidate process SHALL publish
only the canonical Telltale archive and its required public evidence: the exact
archive manifest, a matching `SHA256SUMS` entry, the archive attestation, the
fixed-name `telltale-sbom.cdx.json` asset and its checksum, the SBOM attestation
subject, and the workflow/ref/source identity needed to relate the evidence to
the reviewed tag and commit. Archive members and archive names SHALL remain
unchanged.

#### Scenario: Complete target evidence

- **WHEN** the RC workflow completes successfully for a target
- **THEN** the target has its canonical archive, exact archive checksum,
  verified archive manifest, and archive attestation, and the release has the
  deterministic fixed-name CycloneDX SBOM, an exact SHA256SUMS line, and an
  attestation subject for that SBOM

#### Scenario: Incomplete or noncanonical evidence

- **WHEN** an archive or SBOM has a missing checksum, mismatched digest,
  noncanonical member/content, missing attestation, or source identity that
  cannot be tied to the reviewed tag commit
- **THEN** release publication SHALL fail before the GitHub Release is created

### Requirement: Finalized Windows ZIP validation

For the Windows target, the release process SHALL create the ZIP with the
canonical nine-member manifest, finalize and close the ZIP writer, reopen that
same serialized archive read-only, and validate the exact ordinal canonical
regular-member set before reading every member payload fully to EOF. This
validation SHALL succeed before the staged binary smoke test, archive
attestation, or artifact upload; any packaging or validation error SHALL stop
the workflow.

#### Scenario: Windows archive is validated after finalization

- **WHEN** the Windows package helper has written the staged bundle
- **THEN** it closes the writer and reopens the same archive read-only
- **AND** it rejects noncanonical, duplicate, directory, link, unsupported,
  malformed, corrupt, or unreadable members
- **AND** it reads every canonical member to EOF before downstream evidence
  steps run

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

### Requirement: Native platform evidence executes published artifacts

Native Windows and native macOS release gates SHALL prove runtime behavior of
the exact final published GitHub Release artifact for the target architecture.
A native platform gate MAY be satisfied by either an explicitly authorized
native host or an appropriate GitHub-hosted native runner. The evidence MUST
download that Release archive, verify its filename and SHA-256 against the
published `SHA256SUMS` and the pinned candidate identity, extract it into an
isolated temporary directory, verify the extracted binary SHA-256, and execute
that same downloaded binary. The gate MUST NOT treat cross-compilation, archive
creation, source-unit tests on another OS, staged or rebuilt binaries, or
binary inspection without native execution as native-release evidence.

Required native targets are Windows x86_64, macOS x86_64, and macOS arm64.
Each target MUST record runner OS and architecture, archive filename and hash,
binary hash, exact version identity, bundled-rule validation, one bounded
positive synthetic fixture scan, and canonical Event 3.0 schema validation.
The scan MUST use fixture-safe, no-local-config behavior and MUST NOT load
host or operator rule packs, scan runner session stores, send HEC events,
query Splunk, query ADR runtime resources, install Telltale persistently, or
publish artifacts. If GitHub-hosted CI cannot supply a required native
architecture, that target MUST be recorded as `BLOCKED_EXTERNAL` rather than
silently substituted.

#### Scenario: GitHub-hosted native runner executes the published artifact

- **WHEN** a GitHub-hosted native runner downloads the final published Release
  archive for its architecture, verifies provenance, extracts the binary, and
  that same binary exits 0 with the exact candidate version and commit prefix
  while bundled-rule validation, the bounded positive fixture, and Event 3.0
  schema validation pass
- **THEN** that native platform target is recorded as `PASS`

#### Scenario: Rebuilt or cross-compiled binary is not native evidence

- **WHEN** validation builds Telltale from source, executes a staged CI
  binary, or runs a binary whose architecture does not match the runner
- **THEN** the result MUST NOT be classified as native-release `PASS`

#### Scenario: Required GitHub-hosted architecture is unavailable

- **WHEN** GitHub cannot provide a native runner for a required target
  architecture
- **THEN** that target is recorded as `BLOCKED_EXTERNAL` and MUST NOT be
  silently replaced by another architecture

### Requirement: Live HEC and Splunk validation are environment-dependent

Live G-HEC and live G-SPLUNK SHALL use the outcomes `PASS`,
`SKIPPED_EXTERNAL`, and `FAIL`. `PASS` means an approved controlled
environment was available and the bounded live validation succeeded; that
result is additional release evidence and is not required for stable
promotion. `SKIPPED_EXTERNAL` means no approved endpoint, credential,
authorization, or suitable environment was available; it is not a product
failure, not `BLOCKED`, and not a stable-release blocker. `FAIL` means an
approved environment was available, validation was attempted, and evidence
demonstrates a Telltale product defect.

#### Scenario: Live HEC is skipped without an approved environment

- **WHEN** the operator has not supplied an approved HEC endpoint, token
  reference, authorization window, or reachable collector
- **THEN** live G-HEC is recorded as `SKIPPED: EXTERNAL HEC ENVIRONMENT NOT
  AVAILABLE` and MUST NOT block remaining required gates

#### Scenario: Live Splunk does not inherit a skipped HEC blocker

- **WHEN** live G-HEC is `SKIPPED_EXTERNAL` or no approved Splunk environment
  is available
- **THEN** live G-SPLUNK is recorded as `SKIPPED_EXTERNAL` and MUST NOT be
  treated as a missing required PASS

### Requirement: Deterministic HEC and Splunk-format evidence remains mandatory

Release-preflight and the existing HEC integration, unit, and CLI tests SHALL
remain mandatory stable-release gates for HEC configuration, secret handling,
canonical Event 3.0 serialization, JSONL/HEC body parity, retry and failure
semantics, and deterministic Splunk-format fixtures. A deterministic failure
in those gates SHALL block stable promotion even when live G-HEC is
`SKIPPED_EXTERNAL`.

#### Scenario: Deterministic HEC parity failure blocks promotion

- **WHEN** a required JSONL/HEC body-parity, retry, unreachable-endpoint,
  secret-handling, or schema fixture test fails
- **THEN** stable `v0.5.0` promotion remains prohibited even if live G-HEC is
  `SKIPPED_EXTERNAL`

### Requirement: Stable promotion requires explicit gate completion

Stable `v0.5.0` GitHub promotion SHALL require explicit PASS evidence for the
required G-SERVICE, native Windows, native macOS, release-preflight,
artifact-boundary, and GitHub publication-prerequisite gates, and for the
mandatory deterministic HEC and Splunk-format product gates. Native Windows
and native macOS PASS MAY be produced by an authorized native host or by a
GitHub-hosted native runner that executed the final published Release artifact
for that architecture. Live G-HEC and live G-SPLUNK SHALL be
environment-dependent evidence: `PASS` or `SKIPPED_EXTERNAL` satisfies the
stable matrix, and `FAIL` remains a release blocker. A required `BLOCKED`,
`BLOCKED_EXTERNAL`, or `FAIL` gate MUST NOT be silently reclassified as
`PASS`.

Preparing a reviewed reversible stable-version commit at package version
`0.5.0` is a prerequisite for final stable preflight and is not itself
irreversible promotion. Final stable `make release-preflight` SHALL run
against that exact reviewed commit while `v0.5.0` is absent. The existing
tag-review gate SHALL continue to reject an already-existing matching tag.
Irreversible stable GitHub tagging and GitHub Release publication remain
prohibited until that preflight, the separate artifact-boundary gate, and the
GitHub publication-prerequisite gate all have PASS evidence.

#### Scenario: Complete stable gate matrix

- **WHEN** all required candidate and native gates pass, a reviewed reversible
  stable-version commit changing the package version to `0.5.0` has been
  prepared on `main`, final stable preflight passes against that exact commit
  while `v0.5.0` is absent, and live G-HEC and live G-SPLUNK are each `PASS` or
  `SKIPPED_EXTERNAL`
- **THEN** the matching stable GitHub tag may be created only after the
  separate artifact-boundary and GitHub publication-prerequisite gates also
  pass

#### Scenario: Required gate remains blocked

- **WHEN** any required stable gate remains `BLOCKED`, `BLOCKED_EXTERNAL`, or
  `FAIL`, or a mandatory deterministic HEC or Splunk-format gate lacks passing
  evidence
- **THEN** stable `v0.5.0` GitHub tagging and GitHub Release publication
  remain prohibited

#### Scenario: GitHub-hosted native evidence completes the platform gates

- **WHEN** Windows x86_64, macOS x86_64, and macOS arm64 each have `PASS`
  evidence from GitHub-hosted native execution of the published Release
  artifacts
- **THEN** the native platform gates are complete and MUST NOT still require a
  physical host

#### Scenario: Existing matching tag still blocks preflight

- **WHEN** the workspace package version is `0.5.0-rc.N` and tag
  `v0.5.0-rc.N` already exists, or the workspace package version is `0.5.0`
  and tag `v0.5.0` already exists
- **THEN** `release-tag-review` fails and release-preflight MUST NOT be
  considered passing

### Requirement: GitHub stable publication is independent of crates.io

Stable GitHub `v0.5.0` tagging and GitHub binary Release SHALL require the
accepted release gate matrix, final stable preflight, artifact-boundary
review, and GitHub publication prerequisites. Crates.io publication SHALL
remain a separate later distribution action and MUST NOT be a required PASS
for GitHub stable publication. Deferring crates.io publication MUST NOT block
stable GitHub `v0.5.0`. Cargo package readiness SHALL remain a mandatory
stable-release gate, including version lockstep, internal dependency pins,
lock entries, `release-crate-manifest`, `package-verify`, registry-style
consumer verification, normalized CLI installation verification, and package
public-boundary checks. When crates.io publication is later attempted, the
existing registry-specific safety requirements SHALL remain mandatory.

#### Scenario: Operator defers crates.io publication

- **WHEN** the operator defers crates.io publication
- **THEN** that deferral MUST NOT by itself block stable GitHub `v0.5.0`
  tagging or GitHub binary Release
- **AND** Cargo package-readiness evidence remains required

#### Scenario: Later crates.io publication keeps registry safety

- **WHEN** crates.io publication is later authorized
- **THEN** package name and version availability checks, ownership checks,
  credential readiness, dependency-order publication, registry propagation
  waits, unpatched external consumer verification, and unpatched CLI
  installation verification remain mandatory
