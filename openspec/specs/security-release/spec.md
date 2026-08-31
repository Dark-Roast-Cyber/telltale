# security-release Specification

## Purpose
TBD - created by archiving change 2026-08-30-v060-security-release. Update Purpose after archive.
## Requirements
### Requirement: Actionable security reporting

The repository SHALL publish a `SECURITY.md` that identifies the currently
supported version posture, provides a private reporting path based on actual
repository capabilities, warns against public disclosure, and requests
synthetic reproduction data without secrets or raw session content.

#### Scenario: Private reporting capability is unavailable

- **WHEN** GitHub private vulnerability reporting is disabled
- **THEN** the security policy SHALL say so, SHALL not invent an email address or
  response SLA, SHALL direct reporters to a private maintainer contact path, and
  SHALL prohibit sensitive details in public issues

### Requirement: Repository-specific threat model

The repository SHALL document source/session data, config/rules, parser
ownership, local state/outbox, remote sinks, dependencies, build/CI, release,
publishing, attacker classes, excluded actors, mitigations, and residual risks,
with links to existing privacy, durable-delivery, installer, and release docs.

#### Scenario: Threat coverage is reviewed

- **WHEN** a maintainer reviews the threat model
- **THEN** each listed boundary SHALL identify its threat, current mitigation,
  and residual or excluded condition without claiming perfect redaction,
  exactly-once delivery, or Issue #23 completion

### Requirement: Locked dependency gates

The repository SHALL provide repository-owned commands that verify exact
`cargo-audit` and `cargo-deny` versions, run RustSec audit with warnings denied,
and run cargo-deny advisory, ban, license, and source checks against the locked
workspace graph. Unknown registries/git sources, wildcard requirements, and
unreviewed duplicate versions SHALL fail the deny gate.

#### Scenario: A dependency policy violation appears

- **WHEN** the lockfile contains an advisory, unapproved source, wildcard, or
  license not covered by the live policy
- **THEN** the repository-owned security gate SHALL fail before CI or release
  succeeds

#### Scenario: A graph-derived exception is needed

- **WHEN** the live locked graph requires a duplicate-version or unusual-license
  exception
- **THEN** the exception SHALL identify the exact package/version and rationale
  in `deny.toml` and SHALL not disable advisory/source checks for unrelated crates

### Requirement: Immutable workflow dependencies

Every external GitHub Action in the public CI, release, and native-verification
workflows SHALL use a real lowercase 40-character commit SHA and a readable
version comment. A repository-owned static check SHALL fail on a mutable action
reference. Dependabot SHALL propose weekly GitHub Actions and Cargo updates.

#### Scenario: An action uses a tag or branch

- **WHEN** a workflow action ref is not a full commit SHA
- **THEN** the workflow-pin gate SHALL fail

### Requirement: Reproducible release SBOM

The release process SHALL generate a fixed-name `telltale-sbom.cdx.json` in
CycloneDX JSON from `cargo metadata --locked` and the released workspace's
normal/build dependency graph. Generation SHALL omit host paths and
nondeterministic timestamps, SHALL compare repeated output bytes before the
asset is accepted, and SHALL validate the emitted deterministic CycloneDX 1.6
subset. That subset SHALL enforce mutually exclusive license choices, required
document/metadata/root/component/dependency/ref relationships, component
SHA-256 hashes, lockfile/scope properties, and lowercase serial format. SPDX
`WITH`, `AND`, and `OR` expressions SHALL use `licenses[].expression`, not
`licenses[].license.id`.

#### Scenario: SBOM generation is repeated

- **WHEN** locked metadata is read twice without a source or lockfile change
- **THEN** the generated CycloneDX bytes SHALL be identical and the command SHALL
  report the output digest

#### Scenario: SPDX expression license is emitted

- **WHEN** Cargo metadata reports an SPDX expression using `WITH`, `AND`, or
  `OR`
- **THEN** the corresponding CycloneDX license choice SHALL contain only an
  `expression` field and SHALL not place the expression in `license.id`

#### Scenario: SBOM content or asset transfer is inconsistent

- **WHEN** the release SBOM is missing, malformed, noncanonical, or differs from
  the locked graph
- **THEN** the publication job SHALL run the repository graph-match checker after
  downloaded artifact-set validation and fail before checksum generation; the
  artifact manifest and publication gates SHALL also fail before publication

### Requirement: Existing release integrity remains mandatory

The release SHALL retain tag/version/ancestry and package-boundary checks,
archive member validation, SHA256SUMS, per-archive attestations, native build
and smoke gates, and fail-closed release reservation/publication ordering. The
SBOM SHALL be included in the release asset set, SHA256SUMS, artifact manifest,
and have an attestation subject without changing archive members.

#### Scenario: A required gate fails

- **WHEN** preflight, a target build/attestation, exact artifact set, SBOM,
  checksum, or manifest gate fails
- **THEN** the final release publication job SHALL not run successfully

#### Scenario: Windows runtime support is considered

- **WHEN** a maintainer evaluates Windows clean-host execution or CRT behavior
- **THEN** that work SHALL remain the independent Issue #23 release gate and
  SHALL not be claimed as solved by this security-release change
