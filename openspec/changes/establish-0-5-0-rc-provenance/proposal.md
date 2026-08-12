## Why

`G-SERVICE` is correctly blocked because the reviewed 0.5.0 code has no
approved candidate tag, canonical release archive, `SHA256SUMS` entry, or
fixed digest. The release workflow can create those immutable artifacts only
from a package-version-matching tag whose commit is already on `main`, while
stable `v0.5.0` is not eligible until the remaining live release gates pass.

This change defines the smallest legitimate pre-release provenance path: a
reviewed `0.5.0-rc.1` promotion, exact artifact evidence, ordered live-gate
validation, immutable RC iteration, and only then stable `0.5.0` promotion.
The RC resolves the missing-artifact provenance blocker only; the previously
observed unexpected legacy service drop-in remains an independent fail-closed
G-SERVICE precondition.

## What Changes

- Establish Strategy A, a true `0.5.0-rc.1` candidate, as the release path.
- Record the dependency loop and the required order: candidate package version,
  reviewed `main` commit, matching RC tag, canonical workflow artifacts,
  immutable provenance evidence, live gates, and stable promotion.
- Define the lockstep package-version transition for the workspace, all internal
  Cargo requirements, `Cargo.lock`, CLI/package assertions, and release tests;
  keep Event 3.0, configuration, state, and rule-contract versions unchanged.
- Specify the smallest release-workflow change needed to pass explicit
  `prerelease: true` for hyphenated RC tags and `false` for stable tags, while
  preserving the existing tag/version/ancestry, Telltale-only packaging,
  attestation, checksum, manifest, and installer-provenance gates.
- Define exact RC installer selection/provenance so G-SERVICE cannot silently
  consume `releases/latest`, another tag, a different archive, or
  `--skip-checksum`; any installer support needed for an explicit authorized
  tag is release tooling only and must preserve the stable default path.
- Define the per-target artifact evidence record: RC tag, reviewed `main` SHA,
  package version, archive filename, archive and extracted-binary SHA-256
  values, `SHA256SUMS` entry, canonical manifest result, Actions attestation,
  and workflow/run identity.
- Define the post-RC order for G-SERVICE, G-HEC, G-SPLUNK, native Windows and
  macOS validation, defect follow-up, stable preflight, final `0.5.0`, and
  separate dependency-ordered crates.io publication.
- Define immutable `rc.2`, `rc.3`, and later iteration rules, including when a
  deterministic recheck is sufficient and when a new reviewed RC is required.

### Rejected Strategies

- **Strategy B — branch-based candidate artifacts:** rejected as a weaker,
  duplicate provenance path that would require new artifact infrastructure or
  changed G-SERVICE acceptance semantics instead of using the existing tag,
  checksum, attestation, and release-manifest contract.
- **Strategy C — stable `v0.5.0` now:** rejected because G-SERVICE, G-HEC,
  G-SPLUNK, native Windows/macOS validation, and stable preflight remain
  unresolved; a stable tag must not be used as a validation bypass.
- **Strategy D — tag the current release branch:** rejected because the
  release workflow requires the tagged commit to be an ancestor of
  `origin/main`; the candidate must be reviewed and merged to `main` first.

### Non-goals

- Do not create a tag, GitHub Release, RC artifact, checksum file, or package
  publication during this planning or its later apply session. Those are
  separate, freshly authorized release operations after the preparation batch
  stops.
- Do not merge or ready PR #9 in this planning session. The later process may
  mark it ready only after RC-preparation review and green CI; merging the
  candidate to `main` is distinct from declaring stable release readiness.
- Do not run G-SERVICE, HEC/Splunk, native-host validation, or installer/service
  validation in this planning session.
- Do not change scanner runtime behavior, Event 3.0 schemas, historical
  schemas, configuration/state schema versions, detection semantics, or
  deployment-specific SIEM settings.
- Do not publish RC or stable crates merely because the GitHub binary release
  workflow runs; crates.io publication remains a separate stable-release step.
- Do not modify the README/docs stash or inspect or modify
  `tokscale-export-20260809-013857.json`.

## Capabilities

### New Capabilities

- `release-rc-provenance`: package/tag lockstep, explicit prerelease release
  metadata, immutable canonical artifact evidence, and RC-to-stable promotion
  rules for the release workflow.

### Modified Capabilities

- `installer-service-archive`: add exact approved release-tag selection and
  pre-mutation artifact provenance requirements for candidate validation while
  preserving the stable default installer path and checksum enforcement.

## Impact

- **Release metadata:** later RC preparation will touch only package/release
  version surfaces, including the workspace package version, five internal
  workspace dependency requirements, generated `Cargo.lock` entries, and
  version-sensitive release tests/docs. Event, config, state, and schema
  versions remain independent and unchanged.
- **Release workflow:** later implementation may add explicit conditional
  prerelease metadata to `softprops/action-gh-release@v3` and tests for RC versus
  stable behavior. Existing canonical package, ancestry, installer-provenance,
  attestation, checksum, Windows ZIP, and manifest checks remain mandatory.
- **Installer/release tooling:** later implementation must provide or verify a
  safe explicit RC tag selection path for downstream validation, while keeping
  the default stable `releases/latest` path and mandatory checksum verification.
- **Process/docs/tests:** the apply session will record the provenance ledger,
  RC/stable transition rules, focused test expectations, and the exact handoff
  for a fresh validation session. No release side effect is authorized by this
  planning artifact alone.
- **Authoritative references:** `PLAN.md` Release Posture and Phase 6 gate
  evidence; `docs/versioning.md`; `docs/release-readiness.md`;
  `.github/workflows/release.yml`; `scripts/install-telltale`; and the
  `resolve-g-service-validation-gate` archived evidence. The prerelease action
  decision is based on the `softprops/action-gh-release` input documentation
  and GitHub's Releases API contract, where `prerelease` is an explicit boolean
  defaulting to `false`.
