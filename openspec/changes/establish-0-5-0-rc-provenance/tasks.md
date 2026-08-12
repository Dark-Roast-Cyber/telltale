## 1. Freeze the RC contract and boundaries

- [x] 1.1 Reconfirm the reviewed candidate source, PR #9 Draft/merge state,
  `origin/main` ancestry rule, current gate matrix, and the protected README/
  docs stash and Tokscale export; record that this change does not authorize a
  tag, GitHub Release, publication, installer/service run, HEC/Splunk work, or
  native-host validation. Preserve the independent G-SERVICE manager
  precondition: the previously observed unexpected legacy service drop-in is a
  separate fail-closed blocker and is not waived by obtaining an RC artifact.
- [x] 1.2 Record the dependency loop in the release handoff: G-SERVICE needs
  an approved tag/archive/digest; the tagged workflow creates those artifacts;
  the tag must point to reviewed `main`; and stable `v0.5.0` must wait for all
  required gates.
- [x] 1.3 Establish the redacted per-target provenance ledger fields and
  acceptance rules from `design.md`, including tag, source SHA, package
  version, archive/member manifest, archive and binary hashes, `SHA256SUMS`,
  attestation, workflow run, and tagged installer blob.

## 2. Prepare the lockstep RC package version

- [x] 2.1 Change only the package/release version surfaces from `0.5.0` to
  `0.5.0-rc.1`: the root workspace version and all five internal workspace
  dependency requirements; leave member `version.workspace = true` manifests
  unchanged.
- [x] 2.2 Regenerate `Cargo.lock` and verify all six functional packages and
  internal requirements resolve to the same RC version with `cargo metadata
  --locked`; do not change Event 3.0, historical, configuration, state, or
  rule-language schema versions.
- [x] 2.3 Audit and update only release/package-sensitive tests, fixtures,
  package verification, CLI version assertions, and candidate documentation;
  preserve stable `=0.5.0` registry/publication checks for the later stable
  promotion and do not globally replace unrelated historical version literals.

## 3. Make the release workflow RC-safe

- [x] 3.1 Add explicit conditional prerelease metadata to the existing
  `softprops/action-gh-release@v3` step: validated hyphenated RC tags create a
  prerelease and stable `v0.5.0` creates a normal release; retain the exact
  package/tag check, `origin/main` ancestry check, installer blob check, target
  matrix, canonical Telltale-only archives, Windows ZIP hardening,
  attestations, `SHA256SUMS`, and manifest verification. Add an existing-
  Release/tag guard and disable asset overwrites so a rerun cannot mutate a
  published RC.
- [x] 3.2 Add focused workflow/public-boundary assertions for both
  `v0.5.0-rc.1` and `v0.5.0`, including explicit prerelease behavior, canonical
  archive/attestation subjects, no ADR release surface, and no alternate
  branch-artifact path.
- [x] 3.3 Validate that the workflow's generated filenames and package/tag
  equality continue to use the exact RC tag without creating release artifacts
  locally or invoking the tag-triggered workflow.

## 4. Make exact RC installer provenance executable

- [x] 4.1 Add a narrowly scoped optional explicit release-tag input to
  `scripts/install-telltale` for approved candidate validation. Query the exact
  tag's published GitHub Release before acquiring the installer lock or
  changing files, schedules, units, or the manager; require exact `tag_name`,
  `draft=false`, and `prerelease=true` RC metadata; derive the archive and
  `SHA256SUMS` URLs from that tag; and keep the no-argument stable
  `releases/latest` behavior unchanged.
- [x] 4.2 Ensure `--from-source` uses the same exact selected tag, and retain
  current checksum verification, archive manifest rejection, binary version
  verification, current-user safety, and explicit `--skip-checksum` semantics;
  the G-SERVICE procedure must never use the bypass.
- [x] 4.3 Add synthetic installer fixtures/tests for exact RC selection, tag
  mismatch, draft/non-RC rejection, wrong archive/checksum, wrong binary
  version, tagged installer provenance, and stable default compatibility. Do
  not query live GitHub releases or use credentials in tests.

## 5. Document and validate candidate preparation

- [x] 5.1 Update the applicable release/version/installation guidance with the
  RC-to-stable transition, explicit candidate selection, GitHub prerelease
  semantics, artifact evidence requirements, and the separation between GitHub
  binary releases and crates.io publication.
- [x] 5.2 Run package-boundary, package verification, public documentation,
  canonical identity, workflow-shape, installer-fixture, and archive-manifest
  checks using synthetic/local inputs only; confirm no package version,
  release workflow, tag, release asset, checksum file, or protected boundary
  was changed outside the scoped preparation.
- [ ] 5.3 Obtain independent review of the RC preparation and keep PR #9 Draft
  until the candidate code, version transition, workflow adjustment, and
  exact-tag installer path are approved and CI is green.

## 6. Prepare the candidate release and live-gate handoff (do not execute)

- [x] 6.1 Write the operator handoff for PR #9 readiness and normal merge to
  `main`: candidate version and supporting changes complete, independent review
  passed, and CI green. Do not modify PR state in this change; treat a later
  merge as merge readiness, not stable-release approval.
- [x] 6.2 Write the separate release-operation checklist for tagging only the
  reviewed main commit `v0.5.0-rc.1`, verifying the five target archives,
  explicit prerelease Release metadata, attestations, `SHA256SUMS`, exact
  manifests, release-level metadata, and installer provenance. Do not create a
  tag, Release, artifact, or checksum in this change.
- [x] 6.3 Write the separate validation-batch handoff for exact RC artifacts in
  dependency order: G-SERVICE (including the independent manager/drop-in
  preflight); controlled G-HEC/G-SPLUNK; native Windows; native macOS. Do not
  run any of those gates in this change; require independent statuses and a
  stop on missing or mismatched provenance.
- [x] 6.4 If a validation-relevant defect changes code, package metadata,
  installer behavior, workflow, archive, checksum, or attestation provenance,
  create a new reviewed main commit and issue `v0.5.0-rc.2` (or later); never
  mutate or reuse a published RC tag. A purely transient environment failure
  with unchanged immutable artifacts may receive a bounded recheck.

## 7. Prepare the stable promotion and publication handoff (do not execute)

- [x] 7.1 Write the stable gate matrix requiring explicit PASS evidence for
  G-SERVICE, G-HEC, G-SPLUNK, native Windows, native macOS, release preflight,
  public artifact boundary, and publication prerequisites; include the rule
  that a required BLOCKED gate is never silently reclassified as PASS.
- [x] 7.2 Write the new reviewed RC-to-stable promotion checklist: change only
  package/release versions from the accepted RC to `0.5.0`, regenerate the
  lockfile, run final stable preflight, and tag `v0.5.0` only from reviewed
  `main`; do not perform that transition or tag in this change.
- [x] 7.3 Document that crates.io publication remains separate from the GitHub
  Release and, only after stable approval, publishes schema, rules, sources,
  detect, core, and cli in documented dependency order with unpatched
  registry-consumer checks; do not publish crates in this change.
- [x] 7.4 Run narrowest verification, then `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test`.
