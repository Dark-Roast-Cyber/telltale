## Context

See `proposal.md` for the motivation and scope. The current workspace reports
`0.5.0`; the five library packages declare `version.workspace = true`, and the
root workspace carries five internal `version = "0.5.0"` requirements. The
release workflow requires an exact `v<package-version>` tag and rejects a tag
whose commit is not an ancestor of fetched `origin/main`. It already builds
the five canonical target archives, attests each archive, generates
`SHA256SUMS`, validates the canonical archive manifest, and checks the tagged
installer blob.

The current installer discovers `releases/latest`. GitHub's documented latest
release endpoint excludes prereleases, so that lookup cannot safely select a
published `v0.5.0-rc.1` while the current stable release remains `v0.3.0`.
The installer already verifies the tag-derived archive against the tag's
`SHA256SUMS`; the missing part is selecting and proving the intended RC tag.

The action documentation for `softprops/action-gh-release@v3` exposes an
explicit `prerelease` input. GitHub's Releases API documents `prerelease` as a
boolean whose default is `false`. The workflow therefore must not rely on a
hyphenated tag being inferred as a prerelease.

## Goals / Non-Goals

**Goals:**

- Use one true RC train: `0.5.0-rc.1`, then immutable `rc.2`, `rc.3`, and so on
  only when a new reviewed main commit is required.
- Make the candidate's package version, tag, reviewed `main` commit, release
  metadata, archives, checksums, attestations, and installer selection form one
  auditable provenance chain.
- Preserve the existing Telltale-only archive manifest, target matrix,
  Windows ZIP hardening, installer content-provenance check, checksum
  verification, and public-boundary checks.
- Make GitHub Release prerelease status explicit and prove that stable
  `v0.5.0` still creates a normal release.
- Provide downstream G-SERVICE with an exact-tag path that cannot silently use
  `releases/latest` or another candidate, while preserving the stable default
  installer behavior and refusing checksum bypass.
- Keep merge readiness, RC readiness, and stable-release readiness as separate
  decisions with separate evidence.

**Non-Goals:**

- No scanner runtime, Event 3.0, historical schema, configuration, state,
  detection, scoring, or SIEM behavior changes.
- No alternate branch-artifact infrastructure, unsigned/local candidate path,
  artifact-manifest fork, or weakened G-SERVICE acceptance rule.
- No RC crates.io publication. The GitHub binary release workflow remains
  independent of the later dependency-ordered crates.io publication.
- No live service, HEC/Splunk, native Windows/macOS, or installer validation in
  the planning/apply work that prepares the RC; synthetic installer fixtures
  are allowed, while live validation is explicitly ordered downstream after
  immutable artifacts exist.

## Decisions

### 1. Choose a true RC promotion, not branch artifacts or stable bypass

Strategy A is the only path that satisfies the existing release contract:

1. prepare and review the RC version/provenance changes;
2. run the full candidate preflight and CI;
3. review PR #9 as the candidate code and only then mark it ready;
4. merge the candidate to `main`;
5. tag that reviewed `main` commit `v0.5.0-rc.1`;
6. let the existing tag workflow produce the canonical immutable assets;
7. validate the assets through the remaining gates; and
8. promote to stable `0.5.0` only after every required stable gate passes.

Strategy B would duplicate the release workflow and would require changing
G-SERVICE's trusted-artifact contract. Strategy C would use stable semantics
to bypass unresolved gates. Strategy D fails the workflow's tag-ancestor check.
Steps after candidate preparation are operator handoffs for separately
authorized release and validation sessions; they are not execution tasks for
this OpenSpec apply batch.

### 2. Merge PR #9 before RC validation, but not before RC preparation

PR #9's green CI and clean mergeability are merge-readiness evidence, not
stable-release evidence. The current Draft PR must remain unmerged and Draft in
this session. After this preparation batch is reviewed, a separate operator
session may review the RC-preparation changes on the candidate PR (or a
tightly scoped prerequisite PR), confirm CI, mark it ready, and merge to
`main`. The merge is required because the release workflow rejects tags that
are not ancestors of `origin/main`; it does not authorize a stable release.

If a defect is found during RC validation, fix it in a new reviewed change,
merge that change to `main`, and issue the next immutable RC. Do not tag the
current release branch and do not mutate the published PR/tag history.

### 3. Move only package/release versions to the RC value

For the RC preparation, change the root `[workspace.package]` version and all
five root internal workspace dependency requirements from `0.5.0` to
`0.5.0-rc.1`, preserving the existing requirement form unless Cargo validation
requires the equivalent exact RC constraint. Regenerate `Cargo.lock` so all
six package entries and their internal requirements resolve to the same RC.
The member manifests continue to use `version.workspace = true`.

Update only release/package-sensitive tests, fixtures, package verification,
and candidate documentation that assert the package version or archive/tag
name. The CLI `--version` comes from Cargo metadata and must be checked rather
than separately versioned. Stable documentation and registry checks that
require `=0.5.0` remain stable-promotion requirements; they must not be
globally rewritten to the RC value.

Do not change `schema_version`, Event 3.0 versions, configuration versions,
state schema versions, rule-language versions, or historical schema fixtures.
The installer date/provenance identifier is also independent of the Cargo
package version; change it only if an actual installer edit requires its own
reviewed provenance update.

### 4. Make prerelease metadata explicit and conditional

Retain the existing `v*` trigger, exact package/tag equality check, fetched
`origin/main` ancestry check, preflight, matrix, attestations, archive
manifests, checksums, and installer blob check. Add the smallest workflow
adjustment to the GitHub Release step so its `prerelease` input is true for a
validated RC tag containing the SemVer prerelease component and false for
stable `v0.5.0`. A conditional expression such as
`${{ contains(github.ref_name, '-') }}` is acceptable only when covered by
tests for both `v0.5.0-rc.1` and `v0.5.0` and after the package/tag gate has
already rejected malformed tags.

This makes `v0.5.0-rc.1` a GitHub prerelease without changing the stable path.
Add an explicit pre-release guard before the release action: if a Release for
the tag already exists, fail rather than update it. Set the action's
`overwrite_files: false` as defense in depth. A same-tag workflow retry is
allowed only before a Release or any release asset exists; once an asset or
Release exists, the candidate is immutable and the next candidate requires a
new reviewed commit/tag. Do not use a non-prerelease GitHub Release to make
`releases/latest` select an RC; that would misrepresent candidate stability and
corrupt installer selection semantics.

### 5. Add explicit RC tag selection to release tooling, not scanner runtime

The current `releases/latest` lookup is retained as the default stable path,
but the installer/release tooling must gain a narrowly scoped explicit tag
selection path for approved candidate validation. The later implementation
should:

- accept an optional validated `--release-tag v0.5.0-rc.N` input;
- query the release identified by that exact tag before acquiring the installer
  lock or changing any file, schedule, unit, or manager state; assert the
  returned `tag_name` matches and require `draft=false` and `prerelease=true`
  for candidate use;
- derive the archive and `SHA256SUMS` URLs from that exact tag;
- retain the existing archive manifest checks, archive checksum comparison,
  binary version check, current-user restrictions, and `--skip-checksum`
  refusal in the G-SERVICE procedure; and
- make `--from-source` use the same exact selected tag rather than silently
  falling back to the latest release.

The default no-argument installer behavior remains `releases/latest`, so a
candidate option cannot change stable operator behavior accidentally. This is
release tooling needed to make the existing G-SERVICE contract executable, not
a scanner runtime or event-schema change. Add fixture-backed installer tests
for RC selection, tag mismatch, draft/non-RC rejection, checksum mismatch, and
stable default compatibility; do not use live releases or credentials in
tests.

### 6. Use a fixed, redacted provenance ledger per target

For each matrix target, retain only public metadata and hashes, plus one
release-level metadata record:

| Field | Required value/evidence |
| --- | --- |
| Package/tag | `0.5.0-rc.N` and `v0.5.0-rc.N`, exactly matching |
| Source | Reviewed `main` commit SHA; tag resolves to this commit and is an ancestor of `origin/main` |
| Archive | Exact canonical `telltale-v0.5.0-rc.N-<target>.<tar.gz\|zip>` name |
| Checksum | Matching `SHA256SUMS` line and independently recomputed archive SHA-256 |
| Binary | Extracted canonical `telltale`/`telltale.exe` SHA-256 and `--version` result |
| Manifest | `release-artifact-manifest` pass and exact archive member set |
| Attestation | GitHub Actions attestation for the exact archive subject, verified with supported GitHub tooling |
| Release metadata | Release ID/URL, exact `tag_name`, `draft=false`, `prerelease=true`, and target source SHA |
| Workflow | Run ID/URL, job result, repository, ref/tag, and source SHA |
| Installer | Exact tagged `scripts/install-telltale` blob hash and executable mode match the workflow check; no checksum bypass |

For G-SERVICE, fix this ledger before any manager mutation, pass the exact RC
tag to the installer, compare the installer-selected archive and extracted
binary to the fixed hashes, and record only redacted version/hash/status
classes. A missing tag, mismatched release metadata (including
`draft`/`prerelease`), missing checksum, tag drift, installer drift, or
selected-artifact mismatch remains `BLOCKED/B`. The previously observed
unexpected `adr-scan.service` manager drop-in is an independent fail-closed
precondition; obtaining the RC artifact does not authorize deleting, masking,
or bypassing it.

### 7. Order the downstream gates by provenance dependency

After an RC workflow completes, a separately authorized validation session must:

1. verify the tag, reviewed `main` ancestry, package version, workflow run,
   five target assets, canonical manifests, attestations, and `SHA256SUMS`;
2. run G-SERVICE against the exact Linux RC artifact and exact tagged
   installer, without `--skip-checksum`;
3. perform controlled G-HEC and G-SPLUNK checks using only approved synthetic
   events and the RC binary, keeping endpoints and credentials out of evidence;
4. perform native Windows host validation using the exact Windows RC archive;
5. perform native macOS host validation using the exact macOS RC archive;
6. classify defects and either perform deterministic rechecks or create a new
   bounded reviewed change and RC;
7. rerun all affected RC checks after any change;
8. run final stable release preflight and public-boundary review on reviewed
   `main`;
9. change all package/release versions from the RC value to `0.5.0` in a new
   reviewed promotion; and
10. create stable `v0.5.0`, inspect its final workflow assets/checksums, then
    perform the separately authorized crates.io publication sequence.

`G-HOST-SOURCE=PASS` may be carried forward only as the recorded existing
source result if its evidence remains applicable; all other required gates
must be explicitly remeasured. No `BLOCKED` required gate may be silently
reclassified as `PASS`.

### 8. Keep RCs immutable and promote only from a complete gate matrix

`rc.2` or later is required when code, package metadata, installer behavior,
release workflow, archive contents, checksum/attestation provenance, or a
validation-relevant defect changes. Each RC gets a new reviewed `main` commit,
new tag, new workflow run, and new ledger entries; never move or overwrite a
published tag or release asset. The workflow's existing-release guard and
`overwrite_files: false` setting enforce this at the Release boundary. A
transient local/test-environment failure that leaves the immutable RC artifacts
and code unchanged may be retried as a recheck, but an artifact or provenance
defect requires a new RC.

Stable promotion is allowed only when G-SERVICE, G-HEC, G-SPLUNK, native
Windows live-host validation, native macOS live-host validation, release
preflight, artifact/public-boundary review, and publication prerequisites are
explicitly resolved under the current policy. A blocked required gate is not
an acceptable stable-release disposition.

## Risks / Trade-offs

- **[Risk]** An RC accidentally remains a normal GitHub Release and becomes
  eligible for `releases/latest`. → Set and test explicit conditional
  `prerelease` metadata; inspect the created Release API object before any
  installer validation.
- **[Risk]** The installer silently selects the stable release or a different
  RC. → Require explicit tag selection for candidate validation, exact API
  `tag_name` equality, exact tag-derived URLs, fixed digest comparison, and
  tagged-installer blob equality.
- **[Risk]** Cargo accepts a mixed stable/RC workspace or lockfile. → Update
  the root version and all five internal requirements together, regenerate the
  lockfile, and run metadata/package/consumer checks before tagging.
- **[Risk]** CI success is mistaken for native host proof. → Keep CI, live
  Linux service, HEC/Splunk, and native Windows/macOS evidence as separate
  ledger rows with separate gate statuses.
- **[Risk]** A stable promotion accidentally carries RC-only requirements or
  contract versions. → Use an explicit reverse transition checklist and assert
  package/release versions independently from Event, config, and state schema
  versions.
- **[Risk]** Candidate evidence exposes private operational data. → Record only
  tags, public run identifiers, statuses, filenames, and cryptographic hashes;
  never include credentials, endpoints, raw service output, paths, or session
  contents.

## Migration Plan

1. In a fresh apply session, implement only the RC version/workflow/installer
   release-tooling changes, focused tests, and operator handoffs; do not change
   PR state, create a tag or Release, publish artifacts, or run live gates.
2. Run package metadata, lockfile, package-boundary, installer-fixture, public
   boundary, workflow-shape, and no-side-effect checks, followed by the
   required Rust checks.
3. Stop with the candidate handoff complete. A separate reviewed GitHub
   operation may then ready/merge the candidate, tag `v0.5.0-rc.1`, wait for
   the workflow, and populate the redacted provenance ledger.
4. Separate bounded validation sessions may execute the ordered live gates. If
   a change is needed, stop, create a reviewed change, merge it, and issue the
   next immutable RC.
5. After all stable gates pass, a separate reviewed promotion may change the
   package version to `0.5.0`, run stable preflight, create the stable tag/
   Release, and then perform the separately authorized crates.io sequence.

Rollback is non-destructive: do not delete or retag a published RC. If the
candidate is rejected, leave its prerelease and evidence as historical, keep
stable `v0.5.0` untagged, and use a new reviewed commit/RC for corrections.
