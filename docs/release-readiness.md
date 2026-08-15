# Release Readiness

Use this checklist before preparing a tagged Telltale Core release or publishing
release artifacts from the public repository. The single local Telltale checkout is
the release source of truth; public release curation stages reviewed public-safe
material from this checkout to the public remote.

## Scope

A public release should include the open-source core, public technical
documentation, synthetic fixtures, schemas, bundled rules, and reviewed example
configuration. It should not include local scanner state, telemetry logs, raw
agent transcripts, credentials, private planning notes, local agent workflow
state, or deployment-specific SIEM settings.

Release archives should contain only the canonical `telltale` command-line
binary, the Apache-2.0 license, a concise quick-start README, and reviewed
deployment examples generated from checked-in public repository contents.

Public release evidence should be reproducible from synthetic fixtures or
already-redacted telemetry output. Keep live host validation notes local-only;
public summaries should cite deterministic fixture commands, supported client
families, schema checks, or aggregate results without exposing workstation
paths, raw transcript excerpts, SIEM endpoints, scanner state, or credentials.

Version selection and package/tag alignment follow
[Versioning and Releases](versioning.md). The workspace is currently preparing
the next `0.5.0-rc.4` candidate for the approved `0.5.0` Event 3.0 migration;
compatible maintenance fixes remain on the prior `0.3.x` line until stable
publication. Do not create `0.5.x` for a round of small tasks; follow-up fixes
belong there only after the reviewed `0.5.0` milestone ships.

The prior `v0.5.0-rc.1` tag is immutable history at reviewed commit
`8f261317022352ebc812c30814aa776964c84e6b`. Windows packaging failed; no
GitHub Release or complete five-target asset/checksum/attestation set was
created. Never reuse `rc.1`.

`v0.5.0-rc.2` is immutable history at reviewed commit
`973ce825550941a824aa568a07f80036cd89f497`; do not mutate its tag, Release,
assets, or evidence. `v0.5.0-rc.3` is immutable history at reviewed commit
`a791ebf8894b3329030fad9e252e22d21e8b7e07` and has no GitHub Release. `rc.4`
is the next prepared candidate.

## RC Candidate Handoff

The preparation batch does not create a tag, Release, archive, checksum, crate,
or live-gate evidence. A later reviewed operation may merge the candidate to
`main`, tag only that reviewed commit as `v0.5.0-rc.4`, and inspect the workflow
before validation. The RC Release must be explicitly marked `prerelease=true`.
If code, package metadata, installer behavior, workflow, archive, checksum, or
attestation provenance changes, use a new reviewed commit and the next unused
RC tag; do not overwrite a published candidate. A transient environment
failure with unchanged artifacts may receive only a bounded recheck.

For each of the five target archives, retain a redacted ledger row containing:
the package/tag pair, reviewed `main` SHA and ancestry result, canonical archive
name and member-manifest result, archive and extracted-binary SHA-256 values,
the exact `SHA256SUMS` line, archive attestation subject, Release ID/URL and
`draft`/`prerelease` metadata, workflow run/ref/source identity, and the exact
tagged installer blob and executable-mode result. Do not record credentials,
endpoints, local paths, raw service output, or session contents.

After artifact review, downstream validation is dependency-ordered: G-SERVICE
with the exact RC tag and canonical unit/drop-in preflight, then
controlled G-HEC and G-SPLUNK, native Windows, and native macOS. Each gate has
its own PASS/BLOCKED/FAIL status; a BLOCKED gate is never silently reclassified
as PASS. The current preparation claims no live gate passed. Stable promotion
requires explicit PASS evidence for those gates plus release preflight, public
artifact-boundary review, and publication prerequisites.

## Pre-Release Checks

Run these checks from a clean working tree in the local Telltale checkout before
tagging a release:

```sh
make release-preflight
```

The preflight target wraps the same public release checks shown below:

```sh
make release-context-check
make release-tag-review
make release-crate-manifest
make package-verify
make release-public-docs-check
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
make release-fixture-smoke
```

`make release-fixture-smoke` runs the fixture scan with
`--root tests/fixtures/session_stores`, `--dry-run`, `--emit-activity`, and
`--emit-session-risk-summary`, then validates the bundled rules. The fixture
scan must use `--dry-run` unless you are intentionally writing synthetic fixture
output in CI or local development.

### Synthetic watch soak

Before broadening watch reliability claims, run the ignored Linux soak
explicitly:

```sh
cargo test --test cli scan_watch::watch_synthetic_multi_cycle_soak -- --ignored --nocapture
```

The test uses temporary synthetic stores only. It exercises six triggered scan
cycles, unchanged-state persistence, bounded process file descriptors, built-in
JSONL rotation and retention, deduplicated malformed-source errors followed by
valid detections, and clean finite-cycle exit. It requires Linux procfs/inotify,
so it is evidence for that bounded runtime path rather than a macOS or Windows
live-watch claim.

When only public documentation or release guidance changed, run the focused
boundary check before the full release preflight:

```sh
make release-public-docs-check
```

The target runs the existing public Markdown link, tracked-target,
host-absolute-path, host-only-link, host-only-ignore-pattern, example-config,
release-workflow path, and retired repository workflow wording regressions
without scanning fixtures or building release artifacts.

It is intentionally limited to these focused commands:

```sh
cargo test --quiet public_docs_
```

`make release-context-check` verifies the working tree is clean, the current
branch is `main`, the `origin` fetch and push URLs point at the public
Telltale repository, and `HEAD` is not behind the public upstream. For an
intentional alternate public release branch or remote, override
`PUBLIC_RELEASE_BRANCH` or `PUBLIC_RELEASE_REMOTE` when running the target.
It also prints staged paths for review. `make release-tag-review` derives the
Cargo package version, expects the public tag to be `v<version>` unless
`PUBLIC_RELEASE_TAG` is overridden, and fails if that tag already exists
locally. If you are reviewing a release-preparation commit before it is created,
inspect `git diff --cached --name-only` and confirm each staged path belongs in
the public repository boundary described below.

Before any public push, stage only reviewed public-safe files from this
checkout, keep ignored host-only material local, and review
`git diff --cached --name-only`. `make public-push-review` prints the current
branch, public remote URLs, short working-tree status, staged path list, and the
release-readiness reminder in one reviewable summary.

`make release-crate-manifest` lists all six functional Cargo package inventories
with `cargo package --list` and fails if a package would include host-only
planning, local automation, telemetry, scanner state, or deployment-specific
Splunk material. It also requires the package-owned default rules data in
`telltale-rules`. Use it to review source package contents before publishing a
crate or tagged source release.

`make package-verify` performs full locked `cargo package` verification in
dependency order using temporary local crates.io patches for unpublished
workspace packages. It then compiles a registry-style external consumer and
installs the normalized `telltale-cli` package into a temporary root, checking
the canonical `telltale` install and `telltale --version`. The target supports
Linux and macOS and cleans
its temporary workspace on exit.

For the actual publication pass, first recheck crates.io ownership and name
availability. Publish in dependency order, waiting for each prerequisite to
appear in the index and verifying that it resolves without a local patch before
publishing the next dependent package. After all six packages are available,
repeat the external consumer and CLI installation checks with every local
`patch.crates-io` override removed. Those final checks must resolve only the
`=0.5.0` registry packages before publication is declared complete.

## Artifact Boundary

Before publishing release artifacts, verify that the staged or tagged content
does not contain:

- local scanner state or baseline files;
- telemetry output such as `logs/telltale-events.jsonl`;
- raw agent session stores or copied transcripts;
- credentials, API keys, tokens, or `.env` values;
- host-specific filesystem paths, IP addresses, or SIEM endpoints;
- private planning, local agent workflow state, or internal release notes.

Keep environment-specific service files and SIEM shipper configuration outside
the archive unless they are reviewed public examples with placeholder values.

For generated binary archives, inspect the archive listing before upload. The
archive should contain only the `telltale` binary, `LICENSE`, `README.md`, and
the curated `config/examples/` deployment files
(`telltale-outputs.yaml`,
`telltale-scan.service`, `telltale-scan.timer`, `telltale-scan-task.xml`,
`elastic-telltale-index-template.json`, `elastic-telltale-role.json`) only. It should not
contain checked-out working-tree residue, scanner state, telemetry output,
session stores, local planning notes, local agent workflow state, or
deployment-specific configuration.

Use the archive format's listing command, such as:

```sh
tar -tzf telltale-<target>.tar.gz
unzip -l telltale-<target>.zip
shasum -a 256 telltale-<target>.tar.gz telltale-<target>.zip
```

After downloading workflow artifacts into the default `release-downloads/`
directory, run the reusable manifest check:

```sh
make release-artifact-manifest
```

The target lists every `.tar.gz` and `.zip` archive and verifies that each
archive contains exactly the expected canonical bundle manifest: the `telltale`
binary (or its `.exe` form), `LICENSE`, `README.md`, and the curated
`config/examples/` deployment files. The target requires `SHA256SUMS` in the same directory,
then
verifies that its entries match the reviewed archives exactly and that each
checksum validates. The default `release-downloads/` directory is local review
residue and is ignored and excluded from source packages; legacy local
`artifacts/` review directories remain ignored and excluded as well. Use
`RELEASE_ARTIFACT_DIR=<path>` when reviewing artifacts from another directory.

The tagged release workflow generates `SHA256SUMS` in its temporary
`release-downloads` artifact directory from the downloaded `.tar.gz` and `.zip`
archives and uploads it with the GitHub release. Publish equivalent checksums
for any manually produced archives so operators can verify downloads before
running the binary.

The Windows release job uses `scripts/release-windows-zip.ps1` for both package
creation and finalized-archive validation. It reopens the serialized ZIP
read-only and reads every canonical member before the staged binary smoke test,
attestation, or upload.

The default installer selects the latest stable Release. For candidate
validation, pass the exact tag, for example:

```sh
RC_TAG='v0.5.0-rc.N' # replace N with the exact published candidate number
./scripts/install-telltale --release-tag "$RC_TAG" --no-timer
./scripts/install-telltale --release-tag "$RC_TAG" --from-source --no-timer
```

The candidate path verifies exact Release metadata, the canonical archive
manifest, the tag-derived `SHA256SUMS` entry, and the extracted binary version
before acquiring its installer lock. It never uses `--skip-checksum` for the
G-SERVICE procedure and never falls back to `releases/latest`.

## Post-Release Smoke Test

After downloading a release archive, run a fixture-safe smoke test before
scanning real session stores:

```sh
telltale scan --once --dry-run --no-local-config --root tests/fixtures/session_stores
telltale rules validate --no-local-config
```

Only point Telltale at real session-store roots after the fixture scan and rule
validation complete successfully.

## Related Boundaries

- [privacy-model.md](privacy-model.md) defines evidence classes, redaction, and
  public-example privacy expectations.
- [telemetry-output.md](telemetry-output.md) describes the JSONL sink, SIEM
  forwarding model, and public evidence boundary.
- [trust-boundaries.md](trust-boundaries.md) explains how untrusted session
  content handling carries into publication guidance.
