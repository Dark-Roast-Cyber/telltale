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
[Versioning and Releases](versioning.md). Official `v0.5.0` is published and
immutable. The immutable `v0.6.0-rc.2` prerelease is published as Release ID
`385903701` from source SHA
`158b18ce78c6f503c38619e816790035f88b09db`. Publication/provenance and
G-SERVICE passed; five-platform native verification passed in run `34444628698`
using verifier tooling SHA `8b65c1f517a9910b0dc197633d6bebd41859ee46`.
Official stable remains `v0.5.0`, and Issues #23 and #37 remain open. The
prospective `v0.6.0-rc.3` implements the selected static MSVC CRT release policy
but is not published or clean-Windows qualified. The published immutable
`v0.6.0-rc.1` candidate passed publication/provenance and failed G-SERVICE
because the current-user generated `EnvironmentFile` declaration was ignored as
a non-absolute quoted path. It is historical failed-candidate evidence, not an
official stable release or a qualification input to retry. The real systemd
parser consumes this directive's complete value without shell-unquoting it; the
repaired canonical shape is `EnvironmentFile=-/absolute/path`, including when
the path contains spaces. Distinguish every untagged candidate with full Git SHA
and archive/binary SHA-256. Use the post-publication-safe metadata gates for an
already published candidate; do not run a pre-tag check that requires the rc.2
tag to be absent. The [version gate contract](versioning.md#authoritative-version-gate)
owns package, RC/stable tag and published-version separation. Do not reuse
`v0.5.0` artifacts.

A separate rc.1 synthetic qualification invocation used the environment file as
an override channel and started with the ordinary user scan root instead of the
intended synthetic-only root. That is a qualification-tooling defect and did not
establish additional candidate behavior. No raw event content is retained as
release evidence, and state/log consistency was preserved.

The authoritative rc.2 G-SERVICE result is **PASS** on Fedora 44 x86_64 under
`systemd --user`. The one-shot and timer-triggered executions retained
`PrivateTmp=yes`, used `--no-local-config`, proved `remote_sink_count=0`, did not
scan the normal user root, did not enable remote delivery, and passed Event3
validation against schema SHA-256
`9014a15c010bc613b4deb7e0195ec56f702e9e950fb13a12c6937a733e38d754`.
Aggregate synthetic Event3 evidence was activity 2 / detection 1 / health 1 for
the one-shot execution and activity 1 / detection 1 / health 1 newly appended by
the timer, for totals of activity 3 / detection 2 / health 2. The expected
detection occurred in both executions, and every emitted event reported
`telltale_version=0.6.0-rc.2`. No raw event payload is repository evidence.

The prior `v0.5.0-rc.1` tag is immutable history at reviewed commit
`8f261317022352ebc812c30814aa776964c84e6b`. Windows packaging failed; no
GitHub Release or complete five-target asset/checksum/attestation set was
created. Never reuse `rc.1`.

`v0.5.0-rc.2` is immutable history at reviewed commit
`973ce825550941a824aa568a07f80036cd89f497`; do not mutate its tag, Release,
assets, or evidence. `v0.5.0-rc.3` is immutable history at reviewed commit
`a791ebf8894b3329030fad9e252e22d21e8b7e07` and has no GitHub Release. `rc.4`
is historical; the immutable `rc.5` publication/provenance passed, but G-SERVICE
failed on the canonical optional `EnvironmentFile` defect. The immutable `rc.6`
publication/provenance passed and repaired that defect, but G-SERVICE then failed
before binary replacement on user-manager `WorkingDirectory` normalization.
`rc.7` is published and immutable at reviewed commit
`6696888cd5d559fa47b8252e3495524da9fbd1eb`; its GitHub Release and assets are
the accepted candidate artifacts. The resulting `v0.5.0` tag and stable GitHub
Release are now published and immutable. Subsequent development version alignment
does not replace those artifacts or the separately pinned controlled-development lab.

## Historical RC Candidate Handoff

The `v0.5.0-rc.7` handoff completed before stable publication: the reviewed commit was tagged and its
immutable GitHub Release is explicitly marked `prerelease=true`. Native
validation used those published artifacts. Final stable preflight ran against
the reviewed `0.5.0` commit before the now-published `v0.5.0` tag existed.
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

For the published rc.2 candidate, G-SERVICE with the exact `v0.6.0-rc.2` tag and
canonical unit/drop-in preflight passed, and five-platform native verification
passed in run `34444628698`. That evidence remains immutable and is not rebound
to the unpublished rc.3 preparation. Each future native gate may be satisfied by
an authorized native host or appropriate GitHub-hosted native runners. The gate
must download and execute the final published Release artifact for that
architecture; cross-compilation, archive inspection, Linux source-unit tests,
and staged or rebuilt binaries are not native-release evidence. Run the
manually dispatched `.github/workflows/release-native-verify.yml` workflow for
the GitHub-hosted path. Live G-HEC and G-SPLUNK are environment-dependent:
`SKIPPED: EXTERNAL HEC ENVIRONMENT NOT AVAILABLE` does not block stable
promotion, while deterministic HEC/JSONL-parity and Splunk-format gates remain
mandatory. Each gate has its own PASS/BLOCKED/FAIL status; a BLOCKED gate is
never silently reclassified as PASS. Preparing the reversible `0.5.0` version
commit is a prerequisite for final stable preflight and is not itself tagging
or publication. Stable GitHub tagging and GitHub binary Release require
explicit PASS evidence for the required gates plus release preflight against
that `0.5.0` commit, public artifact-boundary review, and GitHub publication
prerequisites. Crates.io publication is a separate later distribution action
and does not block stable GitHub `v0.5.0`.

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
make producer-provenance-check
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
the canonical `telltale` install, `telltale --version`, and packaged provenance
materialization. The target supports Linux and macOS and cleans
its temporary workspace on exit.

`make producer-provenance-check` is the authoritative focused gate for the
closed manifest. It validates the schema/rules/allowlist/core/CLI tests, runs
the command twice from an isolated directory, checks byte determinism and the
closed top-level fields, and verifies that the command creates no application
files. Keep it separate from `event3-contract-check`; the latter remains the
authoritative frozen Event 3.0 gate.

Cargo package readiness from those targets remains a mandatory GitHub
stable-release gate. It is not crates.io publication authorization and does
not weaken version lockstep, internal pins, lock entries, package-boundary
checks, or registry-style consumer and CLI installation verification.

For the actual publication pass, first recheck crates.io ownership and name
availability. Publish in dependency order, waiting for each prerequisite to
appear in the index and verifying that it resolves without a local patch before
publishing the next dependent package. After all six packages are available,
repeat the external consumer and CLI installation checks with every local
`patch.crates-io` override removed. Those final checks must resolve only the
`=0.6.0-rc.3` registry packages while that remains the workspace version, before
publication is declared complete. That
crates.io pass is a separate later distribution action, not a prerequisite for
creating the stable Git tag or GitHub binary Release. Deferring it does not
block a stable GitHub Release. When crates.io publication is later attempted,
those registry-specific safety requirements remain mandatory.

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

The tagged release contains exactly five target archives plus the fixed
`telltale-sbom.cdx.json` SBOM. The target lists every `.tar.gz` and `.zip`
archive and verifies that each archive contains exactly the expected canonical
bundle manifest: the `telltale` binary (or its `.exe` form), `LICENSE`,
`README.md`, and the curated `config/examples/` deployment files. For the
complete release set, run `REQUIRE_SBOM=1 make release-artifact-manifest`; it
requires `SHA256SUMS` in the same directory, verifies exactly six entries (the
five archives and SBOM), and validates every checksum. The default
`release-downloads/` directory is local review residue and is ignored and
excluded from source packages; legacy local `artifacts/` review directories
remain ignored and excluded as well. Use `RELEASE_ARTIFACT_DIR=<path>` when
reviewing artifacts from another directory.

The tagged release workflow verifies the downloaded SBOM against the tagged
locked release graph before generating `SHA256SUMS`; it then generates the
manifest from the five `.tar.gz`/`.zip` archives and SBOM in its temporary
`release-downloads` directory and uploads the checksum file with the GitHub
release. See the detailed procedure in
`docs/security/operations.md#release-integrity-verification` for the complete
SBOM, checksum, and attestation verification procedure.

The Windows release job uses `scripts/release-windows-zip.ps1` for both package
creation and finalized-archive validation. It reopens the serialized ZIP
read-only and reads every canonical member before the staged binary smoke test,
attestation, or upload.

The official `x86_64-pc-windows-msvc` release build sets
`-C target-feature=+crt-static`. Before packaging, the release job runs
`scripts/verify-windows-runtime.ps1` with `dumpbin /DEPENDENTS` against the exact
staged `telltale.exe` that the ZIP helper consumes. The verifier fails closed if
inspection fails or if imports include `VCRUNTIME*.dll`, `MSVCP*.dll`,
`MSVCR*.dll`, or `CONCRT*.dll`. Linux and macOS release builds do not receive
this Windows target feature. This implementation is prepared for rc.3; a
published rc.3 artifact and clean-Windows acceptance remain pending.

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

For a synthetic G-SERVICE run, install the candidate with `--no-timer`, then add
the temporary qualification drop-in before the first candidate service start.
Keep the base unit's `PrivateTmp=true`; host `/tmp` is a different namespace and
must not hold the qualification inputs. Instead create a service-visible
directory under the current user's runtime directory, conceptually
`${XDG_RUNTIME_DIR}/telltale-qualification`, and render its concrete absolute
path into the drop-in. Do not expect shell-variable expansion inside unit
`Environment=` values. Keep the session store, JSONL log, and scanner state
synthetic and confined to that directory.

Do not use `telltale.env` as the synthetic override channel. Reset the base
environment-file list and `ExecStart`, set the three qualification paths as
unit-level values, and reproduce the canonical installed command with
`--no-local-config` added for qualification. In this generalized example,
replace `<qualification-root>` and `<installed-candidate>` with reviewed concrete
absolute paths:

```ini
[Service]
EnvironmentFile=
Environment="TELLTALE_SCAN_ROOT=<qualification-root>/sessions"
Environment="TELLTALE_LOG_PATH=<qualification-root>/events.jsonl"
Environment="TELLTALE_STATE_PATH=<qualification-root>/state.json"
ExecStart=
ExecStart=/usr/bin/env -- "<installed-candidate>" scan --once --emit-activity --root "${TELLTALE_SCAN_ROOT}" --path-profile user --no-local-config
PrivateTmp=true
```

Run `systemctl --user daemon-reload`, then verify both the empty
`EnvironmentFiles` property and the three effective `Environment` values with
`systemctl --user show telltale-scan.service --property=EnvironmentFiles --property=Environment`
before starting the service. Also verify the effective command includes
`--no-local-config`, the service property reports `PrivateTmp=yes`, and effective
configuration reports `remote_sink_count = 0` before the first candidate scan
execution. Only then run the one-shot and timer-triggered synthetic checks. The
installer intentionally rejects unit-specific drop-ins, so create this
qualification-only override only after installation. After the test, remove the
temporary qualification drop-in and synthetic runtime directory, reload the
manager, and confirm the canonical unit has no remaining drop-ins before any
installer rerun. This procedure changes no production defaults.

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
