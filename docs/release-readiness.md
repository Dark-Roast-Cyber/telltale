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

Release archives should contain the primary `telltale` command-line binary and
the compiled `adr` compatibility command, the Apache-2.0 license, a concise
quick-start README, and reviewed deployment examples generated from checked-in
public repository contents.

Public release evidence should be reproducible from synthetic fixtures or
already-redacted telemetry output. Keep live host validation notes local-only;
public summaries should cite deterministic fixture commands, supported client
families, schema checks, or aggregate results without exposing workstation
paths, raw transcript excerpts, SIEM endpoints, scanner state, or credentials.

Version selection and package/tag alignment follow
[Versioning and Releases](versioning.md). The workspace is currently preparing
the approved `0.5.0` Event 3.0 migration; compatible maintenance fixes remain
on the prior `0.3.x` line until that release is published. Do not create
`0.5.x` for a round of small tasks; follow-up fixes belong there only after the
reviewed `0.5.0` milestone ships.

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
both `telltale --version` and `adr --version`. The target supports Linux and
macOS and cleans its temporary workspace on exit.

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
- telemetry output such as `logs/adr-events.jsonl`;
- raw agent session stores or copied transcripts;
- credentials, API keys, tokens, or `.env` values;
- host-specific filesystem paths, IP addresses, or SIEM endpoints;
- private planning, local agent workflow state, or internal release notes.

Keep environment-specific service files and SIEM shipper configuration outside
the archive unless they are reviewed public examples with placeholder values.

For generated binary archives, inspect the archive listing before upload. The
archive should contain both `telltale` and `adr` binaries, `LICENSE`,
`README.md`, and the curated `config/examples/` deployment files
(`telltale-outputs.yaml`,
`adr-scan.service`, `adr-scan.timer`, `adr-scan-task.xml`,
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
archive contains exactly the expected bundle manifest: both the `telltale` and
`adr` binaries (or their `.exe` forms), `LICENSE`, `README.md`, and the curated
`config/examples/` deployment files. It also verifies that every `adr-*` archive
is an exact copy of its matching `telltale-*` archive. When `SHA256SUMS` is
present in the same directory, the target also
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
