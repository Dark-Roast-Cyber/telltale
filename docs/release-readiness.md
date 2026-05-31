# Release Readiness

Use this checklist before preparing a tagged Telltale Core release or publishing
release artifacts from the public repository. The single local ADR checkout is
the release source of truth; public release curation stages reviewed public-safe
material from this checkout to the public remote.

## Scope

A public release should include the open-source core, public technical
documentation, synthetic fixtures, schemas, bundled rules, and reviewed example
configuration. It should not include local scanner state, telemetry logs, raw
agent transcripts, credentials, private planning notes, local agent workflow
state, or deployment-specific SIEM settings.

Release archives should contain the compiled `adr` command-line binary and
release metadata generated from checked-in public repository contents.

Public release evidence should be reproducible from synthetic fixtures or
already-redacted telemetry output. Keep live host validation notes local-only;
public summaries should cite deterministic fixture commands, supported client
families, schema checks, or aggregate results without exposing workstation
paths, raw transcript excerpts, SIEM endpoints, scanner state, or credentials.

## Pre-Release Checks

Run these checks from a clean working tree in the local ADR checkout before
tagging a release:

```sh
make release-preflight
```

The preflight target wraps the same public release checks shown below:

```sh
git status --short
make release-context
make release-public-alignment
git diff --cached --name-only
make release-crate-manifest
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
cargo test --quiet readme_local_markdown_links_resolve
cargo test --quiet public_docs_local_markdown_links_resolve
cargo test --quiet public_docs_local_markdown_links_target_tracked_content
cargo test --quiet public_surfaces_do_not_reintroduce_split_checkout_guidance
cargo test --quiet public_release_workflows_do_not_reference_host_only_paths
cargo test --quiet public_docs_do_not_contain_host_absolute_home_paths
cargo test --quiet public_docs_do_not_link_to_host_only_paths
cargo test --quiet host_only_release_paths_remain_ignored
cargo test --quiet public_docs_linked_example_configs_are_public_safe
```

`git status --short` should be empty before tagging. By default,
`make release-context` fails unless the current branch is `public-main` and
the `origin` fetch and push URLs point at the public Telltale repository. For
an intentional alternate public release branch or remote, override
`PUBLIC_RELEASE_BRANCH` or `PUBLIC_RELEASE_REMOTE` when running the target.
`make release-public-alignment` then compares `HEAD` with
`origin/${PUBLIC_RELEASE_BRANCH}` by default, fails if the local branch is
behind the public upstream, and reports any local commits that still need
pre-push review. If you are reviewing a release-preparation commit before it is
created, inspect `git diff --cached --name-only` and confirm each staged path
belongs in the public repository boundary described below.

Before any public push, stage only reviewed public-safe files from this
checkout, keep ignored host-only material local, and review
`git diff --cached --name-only`.

`make release-crate-manifest` lists the Cargo source package contents with
`cargo package --list` and fails if the package would include host-only planning,
local automation, telemetry, scanner state, or deployment-specific Splunk
material. Use it to review source package contents before publishing a crate or
tagged source release.

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
archive should contain the `adr` binary, release metadata, and public license or
readme material only. It should not contain checked-out working-tree residue,
scanner state, telemetry output, session stores, local planning notes, or
local agent workflow state, or deployment-specific configuration.

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
current binary archive contains only the expected `adr` or `adr.exe` binary
entry. When `SHA256SUMS` is present in the same directory, the target also
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
adr scan --once --dry-run --root tests/fixtures/session_stores
adr rules validate --rules config/rules/tool-call-regex.yaml
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
