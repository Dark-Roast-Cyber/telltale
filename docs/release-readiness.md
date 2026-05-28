# Release Readiness

Use this checklist before preparing a tagged Telltale Core release or publishing
release artifacts from the public repository.

## Scope

A public release should include the open-source core, public technical
documentation, synthetic fixtures, schemas, bundled rules, and reviewed example
configuration. It should not include local scanner state, telemetry logs, raw
agent transcripts, credentials, private planning notes, or deployment-specific
SIEM settings.

Release archives should contain the compiled `adr` command-line binary and
release metadata generated from checked-in public repository contents.

## Pre-Release Checks

Run these checks from a clean working tree before tagging a release:

```sh
git status --short
git branch --show-current
git remote -v
git diff --cached --name-only
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo run -- scan --once --dry-run --root tests/fixtures/session_stores
cargo run -- rules validate --rules config/rules/tool-call-regex.yaml
```

The fixture scan must use `--dry-run` unless you are intentionally writing
synthetic fixture output in CI or local development.

`git status --short` should be empty before tagging. Confirm that the current
branch is the intended public release branch and that the configured remote
points at the public Telltale repository before any tag or push. If you are
reviewing a release-preparation commit before it is created, inspect
`git diff --cached --name-only` and confirm each staged path belongs in the
public repository boundary described below.

## Artifact Boundary

Before publishing release artifacts, verify that the staged or tagged content
does not contain:

- local scanner state or baseline files;
- telemetry output such as `logs/adr-events.jsonl`;
- raw agent session stores or copied transcripts;
- credentials, API keys, tokens, or `.env` values;
- host-specific filesystem paths, IP addresses, or SIEM endpoints;
- private planning, workflow, or internal release notes.

Keep environment-specific service files and SIEM shipper configuration outside
the archive unless they are reviewed public examples with placeholder values.

For generated binary archives, inspect the archive listing before upload. The
archive should contain the `adr` binary, release metadata, and public license or
readme material only. It should not contain checked-out working-tree residue,
scanner state, telemetry output, session stores, local planning notes, or
deployment-specific configuration.

Use the archive format's listing command, such as:

```sh
tar -tzf telltale-<target>.tar.gz
unzip -l telltale-<target>.zip
shasum -a 256 telltale-<target>.tar.gz telltale-<target>.zip
```

Publish checksums with the release so operators can verify downloaded artifacts
before running the binary.

## Post-Release Smoke Test

After downloading a release archive, run a fixture-safe smoke test before
scanning real session stores:

```sh
adr scan --once --dry-run --root tests/fixtures/session_stores
adr rules validate --rules config/rules/tool-call-regex.yaml
```

Only point Telltale at real session-store roots after the fixture scan and rule
validation complete successfully.
