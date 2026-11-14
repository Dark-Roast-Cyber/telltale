# ADR 0007: Hooks live inside Telltale

Status: Accepted. Supersedes the pinned-revision and build-ID parts of
[ADR 0001](0001-rust-and-telltale-embedding.md) and
[ADR 0003](0003-process-model.md).

## Context

Hooks began as a separate repository that depended on `telltale-core` by Git
revision. Every Telltale change that mattered to enforcement needed a pin bump
in a second repository, which blocked unpublished fixes, duplicated CI, and
split one security product across two release trains.

## Decision

- The library is the module `telltale_core::hooks` behind the `hooks` Cargo
  feature of `telltale-core`, on by default. It keeps the same submodules
  (`claude_code`, `codex_cli`, `copilot_cli`, `harness`, `runtime`, `engine`,
  `journal`, `state`, `evaluator`, ...) and still reaches detection only through
  the public facade.
- The CLI exposes it as `telltale hooks ...` behind a default `hooks` feature of
  `telltale-cli`; building without default features drops both.
- Embedders get the feature by default and opt out with
  `default-features = false`. The embedding MSRV rises to Rust 1.89 with it.
- Configuration and state keep the `telltale-hooks` names and the
  `TELLTALE_HOOKS_*` variables so existing installations keep working.
- Generated settings invoke `telltale hooks <harness> hook`, and the evaluator
  autostarts by running the current executable as `hooks serve`.
- A hook invocation is dispatched before the scanner's startup work, so tool
  calls do not wait for it.

## Build identity

A package build script may not read files outside its own package, so the
former source-hash build ID cannot exist. Compatibility instead follows the
executable: the evaluator fingerprint covers the package version, the Git hash
the CLI registers at startup, the configuration and rule bytes, and the file
identity (device, inode, size, modification time) of the running executable,
which changes whenever the binary is rebuilt or replaced. The telemetry field
`producer.telltale_rev` remains 40 lowercase hex digits (schema unchanged) and
is now a digest of the package version and that Git hash. It names the Telltale
release and commit that wrote a record and is stable across reinstalls; it is
not a Git object name.

## Rejected

- A separate crate depending on `telltale-core`: it would be a dependency cycle
  with the facade the hooks use.
- An opt-in application: hooks would stay an unreviewed second product.
- Hashing workspace sources in a build script: reads outside the package.

## Consequences

- One lockfile, one CI, one signed history. Hooks code is covered by the
  workspace gates and the external embedding checks, with the feature on and off.
- Telltale's enforcement-affecting changes (shell reading, rules) are tested
  against the hooks suites in the same change.
- Embedders compile a few more dependencies by default (a TOML parser, `regex`,
  `serde_json`) unless they opt out.
