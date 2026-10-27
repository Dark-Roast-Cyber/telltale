# Telltale

<p align="center">
  <img src="telltail.png" alt="Telltale logo" width="240" />
</p>

<p align="center">
  <a href="https://agentarchaeology.ai/">
    <img src="https://img.shields.io/badge/AgentArchaeology.ai-Visit_Site-0066cc?style=flat-square" alt="AgentArchaeology.ai" />
  </a>
  <a href="https://darkroastcyber.io/">
    <img src="https://img.shields.io/badge/Dark_Roast_Cyber-Visit_Site-8b4513?style=flat-square" alt="Dark Roast Cyber" />
  </a>
  <img src="https://img.shields.io/badge/License-Apache_2.0-blue?style=flat-square" alt="License" />
  <img src="https://img.shields.io/badge/Supported_Agents-6-green?style=flat-square" alt="Supported Agents" />
  <img src="https://img.shields.io/badge/Detection_Categories-20-orange?style=flat-square" alt="Detection Categories" />
</p>

Telltale is an open-source detection layer for AI coding agents, built as the foundation for Agent Detection and Response (ADR). It detects telltale signs of risky behavior, preserves redacted evidence, and exports telemetry for review, alerting, and future response workflows.

## Start here

- **Try it:** [Quick start](#quick-start) or [install a release](docs/install.md).
- **Explore the code:** [CLI](src/cli/), [reusable crates](crates/), and [tests](tests/).
- **Browse detections:** [Bundled rules](config/rules/) and [synthetic samples](tests/fixtures/rule_samples/).
- **Embed it:** [Rust API](crates/telltale/src/lib.rs) and [embedding contract](docs/embedding.md).
- **Check compatibility:** [Source validation matrix](docs/source-validation-matrix.md) and [event schema](schemas/event.schema.json).
- **Find other guidance:** [Documentation map](docs/README.md).
- **Learn the practice:** [Agent Archaeology](https://agentarchaeology.ai/).

The command is `telltale` (`telltale.exe` on Windows). See [Install](docs/install.md)
for `TELLTALE_*` configuration and storage paths, and
[Telemetry output](docs/telemetry-output.md) for the Event 3.0 contract.

## Why Telltale exists

Coding agents act on prompts, repository files, web pages, tool results, and
harness configuration. When an action crosses a trust boundary or drifts from
user intent, the evidence is scattered across source-specific session stores.

Telltale normalizes those stores, applies deterministic detections, and emits
redacted JSONL for investigation and alerting. It is detection-first, not an
active blocking system.

## What it does

The optional [Telltale Console](docs/telltale-console.md) is a separate read-only
local Event3 viewer (`cargo run -p telltale-console`). It does not start the
scanner and is excluded from headless default builds and installs.

- Discovers supported agent session stores on disk.
- Acquires heterogeneous session-store formats into Canonical Observation v2.
- Detects suspicious tool activity with YAML-defined rules.
- Scores related behavior across a session window.
- Redacts sensitive evidence before writing events.
- Supports synthetic fixture-based testing across multiple client formats.

## Source support status

The [Source Validation Matrix](docs/source-validation-matrix.md) is canonical
for public source-support claims. The built-in denominator is eight exact source
identities across six agent families: Claude Code, Codex, OpenCode, OpenClaw,
Qwen, and GitHub Copilot. Current client-level status is:

- **Fixture-backed plus bounded live validation**: Codex, OpenCode, Claude Code,
  and GitHub Copilot.
- **Fixture-backed only**: OpenClaw and Qwen CLI.

These labels describe source-store validation, not broad live coverage.
Release archives and CI smoke checks cover binary packaging and execution on
Linux, macOS, and Windows; they do not establish broad live source-store
validation. Fixture-backed-only clients remain preview/experimental for live use.

Canonical Observation v2 acquisition and the Detection v2 runtime are now the
authoritative path for CLI scan/watch and every `Pipeline` scan method across the
eight supported source identities. Rule v1 remains the content-compatibility
format, and Event 3.0 remains the compatibility projection. Rust hosts embed
`telltale-core` and use detailed scans for per-action findings with typed
outcomes; see [embedding](docs/embedding.md) for the contract and surface
classification. Event4 and Telemetry/Output v2 remain inactive.

## Quick start

```sh
cargo run --bin telltale -- scan --once --dry-run --no-local-config --root tests/fixtures/session_stores
cargo run --bin telltale -- config provenance --no-local-config
cargo test
```

The fixture tree in `tests/fixtures/` is synthetic and safe for local verification.
Use `--dry-run` for fixture checks. Reserve `--allow-fixtures` for intentional
synthetic writes in CI or local development, not normal scans. See
[Install](docs/install.md) for the full fixture-safe verification sequence and
real-session-store setup. Explicit state and historical-event
migration guidance is in the [migration contract](docs/migration-contract.md).
See [GitHub Releases](https://github.com/Dark-Roast-Cyber/telltale/releases) for
published builds and the [0.7.0 migration guide](docs/migrations/0.7.0.md) for that
upgrade line. A source checkout is not evidence of release qualification.

## Development verification

Use the smallest gate that answers the current question:

```sh
make check-fast   # repeated local feedback: format, Clippy, library tests
make check        # broader Rust developer verification
make ci-local     # locked Linux pre-push CI gate
```

Routine workspace and embedding-fixture dev/test builds use limited debug
information (`debug = 1`), retaining source locations, backtraces and incremental
compilation. Reuse warm outputs rather than routinely cleaning them. For deeper
debugger inspection only, see [Debugging test failures](#debugging-test-failures).

`make ci-local` also runs the repository-owned contract, console/headless,
documentation-boundary, security/supply-chain, fixture-smoke, and package checks.
It is Linux-only and does not replace GitHub validation for Windows, macOS,
clean-room behavior, published/native release artifacts, or release candidates.
Use `make security-tools` once to install the pinned local security tools before
the security portion of the gate. Release work remains separate: use
`make release-preflight` and the release/native workflows when preparing an RC or
release.

### Debugging test failures

Start with the focused failing test, logs and backtrace using the normal profile.

<details>
<summary>Escalate only when diagnosis needs local variables or detailed types</summary>

Routine builds omit full type/local-variable debug information. If that blocks
diagnosis, opt in for the affected dev/test run:

```sh
CARGO_PROFILE_DEV_DEBUG=2 CARGO_PROFILE_TEST_DEBUG=2 cargo test --locked
```

Retain the failing command's package, feature and test selectors when narrowing
this command. The same overrides can prefix the relevant `make` gate; do not
export them globally or make full debug a routine harness/CI default. Release
profiles are unaffected.

For hard-to-reproduce crashes, build with full debug before reproducing and keep
the matching binary and symbols. Rebuilding afterward cannot recover debug data
missing from an earlier crash. Changing debug levels can retain another artifact
set; it does not remove older outputs. Keep validation logs outside disposable
build outputs, and retain separate embedding and embedding MSRV targets.

</details>

## Cargo packages

The [workspace manifest](Cargo.toml) lists the packages. The official packages are:

- [`telltale-schema`](crates/telltale-schema/) — shared types and privacy
- [`telltale-rules`](crates/telltale-rules/) — rule loading and validation
- [`telltale-sources`](crates/telltale-sources/) — source acquisition
- [`telltale-detect`](crates/telltale-detect/) — detection and scoring
- [`telltale-core`](crates/telltale/) — the supported embedding surface (`telltale_core` in Rust)
- [`telltale-cli`](crates/telltale-cli/) — command-line package

The separate [inference crate](crates/telltale-inference/README.md) is an
experimental normalizer, not a gateway or additional production source. Its
README defines the supported subsets.

Exact-artifact qualification evidence lives in [Release readiness](docs/release-readiness.md),
not in this overview. Qualification of a published artifact does not qualify
later source changes.

See [Versioning and releases](docs/versioning.md) for the package and `0.x`
compatibility policy. Until crates.io publication begins, install or build from
GitHub releases or source rather than assuming these package names are available
from the registry.

> **Crates.io name warning:** The package named `telltale` is an unrelated
> active session-types crate, not this project. Telltale uses `telltale-core`
> for its embedding facade. Recheck crates.io availability immediately before
> any future publication.

When you are ready to scan real session stores, point `telltale scan --root` at the
directory that contains your actual supported session-store roots, such as `$HOME`
on a typical single-user workstation, instead of `tests/fixtures/`.

For continuous local monitoring, `telltale watch` accepts the same repeated
`--client <id>` filters as `telltale scan`, so watched runs can stay scoped to one
or more supported client IDs such as `codex` or `opencode`.
Keep scanner state, canonical JSONL, and any durable outbox outside the actual
watched session-store directories (including project roots). `watch` rejects
runtime storage inside those directories before activation, so its own sidecars,
rotation, and delivery writes cannot trigger source scans. Other directories
under the broader `--root` remain valid output locations.
Watch mode bounds its notification queues and reconciles overflow; watcher errors
stop the run. See the [watch implementation](src/cli/scan/watch.rs) for current
limits. Those limits do not bound OS/backend buffers or total process memory.

### Local rule configuration

Telltale ships bundled core rules and an embedded community rule package
(`telltale.community`, rule IDs `tdx.*`) from the
[community detections repository](https://github.com/Dark-Roast-Cyber/telltale-detections);
both are on by default. Use `--no-community-rules` (or
`TELLTALE_COMMUNITY_RULES=0`) to run only the core rules.

Telltale discovers local YAML config files under `/etc/telltale` and
`$XDG_CONFIG_HOME/telltale` (or `$HOME/.config/telltale`) without requiring
every path on the command line. Managed rule packs resolve in fixed tier order
(bundled core → rule packages → `organization-rules.d` → `rules.d` →
`ui-rules.d`); a higher tier fully replaces a same-ID definition in place, while
unique IDs are additive. Rule packages in `rule-packages.d` are versioned,
namespaced, additive files: install a newer community release or your own
custom package there without a Telltale release. `overrides.d` tunes rules
without editing source YAML, and `policies.d`/`allowlists.d` provide policy and
suppression config.

Use `--config-dir <path>` for explicit config roots, or `--no-local-config` to
disable discovery. Run `telltale config validate` as the local config preflight
before scans with custom content, and `telltale rules export-default` to inspect
or fork the bundled default rules.

`telltale config provenance` prints a deterministic, privacy-safe manifest of the
effective compiled rules, suppression semantics, thresholds, and audited producer
switches. It is a content-integrity identity for configuration, not an Event 3.0
field, scan identity, telemetry record, attestation, or proof that an event used
that configuration. The command uses the same scan configuration and rule
resolvers. The public Rust assembler accepts an already effective compiled rule
set and resolved values; it does not resolve configuration paths or policy files.
Source YAML formatting, paths, policy labels, and descriptive rule metadata are
not part of the ruleset identity; hashes remain guessable for low-entropy inputs
and are not encryption.

See [Install](docs/install.md) for the full directory layout, rule-pack
precedence, trust-boundary guidance, override YAML format, and flag behavior.

### Project-local session stores

Copilot process logs are discovered inside project directories. By default,
Telltale scans `~/github` and `~/projects` if they exist. To customize, declare
project roots in a YAML file and pass it with `--project-config` (or set
`TELLTALE_PROJECT_CONFIG`). Project-local discovery is additive — home-relative
sources are still discovered from `--root`.

See [Install](docs/install.md) for the YAML format and `--project-config` usage.

- Install and setup guide: [docs/install.md](docs/install.md)
- Controlled development upgrade and rollback: [docs/controlled-deployment.md](docs/controlled-deployment.md)

Tagged GitHub releases provide platform-specific archives when available. See
the [Linux](docs/install.md#quick-install-linux),
[macOS](docs/install.md#macos), and
[Windows](docs/install.md#windows) installation and scheduling instructions.
On Linux, run `./scripts/install-telltale` from a checkout; `--with-timer` opts
into its user-level systemd timer.
The guide also covers checksum and attestation verification, source builds, and
platform caveats. Start with its fixture-safe verification before scanning real
session stores; binary packaging support does not establish broad source-store
validation.

Before pushing public history, run `make public-push-review` to review the
current branch, public remote URLs, working-tree status, and staged path list.
Before tagging a public release, run `make release-preflight` from a clean
working tree. The target runs formatting, linting, tests, fixture-safe scanning,
rule validation, and the branch/remote/staged-content checks covered by the
release readiness checklist.

## Telemetry Output

Telltale is designed to produce structured telemetry that can be searched,
charted, and alerted on in a SIEM. Write append-only JSONL locally, then
connect the output to your preferred shipper or log pipeline after reviewing
your environment's data-handling requirements. See
[Telemetry output](docs/telemetry-output.md) for the public event-output and
forwarding model.

Common use cases include:

- tracking agent activity volume across hosts, clients, and sessions;
- highlighting high and critical detections for analyst review;
- breaking down detection categories and evidence rule IDs for triage;
- emitting optional per-session risk summaries for dashboards that need one
  compact row per agent session;
- spotting spikes, outliers, and session drift over time;
- feeding dashboards, alerts, and investigations in Splunk or another SIEM.

## Early development and community

Telltale is still in early development. The project is usable, but source coverage, detections, and operational ergonomics are still evolving.

PRs, issues, feedback, and active engagement are very welcome. We would especially love testers who can help identify missing features, blind spots, or source-adapter gaps across different coding-agent platforms and handlers.

## Project layout

- [`src/`](src/) — CLI, scan/watch orchestration, state, and telemetry delivery
- [`crates/`](crates/) — reusable packages and experimental inference normalization
- [`apps/telltale-console/`](apps/telltale-console/) — optional read-only local Event3 viewer
- [`tests/`](tests/) — CLI coverage plus synthetic fixtures
- [`schemas/`](schemas/) — JSON schema for emitted events
- [`config/rules/`](config/rules/) — bundled detection rules
- [`config/allowlists.yaml`](config/allowlists.yaml) — suppression examples
- [`docs/`](docs/) — public technical documentation
- [`openspec/specs/`](openspec/specs/) — durable public behavioral requirements

For project direction and planning ownership, see [ROADMAP.md](ROADMAP.md). Detailed active implementation planning and scratch context are intentionally kept out of the public release boundary.

## Further guidance

Use the [documentation map](docs/README.md) for contracts and operational guides;
proposed behavior is labeled separately from shipped behavior. Before tagging or
publishing release artifacts, follow [Release readiness](docs/release-readiness.md).

## License

Telltale Core is licensed under Apache-2.0. See [LICENSE](LICENSE) and
[License and packaging](docs/license-and-packaging.md) for the open-source core
boundary and the boundary for future separately licensed features.
