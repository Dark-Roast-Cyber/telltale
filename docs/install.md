# Install

> **Website:** For an approachable install guide, see [AgentArchaeology.ai/telltale/install](https://agentarchaeology.ai/telltale/install/).

Telltale Core can be installed from a tagged GitHub release archive when one
is available, or built from source with Cargo. In both cases, start with a
fixture-safe scan before pointing the scanner at real agent session stores.

## Prerequisites

- Rust toolchain with `cargo` when building from source
- Local access to the agent session stores you want to scan
- Optional: a SIEM or log shipper for the generated JSONL event stream

## Install From A Release Archive

Tagged GitHub releases publish platform-specific `adr` binary archives for
Linux, macOS, and Windows. Download the archive that matches your platform,
extract the `adr` binary, and place it on your `PATH` or run it from the
extracted directory.

Release archives contain the command-line binary and release metadata generated
from the public repository. They do not include local scanner state, telemetry
logs, session stores, credentials, or deployment-specific SIEM configuration.

### Quick install (Linux)

A user-first installer is available for Linux. It downloads the latest release
binary, verifies it against the release's published `SHA256SUMS`, and installs
it to `~/.local/bin/adr` (no sudo). It does not enable anything beyond the
binary install unless you opt in:

```sh
curl -fsSL https://agentarchaeology.ai/telltale_install.sh | bash
```

To build from source instead of downloading a prebuilt binary, or to also
install a user-level systemd timer for periodic scans, pass flags:

```sh
curl -fsSL https://agentarchaeology.ai/telltale_install.sh | bash -s -- --from-source --with-timer
```

The installer does not create system users, configure SIEM shippers, or require
root. For managed Linux deployments with the `system` path profile, use the
examples in `config/examples/` and the manual systemd setup below.

Built-in size-based log rotation is enabled by default (100 MB max, keep 5
rotated files). No OS-specific rotation tooling is required for user-profile
installs. See [telemetry-output.md](telemetry-output.md#built-in-rotation) for
configuration details.

## Build From Source

```sh
git clone https://github.com/Dark-Roast-Cyber/telltale.git
cd telltale
cargo build --release
```

The release binary will be available at `target/release/adr`.

## Verify The Install Safely

Run a fixture-safe dry run before scanning real local session stores:

```sh
cargo run -- scan --once --dry-run --no-local-config --root tests/fixtures/session_stores
cargo run -- config validate --no-local-config
cargo run -- rules validate --no-local-config
cargo run -- rules export-default > /tmp/telltale-default-rules.yaml
cargo test
```

The fixture tree under `tests/fixtures/` is synthetic and safe for local
verification.

Use `--dry-run` for this verification step. Do not use `--allow-fixtures`
unless you intentionally want to write synthetic fixture output in CI or local
development.

## Scan Real Session Stores

Once the fixture scan looks healthy, run against your local session stores.
Use the directory that contains the supported session-store roots you want to
scan; for a typical single-user workstation, that is usually your home
directory. Keep `tests/fixtures/` for dry-run verification only:

```sh
cargo run -- scan --once --emit-activity --root "$HOME"
```

For a first real-store check, keep the scan read-only and bounded before
opening it up to every discovered source. `--client` scopes discovery to one or
more supported clients, and `--max-sources` deterministically caps the number of
sources scanned after that filtering:

```sh
cargo run -- scan --once --dry-run --root "$HOME" --client codex --max-sources 5
```

Telltale writes append-only JSONL by default so the output can be reviewed
locally or shipped to a SIEM. The default `user` path profile writes telemetry
under the operating-system-standard per-user location, such as
`$XDG_STATE_HOME/telltale/logs/adr-events.jsonl` or
`~/.local/state/telltale/logs/adr-events.jsonl` on Linux,
`~/Library/Logs/Telltale/adr-events.jsonl` on macOS, and
`%LOCALAPPDATA%\Telltale\Logs\adr-events.jsonl` on Windows. Use
`--path-profile system` for managed service deployments and
`--path-profile project` when you intentionally want repo-relative development
paths.

Explicit `--log-path` and `--state-path` flags override profile defaults. Service
managers can also set `ADR_LOG_PATH` and `ADR_STATE_PATH`.

## Local Rule, Policy, And Allowlist Config

Telltale loads bundled detection rules by default. Operators can add local YAML
without repeating every path by creating a local config root. Existing default
roots are checked in deterministic order:

- `/etc/telltale`
- `$XDG_CONFIG_HOME/telltale`, or `$HOME/.config/telltale` when
  `XDG_CONFIG_HOME` is not set

Supported directories for this phase are:

```text
/etc/telltale/
  rules.d/*.yaml|*.yml
  overrides.d/*.yaml|*.yml
  policies.d/*.yaml|*.yml
  allowlists.d/*.yaml|*.yml
```

`rules.d` files are sorted within each root and loaded before explicit
`--rules` paths. `overrides.d` files are sorted the same way and applied after
rules are merged, before policy filtering. If no explicit `--policy` is provided,
exactly one discovered `policies.d` file may be used; multiple discovered
policies require passing `--policy` explicitly or removing extras. `scan` and
`watch` apply the same single-file rule for discovered `allowlists.d` files when
`--allowlist` is not provided.

Use overrides for local rule disablement or score tuning without editing bundled
or custom rule files:

```yaml
version: 1
description: Local workstation tuning.
overrides:
  - rule_id: network.download
    enabled: false
    reason: Too noisy on this workstation.
  - rule_id: secret.env.read
    score: 20
    reason: Lab environment tuning.
```

Use `--config-dir <path>` to use explicit config roots instead of the default
roots, and `--no-local-config` when a command should ignore local config.
Explicit config roots must exist so path typos fail closed.

Use `adr config validate` as the local config preflight before running scans with
custom content. It resolves config the same way as `scan` and `watch`, validates
the effective rule, override, and policy set, validates the selected allowlist
YAML, and prints a JSON status summary without reading session stores.

Use `adr rules export-default` when you want to inspect or fork the bundled
default rules from an installed binary. Write the output into a local `rules.d`
file or pass the exported file explicitly with `--rules`; do not edit bundled
defaults in place.

## Project-Local Session Stores

Some clients store session data inside project directories rather than under
`$HOME`. By default, Telltale scans `~/github` and `~/projects` if they exist.
Copilot, OpenCode-in-project, and Codex per-project CLI logs are discovered
from these default paths. To customize, declare project roots in a YAML config
file:

```yaml
projects:
  - name: my-project
    path: ~/github/my-project
```

Pass the config to scans or watch mode:

```sh
cargo run -- scan --once --root "$HOME" --project-config projects.yaml
```

You can also set the colon-separated `ADR_PROJECT_CONFIG` environment variable
instead of repeating the flag. When neither is provided, Telltale uses the
default paths (`~/github` and `~/projects`).

## Optional Watch Mode

Use `adr watch` when you want repeated scans after local session-store changes.
The watch command accepts the same repeated `--client <id>` filters as
`adr scan`, which keeps filesystem watches and triggered scans scoped to the
selected supported clients:

```sh
cargo run -- watch --client codex --client opencode --root "$HOME"
```

## Check Scanner Status

After a scan writes JSONL telemetry, use `adr status` to review the latest local
scanner summary:

```sh
cargo run -- status
```

The command keeps its top-level `status` field for the status lookup result. The
latest scanner health check is reported separately as `health_component`,
`health_check_name`, and `health_check_status`, matching the health event fields
that SIEM dashboards can group by as `component`, `check_name`, and `status`.

## Optional Service Setup (Advanced)

The repository includes Linux-oriented systemd examples in
`config/examples/adr-scan.service` and `config/examples/adr-scan.timer` for
managed deployments that use the `system` path profile with a dedicated service
account. This is an advanced path for shared scan servers or fleet-managed
hosts where the scanned session stores are explicitly made readable by the scan
account.

The example service assumes a managed Linux deployment with `/usr/local/bin/adr`,
`/var/log/telltale/adr-events.jsonl`, and `/var/lib/telltale/adr-state.json`.
Create the service account and directories with permissions that let Telltale
append telemetry while granting your shipper read-only access to the log file.
Use `config/examples/telltale-logrotate` as a starter Linux rotation policy so
the active shipper target remains `/var/log/telltale/adr-events.jsonl`.

For the common workstation case, the quick installer above sets up a user-level
timer that runs as your user with no sudo and no service account.

## Optional SIEM Setup

Telltale writes append-only JSONL. Review the generated event schema and your
environment's data-handling requirements before forwarding events to a SIEM or
central log platform. See [telemetry-output.md](telemetry-output.md) for the
vendor-neutral event-output model and forwarding boundary.

Configure file monitors for the active path profile. Workstation installs write
to the `user` profile path by default, such as
`~/.local/state/telltale/logs/adr-events.jsonl` on Linux. Managed Splunk/Filebeat
deployments should run scans with `--path-profile system` or explicit
`ADR_LOG_PATH`/`ADR_STATE_PATH` values and monitor
`/var/log/telltale/adr-events.jsonl`. Do not monitor legacy repo-local
`logs/adr-events.jsonl` unless scans intentionally use `--path-profile project`.
