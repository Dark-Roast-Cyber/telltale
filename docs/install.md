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
cargo run -- scan --once --dry-run --root tests/fixtures/session_stores
cargo run -- rules validate --rules config/rules/tool-call-regex.yaml
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

## Optional Service Setup

The repository includes Linux-oriented systemd examples in
`config/examples/adr-scan.service` and `config/examples/adr-scan.timer` for
periodic scans.

The example service assumes a managed Linux deployment with `/usr/local/bin/adr`,
`/var/log/telltale/adr-events.jsonl`, and `/var/lib/telltale/adr-state.json`.
Create the service account and directories with permissions that let Telltale
append telemetry while granting your shipper read-only access to the log file.
Use `config/examples/telltale-logrotate` as a starter Linux rotation policy so
the active shipper target remains `/var/log/telltale/adr-events.jsonl`.

## Optional SIEM Setup

Telltale writes append-only JSONL. Review the generated event schema and your
environment's data-handling requirements before forwarding events to a SIEM or
central log platform. See [telemetry-output.md](telemetry-output.md) for the
vendor-neutral event-output model and forwarding boundary.
