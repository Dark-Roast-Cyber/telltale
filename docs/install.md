# Install

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
cargo run -- scan --once --emit-activity --root "$HOME" --log-path logs/adr-events.jsonl
```

Telltale writes append-only JSONL by default so the output can be reviewed
locally or shipped to a SIEM.

## Optional Watch Mode

Use `adr watch` when you want repeated scans after local session-store changes.
The watch command accepts the same repeated `--client <id>` filters as
`adr scan`, which keeps filesystem watches and triggered scans scoped to the
selected supported clients:

```sh
cargo run -- watch --client codex --client opencode --root "$HOME" --log-path logs/adr-events.jsonl
```

## Check Scanner Status

After a scan writes JSONL telemetry, use `adr status` to review the latest local
scanner summary:

```sh
cargo run -- status --log-path logs/adr-events.jsonl
```

The command keeps its top-level `status` field for the status lookup result. The
latest scanner health check is reported separately as `health_component`,
`health_check_name`, and `health_check_status`, matching the health event fields
that SIEM dashboards can group by as `component`, `check_name`, and `status`.

## Optional Service Setup

The repository includes Linux-oriented systemd examples in
`config/examples/adr-scan.service` and `config/examples/adr-scan.timer` for
periodic scans.

The example service runs the repository build artifact directly from
`target/release/adr`, so build the release binary before enabling the timer.

## Optional SIEM Setup

Telltale writes append-only JSONL. Review the generated event schema and your
environment's data-handling requirements before forwarding events to a SIEM or
central log platform. See [telemetry-output.md](telemetry-output.md) for the
vendor-neutral event-output model and forwarding boundary.
