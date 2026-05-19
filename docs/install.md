# Install

Telltale Core is currently source-first. The simplest setup is to build the
Rust binary locally, run a fixture-safe scan, then point the scanner at your
real agent session stores.

## Prerequisites

- Rust toolchain with `cargo`
- Local access to the agent session stores you want to scan
- Optional: a SIEM or log shipper for the generated JSONL event stream

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

## Scan Real Session Stores

Once the fixture scan looks healthy, run against your local session stores:

```sh
cargo run -- scan --once --emit-activity --root . --log-path logs/adr-events.jsonl
```

Telltale writes append-only JSONL by default so the output can be reviewed
locally or shipped to a SIEM.

## Optional Service Setup

The repository includes Linux-oriented systemd examples in
`config/examples/adr-scan.service` and `config/examples/adr-scan.timer` for
periodic scans.

## Optional SIEM Setup

Telltale writes append-only JSONL. Review the generated event schema and your
environment's data-handling requirements before forwarding events to a SIEM or
central log platform.
