# Docker Support

Telltale ships a multi-stage `Dockerfile` and a `docker-compose.yml` that
demonstrates fixture-safe scanner execution.

## Quick Start

### Build the image

```sh
make docker-build
# or
docker build -t adr:latest .
```

### Run a one-shot scan (fixtures, no writes)

```sh
make docker-scan-dry
# or
docker run --rm adr:latest scan --once --dry-run --root /session-stores
```

### Run against real session stores

Mount your agent session store directory into the container:

```sh
docker run --rm \
  -v ~/.codex/sessions:/session-stores:ro \
  -v adr-logs:/var/log/adr \
  adr:latest scan --once --emit-activity --root /session-stores
```

## Docker Compose

The `docker-compose.yml` runs a one-shot Telltale scan against a mounted
session store and writes JSONL output to a named volume.

### Usage

```sh
# Scan Codex sessions
SESSION_STORE=~/.codex/sessions docker compose up --build

# Scan OpenCode sessions
SESSION_STORE=~/.local/share/opencode docker compose up --build

# Use fixture data (default, no SESSION_STORE override)
docker compose up --build
```

### Services

| Service | Container | Description |
|---------|-----------|-------------|
| `adr` | `adr-scanner` | Runs `adr scan --once --emit-activity` against the mounted session store. |

### Volumes

| Volume | Purpose |
|--------|---------|
| `adr-logs` | Shared JSONL output from Telltale. |
| `adr-state` | Persists scan state (fingerprints) across runs. |

### Configuration

- **Session store**: set `SESSION_STORE` environment variable to the host path.
- **Rules**: the repo's `config/` directory is mounted read-only; edit rules on the host and re-run.

## Makefile Targets

| Target | Description |
|--------|-------------|
| `make docker-build` | Build the Telltale Docker image. |
| `make docker-scan-dry` | Run a fixture-safe dry-run scan in a container. |
| `make docker-up` | Start Docker Compose. |
| `make docker-down` | Stop Docker Compose. |

## Architecture

The Dockerfile uses a multi-stage build:

1. **Builder stage** (`rust:1.94-bookworm`): compiles the Telltale binary with `cargo build --release` and strips debug symbols.
2. **Runtime stage** (`debian:bookworm-slim`): minimal image with only `ca-certificates` and the Telltale binary. No Rust toolchain in the final image.

The `rusqlite` crate bundles SQLite via its `bundled` feature, so no SQLite development libraries are needed in the runtime image.

## Production Notes

- The container runs `scan --once` by default. For periodic scanning, override the command or use an external scheduler (cron, systemd timer).
- Mount agent session stores read-only (`:ro`) to prevent Telltale from modifying source data.
- For CI, use `--dry-run` to validate rules against fixtures without writing events.
