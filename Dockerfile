# Telltale - Agent Detection and Response
# Multi-stage build: Rust builder → minimal Debian runtime.

# ---------- Stage 1: build ----------
FROM rust:1.94-bookworm AS builder

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY build.rs ./
COPY src/ src/
COPY config/ config/
COPY schemas/ schemas/

# rusqlite bundles SQLite via the "bundled" feature; no extra -dev packages.
RUN cargo build --release && strip target/release/adr

# ---------- Stage 2: runtime ----------
FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/adr /usr/local/bin/adr
COPY --from=builder /build/config/ /opt/adr/config/
COPY --from=builder /build/schemas/ /opt/adr/schemas/

# Default directories for logs, state, and session-store mounts.
RUN mkdir -p /var/log/adr /var/lib/adr/state

# Scan root is mounted at runtime; Telltale refuses to scan / inside the container.
VOLUME ["/session-stores", "/var/log/adr"]

ENV ADR_LOG_PATH=/var/log/adr/adr-events.jsonl
ENV ADR_STATE_PATH=/var/lib/adr/state/adr-state.json

ENTRYPOINT ["adr"]
CMD ["scan", "--once", "--emit-activity"]
