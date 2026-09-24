# telltale-sources

[![crates.io](https://img.shields.io/crates/v/telltale-sources.svg)](https://crates.io/crates/telltale-sources)

Cross-platform session-store discovery, native extraction, and Canonical
Observation v2 acquisition for supported AI coding agents, including source
definitions and install inventory. This crate does not apply detection rules,
emit telemetry, or produce caller-record compatibility types.

```rust
let sources = telltale_sources::discovery::discover_sources(std::path::Path::new("/tmp"))?;
println!("{} sources", sources.len());
```

The public acquisition route is source discovery, native extraction, native
accounting and progress, then source-owned canonical mapping. There is no
parser registry and no source-backed conversion into `NormalizedRecord`.
OpenCode is only `opencode.sqlite`. Its SQLite read options, busy timeout, part
limit, and cursor overlap stay on that native path. There is no OpenCode
investigation export helper.

This package follows Telltale's pre-1.0 release and compatibility policy.

- [API documentation](https://docs.rs/telltale-sources)
- [Repository](https://github.com/Dark-Roast-Cyber/telltale)
