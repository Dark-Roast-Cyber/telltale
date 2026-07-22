# telltale-sources

[![crates.io](https://img.shields.io/crates/v/telltale-sources.svg)](https://crates.io/crates/telltale-sources)

Cross-platform session-store discovery and parsing for supported AI coding
agents, including source definitions and install inventory. This crate parses
and normalizes source data but does not apply detection rules or emit telemetry.

```rust
let sources = telltale_sources::discovery::discover_sources(std::path::Path::new("/tmp"));
println!("{} sources", sources.len());
```

This package follows Telltale's pre-1.0 release and compatibility policy.

- [API documentation](https://docs.rs/telltale-sources)
- [Repository](https://github.com/Dark-Roast-Cyber/telltale)
