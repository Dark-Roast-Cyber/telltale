# telltale-detect

[![crates.io](https://img.shields.io/crates/v/telltale-detect.svg)](https://crates.io/crates/telltale-detect)

Detection over normalized Telltale records: rule evaluation, timelines,
baselines, correlation, allowlists, and MCP analysis. It consumes source and
rule crates but leaves storage, telemetry sinks, and process lifecycle to the
caller.

```rust
let _events = telltale_detect::detection::detect_sources(&[]);
```

The default `source-io` feature enables filesystem-backed detection, source
parsing, MCP inventory, SQLite, and `walkdir`. Consumers that already have
normalized records can use `default-features = false` to omit source discovery,
parsing, SQLite, and `walkdir`; pair it with `telltale-rules` and
`telltale-schema` for rule sets and record/source types.

This package follows Telltale's pre-1.0 release and compatibility policy.

- [API documentation](https://docs.rs/telltale-detect)
- [Repository](https://github.com/Dark-Roast-Cyber/telltale)
