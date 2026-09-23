# telltale-detect

[![crates.io](https://img.shields.io/crates/v/telltale-detect.svg)](https://crates.io/crates/telltale-detect)

Detection over caller-supplied records and canonical observations: rule
evaluation, timelines, baseline models, correlation, allowlists, and optional
MCP analysis. Source acquisition belongs to `telltale-sources`; scan/watch
orchestration belongs to `telltale-core` and the CLI.

```rust
let rules = telltale_rules::load_default_rule_set()?;
let records: Vec<telltale_schema::record::NormalizedRecord> = Vec::new();
let _matches = telltale_detect::detection::evaluate_session_matches(&rules, &records)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

`allowlist::Allowlist::suppression_provenance()` provides the separate
domain-separated suppression identity used by the provenance manifest. It
declares canonicalization `suppression-v1-effective-v1`. Criteria remain in the
digest preimage only; public materialization exposes only suppression state,
count, canonicalization, and fingerprint, not names or criteria.

The default `source-io` feature enables source-dependent support such as MCP
inventory and its I/O dependencies (`telltale-sources`, `walkdir`). It does not
expose a filesystem-backed detection/parser pipeline. Direct-record and
Detection v2 evaluation remain I/O-free; consumers can use
`default-features = false` to omit source I/O, SQLite, and `walkdir`. Pair the
crate with `telltale-rules` and `telltale-schema` for rule sets and record types.

This package follows Telltale's pre-1.0 release and compatibility policy.

- [API documentation](https://docs.rs/telltale-detect)
- [Repository](https://github.com/Dark-Roast-Cyber/telltale)
