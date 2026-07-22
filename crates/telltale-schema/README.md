# telltale-schema

[![crates.io](https://img.shields.io/crates/v/telltale-schema.svg)](https://crates.io/crates/telltale-schema)

Canonical Telltale events, normalized records, source identities, redaction,
and scoring types. This crate owns data contracts only; it does not discover
session stores or evaluate detection rules.

```rust
use telltale_schema::record::NormalizedRecord;

let _record: Option<NormalizedRecord> = None;
```

This package follows Telltale's pre-1.0 release and compatibility policy.

- [API documentation](https://docs.rs/telltale-schema)
- [Repository](https://github.com/Dark-Roast-Cyber/telltale)
