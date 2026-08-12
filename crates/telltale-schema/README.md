# telltale-schema

[![crates.io](https://img.shields.io/crates/v/telltale-schema.svg)](https://crates.io/crates/telltale-schema)

Canonical Telltale events, normalized records, source identities, redaction,
and scoring types. This crate owns data contracts only; it does not discover
session stores or evaluate detection rules.

Native serialized events use Event 3.0, package-only `telltale_version`,
`telltale-<UUIDv4>` event IDs, and top-level `timeline_anchors`. Legacy Event
1.0/2.0 fields are historical compatibility data and are read by the CLI's
strict historical dispatcher rather than emitted by native builders.

```rust
use telltale_schema::record::NormalizedRecord;

let _record: Option<NormalizedRecord> = None;
```

This package follows Telltale's pre-1.0 release and compatibility policy.

- [API documentation](https://docs.rs/telltale-schema)
- [Repository](https://github.com/Dark-Roast-Cyber/telltale)
