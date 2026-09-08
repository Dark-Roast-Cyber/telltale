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

## Event 3.0 consumer

External consumers can parse one complete terminal Event 3.0 object without
deserializing the trusted producer `Event`:

```rust
use telltale_schema::event::Event3Record;

let record = Event3Record::from_json(bytes)?;
println!("{}", record.event_type());
```

The consumer parses JSON, requires exact `schema_version` `3.0`, validates the
frozen strict schema, applies current identity/family/risk semantics, and then
returns typed common and family projections. `Event3Family::Activity` keeps
standard activity separate from install inventory even though both use the
wire event type `activity`. `Event3ConsumerError` exposes stable categories and
codes but never includes input JSON, values, paths, or serde diagnostics.

This API reads terminal bytes; it does not reconstruct native producer state,
perform delivery, infer ordering, or claim that response guidance was an
executed action. See [Telemetry Output](../../docs/telemetry-output.md) for
timing, identity, JSONL, replay, and sink boundaries.

## Producer provenance

`ProducerProvenanceManifestV1` is a separate, closed contract for comparing
effective producer configuration. It includes compiled Rule v1 and suppression
fingerprints, the declared suppression canonicalization
`suppression-v1-effective-v1`, thresholds, audited feature switches, and the
frozen Event 3.0 identity. It does not contain rule YAML, regexes, paths,
suppression criteria, scan identity, or telemetry linkage. Its hashes are
content-integrity aids, not encryption or attestation.

This package follows Telltale's pre-1.0 release and compatibility policy.

Canonical Observation v2 core types are local-only scaffolding and are not the
Event 3.0 output contract. Callers must not log these types; nested `Debug`
implementations can still expose local or sensitive values if logged directly.

- [API documentation](https://docs.rs/telltale-schema)
- [Repository](https://github.com/Dark-Roast-Cyber/telltale)
