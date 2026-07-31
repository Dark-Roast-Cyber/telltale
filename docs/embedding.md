# Embedding Telltale

Telltale can run inside another Rust application — an EDR agent, an endpoint
security tool, or an inference proxy — as an ordinary Cargo dependency. The
embedded pipeline returns detection events as values; the host application
decides where they go. Nothing in the library crates writes JSONL, talks to a
SIEM, or exits the process.

## Which crate to depend on

| Integrator profile | Dependency | What you get |
| --- | --- | --- |
| Consume or emit Telltale events (backend, analytics) | `telltale-schema` | Event model, normalized records, redaction, risk thresholds. Events support Serde serialization; event deserialization is not part of the API. |
| Evaluate the rule language inline (proxy, gateway) | `telltale-rules` | YAML rule parsing/validation/policy merge and in-memory regex evaluation. I/O-free: no filesystem, watcher, or database access. |
| Discover and parse agent session stores | `telltale-sources` | Cross-platform discovery, static per-agent source definitions, parser entry points, and install inventory. |
| Full pipeline in-process (EDR, security tool) | `telltale-core` | The supported embedding facade: discover → parse → detect with one dependency. |

## Getting the crates

These packages are in current release preparation and are not published to
crates.io yet. The supported embedding surface is `telltale-core`; consume it
as a git dependency and pin a revision until publication:

See the [0.4.0 migration guide](migrations/0.4.0.md) before upgrading an
existing integration.

```toml
[dependencies]
telltale-core = { git = "https://github.com/Dark-Roast-Cyber/telltale", rev = "<commit>" }
```

Pin a `rev` (not a branch): the crates are pre-1.0 and APIs may change
between commits. Update the pin deliberately and re-run your tests.

## Quick start

```rust
use telltale_core::Pipeline;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Bundled default rules; add .rules_document(yaml) for custom packs.
    let pipeline = Pipeline::builder().build()?;

    // Discover and scan every supported agent session store under a root.
    for (source, event) in pipeline.scan_root(std::path::Path::new("/home/user"))? {
        println!("{}: {} {:?}", source.source_id, event.event_type, event.rule_ids);
    }
    Ok(())
}
```

A compile-tested version lives at `crates/telltale/examples/embed_scan.rs`
(`cargo run -p telltale-core --example embed_scan` scans the repository's synthetic
fixtures).

> **Crates.io name warning:** The crates.io package named `telltale` is an
> unrelated session-types crate, not this project. Do not use it for Telltale
> integrations.

Existing local or git consumers that already import `telltale::Pipeline` can
use an explicit Cargo alias during migration; this is compatibility guidance,
not the official package name:

```toml
[dependencies]
telltale = { package = "telltale-core", git = "https://github.com/Dark-Roast-Cyber/telltale", rev = "<commit>" }
```

### Records you already have

If the host application parses or synthesizes its own normalized records, skip
discovery:

```rust
let events = pipeline.detect_records(&source, &records);   // full events
let matched = pipeline.evaluate_session(&records)?;        // raw rule matches
```

`detect_records` stamps events with the identity in `source`; construct a
`telltale_core::Source` with a synthetic path if the records did not come from a
file. `evaluate_session(&records)` returns
`Result<Option<MatchResult>, RiskAccountingError>`. `Ok(None)` means no rule
matched; `Ok(Some(match_result))` contains rule IDs, categories, score, and
redacted evidence. Contribution overflow, invalid rule IDs, or other accounting
failures are returned to the host and must not be silently dropped.

This is record evaluation, not runtime source registration. Setting an
arbitrary `NormalizedRecord.client` string does not add a supported client,
discovery root, or parser. Custom client/source parser registration remains
unsupported; new sources require a bundled implementation and registry change.

### Custom rules and policy

The builder mirrors the `telltale` CLI's rule semantics:

```rust
let pipeline = Pipeline::builder()
    .rules_document(custom_yaml)      // additive, like --rules
    .policy_document(policy_yaml)     // enable/disable, like --policy
    .build()?;
// .without_bundled_defaults() mirrors --no-default-rules
```

Rule documents are strings, not paths — the host owns file loading, which
keeps the rule engine usable in processes with no filesystem access.

## What an embedder inherits

- **Redaction stays on.** Evidence fields carry redacted excerpts and hashes;
  raw transcripts never appear in events. Do not log raw session content
  around the pipeline — that would defeat the privacy model documented in
  `privacy-model.md`.
- **Deterministic, offline evaluation.** No network access at scan time; rules
  are regex/static scoring. LLM triage is a CLI-side layer and is not part of
  the embedded pipeline.
- **Vendor-neutral events.** The event body is SIEM-agnostic; envelope
  formatting (Splunk HEC, Elastic bulk) belongs at the transport boundary in
  the host.

## Stability

Pre-1.0: the `telltale-core` facade (`Pipeline`) and its documented type
re-exports are the intended stable surface. The lower-level crates may
reorganize more freely, and `telltale-detect` can be used without source I/O by
disabling its default `source-io` feature. If you need something the facade does
not expose, open an issue describing the integration — that feedback drives what
gets stabilized.
