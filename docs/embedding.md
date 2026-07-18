# Embedding Telltale

Telltale can run inside another Rust application — an EDR agent, an endpoint
security tool, or an inference proxy — as an ordinary Cargo dependency. The
embedded pipeline returns detection events as values; the host application
decides where they go. Nothing in the library crates writes JSONL, talks to a
SIEM, or exits the process.

## Which crate to depend on

| Integrator profile | Dependency | What you get |
| --- | --- | --- |
| Consume or emit Telltale events (backend, analytics) | `telltale-schema` | Event model, normalized records, redaction, risk thresholds. Serde only. |
| Evaluate the rule language inline (proxy, gateway) | `telltale-rules` | YAML rule parsing/validation/policy merge and in-memory regex evaluation. I/O-free: no filesystem, watcher, or database access. |
| Discover and parse agent session stores | `telltale-sources` | Cross-platform discovery, per-agent adapters, parsers, install inventory. |
| Full pipeline in-process (EDR, security tool) | `telltale` | The facade: discover → parse → detect with one dependency. |

## Getting the crates

The crates are not published to crates.io yet. Consume them as git
dependencies and pin a revision:

```toml
[dependencies]
telltale = { git = "https://github.com/Dark-Roast-Cyber/telltale", rev = "<commit>" }
```

Pin a `rev` (not a branch): the crates are pre-1.0 and APIs may change
between commits. Update the pin deliberately and re-run your tests.

## Quick start

```rust
use telltale::Pipeline;

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
(`cargo run -p telltale --example embed_scan` scans the repository's synthetic
fixtures).

### Records you already have

If the host application parses or synthesizes its own normalized records, skip
discovery:

```rust
let events = pipeline.detect_records(&source, &records);   // full events
let matched = pipeline.evaluate_session(&records);         // raw rule matches
```

`detect_records` stamps events with the identity in `source`; construct a
`telltale::Source` with a synthetic path if the records did not come from a
file. `evaluate_session` returns the raw `MatchResult` (rule ids, categories,
score, redacted evidence) for callers that build their own alerting.

### Custom rules and policy

The builder mirrors the `adr` CLI's rule semantics:

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

Pre-1.0: the facade (`Pipeline`) is the intended stable surface; the
lower-level crates re-exported through `telltale::{schema, rules, sources,
detect}` may reorganize more freely. If you need something the facade does not
expose, open an issue describing the integration — that feedback drives what
gets stabilized.
