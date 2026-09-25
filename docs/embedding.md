# Embedding Telltale

Telltale can run inside another Rust application — an EDR agent, an endpoint
security tool, or an inference proxy — as an ordinary Cargo dependency. The
embedded pipeline returns detection events as values; the host application
decides where they go. Nothing in the library crates writes JSONL, talks to a
SIEM, or exits the process.

The versioned state file, sidecar locking, platform-qualified local JSONL
durability, and the `migrate state` command described in the migration contract
belong to the standalone CLI runtime. Embedding hosts retain ownership of
persistence and delivery while using the same analytic and event semantics.

## Delivery boundary

`Pipeline::scan_root` uses the shared canonical source runtime and returns the
same Event 3 detection/activity compatibility projection as CLI scan/watch.
Acquisition is source-native Canonical Observation v2 followed by authoritative
Detection v2 evaluation. The runtime remains a private implementation seam; it
does not add a second public embedding abstraction. See the [canonical runtime
boundary](canonical-observation-v2.md#shared-canonical-source-runtime).

`detect_records` and `evaluate_session` remain deliberate Rule v1 record-level
compatibility APIs accepting `NormalizedRecord`. They cannot supply native
acquisition/accounting facts and are not converted into canonical observations.
They remain separate from the active source runtime by design.
The facade has no baseline-state, cursor, process-chain configuration, or event
allowlist contract. Rule policy controls rule enablement, not event allowlisting.

`telltale-core::Pipeline` yields `Event` values; the embedding host owns
serialization, persistence, and I/O. The public out-of-process path is exactly
`terminal/emittable Event 3.0 -> durable JSONL -> future generic vendor-neutral
local collector transport`. The collector transport is a future extension, not
an implementation in this release.

Event 3.0 is independent of transport. Sink identity, transport, delivery
policy, and persistence role are separate concerns.
A future local IPC transport may be `BestEffort`, while a durable transport need
not be HTTP. The extension seam reuses generic structured delivery
classification and outbox dispatch; adding a transport does not require a
foundational sink refactor.

The future local collector implementation and protocol are deferred. Issue #26
defines no local collector protocol, introduces no public plugin ABI, and does
not change Event 3.0. Adopter-specific integrations remain outside the core
contract. Issue #28 remains deferred and unfrozen; JSONL-only is not its final
adoption architecture.

## Which crate to depend on

| Integrator profile | Dependency | What you get |
| --- | --- | --- |
| Consume or emit Telltale events (backend, analytics) | `telltale-schema` | Event model, normalized records, redaction, risk thresholds. Events support Serde serialization; event deserialization is not part of the API. |
| Evaluate the rule language inline (proxy, gateway) | `telltale-rules` | YAML rule parsing/validation/policy merge and in-memory regex evaluation. I/O-free: no filesystem, watcher, or database access. |
| Discover and acquire agent session stores | `telltale-sources` | Cross-platform discovery, static per-agent source definitions, canonical acquisition, and install inventory. |
| Full pipeline in-process (EDR, security tool) | `telltale-core` | The supported embedding facade: discover → native acquisition → canonical detection with one dependency. |

## Getting the crates

These packages are in current release preparation and are not published to
crates.io yet. The supported embedding surface is `telltale-core`; consume it
as a git dependency and pin a revision until publication:

See [Versioning and Releases](versioning.md) and the planned
[0.7.0 migration guide](migrations/0.7.0.md) before upgrading an existing
integration.

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
discovery root, or extractor. New sources require a bundled native extractor
and registry change.

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
  and scoring are static and native Event 3.0 response metadata and timeline
  anchors are deterministic. Downstream analyst review is outside the embedded
  pipeline.
- **Vendor-neutral events.** The event body is SIEM-agnostic; envelope
  formatting (Splunk HEC, Elastic bulk) belongs at the transport boundary in
  the host.

## Stability

For 0.7, `telltale-core::Pipeline` (including `scan_root`, its builder, and the
deliberate caller-provided `detect_records` / `evaluate_session` compatibility
methods) and the types needed to call it are the supported Rust embedding
facade. The core re-exports of `Source`, `Event`, `NormalizedRecord`, and rule
result/error types serve that facade; their presence does not promise that
every public module of the originating crate is a stable embedding API.

Other intentional adoption contracts have separate owners:

- `telltale_schema::event::Event3Record` consumes one complete, terminal Event3
  object; native `Event` is the producer type, not an event deserializer.
- `telltale_core::LocalEventFeed` and its documented config, batch, and notice
  types support bounded read-only polling of local Event3 JSONL. See
  [telemetry/output](telemetry-output.md#runtime-neutral-local-journal-polling).
- `ProducerProvenanceManifestV1` and the public core provenance assembler/
  `Pipeline::producer_provenance_manifest` describe effective producer
  configuration, not per-event attestation or CLI path resolution. See
  [producer provenance](telemetry-output.md#producer--detector-provenance-manifest).
- Rule v1 **documents** remain supported content compatibility independent of
  the stability of the `telltale-rules` Rust implementation API.

The other public APIs in `telltale-schema`, `telltale-sources`,
`telltale-detect`, and `telltale-rules` are usable foundations but do not receive
a blanket 0.7 Rust API compatibility promise. In particular, Canonical
Observation v2 and Detection v2 are authoritative *semantic/runtime* contracts,
not a supported third-party source-adapter or detector plugin ABI.
`telltale_core::canonical_runtime` is a hidden migration seam, not an embedding
entry point. The optional `telltale_core::assignment` store has a documented
fail-closed identity/replay contract but is not used by normal source scans or
promised as a general-purpose stable storage API. Public visibility alone does
not authorize removing these modules or weakening their behavior.

Pin a git revision and test upgrades: this is pre-1.0, not a promise of
unchanged Rust signatures between commits. `telltale-detect` can be used
without source I/O by disabling its default `source-io` feature. If an
integration needs a lower-level API stabilized, open an issue describing the
use case before treating the module layout as a compatibility contract.
