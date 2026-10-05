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

`Pipeline::scan_root` and `Pipeline::scan_sources` use the shared canonical source
runtime and return the same Event 3 detection/activity compatibility projection
as CLI scan/watch.
Acquisition is source-native Canonical Observation v2 followed by authoritative
Detection v2 evaluation. The runtime remains a private implementation seam; it
does not add a second public embedding abstraction. See the [canonical runtime
boundary](canonical-observation-v2.md#shared-canonical-source-runtime).

Hosts can discover sources with `telltale_sources::discovery::discover_sources`,
select them, then pass those exact `Source` values to `scan_sources(&sources)`.
Unlike `scan_root`, it performs no discovery; neither method persists state or
output. Both preserve session-scoped detections and `timeline_anchors`, not
per-action detection events, and map source failures to `scanner_error` events.
Removed parser registration and source-backed flat-record projection are not
compatibility paths.

### Typed pipeline errors (current development after RC1)

`PipelineBuilder::build` and the `Pipeline` scan methods return `PipelineError`
rather than `Box<dyn Error>`. This is a source-breaking Rust interface change
in the untagged, unpublished `0.7.0-rc.2` development line, not a change to
published RC1 artifacts or stable qualification. Update a Git pin deliberately
and validate the host integration separately.

| Operation | Returned categories |
| --- | --- |
| `build` | `InvalidConfiguration`, `Compilation` |
| `scan_root`, `scan_root_with_occurrences` | `Discovery`, `Clock`, `Observation`, `Compilation` |
| `scan_sources`, `scan_sources_with_occurrences` | `Clock`, `Observation`, `Compilation` |
| detailed scans and `semantic_provenance` | the matching scan categories, plus `InvalidOptions` |

`Observation` means batch observation-time validation, not per-source canonical
validation. Clock/time validation and canonical compilation run even for an
empty source batch. Root scans complete checked discovery first. Source-processing
failures still become source-local `scanner_error` events, with no successful
partial source projection or occurrences; they are not returned `PipelineError`s.
Event 3.0, state formats, rule validation order, and CLI diagnostics/exit semantics
are unchanged.

The enum is `#[non_exhaustive]`; hosts match meaningful categories with a fallback:

```rust,no_run
use telltale_core::{Pipeline, PipelineError};

let pipeline = Pipeline::builder().build()?;
match pipeline.scan_root(std::path::Path::new("/synthetic/session-root")) {
    Ok(events) => { /* host owns event handling */ }
    Err(PipelineError::Discovery(cause)) => {
        // Choose another root or report the checked discovery failure.
        eprintln!("{cause}");
    }
    Err(error) => return Err(error),
}
# Ok::<(), PipelineError>(())
```

Display and Debug render closed codes and do not include paths, configuration,
or source text. `std::error::Error::source()` preserves the original payload
except for `InvalidConfiguration` and `InvalidOptions`. `DiscoveryError`,
`RuleV1CompileError`, and `ObservationError` are available from the core crate
root. `Compilation` boxes loader and canonical-compile failures; its concrete
source type is not a supported subtype taxonomy, and hosts should not parse
strings to classify failures.

Host entrypoints may still use `Box<dyn Error>` and propagate these errors with
`?`. Explicit boxed-result forwarding and old downcast-based matching require
migration; see the [migration guide](migrations/0.7.0.md#typed-pipeline-errors-current-development-after-rc1).

### Canonical bound diagnostics (current development after RC1)

Codex canonical bound failures retain a typed, content-free field category and
bound dimension in `SourceFailure.acquisition`. Hosts can use
`AcquisitionError::bound_context()`; absence means no contextual bound diagnostic,
not successful acquisition. `CanonicalValidation { code }` remains supported,
but the new `CanonicalBoundValidation { context }` variant requires updating
exhaustive Rust matches: this is not fully source compatible. `code()` and Display
still return `unbounded_value`. Debug contains only closed diagnostic enums/code,
never source content or locations. Native accounting errors keep their own codes
and no bound context. Event3 adaptation remains generic
`canonical_acquisition_failed`, source-atomic, and content-free. See the
[canonical contract](canonical-observation-v2.md) for categories, dimensions,
unchanged limits/check order/NFC behavior, and current Codex-only acquisition scope.
This requires git-pin host validation and is not RC1/stable qualification.

### OpenCode acquisition feature (current development after RC1)

The default `telltale-core` normal dependency graph has no `rusqlite`.
Git-pinned hosts that scan OpenCode must explicitly enable `opencode-sqlite`:

```toml
telltale-core = { git = "https://github.com/Dark-Roast-Cyber/telltale", rev = "<commit>", features = ["opencode-sqlite"] }
```

This forwards the default-off `telltale-sources/opencode-sqlite` feature, using
bundled SQLite. Without it, OpenCode acquisition fails closed with a per-source
`scanner_error`; mixed scans retain successful JSONL results. The CLI explicitly
enables acquisition. `protected-assignment` is independent and does not enable
OpenCode acquisition. OpenCode investigation remains deferred with either feature
setting, before discovery, source I/O, or process spawn. Updating a host's Git pin
requires separate validation; this is not RC1 or stable qualification.

### Inventory facade (current development after RC1)

`telltale_core::inventory` exposes existing install snapshots, signal types,
`collect_install_inventory_with_context`, and `snapshot_to_event`, plus
`discover_mcp_inventory(root)` returning `Vec<(Source, Event)>`. Prefer an explicit
host-owned `InstallInventoryContext`: `current()` and `collect_install_inventory`
read the process environment. Snapshots retain presence/path hashes, not paths;
the context and returned MCP `Source.path` are local caller data, not telemetry.
MCP events use the existing privacy projection from supported static configs.
No MCP connection or rule compilation is needed. This facade adds no scan/watch
activation; `Pipeline` scan methods do not emit inventory. These after-RC1 APIs
are not RC1-qualified or stable-qualified; hosts must validate a new Git pin.

### Detection occurrences (current development after RC1)

`Pipeline::scan_sources_with_occurrences(&sources)` and
`Pipeline::scan_root_with_occurrences(root)` return `Vec<SourceScan>`. Each
result holds its `Source`, the same session-scoped `events`, and precise
`DetectionOccurrence` values produced in the same evaluation/projection pass.
These methods and types are current-development additions after RC1, not part
of the published RC1 artifacts or their qualification. The existing
`scan_sources` and `scan_root` methods flatten these events; they do not perform
another detection pass.

An occurrence is a canonical observation supporting a finding, not a per-rule
match or another Event3 event. `finding_index` points into that result's `events`
vector. Session detections have one occurrence per `timeline_anchors` entry,
with the same timeline index, rule IDs (including triggered modifiers),
categories, and selector-derived evidence field names. Activity and MCP events
have no detection occurrences. Session-level response metadata stays on the
associated Event.

`OccurrenceId::as_str()` exposes the validated Canonical Observation v2
`observation_id`, in the form `obs:v2:sha256:<64 lowercase hex>`. It is opaque,
not a content hash, Event3 `event_id`, rule/observation pair, or suppression key.
Its coordinate tuple is adapter type, adapter ID, coordinate kind/value,
family, stage, and child ordinal. Content, paths, timestamps, session titles,
acceptance clocks, and Event3 materialization clocks are excluded. Re-scanning
the same stable coordinates preserves identity even when event IDs change;
identical text at different coordinates has different identities. One
observation associated with multiple findings keeps one identity and multiple
finding associations. This is not authentication or an immutable-history claim.
Unchecked strings cannot construct an `OccurrenceId`; invalid projected IDs
fail that source closed with `scanner_error` and no successful events or
occurrences.
Event3's existing `canonical_observation_id` evidence may redact the ID snippet;
its evidence hash links to the full occurrence ID without changing Event3.

`occurred_at` is source-reported time when retained, otherwise `None`; neither
the session's latest time nor `observed_at` fills a missing timestamp. Sources
without stable coordinates fail acquisition with `replay_unverifiable`; these
stateless scans do not use the assignment store or mint ephemeral identities.
Discovery, clock, and rule compilation failures remain `Err`. No writes,
cursors, or baseline persistence are added.

Process-chain/correlation projection emits one occurrence per supporting
observation ID within a finding. Timeline indexes are retained only when the
exact observation ID has a retained ID/index association from evaluation; vector
length or position is not proof. Missing or conflicting associations yield `None`.
Only single-observation findings retain a source timestamp;
multi-observation correlations have no per-step timestamps. Rule IDs and
categories come from the process event; evidence field names are empty because
there is no Rule v1 selector. The facade has no process-chain configuration
API: hosts can toggle the bundled process pack on or off via detailed options,
but custom process packs or external process rule YAML configuration remain
unavailable.

Occurrences expose no raw prompts, tool output, paths, credentials, process
command lines, redacted excerpts, or raw-value evidence hashes. `session_id`
matches the associated in-memory Event, so hosts associate findings without
parsing Event3 JSON. `finding_index` is the unambiguous link inside that result.
Terminal Event3 serialization remains the wire privacy boundary and is unchanged.
`canonical_runtime` remains an unsupported implementation seam, not the embedding API.

### Contextual investigation (current development after RC1)

`investigation::SessionInvestigator::investigate_context` is an opt-in, read-only
present-day window around `ContextAnchor::Occurrence(OccurrenceId)` or
`ContextAnchor::TimelineIndex(usize)`. Pass `&ContextInvestigationRequest` with
the consumed `Event3Record`, anchor, `before`, `after`, and `ContextContent`.
The existing `investigate` method remains content-free. CLI scan/watch and
`Pipeline` scanning do not call contextual investigation.

All three content switches (`user_text`, `assistant_text`, `tool_arguments`)
default to false. The projection retains only user/assistant messages,
non-result tool observations, and structural session entries. Tool results,
system/developer/tool messages, other observation families, raw canonical
objects, paths/path hashes, observation IDs, and evidence are excluded. Text
uses string message content and text parts, or canonical JSON arguments
(`tool.arguments()`) with adapter-searchable arguments (`tool.searchable_arguments()`)
as fallback, matching the pure projector; it never includes tool results.
Every retained excerpt crosses `redact_sensitive_text` before entering public
output. Timestamps/tool labels/opaque call IDs/link indexes reuse the
content-free timeline's terminal projection and linker; a link can point to an
omitted result outside the returned entries.

Each radius is at most 32 and is validated before I/O. The inclusive window
does not raise existing discovery/acquisition limits. Stored redacted text is
at most 16,384 bytes total (the existing Evidence sanitizer bounds each snippet
to 512 bytes). On exhaustion, farthest neighbors lose text first, with higher
indexes first on equal distance; structure and anchor text remain.
`Found(OccurrenceContext)` contains only `anchor_index`, `entries`, and
`text_budget_exhausted`; entries contain only index/kind, terminal metadata,
linkage, and optional redacted text. An excluded anchor, including a tool
result, still yields `Found`, possibly with no entries.

Resolution uses the same exact source/session boundary as `investigate`.
Occurrence anchors match the exact canonical `observation_id` within that
resolved session: zero/multiple matches return `occurrence_absent`/
`ambiguous_occurrence`, with no index or semantic-fingerprint fallback.
`OccurrenceId` identifies a coordinate-derived canonical source fact, not a
semantic fingerprint or authenticated history; paths/content are not identity
inputs. A timeline index is merely today's order, not proof that a historical
entry is unchanged. Out-of-range indexes return `timeline_index_absent` with
no partial context. Existing unavailable reasons are reused. OpenCode remains
deferred before discovery, source I/O, or process spawning.

This development API is not Event3, is not in the RC1-qualified artifacts, and
does not qualify stable 0.7.0.

`detect_records` and `evaluate_session` remain deliberate Rule v1 record-level
compatibility APIs accepting `NormalizedRecord`. They cannot supply native
acquisition/accounting facts and are not converted into canonical observations.
They remain separate from the active source runtime by design.
The facade has no baseline-state, cursor, custom process-chain configuration,
or event allowlist contract (the only supported process-chain control is
toggling the bundled process pack on or off via detailed options, not custom
rule packs or arbitrary process configurations). Rule policy controls rule
enablement, not event allowlisting.

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

See [Versioning and Releases](versioning.md) and the
[0.7.0 migration guide](migrations/0.7.0.md) before upgrading an existing
integration.

```toml
[dependencies]
telltale-core = { git = "https://github.com/Dark-Roast-Cyber/telltale", rev = "<commit>" }
```

Pin a `rev` (not a branch): the crates are pre-1.0 and APIs may change
between commits. Update the pin deliberately and re-run your tests.

### Optional protected assignment store

Default builds expose `Pipeline` and `LocalEventFeed` without compiling or
exposing `telltale_core::assignment`. To use the protected assignment store,
enable the default-off `protected-assignment` Cargo feature explicitly:

```toml
[dependencies]
telltale-core = { git = "https://github.com/Dark-Roast-Cyber/telltale", rev = "<commit>", features = ["protected-assignment"] }
```

Existing git-pinned adopters importing `telltale_core::assignment` must add
this feature when updating their pin. The enabled API keeps the same module
path, store format, and replay/privacy guarantees; no state migration is
required. The store remains Linux-only and fails closed on other platforms.
Enabling the feature does not activate it in scan/watch or adapter projection.
Cargo features are additive: another consumer can enable it through feature
unification. See the [core README](../crates/telltale/README.md#protected-assignment-optional)
for the caller's replay-association requirements and operational limits.

## Quick start

```rust
use telltale_core::{Pipeline, PipelineError};

fn main() -> Result<(), PipelineError> {
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
(`cargo run -p telltale-core --example embed_scan -- <session-root>`; use a
synthetic fixture root for validation). Its host entrypoint deliberately keeps
boxed errors for argument handling and demonstrates matching scan categories.

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

## Current development facade contract

This section describes the current source tree, not the published RC1 artifact
or stable qualification. Pin an exact revision and validate it in the host.
`Pipeline`, `PipelineBuilder`, and the core re-exports are the bounded facade;
lower-level canonical/detection crates are not a source-adapter or detector
plugin ABI. Audited public error/result enums (like `PipelineError`) and extensible result
structs (like `SourceScan`) are declared `#[non_exhaustive]`; downstream matches
must include fallback wildcard arms (`_ => ...`) for enums and struct rest patterns
(`..`) or accessors for non-exhaustive structs, and callers must not depend on
exhaustive construction or destructuring of those types. In contrast, audited
constructible types such as `InstallInventorySnapshot` remain exhaustive and
directly constructible by callers.

### Core Pipeline and scan methods

`PipelineBuilder` provides fluent, typed configuration:
- `Pipeline::builder().build()` compiles bundled rules by default. Rule documents
  are in-memory strings and additive; `without_bundled_defaults()` selects
  custom-only content, and an empty custom-only build fails with `PipelineError::InvalidConfiguration`.
- A policy document applies rule enable/disable policy without filesystem access.
- `PipelineError` is a typed, non-exhaustive enum covering `Discovery(DiscoveryError)`,
  `Clock`, `Observation`, `Compilation`, `InvalidConfiguration`, and `InvalidOptions`.
  Its Display and Debug implementations render closed diagnostic codes
  (`pipeline_discovery_failed`, `pipeline_clock_failed`, `pipeline_observation_failed`,
  `pipeline_compilation_failed`, `pipeline_no_rule_documents`,
  `pipeline_invalid_options`) rather than leaking paths or source text; underlying
  errors are retrievable through `std::error::Error::source`. Source-processing
  failures during a scan surface as per-source `scanner_error` events rather than
  a batch error.
- Discovery core re-exports provide official discovery helpers: `discover_sources`,
  `discover_sources_best_effort`, `discover_watch_roots_for_clients`, `DiscoveryError`,
  and `PathProfile`.

Scan methods provide distinct collection and evaluation modes:
- `scan_root` discovers supported sources below the caller's root path.
- `scan_sources` processes exactly the caller-provided `Source` values without
  performing discovery. Both return session-scoped Event 3 events. Caller-created
  `Source` values and paths remain local host data.
- `scan_root_with_occurrences` and `scan_sources_with_occurrences` return
  `Vec<SourceScan>`, adding precise `DetectionOccurrence` mappings.
- `scan_root_detailed` and `scan_sources_detailed` accept `&DetailedEvaluationOptions`
  and return one non-exhaustive `SourceScan` per supplied or discovered source.
- `SourceScan` is an extensible, non-exhaustive struct with public fields:
  `pub source: Source`, `pub events: Vec<Event>`, `pub occurrences: Vec<DetectionOccurrence>`,
  `pub action_findings: Vec<ActionFinding>`, `pub semantic_provenance: Option<SemanticProvenance>`,
  and `pub completion: Option<EvaluationCompletion>`. Failure results produce the
  `scanner_error` event with no partial successful findings.
- These stateless scan methods do not watch, debounce, backfill, persist seen
  state/cursors/baselines, or deliver events; the host owns those lifecycle and
  durability decisions. They use a single observation clock for the batch, but
  detailed action timestamps are source-reported times only and missing source
  time is never filled with a host/scan timestamp.

### Direct record evaluation

The existing `detect_records(&Source, &[NormalizedRecord])` and
`evaluate_session(&[NormalizedRecord])` methods remain caller-supplied record
compatibility APIs:
- `Source` and `NormalizedRecord` remain directly constructible by callers and
  are passed untouched; these calls do not register a source adapter or create
  canonical acquisition facts.
- Record evaluation returns a typed `RiskAccountingError` rather than silently
  discarding failed accounting.

### Detailed action output and comparison

Detailed scanning adds immutable, constructor-sanitized DTOs, not Event 3
wire changes:
- `ActionFinding::canonical_findings()` exposes native semantic `Finding`
  identities, detector/category/severity, and optional risk points emitted from
  the authoritative `DetectorResult -> Signal -> Finding` pipeline.
- `coordinate()` returns `&ActionCoordinate`, identifying the host-facing action
  grouping. It is distinct from a native `Finding` ID.
- `promotion_score()` describes the host action contribution sum. That promotion
  score is not the native Finding risk assessment and is not the Event 3 session score.
  Keep those values and their purposes distinct.
- Finding kinds are transparently distinguished through `ActionFindingKind::Atomic`
  and `ActionFindingKind::Correlation`. Process chain evaluation is opt-in via
  `DetailedEvaluationOptions::process_chain`; it never runs a second pass or
  replays past sessions.
- Severity and risk come from detector content; stage and supporting observation
  identities retain canonical acquisition facts. `occurred_at` is source-reported
  only. Tool intent never becomes proof of operating-system execution.

Replay identity and semantic provenance provide comparison aids:
- `ReplayIdentity` (algorithm version 1) is an optional, versioned host dedup/replay
  aid, not authentication, an Event3 identity, or a durable cursor. Its framed
  semantic action preimage excludes source paths, session IDs, and source
  coordinates. Source time is required; ambiguous identical candidates within
  an acquisition have no replay identity. Preserve coordinate fallback identities
  alongside replay identities when recording excluded history: a later duplicate
  can make a previously available replay identity ambiguous. `OccurrenceId`
  remains the distinct, validated canonical coordinate. No universal identity
  across lossy sources is promised.
- Startup `Pipeline::semantic_provenance(options)` computes effective detailed
  semantic identity before acquisition so a host can compare startup configuration
  with each detailed result. It frames the effective rule fingerprint,
  `ACTION_SEMANTICS_VERSION` (2), `NATIVE_ACTION_PROFILE_VERSION` (2),
  `REPLAY_ALGORITHM_VERSION` (1), effective linked download score, and the
  `process_chain` flag/YAML. It does not hash context options, host YAML/path
  resolution, binary artifact identity, or per-event attestation. Hosts needing
  binary identity must bind the exact binary/revision separately. The existing
  producer provenance manifest (`ProducerProvenanceManifestV1`) has a different
  operational scope and is not substituted by this semantic identity.

Same-pass context extraction:
- Content disclosure switches default to false (`user_text: false`,
  `assistant_text: false`, `tool_arguments: false`). Enabling them is an explicit
  disclosure decision by the host.
- Neighbor offsets are bounded to at most 32 before and 32 after the anchor
  observation (`before <= 32`, `after <= 32`).
- Only explicitly enabled user/assistant messages and non-result tool observations
  at proposed, requested, started, or completed stages can contribute.
- The anchor observation itself is excluded from its own context (`index == anchor`).
- Tool results, imported observations, and unknown or excluded bodies are excluded.
- Extracted text is sanitized by the privacy boundary (`redact_sensitive_text`)
  before entering `ActionContextEntry` DTOs, bounding each entry to 512 bytes and
  capping total extracted context text at 32 KiB across the maximum 64 neighbor observations.
- Context extraction runs entirely in-memory over the same-pass canonical observations
  without reopening SQLite databases. Byte budgets and metadata bounds are respected.

Ordered category chains and linked downloads:
- Category chains are ordered within a 15-minute source-time window
  (`ACTION_CHAIN_WINDOW_SECONDS = 900`).
- Bundled downloaded-artifact correlation links supported download and execution
  forms; repeated meaningful linked download requires a literal artifact match,
  temporal ordering, and source time; unknown or unsupported syntax does not
  establish a link.
- Default action-only download-link promotion score is 50
  (`DEFAULT_ACTION_DOWNLOAD_LINK_SCORE`), while the frozen Event 3 compatibility
  modifier remains 35. An explicit `linked_download_score` option may override
  the action score (0–100).
- Rule-ID-only modifiers remain same-action predicates. Native precision profiles
  apply only to bundled predicates; a custom rule with the same ID uses its own
  effective matcher over action fields, never a hidden override.

Bundled rule catalog:
- `bundled_rule_catalog(options)` exposes safe immutable presentation metadata
  (`RuleCatalogEntry` items: `id`, `kind`, `title`, `explanation`, `falsepositives`,
  `category`, `severity`, `session_score`, `action_score`, `action_ordered`,
  `action_within_seconds`, `action_link`).
- Session scores describe frozen compatibility contributions; action scores
  describe individual native contributions, not host promotion totals.
- It exposes supported immutable rule metadata, not detector internals, custom
  documents, policy overrides, or an executable process AST.

### Inventory facade (current development after RC1)

The inventory facade offers host-selected collection, not an implicit machine
or workspace scan:
- `telltale_core::inventory` exposes install snapshots, signal types,
  `collect_install_inventory_with_context`, `collect_install_inventory_for_platform`,
  `collect_install_inventory_with_sources`, `snapshot_to_event`, and
  `discover_mcp_inventory(root)`.
- `InstallInventorySnapshot` is an exhaustive struct and directly constructible by
  callers (unlike `#[non_exhaustive]` signal/observation structs), preserving
  straightforward construction for caller-supplied snapshots and synthetic test fixtures.
- Prefer an explicit host-owned `InstallInventoryContext`: `current()` and
  `collect_install_inventory` read the process environment (home, PATH, extension
  roots), which may not describe the intended host roots.
- Structured inventory `Configs` and `FixedRoot` return privacy-projected safe
  DTOs: local paths are hashed (`path_hash`), URL userinfo and credentials are
  redacted (`[redacted-url]`), counts and safe identifiers are retained, and
  environment variable values and secrets are never emitted. Command basenames
  are sanitized including URL redaction; no hidden directory walks are performed.
- Collection bounds: 64 configuration candidates, 1 MiB of accepted content per
  file, a 4 MiB aggregate read budget including one-byte overrun probes, and 256
  observations plus one content-free exhaustion observation. Each read reserves
  at most 1 MiB + 1 byte, capped by the remaining budget; only successful reads
  refund unused allowance. Every failed read retains its full reservation because
  consumed bytes are unknown, including failures before content is read.
  Unsupported identities perform no reads and consume no read budget. Reduced
  remaining capacity can reject an otherwise valid file (`source_limit_exceeded`);
  exhausted collection bounds report `mcp_inventory_limit_exceeded`, never partial
  content or silently widened bounds.
- MCP configuration inspection is static and does not connect to a server.
- Codex TOML handling is a deliberately bounded single-line subset supporting
  quoted sections, environment keys, and arrays; unsupported MCP syntax produces
  an explicit unsupported observation outcome, while only unrelated multiline
  strings are skipped.
- None of this enables inventory emission in normal pipeline scans or CLI watch modes.
- Install discovery recognizes platform executable suffixes (`.exe`, `.cmd`,
  `.bat`, `.ps1`) through `InstallPlatform::Windows` platform-aware matching.
- Caller-supplied exact supported sessions (`collect_install_inventory_with_sources`)
  mark agent presence as `InstallConfidence::Partial` (historical or installed
  evidence), without discovering sources or reading contents. Discovery does not
  silently search arbitrary locations.

### OpenCode acquisition feature (current development after RC1)

The default `telltale-core` normal dependency graph has no `rusqlite`:
- Git-pinned hosts that scan OpenCode must explicitly enable `opencode-sqlite`:

```toml
telltale-core = { git = "https://github.com/Dark-Roast-Cyber/telltale", rev = "<commit>", features = ["opencode-sqlite"] }
```

- This forwards the default-off `telltale-sources/opencode-sqlite` feature, using
  pinned `rusqlite` 0.32.1. Other workspace functionality or downstream consumer
  crates may use `sqlx` 0.8.6; both bind to compatible `libsqlite3-sys` 0.30.1.
  Enabling one does not imply the other is removed.
- Without this feature, OpenCode acquisition fails closed with a per-source
  `scanner_error`; mixed scans retain successful JSONL results.
- `protected-assignment` is an independent feature and does not enable OpenCode
  acquisition.
- OpenCode investigation remains deferred with either feature setting, before
  discovery, source I/O, or process spawn.

### Canonical bound diagnostics (current development after RC1)

Codex canonical bound failures retain a typed, content-free field category and
bound dimension in `SourceFailure.acquisition`:
- `telltale_sources::acquisition::AcquisitionError` adds the public
  `CanonicalBoundValidation { context: CanonicalBoundContext }` variant.
  `CanonicalValidation { code }` remains available; both return `unbounded_value`
  for `code()` and Display.
- The optional `bound_context()` accessor returns only closed field-category and
  bound-dimension enums.
- Adding an enum variant is a Rust source compatibility break for exhaustive
  matches: downstream hosts must include a wildcard fallback arm when updating
  their git pin.
- Event 3 bytes and scanner error adaptation remain generic `canonical_acquisition_failed`,
  source-atomic, and content-free.
- See the [canonical contract](canonical-observation-v2.md) for categories,
  dimensions, unchanged limits/check order/NFC behavior, and current Codex-only scope.

### Host responsibilities and API evolution

Embedding boundaries divide responsibilities between Telltale and the host:
- Host responsibilities: watcher management, debounce timing, backlog backfill,
  ACK retry, seen state / cursor persistence, fleet coordination, and alert
  promotion remain the host application's responsibility.
- API evolution rules: audited extensible result DTOs use accessors or
  `#[non_exhaustive]`; this is not a blanket claim about every public return type.
  Non-exhaustive error matches need wildcard fallbacks and non-exhaustive struct
  patterns need `..`. `Source` and existing constructible input types are preserved;
  `LocalEventFeed` configuration, notices, and provenance are explicitly supported.
- Lower-level runtime semantics: internal modules in `telltale-detect`, `telltale-sources`,
  and `telltale-rules` are implementation foundations, not a stable third-party
  source-adapter or detector plugin ABI.
- Toolchain and verification gates:
  - `make embedding-contract-check` tests 8 feature combinations and is part
    of the canonical `ci-local` pre-push gate.
  - `make embedding-rust188-check` qualifies the explicit external supported
    subset against installed Rust 1.88.0. This qualifies only that explicit
    dependency subset, not a global CLI/workspace MSRV promise.

## Stability

For 0.7, `telltale-core::Pipeline` (including `scan_root`, `scan_sources`, its
builder, and the deliberate caller-provided `detect_records` / `evaluate_session`
compatibility methods) and the types needed to call it are the supported Rust
embedding facade. The core re-exports of `Source`, `Event`, `NormalizedRecord`, and rule
result/error types serve that facade; their presence does not promise that
every public module of the originating crate is a stable embedding API.
The current-development occurrence methods, contextual investigation,
`opencode-sqlite` feature, and `inventory` module extend this facade after RC1.
They are not covered by published RC1 qualification, and they are not a stable
0.7.0 promise without the required release qualification. Reviewing and testing
a Git pin validates that integration, not the stable release.

### Scope and non-goals

These boundaries remain intentional:

- OpenCode investigation stays deferred. There is still no read-only provider,
  and feature-off OpenCode acquisition is a per-source `scanner_error`, not a
  separate "capability not compiled" code.
- `OccurrenceId` is the exact canonical source coordinate. It is not a
  cross-session replay or semantic fingerprint. Identical coordinates in one
  resolved session fail closed as ambiguous.
- Default `telltale-core` does not compile `rusqlite`. The CLI outbox and the
  separate `protected-assignment` feature still use it when that code is built.
- These embedding additions do not change existing CLI inventory activation.
  `Pipeline` scans emit neither install/MCP inventory nor investigation context;
  CLI scan/watch does not emit investigation context. There is still no embedding
  facade for baseline state, cursors, custom process-chain configuration (only
  toggling the bundled process pack on or off via detailed options is supported),
  or event allowlists.
- This repository stays vendor-neutral. Do not add downstream product types,
  names, or behavior to the embedding API.

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

Accepted follow-up: a genuinely read-only OpenCode investigation provider remains
[Issue #42](https://github.com/Dark-Roast-Cyber/telltale/issues/42), not a capability
of this surface.

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
