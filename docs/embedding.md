# Embedding Telltale

Telltale can run inside another Rust application, such as an EDR agent, an
endpoint security tool, or an inference proxy, as an ordinary Cargo dependency.
The embedded pipeline returns findings and events as values; the host decides
where they go. Nothing in the library crates writes JSONL, talks to a SIEM, or
exits the process.

The versioned state file, sidecar locking, platform-qualified local JSONL
durability, and `migrate state` belong to the standalone CLI. Embedding hosts
own persistence and delivery while using the same analytic and event semantics.

## Contract at a glance

**Telltale owns** acquisition, canonical observations, Detection v2, action
findings, contributions, redacted evidence, same-pass context, conditional replay
identity, semantic provenance, and bundled rule metadata.

**The host owns** watchers, debounce, safety scans and backfill, enabled/disabled
lifecycle and allowlists, seen/excluded/pending state, rebaseline, ACK and retry,
fleet wire/IPC and version migration, host identity, promotion thresholds,
incident grouping, storage, rendering, inference, catalog publication, and pin
refresh. Returning a finding is not durable delivery.

### 0.7 surface classification

| Class | Surface | Meaning |
| --- | --- | --- |
| Supported | `scan_sources_detailed`, `scan_root_detailed`, `scan_source_detailed_resuming` with `ResumeToken`, `DetailedEvaluationOptions`, `SourceScan` (fields plus `failure()`, `coverage()`, `visibility_limits()`, `resume_token()`), `ActionFinding` accessors (including `session_event_index()`), `semantic_provenance`, `bundled_rule_catalog`, `producer_provenance_manifest`, `PipelineError`, discovery helpers, `inventory`, `Event3Record`, `LocalEventFeed`, `opencode-sqlite` | The adoption path. Changes are deliberate and documented in the [migration guide](migrations/0.7.0.md). |
| Compatibility | `scan_sources`, `scan_root`, `scan_*_with_occurrences` | Session Event 3 and observation linkage for existing callers. Kept for 0.7; new integrations use detailed scans. |
| Unstable | `investigation`, `assignment` (`protected-assignment`) | Usable, but may change or be removed with notice. |
| Not an API | `canonical_runtime`, lower-level crate modules | Implementation seams, not a source-adapter, detector, or plugin ABI. |

Core re-exports such as `Source`, `Event`, and error types serve the facade; they do not make every public module of the originating
crate a stable embedding API.

### Qualification status

The current untagged `0.7.0-rc.2` tree implements this contract; it is not a
stable API freeze or a qualified release. Published RC1 evidence does not cover
post-RC1 additions, and a passing host test of a Git pin is integration evidence,
not release qualification. Candidate gates live in
[release readiness](release-readiness.md#post-rc1-embedding-qualification).

## Getting the crate

| Integrator profile | Dependency | What you get |
| --- | --- | --- |
| Full pipeline in-process (EDR, security tool) | `telltale-core` | The supported facade: discover → native acquisition → canonical detection. |
| Consume or emit Telltale events (backend, analytics) | `telltale-schema` | Event model, redaction, risk thresholds, and `Event3Record` for strict terminal Event 3 consumption. |
| Evaluate the rule language inline (proxy, gateway) | `telltale-rules` | I/O-free YAML rule parsing, validation, policy merge, and regex evaluation. |
| Discover and acquire agent session stores | `telltale-sources` | Cross-platform discovery, static source definitions, canonical acquisition, install inventory. |

The crates are not on crates.io yet. Depend on `telltale-core` from Git and pin
a revision, not a branch; update the pin deliberately and rerun your tests. See
[versioning](versioning.md) and the [0.7.0 migration guide](migrations/0.7.0.md)
before upgrading.

```toml
[dependencies]
telltale-core = { git = "https://github.com/Dark-Roast-Cyber/telltale", rev = "<commit>" }
```

Default-off features:

- `opencode-sqlite`: OpenCode acquisition; see [OpenCode acquisition](#opencode-acquisition).
  The default normal dependency graph has no `rusqlite`.
- `protected-assignment`: the Linux-only assignment store; see
  [protected assignment store](#protected-assignment-store). It also links
  `rusqlite` but does not enable OpenCode acquisition.

Cargo features are additive, so another consumer in the same build can enable
either feature through feature unification.

> **Crates.io name warning:** the crates.io package named `telltale` is an
> unrelated session-types crate. Do not use it for Telltale integrations.

Consumers that already import `telltale::Pipeline` can alias the package during
migration: `telltale = { package = "telltale-core", git = "…", rev = "<commit>" }`.

Gates: `make embedding-contract-check` tests eight feature combinations and is
part of `ci-local`. `make embedding-rust188-check` qualifies this external subset
on Rust 1.88.0; it is not a CLI/workspace MSRV promise. External coverage lives in
[`tests/embedding-consumer`](../tests/embedding-consumer/tests).

## Quick start

```rust
use telltale_core::{DetailedEvaluationOptions, Pipeline, PipelineError};

fn main() -> Result<(), PipelineError> {
    // Bundled default rules. Build once and reuse: canonical semantics compile here.
    let pipeline = Pipeline::builder().build()?;
    let options = DetailedEvaluationOptions::default();
    for scan in pipeline.scan_root_detailed(std::path::Path::new("tests/fixtures/session_stores"), &options)? {
        if let Some(failure) = scan.failure() {
            eprintln!("{}: {}", scan.source.source_id, failure.code());
            continue;
        }
        for action in &scan.action_findings {
            println!("{} {} {}", action.stage().as_str(), action.severity().as_str(), action.promotion_score());
        }
    }
    Ok(())
}
```

A compile-tested example lives at `crates/telltale/examples/embed_scan.rs`
(`cargo run -p telltale-core --example embed_scan -- <session-root>`; use a
synthetic fixture root).

The builder mirrors the CLI's rule semantics. Rule documents are strings, not
paths, so the rule engine works without filesystem access:

```rust
let pipeline = Pipeline::builder()
    .rules_document(custom_yaml)      // additive, like --rules
    .policy_document(policy_yaml)     // enable/disable, like --policy
    .build()?;
// .without_bundled_defaults() mirrors --no-default-rules; with no documents
// left, build() fails with PipelineError::InvalidConfiguration.
```

What an embedder inherits:

- **Redaction stays on.** Evidence carries redacted excerpts and hashes; raw
  transcripts never appear. Do not log raw session content around the pipeline;
  see the [privacy model](privacy-model.md).
- **Deterministic, offline evaluation.** No network access at scan time; rules,
  scoring, response metadata, and timeline anchors are deterministic.
- **Vendor-neutral events.** Envelope formatting (Splunk HEC, Elastic bulk)
  belongs at the host's transport boundary.

## Detailed action scanning

This is the action API. Rule IDs, scores, evidence, and context are produced by
one authoritative canonical path (`DetectorResult -> Signal -> Finding`), not a
second detector or an Event 3 conversion loop.

### Scan methods

- `scan_sources_detailed(&sources, &options)` scans exactly the supplied `Source`
  values, with no discovery. Caller-created sources and paths stay host data.
- `scan_root_detailed(root, &options)` completes checked discovery first, then
  scans every discovered source. Discovery helpers (`discover_sources`,
  `discover_sources_best_effort`, `discover_watch_roots_for_clients`,
  `DiscoveryError`, `PathProfile`) are re-exported from core. Watch roots are
  discovery inputs, not a watcher.
- Both return one `SourceScan` per source. Scans are stateless: they do not
  watch, debounce, backfill, persist seen state, cursors, or baselines, or deliver
  anything. One observation clock covers the batch.
- `build()` compiles canonical semantics once; keep one long-lived `Pipeline`.
  Rule content that loads as Rule v1 but that canonical compilation rejects
  fails `build()` with `Compilation`, so a built `Pipeline` can always scan.
- `DetailedEvaluationOptions` holds `context` (same-pass context),
  `linked_download_score` (0–100), and `process_chain`, which opts into the
  bundled process pack in the same pass, never a second pass or a replay. There
  is no custom process pack, process-rule YAML, baseline, general cursor, or event
  allowlist API; rule policy controls rule enablement, not event allowlisting.

### Source outcome

`SourceScan` has public fields `source`, `events`, `occurrences`,
`action_findings`, `semantic_provenance`, and `completion`, plus accessors:

- `failure()` is `Some(SourceScanFailure)` exactly when the source failed. It
  carries `stage()`, an optional `acquisition_error()`, and the Event 3 `code()`;
  Debug renders closed codes only. A failed source has exactly one
  `scanner_error` event, no findings or occurrences, and `None` for
  `completion`, `coverage()`, and `semantic_provenance`. There is no partial
  success. Match on `failure()`, not on `event_type` strings.
- `coverage()` is `WholeSource` or `Partial` for a successful source. `Partial`
  (OpenCode's bounded window) means unselected history was not evaluated: no
  findings is not a clean bill of health for it, and a later scan may not select
  an earlier action. Coverage is acquisition scope, separate from rule
  visibility.
- `completion` is the closed `EvaluationCompletion` enum: `Complete` or
  `VisibilityLimited`; match variants, not Debug text. `visibility_limits()`
  names the reasons as non-exhaustive `VisibilityLimit` values with stable
  `as_str()` codes, and `VisibilityLimited` holds exactly when that set is
  non-empty. Ordinary bundled scans of timed, session-scoped sources are
  `Complete`: the Rule v1 `url` target reads URL-keyed tool arguments (see
  [Rule v1 URL target](#rule-v1-url-target)). Limits come from the source or
  options, such as missing session identity, a detector that could not evaluate
  an input, or process-chain evaluation over tool calls without source time.
  Limited evaluation still returns its successful findings.
- `resume_token()` is a position to resume a resumable source from; see
  [resuming OpenCode scans](#resuming-opencode-scans).

### Rule v1 URL target

The Rule v1 `url` target (`compat.v1.url`) is the URL-keyed top-level string
arguments of a tool call: `url`, `uri`, `href`, and `endpoint`, read from object
arguments or from an argument string that is exactly one JSON object. Command
text and tool results are their own targets and are not copied into `url`, so a
URL in a shell command matches through `command` and a URL in output through
`tool_result`. A tool call without such an argument is an evaluated absence, not
a visibility gap. The action view reads the same keys and also reads command
text as `url`, so an action can match a URL rule that the session detection does
not carry; `session_event_index()` is then `None`.

### Action findings

`ActionFinding` values are immutable and constructor-sanitized.

- `coordinate()` identifies the host-facing action group. It equals the anchor's
  canonical `observation_id()` and is distinct from native finding IDs.
- `canonical_findings()` exposes native `Finding` identities, detector, category,
  severity, and optional risk points. `finding_kind()` separates
  `ActionFindingKind::Atomic` from `Correlation`, and
  `supporting_observation_ids()` lists every supporting observation.
- Observed facts are typed: `stage()` is `ObservationStage` (for example
  `ToolProposed` or `ToolExecutionCompleted`), `kind()` is `ObservationFamily`,
  and `severity()` is `Severity`; use `as_str()` for stable labels. A requested or
  proposed tool call is never proof of operating-system execution. Native finding
  kind and `detector_kind()` remain closed string vocabularies until analyzer
  provenance is designed.
- `occurred_at()` is source-reported time only; a missing time is never filled
  with session or scan time.
- `tool_name()` keeps known built-in harness tool names (for example `Bash`,
  `Read`, `WebFetch`) readable; any other name is an opaque terminal identifier.
  Event 3 keeps its terminal identifiers unchanged. To validate a received or
  stored action tool label, check
  `telltale_schema::event::terminal_historical_tool_label(label) == label`.
  `terminal_historical_identifier("tool", …)` re-hashes readable built-in names,
  so it rejects valid action labels.
- `session_event_index()` is the index into the same `SourceScan::events` of
  the Event 3 event projected for this action: the session's Rule v1 detection
  when it carries every rule of a Rule v1 action, or the `process_chain` event
  from the same result (including its dedupe key) for a process-chain action. It
  is `None` when no such event was projected (for example, a suppressed process
  result or an action-only rule match) or the link would be ambiguous. Use it
  instead of matching session identifiers.
- `ActionFinding` and its parts implement `Debug`, `Clone`, and `Eq`, not
  `Serialize`; see [host wire and durable handoff](#host-wire-and-durable-handoff).

### Scores, chains, and linked downloads

Three scores exist and must stay distinct: native finding risk
(`risk_points()`), the action `promotion_score()` (the sum of the action's
`contributions()`), and the Event 3 session `risk_score`.

- Category chains are ordered within a 15-minute source-time window
  (`ACTION_CHAIN_WINDOW_SECONDS = 900`).
- The bundled downloaded-artifact correlation links supported download and
  execution forms. A link needs a literal artifact match, temporal order, and
  source time; unknown or unsupported syntax establishes no link.
- The default action link contribution is 50
  (`DEFAULT_ACTION_DOWNLOAD_LINK_SCORE`); the frozen Event 3 session modifier
  stays 35. `linked_download_score` overrides only the action score.
- Rule-ID-only modifiers remain same-action predicates. Native precision profiles
  apply only to bundled predicates; a custom rule with the same ID uses its own
  matcher, never a hidden override.
- Enabling `process_chain` can add Event 3 events without changing the Event 3
  schema; output equality holds only for equivalent processing configuration.

### Replay identity and semantic provenance

- `replay_identity()` (algorithm version 1) is an optional host dedup aid, not
  authentication, an Event 3 identity, or a cursor. Its framed preimage excludes
  source paths, session IDs, and coordinates and requires source time. It is
  absent without source time or when identical candidates in one acquisition are
  ambiguous; a later duplicate can withdraw a previously present identity.
  Continuation or coordinate rewrite preserves it only when the preimage and
  source time are preserved. Never invent a substitute.
- Always keep the coordinate fallback, bound to exact source identity:
  identical canonical coordinates do not distinguish stores. No universal
  identity across lossy sources is promised.
- `Pipeline::semantic_provenance(&options)` computes the effective semantic
  identity before acquisition, for comparison with each result's
  `semantic_provenance`. It frames the effective rule fingerprint,
  `ACTION_SEMANTICS_VERSION` (2), the native action profile version (2),
  `REPLAY_ALGORITHM_VERSION` (1), the effective linked download score, and the
  `process_chain` switch. It does not cover context options, host path
  resolution, binary identity, or per-event attestation; bind the binary or
  revision separately. `ProducerProvenanceManifestV1` has a different scope; see
  [producer provenance](telemetry-output.md#producer--detector-provenance-manifest).
- Identity grammar: `semantic:v1:sha256:` or `replay:v1:sha256:` followed by 64
  lowercase hex characters. Unknown future versions are contract evolution, not
  permission to invent a substitute. Golden values are pinned by tests and change
  only with a version bump.

### Same-pass context

`action.context()` is scan-time context from the same acquired observations; it
never reopens a source.

- Disclosure switches `user_text`, `assistant_text`, and `tool_arguments` default
  to false; enabling them is an explicit host decision. They do not change
  semantic provenance.
- `before` and `after` are each at most 32 neighbors.
- Only enabled user/assistant messages and non-result tool observations at
  proposed, requested, started, or completed stages contribute. The anchor, tool
  results, imported observations, and unknown bodies are excluded.
- Each entry has `offset()`, typed `kind()` (`ActionContextKind`), observed
  `stage()`, optional `occurred_at()` and `tool_name()`, and `redacted_text()`.
  Text crosses `redact_sensitive_text`; each entry is at most 512 bytes and all
  context text at most 32 KiB.

### Bundled rule catalog

`bundled_rule_catalog(&options)` returns immutable presentation metadata
(`RuleCatalogEntry`: `id`, `kind`, `title`, `explanation`, `falsepositives`,
`category`, `severity`, `session_score`, `action_score`, `action_ordered`,
`action_within_seconds`, `action_link`). Session scores are frozen compatibility
contributions; action scores are individual native contributions, not host
promotion totals. It exposes no detector internals, custom documents, policy
overrides, or executable process AST. Like `ActionFinding`, catalog entries do
not implement `Serialize`; project accessors into the host's own catalog
document.

## Host wire and durable handoff

`ActionFinding` is a Rust value. It deliberately does not implement `Serialize`:
Telltale's cross-process formats are explicit, versioned schemas (Event 3 today),
never the derive output of a facade struct. For independently versioned host
components, project the needed accessors into a host-owned, versioned envelope and
validate it at the receiving boundary. Read delivery identity from accessors
(`coordinate()`, `replay_identity()`), never back out of serialized field names.
Do not turn an unknown field or version into a rejected but acknowledged
delivery. Keep terminal Event 3 separate from host extensions: `Event3Record`
consumes one complete terminal Event 3 object (`Event` is the producer type, not
a deserializer), and an augmented storage document is not a strict
`Event3Record` input. Historical Event 3 rendering stays valid.

Do not reimplement replay hashing, occurrence matching, context rereads, YAML
catalog parsing, or parser registration in a host; the facade supersedes them.

Preserve stage and optional source time through that projection. If a host needs
an observation-time fallback for indexing, label that basis instead of presenting
it as action time. Session-wide guidance and confidence are not action-specific.

Durable delivery needs more than a successful scan or queue send: acknowledge
durable retention, distinguish rejection from acceptance, and retain recoverable
downstream work before retiring the sender's pending copy. Identity alone cannot
rebuild a payload after source deletion, mutation, or movement outside a selected
window. Bound pending counts and bytes, make retries idempotent, and test restart
and capacity recovery with the actual host storage and transport. The CLI's
outbox guarantees do not transfer to an embedding host.

## Typed pipeline errors

`build` and the scan methods return `PipelineError`, a `#[non_exhaustive]` enum:

| Operation | Returned categories |
| --- | --- |
| `build` | `InvalidConfiguration`, `Compilation` |
| `scan_root`, `scan_root_with_occurrences` | `Discovery`, `Clock`, `Observation` |
| `scan_sources`, `scan_sources_with_occurrences` | `Clock`, `Observation` |
| detailed scans and `semantic_provenance` | the matching scan categories, plus `InvalidOptions`, and `Compilation` only if the bundled process pack fails to load when `process_chain` is set |
| `scan_source_detailed_resuming` | `Clock`, `Observation`, `InvalidOptions`, `InvalidResumeToken`, and the detailed `Compilation` case |

`Observation` is batch observation-time validation, not per-source canonical
validation. Clock validation runs even for an empty batch. Source-processing
failures are per-source `scanner_error` events
(see [source outcome](#source-outcome)), not returned errors.

Display and Debug render closed codes (`pipeline_discovery_failed`,
`pipeline_clock_failed`, `pipeline_observation_failed`,
`pipeline_compilation_failed`, `pipeline_no_rule_documents`,
`pipeline_invalid_options`) without paths, configuration, or source text.
`Error::source()` keeps the original cause except for `InvalidConfiguration` and
`InvalidOptions`. `DiscoveryError`, `RuleV1CompileError`, and `ObservationError`
are re-exported from core. `Compilation`'s boxed cause is not a supported subtype
taxonomy; do not parse strings to classify failures.

```rust,no_run
use telltale_core::{Pipeline, PipelineError};

let pipeline = Pipeline::builder().build()?;
match pipeline.scan_root(std::path::Path::new("/synthetic/session-root")) {
    Ok(events) => { /* host owns event handling */ }
    Err(PipelineError::Discovery(cause)) => eprintln!("{cause}"),
    Err(error) => return Err(error),
}
# Ok::<(), PipelineError>(())
```

Host entrypoints can keep `Box<dyn Error>` and use `?`.

## OpenCode acquisition

Enable `opencode-sqlite` only when scanning OpenCode:

```toml
telltale-core = { git = "https://github.com/Dark-Roast-Cyber/telltale", rev = "<commit>", features = ["opencode-sqlite"] }
```

- It forwards `telltale-sources/opencode-sqlite` and uses pinned `rusqlite`
  0.32.1. Hosts may also use SQLx 0.8.6; both bind to `libsqlite3-sys` 0.30.1.
- Without the feature, OpenCode fails closed per source with no source I/O:
  `failure()` reports `AcquisitionError::CapabilityNotCompiled`
  (`capability_not_compiled`), while Event 3 keeps the generic
  `canonical_acquisition_failed` code. Mixed scans keep JSONL successes.
- Without a resume token, an embedded scan evaluates OpenCode's bounded recent
  selection (see [limits](opencode-live-ingestion.md#failure-recovery-and-coverage)).
  Every OpenCode scan reports `coverage() == Some(Partial)`. Repeated unchanged
  input has stable action semantics with fresh Event 3 IDs and materialization
  clocks. `PartialSource` accounting never installs a whole-source baseline.
- CLI scan/watch aggregates also describe bounded selected windows, not
  cumulative snapshots or exactly-once actions: bootstrap-to-incremental
  selection can re-emit changed evidence on an unchanged store. Do not count
  fresh aggregate event IDs as new actions.
- OpenCode investigation is deferred with either feature setting, before
  discovery, source I/O, or process spawn; a read-only provider is
  [Issue #42](https://github.com/Dark-Roast-Cyber/telltale/issues/42).

### Resuming OpenCode scans

`Pipeline::scan_source_detailed_resuming(source, resume, options)` is a detailed
scan of one source. A successful `opencode.sqlite` scan returns
`resume_token()`: an opaque, versioned `ResumeToken` bound to that source (by
client, source identity, and the Event 3 source path hash; no path or content).
It is monotone and never earlier than the token the scan resumed from. Sources
without part history to resume from, and every JSONL source, return `None`.

- Persist `ResumeToken::as_str()` only after durably accepting that scan's
  findings; restore it with `ResumeToken::parse`, which rejects unknown versions
  and malformed text with `ResumeTokenError`.
- A resumed scan reads parts updated since the token's high-water minus a fixed
  ten-minute overlap, the same policy as the CLI cursor. Expect actions from the
  overlap again and deduplicate with replay identity or source-bound coordinates.
  Chains whose earlier steps fall before the window are not reconstructed.
- A resumed read that selects more than 25,000 parts fails with
  `AcquisitionError::BoundedSourceRead(LimitExceeded)` and no new token. Drop the
  token and scan without one; history between the two reads stays unevaluated.
- A token for another source or a non-resumable source returns
  `PipelineError::InvalidResumeToken` before any source I/O.

## Canonical bound diagnostics

Codex canonical bound failures keep a typed, content-free field category and
bound dimension: `AcquisitionError::CanonicalBoundValidation { context }`, read
through `bound_context()` (absence means no bound diagnostic, not success).
`CanonicalValidation { code }` remains; both return `unbounded_value` from
`code()` and Display, and Debug holds only closed enums. Native accounting errors
keep their own codes. Event 3 adaptation stays the generic, source-atomic,
content-free `canonical_acquisition_failed`. `AcquisitionError`,
`BoundedReadError`, and `CanonicalBoundContext` are re-exported from core; adding
variants breaks exhaustive matches, so keep a wildcard arm. Limits, check order,
and NFC behavior are in [Canonical Observation v2](canonical-observation-v2.md).

## Inventory

`telltale_core::inventory` collects only what the host selects; nothing is
emitted by scans or CLI watch.

- API: install snapshots and signal types,
  `collect_install_inventory_with_context`, `collect_install_inventory_for_platform`,
  `collect_install_inventory_with_sources`, `snapshot_to_event`, and
  `discover_mcp_inventory(root)`.
- Prefer an explicit `InstallInventoryContext`; `current()` and
  `collect_install_inventory` read the process environment (home, PATH, extension
  roots), which may not describe the intended host roots.
- `InstallInventorySnapshot` is exhaustive and directly constructible, unlike the
  `#[non_exhaustive]` signal and observation structs.
- Projections are privacy-safe: local paths are hashed (`path_hash`), URL
  userinfo and credentials become `[redacted-url]`, command basenames are
  sanitized, and environment values and secrets are never emitted. No hidden
  directory walks.
- Bounds: 64 configuration candidates, 1 MiB accepted per file, a 4 MiB aggregate
  read budget including one-byte overrun probes, and 256 observations plus one
  content-free exhaustion observation. Each read reserves at most 1 MiB + 1 byte,
  capped by the remaining budget; only successful reads refund unused allowance,
  and failed reads keep their full reservation. Unsupported identities read
  nothing. Reduced capacity can reject an otherwise valid file
  (`source_limit_exceeded`); exhausted bounds report
  `mcp_inventory_limit_exceeded`, never partial content.
- MCP inspection is static and never connects to a server. Codex TOML handling
  is a bounded single-line subset (quoted sections, environment keys, arrays);
  unsupported MCP syntax yields an explicit unsupported outcome, and only
  unrelated multiline strings are skipped.
- `InstallPlatform::Windows` matches `.exe`, `.cmd`, `.bat`, and `.ps1`.
  `collect_install_inventory_with_sources` marks agents present from exact
  supported sources as `InstallConfidence::Partial`, without reading contents.

## Compatibility and unstable surfaces

### Session Event 3 scans

`scan_root` and `scan_sources` return the session-scoped Event 3
detection/activity projection, equal to CLI output for equivalent source, rule,
policy, and processing options. They keep `timeline_anchors` rather than
per-action events and map source failures to `scanner_error`. Removed parser
registration and source-backed flat-record projection are not compatibility
paths. The runtime behind them is a private seam; see the
[canonical runtime boundary](canonical-observation-v2.md#shared-canonical-source-runtime).

### Detection occurrences

`scan_*_with_occurrences` return `SourceScan` with the same session events plus
`DetectionOccurrence` values from the same pass; `action_findings` stays empty.
Occurrences are observation linkage, not the action API.

- An occurrence is a canonical observation supporting a finding, not a per-rule
  match or another Event 3 event. `finding_index` points into that result's
  `events`. Session detections have one occurrence per `timeline_anchors` entry,
  with the same timeline index, rule IDs (including triggered modifiers),
  categories, and selector-derived evidence field names. Activity and MCP events
  have none.
- `OccurrenceId::as_str()` is the validated `obs:v2:sha256:<64 hex>` observation
  ID. Its coordinate tuple is adapter type and ID, coordinate kind and value,
  family, stage, and child ordinal; content, paths, timestamps, titles, and clocks
  are excluded. Re-scanning stable coordinates keeps the identity even when event
  IDs change; identical text at different coordinates differs. It is not
  authentication or an immutable-history claim. Unchecked strings cannot build an
  `OccurrenceId`; invalid projected IDs fail the source closed. Event 3's
  `canonical_observation_id` evidence may redact the snippet; its evidence hash
  still links to the full ID.
- `occurred_at` is source time or `None`. Sources without stable coordinates fail
  acquisition with `replay_unverifiable`; these scans never mint ephemeral
  identities or use the assignment store.
- Process-chain projection emits one occurrence per supporting observation.
  Timeline indexes are kept only when evaluation retained the exact ID/index
  association; otherwise `None`. Only single-observation findings keep a source
  timestamp. Evidence field names are empty (no Rule v1 selector).
- Occurrences carry no prompts, tool output, paths, credentials, command lines,
  excerpts, or raw-value hashes. `session_id` matches the in-memory Event.

### Contextual investigation

`investigation::SessionInvestigator::investigate_context` is an opt-in,
read-only, present-day reread around `ContextAnchor::Occurrence(OccurrenceId)` or
`ContextAnchor::TimelineIndex(usize)`, given a `ContextInvestigationRequest`
(consumed `Event3Record`, anchor, `before`, `after`, `ContextContent`). It is
separate from same-pass context; `investigate` stays content-free, and neither
`Pipeline` nor CLI scan/watch calls it.

- Content switches default to false. Only user/assistant messages, non-result tool
  observations, and structural entries are kept; tool results, system/developer/
  tool messages, raw objects, paths, observation IDs, and evidence are excluded.
  Text comes from message content and text parts or canonical tool arguments
  (adapter-searchable arguments as fallback) and crosses
  `redact_sensitive_text`. Labels and links reuse the content-free timeline
  projection; a link may point outside the returned entries.
- Each radius is at most 32, validated before I/O. Stored redacted text is at most
  16,384 bytes; on exhaustion the farthest neighbors lose text first (higher
  index first on ties), keeping structure and anchor text. An excluded anchor,
  including a tool result, still yields `Found`, possibly empty.
- Resolution uses the exact source/session boundary of `investigate`. Occurrence
  anchors match the exact `observation_id`; zero or multiple matches return
  `occurrence_absent` or `ambiguous_occurrence`, with no fallback. A timeline index
  is today's order, not proof that history is unchanged; out of range returns
  `timeline_index_absent`. OpenCode is deferred.

### Removed record evaluation

`detect_records` and `evaluate_session` (Rule v1 over caller-built
`NormalizedRecord`s) and the core re-exports used only by them are removed.
Evaluate native session sources with detailed scans instead; synthetic tests can
write a small native fixture (for example Codex JSONL) and scan it with
`scan_sources_detailed`.

### Protected assignment store

`telltale_core::assignment` compiles only with `protected-assignment`. It is
Linux-only and fails closed elsewhere, keeps its store format and replay/privacy
guarantees, and is not used by scans, watch, or adapter projection. See the
[core README](../crates/telltale/README.md#protected-assignment-optional) for
replay-association requirements and limits.

## Out-of-process path

`Pipeline` yields values; the public out-of-process path is terminal Event 3 →
durable JSONL → a future vendor-neutral local collector transport. Event 3 is
independent of transport: sink identity, transport, delivery policy, and
persistence role are separate, a local IPC transport may be `BestEffort`, and a
durable transport need not be HTTP. Issue #26 defines no collector protocol or
plugin ABI and does not change Event 3; Issue #28 remains deferred, and JSONL-only
is not its final architecture. `LocalEventFeed` supports bounded read-only polling
of local Event 3 JSONL; see
[telemetry/output](telemetry-output.md#runtime-neutral-local-journal-polling).
Analyzer extensions are a separate future protocol; see
[development principles](development-principles.md#analyzer-extensions-direction-not-implemented).

## Rust API evolution

- `PipelineError`, `SourceScan`, `ActionFinding`, `ActionFindingKind`,
  `VisibilityLimit`, and the other action DTOs are `#[non_exhaustive]`: use
  wildcard arms, struct rest patterns, or accessors. `EvaluationCompletion` is a
  deliberately closed two-variant enum. Constructible inputs such as `Source` and
  `InstallInventorySnapshot` stay exhaustive.
- Other public APIs in `telltale-schema`, `telltale-sources`, `telltale-detect`,
  and `telltale-rules` are usable foundations without a blanket compatibility
  promise. Canonical Observation v2 and Detection v2 are semantic contracts, not a
  source-adapter or detector plugin ABI. Rule v1 documents remain supported
  content regardless of the `telltale-rules` Rust API.
- `telltale-detect` works without source I/O when its default `source-io` feature
  is disabled.
- Public visibility alone does not authorize removing these modules or weakening
  their behavior. If you need a lower-level API stabilized, open an issue first.

This repository stays vendor-neutral: downstream product types, names, or
behavior do not belong in the embedding API.
