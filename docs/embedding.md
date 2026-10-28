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
identity, semantic provenance, bundled rule metadata, and their versioned wire
forms: Event 3, action record v1, and rule catalog v1.

**The host owns** watchers, debounce, safety scans and backfill, enabled/disabled
lifecycle and allowlists, seen/excluded/pending state, rebaseline, ACK and retry,
fleet wire/IPC and version migration, host identity, promotion thresholds,
incident grouping, storage, rendering, inference, catalog publication, and pin
refresh. Returning a finding is not durable delivery.

### 0.7 surface classification

| Class | Surface | Meaning |
| --- | --- | --- |
| Supported | `scan_sources_detailed`, `scan_root_detailed`, `scan_source_detailed_resuming` with `ResumeToken`, `DetailedEvaluationOptions`, `SourceScan` (fields plus `failure()`, `coverage()`, `visibility_limits()`, `quarantined()`, `resume_token()`, `action_records()`), `ActionFinding` accessors (including `session_event_index()`), `ActionRecordV1`, `semantic_provenance`, `bundled_rule_catalog`, `rule_catalog_document` with `RuleCatalogV1`, `producer_provenance_manifest`, `PipelineError`, discovery helpers, `inventory`, `Event3Record`, `LocalEventFeed`, `opencode-sqlite` | The adoption path. Changes are deliberate and documented in the [migration guide](migrations/0.7.0.md). |
| Compatibility | `scan_sources`, `scan_root`, `scan_*_with_occurrences` | Session Event 3 and observation linkage for existing callers. Kept for 0.7; new integrations use detailed scans. |
| Unstable | `investigation`, `assignment` (`protected-assignment`) | Usable, but may change or be removed with notice. |
| Not an API | `canonical_runtime`, lower-level crate modules | Implementation seams, not a source-adapter, detector, or plugin ABI. |

Core re-exports such as `Source`, `Event`, and error types serve the facade; they do not make every public module of the originating
crate a stable embedding API.

### Qualification status

Published `v0.7.0-rc.2` implements the pre-v2 facade, not this whole contract.
OpenCode v2 resume, cut-window tokens, and quarantine described here are
later than RC2. Neither published RC1 nor RC2 qualifies this tree. RC2 is not a
stable API freeze or a fully qualified release (clean-host gates are pending).
A passing host test of a Git pin is integration evidence, not release
qualification. Candidate gates live in
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
part of `ci-local`. `make embedding-msrv-check` runs the same combinations on the
embedding crates' declared `rust-version` (Rust 1.85.0), which CI checks on Linux,
macOS and Windows; it is not a CLI MSRV promise. External coverage lives in
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

The builder shares the CLI's rule content, defaults, policy, and evaluation
semantics: bundled core rules plus the embedded community package
(`telltale.community`) by default. It accepts document and package strings, not
filesystem paths, and rejects duplicate IDs across documents, including bundled
defaults. It does not implement the CLI's filesystem-managed tiers, same-ID
replacement, or override files
([tier resolution](install.md#local-rule-policy-and-allowlist-config)):

```rust
let pipeline = Pipeline::builder()
    .rule_package(package_yaml)       // additive, like rule-packages.d
    .rules_document(custom_yaml)      // additive, like --rules
    .policy_document(policy_yaml)     // enable/disable, like --policy
    .build()?;
// .without_community_rules() mirrors --no-community-rules.
// .without_bundled_defaults() mirrors --no-default-rules: it drops core rules
// and the embedded community snapshot; supplied packages still load. With no
// content left, build() fails with PipelineError::InvalidConfiguration. Content
// and policy that leave no effective rule fail with PipelineError::EmptyRuleSet,
// even if scans enable process_chain (build() cannot know that).
```

A supplied package with ID `telltale.community` replaces the embedded snapshot
as a whole, so a host that distributes rule content can deliver a newer verified
community release, or its own namespaced packages, without a Telltale upgrade.
`Pipeline::rule_packages()` returns each compiled package's ID, version, content
SHA-256, and whether it is the embedded snapshot, for inventory and provenance
reporting. Package validation lives in `telltale_rules::package`
(`RulePackage::parse`, `resolve_rule_packages`); see the
[rule-packages specification](../openspec/specs/rule-packages/spec.md).

What an embedder inherits:

- **No ambient operational settings.** Telltale libraries do not read
  `settings.d` or the [operational settings](install.md#operational-settings)
  variables; the CLI resolves those. Event 3 severity bands use
  `RiskThresholds::default()` (20/50/70/90) unless the host calls
  `telltale_schema::scoring::configure_thresholds` once before scanning, and
  `ProducerProvenanceOptions::default()` holds compiled defaults. Default path
  and source discovery in `telltale-sources` still reads host variables such as
  `HOME`, `TELLTALE_LOG_PATH`, `TELLTALE_STATE_PATH`, and
  `TELLTALE_PROJECT_CONFIG`.

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
  means a bounded selection or quarantined native units left some source evidence
  unevaluated. No findings is not a clean bill of health for excluded evidence;
  a later bounded scan may not select an earlier action. Coverage is acquisition
  scope, separate from rule visibility and failed-source atomicity.
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
- `quarantined()` lists native units a successful scan excluded, as
  `QuarantinedUnit` coordinates (session, native ID, source sequence, code and,
  when the bound reports one, bound context) without content. A unit is
  excluded for an unsupported shape or an oversized or invalid value of its own.
  Claude Code and OpenCode v2 support native-unit quarantine; see the source-specific notes in
  [session sources](session-sources.md). OpenCode v2 also reports
  `evaluation_capacity_exceeded` when even the smallest window of rows exceeds
  evaluation work or projection capacity. Only OpenCode returns progress covering
  quarantined units; other units in its selected window were evaluated. Claude
  quarantine does not add a progress or resume mechanism.

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
  `Serialize`. Its wire form is `SourceScan::action_records()`; see
  [host wire and durable handoff](#host-wire-and-durable-handoff).

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
  `ACTION_SEMANTICS_VERSION` (2), the native action profile version (4),
  `REPLAY_ALGORITHM_VERSION` (1), the effective linked download score, and the
  `process_chain` switch. It does not cover context options, host path
  resolution, binary identity, or per-event attestation; bind the binary or
  revision separately. `ProducerProvenanceManifestV1` has a different scope; see
  [producer provenance](telemetry-output.md#producer--detector-provenance-manifest).
  Native profile 3 applies credential boundaries and example exclusions to the
  same token; semantic identities change from profile 2, while replay identities
  and Event 3 session semantics remain unchanged. Native profile 4 reads a wget
  flag cluster ending in `-O` (such as `-qO-`) as output to standard output when
  linking downloads, adds the `written_path` field for files a call writes,
  stops counting a shell parameter as a cloud credential read unless the command
  reads paths, and applies declared modifier links; semantic identities change
  from profile 3, and replay identities are unchanged.
  `ActionModifierSemantics::within_calls` reports a declared link's call bound.
- Identity grammar: `semantic:v1:sha256:` or `replay:v1:sha256:` followed by 64
  lowercase hex characters. Unknown future versions are contract evolution, not
  permission to invent a substitute. Golden values are pinned by tests and change
  only with a version bump.

### Replacing rule content

Rule content can change without a new Telltale build. A `Pipeline` never
changes after `build()`, so replace it as a whole:

1. Build a new `Pipeline` from the new rule and policy documents.
2. On `Err`, keep the active pipeline. Rejected or empty content
   (`Compilation`, `InvalidConfiguration`, `EmptyRuleSet`) never produces one.
3. On `Ok`, compare `semantic_provenance(&options)` with the active pipeline's,
   then swap. A different identity is a semantic rebaseline; keep admitted
   pending work across it.

Telltale does not fetch, sign, or schedule rule content. Obtaining and
authenticating documents is the host's job.

### Evidence

`action.evidence()` holds one `ActionEvidence` per rule or modifier that
counted for the action: `field()`, `rule_id()`, and `redacted_value()`, which
crossed `redact_sensitive_text` and is at most 512 bytes and 80 tokens.

- A field whose redaction fits is shown whole. A longer field is shown as an
  excerpt of about 160 bytes before and 240 after the hit that counted:
  the first match of the rule's counting matcher for a Rule v1 rule, the
  command stage that satisfied a native predicate, or, for a download link, the
  stage that runs the artifact or the piped pipeline. `elided_before()` and
  `elided_after()` say whether field text was cut on each side. Evidence
  without a single span (a whole-field predicate) starts at the field start.
- A hit past the sanitizer's 4 KiB input bound is still shown: the excerpt is
  cut from the redaction of a region around the hit. Both cuts of that region
  drop the fragment that holds them, as the input bound does, including a
  quoted value that spans the cut, so a secret that straddles a cut is never
  partly shown. A leading cut inside a private key block moves past the
  block's end. The first 256 bytes after a leading cut, in whole fragments and
  at least three of them, are redacted but never shown: a label that would
  mask them (`--password`, `key =`, `Bearer`, the start of a path with
  spaces) may lie before the cut. Evidence can therefore be empty, with
  `elided_before` set.
- `highlight()` is the UTF-8 byte range of the hit in `redacted_value()`, set
  only when the position is exact: redacting the text before, at and after the
  hit separately gives the same text. It is `None` when redaction joins the hit
  to its neighbors (a secret's label outside the hit, for example), when a
  dropped fragment holds the hit, or when the hit does not fit the bounds.
  Never infer a position from the text.
- Evidence is not reread from the source and rules are not rerun to place it.
  Event 3 evidence is unchanged.

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
`action_within_seconds`, `action_link`, `atlas_tags`, `attack_techniques`,
`package_id`) for core rules and the embedded community package; `package_id`
is `None` for core rules and `enabled` describes the default pipeline. When
`options.process_chain` is set, it also lists every rule of the bundled
process-chain pack as `RuleCatalogKind::ProcessChain` (`"process_chain"` on the
wire), with its title, reason as `explanation`, category false-positive
guidance, score before environment false-positive controls, signal type
(`chain`, `atomic` or `correlation`) and, for correlations, its window in
`action_within_seconds`. Process-chain entries carry MITRE ATT&CK technique IDs
in `attack_techniques`; Rule v1 rules and modifiers carry only `atlas_tags`. Session scores are frozen compatibility
contributions; action scores are individual native contributions, not host
promotion totals. It exposes no detector internals, custom documents, policy
overrides, or executable process AST. Like `ActionFinding`, catalog entries do
not implement `Serialize`. `rule_catalog_document(&options)` returns the same
entries as a versioned `RuleCatalogV1` document (`telltale.rule_catalog.v1`)
with the default pipeline's semantic identity; publish it to services that
render detections. Its JSON Schema is
[`schemas/rule-catalog-v1.schema.json`](../schemas/rule-catalog-v1.schema.json).

## Host wire and durable handoff

`ActionFinding` is a Rust value and deliberately does not implement
`Serialize`. Telltale's cross-process formats are explicit, versioned schemas:
Event 3 for session events, action record v1 for actions, and rule catalog v1
for presentation metadata. Hosts forward these; they do not design their own
action format.

`SourceScan::action_records()` returns one `ActionRecordV1`
(`telltale.action.v1`) per action finding, in `action_findings` order, and none
for a failed source. A record carries every accessor value (`coordinate` is
the anchor observation ID) plus the scan's `client`, `source_id`,
`source_path_hash` (as in Event 3) and `semantic_identity`, and
`session_event_id`: the `event_id` of the session Event 3 object at
`session_event_index()` in the same scan, or null. Event IDs
are fresh per scan, so that link holds only for records and events delivered
together. Every key is always serialized; absent values are null. Its JSON
Schema is [`schemas/action-record-v1.schema.json`](../schemas/action-record-v1.schema.json).

```text
host envelope { host delivery key, tenancy, transport version,
                record: ActionRecordV1 }      -- one per action
Event 3 object                                -- session events, unchanged
```

- The receiver validates with `ActionRecordV1::from_json` (in
  `telltale-schema`, no SQLite), as it validates Event 3 with `Event3Record`.
  It rejects oversized input, another record version, unknown fields, values
  outside the schema, inconsistent values, and text that redaction would
  still change, with closed error codes that contain no input text. A
  consumer whose redactor differs from its producer's may reject valid output:
  a newer consumer when redaction grew stricter, an older consumer when it
  kept more text, so move producer and consumer pins together. Do not turn an unknown
  field or version into a rejected but acknowledged delivery.
- Delivery key: `record.delivery_key()`. It hashes the semantic identity with
  `replay_identity` when present, otherwise with `source_path_hash`,
  `coordinate` and the canonical finding IDs: equal coordinates distinguish
  neither stores nor the several process-chain actions one tool call can
  carry. A rules change gives new keys. Never derive a key from Event 3 IDs.
- Delivery aliases: `record.delivery_aliases()` starts with `delivery_key()`
  and, when `replay_identity` is present, adds the source-bound key the action
  has without one. Replay identity can come and go between scans of one store:
  a later identical candidate makes an earlier action ambiguous and withdraws
  its replay identity, and a rewrite that removes the candidate restores it.
  The source-bound alias survives both transitions; the replay alias matches a
  copy of the action in another source. Treat an action as handled when any of
  its aliases is known, and remember all of them.
- Event link: `record.check_session_event(&event)` checks that a detection or
  process-chain `Event3Record` travelling with the record has the same client,
  source path hash and session and, when `session_event_id` is set, that it
  is that event, of the matching family, carrying every record rule. An
  unlinked record names no event; which event it travels with is the host's
  choice.
- A record or catalog version is frozen from the first release tag that
  carries it. After that, adding, removing or redefining a field is a new
  version and a new type; plan to accept both during a host upgrade. Before
  that tag, a Git pin can see v1 amended in place; see the
  [migration guide](migrations/0.7.0.md).
- Keep terminal Event 3 separate from host extensions: `Event3Record` consumes
  one complete terminal Event 3 object (`Event` is the producer type, not a
  deserializer), and an augmented storage document is not a strict
  `Event3Record` input. Historical Event 3 rendering stays valid.

Do not reimplement replay hashing, delivery keys, event-link checks, redaction
re-checks, occurrence matching, context rereads, YAML catalog parsing, or
parser registration in a host; the facade supersedes them.

Preserve `stage` and optional `occurred_at` through storage. If a host needs
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
| `build` | `InvalidConfiguration`, `EmptyRuleSet`, `Compilation` |
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
`pipeline_empty_rule_set`, `pipeline_invalid_options`,
`pipeline_invalid_resume_token`) without paths, configuration, or source text.
`Error::source()` keeps the original cause except for `InvalidConfiguration`,
`EmptyRuleSet`, `InvalidOptions`, and `InvalidResumeToken`. `DiscoveryError`, `RuleV1CompileError`, and `ObservationError`
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
  Every successful OpenCode scan reports `coverage() == Some(Partial)`; a
  failed scan reports `None`. Repeated unchanged
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
client, source identity, and a hash of the exact platform-native path; no path or
content). Its evaluated checkpoint is monotone. An idle complete-window resume
keeps its token; unfinished overlap can advance its separate continuation without
moving that checkpoint. Sources without history to resume from, and every JSONL
source, return `None`.

- Persist `ResumeToken::as_str()` only after durably accepting that scan's
  findings; restore it with `ResumeToken::parse`, which rejects unknown versions
  and malformed text with `ResumeTokenError`.
- A token names its coordinate: legacy part tokens keep their form, and OpenCode
  v2 stores issue `resume:v1:opencode.sqlite:session_message:` tokens. After a
  window that was cut (`resume_token()` from a scan whose v2 window did not
  hold the whole selection), they issue
  `resume:v1:opencode.sqlite:session_message_window:<checkpoint>:<cut>:<binding>`.
  Those continue strictly after the raw cut without the overlap, even when the
  cut is below the prior monotone checkpoint. Regression checks still use the
  checkpoint, not the cut. Persisting each token and scanning again drains a
  backlog; complete windows return to the overlapping form. Older
  `session_message_drain:` tokens still parse, but replay the checkpoint's
  overlap because they do not retain a trustworthy raw cut. Older readers
  reject the new coordinate. A token
  for the other schema is not applied; the scan reads that store's bootstrap
  selection and returns a token for the schema it read. A store with an
  incomplete v2 schema fails as `UnsupportedSourceSchema`
  (`unsupported_source_schema`) without a token; keep the prior token and scan
  again once the store's schema is complete.
- Token checkpoints remain nonnegative. A v2 raw cut instead preserves the
  native signed 64-bit integer `time_updated`, including negative values, and
  must not exceed its checkpoint. For example, checkpoint `0` can have an
  unfinished overlap ending at `-2`; continuing after that cut still acquires a
  row at `-1`, while a cut at `-1` continues from `0`. This is progress, not
  authorization: supplied cuts never remove row/byte admission caps, whole
  timestamp-group boundaries or checkpoint regression checks.
- Legacy part tokens, complete v2 tokens and older drain-token replays read from
  the checkpoint minus a fixed ten-minute overlap, the same policy as the CLI
  cursor. New v2 cut tokens instead use strict raw-cut continuation as described
  above. Expect actions from overlapping reads again and deduplicate with replay
  identity or source-bound coordinates. Chains whose earlier steps fall before
  the window are not reconstructed.
- Legacy resumed reads select every part at or after that lower bound, not only
  parts inside the overlap. V2 reads evaluate bounded windows and issue cut
  tokens until the selection completes.
- These resumed acquisition failures are atomic, with `coverage() == None` and
  no new token. A tokenless bootstrap is a bounded rebaseline with possible
  history gaps, not an overlap-safe rollback:

  | `failure().acquisition_error()` | Cause | Host action |
  | --- | --- | --- |
  | `BoundedSourceRead(LimitExceeded)` | Legacy: more than 25,000 selected parts. V2: one whole `time_updated` group cannot fit a bounded window; ordinary larger selections return cut windows instead. | Do not advance the token. A tokenless bootstrap may abandon unevaluated history; it does not guarantee that an oversized v2 group becomes readable. |
  | `ResumeRegressed` (`resume_regressed`) | No row in the selected schema with an integer `time_updated` at or after the token's checkpoint remains: a restored or replaced database, or newest rows deleted (ordinary session deletion or undo can do this) | Recover the source snapshot, or explicitly accept bounded tokenless rebaselining and its history gap; deduplicate repeats with replay identity or coordinates. |

  Not detected: a replaced store whose newest row is at or after the checkpoint,
  and a clock rollback while rows at or after that checkpoint remain. Rows
  written below the overlap window in those cases are not read.
- Malformed or unsupported token text fails parsing as `ResumeTokenError`;
  `PipelineError::InvalidResumeToken` rejects a parsed token that does not bind
  to this source, including an older binding. For normal recovery, restore the
  correct source/token pair or explicitly accept bounded tokenless rebaselining
  and its history gap. Rejection by an older reader during downgrade is not
  permission to discard or rewrite an unfinished token; use the rollback rules
  below.
- A token for another source or a non-resumable source returns
  `PipelineError::InvalidResumeToken` before any source I/O.

**Downgrade:** do not strip `continue_after_time_updated` while leaving
`draining: true`, or rewrite a `session_message_window:` token into an older
`session_message_drain:` token containing only the checkpoint. Older readers
then continue strictly after that checkpoint and can skip unfinished overlap.
Finish the drain with the new reader before downgrading, or restore a coordinated
earlier source/state/token snapshot (and matching accepted output). Dropping the
token and bootstrapping is not an overlap-safe rollback. See the
[migration guide](migrations/0.7.0.md#opencode-v2-changes-after-rc2).

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
  `collect_install_inventory_with_sources`, `snapshot_to_event`,
  `discover_mcp_inventory(root)` (Event 3 inventory events), and
  `discover_mcp_inventory_servers(root)` (the same discovery as structured
  `McpServerInventory` values; their `path` is host-local, so hash it before it
  leaves the host).
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
  read budget, and 256 observations plus one content-free exhaustion observation.
  Each read reserves at most 1 MiB + 1 byte, including a one-byte overrun probe,
  capped by the remaining budget. Successful reads refund unused allowance,
  including the probe. Failed reads restore the full reservation because the
  reader returns no bytes; only accepted bytes stay charged. Unsupported
  identities read nothing. Reduced capacity can reject an otherwise valid file
  (`source_limit_exceeded`) without consuming the remaining budget; exhausted
  bounds report `mcp_inventory_limit_exceeded`, never partial content.
- MCP inspection is static and never connects to a server. Codex TOML handling
  is a bounded single-line subset (quoted sections, environment keys, arrays);
  unsupported MCP syntax yields an explicit unsupported outcome, and only
  unrelated multiline strings are skipped.
- `InstallPlatform::Windows` matches `.exe`, `.com`, `.cmd`, `.bat`, and `.ps1`.
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
