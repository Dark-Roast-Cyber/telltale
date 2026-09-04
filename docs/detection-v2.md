# Detection v2

> **Status:** **Experimental foundation implemented (non-production).** The
> `telltale_detect::v2` module implements only the `observation_match` detector,
> `DetectorResult` -> `Signal` -> atomic `Finding`, and the Rule v1 compiler.
> It is not the current engine. There is no shadow path, activation path,
> advanced detector runtime, or Detection Content v2 loader. **Existing
> compatibility:** Event 3.0 remains the current frozen external compatibility
> and output contract.

The current Rule v1, process-chain, and Event3 scoring behavior remains documented
in [Detection model](detection-model.md). This page describes the accepted future
model and identifies the small non-production foundation that is implemented.

## Detection path and units

```text
Canonical Observation
    ↓
DetectorResult
    ↓
Signal
    ↓
Finding
```

An Observation is the unit of evidence. A Signal is the unit of detection. A
Finding is the unit of security meaning. A session is a primary correlation
boundary when a meaningful session ID exists, not a detection unit. One
observation may produce multiple signals, and one Finding may be supported by
multiple signals. Detection has no policy or enforcement authority.

## Bounded detector taxonomy

The initial detector kinds are deliberately limited:

| Kind | Contract |
| --- | --- |
| `observation_match` | A text or structured match over canonical fields/facets, with explicit applicability and `where`. |
| `process_chain` | Specialized parent/child, standalone, or entity-correlation process matching; it does not reuse generic `where` or sequence steps. |
| `sequence` | Ordered steps over one declared input stream. |
| `correlation` | Unordered co-occurrence steps over one declared input stream. |
| `imported` | External detector-result normalization with lineage and observation linkage. |

`baseline` and `guard_model` are reserved, not active detector implementations.
The reserved `baseline` kind does not change frozen Event 3.0: current Event
3.0 baseline-deviation activity events remain unchanged, and Event 3.0 does not
gain Detection v2 baseline semantics. A guard model may
enter only through DetectorResult/imported normalization and never gains
Decision or Action authority. `classifier` is not a kind; future model content
uses `guard_model`. `external` is not a kind; imported results use `imported`.
Unknown kinds are rejected.

The implementation activates only `observation_match`. Process-chain,
sequence, correlation, imported, baseline, and guard-model behavior remains
reserved architecture and is not runtime-supported by this foundation.

## DetectorResult

Every detector invocation converges on a detector-neutral DetectorResult. Its
common contract includes:

- detector kind, stable ID, optional version/engine/content reference, and
  optional `rule_version: 1`;
- exactly one evaluation status;
- a required non-evaluation reason when applicable;
- supporting `observation_ids` (empty is allowed for non-evaluated/error);
- finding kind, category, severity, optional declared risk contribution,
  confidence, tags, and techniques;
- bounded evidence references, capability/evaluation context, declared
  correlation scope, optional deduplication key, and privacy-safe diagnostics.

Evaluation status is exactly:

```text
evaluated_match | evaluated_no_match | not_applicable |
not_evaluated | detector_error
```

`not_evaluated` requires exactly one of:

```text
insufficient_visibility | required_capability_unsupported |
required_capability_unknown | missing_ordering_field |
missing_correlation_key | type_mismatch | ineligible_input
```

Unsupported or unknown required capability is never `evaluated_no_match`.
Supported means only that a source can provide a fact if it occurs. Absence is
not negative truth. `exists` and `not_exists` inspect field presence and cannot
turn unsupported or unknown visibility into a clean claim. A wrong type,
missing ordering field, or missing correlation key is non-evaluation, not a
fabricated match. `not_applicable` means the detector does not apply to the
family/stage. `detector_error` identifies compile or evaluation failure.
Downstream risk must not treat non-evaluation or errors as benign. Only
`evaluated_match` materializes a Signal by default.

## Signal

Signal is internal by default and is not an Event4 body. Its identity is
distinct from observation, Finding, and Event4 identities:

```text
sig:v2:sha256:<64 lowercase hex digits>
```

Signal identity uses domain-separated canonical UTF-8 JSON containing detector
identity, sorted observation IDs, semantic identity or dedupe key, evaluation
status, and a digest of matched selector paths. Values and raw evidence do not
enter the selector digest. Replay of the same tuple yields the same Signal ID;
changing an observation ID changes it.

A Signal links detector and observations, retains session scope when known,
finding kind/category/severity, optional declared risk and confidence, evidence
references, tags/techniques, and explicit suppression/deduplication state. It is
not a duplicate Finding and does not carry policy/action or Event4 projection
fields.

## Finding and deterministic grouping

Finding is the internal security-meaning object. It is distinct from Decision
and Action and has a separate internal identity:

```text
fnd:v2:sha256:<64 lowercase hex digits>
```

The default atomic identity is one evaluated-match Signal:

```json
["telltale:detection-v2-finding", 1, "atomic", signal_id]
```

Grouped findings are allowed only when content declares a bounded
`finding_identity_key`, or when a sequence, correlation, or process-chain
detector emits one. The key uses opaque identity tokens such as `session_id`,
`call_id`, `process_instance_id`, `workflow_id`, `resource_identity`,
`destination_identity`, `observation_id`, `signal_id`, `window_start`,
`detector.id`, or `rule.id`, separated by `+`. A missing or disagreeing value
makes grouping ineligible; no key is invented. Category alone never groups.

Grouping preserves detector, Signal, and observation provenance. Affected entity
types are bounded to session, process instance, resource, network destination,
tool, model provider, and credential class. Entity identity is a safe ID or
fingerprint, never a raw path, URL, command, or universal asset graph.

## Canonical selectors and matcher grammar

The implemented registry contains exactly 48 native selectors and eight
`compat.v1` views. Native selectors are admitted only when backed by a typed
Canonical Observation field/accessor, a deterministic derived view, or one of
the explicitly governed facets. A namespace permission alone does not make a
facet selectable.

| Backing | Count | Selectors |
| --- | ---: | --- |
| Direct | 2 | `session.id`, `tool.call_id` |
| Typed | 37 | `message.role`, `message.content`; `tool.name`, `tool.arguments`, `tool.searchable_arguments`, `tool.result`, `tool.searchable_result`, `tool.reported_status`, `tool.is_error`, `tool.exit_code`; `resource.operation`, `resource.path_class`; `network.domain`, `network.destination_class`, `network.operation`, `network.port`, `network.protocol`; `process.name`, `process.pid`, `process.instance_id`, `process.privilege`; `inference.provider`, `inference.requested_model`, `inference.resolved_model`, `inference.streaming`, `inference.stop_reason`; `mcp.server.id`, `mcp.server.transport`, `mcp.server.location_class`, `mcp.tool.name`; `runtime.execution_mode`, `runtime.isolation.state`, `runtime.privilege`, `runtime.workspace.class`; `browser.surface`, `browser.origin_class`, `browser.navigation_id` |
| Derived | 7 | `message.text`, `tool.stage`, `tool.arguments.text`, `tool.arguments.keys`, `tool.result.text`, `tool.result.is_error`, `tool.result.exit_code` |
| Governed facet | 2 | `command.text`, `resource.path` |

`resource.operation` and `resource.path_class` resolve typed `File` body
accessors (`file.operation` and `file.path_class`); they do not authorize
arbitrary facets. The native namespace counts are: `session` 1, `message` 3,
`tool` 15, `command` 1, `resource` 3, `network` 5, `process` 4,
`inference` 5, `mcp` 4, `runtime` 4, and `browser` 3.

The `Derived` backing category describes deterministic selector views; it does
not by itself change fact provenance. The scalar aliases `message.text`,
`tool.arguments.text`, and `tool.result.text` preserve the metadata and
provenance of the canonical scalar fact they expose, including a searchable
fact when that is selected. The same applies to the scalar result aliases
`tool.result.is_error` and `tool.result.exit_code`. Manufactured values such
as `tool.stage` use `derived` provenance and are absent outside their owning
family. `tool.arguments.keys` is a deterministic manufactured key list and
always uses `derived` provenance.

Selectors target governed Canonical Observation fields and facets in these
namespaces:

```text
session.* message.* tool.* command.* resource.* network.*
process.* inference.* mcp.* runtime.* browser.*
```

Source-native keys are not selectors. `actor.*` and flattened aliases such as
invented `file_path` or URL-as-content fields are not canonical. A selector may
require fact provenance (`reported`, `parsed`, `derived`, `inferred`, or
`observed`) and/or a capability. Parsed URL facts cannot satisfy an observed
network selector. Registered local structured values require explicit inspection
and privacy permission.

`observation_match` has only these operators:

```text
equals, not_equals, contains, regex, glob, exists, not_exists,
in, not_in, starts_with, ends_with, gt, gte, lt, lte
```

Boolean composition is recursive `all`, `any`, and `not`; `not` wraps exactly one
matcher. Empty groups, unknown selectors/operators, undocumented query
features, and ambiguous matcher forms are rejected. String operators require
strings; `in` and `not_in` use string fields with a string or array of strings;
numeric comparisons require finite numbers; boolean fields accept booleans for
equality; presence operators take no value.

Required capabilities from the detector and all recursive matcher branches are
preflighted before evaluation. Provenance eligibility is checked before every
operator, including presence operators. A typed mismatch is non-evaluation. A
valid regex is compiled before evaluation; invalid content is `detector_error`,
not a type mismatch. The matcher status algebra is `match`, `no_match`, or
`not_evaluated`; `not_evaluated` is never inverted into a clean match.

The eight compatibility views are exact and remain separate from native
selectors: `arguments` uses searchable or string tool arguments,
`assistant_context` and `user_context` use role-specific message content,
`command` uses `command.text`, `file_path` uses `resource.path`, `tool_name`
uses the typed tool name, and `tool_result` uses searchable or string result
content. `url` is compiler-supported as `compat.v1.url` but resolves truthfully
absent; it does not manufacture URL, path, or network facts. All tool-side
compatibility views require `ToolCall`, not `ToolExecution`. The URL visibility
gap and its compatibility impact are deferred to P13 measurement.

## Sequence, correlation, and process declarations

Every sequence and correlation declares exactly one input stream:
`observations`, `signals`, or `findings`; one ordering field from
`occurred_at`, `observed_at`, `source.sequence`, `source.offset`, or
`observation.sequence`; one or more bounded correlation keys; a positive bounded
window; steps; deduplication; and `emits.result: signal_then_finding`.

The allowed correlation keys are `session_id`, `call_id`,
`process_instance_id`, `workflow_id`, `resource_identity`, and
`destination_identity`. Missing selected ordering or key data is
`not_evaluated`, with no time fallback. Eligible items are partitioned by the
declared keys, and an item with a missing or null key cannot join another
partition. Ties are deterministic by the relevant observation, Signal, or
Finding ID. Linked stream context must resolve to one unambiguous value; raw
evidence is not reparsed to choose one.

A sequence consumes distinct input items in declared order. A correlation
consumes distinct input items in any order. Overlapping windows choose the
earliest satisfying start, and later completions with the same dedupe key are
duplicates. Process chains use their specialized `parent_child`, `standalone`,
or ordered `entity_correlation` shape and converge through DetectorResult.

## Suppression, deduplication, and risk

Suppression and deduplication are separate, and neither is telemetry export
throttling. Suppression may control detector, Signal, or Finding materialization
but never deletes a Canonical Observation. It is scoped, deterministic,
explainable, and testable. Export suppression is a later telemetry concern.

Deduplication prevents equivalent semantic outputs using one of
`per_input`, `per_window`, `per_session_detector`, or `none`. It is never
category-only. Dedupe keys use bounded opaque IDs, canonical correlation
identities, window start, and detector/rule IDs; raw prompts, arguments, paths,
URLs, commands, and result values are invalid key material.

`risk_points` is an optional integer contribution in `0..100`, declared by
detector content. It is not inferred from inputs and is never implicitly summed.
Atomic Finding risk copies the one DetectorResult/Signal contribution;
sequence/correlation/process-chain Finding risk is the emitting detector's
declared contribution. Contribution identity and dedupe prevent replay from
inflating it. Severity (`informational`, `low`, `medium`, `high`, `critical`),
risk, and confidence (`low`, `medium`, `high`, optionally a `0..1` score) are
independent.

No session, entity, or workflow aggregate risk contract is accepted. Event4 may
project one declared Finding contribution as `risk_points`, but aggregate names
such as `risk_score`, `aggregate_risk`, and `aggregate_risk_points` remain
rejected. Event3's existing sum and thresholds remain compatibility-only.

## Evidence, Rule v1, and imported results

Evidence is a reference or bounded hint: a canonical field reference, hash,
classification, local structured-value reference, correlation/timeline ID, or
safe derived excerpt. It never copies raw evidence, and terminal telemetry
privacy always wins. Diagnostics contain bounded codes, not prompts, arguments,
paths, URLs, secrets, or source records.

The compatibility path is:

```text
Rule v1 -> compatibility compiler/adapter -> Detection v2 IR -> DetectorResult
```

The eight stable v1 targets remain exactly `arguments`, `assistant_context`,
`command`, `file_path`, `tool_name`, `tool_result`, `url`, and `user_context`.
The compiler copies effective Rule v1 IDs, metadata, scores, and compiled
target/regex matchers into non-production observation-match detector
definitions with `rule_version: 1`; IDs are not renamed. Modifiers remain
non-executing compatibility plans. This compiler does not implement Rule v1
allowlist or suppression behavior, existing scoring/evaluation equivalence, or
Event3 projection/equivalence. Native v2 selectors are observation-scoped,
preserve absence, and do not treat parsed paths or URLs as observed side
effects. `url` remains compiler-supported as `compat.v1.url`, but it resolves
truthfully absent until P13 measures URL visibility and compatibility impact.
Results without a lossless Event3 mapping are not projected by this foundation;
future Event4 handling is outside this scope.

Imported detectors normalize external results with source/version, confidence
semantics, evidence lineage, and observation linkage. Imported results cannot
bypass provenance, privacy, risk, policy, or action boundaries. No imported
detector has Decision or Action authority.

See the [Detection Content v2 draft schema](../schemas/detection-content-v2-draft.schema.json)
(**architecture draft / not runtime-supported**) for the bounded content shape.

## Compatibility

> **Event 3.0: FROZEN / CURRENT COMPATIBILITY CONTRACT**

The foundation is not currently wired into production or running in the
scanner. Event3 remains supported and unchanged:
its Rule v1 IDs, deterministic scoring, thresholds, parser ownership, privacy,
and persisted/replayed bytes remain current. Event4 is independently versioned
and does not replace Event3 until explicit migration gates pass. Future semantics
are not backported. Event3 and Event4 are independent projections from common
accepted internal semantics, not conversions of one another.
