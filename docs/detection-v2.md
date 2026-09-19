# Detection v2

> **Status:** **Experimental foundation and fixture-only shadow harness
> implemented (non-production).** The `telltale_detect::v2` module implements
> `observation_match`, bounded Tool-derived parent/child and standalone
> `process_chain` evaluation, caller-grouped process-chain session suppression
> and the six specialized correlations, `DetectorResult` -> `Signal` -> atomic
> `Finding`,
> and the Rule v1 compatibility compiler and session evaluator. An inactive
> source/session orchestration and Event3 compatibility API now joins these
> evaluators without switching production callers. It is not the
> current engine. All eight contracted identities have authoritative Canonical
> Observation v2 acquisition coverage (`claude.projects`;
> `codex.sessions`, `codex.archived_sessions`, `codex.headless_sessions`;
> `opencode.sqlite`; `openclaw.agents`; `qwen.projects`; `copilot.process_log`) and
> feed an offline, deterministic, immutable-fixture harness. The current reviewed
> corpus covers 15 cases, 17 sessions, and 306 detector/session evaluations: 15
> both-match, 251 both-no-match, one legacy-only match, zero v2-only matches, 28
> v2-indeterminate outcomes, zero v2 errors, and 11 v2-not-applicable outcomes.
> Fifteen sessions have equivalent risk and two are legacy-only; the current
> accounting contains 29 reviewed exceptions and zero unexplained differences.
> This is bounded fixture evidence, not complete behavioral equivalence or proof
> for every custom Rule v1 rule; in particular, `compat.v1.url` remains
> intentionally absent. Copilot native-v2 capabilities are ToolCall **Supported**,
> UserContext **Unsupported**, and ToolExecution **Unknown**.
> Live scanner shadow: **NO**. Detection v2 production runtime activation:
> **NOT STARTED**. Complete acquisition coverage does not mean complete production
> runtime coverage: production remains on `NormalizedRecord` and Rule v1, and
> Event3 remains frozen. The v2 process-chain session path is still
> non-production; legacy Event3 remains the active projection and now delegates
> repeat/correlation decisions to the shared pure semantic kernel. Advanced detector
> runtime and a Detection Content v2 loader are not implemented. **Existing
> compatibility:** Event 3.0 remains the current frozen external compatibility
> and output contract.

The current Rule v1, process-chain, and Event3 scoring behavior remains documented
in [Detection model](detection-model.md). This page describes the accepted future
model and identifies the implemented non-production foundation and fixture-only
offline measurement harness.

## Offline shadow/equivalence boundary

The Rule v1 compatibility compiler retains one effective export with its compiled
observation-match detectors. Its shared, source-free session evaluator aggregates
caller-grouped canonical observations, applies Rule v1 modifiers once, and
reconstructs Rule v1 compatibility contributions, score, and metadata. The
offline shadow harness consumes that evaluator and reports three separate
compatibility questions: atomic rule-set equivalence, modifier compatibility,
and contribution/score compatibility. It
does not combine those questions into a parity claim. The current reviewed
reference corpus has exactly one reviewed match-set difference:
`execution.shell` legacy-only command-content broadening. Separately, 28
reviewed capability-driven indeterminate outcomes are
reported as visibility evidence, not additional mismatches. The complete corpus
has zero unexplained differences. Focused synthetic compatibility coverage proves
`compat.v1.url` is compiler-supported but
truthfully absent and demonstrates the compatibility gap; there is no
end-to-end reference-corpus URL mismatch in the current corpus.

The harness explicitly excludes Event3/event construction, allowlist/suppression,
timeline, baseline, process-chain, mutable live-store reads, and all-client
parity. It is an opt-in measurement seam only; it does not change production
behavior or the frozen Event3 contract.

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

The implementation runtime-supports `observation_match` and the bounded
non-production `process_chain` path described below. Sequence, correlation,
imported, baseline, and guard-model behavior remains reserved architecture and
is not runtime-supported by this foundation.

## Tool-derived process-chain boundary

The bounded process-chain path consumes one already-created Canonical
Observation v2 value at a time. Only Tool observations at `ToolProposed`,
`ToolRequested`, `ToolExecutionStarted`, or `ToolExecutionCompleted` are
eligible. `ToolResultReturned` is excluded. The policy is source-neutral.

Command candidates come from, in order, the governed `command.text` facet,
reported `tool.searchable_arguments`, and string-valued `tool.arguments`.
Arbitrary JSON arguments are not stringified, and a tool name is not treated as
a command. Identical command strings within one observation are parsed once;
different strings are all evaluated. Private matcher candidates retain parser
traversal order for session correlation, including multiple statements derived
from one Tool observation. Outward atomic results are separately detector-ordered
and deduplicated by final Signal identity. Atomic normalization does not discard
private child context used by correlation. Session grouping is caller-defined;
there is no source discovery or cross-session state in this tranche.

The existing command parser converts each command candidate into private
`telltale-rules` matcher working input. `CompiledProcessChainRules` remains the
only owner of parent/child and standalone matching, rule-level deduplication,
context adjustment, and inferred-parent confidence weakening. A surviving
match becomes an ordinary `DetectorResult(kind = process_chain)` supported by
the actual Tool observation ID, then an ordinary Signal and Finding. The
immutable process-chain rule ID is the detector ID and `rule_version` remains
1. Effective score, severity, confidence, dedupe key, and merged techniques are
copied after matcher semantics run. ATT&CK IDs are validated and normalized at
this boundary (`T1219` -> `attack:T1219`, `T1003.001` ->
`attack:T1003.001`); malformed values fail closed.

This parsing is detector interpretation, not direct operating-system
observation. It does not create a Canonical Process observation, a
`ProcessObserved` stage, a PID, or a process-instance identity. Direct
Canonical Process evidence remains a separate, stronger future input class.
Runtime sources such as OpenShell may eventually report Process, Network,
Runtime, policy, enforcement, or action-result evidence directly, but no
OpenShell integration or provider abstraction exists in this tranche.

### Process-chain session convergence (non-production)

The caller may pass a grouped slice of already-created Canonical Tool
observations to the crate-private session evaluator. It performs one matcher
pass per observation, retains atomic matches, applies the shared process-chain
session kernel, and returns ordinary `DetectorResult` values for both atomic
and satisfied correlation rules. It does not discover sessions, sources, or
scanner state.

The pure kernel is shared with the Event3 adapter and owns repeat grouping,
repeat-window anchor selection, ordered sequence walking, per-rule/per-entity
throttling, and per-entity risk-cap accounting. `CompiledProcessChainRules`
remains the owner of the six correlation definitions and
`CorrelationStep::matches`; generic `sequence` and `correlation` detector kinds
remain runtime-unsupported.

Private matcher variants are grouped into atomic occurrences by supporting
observation, detector, and matcher dedupe identity. Repeat suppression selects
the retained occurrences before specialized process-chain correlation. Every
private child variant belonging to a retained occurrence remains available to
`CorrelationStep::matches`; no variant from a suppressed occurrence can become
correlation evidence.

Timed v2 semantics use only truthful source-reported `occurred_at`. They never
substitute `observed_at`, materialization time, Event3 construction time, or the
wall clock. Missing `occurred_at` retains the atomic match but makes it
ineligible for timed repeat suppression and correlation. Candidates are ordered
chronologically, with stable parser and caller order for equal timestamps.

Tool-derived matcher input in this tranche has no truthful host or user. The v2
Tool session path therefore uses only the opaque canonical session ID as its
scope and does not compose it with matcher values or label it as a host. Direct
host/user-scoped runtime evidence remains future canonical Process work. Without
a canonical session ID, the atomic match survives but cannot join a
cross-observation operation. Different canonical sessions never correlate.

Repeat identity remains `rule ID + canonical session scope + matcher-owned dedupe key`.
The first timed match is the anchor; repeats inside the configured window are
omitted while the private session result retains total occurrence count and
suppressed count. The defaults remain one hour, one correlation per rule/entity,
and 150 correlation-risk points per entity per caller evaluation.

Each satisfied shipped correlation is an ordinary `DetectorResult` with
`DetectorKind::ProcessChain`, the immutable correlation rule ID, rule version 1,
`FindingKind::Correlation`, and `CorrelationScope::Sequence`. It includes every
actual supporting canonical Tool observation ID, so ordinary Signal/Finding
identity changes when that supporting set changes. Risk-capped results still
emit as evaluated matches with risk 0, informational severity, preserved
confidence/ATT&CK metadata, and a bounded `risk_capped` tag. Zero-risk atomic
matches remain eligible sequence steps. Correlation results omit
`capability_context`; one supporting observation's context is not presented as
an aggregate fact. Their replay-stable dedupe key is a domain-separated SHA-256
identity over the immutable correlation rule ID and opaque canonical session
scope; it contains neither preimage, path, timestamp, nor random material.

The new path is not scanner- or watch-wired. Production continues to acquire
`NormalizedRecord` values and project Event3 through its existing wrapper;
Event3 remains frozen and Event4 remains inactive. Direct Process evidence,
OpenShell, generic temporal engines, Detection Content v2 loading, and v2
Event4 projection remain deferred. The inactive Event3 adapter below does not
change production routing.

## Inactive canonical processing (Issue #51, Tranche A)

`telltale_detect::v2::session::evaluate_source` accepts a `CanonicalSourceInput`,
a compiled `RuleV1CompatibilityPlan`, and optional compiled process-chain rules
with the existing `ProcessChainConfig`. One invocation owns one caller-verified
source instance. It checks the exact client/adapter identity and rejects duplicate
observation IDs; it does not discover sources or read paths.

The boundary groups by canonical session value **and identity origin** within
that source instance. An absent instance or session identity makes each
observation a singleton, without inventing a session. Ordering uses source
`occurred_at`, places untimed observations last, and uses canonical/source sequence
and child ordinal to break time ties. Remaining ties preserve acquisition/caller
order. An observation hash is not a substitute for occurrence ordering. Both
evaluators receive the same ordered slice; the process kernel retains its existing
within-observation parser ordering and temporal eligibility rules.

`evaluate_rule_v1_session` remains the sole Rule v1 compatibility evaluator. Its
detector counters preserve match, no-match, not-applicable, visibility reasons,
and errors separately, even when aggregate match precedence hides a lower-ranked
status. Session modifiers, effective policy/exclusion behavior, checked
contributions, and overflow behavior are unchanged. `compile_rule_v1` still
rejects unsupported custom rule metadata. `compat.v1.url` is unavailable rather
than negatively observed: URL-only rules are indeterminate, mixed-target rules
evaluate only their available alternatives, and source completion remains
visibility-limited whenever the plan contains URL compatibility.

The v2 process-chain evaluator remains the sole canonical matcher pass and uses
the existing shared suppression/correlation kernel. It retains Event3-specific
context before atomic normalization discards private matcher variants. No
canonical Process facts, host/user identities, PIDs, or execution outcomes are
manufactured from Tool evidence.

### Projection and retained context

`telltale_detect::v2::event3::project_event3(&evaluation, &context)` returns
`ProjectedSource { events, completion }` or a bounded `ProcessingError`. The
context contains an artifact hash and optional caller-attested, source-reported
agent/model/provider metadata keyed by the exact canonical session identity.
The artifact hash must already be canonical lowercase SHA-256. Absent metadata
stays absent; duplicate, Event3-ambiguous, or unrelated session metadata is
rejected through one indexed validation pass.
It never propagates one session's first model to another session.

Retained compatibility material has one owner and lifetime: the canonical
evaluation result, dropped after projection. It contains no copied observation,
transcript cache, legacy record, or reevaluation snapshot:

| Material | Why it is retained |
| --- | --- |
| Canonical session identity and origin | Grouping and truthful Event3 session attribution |
| Latest reported occurrence time and first ordered tool name | Existing session-event time/tool fields, without content guessing |
| Rule IDs, dimensions/tags, modifier IDs, checked contributions and score | Existing Event3 detection/risk contract |
| Matching observation ID, ordered occurrence index, selector-derived field, redacted snippet and evidence hash | Evidence linkage and precise detection timeline anchors without rerunning a matcher |
| Process matcher context, secondary rule IDs, inferred-parent flag, rule title/reason, investigation fields, false positives, suppression window, severity and adjustment | Existing process-chain Event3 detail, which generic DetectorResult does not carry |
| Retained private process variants and ordered correlation step references | Preserve child variants sharing one outward atomic identity; scalar process context is the first variant, additional variants are bounded evidence |
| Repeat counts, suppressed count, correlation supporting result keys and effective capped score | Preserve kernel decisions and link to the actually projected supporting Event3 IDs |
| Family/stage counts and unique tool names | Explicit canonical activity/accounting inputs, not fake findings or legacy baseline records |

There are at most 65,536 observations per invocation, 4,096 retained/projection
items, 4,096 UTF-8 bytes per retained compatibility string, and 4 MiB of aggregate
retained compatibility text per source or projection pass. Capacity is consumed
before retaining process variants, correlation steps, evidence, or Event3 material.
Limits fail explicitly; they do not silently truncate required context. Text snippets use existing bounded redaction. New context containers do
not implement Debug; processing errors carry only fixed codes. Process command
and path text is redacted before retention. All output still uses the existing
Event3 constructors and terminal serializer. Projection validates terminal bytes
with the bounded Event3 consumer before returning any events, including its 1 MiB
per-event limit. No partial successful batch is returned on projection failure.

Event3 allows `timeline_anchors` on detection events, **not** process-chain events.
Detection projection first aggregates one anchor per actual matching occurrence,
with sorted unique atomic rule IDs, applicable modifier IDs, and evidence fields;
Event3 canonicalization therefore cannot discard competing per-evidence anchors.
Process events retain occurrence/observation references in
existing evidence fields instead of expanding the schema. Terminal privacy can
sanitize observation-ID snippets; their evidence hashes retain linkage. Event IDs
and materialization timestamps remain constructor-generated, not replay-stable
identities; evaluation results and event ordering are deterministic.

### Completion and later activation gates

Successful evaluation returns `Complete` or `VisibilityLimited`. Missing scope,
capability/provenance limitations, and unavailable process timing do not become
operational failures. Detector errors (even alongside matches), accounting
failures, invalid inputs, and bounds violations return explicit errors. Projection
failure is distinct from evaluation failure. These statuses say nothing about
whether output has been persisted.

A later scanner must require **acquisition success AND operational evaluation
success AND projection success AND required durable output persistence** before
committing acquisition progress. Visibility-limited success may advance after
durability; permanently unsupported capabilities must not freeze progress.
ScanState, OpenCode cursors, scan, watch, and embedding are unchanged here.
Allowlisting remains an event-handling concern after projection and is not applied
by either new API.

### Compatibility differences and Tranche B dependencies

- The reviewed Rule v1 corpus/ledger is unchanged: one legacy command-content
  broadening difference, 28 capability-driven indeterminate outcomes, 29 reviewed
  exceptions, zero unexplained differences. The additional corpus test compares
  orchestration and Event3 IDs/scores to those existing v2 outcomes.
- `compat.v1.url` remains unavailable. URL-only rules are indeterminate, mixed
  rules use their available alternatives, and completion records the visibility
  limitation; no URL evidence is fabricated.
- Current acquisition does not retain generic agent/model/provider metadata.
  Optional omission is truthful; canonical metadata retention or an attested
  source/session compatibility input is a **baseline activation dependency**.
  No client-name-as-agent or message-content-as-tool fallback is reproduced.
- A required Event3 session identity cannot be invented for an unscoped match:
  evaluation completes with limited visibility, but required projection fails.
  Later callers need an explicit handling decision; they must not turn that error
  into successful cursor eligibility.
- Evidence now references actual observations and selectors; cardinality and
  anchors intentionally differ from legacy's first-match/field-kind heuristics.
  Correlation inferred-parent status reflects its supporting matcher context
  rather than an unconditional false value. These are explicit compatibility
  differences outside the old Rule v1-only shadow denominator.
- Canonical family/stage counts are not legacy `record_counts`: extraction may
  split one source item into multiple facts. Baseline partitioning, activity-event
  count semantics, and pre-policy accounting require Tranche B integration work;
  this tranche neither emits fake baseline findings nor migrates baseline state.
- Source-instance verification, safe acquisition chunk/session boundaries,
  configured bounds handling, output durability, post-projection allowlisting,
  and the inherited OpenCode downstream-success cursor issue remain activation
  responsibilities. Step 5 and production activation are not complete.

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
compatibility views require `ToolCall`, not `ToolExecution`. Focused synthetic
compatibility coverage demonstrates this URL visibility gap; this does not add
URL visibility.

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
or ordered `entity_correlation` shape and converge through DetectorResult. The
production entity-correlation path remains the legacy Event3 implementation.
The non-production Detection v2 ProcessChain session evaluator implements the
same six specialized entity correlations for Tool-derived matches. Generic
Detection v2 `Sequence` and `Correlation` detector kinds remain unsupported.

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
target/regex matchers with optional target-local exclusion regexes into
non-production observation-match detector definitions with `rule_version: 1`;
IDs are not renamed. An excluded matcher lowers to existing `all` and `not`
matcher composition; Detection v2 has no rule-specific filter runtime. Modifiers remain
Rule v1 compatibility session constructs: the shared non-production evaluator
triggers them from matched atomic Rule v1 IDs and categories, but they never
become DetectorResults, Signals, Findings, or native v2 correlation detectors.
The evaluator uses the existing validated contribution primitives to construct
Rule v1 compatibility contributions and a checked compatibility score. That sum
is not native Detection v2 aggregate risk; Detection v2 still has no accepted
general session aggregate-risk model. The compiler and evaluator do not
implement Rule v1 allowlist or suppression behavior or Event3
projection/equivalence. Native v2 selectors are observation-scoped,
preserve absence, and do not treat parsed paths or URLs as observed side
effects. `url` remains compiler-supported as `compat.v1.url`, but it resolves
truthfully absent; focused synthetic compatibility coverage demonstrates the
gap without manufacturing URL facts.
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

The foundation, including the Rule v1 compatibility session evaluator and
Tool-derived process-chain evaluator, is not currently wired into production or
running in scan/watch. Event3 remains
supported and unchanged:
its Rule v1 IDs, deterministic scoring, thresholds, parser ownership, privacy,
and persisted/replayed bytes remain current. Event4 is independently versioned
and does not replace Event3 until explicit migration gates pass. Future semantics
are not backported. Event3 and Event4 are independent projections from common
accepted internal semantics, not conversions of one another.
