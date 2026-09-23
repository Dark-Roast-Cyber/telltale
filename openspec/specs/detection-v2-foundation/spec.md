# detection-v2-foundation Specification

## Purpose
This specification covers the Detection v2 foundation and its activated
canonical source evaluation. It implements the `observation_match` detector, bounded
Tool-derived parent/child, standalone, and caller-grouped session
`process_chain` evaluation, the
`DetectorResult` -> `Signal`
-> atomic `Finding` boundary, the final 56-selector registry (48 native plus
exactly eight Rule v1 compatibility views), their capability/provenance/matcher/
identity contracts, and the read-only Rule v1 export/compatibility compiler and
source-free session evaluator, source-instance-scoped session
orchestration, and a source-free Event3 compatibility projection. Process-chain
repeat/correlation semantics have one pure shared owner used by both the
Event3 compatibility adapter and this v2 session evaluator. `compat.v1.url`
remains compiler-supported but truthfully absent. There is no advanced detector
runtime, Event4, gateway, or Detection Content v2 runtime
loader; the Event 3.0 schema remains unchanged.
## Requirements
### Requirement: Detector result materialization

The implementation MUST expose the closed detector taxonomy and exact five
evaluation statuses and seven non-evaluation reasons. Only
`evaluated_match` may materialize a Signal, and only a Signal may materialize
one atomic Finding with the documented domain-separated identities. Signal IDs
MUST hash this exact fixed-order tuple:
`["telltale:detection-v2-signal", 2, kind, id, version|null, engine|null,
content_ref|null, rule_version|null, match_surface|null,
sorted/deduplicated_observation_ids, semantic_identity_else_dedupe_key_else_null,
status, selector_path_digest]`. Absent optionals are JSON `null`, and
`match_surface` is a separate semantic-context member. Finding IDs MUST hash
`["telltale:detection-v2-finding", 1, "atomic", signal_id]`; prefixes remain
`sig:v2:sha256:` and `fnd:v2:sha256:`. Matched raw values MUST NOT enter either
materialized identity.

#### Scenario: Non-match does not materialize output

- **WHEN** an observation-match detector evaluates an applicable observation and
  its matcher returns no match
- **THEN** the result is `evaluated_no_match` and Signal/Finding materialization
  returns no object

#### Scenario: Detector errors require diagnostics

- **WHEN** a reserved detector kind is requested
- **THEN** the result is `detector_error` with a bounded diagnostic and no Signal
  or Finding

#### Scenario: Evaluated matches require observation identity

- **WHEN** a caller constructs an `evaluated_match` without at least one valid
  observation ID
- **THEN** construction fails and no Signal or Finding can be materialized;
  non-match and non-evaluated statuses are not required to carry an observation
  ID

### Requirement: Typed selector and capability boundary

Selectors MUST resolve through an explicit registry over typed observation body
fields and governed facets. The eight `compat.v1` names MUST compile as views,
preserve truthful absence, require their documented capabilities, and never
reparse raw structured arguments/results or invent URL/network facts.
The published registry MUST contain exactly 48 native selectors and exactly
these backing counts: 2 direct, 37 typed, 7 derived, and 2 explicitly governed
facets (`command.text` and `resource.path`). Native selectors without a typed
field/accessor, deterministic derivation, or an explicitly governed facet name
MUST be rejected; a permitted namespace is not sufficient governance.

The native selector counts by group MUST be: `session` 1, `message` 3,
`tool` 15, `command` 1, `resource` 3, `network` 5, `process` 4,
`inference` 5, `mcp` 4, `runtime` 4, and `browser` 3. The eight compatibility
targets MUST remain exactly `arguments`, `assistant_context`, `command`,
`file_path`, `tool_name`, `tool_result`, `url`, and `user_context`.

The native selector names MUST be exactly:

```text
session.id
message.role, message.content, message.text
tool.name, tool.arguments, tool.searchable_arguments, tool.result,
tool.searchable_result, tool.reported_status, tool.is_error, tool.exit_code,
tool.call_id, tool.stage, tool.arguments.text, tool.arguments.keys,
tool.result.text, tool.result.is_error, tool.result.exit_code
command.text
resource.path, resource.operation, resource.path_class
network.domain, network.destination_class, network.operation, network.port,
network.protocol
process.name, process.pid, process.instance_id, process.privilege
inference.provider, inference.requested_model, inference.resolved_model,
inference.streaming, inference.stop_reason
mcp.server.id, mcp.server.transport, mcp.server.location_class, mcp.tool.name
runtime.execution_mode, runtime.isolation.state, runtime.privilege,
runtime.workspace.class
browser.surface, browser.origin_class, browser.navigation_id
```

#### Scenario: Compatibility selectors preserve absence

- **WHEN** a tool observation contains structured arguments but no searchable
  derivative or direct URL activity
- **THEN** the arguments view is absent for text matching when no text is
  available and `compat.v1.url` remains absent

#### Scenario: Capability visibility is not occurrence

- **WHEN** a selector requires an unsupported or unknown capability
- **THEN** evaluation is `not_evaluated` with the corresponding capability reason
  rather than `evaluated_no_match`

#### Scenario: Present not-exists is a no-match

- **WHEN** a present selector passes capability and provenance preflight and a
  `not_exists` predicate evaluates it
- **THEN** the predicate returns `no_match`, not `type_mismatch`;
  unavailable capability or mismatched provenance still returns its respective
  `not_evaluated` state before the operator

### Requirement: Matcher semantics

The matcher MUST implement only the documented predicate and boolean operators,
bounded compilation, typed/no-coercion values, provenance checks, capability
preflight, deterministic precedence, and three-state `all`/`any`/`not` algebra.
Integer equality and ordering MUST be exact, including signed/unsigned
comparisons. Mixed integer/floating-point comparison is allowed only when the
integer round-trips exactly to a finite `f64`; otherwise it is
`type_mismatch`. Floating-point operands MUST be finite.

#### Scenario: Invalid content fails before evaluation

- **WHEN** content contains an unknown selector, invalid regex, empty boolean
  group, or an out-of-bounds recursive matcher
- **THEN** compilation rejects it with a code-only error

#### Scenario: Unknown state is not inverted

- **WHEN** a recursive branch is not evaluated because a required capability is
  unavailable
- **THEN** `not` preserves `not_evaluated` and does not turn it into a match

#### Scenario: Numeric precision is fail-closed

- **WHEN** an integer/floating-point predicate would lose integer precision, or
  an operand is non-finite
- **THEN** evaluation is `not_evaluated` with `type_mismatch` rather than a
  coerced comparison

#### Scenario: Provenance mismatch is operator-independent

- **WHEN** a present fact has `parsed` provenance and a matcher requires
  `observed` provenance
- **THEN** every predicate operator, including `not_equals`, `not_in`,
  `exists`, and `not_exists`, returns `not_evaluated` with `ineligible_input`
  before operator evaluation; `not` preserves that state

#### Scenario: Absence has no provenance mismatch

- **WHEN** a selector is absent and a matcher declares a provenance requirement
- **THEN** the absence-specific capability and `exists`/`not_exists` semantics
  apply without treating absence as a provenance mismatch

#### Scenario: Derived argument keys use derived provenance

- **WHEN** `tool.arguments.keys` is resolved from a structured
  `tool.arguments` object
- **THEN** its value is the deterministic key list and its resolved metadata
  provenance is `derived`, regardless of the argument field's provenance

#### Scenario: Scalar selector views preserve backing provenance

- **WHEN** `message.text`, `tool.arguments.text`, or `tool.result.text` resolves
  a canonical scalar fact
- **THEN** the selector preserves that backing fact's metadata and provenance;
  the selector's view category alone does not change it

#### Scenario: Tool stage is family-scoped

- **WHEN** `tool.stage` resolves a Message or Runtime observation
- **THEN** it is absent; for a Tool observation it remains the derived
  lifecycle-stage value

### Requirement: Rule v1 compatibility

`telltale-rules` MUST expose only an effective read-only Rule v1 compatibility
view containing compiled target/regex pairs and optional target exclusions,
exact IDs, effective metadata,
policy identity, and modifier plans. The v2 compiler MUST consume that view,
map supported classes/severity/scores/ATLAS losslessly, reject operational
health without a truthful mapping, and not create modifier detectors. The
compiled plan MUST retain the effective compatibility view needed to evaluate
one caller-defined canonical session without a separately synchronized export.
The Detection v2 session adapter MUST aggregate each detector over the supplied
observations using match, error, indeterminate, evaluated no-match, then not-applicable
precedence while retaining status/reason counts and sorted matched selector
paths. It MUST determine matched atomic IDs and pass them to the shared Rule v1
content evaluator, which MUST trigger modifiers from all declared category and
rule-ID conditions and reconstruct deterministic compatibility metadata.
Empty-condition modifiers MUST NOT fire.

Each Rule v1 target exclusion MUST be evaluated with its positive matcher by
the shared Rule v1 content evaluator after Detection v2 resolves applicability,
capabilities, and truthful selector values. A matching exclusion regex removes
the positive match. Exclusions MUST remain target-scoped, MUST name a target in
the same `detection.selection`, MUST NOT be accepted on the simple `targets` plus
`regex` form, and MUST NOT depend on rule IDs in either evaluator. Rule
evaluation MUST continue to other target matchers after an excluded candidate.
The effective Rule v1 fingerprint MUST include compiled exclusions under current
canonicalization `rule-v1-compiled-compatibility-v2` and digest domain
`telltale:producer-rule-v1-fingerprint:v2`. New producer manifests MUST emit
that canonicalization, while well-formed historical manifests naming
`rule-v1-compiled-compatibility-v1` remain valid under manifest schema v1.

The I/O-free Rule v1 API, direct-record compatibility path, and Detection v2
MUST share the same Rule v1 content evaluator for matching, exclusions,
modifier eligibility, contributions, checked score, and compatibility metadata.
Canonical applicability, capability and provenance remain Detection v2 concerns.
Rule v1 compatibility contributions and their checked score MUST use
`RiskContribution`, `DeterministicRule`, `ChainModifier`,
`canonicalize_contributions`, and `checked_risk_sum`. A matched rule or triggered
modifier MUST contribute at most once per session and zero-score entries MUST
remain matched/triggered without creating a contribution. This compatibility
sum MUST NOT be treated as native Detection v2 aggregate risk. Modifiers MUST
remain Rule v1 compatibility session constructs and MUST NOT become
DetectorResults, Signals, Findings, or native v2 detector kinds.

#### Scenario: Effective rules compile as atomic detectors

- **WHEN** the bundled effective Rule v1 export is passed to the compatibility
  compiler
- **THEN** each active rule becomes an observation-match detector with its exact
  ID, Rule v1 version, score, severity, class mapping, and ATLAS tags, while
  modifiers remain plans

#### Scenario: Unmappable class fails closed

- **WHEN** an effective Rule v1 rule has the `operational_health` class
- **THEN** compatibility compilation rejects it rather than mapping it to a
  security or informational Finding kind

#### Scenario: Rule v1 URL compatibility remains explicitly unavailable

- **WHEN** an effective Rule v1 rule uses the `url` target
- **THEN** compilation succeeds to `compat.v1.url`, which requires `ToolCall`
  visibility but cannot resolve a URL value without manufacturing URL, path, or
  network facts
- **AND** a URL-only rule is indeterminate, mixed rules evaluate their available
  alternatives, and source completion records the visibility limitation

#### Scenario: Caller-defined session uses one compatibility plan

- **WHEN** a caller supplies a compiled Rule v1 compatibility plan and an empty
  or non-empty slice of already grouped Canonical Observation v2 values
- **THEN** the shared evaluator performs no source access or session inference
  and returns the bounded detector aggregates, effective Rule v1 IDs,
  compatibility contributions and checked score, and compatibility metadata

### Requirement: Tool-derived process-chain evaluation

`process_chain` MUST be runtime-supported without activating `sequence`,
`correlation`, `imported`, `baseline`, or `guard_model`. The evaluator MUST
accept already-created Canonical Observation v2 values and MUST
evaluate only Tool observations at `ToolProposed`, `ToolRequested`,
`ToolExecutionStarted`, or `ToolExecutionCompleted`. `ToolResultReturned` and
all non-Tool families MUST produce no process-chain candidates.

Command candidates MUST come only from the governed `command.text` facet,
reported `tool.searchable_arguments`, or string-valued `tool.arguments`. Tool
names MUST NOT become commands and arbitrary JSON objects MUST NOT be
stringified. Identical strings within one observation MUST be parsed once;
distinct strings MUST all be evaluated. Private matcher candidates MUST retain
the command parser's traversal order for session semantics, including derived
statements within one Tool observation. Outward atomic results MUST instead be
detector-ordered and duplicate-free. Distinct private candidates that produce
the same final Detection v2 Signal identity MUST yield one outward result for
that supporting Tool observation without discarding child context needed by a
correlation predicate; this result normalization MUST NOT replace
matcher-owned rule deduplication.

The existing command parser MUST produce private matcher working state for the
existing `CompiledProcessChainRules`. That matcher MUST remain authoritative for
parent/child and standalone matching, rule-level deduplication, context
adjustment, inferred-parent confidence weakening, winning rule identity, and
merged techniques. The adapter MUST NOT construct or return Canonical Process
observations, `ProcessObserved` stages, PIDs, or process-instance identities.
Direct Canonical Process evidence is a separate stronger evidence class and is
not consumed by this evaluator.

Each surviving match MUST become one ordinary `DetectorResult` with kind
`process_chain`, the immutable process-chain rule ID, `rule_version: 1`, the
supporting Tool observation ID, effective severity/risk/confidence, category,
dedupe key, `CorrelationScope::Process`, and canonically available session ID.
Detection-class mapping MUST share one fail-closed helper with Rule v1. Valid
bare ATT&CK IDs MUST normalize to typed `attack:` IDs and malformed values MUST
fail closed. A zero-risk informational match MUST remain `evaluated_match` and
MUST materialize through the ordinary Signal and atomic Finding path.

#### Scenario: Tool command evidence produces a process-chain result

- **WHEN** an eligible Tool observation contains `cmd.exe /c whoami`
- **THEN** the existing immutable parent/child rule matches with the Tool
  observation ID, and no Canonical Process observation is created

#### Scenario: Command evidence is absent

- **WHEN** a Tool observation has only a shell-like tool name, arbitrary JSON
  arguments, or result content
- **THEN** no process-chain candidate or negative result matrix is produced

#### Scenario: Existing effective matcher semantics survive normalization

- **WHEN** matcher-owned context adjustment, inferred-parent weakening, or
  rule-level deduplication changes the surviving process-chain detection
- **THEN** Detection v2 uses the effective winner, score, severity, confidence,
  and merged techniques without implementing those semantics again

#### Scenario: Process-chain migration remains bounded

- **WHEN** the canonical runtime supplies Tool-derived evidence and compiled
  process-chain rules
- **THEN** scan/watch invoke the Detection v2 process-chain session evaluator and
  project its compatible output through Event3
- **AND** the caller-grouped session evaluator owns repeat suppression and
  specialized process-chain correlation, while Event4, direct Process evidence,
  and any OpenShell integration remain inactive

### Requirement: Process-chain session semantics

The implementation MUST provide one crate-private, I/O-free process-chain
session semantic owner for both the legacy Event3 adapter and the Detection v2
caller-grouped evaluator. The owner MUST operate only on rule ID, category,
normalized child name, matcher-owned dedupe key, resolved entity, an opaque
occurrence-group identity, and an optional caller-supplied ordering timestamp.
The kernel MUST NOT assign or reinterpret timestamp provenance. It MUST remain
independent of Event3 values, Canonical Observation values, DetectorResult,
source access, policy, and enforcement. `CompiledProcessChainRules::correlations()` and
`CorrelationStep::matches` remain authoritative for the six shipped
correlations and their predicates; no generic temporal engine or v2 content
loader is introduced.

The caller MUST supply the observation group. The evaluator MUST NOT discover
sessions or sources, and mixed input MUST NOT correlate or suppress across
different resolved session/entity values. A valid atomic match MUST survive
when session semantics lack an entity or ordering time.

Timed session semantics MUST use only canonical source-reported `occurred_at`.
`observed_at`, materialization time, Event3 construction time, and wall-clock
time MUST NOT be fallbacks. Candidates MUST be ordered chronologically with
stable parser/caller order for equal occurrence times. A missing `occurred_at`
MUST retain its atomic result but MUST NOT be a timed repeat anchor, timed
repeat, or timed correlation step.

Tool-derived matcher inputs in this tranche have no truthful host or user. The
v2 Tool session path MUST therefore use only the opaque canonical session ID as
its session scope, MUST NOT compose it with delimiter-separated matcher values,
and MUST NOT label it as a host. Direct host/user-scoped evidence remains
deferred to the future canonical Process path. Without a canonical session ID,
only the atomic result is retained.

Private matcher variants MUST be grouped into atomic occurrences before repeat
suppression. For the v2 Tool path, occurrence identity MUST use supporting
canonical observation identity, detector identity, and matcher-owned dedupe
identity; raw command text and private child name MUST NOT participate. The
shared kernel MUST receive only an opaque occurrence-group identity.

Repeat suppression MUST compare atomic occurrences using `rule ID + resolved
entity + matcher-owned dedupe key`. The first eligible timed occurrence is the
anchor; equivalent timed occurrences inside the configured window are
suppressed once per occurrence. Correlation MUST evaluate only private variants
from retained occurrences, while every ordered child variant associated with a
retained occurrence remains eligible for `CorrelationStep::matches`. The
retained private anchor count MUST include the anchor as occurrence 1, and
suppressed-occurrence count MUST remain available privately. The existing
defaults MUST remain one hour, one correlation per rule/entity per caller
evaluation, and 150 correlation-risk points per entity.

Each satisfied shipped correlation MUST normalize to an ordinary evaluated
`DetectorResult` with `DetectorKind::ProcessChain`, the immutable correlation
rule ID, `rule_version: 1`, `FindingKind::Correlation`, and
`CorrelationScope::Sequence`. It MUST contain all actual supporting canonical
Tool observation IDs, normalized and deduplicated by the common constructor; no
synthetic observation ID may be created. The ordinary Signal/Finding path MUST
materialize the result, and exact duplicate semantic identity with the same
supporting set MUST collapse without collapsing different supporting sets. A
correlation result MUST omit `capability_context` rather than attribute one
supporting observation's context to the aggregate.

Correlation matching MUST preserve ordered steps, the compiled per-rule window,
the per-rule/per-entity throttle, and the authored correlation-rule iteration
order for risk accounting. Zero-risk atomic matches MUST remain eligible steps.
When an authored correlation score would exceed the per-entity cap, the
correlation MUST still emit as `EvaluatedMatch` with effective risk 0,
informational effective severity, retained detector/confidence/ATT&CK metadata,
and a bounded `risk_capped` tag; the capped score MUST NOT increase accumulated
entity risk.

#### Scenario: Canonical process-chain session correlation

- **WHEN** two eligible Tool observations in one canonical session satisfy one
  of the six compiled process-chain sequences within its `occurred_at` window
- **THEN** one ordinary `ProcessChain` correlation result is emitted with both
  actual observation IDs, `FindingKind::Correlation`, and sequence scope

#### Scenario: Missing source occurrence time is not repaired

- **WHEN** an atomic Tool match has no `occurred_at`
- **THEN** the atomic result remains evaluated, `observed_at` is not substituted,
  and the match cannot suppress or satisfy timed session semantics

#### Scenario: Session fallback remains truthful

- **WHEN** Tool-derived process matching has no truthful host/user entity but
  has a canonical session ID
- **THEN** session-scoped suppression/correlation uses that session ID without
  asserting host evidence; different session IDs do not join

#### Scenario: Derived command order remains semantic

- **WHEN** one Tool observation contains multiple parsed statements with one
  source occurrence time
- **THEN** ordered correlation uses parser traversal order, while outward
  atomic results remain detector-ordered and duplicate-free

#### Scenario: Private child context survives atomic normalization

- **WHEN** distinct private matcher candidates share one outward atomic Signal
  identity but carry child names used by `CorrelationStep::matches`
- **THEN** the retained occurrence exposes its complete ordered private
  candidate set to correlation and the outward atomic result still appears once

#### Scenario: Suppressed occurrence is not correlation evidence

- **WHEN** an atomic occurrence is suppressed as a repeat inside the configured
  suppression window
- **THEN** none of its private matcher variants may satisfy a specialized
  process-chain correlation step

#### Scenario: Repeat outside suppression window is retained

- **WHEN** an equivalent timed occurrence falls outside the suppression window
- **THEN** it becomes a retained occurrence and may satisfy a later correlation
  within that correlation rule's own window

#### Scenario: Aggregate capability context is not inferred

- **WHEN** a process-chain correlation is supported by Tool observations with
  different capability contexts
- **THEN** the correlation result omits capability context instead of copying
  the anchor observation's context

#### Scenario: Generic correlation kinds remain reserved

- **WHEN** a shipped process-chain correlation is satisfied
- **THEN** its detector kind is `ProcessChain`, not generic `Sequence` or
  `Correlation`, and those generic kinds remain runtime-unsupported

### Requirement: Runtime and privacy boundary

The Detection v2 evaluator MUST remain free of source I/O and source-crate
dependencies. The shared canonical runtime MUST own source acquisition and
Event3 projection around that evaluator without adding policy/action authority.
Diagnostics and identities MUST contain no raw matched values. Evidence
references MUST be representation-specific validated handles (selector paths,
valid typed IDs, safe fingerprints, bounded classifications, or accepted local
structured references), not arbitrary content. Debug output for results,
signals, findings, and their evidence-bearing supporting values MUST redact
semantic strings and evidence payloads.

#### Scenario: Local evaluator remains source-free

- **WHEN** the Detection v2 module is built without source-I/O features
- **THEN** it compiles and evaluates only caller-provided typed observations,
  with no direct scanner, adapter, Event, policy, or action ownership

#### Scenario: Identity is value-independent

- **WHEN** two observations with the same detector, observation identity, and
  matched selector paths contain different matched text
- **THEN** their Signal identity is unchanged and no raw matched text appears in
  diagnostics or materialized identity fields

#### Scenario: Unsafe evidence cannot enter a result

- **WHEN** a caller supplies arbitrary source text as an evidence reference or
  formats a result containing a valid evidence reference
- **THEN** construction rejects the arbitrary text, and Debug output contains no
  evidence payload

### Requirement: Canonical source/session evaluation

The canonical evaluation boundary SHALL own source-instance-scoped session
grouping and deterministic occurrence ordering for both Rule v1 compatibility
and process-chain v2 evaluation. It MUST reuse their existing evaluators and
shared scoring/kernel semantics, without a legacy record conversion bridge.

#### Scenario: Identical session strings from unrelated sources
- **WHEN** unrelated source instances report identical session strings
- **THEN** their observations MUST NOT share a session evaluation

#### Scenario: Missing identity or time
- **WHEN** source/session identity or occurrence time is unavailable
- **THEN** the missing information SHALL remain explicit and MUST NOT be invented
- **AND** unavailable identity/time SHALL NOT authorize temporal correlation

#### Scenario: Correlation replay identity
- **WHEN** two immutable process-correlation rules match one canonical session
- **THEN** each SHALL receive a distinct replay-stable, domain-separated digest
  over rule identity and opaque session scope without exposing either preimage

### Requirement: Operational processing completeness

Canonical processing SHALL distinguish ordinary completion, visibility-limited
completion, operational evaluation failure, and compatibility projection failure.
It MUST retain bounded evidence/projection context during the authoritative pass.
The boundary SHALL allow at most 65,536 observations, 4,096 retained/projection
items, 4,096 UTF-8 bytes per retained compatibility string, and 4 MiB aggregate
retained compatibility text. Capacity MUST be consumed before retention.

#### Scenario: Unsupported capability
- **WHEN** a required capability is unsupported or unknown
- **THEN** evaluation SHALL preserve that distinction from no-match and error
- **AND** successfully completed visibility-limited processing MAY later be eligible
  for progress persistence once required output is durable

#### Scenario: Downstream failure
- **WHEN** evaluation or required Event3 projection fails
- **THEN** processing SHALL report an explicit bounded failure without a partial
  successful projection result
- **AND** emitted events SHALL NOT be used as proof of processing completion

#### Scenario: Reordered authoritative coordinates
- **WHEN** input order changes but source occurrence coordinates fully determine
  canonical order
- **THEN** replay-stable evaluation and projection semantics SHALL remain equal
