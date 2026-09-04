# detection-v2-foundation Specification

## Purpose
This specification covers only the experimental, non-production Detection v2
foundation. It implements only the `observation_match` detector, the
`DetectorResult` -> `Signal`
-> atomic `Finding` boundary, the final 56-selector registry (48 native plus
exactly eight Rule v1 compatibility views), their capability/provenance/matcher/
identity contracts, and the read-only Rule v1 export/compatibility compiler.
`compat.v1.url` remains compiler-supported but truthfully absent pending P13
visibility-gap measurement. There is no shadow or activation path, source or
scanner wiring, advanced detector runtime, Event4, gateway, or Detection Content
v2 runtime loader; Event 3.0 remains unchanged.
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
view containing compiled target/regex pairs, exact IDs, effective metadata,
policy identity, and modifier plans. The v2 compiler MUST consume that view,
map supported classes/severity/scores/ATLAS losslessly, reject operational
health without a truthful mapping, and not create modifier detectors.

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

#### Scenario: Rule v1 URL compatibility remains visible but absent

- **WHEN** an effective Rule v1 rule uses the `url` target
- **THEN** compilation succeeds to `compat.v1.url`, which requires `ToolCall`
  visibility and resolves truthfully absent without manufacturing URL, path, or
  network facts; P13 measures the resulting visibility gap

### Requirement: Production and privacy boundary

The foundation MUST be free of source I/O and source-crate dependencies, MUST
not provide policy/action/export/Event fields, and MUST leave current detection,
allowlist, process-chain, timeline, Rule v1 evaluation/scoring, adapters, and
Event 3 behavior unchanged. Diagnostics and identities MUST contain no raw
 matched values. Evidence references MUST be representation-specific validated
 handles (selector paths, valid typed IDs, safe fingerprints, bounded
 classifications, or accepted local structured references), not arbitrary
 content. Debug output for results, signals, findings, and their evidence-bearing
 supporting values MUST redact semantic strings and evidence payloads.

#### Scenario: Local module remains non-production

- **WHEN** the Detection v2 module is built without source-I/O features
- **THEN** it compiles and evaluates only caller-provided typed observations,
  with no scanner, adapter, Event, policy, or action path

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
