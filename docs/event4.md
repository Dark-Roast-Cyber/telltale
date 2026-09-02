# Event4 Architecture

> **Status:** **Accepted architecture.** Event4 is the reviewed intended future
> external contract. **Current implementation:** Event4 is **not implemented**
> and is not runtime-supported. **Existing compatibility:** Event 3.0 remains
> the current frozen external compatibility and output contract.

> **Event 3.0: FROZEN / CURRENT COMPATIBILITY CONTRACT**

This page describes a future projection. It does not activate an Event4
serializer, validator, emitter, adapter, collector, sink, or policy runtime.

## Shape

Event4 uses schema version `4.0`, a sparse common envelope, and exactly one
typed body. The `type` value selects the body and must equal its property name.
There is no generic `body` or `payload` escape hatch.

```json
{
  "schema_version": "4.0",
  "event_id": "evt-example-1",
  "type": "finding",
  "event_action": "rule.matched",
  "observed_at": "2026-08-29T22:00:00Z",
  "materialized_at": "2026-08-29T22:00:01Z",
  "session_id": "session-example-1",
  "finding": {
    "kind": "security_detection",
    "category": "example",
    "severity": "low",
    "detector": {"kind": "rule", "id": "example.rule"}
  }
}
```

### Envelope fields

| Field | Requirement and ownership |
| --- | --- |
| `schema_version` | Required constant `"4.0"`; Event4 schema marker, not a transport version. |
| `event_id` | Required Telltale-assigned Event4 record identity, stable through terminal serialization, replay, and projections. |
| `type` | Required one of `session`, `observation`, `finding`, `decision`, `action`, `state`, `health`, or `summary`. |
| `event_action` | Required action from the closed, type-scoped action registry. |
| `occurred_at` | Optional truthful source-reported occurrence time. Omit it when unavailable; never fill it from another clock. |
| `observed_at` | Required Telltale time when the fact was observed or accepted into the semantic pipeline. |
| `materialized_at` | Required terminal-serialization time. It is retained in canonical bytes for replay. |
| `sequence` | Optional producer-local non-negative ordering aid; not global or a delivery sequence. |
| `session_id` | Optional meaningful session correlation; required for `session` and the accepted session-bound `finding` family. Never fabricate it. |
| `workflow_id` | Optional explicitly observed or configured workflow correlation. |
| `trace_id`, `span_id` | Optional instrumentation correlations. They remain envelope-only and are not event identity. |
| `extensions` | Optional single bounded top-level extension bag. |

Provider/model, detector, rule, risk, severity, evidence, source, provenance,
process, policy, action, and reusable state references are not generic envelope
fields. They belong in an applicable body or a later destination projection.
Aliases such as `id`, `event_type`, `timestamp`, `emitted_at`, and `received_at`
are rejected. `received_at` is collector metadata outside Event4.

## Typed bodies

Every Event4 record contains exactly one closed body. Body objects do not gain
open-ended extension fields.

| Body family | Minimum fields | Meaning |
| --- | --- | --- |
| `session` | `session_id`, `lifecycle` (`opened`, `updated`, `closed`) | Session lifecycle and safe context references. The body ID equals the envelope ID. |
| `observation` | `observation_id`, `kind`, `stage` | A selected canonical fact and, where allowed, source, capability, provenance, and state references. |
| `finding` | `kind`, `category`, `severity`, `detector.kind`, `detector.id` | Detector-neutral security meaning. Related links use canonical observation IDs. |
| `decision` | `requested`, `effective`, `status`, `reason_code` | Provider-neutral policy intent and selected outcome. |
| `action` | `action_id`, `decision_ref`, `requested`, `effective`, `status` | Truthful adapter attempt or result linked to a decision. `action_id` differs from `event_id`. |
| `state` | `kind`, `state_ref` | Reusable authoritative snapshot or state change reference. |
| `health` | `component`, `status` | Operational condition, not automatically a detector result or delivery record. |
| `summary` | `kind`, `scope`, `count` | Explicit bounded rollup, not an implicit risk aggregate or child-field copy. |

The initial `event_action` registry is type-scoped: session lifecycle;
message, inference, tool, definition, MCP, process, file, network, browser,
and runtime observations; rule, sequence, correlation, baseline, and guard-model
findings; policy and approval decisions; enforcement actions; state changes and
heartbeats; health changes; and `summary.emitted`. The semantic validator checks
the action/body pairing and the minimum kind/stage pairing. For example,
`tool.proposed`, `tool.requested`, `tool.execution_started`,
`tool.execution_completed`, and `tool.result_returned` remain distinct facts.

The controlled action vocabulary is:

```text
session.opened                 session.updated
session.closed                 message.observed
inference.requested           inference.completed
inference.failed              tool.proposed
tool.requested                tool.execution_started
tool.execution_completed      tool.result_returned
tool_definition.changed       mcp.inventory_changed
process.observed              file.observed
network.observed              browser.observed
runtime.observed              rule.matched
sequence.matched              guard_model.matched
classifier.matched            baseline.deviation
correlation.matched           policy.evaluated
approval.requested            approval.resolved
enforcement.applied           enforcement.degraded
runtime.changed               isolation.changed
capabilities.changed          ruleset.activated
policy.activated              toolset.changed
sensor.heartbeat              health.degraded
health.failed                 summary.emitted
```

This list is closed. An unlisted action is not a vendor extension, and a listed
action is still invalid when its body family or observation kind/stage does not
match.

## Time and identity ownership

`occurred_at` belongs to the source. `observed_at` belongs to Telltale.
`materialized_at` belongs to terminal serialization. A collector's `received_at`
is never copied into Event4. `materialized_at` must not precede `observed_at`.
Analytic sequences name an explicit ordering field and do not silently fall back
to another time dimension.

| Identity | Meaning |
| --- | --- |
| Event4 `event_id` | Telltale record identity; not a source, body, collector, delivery, or authentication ID. |
| Canonical `observation_id` | Telltale identity of a normalized fact; distinct from `event_id`. |
| `session_id`, `workflow_id` | Meaningful source or explicitly configured semantic correlations; omitted when unavailable. |
| Source/call/process IDs | Optional source facts preserved only when supplied and privacy-safe. |
| `decision_ref` | Action link to the decision's Event4 `event_id`. |
| `state_ref` | Opaque authoritative snapshot reference, not an authentication proof or receipt. |
| Collector identity, tenant, device, receipt, delivery sequence | Transport metadata outside Event4. |

`trace_id` and `span_id` occur only in the envelope. Observation correlation
contains request, response, turn, call, parent-observation, process-instance,
and delegation IDs. There are no duplicate locations or aliases, and missing IDs
remain missing.

## Findings, decisions, and actions

These families deliberately separate security meaning from policy and execution.

### Finding

A Finding has detector identity and bounded severity/category semantics. A
`policy_violation` is a finding kind, not a severity. An optional `risk_points`
value is one deterministic per-detector contribution in `0..100`; Event4 does
not define an aggregate risk score. The reserved aggregate-risk extension names
are `risk_score`, `aggregate_risk`, `risk_points`, and
`aggregate_risk_points`, and they cannot be used to introduce aggregate meaning.
Evidence is terminally privacy-projected.

### Decision and Action

The provider-neutral outcome vocabulary is:

```text
allow | observe | warn | require_approval | reprompt | block | remediate
```

For both decision and action, `requested` is the intended outcome and `effective`
is what the decision or adapter actually selected. A status of `degraded` is
required when they differ, together with an `unsupported` or `unknown`
capability, a limitation, and a degradation reason. Equal outcomes cannot be
marked degraded. A degraded result states what actually happened; it does not
claim that a block or approval occurred.

An Action is not proof that its Decision was fulfilled. Its stable semantic
`action_id` differs from the Event4 record `event_id`; `decision_ref` is
authoritative linkage, and requested outcomes must agree. Only an action with a
truthful success status records successful performance at the named enforcement
point. No enforcement runtime is activated by this architecture.

### Approval vocabulary (reserved, not implemented)

Approval state is exactly:

```text
required | requested | granted | denied | expired | cancelled
```

`pending` is a decision status, never an approval state. `approval_id` is the
authoritative, consumer-opaque, provider-neutral correlation value. Its bounded
syntax does not prove semantic opacity: producers must not encode a provider,
credential, or result in it, and consumers must not infer those meanings from
its characters.

An approval request is a pending decision with equal outcomes and
`approval_state: requested`. A resolution is a new evaluated decision using the
same ID and a terminal state. An approval-dependent action may be successful
only when its linked decision is granted with that same ID; required, requested,
denied, expired, and cancelled states require a truthful non-success status.
Provider, human workflow, authentication, and execution remain future concerns.

## Extensions and terminal validation

The only extension location is top-level `extensions`. Namespace keys are
lower-case, namespace-qualified, contain a dot, and are at most 128 characters;
there are at most 16 namespaces. Each namespace has at most 16 lower-case local
properties, each at most 64 characters. Values are scalars or arrays of at most
32 scalars, strings are at most 1,024 characters, the extension subtree is at
most 16,384 UTF-8 bytes, and it contains at most 512 scalar values. Nested
objects and nested arrays are not valid extension values.

Unknown structurally valid namespaces may be retained for consumers that do not
understand them, but terminal privacy still sanitizes or rejects unsafe content.
Extensions cannot redefine core fields, select a body, carry collector metadata,
or introduce aggregate risk. Reserved core names include `event_id`, `type`,
`schema_version`, the Event4 time names, `severity`, and `confidence`.

After terminal privacy transformation, the complete Event4 JSON must be no more
than **65,536 UTF-8 bytes** and no deeper than **8** object/array levels,
counting the root as level 1. Both limits are mandatory semantic checks because
portable JSON Schema cannot express them fully. A violation fails closed before
bytes are emitted, persisted, projected, or transported.

Structural JSON Schema validation is necessary but insufficient. A future
terminal boundary must, in order:

1. select a privacy-safe projection and assign `materialized_at` once;
2. run the pinned Draft 2020-12 schema with RFC3339 format checking;
3. check body/action pairing, identities, times, outcomes, approval lifecycle,
   cross-event references, and collisions;
4. enforce extension, byte, and depth limits; and
5. encode deterministic canonical UTF-8 JSON.

No bytes are returned or persisted on terminal failure. Validation context is
incremental across restarts and independent input batches: action references,
basis event IDs, approval transitions, and same-ID content hashes are not valid
merely because records share one file. Identical same-ID bytes are idempotent;
different bytes are an integrity collision.

See the [Event4 draft schema](../schemas/event4-draft.schema.json)
(**architecture draft / not runtime-supported**) for the structural shape. The
schema does not replace semantic or terminal validation.

## Event3 coexistence and managed boundary

Event3 remains supported and current. Event4 is independently versioned and does
not replace Event3 until explicit migration gates are satisfied. Existing
persisted/replayed Event3 bytes are unchanged, future semantics are not
backported, and Event3/Event4 are independent projections from common accepted
internal semantics rather than conversions of one another.

Managed metadata is prohibited in canonical Event4. Tenant, device,
authentication, authorization, routing, destination, retry, attempt, receipt,
host, index, source, sourcetype, headers, credentials, and delivery status
belong in a collector or destination envelope. Telltale remains standalone and
offline; a vendor-neutral collector is a future boundary, not a core dependency.
