# Telemetry and Output Architecture

> **Status:** **Accepted architecture.** This is the reviewed intended future
> telemetry/output contract. **Current implementation:** Event4, CanonicalPayload,
> telemetry profiles, and dual Event3/Event4 output are **not implemented**.
> **Existing compatibility:** Event 3.0 remains the current frozen external
> compatibility and output contract.

> **Event 3.0: FROZEN / CURRENT COMPATIBILITY CONTRACT**

Current Event3 JSONL and sink behavior is documented in
[Telemetry output](telemetry-output.md). Nothing on this page changes current
defaults or activates a future emitter, profile, serializer, collector, or
transport.

## Pipeline

```text
internal semantic truth
        ↓
event selection / telemetry policy
        ↓
privacy + export transformation
        ↓
Event3 compatibility projection and/or Event4 future projection
        ↓
terminal validation + canonical serialization
        ↓
CanonicalPayload
        ↓
durable first-write
        ↓
destination projection
        ↓
transport
```

Event3 and Event4 branches are independently eligible. Neither is canonically
derived from the other. Selection, privacy, validation, serialization,
durability, projection, and transport are separate responsibilities.

## Detection policy versus telemetry policy

Detection policy owns detector configuration, evaluation, and Signal/Finding
creation. Telemetry policy owns family selection, evidence representation,
omission, redaction, profile verbosity, diagnostics, coalescing, and destination
eligibility. A profile cannot change a detector match, evaluation status,
Finding existence, severity, or risk contribution.

Suppression/deduplication in Detection v2 may control detector, Signal, or
Finding materialization. Export suppression may omit or coalesce selected
telemetry, but it never means that a Finding did not exist. “Not selected” and
“selected then delivery failed” remain distinct states. Durable policy cannot
silently lose selected telemetry.

Future default selection is Finding-centered: Findings are normally eligible,
Decision/Action are eligible when that subsystem exists, observations are
selective, Session/State/Health are profile-driven, summaries are derived, and
Signals/debug data is internal unless an explicitly sanitized diagnostic mode
allows it.

## Profiles

The only accepted future profile names are `minimal`, `standard`, `verbose`, and
`forensic_safe`. `standard` is the future default; current product defaults are
unchanged.

| Surface | `minimal` | `standard` | `verbose` | `forensic_safe` |
| --- | --- | --- | --- | --- |
| Session | Lifecycle | Lifecycle | Lifecycle | Lifecycle |
| Observation | None except Finding evidence references | Inference/tool metadata; bodies off | Richer sanitized metadata and excerpts | Richer sanitized structure |
| Finding | Security/high-value; low-value may be omitted | All findings | All findings | All findings |
| Decision/Action | When present | When present | When present | When present |
| State | Failures only | Change, initial snapshot, compact heartbeat | Richer heartbeat | Richer heartbeat |
| Health | Failures only | Change and compact heartbeat | Richer heartbeat | Richer heartbeat |
| Summary | Replacement for omitted repetitive telemetry | Derived/profile driven | Derived/profile driven | Derived/profile driven |
| Signal/debug | Internal | Internal | Internal | Sanitized diagnostic only when enabled |
| Evidence | Reference, hash, classification, omission | Plus count and bounded excerpt when allowed | Excerpt up to 512 characters | Same, still sanitized |

The profile controls export only. It cannot fabricate unavailable fields, expose
raw secrets, or let a destination override privacy. Evidence is limited to 32
items per Event4 Finding; a richest-profile redacted excerpt is at most 512
characters. The [telemetry profile draft schema](../schemas/telemetry-profile-draft.schema.json)
is an **architecture draft / not runtime-supported**.

## Privacy and export precedence

The effective configuration precedence is:

```text
built-in defaults
    ↓
telemetry profile
    ↓
organization/local export policy
    ↓
destination configuration
    ↓
privacy/emergency fail-safe (strongest)
```

The semantic order is source sensitivity, canonical eligibility, profile,
explicit export policy, terminal privacy transformation, terminal validation,
and canonical bytes. Conflicts fail closed or choose the more restrictive
result. Rules may request evidence but cannot authorize it. Raw prompts, tool
arguments/results, secrets, full sensitive paths, and native attachments are
not exportable merely because a rule referenced them.

Safe evidence forms are `reference`, `hash`, `classification`, `count`, and a
bounded `redacted_excerpt`. A redacted structured summary may combine those
forms; omission is no evidence item. No sink receives a raw semantic object and
performs its own weaker privacy pass.

## Event4 terminal boundary

The future terminal boundary is conceptually:

```text
validate_terminal(candidate, context) -> AcceptedTerminalEvent | Event4ValidationError
```

An emitter constructs a semantic candidate without rerunning detection,
inferring facts, or adding destination metadata. Selection and export policy
choose eligibility; privacy transformation produces an idempotent safe
candidate; then schema, format, Event4 semantic, reference, extension, 65,536
byte, and depth-8 checks run. `materialized_at` is assigned once and retained on
replay. The incremental validation context is updated only after acceptance.

Invalid or unsafe output fails closed before durable write. No terminal bytes or
partial durable record are returned. Terminal privacy is a required boundary,
not a destination feature.

## Canonical serialization and CanonicalPayload

Future canonical JSON is deterministic compact UTF-8 JSON. For
`event4-json-v1`, closed objects use Event4 contract property order; open maps
normalize keys to NFC and sort them; arrays preserve item order; absent optional
keys are omitted. Non-finite numbers are rejected. Destination wrappers are not
part of canonical bytes.

`CanonicalPayload` is transport-neutral durable content, not another semantic
event and not a transport envelope:

| Field | Meaning |
| --- | --- |
| `payload_schema_version` | CanonicalPayload envelope version, initially integer `1`; distinct from Event3/Event4 schema version. |
| `event_id` | Copied from the terminal event; never a new identity. |
| `content_type` | At least `application/vnd.telltale.event3+json` and `application/vnd.telltale.event4+json`. |
| `content_schema_version` | `3.0` or `4.0`, independent of binary and payload-envelope versions. |
| `canonical_bytes` | Exact terminal JSON bytes. |
| `content_hash` | Lowercase 64-hex SHA-256 of those exact bytes. |
| `serializer_id` | Version-aware identity of the encoder. |

Event family/type remains inside the bytes. CanonicalPayload must not contain
tenant/device identity, authentication, destination credentials, retry state,
collector receipt, Splunk/Elastic fields, delivery status, or attempt IDs.

Replay preserves exact canonical bytes, content type/version, event ID, hash,
serializer identity, and Event4 `materialized_at`. It never reconstructs from
newer structures, reruns interpretation or privacy, regenerates materialization
time, or changes identity/hash. Destination projections may be regenerated from
the immutable payload plus destination configuration. Existing Event3 payloads
remain exact Event3 content; wrapping them later must not rewrite their bytes.

## Emitters and projections

Future emitters are Session, Observation, Finding, Decision, Action, State,
Health, and Summary emitters. They consume accepted semantics and produce
Event4 candidates. They do not rerun detection, infer missing facts, bypass
privacy, inspect sink configuration, embed destination metadata, or repeat large
authoritative inventories.

Projection converts CanonicalPayload into a destination request/body without
changing canonical meaning. Transport performs I/O, authentication I/O,
endpoint handling, retries, and response handling. Transport does not interpret
semantics, select evidence, rewrite fields, or apply privacy. Unsupported
payload versions or destinations are explicitly blocked/dead, never coerced.

### Destination boundaries

Future destination projections, when implemented, follow these boundaries:

- **Splunk:** Event4 remains intact inside the HEC `event` field. `host`,
  `index`, `sourcetype`, `source`, and request `time` are projection metadata.
  `_time` uses `occurred_at` when present, otherwise `observed_at`; never
  collector `received_at` or `materialized_at`.
- **Elastic:** Event4 remains intact in `_source`; Event4 `event_id` is the
  natural `_id` unless a later contract changes it. Index mappings cannot
  require Event4 changes or expand evidence.
- **JSONL/file:** Canonical JSONL is one canonical event byte sequence per line,
  not a CanonicalPayload envelope. File transport preserves those bytes. Durable
  metadata is separate.
- **stdout:** Machine output is canonical serialization or an explicitly
  documented machine format. Human diagnostics remain separate.
- **Collector:** Tenant, device, authentication/routing, destination, retries,
  attempts, receipts, host/index/source metadata, headers, credentials, and
  delivery status remain outside Event4 and CanonicalPayload.

The vendor-neutral collector boundary is future work. Telltale remains
standalone/offline, and a managed adopter owns collector/server, tenancy,
authentication, deployment, encrypted persistence, fleet, cloud, and receipt
concerns around—rather than inside—the canonical payload. Emusary is not a
Telltale core dependency.

## Durability, multi-sink delivery, and failure semantics

The first durable representation of selected telemetry is the terminally
privacy-transformed, validated canonical payload bytes. Required durable-write
failure prevents external delivery. One immutable CanonicalPayload may feed
multiple destinations, each with independent delivery state. A sink failure does
not mutate shared bytes or another sink's state.

Selection omission is not an error. Privacy/export, validation, serialization,
and required durability failures fail closed. Projection rejects unsupported
content or destinations explicitly. Transport retries without changing the
payload bytes.

Delivery health is distinct from runtime health, detector diagnostics, and
destination failure details. A delivery alert is never put in the failed sink's
replay queue. An independently dispatched health event must use a path that
cannot recursively enqueue into the same failing destination; if that alert
fails, no further alert is generated. This anti-recursion rule prevents a sink
failure from creating an infinite telemetry loop.

## Compatibility

Event3 remains supported, current, and frozen. Existing persisted/replayed
Event3 bytes are unchanged. Event4 is independently versioned and does not
replace Event3 until explicit migration gates are satisfied. Future semantics
are not backported to Event3. Event3 and Event4 are independent projections
from common accepted internal semantics, not canonical conversions of each
other. Current Event3 JSONL, Splunk, Elastic, and durable behavior remain in
[Telemetry output](telemetry-output.md).
