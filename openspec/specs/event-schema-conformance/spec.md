# event-schema-conformance Specification

## Purpose
Define the conformance and compatibility evidence for the stable native Event
3.0 scanner/detection output contract. This specification covers parity,
terminal privacy, timing documentation, and the boundaries around durable and
SIEM output. It does not introduce a new Event 3.0 field or runtime semantic.
## Requirements
### Requirement: Native constructors SHALL conform to the strict Event 3.0 schema

The native Event 3.0 constructor set MUST cover detection, standard activity,
install-inventory activity, session-risk summary, health, scanner error,
operational alert, process chain, and correlation. Each constructor output
MUST pass through the terminal Event serialization boundary, parse as one JSON
object, contain no top-level JSON nulls, and validate against the current strict
Event 3.0 schema with `unevaluatedProperties` enforcement. The current reviewed
source-level constructor inventory MUST carry explicit descriptors and corpus
cases for all nine native families, and each descriptor's wire `event_type` MUST
agree with its builder. The registry's wire-event projection MUST remain aligned
with the current schema, so a new wire event type is visible as drift. A new
same-event-type subfamily cannot be mechanically detected by this descriptor
check; reviewer and test maintenance MUST add its descriptor and corpus case.

#### Scenario: Complete native constructor corpus validates

- **WHEN** the nine native constructor families are exercised with synthetic
  valid inputs and terminal-serialized
- **THEN** each output is valid JSON, has the declared family `event_type`, has
  no top-level null, and passes strict current Event 3.0 schema validation

#### Scenario: Reviewed constructor inventory stays explicit

- **WHEN** the current nine native constructors and their explicit descriptors
  are reviewed and exercised
- **THEN** every constructor has a matching family/privacy corpus case, the
  two activity subfamilies remain distinct, and the registry's wire projection
  matches the Event 3.0 schema

### Requirement: Event 3.0 field parity SHALL be explicit and closed

The native domain model, terminal wire representation, current schema, privacy
surface, constructor coverage, synthetic corpus, and family applicability MUST
be recorded for every Event 3.0 field in the parity matrix. Fields omitted by a
family MUST be absent from that family's terminal JSON, and optional fields
MUST be omitted rather than emitted as null. Existing `response`, risk fields,
rule IDs/categories/classes/signal types/intents, evidence, process,
correlation, health, and scanner-error fields MUST remain represented with
their current meaning.

#### Scenario: Optional fields are omitted from sparse output

- **WHEN** a native constructor receives a valid input without an optional
  metadata, path, response, process, or family-specific value
- **THEN** terminal JSON omits that field, emits no JSON null, and remains valid
  for its strict family branch

#### Scenario: Workspace is not an Event 3.0 field

- **WHEN** native Event 3.0 output is serialized or a JSON record containing a
  top-level `workspace` property is checked against the current schema
- **THEN** native output contains no such property and strict validation
  rejects the injected property; workspace MUST NOT be added to the Event 3.0
  schema

### Requirement: The install-inventory activity variant SHALL remain distinct

The install-inventory constructor MUST continue to emit the `activity`
`event_type` with its scanner/client/check/status invariants and MUST validate
against the install-inventory activity branch rather than the standard activity
branch. Its metadata-only evidence and tags MUST remain present and its risk
score MUST remain zero.

#### Scenario: Sparse install inventory validates its dedicated branch

- **WHEN** install inventory has one synthetic metadata-only evidence item and
  no optional session fields
- **THEN** the terminal `activity` JSON validates as install inventory with
  `client=install_inventory`, `session_id=scanner`, and no top-level
  `workspace`

### Requirement: Terminal sanitization SHALL be deterministic and idempotent

Every externally reachable textual Event 3.0 field that can be changed after
construction MUST cross the terminal privacy boundary before emitted bytes are
returned. Repeated terminal serialization of the same Event MUST produce
byte-identical JSON, and terminalizing already terminal-safe values MUST NOT
re-hash or otherwise change them. Synthetic credential, path, URL, diagnostic,
response, risk-rationale, process, identifier, and timing-marker cases MUST
remain absent or safely transformed according to their existing context policy.
Native `telltale_version` MUST equal the trusted compile-time `TELLTALE_VERSION`
on terminal serialization; any public mutation, including credential-bearing
SemVer prerelease/build metadata, MUST be replaced by that current package
version rather than a fabricated hash version. Historical JSONL/Elastic export
MUST retain its existing shape and MAY preserve a safe historical package
version.
`source_path_hash` MUST preserve an established 64-character lowercase
hexadecimal SHA-256 value and MUST deterministically hash any other non-empty
value before emission. `mitre_attack_techniques` MUST preserve canonical
ATT&CK technique shapes `T1234` and `T1234.001`; any other value MUST become a
deterministic schema-compatible `mitre:<sha256>` identifier. Both transformations
MUST be idempotent.
`source_counts` MUST preserve known `<client>.<source-kind>` keys and MUST map
other keys to deterministic schema-compatible `source_count:<sha256>` keys.
Transformed-key collisions MUST receive deterministic numeric suffixes so each
source count remains a separate entry with its original value. This correction
MUST be idempotent.

#### Scenario: Externally mutated text is sanitized on every route

- **WHEN** an Event's public response, process, rationale, source-derived
  identifier, or invalid source-time fields are mutated after construction
- **THEN** direct Event serialization and the explicit emittable representation
  produce identical deterministic bytes with the controlled synthetic marker
  absent from the serialized JSON

#### Scenario: Repeated terminal serialization is stable

- **WHEN** the same raw Event is terminal-serialized multiple times
- **THEN** every byte sequence is identical and the raw in-memory Event remains
  unchanged for local detection/state use

#### Scenario: Version, source hashes, and ATT&CK techniques cannot bypass terminal privacy

- **WHEN** a public constructor Event is mutated with synthetic non-canonical
  credential-bearing SemVer version, source-hash, and technique values,
  alongside a valid lowercase-hex source hash and a valid `T1234.001` technique
- **THEN** direct terminal serialization and canonical JSONL contain neither
  synthetic value, emit the trusted current package version, preserve the
  canonical values, emit deterministic `evidence_hash`/`mitre:<sha256>` fallbacks,
  remain schema-valid, and produce identical bytes on repeated sanitization

### Requirement: Invalid controlled fields SHALL fail closed at terminal serialization

After sanitizable free-text, noncanonical hash, MITRE, and source-count values
have crossed their existing terminal transformations, native Event serialization
MUST reject any noncanonical closed or schema-controlled value before invoking
the wire serializer. This includes `schema_version`, `time_source`,
`time_confidence`, `event_type`, `severity`, `confidence`,
`detection_classes`, `signal_types`, `analytic_intents`, `risk_entity_type`,
`component`, `check_name`, `status`, `response.recommended_action`,
`response.escalation`, `process.rule_severity`, and family-controlled
`client`, `session_id`, correlation dimensions, and install-inventory tags.
The returned serialization error MUST be generic and privacy-safe: it MUST NOT
include the invalid field name or value. Runtime validation MUST use local
code-owned constraints rather than loading a filesystem schema. Schema
validation remains test evidence for the boundary, not the runtime boundary.

#### Scenario: Invalid controlled mutations produce no direct bytes

- **WHEN** a public Event is mutated with a synthetic marker in each reviewed
  closed or family-controlled field
- **THEN** direct and explicit-emittable serialization fail with the same
  generic privacy-safe error and neither the marker nor any serialized Event
  bytes are returned

#### Scenario: Invalid controlled mutations produce no JSONL bytes

- **WHEN** a JSONL batch contains an Event with a noncanonical controlled value
- **THEN** canonical batch serialization fails before the target is opened or
  written, without echoing the invalid marker; remote sink serializers inherit
  the same terminal failure before transport

### Requirement: Native terminal identity and observation times SHALL remain canonical

Native `Event` and in-memory `HistoricalDerivedEvent` serialization MUST
validate `event_id`, `timestamp`, `observed_at`, and `ingested_at` before invoking
the wire serializer. `event_id` MUST match the exact Event 3.0
`telltale-` UUID-v4 syntax and length. Each top-level timestamp MUST be accepted
by the local canonical RFC3339/Event 3.0 timestamp parser used by native
construction and accepted by the Event 3.0 schema. Invalid public values MUST
fail closed with the same generic privacy-safe serialization error and MUST NOT
be transformed into another identity or time value. `event_time` MUST continue
to use its existing terminal policy: parseable RFC3339 values and canonical
`invalid-event-time` markers are preserved, while other values become
deterministic `invalid-event-time` markers. Correlation related-detection text
and any timeline timestamp surfaces MUST use that same event-time terminal
policy; neither path may emit raw invalid timestamps.

#### Scenario: Invalid identity and observation times produce no direct bytes

- **WHEN** a public Event or in-memory historical-derived Event is mutated with
  a synthetic marker in `event_id`, `timestamp`, `observed_at`, or `ingested_at`
- **THEN** direct terminal serialization fails with the generic privacy-safe
  error, does not echo the marker, and returns no serialized bytes

#### Scenario: Invalid identity and observation times produce no JSONL bytes

- **WHEN** a JSONL batch contains a valid Event followed by an Event with an
  invalid identity or top-level timestamp
- **THEN** batch serialization fails before the target is opened or written,
  without echoing the marker or partially persisting the valid Event

#### Scenario: Invalid event-time text remains terminal-safe

- **WHEN** an Event contains a non-RFC3339 `event_time` or related-detection
  timestamp text
- **THEN** terminal serialization emits only the deterministic
  `invalid-event-time` marker and repeated native or historical-derived
  serialization remains byte-identical

### Requirement: Event 3.0 timing semantics SHALL remain coarse and documented

For native events, `timestamp` MUST use a valid source timestamp normalized to
UTC millisecond precision when available. Missing or unparseable source
timestamps, and source timestamps more than five minutes in the future, MUST
fall back to local observation time and record `time_override_reason` with the
existing `time_source` and `time_confidence` semantics. `event_time` MUST retain
the available source/derived time, while `observed_at` and `ingested_at` MUST
represent local scan/ingestion time rather than source event time.

#### Scenario: Valid source time is normalized

- **WHEN** a source provides a valid offset-bearing RFC3339 timestamp within
  the accepted future window
- **THEN** `timestamp` and `event_time` use its UTC millisecond representation,
  `time_source` is `source`, and no override reason is emitted

#### Scenario: Future or missing source time falls back safely

- **WHEN** a source timestamp is missing, unparseable, or more than five
  minutes in the future
- **THEN** `timestamp` uses local observation time, `time_source` and
  `time_confidence` identify the fallback, and `time_override_reason` records
  the bounded reason without changing detection/scoring semantics

### Requirement: Durable and SIEM projections SHALL preserve canonical bytes

Canonical JSONL MUST remain the terminal-sanitized Event 3.0 durable first
write. When durable downstream delivery is enabled, outbox ingestion and replay
MUST use those exact canonical bytes rather than reconstructing or reprojecting
the Event. Splunk HEC MUST wrap the canonical payload and derive envelope time
from canonical `timestamp`; Elastic MUST use the canonical payload with
`event_id` as `_id`. This conformance change MUST NOT alter delivery policy,
retry, outbox, or transport behavior.
Canonical output and event identity from the reviewed constructors remain
unchanged. Noncanonical public source hashes, MITRE values, and source-count
keys, and mutated native `telltale_version` values, are corrected before a
newly emitted event's JSONL first write, so those emitted/persisted bytes
intentionally change. Persisted historical bytes MUST never be replay-time
reserialized. Invalid public controlled mutations are rejected before the
JSONL first write and are not mapped to another event family or invented
semantic value. Invalid public `event_id`, `timestamp`, `observed_at`, and
`ingested_at` mutations are rejected by the same terminal boundary, including
through in-memory historical-derived serialization; valid constructor bytes
remain unchanged.

#### Scenario: Durable replay uses persisted terminal bytes

- **WHEN** a canonical Event is accepted for durable JSONL and later
  reconciled/replayed after restart
- **THEN** the outbox payload is byte-identical to the terminal JSONL Event and
  contains no raw source text or controlled synthetic privacy marker

#### Scenario: Sink projection does not extend the Event schema

- **WHEN** the same Event is delivered to Splunk HEC or Elastic
- **THEN** sink metadata remains outside the canonical Event payload, HEC time
  is derived from canonical `timestamp`, and Elastic `_id` is the Event
  `event_id`

#### Scenario: Historical export preserves safe historical version metadata

- **WHEN** a historical JSONL record contains a schema-valid prior
  `telltale_version`
- **THEN** JSONL/Elastic export preserves that safe historical version while
  applying the existing historical sanitization and does not replace it with
  the native current package version

### Requirement: Event 3.0 SHALL be explicitly frozen

Event 3.0 MUST be treated as stable external compatibility for the v0.6
scanner and deterministic detection layer. After this freeze, only
security/privacy/correctness/documentation/compatibility fixes MAY change its
implementation or evidence. New runtime semantics—including observation
lifecycle, gateway telemetry, decisions, actions, approvals, runtime/browser/
OS context, or equivalent future context—MUST be specified under Event 4.0 or
future architecture and MUST NOT be added implicitly to Event 3.0.

#### Scenario: Existing detection and response meaning is preserved

- **WHEN** a native detection or process-chain event is emitted after the
  freeze
- **THEN** response metadata, risk, rule IDs, categories, classes, signal
  types, intents, evidence, process context, and correlation/health/error
  semantics retain their Event 3.0 meaning

#### Scenario: New runtime semantics require a separate contract

- **WHEN** a future feature needs observation lifecycle, gateway, decision,
  action, approval, runtime, browser, or OS-context telemetry
- **THEN** it is deferred to a separately reviewed Event 4.0/future-architecture
  contract and does not extend the frozen Event 3.0 wire
