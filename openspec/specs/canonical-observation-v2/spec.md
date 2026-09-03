# canonical-observation-v2 Specification

## Purpose
Define the I/O-free Canonical Observation v2 core domain types and scaffolding in `telltale-schema`, covering identity, lifecycle, provenance, capability, fidelity, facets, local structure, and validation. Assignment persistence is interface-only. This scope does not migrate adapters or implement Detection v2, Event 4, or telemetry/output v2; Event 3.0 remains the frozen external compatibility contract.
## Requirements
### Requirement: Closed typed observation bodies

The implementation MUST expose a closed `CanonicalObservationV2` domain model
with exactly the Message, Inference, Tool, ToolDefinition, MCP, Process, File,
Network, Browser, Runtime, Session, and Other families. A discriminated body
MUST determine its family, and construction MUST reject a family/stage mismatch
or a body that does not satisfy its family minimum.

#### Scenario: Valid family minimum

- **WHEN** a caller constructs a Message with a closed role and an observation
  stage of `observed`
- **THEN** construction succeeds and the observation kind is Message

#### Scenario: Invalid family/stage

- **WHEN** a caller combines a Tool body with the Message `observed` stage
- **THEN** construction fails with a non-sensitive invalid-stage error

#### Scenario: Unsupported Other entry

- **WHEN** a caller supplies an unknown Other registry version, kind, or
  classification, or a generic local key such as `other.payload`
- **THEN** construction fails closed

### Requirement: Explicit lifecycle, time, and correlation

The implementation MUST represent Tool stages separately as proposed, requested,
execution_started, execution_completed, or result_returned. It MUST require a
non-empty offset-bearing observed time, accept occurred time only when truthful
and valid, and MUST NOT synthesize occurred time or a missing correlation ID.
IDs and timestamps MUST reject path-derived IDs, empty timestamps, and malformed
values.

#### Scenario: Partial Tool lifecycle

- **WHEN** a source constructs only a Tool proposal or request
- **THEN** the resulting observation remains that stage and no execution,
  success, failure, or result stage is invented

#### Scenario: Missing occurrence time

- **WHEN** the source occurrence time is absent or invalid
- **THEN** observed time remains required and occurred time remains absent rather
  than falling back to observed time

#### Scenario: Correlation is optional and bounded

- **WHEN** a caller omits correlation or supplies a path-derived correlation ID
- **THEN** omission is accepted and the path-derived value is rejected without
  fabricating a replacement

### Requirement: Source and fact semantics remain distinct

Source provenance MUST require a non-empty adapter type and ID, an ingestion
mode, and fidelity. Fact provenance MUST be one of reported, parsed, derived,
inferred, or observed. Capability availability MUST be exactly supported,
unsupported, or unknown and independent of fact provenance and fidelity. Process,
File, and Network bodies MUST contain an operation or state, and at least one
populated operation or state field MUST have observed provenance at its matching
body path. Observed provenance on a non-activity field MUST NOT satisfy this
minimum.

#### Scenario: Parsed activity is not observed activity

- **WHEN** a Tool contains a URL, process name, or path parsed from command text
- **THEN** it remains a Tool observation with parsed/derived metadata and cannot
  satisfy a direct Network, Process, or File observation minimum

#### Scenario: Direct activity is accepted

- **WHEN** a direct process, file, or network fact has observed provenance and
  the family has its required operation/state fact
- **THEN** construction succeeds for that direct family

#### Scenario: Capability absence is explicit

- **WHEN** a capability query is unsupported or unresolved
- **THEN** it resolves to unsupported or unknown and is not treated as clean,
  false, or an observed occurrence

### Requirement: Governed facets and metadata

Facets MUST use only the governed canonical namespaces and MUST be value-only.
Every populated body field and facet MUST have exactly one matching FactMetadata
entry; extra or missing paths and prohibited sensitivity MUST be rejected.

#### Scenario: Tool carries parsed cross-family facets

- **WHEN** a Tool includes governed command, resource, network, or process facets
  with parsed or derived metadata
- **THEN** it remains a Tool observation and metadata is the sole authority for
  facet provenance and sensitivity

#### Scenario: Inline facet metadata is rejected

- **WHEN** a facet attempts to carry provenance, fidelity, or sensitivity inside
  its value object, or metadata has an arbitrary native path
- **THEN** construction fails with a metadata-boundary error

### Requirement: Bounded local evidence

Local structured values MUST be finite JSON-like values with NFC strings,
finite numbers, bounded depth/cardinality/UTF-8 bytes, registered semantic keys,
and optional bounded searchable derivatives. Local values MUST carry local
provenance and sensitivity. Opaque local references MUST reject exportable,
external, and telemetry retention classes, and no local type may be implicitly an
Event4/export type.

#### Scenario: Structured arguments are retained locally

- **WHEN** a Tool retains bounded structured arguments under `tool.arguments`
- **THEN** the structured value and optional searchable derivative remain
  distinct local evidence and the key is accepted

#### Scenario: Local bounds and retention fail closed

- **WHEN** a caller uses an unregistered local key, non-finite number, oversized
  value, prohibited sensitivity, or exportable reference retention
- **THEN** construction rejects it without including the raw value in the error

### Requirement: Deterministic privacy-safe identity

The implementation MUST derive a stable coordinate ID only from this exact
domain-separated canonical UTF-8 JSON tuple:

```text
["telltale:canonical-observation-coordinate-id-v1", adapter_type, adapter_id,
 coordinate_kind, coordinate_value, family, stage, child_ordinal]
```

It MUST retain the external form `obs:v2:sha256:<64 lowercase hexadecimal
digits>`. The tuple MUST NOT contain semantic values, semantic fingerprints,
fingerprint epochs, adapter versions, paths, filenames, session titles,
collection locations, privacy keys, HMAC material, or producer text.

Coordinate selection MUST be native_id, then an explicitly identity-scoped
source sequence, then an explicitly identity-scoped offset. A producer-local
sequence or offset is not a stable observation coordinate unless its uniqueness
namespace is itself stable and explicit. Bare producer coordinates remain
provenance only. Missing coordinates and missing protected assignment state
MUST fail with `replay_unverifiable`; no random or path-derived fallback is
allowed. Sensitive values MUST NOT be hashed unkeyed merely to create a stable
coordinate ID.

#### Scenario: Stable identity ignores semantic comparison material

- **WHEN** two stable-coordinate observations have the same adapter identity,
  scoped coordinate, family, stage, and child ordinal but different semantic
  content, adapter version, or fingerprint epoch
- **THEN** their observation IDs are equal and their semantic comparison reports
  mutation for same-epoch comparable content or incomparability for an epoch
  mismatch

#### Scenario: Stable identity is deterministic

- **WHEN** equivalent stable source input is normalized twice with the same
  adapter identity, scoped coordinate, family, stage, and child ordinal
- **THEN** both IDs equal `obs:v2:sha256:<64 lowercase hex digits>`

#### Scenario: Sensitive identity does not leak raw content

- **WHEN** a sensitive input is used with a stable coordinate and no keyed
  fingerprint is available
- **THEN** the stable ID contains no raw sensitive text and comparison is
  `Unavailable` rather than an unkeyed content hash

#### Scenario: Bare producer sequence is not identity

- **WHEN** a caller sets only a producer-local `source_sequence` or offset
- **THEN** construction fails with `replay_unverifiable` unless a native ID,
  explicitly scoped coordinate, or protected persisted assignment is present

#### Scenario: Distinct scoped namespaces do not collide

- **WHEN** two observations use ordinal zero in different valid identity
  namespaces
- **THEN** their stable observation IDs differ

#### Scenario: Coordinate namespace rejects path text

- **WHEN** an identity namespace is empty, contains a newline, slash,
  backslash, or `..`
- **THEN** construction rejects it with the existing `path_derived_id` code

#### Scenario: No stable coordinate fails closed

- **WHEN** native_id, identity-scoped source sequence, and identity-scoped
  offset are all absent and protected assignment state is unavailable
- **THEN** construction returns `replay_unverifiable` and creates no random ID

### Requirement: Protected assignment replay

Persisted assignment MUST continue to verify the complete semantic commitment
with its protected comparison key. Missing assignment state, missing key, or a
commitment mismatch MUST return `replay_unverifiable` or `replay_collision` as
currently defined. The coordinate identity amendment MUST NOT weaken assignment
verification or make an unkeyed assignment comparison appear equivalent.

#### Scenario: Matching assignment replays idempotently

- **WHEN** a persisted assignment contains the same observation ID and
  protected semantic commitment as the incoming observation
- **THEN** replay is accepted as idempotent

#### Scenario: Assignment state is unverifiable

- **WHEN** no stable coordinate exists and assignment state or its comparison
  key is missing
- **THEN** construction returns `replay_unverifiable`

#### Scenario: Changed assignment content collides

- **WHEN** complete semantic content changes under an existing assignment
- **THEN** construction returns `replay_collision` without exposing content

### Requirement: Event 3.0 and export boundary remain frozen

This capability MUST NOT modify Event 3.0 schemas, constructors, IDs,
serialization, privacy, durable bytes, replay behavior, parsers, detection, or
output. It MUST NOT provide a generic observation serializer or Event4 conversion;
the local core is scaffolding and not an external output contract.

#### Scenario: Existing Event 3.0 behavior is unchanged

- **WHEN** Event 3.0 schema and crate regression tests run after adding the v2
  module
- **THEN** the existing schema bytes and behavior remain unchanged

#### Scenario: Local evidence is not an export

- **WHEN** a caller holds a local structured value or opaque raw reference
- **THEN** it cannot be silently serialized as an Event4 or external type

### Requirement: Separate semantic comparison and identity basis

`IdentityBasis::StableSourceCoordinate` MUST contain only its domain,
coordinate kind, coordinate value, and child ordinal. It MUST NOT own semantic
fingerprints, fingerprint epochs, or adapter versions. The stable basis domain
MUST match `adapter_type:adapter_id`, without an adapter-version suffix.

The implementation MUST store semantic comparison state separately on the local
`CanonicalObservationV2` as either comparable fingerprint plus key epoch or
`Unavailable`. It MUST provide comparison verdicts `Equivalent`, `Mutated`, and
`Incomparable`: same-epoch equal comparable fingerprints are Equivalent,
same-epoch different comparable fingerprints are Mutated, and unavailable or
different-epoch material is Incomparable. Unavailable versus Unavailable MUST
NOT be Equivalent, and epoch mismatch MUST NOT be reported as mutation. This
comparison state MUST have no generic serde or export path and MUST be redacted
from Debug/Display output.

#### Scenario: Normal semantic change is compared separately

- **WHEN** two observations share a stable coordinate and comparable normal
  semantics but their body content differs
- **THEN** construction succeeds with the same observation ID and comparison
  returns `Mutated`

#### Scenario: Key epoch mismatch is incomparable

- **WHEN** two comparable observations share an identity coordinate but use
  different valid fingerprint epochs
- **THEN** their observation IDs are equal and comparison returns
  `Incomparable`, not `Mutated`

#### Scenario: Stable identity does not require HMAC

- **WHEN** normal facts have no producer key, or sensitive facts have no keyed
  fingerprints, but a valid stable coordinate exists
- **THEN** construction succeeds with a stable ID; normal facts are Comparable
  at epoch `none`, while missing sensitive comparison is `Unavailable`

### Requirement: Identity, correlation, and exported event identity remain distinct

`observation_id` MUST identify a canonical source fact, `session_id` MUST remain
a source/session correlation, and Event3/Event4 `event_id` MUST remain exported
event identity. None may be filled from a path, filename, collector value, or
another identity field. Event 3.0 remains frozen and v2 remains a local,
non-production foundation.

#### Scenario: Stable fact identity is not session correlation

- **WHEN** a stable source coordinate is scoped by a truthful session namespace
- **THEN** the namespace may populate `session_id` for correlation, but it is
  represented in the coordinate tuple only as the explicit coordinate scope

#### Scenario: Event 3.0 remains unchanged

- **WHEN** v2 identity and comparison tests run alongside Event 3.0 regressions
- **THEN** Event 3.0 schema bytes, IDs, serialization, privacy, and delivery
  behavior remain unchanged

### Requirement: Canonical construction helpers remain source-neutral

The schema MUST provide only the small source-neutral helpers required by both
reference adapters: conversion from a `serde_json::Value` to bounded
`JsonValue`, Normal `FactMetadata::reported()` and `FactMetadata::parsed()`
constructors, and `CorrelationId::source_reported`. These helpers MUST fail
closed on unsupported/non-finite values and MUST NOT introduce JSONL,
filesystem, provider, lifecycle, adapter registry, or export abstractions.

#### Scenario: Source JSON conversion is bounded and safe

- **WHEN** either reference adapter converts a finite JSON value through the
  shared helper
- **THEN** the equivalent bounded `JsonValue` is produced, while unsupported
  numeric values return a code-only observation error
