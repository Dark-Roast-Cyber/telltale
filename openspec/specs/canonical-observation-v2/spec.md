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

The implementation MUST derive IDs only from a domain-separated canonical UTF-8
JSON identity tuple using NFC strings, compact separators, sorted object keys,
unescaped non-ASCII UTF-8, and SHA-256 lowercase hexadecimal output. Stable
coordinate selection MUST be native_id, then source_sequence, then offset; no
random, path, filename, batch, collector, or inferred-parent fallback is
allowed. Sensitive values MUST enter semantic identity only as structural
location, sensitivity, and a keyed digest.

#### Scenario: Stable identity is deterministic

- **WHEN** equivalent stable source input is normalized twice with the same
  family, stage, semantic fingerprint, epoch, and child ordinal
- **THEN** both IDs equal `obs:v2:sha256:<64 lowercase hex digits>`

#### Scenario: Sensitive identity does not leak raw content

- **WHEN** a sensitive input changes while keyed identity material is used
- **THEN** the derived identity input contains no raw sensitive text and the
  resulting identity changes through the protected digest

#### Scenario: No stable coordinate fails closed

- **WHEN** native_id, source_sequence, and offset are all absent and protected
  assignment state is unavailable
- **THEN** construction returns `replay_unverifiable` and creates no random ID

### Requirement: Protected assignment replay

The implementation MUST provide only an interface-level protected assignment
abstraction for this slice. Assignment comparison commitments MUST use
HMAC-SHA256 over complete canonical semantic content, while comparison keys and
commitments MUST remain outside the observation and identity basis. Matching
assignment and commitment MUST be idempotent; changed content, missing state, or
missing comparison key MUST fail closed.

#### Scenario: Matching assignment replays idempotently

- **WHEN** a persisted assignment contains the same observation ID and protected
  semantic commitment as the incoming observation
- **THEN** replay is accepted as idempotent

#### Scenario: Changed assignment content collides

- **WHEN** content changes under an existing assignment reference
- **THEN** replay is rejected as a collision and raw content is absent from the
  error

#### Scenario: Assignment state is unverifiable

- **WHEN** assignment state or its comparison key is unavailable
- **THEN** replay returns `replay_unverifiable` and does not accept an opaque ID

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
