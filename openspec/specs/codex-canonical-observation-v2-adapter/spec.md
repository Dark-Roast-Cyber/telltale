# codex-canonical-observation-v2-adapter Specification

## Purpose
This specification covers the Codex adapter path. The authoritative public
acquisition API reuses its native interpretation and Canonical Observation v2
mapping for production source evaluation. Record-level compatibility parsing
remains available; Event 3.0 remains the external projection.
## Requirements
### Requirement: One Codex-native interpretation

The Codex adapter MUST read each registered Codex JSONL source once into one
bounded Codex-specific native interpretation. That interpretation MUST retain
enough ordered structure for both the retained `ParsedRecord` /
`NormalizedRecordV1` compatibility projection and Canonical Observation v2.
Production source evaluation MUST use canonical acquisition without routing
through compatibility records.

#### Scenario: One read preserves legacy output

- **WHEN** a valid Codex JSONL source is extracted
- **THEN** legacy record count, order, metadata, kind, flattened arguments,
  content, and filename-stem session fallback remain unchanged

### Requirement: Three source identities remain distinct

The canonical projection MUST accept only `ClientId::Codex` with the matching
source identities and kinds `codex.sessions`/`Jsonl`,
`codex.archived_sessions`/`ArchivedJsonl`, and
`codex.headless_sessions`/`HeadlessJsonl`. It MUST use adapter type `codex`, the
actual source ID as adapter ID, `SessionStore` ingestion, no adapter version or
path identity, and `PartialStructured` fidelity. It MUST NOT deduplicate
observations across source IDs.

#### Scenario: Source identity is represented

- **WHEN** the same native shape is projected through the archived source
- **THEN** provenance uses `codex.archived_sessions`, `ArchivedJsonl`, and no
  live/archive deduplication is attempted

### Requirement: Legacy behavior remains equivalent

Codex legacy extraction MUST preserve current response-item unwrapping,
event-message flattening, generic tool classification, headless `session_meta`
fallback, unknown-discriminator `RecordKind::Other`, and object-envelope
`SchemaDrift` behavior. Canonical mapping failures MUST NOT become production
`ParseError` outcomes.

#### Scenario: Canonical failure is isolated

- **WHEN** an in-scope Codex record fails canonical mapping
- **THEN** legacy parsing of the same source remains successful and unchanged

### Requirement: Canonical session identity is source-reported

For each registered Codex source, the v2 projection MUST use
`effective_session_id` as the namespace for that record's zero-based JSONL
ordinal. The effective value MUST come only from a source-reported
`session_id`, `sessionID`, or `sessionId` on the record, or from a prior
`session_meta` that explicitly supplied one. A bare producer ordinal MUST remain
provenance only. If no truthful session ID exists, v2 MUST not use a filename,
path, project directory, or legacy fallback and MUST fail with
`replay_unverifiable`; legacy parsing retains its filename-stem behavior.

#### Scenario: Session metadata scopes later records

- **WHEN** a Codex `session_meta` reports a session ID and a later record omits
  it
- **THEN** the later v2 ordinal is scoped by that source-reported ID and its
  canonical session correlation remains source-reported

#### Scenario: Truthful absence fails closed

- **WHEN** `session-a.jsonl` contains no source-reported session ID
- **THEN** legacy parsing retains `session-a`, while v2 returns
  `replay_unverifiable` and creates no collision-prone ID

#### Scenario: Session metadata is inherited

- **WHEN** a session metadata record reports `session_id` and a later message
  omits it
- **THEN** the later canonical message carries that source-reported session ID

#### Scenario: Truthful absence is preserved

- **WHEN** a source has no source-reported session ID
- **THEN** v2 omits `session_id` while legacy parsing retains its file-stem
  fallback

### Requirement: Truthful messages preserve order

User and assistant records MUST produce `MessageObserved` observations with
truthful user/assistant roles. Simple records, event-message payloads, and
response-item messages MUST be supported. Ordered `input_text`, `output_text`,
and supported tool content blocks MUST remain ordered content parts. Unknown
roles and in-scope unknown content blocks MUST fail closed. When one source
record emits a message and tools, the message MUST be emitted first, followed
by tools in native content order.

#### Scenario: Response item retains ordered message parts

- **WHEN** a response item contains output text followed by a tool-use block
- **THEN** one assistant Message retains both parts and precedes the requested
  Tool observation

### Requirement: Tool lifecycle is conservative

`tool_call`, `custom_tool_call`, `function_call`, and content-block `tool_use`
MUST map to Tool with `ToolRequested`. `tool_result`,
`custom_tool_call_output`, `function_call_output`, and supported content-block
results MUST map to Tool with `ToolResultReturned` when a result
or explicit error state is returned. Generic `type:tool` running state MUST map
to a conservative request; completed/error or explicit output/error MUST map to
`ToolResultReturned`. The adapter MUST NOT emit ToolProposed,
ToolExecutionStarted, ToolExecutionCompleted, inferred success, or a
source-success status. A state-only generic record MAY use parsed canonical
`Unknown` status solely to satisfy the Tool body's minimum without claiming
execution or success.

#### Scenario: Generic completion does not claim success

- **WHEN** a generic tool reports `state.status: completed` without an explicit
  result
- **THEN** v2 does not emit an execution-completed or successful tool stage

### Requirement: Structured tool values and optional linkage are preserved

Structured tool arguments and results MUST remain structured `JsonValue` values
when the source provides objects or arrays; source strings MUST remain strings.
`custom_tool_call.input` MUST remain its native JSON-encoded string in
`tool.arguments`; a parsed derivative may be used only for a separate governed
facet. Source call IDs from custom calls/outputs and content-block IDs MUST be
copied as `SourceReported` correlation when present. Missing IDs MUST be valid
absence and MUST NOT be hashed, fabricated, or treated as a mapping error.

#### Scenario: Native string input is not replaced

- **WHEN** a custom tool call has `input` equal to a JSON-encoded string
- **THEN** `tool.arguments` is a JSON string and any parsed command facet is
  separate from that native value

### Requirement: Metadata and facets remain bounded

Every populated canonical body field and facet MUST have exactly one matching
`FactMetadata` entry. The adapter MAY add only clear `command.text` and
`resource.path` Tool facets, with parsed provenance, and MUST never emit File,
Process, Network, Session, or Inference observations from those facets or from
Codex metadata. `payload.source` is metadata only and MUST NOT imply execution.

#### Scenario: Command and path facets do not create activity

- **WHEN** a tool argument contains a command or `file_path`
- **THEN** the values remain Tool facets and no File, Process, or Network family
  is emitted

### Requirement: Capabilities and time are explicit

Every v2 observation MUST require the provided `ObservedAt`, preserve valid
source timestamp as `occurred_at` only, and use capability overrides exactly as
ToolCall supported, UserContext supported, and ToolExecution unsupported.
Model/provider/agent metadata MUST NOT emit Inference observations.

#### Scenario: Acceptance and source clocks differ

- **WHEN** the source timestamp and explicit observed time are different valid
  RFC3339 values
- **THEN** `occurred_at` uses the source value and `observed_at` uses the option

### Requirement: Deterministic replay identity

Codex v2 IDs MUST use the coordinate-only tuple and MUST remain unchanged for
semantic content, adapter-version provenance, or privacy-key epoch changes under
the same effective session and ordinal. Semantic comparison MUST use the
separate local comparison state; different comparison epochs are incomparable,
not mutation. Artifact path and filename MUST not participate.

#### Scenario: Same ordinal in different sessions is distinct

- **WHEN** two Codex artifacts each begin at ordinal zero but report different
  effective session IDs
- **THEN** their v2 observation IDs differ

#### Scenario: Artifact rename or move is harmless

- **WHEN** identical synthetic Codex JSONL bytes are projected from two
  filenames or directories with the same truthful source session
- **THEN** corresponding v2 IDs are identical

#### Scenario: Replay is stable

- **WHEN** a Codex source is projected twice with the same `ObservedAt`
- **THEN** observation IDs, source sequences, and child ordinals are identical

### Requirement: Unknown input fails closed without leakage

Unknown explicit discriminators MUST return `unknown_discriminator`, and
unknown content blocks MUST return `unknown_content_block`, while legacy
unknown discriminators remain `Other`. Source parse/schema errors MUST remain
isolated source errors. Canonical error `Display` and `Debug` MUST NOT contain
prompts, tool arguments/results, paths, secrets, or arbitrary source payloads.

#### Scenario: Unknown discriminator is safe

- **WHEN** a record contains an unsupported explicit discriminator and synthetic
  source text
- **THEN** v2 rejects it with a safe mapping code and legacy returns `Other`

### Requirement: Canonical production and Event 3.0 compatibility

Production scanning MUST consume Codex Canonical Observation v2 through the
shared runtime. Parser registration, exact source identity, Event3 schema and
privacy behavior, and already-persisted Event3 data MUST remain compatible.
New canonical evidence, hashes, severity, and constructor-generated IDs/times
need not be byte-identical to legacy output.

#### Scenario: Production uses canonical acquisition

- **WHEN** the normal Codex scanner processes a registered source
- **THEN** it acquires Canonical Observation v2 directly without constructing
  normalized compatibility records

### Requirement: Codex conformance evidence exists

The repository MUST contain test-only canonical conformance vectors comparing
Codex with Claude for equivalent message/tool semantics, truthful missing call
IDs, parsed facets, capability visibility, and the absence of inferred lifecycle
stages. The suite MUST remain test infrastructure and MUST NOT add a provider-
neutral native model, adapter trait, registry, or production cutover.

#### Scenario: Tool lifecycle meaning remains conservative

- **WHEN** equivalent synthetic tool request/result records are projected
- **THEN** requested/result-returned stages, structured values, source call IDs
  when present, and absence of execution stages compare consistently

### Requirement: Codex acquisition preserves all three source identities

The authoritative public acquisition API MUST accept exactly the three Codex
identity/kind pairs specified above, validating them before I/O. Each call
reaching extraction MUST invoke the existing native extractor exactly once and
map those records through the existing canonical semantics without a legacy
record conversion. Shared
acquisition input MUST be caller-owned `observed_at`, without SQLite read
controls. Each identity MUST return `AcquisitionProgress::None`; acquisition
MUST NOT persist scanner state or return successful progress on failure.
Source-read, mapping, and validation failures MUST remain bounded and privacy-safe.

#### Scenario: Three identities acquire native evidence independently

- **WHEN** the same valid native input is acquired as live, archived, and headless
  Codex sources with their respective kinds and a fixed observed time
- **THEN** each returns reference-equivalent observations with its own adapter ID
  and stable replay identity, source-derived occurrence time, and no progress
  coordinate

#### Scenario: Invalid identity and kind fail before I/O

- **WHEN** a Codex source has a wrong client/source pair or another identity's kind
- **THEN** acquisition rejects it before opening the path and does not leak the
  path or native error

#### Scenario: Source session and tool semantics remain unchanged

- **WHEN** acquired native records inherit an explicit session from session metadata
  and contain structured tool calls or results
- **THEN** acquisition preserves source session and call linkage, structured values,
  and request/result stages without manufacturing execution evidence or restoring
  a filename-derived canonical session
