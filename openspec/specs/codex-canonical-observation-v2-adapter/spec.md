# codex-canonical-observation-v2-adapter Specification

## Purpose
This specification covers only the Codex reference adapter path from the
published implementation. It records a local, non-production Canonical
Observation v2 projection; the legacy `NormalizedRecordV1`/`ParsedRecord` path
remains production, with no detector cutover or Event 3.0 change, and no other
adapter migration.
## Requirements
### Requirement: One Codex-native interpretation

The Codex adapter MUST read each registered Codex JSONL source once into one
bounded Codex-specific native interpretation. That interpretation MUST retain
enough ordered structure for both the unchanged legacy `ParsedRecord` /
`NormalizedRecordV1` projection and the crate-private Canonical Observation v2
projection. The production extractor MUST continue to produce only the legacy
projection and MUST NOT call v2.

#### Scenario: One read preserves legacy output

- **WHEN** a valid Codex JSONL source is extracted
- **THEN** legacy record count, order, metadata, kind, flattened arguments,
  content, and filename-stem session fallback remain unchanged

### Requirement: Four source identities remain distinct

The canonical projection MUST accept only `ClientId::Codex` with the matching
source identities and kinds `codex.sessions`/`Jsonl`,
`codex.archived_sessions`/`ArchivedJsonl`, `codex.headless_sessions`/`HeadlessJsonl`,
and `codex.project_sessions`/`Jsonl`. It MUST use adapter type `codex`, the
actual source ID as adapter ID, `SessionStore` ingestion, no adapter version or
path identity, and `PartialStructured` fidelity. It MUST NOT upgrade the
project-local source's maturity or deduplicate observations across source IDs.

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

The v2 projection MUST set `session_id` only from source-reported
`session_id`, `sessionID`, or `sessionId` on the record, or from the most recent
prior `session_meta` that explicitly supplied one. Inherited IDs MUST retain
`SourceReported` origin. It MUST never use a filename, path, or project
directory fallback. `session_meta` itself MUST be skipped as a v2 observation,
and the headless `session_meta`/`turn_context` wrapper MUST be skipped as
ambiguous context rather than treated as a message or execution record.

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

The projection MUST use each non-empty JSONL object's zero-based ordinal as
source sequence and producer sequence, with child ordinals assigned in native
emission order. Same source bytes and options MUST produce the same observation
IDs. No random, filename-derived, path-derived, or fabricated identity is
allowed.

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

### Requirement: Production and Event 3.0 remain frozen

This change MUST NOT alter parser registration symbols, production scanning,
detection, `NormalizedRecordV1`, Rule v1, process-chain behavior, Event 3.0
schemas/IDs/serialization/privacy/durable bytes, or any other adapter. The v2
projection MUST remain a crate-private test/future seam only.

#### Scenario: Production stays on legacy

- **WHEN** the normal Codex scanner parses a registered source
- **THEN** it returns the existing normalized records without requiring or
  emitting Canonical Observation v2 values
