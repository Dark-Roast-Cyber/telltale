# claude-canonical-observation-v2-adapter Specification

## Purpose
This specification covers only the Claude Code `claude.projects` reference
adapter path from the published implementation. It records a local,
non-production Canonical Observation v2 projection; the legacy
`NormalizedRecordV1`/`ParsedRecord` path remains production, with no detector
cutover, Event 3.0 change, or other adapter migration.
## Requirements
### Requirement: One Claude-native interpretation

The Claude adapter MUST read `claude.projects` JSONL once into one bounded
Claude-specific native interpretation. The native record MUST retain enough
ordered structure for both the legacy `ParsedRecord` projection and the
Canonical Observation v2 projection. The production extractor MUST continue to
produce the existing legacy projection and MUST NOT call the v2 projection.

#### Scenario: One read supports both projections

- **WHEN** a valid Claude JSONL source is extracted
- **THEN** native records are built once and the legacy projection preserves its
  existing count, order, metadata, kind, flattened arguments, content, and
  filename-stem session fallback

### Requirement: Legacy behavior remains equivalent

The implementation MUST preserve current Claude legacy behavior, including
tool-use and tool-result kind rules, `type:tool` completed/error result rules,
unknown explicit discriminator to `RecordKind::Other`, and object-envelope
`SchemaDrift` errors. Canonical mapping failures MUST NOT become production
`ParseError` outcomes.

#### Scenario: Legacy characterization remains stable

- **WHEN** the existing Claude, parity, and detection fixtures are parsed
- **THEN** records remain behaviorally equivalent to the pre-v2 adapter path

### Requirement: Canonical projection is not production-active

The v2 projection MUST be a `pub(crate)` future/test seam only. It MUST NOT be
wired into `parse_source_records`, detection, CLI, or the scan pipeline, and
`NormalizedRecordV1` MUST remain the production path.

#### Scenario: Production uses the compatibility path

- **WHEN** the normal scanner parses a `claude.projects` source
- **THEN** it returns the existing normalized records and does not emit or
  require Canonical Observation v2 values

### Requirement: Session identity is split between legacy and v2

The legacy projection MUST use the existing filename stem fallback. The v2
projection MUST set `session_id` only from `sessionId`, `session_id`, or
`sessionID`, with `SourceReported` origin, and MUST omit it when those fields are
absent. It MUST never use a filename or path fallback.

#### Scenario: Session-a has different compatibility and canonical identity

- **WHEN** `session-a.jsonl` has no source session field
- **THEN** legacy `session_id` is `session-a` and every v2 observation has no
  canonical `session_id`

### Requirement: Tool lifecycle is truthful

The v2 projection MUST map `tool_use` to Tool with stage `ToolRequested` and
`tool_result` to Tool with stage `ToolResultReturned`. It MUST NOT emit
`ToolProposed`, `ToolExecutionStarted`, `ToolExecutionCompleted`, success,
failure, or `ToolStatus` from a Claude result or `is_error` value.

#### Scenario: Tool flow exposes only visible lifecycle facts

- **WHEN** the assistant requests Read and a user envelope returns its result
- **THEN** v2 emits a requested Tool observation and a returned-result Tool
  observation, with no inferred execution stages or status

### Requirement: Call linkage is source-reported

Every in-scope `tool_use` and `tool_result` v2 Tool observation MUST carry the
source block ID as `correlation.call_id` with `SourceReported` origin. The
adapter MUST NOT invent or content-hash a call ID, and MUST fail the v2 mapping
when an in-scope block lacks its required ID.

#### Scenario: Read request and result correlate

- **WHEN** `tool_use.id` and `tool_result.tool_use_id` are both
  `toolu_fixture_read`
- **THEN** both Tool observations carry that exact source-reported call ID

### Requirement: Structured tool values are retained

The v2 projection MUST retain structured `tool_use.input` as `tool.arguments`
and tool-result content as `tool.result`, rather than using only legacy strings.
Explicit boolean `is_error` MUST be retained when present. JSON conversion MUST
fail closed on non-finite numbers and MUST not include source payloads in errors.

#### Scenario: Read input and result remain structured

- **WHEN** Read receives `{"file_path":"README.md"}` and returns text
- **THEN** arguments remain a JSON object, result remains a JSON value, and
  `is_error: false` remains an explicit body fact

### Requirement: Messages preserve ordered content parts

Actual user and assistant messages MUST produce Message observations with
`MessageObserved` and truthful user/assistant roles. Present text, tool-use, and
tool-result content parts MUST remain ordered. An assistant message MUST be
emitted before its ToolRequested children. A user envelope containing only
tool-result blocks MUST emit ToolResultReturned observations without a User
Message; mixed content MUST preserve native emission order.

#### Scenario: Assistant text and tool use have deterministic children

- **WHEN** one assistant record contains text followed by `tool_use`
- **THEN** one assistant Message retains both ordered parts, followed by one
  ToolRequested child with child ordinals incrementing from zero

### Requirement: Identity and replay are deterministic

The v2 projection MUST use the non-empty JSONL object's zero-based source
sequence as `SourceProvenance.source_sequence` and producer-local sequence. It
MUST omit native IDs, path hashes, and path-derived identity. The builder MUST
derive `StableSourceCoordinate` identity with per-record child ordinals.

#### Scenario: Replaying the same source is stable

- **WHEN** the same fixture is projected twice with the same required
  `ObservedAt` option
- **THEN** observation order, source coordinates, child ordinals, and
  `observation_id` values are identical

### Requirement: Observed and occurred time remain distinct

`ClaudeCanonicalOptions` MUST require an `ObservedAt` value and the adapter MUST
never call a wall clock. Valid source RFC3339 timestamps MAY populate
`occurred_at`; invalid or absent timestamps MUST leave it absent. The adapter
MUST never copy source time into `observed_at`.

#### Scenario: Controlled acceptance time differs from source time

- **WHEN** a fixture source timestamp is `2026-04-27T12:00:00Z` and options
  provide `2026-09-02T12:00:00Z`
- **THEN** occurred time is the source timestamp and observed time is the option
  value

### Requirement: Capability and fidelity are explicit

Every v2 observation MUST use `SessionStore`, adapter type `claude_code`,
adapter ID `claude.projects`, no adapter version, and `PartialStructured`
fidelity. Capability overrides MUST be exactly ToolCall supported, ToolExecution
unsupported, and UserContext supported.

#### Scenario: Claude visibility limits are represented

- **WHEN** a Claude v2 observation is constructed
- **THEN** its source and capability context expose those exact values and do
  not claim execution telemetry

### Requirement: Parsed facts are not observed activity

The adapter MAY add `resource.path` as a governed `Parsed` Tool facet when a
structured tool argument contains a string `file_path`. It MUST NOT emit File,
Process, or Network observations from that parsed path or from message text.

#### Scenario: Read path remains a parsed Tool facet

- **WHEN** Read has `input.file_path = "README.md"`
- **THEN** the path is a Parsed `resource.path` facet on the Tool observation
  and no File, Process, or Network observation is emitted

### Requirement: Unknown input fails closed

Unknown explicit Claude record discriminators and unknown content-block types
inside otherwise known records MUST return safe canonical mapping errors. The v2
adapter MUST NOT dump arbitrary unknown objects into the `Other` family or
silently drop an in-scope record. Legacy unknown discriminators MUST remain
`RecordKind::Other`.

#### Scenario: Unknown discriminator is isolated

- **WHEN** a Claude record has an explicit future discriminator
- **THEN** legacy parsing returns `Other`, while v2 returns a mapping error with
  a code and non-sensitive detail

### Requirement: Metadata and privacy boundaries hold

Every populated body field and facet MUST have exactly one `FactMetadata` entry.
Structural fields, content, arguments, results, and the parsed path MUST use
`Reported` or `Parsed` provenance as appropriate and `Normal` sensitivity
without export-safe or Event4 claims. Adapter errors MUST NOT include raw
prompt, tool, result, path, or arbitrary source payloads in Display or Debug,
and observations MUST NOT be logged.

#### Scenario: Mapping errors do not leak payloads

- **WHEN** canonical mapping rejects a record containing synthetic source text
- **THEN** its error output contains only safe code/detail and does not contain
  that source text

### Requirement: Event 3.0 and adjacent adapters remain unchanged

This capability MUST NOT modify Event 3.0 schemas, IDs, serialization, privacy,
detection, durable output, or other source adapters. No other adapter migration
is included. Gemini MUST remain legacy compatibility only and MUST NOT be
renamed or migrated by this change.

#### Scenario: Existing compatibility hashes remain fixed

- **WHEN** the Claude adapter tests and Event 3.0 regression checks run
- **THEN** current and historical Event 3.0 schema bytes and all non-Claude
  adapter behavior remain unchanged
