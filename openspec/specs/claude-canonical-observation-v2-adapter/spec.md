# claude-canonical-observation-v2-adapter Specification

## Purpose
This specification covers the Claude Code `claude.projects` adapter. The
authoritative public acquisition API reuses its native interpretation and
Canonical Observation v2 mapping for production source evaluation. Record-level
compatibility parsing remains available and Event3 remains the external projection.
## Requirements
### Requirement: One Claude-native interpretation

The Claude adapter MUST read `claude.projects` JSONL once into one bounded
Claude-specific native interpretation. The native record MUST retain enough
ordered structure for both the retained `ParsedRecord` compatibility projection
and Canonical Observation v2. Production source evaluation MUST use canonical
acquisition without routing through compatibility records.

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

### Requirement: Canonical projection is production-active

The v2 projection MUST remain source-owned and reached through authoritative
acquisition. Scan, watch, and embedding MUST consume it through the shared
canonical runtime. `parse_source_records` remains only a compatibility surface.

#### Scenario: Production uses canonical acquisition

- **WHEN** the normal scanner processes a `claude.projects` source
- **THEN** it acquires Canonical Observation v2 without normalized-record detection

### Requirement: Session identity is split between legacy and v2

For `claude.projects`, the v2 projection MUST use a source-reported
`sessionId`, `session_id`, or `sessionID` as the namespace for that record's
zero-based JSONL ordinal and MUST set the same value as a `SourceReported`
`session_id` correlation. The ordinal MUST NOT be identity-eligible without
that explicit scope. If the source session ID is absent, v2 MUST not use a
filename, path, project directory, or legacy session fallback and MUST fail
closed with `replay_unverifiable`. Legacy parsing MUST retain its filename-stem
session behavior.

#### Scenario: Source session scopes an ordinal

- **WHEN** a Claude record reports `sessionId: claude-tool-use`
- **THEN** its v2 ordinal is scoped by `claude-tool-use`, its canonical session
  correlation is source-reported, and the observation has a stable ID

#### Scenario: Filename fallback is legacy-only

- **WHEN** `session-a.jsonl` has no source session field
- **THEN** legacy parsing uses `session-a`, while v2 emits no canonical session
  identity and fails with `replay_unverifiable` rather than creating an ID

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

Claude v2 IDs MUST be derived from the coordinate-only tuple and MUST remain
unchanged when semantic content, adapter-version provenance, or privacy-key
epoch changes under the same scoped coordinate. Semantic comparison MUST be
performed through the separate local comparison state; incompatible epochs are
incomparable, not mutation. Replaying identical source bytes and coordinates
MUST produce identical IDs.

#### Scenario: Artifact rename or move is harmless

- **WHEN** the same synthetic Claude JSONL bytes with a source session ID are
  written under two different filenames or directories
- **THEN** corresponding v2 observation IDs are identical and no path is used as
  canonical identity

#### Scenario: Local ordinal is scoped by session

- **WHEN** two different Claude artifacts each begin at ordinal zero but report
  different session IDs
- **THEN** their v2 observation IDs differ

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
is included.

#### Scenario: Existing compatibility hashes remain fixed

- **WHEN** the Claude adapter tests and Event 3.0 regression checks run
- **THEN** current and historical Event 3.0 schema bytes and all non-Claude
  adapter behavior remain unchanged

### Requirement: Claude conformance evidence exists

The repository MUST contain test-only canonical conformance vectors that compare
Claude and Codex semantic meaning where both sources truthfully provide it,
including message roles/content, tool request/result fields and linkage,
missing-call-ID absence, parsed resource/command facets, capability gaps, and
lifecycle non-inference. The suite MUST not introduce an adapter trait, native
record abstraction, registry, or runtime migration.

#### Scenario: Equivalent message meaning is compared

- **WHEN** equivalent synthetic user and assistant messages are projected by
  both reference adapters with truthful source sessions
- **THEN** their family, stage, role, content structure, metadata, and lifecycle
  meaning compare equal while source-specific coordinates and IDs may differ

### Requirement: Claude acquisition reuses canonical semantics without progress

The authoritative public acquisition API MUST validate the exact
`(Claude, claude.projects)` identity and `Jsonl` kind before I/O. It MUST invoke
the existing native extractor exactly once and map those records through the
same canonical semantics as the reference projector, without a legacy record
conversion. It MUST accept only
caller-owned `observed_at` as shared acquisition configuration, not SQLite read
controls, and return `AcquisitionProgress::None`. It MUST preserve source time,
session-scoped replay identity, structured evidence, and bounded source-read,
mapping, and validation errors. Failure MUST NOT return successful progress.

#### Scenario: Acquisition preserves reference evidence

- **WHEN** a valid Claude source is acquired with a fixed observed time
- **THEN** its observations match the reference projection, repeated acquisition
  retains observation identity, and progress is `None`

#### Scenario: Canonical identity cannot use the legacy fallback

- **WHEN** a Claude source has no truthful canonical session coordinate
- **THEN** acquisition fails with a privacy-safe replay-unverifiable error while
  legacy parsing retains its existing filename fallback independently

#### Scenario: Invalid acquisition identity or kind is rejected before I/O

- **WHEN** the client/source pair or source kind does not match this contract
- **THEN** acquisition rejects it before opening the path, without exposing the
  path or source contents through Display or Debug
