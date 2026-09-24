# opencode-sqlite-canonical-observation-v2-adapter Specification

## Purpose
This specification covers the current OpenCode `opencode.sqlite` adapter.
One SQLite-native interpretation feeds the authoritative Canonical Observation
v2 acquisition API used by the production source runtime. Older OpenCode source
layouts and source-backed record/export compatibility are not part of this
contract. Event 3.0 remains the external projection.
## Requirements
### Requirement: One OpenCode SQLite-native interpretation

The `opencode.sqlite` adapter MUST read the existing SQLite message and
cursor-bounded selected `text`/`tool` part rows into one OpenCode-specific native
interpretation containing only facts needed by canonical mapping, native
accounting, and bounded read progress. It MUST NOT retain `ParsedRecord`,
`NormalizedRecordV1`, or synchronized legacy-shaped fields for source-backed
compatibility.

#### Scenario: One native interpretation feeds canonical acquisition

- **WHEN** a valid OpenCode SQLite source is acquired
- **THEN** canonical observations, accounting, and progress are derived from the
  same bounded native read without constructing a legacy record projection

### Requirement: SQLite source contract remains bounded

The adapter MUST retain the existing five-second busy timeout, lock mapping,
uncursored message query, selected `tool`/`text` part filter, limit, cursor
predicate and inner/outer ordering. It MUST NOT
read the event table or broaden the selected part set as part of this change.

#### Scenario: Incremental part extraction remains stable

- **WHEN** a part cursor and limit are supplied
- **THEN** only the existing selected rows are projected and
  `sqlite_part_max_time_updated` is calculated from those rows exactly as before

### Requirement: Native identity and source session are truthful

Canonical observations MUST use non-empty source `message.id` or `part.id` as
`SourceProvenance::native_id`, with `SessionStore`, adapter type `opencode`,
adapter ID `opencode.sqlite`, no adapter version/path identity, and
`PartialStructured` fidelity. Rowid, time_updated, row ordinal, path, filename,
workspace, and semantic content MUST NOT be observation identity. Canonical
session correlation MUST use only source-reported SQLite session fields or
truthful joined message context. Missing/empty native IDs MUST fail closed and
MUST NOT be replaced by semantic content.

#### Scenario: Message and part IDs are coordinate-only

- **WHEN** two SQLite artifacts contain the same source message or part ID but
  different paths, rowids, timestamps, or semantic values
- **THEN** the corresponding observation identity uses the source ID coordinate
  and does not contain the path, rowid, timestamp, or semantic value

#### Scenario: Missing source identity fails closed

- **WHEN** an in-scope message or selected part has no non-empty source ID
- **THEN** canonical projection returns a safe replay-unverifiable failure and
  does not derive an ID from content, input/output, path, or rowid

### Requirement: Messages and parts preserve source relationships

Selected text/tool parts MUST own canonical semantic observations when related to
a message; the message row MUST serve as context and MUST NOT create a duplicate
message envelope observation. Text parts with truthful user/assistant context
MUST map to `MessageObserved`. Message-only rows MAY map known role/content or
independent tool facts; unknown future message variants MUST fail closed or be
skipped without arbitrary canonical meaning.

#### Scenario: Joined text is one message observation

- **WHEN** a selected text part joins an assistant message
- **THEN** one Message observation carries the assistant role and text content,
  with no separate envelope duplicate

### Requirement: Direct OpenCode tool lifecycle is preserved

The canonical adapter MUST map only the lifecycle state directly reported by a
selected tool part: pending to `ToolRequested`, running to
`ToolExecutionStarted`, terminal completed/error/cancelled/denied to
`ToolExecutionCompleted`, and explicit output/error returned evidence also to
`ToolResultReturned`. A current terminal row MUST NOT create earlier pending or
running observations. Completed MUST NOT be mapped to `Succeeded`; absent
success/failure MUST remain unknown or absent. Error MUST remain a truthful
failure. The adapter MUST NOT invent process exit codes or OS side effects.

#### Scenario: Running directly proves execution start

- **WHEN** a selected tool part reports `state.status: running`
- **THEN** exactly a ToolExecutionStarted observation is emitted for that part,
  with no fabricated request or completion stage

#### Scenario: Completed result does not reconstruct history

- **WHEN** a selected tool part reports `state.status: completed` with output
- **THEN** ToolExecutionCompleted and ToolResultReturned are emitted for that
  same source part, with no fabricated pending/running stage and no Succeeded
  status

### Requirement: Structured values, linkage, and facets remain bounded

Tool input, output, and error MUST be retained as structured bounded values when
the source provides them, with source JSON strings remaining strings. A source
`callID` MUST be copied as `SourceReported` `correlation.call_id`; missing call
IDs MUST remain absent. Clear command and file-path arguments MAY become Parsed
`command.text` and `resource.path` facets. Parsed facets MUST NOT produce File,
Process, or Network observations.

#### Scenario: Native tool values remain structured

- **WHEN** a selected tool part contains structured input and structured output
- **THEN** canonical tool arguments/results preserve those JSON structures and
  source call linkage without maintaining a parallel flattened representation

### Requirement: Time, capability, and replay identity are explicit

Canonical projection options MUST provide `observed_at` and the adapter MUST
never call a wall clock. Valid source occurrence/lifecycle times MAY populate
`occurred_at`; `time_updated` MUST remain cursor/provenance only. Every
observation MUST expose ToolCall, UserContext, and ToolExecution as supported,
and replay MUST use stable source ID coordinates with child ordinal zero unless
multiple observations share the complete identity coordinate.

#### Scenario: Acceptance and cursor times remain distinct

- **WHEN** a part has a valid lifecycle timestamp and a different
  `time_updated` cursor value
- **THEN** `observed_at` is the supplied option, `occurred_at` uses lifecycle
  time when valid, and `time_updated` is not used as occurrence time

### Requirement: Canonical failures are bounded and source-local

Canonical mapping errors MUST be safe, code-based, and free of raw source
payloads. Production source evaluation MUST consume the Canonical Observation v2
acquisition path and MUST NOT reconstruct normalized records or fall back to a
retired OpenCode source projection.

#### Scenario: Canonical failure does not produce fallback evidence

- **WHEN** canonical mapping rejects a malformed or identity-less selected row
- **THEN** acquisition fails with a bounded source/canonical error and does not
  manufacture compatibility records or checkpointable progress

### Requirement: OpenCode conformance evidence exists

The repository MUST contain test-only canonical conformance vectors covering
OpenCode SQLite overlap with shared message/tool semantics, structured values,
source-reported call linkage, capabilities, direct execution lifecycle, and
the absence of fabricated history, success, or side-effect observations. The
suite MUST remain test infrastructure and MUST NOT add a provider-neutral
native model, adapter trait, registry, or production cutover.

#### Scenario: SQLite lifecycle meaning remains source-backed

- **WHEN** equivalent synthetic message/tool vectors are projected by OpenCode
  and the other reference adapters where the source facts overlap
- **THEN** shared semantics compare consistently while OpenCode-only direct
  execution stages remain limited to the lifecycle state it reports

### Requirement: Acquisition evidence and operational progress remain separate

The authoritative public acquisition API MUST accept caller-owned
`observed_at` plus the existing bounded part minimum-update and limit read
options. It MUST validate the exact `ClientId`, source ID, and SQLite source kind
before source I/O, perform exactly one existing OpenCode native extraction, and
map that extraction through the existing canonical semantics. It MUST return the
canonical observations separately from operational progress containing exactly
the selected extraction's optional part `time_updated` high-water coordinate.
The progress coordinate MUST NOT enter canonical evidence, provenance,
observation identity, or occurrence time, and the acquisition boundary MUST NOT
persist cursor or scanner state.

#### Scenario: Bounded acquisition returns matching progress

- **WHEN** a caller supplies a fixed observed time, part minimum-update
  coordinate, and part limit
- **THEN** the existing native selection receives those values, every returned
  observation preserves the caller's observed time and existing canonical
  semantics, and progress reports the exact high-water coordinate from that same
  extraction

#### Scenario: Invalid identity fails before source access

- **WHEN** the client, source ID, or SQLite source kind is not the exact
  `opencode.sqlite` contract
- **THEN** acquisition fails before reading the supplied path with a bounded
  error that does not expose the path, source payload, session ID, call ID,
  arguments, or result

#### Scenario: Authoritative acquisition remains pre-cutover

- **WHEN** the authoritative public acquisition API is available before the
  coordinated production runtime cutover
- **THEN** scan, watch, detection, embedding, Event 3.0, Event4, and durable scan
  state behavior remain unchanged
