# opencode-sqlite-canonical-observation-v2-adapter Specification

## Purpose
This specification covers only the OpenCode `opencode.sqlite` reference adapter
path. One SQLite-native interpretation feeds the unchanged legacy
`ParsedRecord`/`NormalizedRecordV1` production compatibility projection and a
crate-private, non-production Canonical Observation v2 projection.
`opencode.legacy_json` and `opencode.project_json` remain on their existing
legacy paths; no production cutover, Event 3.0 change, or other adapter
migration is included.
## Requirements
### Requirement: One OpenCode SQLite-native interpretation

The `opencode.sqlite` adapter MUST read the existing SQLite message and
cursor-bounded selected `text`/`tool` part rows into one OpenCode-specific native
interpretation that retains structured source facts and exact legacy projection
fields. The production parser MUST derive `ParsedRecord`/
`NormalizedRecordV1` from that interpretation and MUST NOT call the Canonical
Observation v2 projection.

#### Scenario: Existing legacy projection remains equivalent

- **WHEN** a valid OpenCode SQLite source is parsed
- **THEN** legacy count, order, session fallback, metadata, kind, flattened
  arguments, content, part filtering, cursor, limit, and high-water behavior
  remain unchanged

### Requirement: SQLite source contract remains bounded

The adapter MUST retain the existing five-second busy timeout, lock mapping,
uncursored message query, selected `tool`/`text` part filter, limit, cursor
predicate, inner/outer ordering, and SQLite-over-legacy preference. It MUST NOT
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

#### Scenario: Native tool values are not rebuilt from legacy text

- **WHEN** a selected tool part contains structured input and structured output
- **THEN** canonical tool arguments/results preserve those JSON structures and
  source call linkage, independent of flattened legacy strings

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

### Requirement: Canonical failures and compatibility are isolated

Canonical mapping errors MUST be safe, code-based, and free of raw source
payloads. They MUST NOT become production parse failures. The change MUST NOT
modify JSON source identities, Event 3.0, detection, parser registration,
production scanning, or the legacy projection. `opencode.legacy_json` and
`opencode.project_json` MUST remain unchanged legacy-only source paths, with
their existing status preserved. The Canonical Observation v2 projection MUST
remain a crate-private, non-production reference seam; `NormalizedRecordV1`
MUST remain the production path and no production cutover occurs.

#### Scenario: Canonical failure does not alter legacy parsing

- **WHEN** canonical mapping rejects a malformed or identity-less selected row
- **THEN** legacy parsing of that same SQLite source remains available with its
  existing output and no canonical error is returned through `ParseError`

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
