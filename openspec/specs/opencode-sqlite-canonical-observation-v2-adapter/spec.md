# opencode-sqlite-canonical-observation-v2-adapter Specification

## Purpose
This specification covers the current OpenCode `opencode.sqlite` adapter.
One SQLite-native interpretation feeds the authoritative Canonical Observation
v2 acquisition API used by the production source runtime. The adapter reads two
native SQLite schemas: the legacy `message`/`part` schema and the OpenCode v2
`session_v2`/`session_message` schema (verified against OpenCode v2.0.27,
commit `1f4d07a4a519185955ae8ab2ea3607805509e386`). Requirements that name
`message`, `part` or part progress apply to legacy stores; requirements that
name `session_message` apply to OpenCode v2 stores; all other requirements apply
to both. "Canonical Observation v2" is Telltale's evidence model, unrelated to
the OpenCode v2 storage schema. Older OpenCode source
layouts and source-backed record/export compatibility are not part of this
contract. This production adapter is not an investigation provider: on-demand
OpenCode investigation is deferred and MUST fail before source I/O or native
invocation, as specified by session-investigation. Event 3.0 remains the external
projection.
## Requirements
### Requirement: One OpenCode SQLite-native interpretation

For a legacy store, the `opencode.sqlite` adapter MUST read the existing SQLite message and
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

The adapter MUST retain the five-second busy timeout, lock mapping, uncursored
message query and selected `tool`/`text` part filter.
It MUST open existing SQLite
databases read-only without creating a missing database and establish one read
transaction before schema inspection, covering messages and every part page.

#### Scenario: Incremental part extraction remains stable

- **WHEN** a part cursor and limit are supplied and the selected result contains
  L or fewer rows
- **THEN** only the existing selected rows are projected and
  `sqlite_part_max_time_updated` is calculated from those rows exactly as before

#### Scenario: Incremental part extraction exceeds the budget

- **WHEN** the selected incremental result contains more than L rows, or the L+1
  limit cannot be represented
- **THEN** acquisition fails without observations, accounting, or checkpointable
  progress, even when the first L rows could have been mapped

#### Scenario: Bootstrap retains bounded sampling

- **WHEN** no minimum timestamp is supplied and more than L matching parts exist
- **THEN** the newest L are selected without incremental overflow failure; a
  subsequent incremental overlap poll can fail if it selects more than L parts

#### Scenario: Missing database is not created

- **WHEN** acquisition is requested for an absent SQLite database
- **THEN** source opening fails without creating a database

#### Scenario: Equal timestamps cross page boundaries

- **WHEN** more than 5,000 selected incremental rows share a timestamp and fit L
- **THEN** strict timestamp/rowid continuation returns every row in stable order
  and evaluation sees one batch, not separate page-local correlation domains

#### Scenario: Exact page boundary and later failure

- **WHEN** the selection fills L exactly, exceeds L by one, or a later page has
  an invalid continuation coordinate or source payload
- **THEN** exact L succeeds only after exhaustion is checked; overflow or source
  failure returns no observations, accounting or checkpointable progress

#### Scenario: Concurrent updates and restart

- **WHEN** a writer commits after schema inspection pins the read snapshot
- **THEN** all message context and part pages reflect the pinned snapshot
- **AND** subsequent polls reread updates inside the existing ten-minute overlap;
  restart or failed required output persistence retries from committed progress

### Requirement: Uncursored SQLite parts retain newest-L sampling

Uncursored parts MUST retain newest-L sampling and ascending returned ordering,
where L is the supplied aggregate part limit clamped to at least one.

#### Scenario: Uncursored SQLite parts retain newest-L sampling

- **WHEN** OpenCode acquisition has no lower bound
- **THEN** newest-L sampling returns ascending parts

### Requirement: Incremental SQLite pages use validated keyset coordinates

Incremental parts MUST retain the inclusive minimum timestamp and strictly
ascending `(time_updated, rowid)` selection, using internal keyset pages of at
most 5,000 rows.
Continuation coordinates MUST be integer and strictly increasing;
invalid coordinates MUST fail the whole extraction, not be defaulted or coerced.

#### Scenario: Incremental SQLite pages use validated keyset coordinates

- **WHEN** an incremental query continues to another page
- **THEN** integer coordinates increase strictly under the inclusive lower bound

### Requirement: Incremental SQLite acquisition proves exact-L exhaustion

Incremental reads MUST return the complete selected result when it contains at
most L rows, or fail the entire acquisition when it contains more than L rows.
Checked L+1 lookahead MUST check exhaustion even after an exact full page; a
truncated successful incremental result MUST NOT be returned.

#### Scenario: Incremental SQLite acquisition proves exact-L exhaustion

- **WHEN** an incremental selection reaches its aggregate limit
- **THEN** complete selections at or below L succeed and over-L selections fail atomically

### Requirement: SQLite pages feed one canonical native batch

Native records
MUST be accumulated before one canonical projection and evaluation, preserving
cross-page message suppression and process-chain correlation.
The public default
L remains 5,000.
CLI scans with an actual incremental lower bound MUST use
L=25,000; bootstrap, dry-run and backfill retain newest-5,000 sampling.

#### Scenario: SQLite pages feed one canonical native batch

- **WHEN** selected parts span pages
- **THEN** one complete native batch preserves cross-page semantics

### Requirement: SQLite selection budgets do not claim unlimited recovery

Independent canonical and projection budgets MUST remain enforced.
The adapter
MUST NOT read the event table or broaden the selected part set.

#### Scenario: SQLite selection budgets do not claim unlimited recovery

- **WHEN** bounded SQLite recovery runs
- **THEN** independent budgets remain enforced without broadening the selected part set or recovery claims

### Requirement: SQLite recovery claims remain limited to the selected snapshot

SQLite selected-row limits MUST remain distinct from end-to-end resource bounds. Page and aggregate
limits bound selected part rows, not whole-cycle CPU or memory.
The separate
SQLite row-admission requirement specifies projected envelope and delivered row
caps across messages and parts; it does not establish end-to-end bounds.
Recovery covers only the finite selected snapshot, not arbitrary backlogs,
deleted or overwritten history, or backdated updates outside overlap.

#### Scenario: SQLite recovery claims remain limited to the selected snapshot

- **WHEN** selected row caps are described
- **THEN** they do not establish end-to-end resource bounds or arbitrary history recovery

### Requirement: Projected SQLite row admission is source atomic

Each extraction MUST use fresh counters shared by all messages and selected part
pages.
Inclusive fixed caps MUST be 8,388,608 bytes per projected TEXT/BLOB cell
or UTF-8 column name, 134,217,728 aggregate row-envelope bytes, and 100,000
delivered rows.

#### Scenario: Inclusive boundary and fresh extraction
- **WHEN** a projected cell, key, aggregate or delivered row count equals its cap
- **THEN** admission succeeds and a fresh extraction starts with zero counters
- **AND** exceeding any cap by one rejects the whole source without owned rejected rows

#### Scenario: Late failure and snapshot consistency
- **WHEN** a later message, part page or lookahead exceeds a cap while a WAL writer changes the store
- **THEN** the pinned snapshot governs all charges and no successful prefix or source state replacement is returned

### Requirement: SQLite row accounting includes every projected occurrence

Each column occurrence MUST charge its UTF-8 name and cell:
SQLite-exposed borrowed TEXT bytes, actual BLOB bytes, NULL zero, INTEGER/REAL
eight.
Unknown fields, overwritten aliases, metadata, suppressed messages and
repeated joined context MUST count independently.

#### Scenario: SQLite row accounting includes every projected occurrence

- **WHEN** metadata, aliases or repeated join context are delivered
- **THEN** each UTF-8 name and cell is charged independently

### Requirement: SQLite admission checks borrowed data before ownership

Names MUST be checked borrowed by index before cloning, even for zero-row
schemas; zero rows MUST charge zero aggregate bytes.
Whole-row prospective
checked totals MUST pass before owned JSON, keys, decoding or native construction.

#### Scenario: SQLite admission checks borrowed data before ownership

- **WHEN** a row or even a zero-row schema is inspected
- **THEN** names and whole-row prospective totals pass before cloning or constructing owned JSON

### Requirement: SQLite admitted rows stream inside one coherent native batch

Incremental excess lookahead MUST reject before owning its payload, retaining
exact-L exhaustion.
Schema inspection, messages and all pages MUST remain in
one read-only transaction.
Admitted rows MUST stream into native records without
retained raw row batches; one complete native batch MUST feed suppression and
evaluation.
Queries, selected parts, ordering and sampling MUST remain unchanged.

#### Scenario: SQLite admitted rows stream inside one coherent native batch

- **WHEN** part pages and incremental lookahead are processed
- **THEN** lookahead rejects before ownership and one read transaction feeds one native batch

### Requirement: SQLite admission rejection preserves source state atomically

Rejection MUST use privacy-safe fixed SourceRead detail and return no
observations, accounting or progress.
It MUST NOT replace the source baseline or
cursor; other sources MAY succeed.
Successful coverage MUST remain PartialSource.
Independent canonical/accounting/projection and durable output gates MUST remain.

#### Scenario: SQLite admission rejection preserves source state atomically

- **WHEN** any projected admission limit is exceeded
- **THEN** no observations/accounting/progress or baseline/cursor replacement survives

### Requirement: SQLite row admission makes no end-to-end resource or join-recovery claim

Admission MUST NOT be described as bounding SQLite preparation/filtering/UTF-8
conversion, decoded DOM/native heap, RSS, CPU or end-to-end memory.
Delivered-row
counting MUST NOT claim exhaustive recovery of nonunique message joins.

#### Scenario: SQLite row admission makes no end-to-end resource or join-recovery claim

- **WHEN** projected row caps are documented
- **THEN** they do not bound SQLite work, heap, RSS, CPU or exhaustive nonunique joins

### Requirement: Native identity and source session are truthful

Canonical observations MUST use non-empty source `message.id` or `part.id` as
`SourceProvenance::native_id`, with `SessionStore`, adapter type `opencode`,
adapter ID `opencode.sqlite`, no adapter version/path identity, and
`PartialStructured` fidelity.
Rowid, time_updated, row ordinal, path, filename,
workspace, and semantic content MUST NOT be observation identity.

#### Scenario: Message and part IDs are coordinate-only

- **WHEN** two SQLite artifacts contain the same source message or part ID but
  different paths, rowids, timestamps, or semantic values
- **THEN** the corresponding observation identity uses the source ID coordinate
  and does not contain the path, rowid, timestamp, or semantic value

#### Scenario: Missing source identity fails closed

- **WHEN** an in-scope message or selected part has no non-empty source ID
- **THEN** canonical projection returns a safe replay-unverifiable failure and
  does not derive an ID from content, input/output, path, or rowid

### Requirement: OpenCode session and missing native identity remain truthful

Canonical
session correlation MUST use only source-reported SQLite session fields or
truthful joined message context.
Missing/empty native IDs MUST fail closed and
MUST NOT be replaced by semantic content.

#### Scenario: OpenCode session and missing native identity remain truthful

- **WHEN** source session context is joined or native ID is empty
- **THEN** only reported session context is used and missing IDs fail without semantic fallback

### Requirement: Messages and parts preserve source relationships

Selected text/tool parts MUST own canonical semantic observations when related to
a message; the message row MUST serve as context and MUST NOT create a duplicate
message envelope observation.
Text parts with truthful user/assistant context
MUST map to `MessageObserved`.
Message-only rows MAY map known role/content or
independent tool facts; unknown future message variants MUST fail closed or be
skipped without arbitrary canonical meaning.

#### Scenario: Joined text is one message observation

- **WHEN** a selected text part joins an assistant message
- **THEN** one Message observation carries the assistant role and text content,
  with no separate envelope duplicate

#### Scenario: Invalid serialized message data

- **WHEN** any read message row has present malformed or non-object serialized data
- **THEN** acquisition fails without a successful prefix, accounting, or progress

### Requirement: OpenCode serialized message data validates atomically

Present serialized message data
MUST be a string encoding a JSON object; malformed or non-object data MUST fail
acquisition source-atomically.
A valid metadata-only JSON object MUST remain
supported.

#### Scenario: OpenCode serialized message data validates atomically

- **WHEN** message data is malformed or is a metadata-only JSON object
- **THEN** malformed/non-object data rejects and valid metadata-only objects remain supported

### Requirement: Direct OpenCode tool lifecycle is preserved

The canonical adapter MUST map only the lifecycle state directly reported by a
selected tool part: pending to `ToolRequested`, running to
`ToolExecutionStarted`, terminal completed/error/cancelled/denied to
`ToolExecutionCompleted`, and explicit output/error returned evidence also to
`ToolResultReturned`.
A current terminal row MUST NOT create earlier pending or
running observations.

#### Scenario: Running directly proves execution start

- **WHEN** a selected tool part reports `state.status: running`
- **THEN** exactly a ToolExecutionStarted observation is emitted for that part,
  with no fabricated request or completion stage

#### Scenario: Completed result does not reconstruct history

- **WHEN** a selected tool part reports `state.status: completed` with output
- **THEN** ToolExecutionCompleted and ToolResultReturned are emitted for that
  same source part, with no fabricated pending/running stage and no Succeeded
  status

### Requirement: OpenCode terminal state does not infer success or OS effects

Completed MUST NOT be mapped to `Succeeded`; absent
success/failure MUST remain unknown or absent.
Error MUST remain a truthful
failure.
The adapter MUST NOT invent process exit codes or OS side effects.

#### Scenario: OpenCode terminal state does not infer success or OS effects

- **WHEN** a terminal tool row has no explicit success/failure
- **THEN** unknown/absent remains truthful and no exit code or side effect is invented

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
options.
It MUST validate the exact `ClientId`, source ID, and SQLite source kind
before source I/O, perform exactly one existing OpenCode native extraction, and
map that extraction through the existing canonical semantics.

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

#### Scenario: Successful incremental read does not regress cursor

- **WHEN** selected parts on a successful incremental scanner poll are older than
  the stored timestamp or no parts are selected
- **THEN** scanner installation retains the prior high-water or stages no new
  candidate, respectively
### Requirement: OpenCode acquisition progress is not canonical evidence

It MUST return the
canonical observations separately from operational progress containing exactly
the selected extraction's optional part `time_updated` high-water coordinate.
The progress coordinate MUST NOT enter canonical evidence, provenance,
observation identity, or occurrence time, and the acquisition boundary MUST NOT
persist cursor or scanner state.

#### Scenario: OpenCode acquisition progress is not canonical evidence

- **WHEN** acquisition returns selected-part high-water
- **THEN** it is separate from observations and cannot become identity, provenance or occurrence time

### Requirement: OpenCode scanner progress is monotone and durability-gated

Failed extraction MUST NOT return observations, accounting, or progress.
The
scanner MUST stage a successful incremental high-water at no less than the
previously stored high-water. A failed window MUST NOT stage its cursor or
baseline replacement; earlier successful v2 windows in the same scan remain
eligible as specified by the rolling-window requirement below.
Dry-run and backfill MUST NOT stage a cursor.
An incremental poll MUST fail the source as `resume_regressed`, staging nothing,
when no part with an integer `time_updated` at or after the stored high-water
remains.
Required output
persistence MUST still gate scanner-state installation.

#### Scenario: OpenCode scanner progress is monotone and durability-gated

- **WHEN** incremental acquisition fails or succeeds
- **THEN** a failed window stages no progress or baseline, earlier successful v2 windows remain output-gated, successful checkpoint high-water cannot regress, and dry-run/backfill do not stage a cursor

#### Scenario: A regressed store fails the scanner closed

- **WHEN** an incremental scanner poll finds no part with an integer `time_updated` at or after the stored high-water (restored or replaced older store, newest parts deleted, or part table removed)
- **THEN** the source fails with acquisition code `resume_regressed` and a privacy-safe scanner error, the stored cursor is neither advanced nor reset, backfill still reads without staging, and polling resumes once a part at or after the cursor exists

### Requirement: Operator cursor reset is exact, explicit and state-only

`telltale cursor list --state-path <existing-native-state>` MUST inspect stored
OpenCode SQLite cursors without discovering/reading source stores, preparing scan
configuration or activating sinks. Results MUST expose only the fixed adapter,
opaque source instance, supported schema table, checkpoint/observation time,
drain/raw cut and inspection digest, never paths or content. Native validation
and exact agreement between map key and stored client/adapter/instance/table
binding MUST precede output or mutation. No profile/environment state default
is permitted.

`cursor reset` MUST require explicit state path, exact stored source instance,
explicit `part` or `session_message` table, matching inspection digest and
`--accept-history-gap`. Missing or changed selection MUST fail without writing.
The digest MUST bind the complete selected cursor including checkpoint,
observation time, drain and optional raw cut. It MUST remove the whole selected
record, never just the raw cut or checkpoint, and preserve every other schema
and source cursor, baseline contribution/snapshot, fingerprint, observation and
inventory value. An unfinished drain, including an older drain without a raw cut,
MUST fail unless `--abandon-incomplete-drain` is also present. This is an
intentionally lossy maintenance exception, not overlap-safe rollback or token
conversion; surviving continuations retain their existing downgrade semantics.

Maintenance MUST use existing state locking, strict validation and atomic
replacement. Pre-installation failures MUST preserve persisted state. Installation
errors MUST conservatively report potentially committed outcome; acknowledgement
failure after replacement MUST report committed-but-unacknowledged. Operators
MUST pause scanning throughout inspection/reset/retry and inspect after uncertain
outcomes. An absent selection MUST NOT be treated as proof that a previous reset
did or did not commit; `cursor_not_found` on retry requires inspection. A changed digest
MUST NOT be refreshed automatically to retry destructive maintenance.

Maintenance MUST NOT evaluate source data, install scan progress, modify source
history/log/outbox, emit Event 3 or replace a whole-source baseline. A subsequent
scan selecting the reset schema attempts the unchanged bounded bootstrap and
later incremental scans resume normal overlap (or an unfinished v2 raw cut),
with unchanged output-before-progress installation. No recovered
history, full evaluation, exactly-once replay or successful ingestion is implied.
Retained fingerprints can suppress identical projections while changed selected
window aggregates can repeat.

#### Scenario: Reset isolates the selected source and schema

- **WHEN** a validated native state contains several clients, source instances and both OpenCode schema cursors, and the operator confirms one current selection
- **THEN** only its complete cursor record is removed, baseline/deduplication and every other state value are retained, and source/output bytes are untouched

#### Scenario: Unfinished continuation is never silently discarded

- **WHEN** reset selects an interrupted v2 drain with or without a raw cut
- **THEN** it fails unchanged without separate abandonment acknowledgement; with both acknowledgements it removes the whole selected record and reports abandonment without claiming historical coverage or safe downgrade

#### Scenario: Reset is not successful ingestion or history recovery

- **WHEN** reset is followed by a scan of a restored older store, empty/missing table or more than 5,000 retained rows
- **THEN** only the normal selected-schema bootstrap is attempted, omitted/lost history remains a gap, unsupported schemas still fail, and required output failure installs no new progress

#### Scenario: Stale retry cannot silently discard changed progress

- **WHEN** state is locked/invalid, source binding disagrees, acknowledgement is missing or the inspected cursor digest changed
- **THEN** maintenance returns a closed privacy-safe error without changing persisted state; after possible commit or failed acknowledgement the operator must inspect rather than blindly retry

### Requirement: Embedded OpenCode scans report partial coverage and missing capability

The embedding facade MUST report a successful OpenCode source scan as
`SourceCoverage::Partial`, because the stateless bounded selection does not
establish whole-source coverage. JSONL sources with complete source accounting
MUST report `WholeSource`. Failed sources MUST report no coverage and a typed,
content-free `SourceScanFailure`. Without the `opencode-sqlite` feature, OpenCode
acquisition MUST fail before source I/O with `AcquisitionError::CapabilityNotCompiled`
(`capability_not_compiled`), not `SourceRead`. The Event 3 `scanner_error` code
MUST remain the generic stage code.

#### Scenario: Embedded OpenCode coverage and capability are explicit

- **WHEN** a host scans OpenCode with and without `opencode-sqlite`
- **THEN** success reports `Partial` coverage, and the feature-off build reports `capability_not_compiled` without reading the database or changing Event 3

### Requirement: Embedded OpenCode scans resume from a source-bound token

A successful embedded `opencode.sqlite` scan MUST return a versioned
`ResumeToken` bound to the exact source, including its exact platform-native
path, with an evaluated checkpoint never earlier than the same-schema token it
resumed from. An idle complete-window resume MUST return the token it resumed
from; an unfinished v2 window MUST retain its separate raw continuation even
below that checkpoint. A tokenless scan MUST return
none when no part high-water exists. A resumed scan MUST apply the CLI's single
overlap and incremental part limit, selecting parts from the overlap-adjusted
lower bound onward; exceeding the limit MUST fail as
`BoundedSourceRead(LimitExceeded)` without a new token. A token for another or
non-resumable source MUST be rejected before source I/O.

A resumed scan MUST fail as `AcquisitionError::ResumeRegressed`, with no coverage
and no token, when no part with an integer `time_updated` at or after the
token's high-water remains, including when the store has no parts. The check
MUST use the same read snapshot as the selection and MUST run before any part is
selected. It does not detect a replaced store whose newest part is at or after
the token, or a clock rollback while such parts remain.

#### Scenario: Embedded OpenCode scans resume from a source-bound token

- **WHEN** a host persists a token, new parts arrive, and it resumes
- **THEN** parts from the overlap-adjusted lower bound onward are read, the token advances monotonically, an idle resume keeps its token, overflow is recoverable by a tokenless scan, and a mismatched token fails before I/O

#### Scenario: Resume tokens distinguish lossy-equal paths

- **WHEN** two Unix paths differ only in bytes that are not valid UTF-8
- **THEN** their tokens have different bindings and a token for one is rejected for the other

#### Scenario: A regressed store fails instead of stalling

- **WHEN** a host resumes against a store with no integer-timed part at or after the token's high-water (restored, replaced, newest parts deleted, or part table removed)
- **THEN** the scan fails as `ResumeRegressed` with no token or coverage, and a tokenless scan recovers; it issues a new token once the store has a part high-water

### Requirement: One native schema is selected inside the read snapshot

Each extraction MUST select exactly one native schema with the first reads of
its read-only transaction, before any row is selected, so a concurrent migration
cannot split selection from the rows it governs. A store with both
`session_message` and `session_v2` tables, each with its required columns
(`id`, `session_id`, `type`, `seq`, `time_updated`, `data`; and `id`, `agent`,
`model`), MUST be read as OpenCode v2, even when legacy tables exist; legacy rows
in such a store MUST NOT be read or emitted. A store with neither table MUST use
the unchanged legacy path. A store with only one of the two tables, or without a
required column, MUST fail as `unsupported_source_schema` with no observations,
accounting or progress, and MUST NOT fall back to legacy history.

#### Scenario: A migrated store does not emit stale or duplicate history

- **WHEN** a store holds complete v2 tables and legacy rows that look newer
- **THEN** only v2 rows are acquired and progress names the `session_message` coordinate

#### Scenario: An incomplete v2 schema fails closed

- **WHEN** a store holds `session_message` without `session_v2`, or lacks a required column, with or without legacy tables
- **THEN** acquisition fails as `unsupported_source_schema` without reading legacy rows

### Requirement: OpenCode v2 rows feed canonical acquisition directly

OpenCode v2 rows MUST be interpreted into OpenCode-specific native records and
mapped by the same acquisition API, exact `(OpenCode, opencode.sqlite)`
identity, collector budgets, Detection v2 evaluation and Event 3.0 projection.
They MUST NOT be converted into the legacy native model, `ParsedRecord` or a
second detection path. Projection MUST select only `session_message.rowid`,
`id`, `session_id`, `type`, `seq`, `time_updated` and `data`, plus the
left-joined `session_v2.agent` and `session_v2.model`; other session columns and
other tables, including credential tables, MUST NOT be selected. `data` MUST be
a string encoding a JSON object without `id` or `type` members, `type` a string,
`seq` a non-negative integer and `time_updated` an integer; any other value MUST
fail the source atomically with a fixed, payload-free SourceRead detail.

#### Scenario: A fresh v2 store is not an empty success

- **WHEN** a store has only v2 tables with a user message and assistant tool content
- **THEN** acquisition returns their canonical observations and v2 progress, not zero records

### Requirement: OpenCode v2 message variants map truthfully

A `user` row MUST map `data.text` to one User `MessageObserved`. Each assistant
`content` entry MUST map by type: `text` to an Assistant `MessageObserved`;
`reasoning` to nothing (raw reasoning is not retained); `tool` to tool
observations. Recognized `agent-switched`, `model-switched` and
`location-switched` rows MUST count as native `SessionMeta`, and `synthetic`,
`system`, `skill`, `compaction` and `idle` rows as `Other`, without
observations. Unknown message types, assistant content types, tool statuses and
shell statuses, non-array assistant content and non-string text MUST fail
closed with fixed codes (`unknown_message_variant`, `unknown_content_variant`,
`unknown_tool_status`, `unknown_shell_status`, `invalid_assistant_content`,
`invalid_message_text`). Assistant-level error, finish, token and cost fields
and user attachments are not mapped.

#### Scenario: Auxiliary variants are accounted, not interpreted

- **WHEN** a store holds switch, synthetic, system, skill, compaction and idle rows
- **THEN** they are counted as native units with no observation and no failure

### Requirement: OpenCode v2 tool requests and outcomes are separate

Every tool entry MUST emit `ToolRequested` at `time.created`, with the raw
streaming input string or the input object as arguments. Completed and error
entries MUST also emit `ToolResultReturned` at `time.completed`: a completed
result whose parts are all text is those texts joined by a blank line as one
direct string, otherwise the structured `content` array under ordinary bounds
with each `data:` URI reduced to `data:<media type>` and the dropped length as
the Derived `tool.result.omitted_bytes` facet; an error result is
`error.message` as direct text (the structured `error` object when it has no
string message), with `error.type` as the Reported `tool.error_type` facet and
reported status `Failed`. Streaming and running entries
MUST NOT emit an outcome. Execution stages MUST be emitted only from source
evidence: an entry reporting `executed: true` (running: `ToolExecutionStarted`
at `time.ran`; terminal with `time.ran`: `ToolExecutionCompleted`), or a
completed entry named `shell` whose state `metadata` reports a settlement.
Because OpenCode sets `executed` from provider execution, `false` or absence
MUST make no execution claim by itself, and its reported value MUST be
preserved as the Reported `tool.executed` facet. The adapter MUST NOT emit
`Succeeded`, PIDs, approval or Process, File or Network observations for tool
entries, MUST NOT emit an exit code except from a `shell` settlement, and MUST
NOT map an `aborted` error (including a user decline) to anything but `Failed`.
The entry `id` MUST be the SourceReported `correlation.call_id`; a missing id or
name, a non-boolean `executed`, a non-object state, empty completed content or
an input of the wrong shape MUST fail closed (`missing_tool_id`,
`missing_tool_name`, `invalid_tool_state`). Tool-entry and message observations
report ToolExecution capability `Unknown`.

#### Scenario: Denied and unexecuted tools are not successes

- **WHEN** an entry reports `error` after a decline, or after malformed input without `time.ran`
- **THEN** it emits only `ToolRequested` and a `Failed` `ToolResultReturned`

#### Scenario: Running and streaming tools have no outcome

- **WHEN** an entry reports `streaming`, or `running` with `executed: false`
- **THEN** only `ToolRequested` is emitted

### Requirement: OpenCode v2 authored text uses the direct-text budget

Exact `(tool, field)` argument strings MUST use the 65,536-byte direct-text
budget instead of the 4,096-byte ordinary string bound, with every other member
under ordinary bounds: `shell` and `bash` `command`, `patch` and `apply_patch`
`patchText`, `write` `content`, `edit` `oldString` and `newString`, `execute`
`code`, and `subagent` and `task` `prompt`. A non-string value in one of these
fields MUST keep ordinary conversion. A user `!` command's `shell` arguments,
which are the command string itself, MUST use the same budget; legacy `bash`
input that is a bare string keeps ordinary bounds. For `shell` and `bash`, the
Parsed `command.text` facet MUST carry the same full command under the same
budget, so detection sees the whole command. The observation's 65,536-byte
encoded aggregate still applies, but a `command.text` facet that repeats the
tool's authored command exactly MUST count once toward it; retained bytes still
count both copies. v2 `read`, `write` and `edit` `path` MUST become the
Parsed `resource.path` facet; `path` on other tools is not a resource.

#### Scenario: A long command is detected by its full text

- **WHEN** a v2 `shell` entry's `command` is 20,000 bytes with a rule marker at its end
- **THEN** it maps without failure, `command.text` carries the full command and the rule matches

#### Scenario: A command near the direct-text budget is not quarantined

- **WHEN** an agent `shell` entry's `command`, or a user `!` shell row's command, is 60,000 bytes
- **THEN** the row maps, and every stage's `command.text` carries the full command

#### Scenario: The same field on another tool keeps ordinary bounds

- **WHEN** an `exec` tool's argument `command`, or a `shell` tool's other argument, is over 4,096 bytes
- **THEN** that value keeps the ordinary bound

### Requirement: Oversized OpenCode v2 rows are quarantined, not fatal

A row whose own values exceed a canonical value bound, or whose request input
exceeds a contribution bound, MUST be quarantined as a unit. It emits no
observations, tool usage or contributions, and it still counts as a native
unit. It MUST be reported on the acquisition batch by session id, message id,
`seq`, code (`unbounded_value` or `invalid_native_contribution`) and bound
category and dimension, without content. A row whose model-chosen value the
canonical body cannot hold, such as a requested tool name with a line break,
MUST be quarantined the same way as `invalid_body`. A row whose stored `data`
exceeds the 8,388,608-byte read cell limit MUST NOT be loaded: only its size is read, and
the row MUST be quarantined as `oversized_native_cell`, counted as one native
unit of the kind its `type` column names. The rest of the selection MUST still
be mapped and evaluated, and progress MUST cover the quarantined row. Every
entry of a quarantined row MUST still be checked, so a missing identity,
malformed or unknown entry, aggregate retention cap or contribution-key
capacity still fails the whole source as before. The scanner MUST emit one
content-free degraded `scanner_error` per affected source and list the
coordinates (at most 1,000, with a complete count) in the stdout scan summary.

#### Scenario: One padded row does not blind the source

- **WHEN** one row holds a 200,000-byte command and other rows hold detectable activity
- **THEN** the other rows are evaluated and detected, the padded row is reported with its coordinates and no content, and the cursor advances past it

#### Scenario: A payload over the read cell limit does not fail the source

- **WHEN** one row's stored `data` is 9 MiB
- **THEN** it is quarantined as `oversized_native_cell` without being read, and the other rows are evaluated

#### Scenario: Quarantine never hides an integrity failure

- **WHEN** an oversized row is followed by a row whose assistant content is not an array
- **THEN** the source fails with `invalid_assistant_content`

### Requirement: OpenCode v2 shell-tool settlements report completed execution

OpenCode's built-in `shell` tool writes its completed state `metadata` as `{status,
truncated, exit?, signal?, timeout?, shellID?}` only after the command was
authorized, ran and settled; a background command returns `status: "running"`
before it settles (OpenCode v2.0.27, `packages/core/src/tool/plugin/shell.ts`
and `packages/core/src/shell/result.ts`). A completed entry named `shell` whose
`metadata` is an object with `status: "completed"`, whose present `exit` is an
integer, whose present `signal` is a non-empty string and whose present
`timeout` is a boolean, and which reports an `exit`, a `signal` or `timeout:
true`, MUST emit one `ToolExecutionCompleted` at `time.completed` between its
`ToolRequested` and `ToolResultReturned`, whatever `executed` reports. Both
outcome stages MUST carry the reported `exit` as Reported `exit_code`, a
reported `signal` as the Reported `tool.signal` facet, and `timeout: true` as
Reported status `Failed`. An exit code, including zero, MUST NOT become
`Succeeded` or `Failed`. Any other metadata shape, any other tool name, and
running or error entries MUST make no execution claim from metadata alone and
MUST NOT fail the row because of metadata, which is an open record. Existing
`executed: true` execution-stage semantics remain unchanged. The settlement MUST
NOT change identity, cursors or the ToolExecution capability, which stays `Unknown`, and
MUST NOT produce OS observations. Metadata `shellID` can identify a background
or in-progress command, including in an error snapshot, and MUST NOT become a
correlation. A plugin can replace the tool registered as `shell`; matching
metadata is source-reported evidence, not authenticated OS-side execution.

#### Scenario: A settled shell tool reports completion and its exit code

- **WHEN** a completed `shell` entry with `executed: false` reports metadata `{status: "completed", exit: 2}`
- **THEN** it emits `ToolRequested`, `ToolExecutionCompleted` and `ToolResultReturned`, both outcome stages carry `exit_code` 2 and neither reports a status

#### Scenario: Unsettled or unrecognized shell metadata makes no claim

- **WHEN** a completed `shell` entry reports background metadata `{status: "running"}`, no metadata, or an `exit` that is not an integer
- **THEN** it emits only `ToolRequested` and `ToolResultReturned`, without `exit_code`

### Requirement: OpenCode v2 user shell messages report harness execution

A `shell` row MUST map to Tool observations named `shell` (Parsed from the row
type), with the reported `command` as string arguments and Reported
`command.text`, and `shellID` as `correlation.call_id`. Every shell row MUST
emit `ToolExecutionStarted` at `time.created`; `exited`, `timeout` and `killed`
rows MUST also emit `ToolExecutionCompleted` at `time.completed`, plus
`ToolResultReturned` when output is reported. The reported `exit` MUST become
`exit_code`; `timeout` reports `Failed` and `killed` reports `Cancelled`; an
exit code of zero MUST NOT become `Succeeded`. Shell observations report
ToolExecution capability `Supported` and MUST NOT produce OS observations.

#### Scenario: A completed shell command keeps its reported exit code

- **WHEN** a shell row reports `exited`, exit 0 and output
- **THEN** started, completed (exit code 0, no status) and result observations are emitted

### Requirement: OpenCode v2 identity is coordinate-based

Observations MUST use the row `id` as `SourceProvenance::native_id`, the
assistant `content` index as `child_ordinal` (zero for user and shell rows),
`seq` as the producer-local source sequence, and the `session_id` column as the
SourceReported session. Rowid, `seq`, `time_updated`, path and content MUST NOT
enter identity, so identities are stable across relocation, vacuum, rowid
changes and in-place lifecycle updates. A missing row id MUST fail as
`replay_unverifiable`, a repeated row id in one selection as
`ambiguous_source_identity`, and a missing session as `missing_session_id`.
A source-side replacement that reorders `content` can rebind child identity.

#### Scenario: Lifecycle updates keep message and child identities

- **WHEN** an assistant row is updated in place from streaming/running to completed/error, copied to another path, or stored under different rowids
- **THEN** every previously emitted observation keeps its identity and new outcome stages are added

### Requirement: OpenCode v2 selection and progress use the update coordinate

Bootstrap MUST select the newest `message_limit` rows (default 5,000) by
`(time_updated, rowid)` descending and return them ascending. Incremental reads
MUST use an inclusive `time_updated` lower bound, strictly ascending integer
`(time_updated, rowid)` keyset pages of at most 5,000 rows, and checked L+1
lookahead. Every selected row MUST have an integer `time_updated`. An
incremental read MUST stop before the row whose stored `data` would take it
past twice the window's retained budget, always taking the first row, and
report that row's `time_updated` as the next coordinate; the selection is then
cut, as at the row limit.

Rows MUST be mapped in update order into one window. The window MUST end on a
row boundary when the row limit is reached or when the next row would exceed
the 8 MiB retained-semantics budget. A single row larger than that budget is
quarantined. Admitted rows MUST be evaluated in source session and `seq`
order. Progress MUST be `OpenCodeSessionMessages { message_max_time_updated,
window_complete }`, never part progress, where the high-water is the last
admitted row's `time_updated` and `window_complete` is false when the window
was cut. A cut window MUST end on a whole `time_updated` group: when the
first row it leaves out shares the last admitted row's timestamp, admitted
rows with that timestamp are deferred too, and only a single timestamp that
fills a window fails as `LimitExceeded`. A cut window MUST also report
`message_overlap_from`: the earliest `time_updated` from which whole timestamp
groups at the end of the window hold at most half of its rows and half of its
retained bytes.

One CLI scan MUST drain a cut selection window after window, up to 64 windows.
Each next window MUST re-read from `message_overlap_from`, but no earlier than
one hour before the high-water, so a correlation straddling the cut is
evaluated whole; when that window would not advance past the high-water, the
scan MUST read strictly after it instead (`continue_session_messages_after`),
as it MUST when the overlapped window fails or quarantines rows for
evaluation capacity.
A window that fit after shrinking MUST set the size of the next one, and the
size MUST double again after four consecutive windows fit it. Events of
every window are released together with the final position; a later window
that fails keeps the earlier windows and their position, and is reported.
Repeated detections from re-read rows are deduplicated like those of the
routine overlap, and re-read rows count again in summary record counts, but
a quarantined row that is re-read MUST be reported once. After
the window limit or a later-window failure, the next scan MUST continue strictly
after the last successful window's raw cut, even below the prior checkpoint.
The ten-minute overlap MUST resume once a window completes. The CLI cursor
MUST clear its drain even if that complete window selected no rows, retaining
the prior checkpoint. The CLI cursor
records a drain with `draining: true` and `continue_after_time_updated`; its
`last_time_updated` checkpoint MUST remain monotone independently of that cut.
Embedding cut tokens MUST use
`resume:v1:opencode.sqlite:session_message_window:<checkpoint>:<cut>:<binding>`;
an embedding scan evaluates one window. The cut MUST preserve the native signed
64-bit integer `time_updated`, including negative values, and MUST be no greater
than the checkpoint; embedding token checkpoints remain nonnegative. A negative
cut MUST NOT bypass admission caps, whole timestamp-group boundaries or the
checkpoint regression check. Both coordinates MUST retain exact source/schema binding
and required-output installation gating. Regression checks during a drain MUST
use the monotone checkpoint, not a lower raw cut; the read-option continuation
helper MUST preserve a higher regression floor already supplied by its caller.
Older `draining` state without a cut and `session_message_drain:` tokens MUST
remain accepted and replay the checkpoint's ten-minute overlap, because their
raw cut cannot be recovered. New writes MUST include the raw cut; older readers
MUST reject that unknown state field/token coordinate rather than reinterpret
it. Complete state/tokens and legacy schema semantics remain unchanged.
This upgrade MUST NOT claim to recover historical omissions outside the overlap.
Canonical
source processing MUST re-read a window at half its retained size when
evaluating or projecting it exhausts the shared evaluation work budget or a
retained projection capacity bound, until it fits. When even the smallest
window does not fit, its rows MUST be quarantined by coordinates as
`evaluation_capacity_exceeded`, and the window is evaluated without them. The
stdout
summary MUST count windows as `evaluated_window_count`, and sources whose
last window was still cut as `incomplete_window_source_count`. A
resumed read (`resume_session_messages_after`) MUST apply the shared ten-minute
overlap and 25,000-row limit, and MUST fail as `resume_regressed` before
selection when no integer `time_updated` at or after the high-water remains.
In-place updates refresh `time_updated` without changing `seq`, so they MUST be
reselected; a `seq` cursor is not used. Admission caps, the five-second busy
timeout and one snapshot covering every page and committed WAL contents are
shared with legacy reads.

#### Scenario: An in-place update below the highest seq is reselected

- **WHEN** an earlier-`seq` row is updated after the stored high-water
- **THEN** the next incremental read selects it, ordered by `seq`, and advances progress

#### Scenario: Equal timestamps and late failures

- **WHEN** many rows share `time_updated` across pages, or a later page holds malformed data or a non-integer coordinate
- **THEN** ties are returned once in rowid order, and a late failure returns no prefix or progress

#### Scenario: A backlog larger than one window drains in one scan

- **WHEN** the selected rows need more than the 8 MiB retained budget, or exceed the row limit
- **THEN** one scan evaluates successive overlapping windows, finds every detection, and ends with the cursor at the newest row and no drain pending

#### Scenario: A correlation straddling a window cut is detected once

- **WHEN** the first step of a bundled correlation lies in the re-read tail of a cut window and its second step only in the next window
- **THEN** a routine drain and a history scan each report the correlation exactly once

#### Scenario: A burst inside the overlap still drains

- **WHEN** more rows than one window holds lie inside the overlap before the resume high-water
- **THEN** the cut window's successors continue strictly after each raw cut until a window completes, without lowering the checkpoint

#### Scenario: An unfinished overlap survives persisted restart

- **WHEN** late rows within the overlap cut a window below the prior complete checkpoint, and the CLI stops at its window limit or a later-window failure, or an embedding host persists the cut token
- **THEN** restarting continues after the raw cut and acquires the still-unseen overlap rows, the checkpoint stays monotone, and deleting rows at or above that checkpoint fails as `resume_regressed` even if rows remain after the cut

#### Scenario: Older unfinished state replays safely on upgrade

- **WHEN** an older draining state/token has only its clamped checkpoint
- **THEN** the new reader replays that checkpoint's overlap and issues a separate raw cut if still unfinished, while older readers reject the new drain representation

#### Scenario: Evaluation work shrinks the window

- **WHEN** bundled rules exhaust the evaluation work budget on a full retained window, or its detections exceed retained projection capacity
- **THEN** the scan evaluates smaller windows instead of failing and drains the rest in the same scan

#### Scenario: Known v2 coverage limits

- **WHEN** OpenCode copies forked history with its parent's `time_updated`, deletes reverted rows, or the clock moves backwards
- **THEN** rows older than the overlap stay unread; deleting the newest rows can trigger `resume_regressed`

### Requirement: A history scan reads a v2 store from its earliest message

`telltale scan --once --history all` MUST read each OpenCode v2 store from
its earliest message (`session_message_history`) and drain it in overlapping
windows without a window limit. It MUST require `--once` and an explicit
`--log-path`, and MUST NOT be combined with `--backfill`,
`--rebuild-baselines` or `--interval-seconds`. It MUST neither read, lock nor
write scan state: detections are deduplicated within the run only, so
repeating it reports again. It MUST skip install inventory, source
inventory-change reporting and baseline replacement, and the stdout summary MUST carry `"history": "all"`. Legacy
`part` stores keep their bootstrap selection.

#### Scenario: History reaches messages a first scan skips

- **WHEN** a v2 store holds more than 5,000 messages and the oldest one holds a detection
- **THEN** a first routine scan misses it, a history scan reports it, and the routine state file is unchanged

### Requirement: Legacy and v2 progress are never interchanged

The CLI MUST store v2 progress under the `session_message` cursor table and
legacy progress under `part`, and each cursor MUST apply only to its own schema;
a v2 store without a `session_message` cursor MUST bootstrap, and an existing
`part` cursor MUST be left unchanged. Embedded legacy tokens keep the form
`resume:v1:opencode.sqlite:<high-water>:<binding>`; complete v2 tokens MUST use
`resume:v1:opencode.sqlite:session_message:<high-water>:<binding>`, and cut
windows MUST use the two-coordinate form specified above. A token for
the other schema MUST read the selected schema's bootstrap selection; the
returned token MUST carry the selected schema's high-water, or the unchanged
resumed token when that schema has none. Failure, dry-run and backfill rules and
durability gating are unchanged.

#### Scenario: A legacy watermark does not skip migrated history

- **WHEN** a store with a stored `part` cursor migrates to v2 tables whose rows are older than that cursor
- **THEN** the v2 rows are acquired by bootstrap, a `session_message` cursor is staged, and the `part` cursor is unchanged

### Requirement: OpenCode v2 accounting counts native rows

Each selected row MUST be one native unit: user `UserMessage`; assistant
`AssistantMessage` plus `ToolCall` per tool entry and `ToolResult` per terminal
entry; shell `ToolCall` plus `ToolResult` when terminal; and the auxiliary
classes above. Tool usage and contributions MUST be recorded per tool entry and
shell row. Contribution input MUST be request-side only: the tool entry's input
and the shell row's `command`. Tool results,
error objects and shell output MUST NOT be contribution input, so their paths
and hosts are not counted and cannot cause contribution rejection. The
existing contribution bounds still apply to request input; a row that exceeds
them is quarantined (see the quarantine requirement). Session metadata MUST come from message `agent`/`model` and the
joined session `agent`/`model`, with contradictions kept ambiguous and malformed
model values failing as invalid attestation. Coverage remains `PartialSource`.

#### Scenario: Accounting follows native rows

- **WHEN** a user row and an assistant row with one completed tool entry are acquired
- **THEN** two native units count one user, one assistant, one tool call and one tool result

#### Scenario: Returned payloads are not contributions

- **WHEN** a direct-text completed tool result or shell output holds a host, or a token longer than 4,096 bytes that looks like a path, within unchanged canonical bounds
- **THEN** it does not cause `invalid_native_contribution`, and only hosts and path classes from tool input and shell commands are counted

#### Scenario: Request input keeps its contribution bound

- **WHEN** tool input holds a path-like token longer than 4,096 bytes
- **THEN** the row is quarantined with code `invalid_native_contribution` and contributes nothing
