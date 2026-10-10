# opencode-sqlite-canonical-observation-v2-adapter Specification

## Purpose
This specification covers the current OpenCode `opencode.sqlite` adapter.
One SQLite-native interpretation feeds the authoritative Canonical Observation
v2 acquisition API used by the production source runtime. Older OpenCode source
layouts and source-backed record/export compatibility are not part of this
contract. This production adapter is not an investigation provider: on-demand
OpenCode investigation is deferred and MUST fail before source I/O or native
invocation, as specified by session-investigation. Event 3.0 remains the external
projection.
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
previously stored high-water and MUST NOT stage cursor or baseline replacement
on source failure.
Dry-run and backfill MUST NOT stage a cursor.
Required output
persistence MUST still gate scanner-state installation.

#### Scenario: OpenCode scanner progress is monotone and durability-gated

- **WHEN** incremental acquisition fails or succeeds
- **THEN** failure stages no state, successful high-water cannot regress, dry-run/backfill do not stage and durable output gates installation

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
path, and never earlier than the token it resumed from. A resumed scan with no
newer parts MUST return the token it resumed from. A tokenless scan MUST return
none when no part high-water exists. A resumed scan MUST apply the CLI's single
overlap and incremental part limit, selecting parts from the overlap-adjusted
lower bound onward; exceeding the limit MUST fail as
`BoundedSourceRead(LimitExceeded)` without a new token. A token for another or
non-resumable source MUST be rejected before source I/O.

A resumed scan MUST fail as `AcquisitionError::ResumeRegressed`, with no coverage
and no token, when the store's newest part is older than the token's
high-water or the store has no parts. The check MUST use the same read snapshot
as the selection and MUST run before any part is selected.

#### Scenario: Embedded OpenCode scans resume from a source-bound token

- **WHEN** a host persists a token, new parts arrive, and it resumes
- **THEN** parts from the overlap-adjusted lower bound onward are read, the token advances monotonically, an idle resume keeps its token, overflow is recoverable by a tokenless scan, and a mismatched token fails before I/O

#### Scenario: Resume tokens distinguish lossy-equal paths

- **WHEN** two Unix paths differ only in bytes that are not valid UTF-8
- **THEN** their tokens have different bindings and a token for one is rejected for the other

#### Scenario: A regressed store fails instead of stalling

- **WHEN** a host resumes against a store whose newest part is older than the token (restored, replaced, clock rollback, newest parts deleted, or part table removed)
- **THEN** the scan fails as `ResumeRegressed` with no token or coverage, and a tokenless scan recovers and issues a new token
