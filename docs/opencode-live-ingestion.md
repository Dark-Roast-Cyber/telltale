# OpenCode live ingestion limits and recovery

The 0.7 canonical cutover introduced a regression relative to 0.5: native
OpenCode tool output became ordinary structured JSON, with a 4,096-byte string
limit. One supported large result rejected the entire acquisition. The older
parser passed these outputs through without this canonical policy. Restoring
the unbounded parser would lose the newer resource admission guarantees.

## Native schemas

Each scan reads exactly one schema, chosen inside the same read snapshot as
its rows:

- **OpenCode v2** (`session_v2` and `session_message`, verified against
  OpenCode v2.0.27): read whenever both tables and their required columns exist,
  even beside legacy tables. Legacy rows in such a store are not read.
- **Legacy** (`message` and `part`): read when neither v2 table exists. Its
  behavior below is unchanged.
- **Incomplete v2** (one table, or a missing required column): the source fails
  as `unsupported_source_schema`. It never falls back to legacy rows.

For v2, one `session_message` row is one native unit. Only the message columns
and the session `agent`/`model` are selected; other session columns and tables
are never read. Assistant `text`, user text and tool entries are mapped;
reasoning, attachments and switch, synthetic, system, skill, compaction and idle
rows are counted but not mapped. Unknown variants fail the source. Activity
contributions (tool names, path classes, network hosts) come only from tool
input and shell commands; tool results, errors and
shell output are not scanned for them.

Every tool entry emits `ToolRequested`. Completed and error entries also emit
`ToolResultReturned`; an error reports `Failed`, including user declines,
which OpenCode stores as `aborted` errors. Execution stages are emitted for
`executed: true`. OpenCode sets that field from provider execution, so local
tools report `false`. Telltale keeps the value as a reported fact and does not
claim local execution from it. The built-in agent `shell` tool is the exception:
its completed metadata reports how the command settled (`exit`, `signal` or
`timeout`) only after the command ran, so such an entry also emits
`ToolExecutionCompleted`. Both outcome stages carry an exit code when reported,
a reported signal as `tool.signal`, and `timeout: true` as `Failed`. An exit
code alone, including zero, is neither success nor failure. Background commands,
which return before they settle, make no claim from metadata. `shellID` can also
occur in running/error metadata and never becomes a correlation. Plugins can
replace `shell`: these are source-reported outcomes, not authenticated OS-side
effects. User `!` shell commands (`shell` rows) map to
a `shell` tool with reported start, exit code, output and `timeout`/`killed`
status.

Identity is the message ID plus the assistant `content` index. It survives
copying the database, vacuuming and in-place updates. Selection uses the
`time_updated` column, which OpenCode refreshes on every in-place update without
changing `seq`. Bootstrap takes the newest 5,000 messages; incremental reads take
up to 25,000 from the prior message high-water minus ten minutes, with the same
keyset pages, exhaustion check and regression check as parts. An incremental
read stops early once the stored payloads it took reach twice the window budget,
so a large backlog is read a window at a time. A v2 selection is evaluated in
**rolling windows**:
- a window ends on a message boundary when it reaches the row limit or the
  8 MiB retained-semantics budget, and never splits rows that share one
  `time_updated`;
- one scan drains a cut selection window after window, up to 64 windows. Each
  next window re-reads the tail of the last one (at most half of it, and at
  most one hour before its high-water), so a correlation that straddles the cut
  is still evaluated whole. Detections found again in that tail are
  deduplicated like those of the routine overlap; when the tail alone would
  fill a window, the next one starts strictly after the high-water;
- if bundled rules exhaust the evaluation work budget on a window, or its
  detections exceed the retained projection capacity (4,096 items, 4 MiB), the
  scan re-reads a window at half its size until it fits. Later windows of that
  scan keep the size that fit, and it doubles again after four windows fit.
  Rows whose smallest window still does not fit are quarantined as
  `evaluation_capacity_exceeded`, so one dense row cannot stop a drain;
- `source_processing.evaluated_window_count` counts the windows. A source
  still cut after 64 windows is counted in `incomplete_window_source_count`;
   its cursor carries a `draining` flag and a raw `continue_after_time_updated`
   cut, and the next scan continues strictly after that cut. Embedding scans
   evaluate one window per call, with `session_message_window:` tokens carrying
   both checkpoint and cut. The ten-minute overlap returns once a
  window completes;
- only one timestamp holding more rows than a whole window fails, as
  `LimitExceeded`.

Drain checkpoints remain monotone, independently of the raw continuation. If a
cut falls below the prior checkpoint, the next read starts after the raw cut,
so unseen late or backdated rows in the unfinished overlap are not skipped.
Regression detection still requires a row at or after the higher checkpoint,
including during a drain. Required outputs gate installation of both values.
A successful empty final window also clears the drain, without lowering the
checkpoint, so later backdated rows are read by the normal overlap.
An older `draining` cursor or `session_message_drain:` token lacks the raw cut;
the new reader conservatively replays the checkpoint's ten-minute overlap before
issuing a new continuation. Already-skipped rows outside that overlap cannot be
recovered by this upgrade; use a separately selected history scan for those.
Older readers reject the new field/token coordinate rather than misread it.
Do not strip the raw-cut field while leaving `draining: true`, or rewrite a new
window token into an old drain token carrying only the checkpoint: older readers
can then skip unfinished overlap. Finish the drain with the new reader, or
restore a coordinated earlier source/state/token snapshot with matching accepted
output. Tokenless bootstrap is not an overlap-safe rollback; see the
[migration guide](migrations/0.7.0.md#opencode-v2-changes-after-rc2).

Rows that cannot be mapped within a size bound are quarantined by coordinates,
never by content, while the rest is evaluated: a row over the 64 KB text
budgets, a request input over a contribution bound, a requested tool name the
canonical body cannot hold (`invalid_body`), a stored payload over
the 8 MiB read cell limit (`oversized_native_cell`), which is never loaded,
and rows that exceed evaluation capacity even alone
(`evaluation_capacity_exceeded`).
Shell commands, including user `!` commands, keep the 64 KB direct-text budget;
the `command.text` copy of a command counts once toward an observation's 64 KB
total.

**History scans.** A first scan samples only the newest 5,000 messages. For a
forensic pass over everything a v2 store still holds, run:

```sh
telltale scan --once --history all --client opencode --log-path ./history.jsonl
```

It reads from the earliest message in overlapping windows without the
64-window limit, prints `history: N windows evaluated` to stderr every 50
windows, deduplicates detections within the run, and never reads,
locks or writes scan state, so it can run beside a routine scanner and
repeating it reports again. The stdout summary carries `"history": "all"` with
the usual window, quarantine and failure counts. Legacy `part` stores keep
their newest-5,000 bootstrap.

Events are evaluated in session `seq` order. Known gaps: forked
sessions copy history with the parent's older `time_updated`, reverts delete
rows, and a clock rollback can hide updates outside the overlap.

v2 progress is a separate `session_message` cursor (CLI) or a
`resume:v1:opencode.sqlite:session_message:` token (embedding). A legacy `part`
cursor never resumes a v2 store, so a migrated store bootstraps instead of
skipping history older than the legacy watermark; the `part` cursor is kept.

## Supported text

Direct `tool.result` strings share the existing message-text budget: 65,536 UTF-8
bytes, checked before and after NFC normalization. OpenCode uses this for output
and error text, message-table fallback results and part lifecycle observations.
Nested result strings retain ordinary bounds; objects are not converted to prose.

The exact `apply_patch` tool's direct `arguments.patchText` string also gets the
65,536-byte text budget. OpenCode's [public tool schema](https://github.com/anomalyco/opencode/blob/dev/packages/opencode/src/tool/apply_patch.ts)
defines this as full authored patch text. The exception requires the exact tool
and field name and a string value. Nested lookalikes, other tools and other
arguments do not qualify. The object with `patchText` replaced by null must still
fit ordinary structured bounds. No patch parser or execution claim is introduced.

OpenCode v2 stores get the same 65,536-byte budget for these exact argument
fields: `shell`/`bash` `command`, `patch`/`apply_patch` `patchText`, `write`
`content`, `edit` `oldString`/`newString`, `execute` `code` and
`subagent`/`task` `prompt`. A `shell` or `bash` command's `command.text` carries
the whole command, so a rule can match text at its end. For v2 results:
- all-text results are joined into one text;
- error results are their message text, with the reported error type kept as
  `tool.error_type`;
- `data:` file URIs keep only their media type, with the dropped length as
  `tool.result.omitted_bytes`.

v2 `read`, `write` and `edit` paths become `resource.path`. A command duplicated
in arguments and `command.text` fits up to roughly 32 KB within the
per-observation aggregate.

A v2 row whose own values still exceed a bound is **quarantined**, not fatal:
- it emits nothing and contributes nothing;
- it is listed by session, message ID, `seq` and bound code (never content) in
  the scan summary's `source_processing.quarantined_units`;
- it marks the source with one degraded `scanner_error`;
- the rest of the selection is evaluated, and the cursor moves past it.

Malformed or unknown rows, identity failures and aggregate caps still fail the
source. Padding a payload past the limits therefore produces a located finding
instead of blinding the scan.

Both fields remain subject to the unchanged **65,536 encoded semantic bytes per
observation**, including other facts and facets. JSON quotes, escaping and NFC
matter. A result-only observation accepts 65,534 ASCII bytes; a `bash` result with
no other facts accepts 65,528. Passing conversion does not imply the assembled
observation fits. These are field policies, not limits tailored to an installation.

| Boundary | Limit |
| --- | --- |
| Ordinary structured string / encoded value | 4,096 UTF-8 bytes / 16,384 JSON bytes |
| Structured depth / array items / object members / key bytes | 6 / 64 / 32 / 64 |
| Direct message/result text and exact patch text | 65,536 raw UTF-8 bytes; aggregate can be tighter |
| Semantic body and facet aggregate | 65,536 encoded bytes per observation |
| Retained canonical semantics | 8 MiB per acquisition, checked before retention |
| SQLite cell / selected envelope / rows | 8 MiB / 128 MiB / 100,000; joined and unused columns count |
| Session attestations / contribution keys | 4,096 / 4,096 per acquisition |
| Evaluation observations / retained projection items / material | 65,536 / 4,096 / 4 MiB |
| Shared evaluation work | 256 MiB of charged byte visits, including projection and optional comparison |
| Evidence preview | Existing sanitizer: 4,096 input bytes, at most 512 redacted output bytes |
| Serialized-event marker-check / Event 3.0 input | 1 MiB per event |

OpenCode opts into the new converters; other source adapters keep their existing
conversion policies. Builder validation applies these field policies to direct
embedding construction too. Ordinary arguments, names, facets, identifiers and
local originals have not acquired larger string limits.

## Evaluation and privacy

Accepted content reaches matching in full. Rule v1 borrows canonical result text;
standalone selectors copy it once without repeating NFC normalization. Control
selectors that never visit a result exclude its direct text from reservations.
Matcher scans, full-content hashing and sanitization remain charged.

Within one session evaluation, matches of the same observation and selector
reuse bounded redacted evidence and its full-content hash. This cache retains
no raw transcript and counts against existing retention capacity. Each rule
still retains attributed evidence and timeline associations. Detection content,
identities and deduplication policy are unchanged.

Assignment redaction reserves decoding and partitioning linearly, then charges
reached key/value scans before execution. Previously one quote reserved the
square of the entire 4,096-byte preview, rejecting ordinary structured output.
No secret recognition, replacement or encoding rules change. Long pathological
key attempts still incur quadratic charged work and can exhaust the same budget.
The encoded-URL work reservations remain conservative. Oversize or excessive
workload still rejects the source; none of these budgets is increased.

The shorter emitted preview is intentional and does not limit detector input.
Full-value hashing preserves suffix distinctions. Stable observation identity
remains coordinate-based. Existing detection fingerprints suppress identical
projected events; they do not deduplicate every observation across read windows.

## Failure, recovery and coverage

Extraction opens SQLite read-only, with a five-second busy timeout and one
transaction snapshot across messages and part pages, including committed WAL
contents. Scanning does not repair, checkpoint or rewrite the session database.
Malformed state, unsupported variants, bound failures and evaluation/projection
failure reject the failed window atomically. A later-window failure retains
earlier successful windows and their raw continuation, with the failure reported.
OpenCode
bound diagnostics expose only closed field/dimension enums, never payloads,
dynamic keys, source IDs, paths or measured sizes.

Progress is staged only after successful processing. Required canonical JSONL
persistence, or durable outbox retention, precedes scanner state installation.
Rejected acquisition contributes no new progress; earlier successful windows
remain eligible. Required persistence failure leaves the prior stored cursor,
including its raw continuation.
After input becomes supported or the sink is repaired, restart with the same
state/output configuration: the inclusive overlap retries pending data. Deleting
state or bypassing rejection is not required. Remote-only best-effort delivery
retains its documented non-recoverable posture; this change adds no durability.

A store regressed below the cursor fails the same way. That includes a restored
or replaced older copy, a store whose newest parts were deleted (ordinary session
deletion can do this) and a store with no `part` table. The scan finds no part
with an integer `time_updated` at or after the cursor. It emits a privacy-safe
`scanner_error` and reports acquisition code `resume_regressed` in
`source_processing.failures`. The cursor is not advanced, reset or replaced.
Scans resume on their own once OpenCode writes a part at or after the cursor.
Changes the store lost before that point stay unevaluated. `--backfill` reads the
newest bootstrap window without the cursor and stages no cursor or baseline.
`--rebuild-baselines` rebuilds baseline snapshots only. For an explicitly accepted
history gap, use the targeted cursor reset below, not deletion of the state file:
deleting the file discards every other source's state as well.
The check does not detect a replaced store whose newest part is at
or after the cursor, or a clock rollback while such parts remain.

### Explicit operator cursor reset

This is **cursor reset, not rebaseline or history recovery**. It is a separate
state-only maintenance action. Pause every scan/watch process or schedule using
the state file, and keep them paused through inspection, reset and any retry.
Retain a coordinated source/state/output snapshot if restoration may be needed.
Prefer repairing/restoring the source or completing its drain without reset.

Inspect the **explicit existing native state file** (there is no environment or
profile default):

```sh
telltale cursor list --state-path /path/to/telltale-state.json
```

The JSON result lists only OpenCode SQLite cursors, with opaque
`source_instance_id`, `table`, checkpoint, observation time, drain/cut and
`cursor_digest`. It does not discover or open source stores, load rules/config,
activate sinks, or print paths/content. The source instance is the existing
SHA-256 of the scanner's exact stored path spelling, **not** a new canonicalized
path or database identity. It matches the scanner's `source_path_hash` for that
same path spelling. Match the intended stored source; do not guess from another
path spelling. Map keys and stored source/schema ownership must agree.

Select exactly one listed instance and table (`part` or `session_message`),
and copy its fresh digest:

```sh
telltale cursor reset --state-path /path/to/telltale-state.json \
  --source-instance-id <64-lowercase-hex> --table session_message \
  --expect-cursor <cursor_digest> --accept-history-gap
```

The reset atomically removes **that entire cursor record**: checkpoint,
`draining` and raw continuation together. It preserves every other source and
schema cursor, baseline contributions/snapshots, observations, inventory and
source/detection fingerprints. It never changes source history, canonical JSONL
or the outbox and emits no Event 3 record. Its JSON acknowledgement is a
maintenance result, not evidence that any source was evaluated.

An unfinished drain is refused unless the operator additionally passes
`--abandon-incomplete-drain`. This also applies to older `draining: true`
records without a raw cut. The separate acknowledgement accepts loss of the
unfinished continuation: pending rows outside the subsequent bootstrap window
may remain unevaluated. No raw cut is stripped from a surviving record, no
embedding token is rewritten, and this is **not an overlap-safe downgrade**.
Other unfinished cursors retain their downgrade rejection. To avoid abandonment,
finish with the current reader or restore coordinated source/state/output.

A subsequent normal scan **if it selects that schema** attempts the existing
uncursored newest-5,000 bootstrap under all normal bounds. Normal overlap resumes
on later incremental scans; unfinished v2 windows retain raw-cut continuation.
Resetting a dormant `part` cursor does not reset active v2 progress, or vice
versa. Empty/missing/unsupported stores do not acquire invented progress or
become successfully recovered through reset. Required canonical output/durable
outbox persistence still precedes installation of any newly evaluated progress.
Maintenance itself evaluates nothing and installs no scan progress, so it does
not require a scan-output transaction.

Retained deduplication can suppress identical earlier projections; changed
selected-window aggregates can emit again. Reset does not promise exactly-once
replay, whole-store evaluation, a whole-source baseline or recovery of lost or
omitted history. For v2, a separately selected `--history all` scan can inspect
history the store still retains; it neither restores deleted history nor repairs
the routine cursor.

Validation, selection, required-acceptance, lock and preparation failures leave the
state file unchanged. Missing selections fail without writing; absence is not
proof that an earlier reset succeeded. A changed digest rejects stale selection,
including changed observation time or continuation. Do not automatically refresh
the digest and retry: review the fresh selection with scanners still paused.
`cursor_reset_outcome_unknown` means installation may have occurred (for example,
rename succeeded but parent-directory sync failed); `cursor_reset_committed_ack_failed`
means replacement completed but stdout acknowledgement failed. Inspect state
before retrying either case; never roll back newly installed state or discard a
recreated cursor blindly. No state migration or compatibility conversion occurs.

Bootstrap and backfill still select the **newest 5,000 eligible tool/text parts**,
plus message-table records. Incremental reads use the prior part update high-water
minus ten minutes, and permit 25,000 selected parts across keyset pages. Overflow
fails instead of committing incomplete progress. Changes older than the overlap,
parts outside bootstrap selection, upstream omissions/truncation and unsupported
parts remain coverage limitations. Accounting remains `PartialSource`, even for
a store that fits in the sample, and cannot replace a whole-database baseline.

OpenCode scan/watch evaluates bounded selected windows, **not cumulative session
snapshots or exactly-once actions**. An unchanged `scan --once` retains cursor
high-water, but bootstrap-to-incremental selection can change session activity/
detection evidence and fingerprints, emitting another aggregate. Identical later
incremental projections are suppressed. Do not count these emissions as new
actions solely by Event 3 event ID; retain the evidence's selected-window meaning.
Observation timestamps can refresh; byte-identical state files are not promised.

The earlier live validation emitted one additional detection and six activity
events without a source append, then settled to zero. Its production-risk note
remains relevant: consumers treating every aggregate as a new action can miscount
activity or promote duplicate incidents. The isolated two-part store on starting
commit `0fe85f062db5e7ebe818ebde83b6ac0aa693ac48` and the corrected build showed
2/1/1 parsed records and 2/2/0 emitted aggregates. Current synthetic
characterization confirms those counts with unchanged database/WAL bytes and
high-water; earlier fingerprints remain retained. Both whole-source baseline
snapshots and source contributions stay empty because `PartialSource` cannot
replace whole-source accounting.

This limitation is accepted as nonblocking **only within the existing bounded
selected-window/session-aggregate contract**, not because it predates this change.
Cumulative snapshots, exactly-once actions, or global replay invariance would be
different acceptance criteria. Neither arbitrary suppression of changed evidence
nor installation of a partial baseline is safe; no persisted reconciliation
redesign is promised by this candidate.

The public embedding facade persists nothing. Without a resume token it reads the
bounded bootstrap selection; with a host-persisted `ResumeToken` it applies the
same schema-specific incremental read policy as the CLI cursor. Legacy parts
use the overlap and 25,000-part limit; v2 uses overlapping complete tokens and
strict raw-cut continuation tokens, with a whole-timestamp-group limit rather
than ordinary selection overflow. Both schemas detect checkpoint regression as
`AcquisitionError::ResumeRegressed`; see
[embedding recovery](embedding.md#resuming-opencode-scans). It has no persisted
suppression. Repeated scans of unchanged selected input have stable action
semantics and Event 3 semantic projections, apart from fresh event IDs and
materialization clocks.
Detailed replay identities require source time and unambiguous semantic preimages;
selection, continuation, or duplicate ambiguity can change identity or availability.
Retain fallback coordinates bound independently to exact source identity. Measured
adoption through an isolated vendor-neutral public facade passed 33 and 75
downstream-consumer tests; this supports that adoption path, not native platform,
live append, or release qualification. Updates outside overlap and unsampled
history remain coverage limits.

## Validation scope

Synthetic tests cover realistic multiline output, raw UTF-8 and encoded-size
boundaries, malformed/oversized nested input, the exact patch exception, stable
IDs across content changes, detection and hashing beyond 4,096 bytes, active WAL
append, fresh-process repeats, required output failure, cursor retention on
rejection, repair and restart. Existing multi-page WAL snapshot, inclusive ties,
overlap updates, late-page rejection and activation tests remain relevant.

Earlier live validation used one Windows OpenCode Desktop v2.0.24 store on
2026-10-06, using default discovery, bundled rules, `--no-local-config`, isolated
temporary logs/state and no `--allow-fixtures`. Transcripts and private workstation
evidence stay outside the repository. Append is claimed live only if upstream
changes are observed; deterministic WAL tests otherwise cover append/recovery.

The corrected debug build acquired 283 selected native records (88 messages and
195 eligible parts), with zero parse errors. The summary reported five detections
(including one process-chain detection) and eight activity events using bundled
rules. All 21 JSONL objects across bootstrap and repeats, including health,
validated against the Event 3.0 schema with format validation. Incremental
repeats acquired 102 records, retained cursor
high-water and settled to zero emitted events after the transition described
above. This establishes supported live acquisition of the selected window,
not complete historical coverage or unrestricted production readiness.
After the final admission changes, a fresh default-discovery bootstrap again
acquired 283 records without parse errors, reported five detections and eight
activity events, and produced 14 schema-valid JSONL objects. A repeat using the
settled incremental state acquired 102 records and emitted zero events.

Database and WAL hashes were unchanged during that scan series. A later check
saw changed WAL bytes without changed message/part counts or update high-water;
no live append to these session tables was demonstrated. Tests exercise committed
WAL append, same-state restart, failed required JSONL persistence, rejected input
and repair instead. All validation artifacts and source hashes remain temporary
workstation evidence, outside the repository.

Workspace library tests, doctests, formatting and strict workspace/all-target
Clippy passed. The broad Windows CLI run passed 237 tests and failed eight.
Three release/document checks passed after repairing the inherited process PATH;
the release-pin byte hash is affected by this checkout's CRLF conversion and
passes on the LF starting-commit archive. Two cross-process lock tests pass on
both the starting commit and corrected build when isolated; two scan-concurrency
tests fail on the starting commit too,
at their ten-second startup deadlines. The temporary lock-holder lifetime is
also only thirty seconds. These timing-sensitive failures are not treated as
passing release gates or as demonstrated regressions in this change.
Subsequent candidate test-harness repairs address the confirmed concurrency
defects with focused Linux synthetic validation; they do not retroactively pass
that Windows run. The exact original eight failing test names are unavailable,
and no native Windows rerun is available. Required candidate gates remain pending.

### OpenCode v2 session-message validation

On 2026-10-13, bounded live validation used OpenCode v2.0.28 on Fedora Linux 44,
read-only aggregate SQLite queries, discovery, bundled rules, `--no-local-config`,
isolated temporary logs/state and no `--allow-fixtures`. The v2.0.28 tagged shell,
result, publisher and updater code matched the settlement evidence path.

Five generated agent `shell` calls all reported `executed: false` and `time.ran`.
Foreground exit 0, exit 3, timeout and signal calls each emitted request,
execution-completed and result stages; the background call emitted only request
and result (14 observations across five calls). Exit codes carried no status;
the signal was `SIGTERM`; timeout reported `Failed` without an exit or signal.
Background metadata remained `running` with `shellID` after the command finished.
A bounded recent acquisition returned 16 native rows and 50 observations; one
local error and one running entry gained no execution stage. Historical shell
error metadata also carried `shellID`, refuting the background-only description.

The default bootstrap and two CLI repeats each reported one parse-error source,
zero parsed records and `invalid_native_contribution`, before canonical mapping.
No SQLite cursor was installed. All seven emitted JSONL objects (one health,
one scanner error and five static MCP inventory activity events) validated
against Event 3.0 with format checking. Repeats emitted zero new objects, but
the source still failed: successful ingestion and incremental settling were
**blocked**, not passed. Existing fail-closed contribution bounds were not relaxed.
The v2 adapter then scanned terminal tool results and shell output for contributions;
a synthetic test reproduces `invalid_native_contribution`
from a long encoded token in a tool result. Contributions are now request-side
only, with the bound unchanged for input. The earlier run does not establish
successful ingestion with the request-side fix.

No denial/interruption was deliberately generated. Historical user `!` shell
rows existed but their mapping was not live-validated. Changes occurred during
the scan series, so unchanged-store repeat behavior, controlled live append,
other OpenCode versions/platforms and release qualification remain unvalidated.
Temporary data and harnesses were deleted; tests remain synthetic.

On 2026-10-14, with request-side contributions, row quarantine and window
draining in place, a read-only validation with aggregate evidence only drained
the newest 5,000 messages in 2 scans in about 30 seconds (previously 31 scans
and about 9.5 minutes). A `--history all` pass over the whole store evaluated
1,627 windows and 996,406 records (re-reads included) in about 13 minutes with
no source failure, reported 292 quarantined units by coordinates, and emitted
16,758 objects that all validated against Event 3.0. That build reported a
quarantined row again when an overlapping window re-read it, so 292 is an
upper bound on distinct quarantined rows; such a row is now reported once. Correlations straddling a window
cut are covered by synthetic tests only. The limits listed above still apply.
