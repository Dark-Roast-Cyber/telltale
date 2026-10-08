# OpenCode live ingestion limits and recovery

The 0.7 canonical cutover introduced a regression relative to 0.5: native
OpenCode tool output became ordinary structured JSON, with a 4,096-byte string
limit. One supported large result rejected the entire acquisition. The older
parser passed these outputs through without this canonical policy. Restoring
the unbounded parser would lose the newer resource admission guarantees.

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
failure reject the entire source without partial successful output. OpenCode
bound diagnostics expose only closed field/dimension enums, never payloads,
dynamic keys, source IDs, paths or measured sizes.

Progress is staged only after successful processing. Required canonical JSONL
persistence, or durable outbox retention, precedes scanner state installation.
Rejected acquisition or required persistence failure leaves the prior cursor.
After input becomes supported or the sink is repaired, restart with the same
state/output configuration: the inclusive overlap retries pending data. Deleting
state or bypassing rejection is not required. Remote-only best-effort delivery
retains its documented non-recoverable posture; this change adds no durability.

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
same incremental read policy as the CLI cursor (high-water minus the overlap,
25,000-part limit, overflow fails as `LimitExceeded`). It has no persisted
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

Live validation is limited to one Windows OpenCode Desktop v2.0.24 store on
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
