# ADR 0005: Host envelope around unmodified ActionRecordV1

Status: Accepted (2026-11-04)

## Context

Telltale: "Hosts forward these; they do not design their own action format"
(`docs/embedding.md`, host wire). Telltale models detections, not hook
decisions, harness lifecycle, or whether enforcement held; Event 4.0 alert
records are planned but inactive.

## Decision

One JSONL record per hook observation, schema `telltale_hooks.record.v1`
(`schemas/telltale-hooks-record-v1.schema.json`), kinds `decision`,
`outcome`, `result_finding`, `lifecycle`, `error`. Detection content travels
only as `telltale: [{delivery_key, record: ActionRecordV1}]`, unmodified and
strictly re-validatable with `ActionRecordV1::from_json`. Host fields cover
what Telltale does not: harness and hook identity, permission mode, session,
subagent and prompt IDs, verdict, basis, scores, enforcement outcome, and
evaluation status (coverage, visibility limits, failure codes, timings).

Privacy: no prompts, tool inputs, outputs, or paths. Inputs and cwd appear
only as SHA-256; prompt length and hash only. Telltale's redacted evidence is
the only content.

## Consequences

- SIEM mapping (Elastic, Splunk HEC) happens at the transport boundary,
  per Telltale guidance; a later issue covers shipping.
- When Telltale ships Event 4.0, re-evaluate whether decision/outcome
  records should move into it; keep `delivery_key` stable across that move.

## Addendum (2026-11-26): upload destination facts

Status: Accepted. Amends "Decision" for 0.8.0; the record version stays
`telltale_hooks.record.v1` because the field is optional and additive.

An entry of `telltale` whose action carries `exfil.outbound_upload` may also
hold `destinations`: the upload's destination facts
(`DestinationFacts`: `destinations`, `complete`, `local_only`), beside the
unmodified record. Evidence is redacted, so without them a host cannot tell
an upload to its own artifact host from one to an unknown host.

This adds one content source to the privacy statement above. Besides
Telltale's redacted evidence, a record may now carry destination entries:
hosts and at most two path segments or an object-storage bucket and prefix,
built from parsed URL parts in a closed alphabet, never a port, userinfo,
query or fragment, and kept only when the evidence sanitizer leaves them
unchanged. A strict reader checks them with `DestinationFacts::is_valid`.

## Addendum (2026-11-26): strict readback and the line bound

Status: Accepted. Adds a supported reader; the record version is unchanged.

Pass a complete JSONL line to `telltale_schema::hooks_record::HooksRecordV1::from_json`.
Embedding hosts can use `telltale_core::HooksRecordV1` with or without the
`hooks` feature. `validate()` applies the same checks to a record built in
memory. Ordinary serde deserialization alone is not validation.

`HOOKS_RECORD_MAX_INPUT_BYTES` is 16 MiB per JSONL record, including its
line feed. The writer never appends a longer line. The runtime replaces
an oversized record with an `error` record coded `telemetry_record_too_large`,
keeping the original ID, time, producer, harness, session and optional action.
The verdict is unaffected. An outcome can still link to the original ID
even when the corresponding decision was replaced.

The consumer checks the published envelope schema, validates each embedded
action with `ActionRecordV1`, and checks internal consistency. This includes
the blocks allowed for each kind, delivery keys, destination facts, verdicts,
grant and outcome accounting, and scores and summaries derived from the
embedded findings. The consumer validates one record at a time; it cannot
confirm that a record linked by ID exists or that a harness reported truthfully.

Open-form text must already be a fixed point of the current sanitizer.
Harness labels follow the encoding in the next addendum. Redaction
changes can also make a line from a different producer version fail. A
successful check is evidence about the current sanitizer, not authentication
or a guarantee that the line contains no sensitive information.

Errors contain only a category and a stable code:

| Category | Codes |
| --- | --- |
| Malformed | `malformed_json` |
| Version | `unsupported_record_version` |
| Structure | `input_too_large`, `schema_mismatch` |
| Identity | `delivery_key_mismatch`, `action_source_mismatch` |
| Semantic | `inconsistent_kind`, `invalid_action_record`, `invalid_destinations`, `inconsistent_evaluation`, `inconsistent_verdict`, `inconsistent_grant`, `score_mismatch`, `finding_summary_mismatch`, `inconsistent_outcome`, `inconsistent_lifecycle`, `unredacted_text` |

## Addendum (2026-11-26): bounded telemetry labels

Status: Accepted. Amends the privacy statement in "Decision": harness labels
are content too, and are now bounded as follows.

The writer now checks native labels before putting them in a record.
These are `harness.hook_event` and `permission_mode`, session, agent and
prompt IDs and agent type in `session`, `action.tool_use_id` and
`tool_name`, `outcome.established_by`, and lifecycle `source`, `reason`,
subagent `agent_id` and `agent_type`, and grant `tool`. A label stays as
reported only if it is nonblank, at most 256 UTF-8 bytes, has no control
characters or leading or trailing whitespace, and is unchanged by the
Metadata sanitizer (Summary for a session-end reason). An absent optional
label remains absent or null as specified by its field; empty sentinels
still identify terminal or unhandled records without a session.

Other labels become `tth-esc-` followed by the first 32 lowercase hex
digits of SHA-256 of the raw value. Equal raw values produce equal stand-ins
across records. This is a keyless hash: someone who can guess a low-entropy
raw value can hash the guess and recognize its stand-in.

The strict reader accepts only a readable label or a stand-in of the stated
shape. An earlier file can contain raw labels that now fail readback.
The change is at the telemetry boundary; the journal, state, evaluation and
harness response continue to use their existing encodings. Record IDs and
links are unchanged.

When a terminal grant starts from a tool-name stand-in, `telltale hooks
allow` asks for the exact native tool name before asking for confirmation.
It verifies the name against the stand-in and stores the native name for
the existing exact grant match. The confirmation displays the stand-in.
`allow` skips oversized input lines and checks that the grant lifecycle
record fits the shared 16 MiB bound before storing the grant.
## Addendum (2026-11-26): size rotation and incremental readback

`hooks.telemetry.max_size_bytes` defaults to 100 MiB; zero disables
rotation. Before an append would exceed the threshold, the writer archives
the nonempty active file as `<stem>-YYYY-MM-DD[.<counter>].<extension>` and
appends to a fresh file. A single record larger than the rotation threshold
is written whole to an empty file. The 16 MiB per-line limit still applies.
`hooks.telemetry.keep` defaults to five archived files; zero keeps only the
active file. Cleanup removes the oldest archives after the append.

Writers try for up to 200 ms to take an exclusive lock on a stable sidecar
named by appending `.lock` to the active file name, even when their own
rotation is disabled. If the sidecar cannot be opened or locked, the writer
appends to the active path without rotating or pruning. That append can
race another writer's rename and land in the file that was just archived.
`telltale hooks allow` still searches that file while it is retained.
If rotation fails or directory discovery reaches its entry bound, the writer
reports the rotation failure and attempts to append through its already-open
handle. Cleanup reports failed removals and continues with the other archives.
These failures do not turn a successful append into a write error or change
the verdict.

Embedding hosts can poll `HooksRecordFeed` without enabling the Hooks runtime.
It returns strictly validated records and closed-code rejections, each
rejection identifying an opaque generation and byte offset. An incomplete
line in the active file is deferred until its line feed arrives. Persist the
cursor only after handling the batch. If its generation was deleted or
replaced, or was truncated below the cursor, a gap notice means records may
have been lost. The feed resumes at the oldest available position and may
return records the caller has handled before.
A fallback append that lands in a just-archived file can be missed by a feed
that has already moved past that generation.
