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
strictly re-validatable with `ActionRecordV1::from_json` (since 0.8.0 an upload
action's entry may also carry its `destinations` facts beside the record). Host fields cover
what Telltale does not: harness and hook identity, permission mode, session,
subagent and prompt IDs, verdict, basis, scores, enforcement outcome, and
evaluation status (coverage, visibility limits, failure codes, timings).

The envelope has no fields for raw prompts, tool inputs, outputs, or working
directories. Input and working directory fields contain only SHA-256 digests;
prompt fields contain only a length and digest. Detection evidence travels
redacted inside the action record. Native harness labels are separate fields.

## Strict readback

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
Harness labels follow the encoding in the addendum below. Redaction
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

## Consequences

- SIEM mapping (Elastic, Splunk HEC) happens at the transport boundary,
  per Telltale guidance; a later issue covers shipping.
- When Telltale ships Event 4.0, re-evaluate whether decision/outcome
  records should move into it; keep `delivery_key` stable across that move.

## Addendum (2026-11-26): bounded telemetry labels

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
