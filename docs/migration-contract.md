# Scanner state and historical events

This version does not provide `telltale migrate state` or `telltale migrate
events`. There is no shim and no in-place rewrite. Published v0.7.0 retains
both commands. Use that binary for explicit state migration, then select the
destination before scanning with a later build. This is not a
claim that a newer release is published or fully qualified.

`migrate state` on published v0.7.0 writes current native state. It can accept
the known unversioned state shape and native 1.0 state whose nested baseline
schema is 1 or 2. It does not repair empty files, duplicate keys, unknown
fields, an unknown `state_schema_version`, or plaintext hosts in current
baseline schema 3.

`migrate events` on that binary relocates explicit historical files without
rewriting Event 1.0 or 2.0 records as Event 3.0. Read or export those journals
with the retained older binary. Current export and status accept only Event3;
an obsolete record anywhere in the input makes the journal fail validation.
Select a separate Event3 journal for current scans. Do not truncate or relabel
historical evidence to make it appear current.

## Scanner state

Native state is UTF-8 JSON with two-space indentation, LF line endings, one
trailing newline, and a required top-level `state_schema_version: "1.0"`.
The fingerprint, baseline, source-observation, SQLite-cursor, and
install-inventory families remain present. A missing state file initializes
empty native state and does not create the file until a successful save.
Existing state is never replaced with empty state because it failed to parse.

A missing `state_schema_version` on an object that has a known state family,
or native 1.0 state whose nested baseline schema is 1 or 2, is rejected by
marker and left unchanged. That diagnostic is not a migration-eligibility
check. It says the file may use an older format or be invalid. Published
v0.7.0 migrates supported older state only. It does not repair invalid data,
and this version does not validate whether a particular file is eligible.
Empty files, duplicate keys, unknown top-level fields or versions, and invalid
current-baseline data are rejected as invalid state. A nested defect in an
old-marked file does not make the conditional upgrade guidance proof of validity.

The nested baseline version must be current. Every persisted network host key
must be exactly `sha256:` followed by 64 lowercase hexadecimal characters.
That rule applies to both `baseline_snapshots` and
`baseline_source_contributions`. A hashed host in current schema remains
valid. Raw labels are not echoed in the rejection.

OpenCode v2 unfinished windows optionally carry `draining: true` plus
`continue_after_time_updated`, the raw cut independent of the monotone
`last_time_updated` checkpoint. A cut must be an integer no greater than the
checkpoint and is valid only on an exact `opencode` / `opencode.sqlite` /
`session_message` draining cursor. An older draining cursor with no raw cut
remains readable and replays the checkpoint's overlap, rather than assuming a
strict cut. A cut past the checkpoint is invalid, not an older migratable
shape. The raw cut is removed when the drain completes. No top-level version
change is required.

Explicit `cursor reset` is a separate, intentionally lossy maintenance
operation, not migration or baseline replacement. With exact instance/table
selection, matching inspection digest and explicit history-gap acceptance, it
removes the whole selected OpenCode cursor record. An unfinished drain
requires the separate abandonment acknowledgement, including an older drain
without a raw cut. Every other cursor, baseline and fingerprint remains
unchanged. It evaluates nothing and installs no scan progress. Preparation
failures preserve state. See the
[operator procedure](opencode-live-ingestion.md#explicit-operator-cursor-reset).

Native state requires every serialized field. It does not accept omitted
`source_instance_id` fields or omitted optional inventory `path_hash` values.

The `<path>.migration.json` suffix remains reserved. State, log, sidecar, and
that companion name must not overlap, including when the file does not exist.
This version does not write the companion. Enabled local JSONL rotation also
reserves its `<stem>-*<extension>` namespace. Normal scans validate these
relationships before processing. Dry-run scans do not create a state parent
or lock.

State and sidecar locks are permanent and cross-process advisory locks. Lock
contention fails fast with a bounded busy error. The runtime write path holds
its state lock from load through parsing, detection, durable delivery, and
commit. It installs a same-directory temporary file only after durable
delivery succeeds. It does not silently create fresh replacement state for an
existing file that failed validation.
