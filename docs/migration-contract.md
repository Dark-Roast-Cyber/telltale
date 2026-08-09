# Migration contract

The standalone state migration command is explicit and state-only:

```sh
telltale migrate state --from <OLD> --to <NEW>
```

Native scans emit and consume Event 3.0. Historical Event 1.0 and 2.0 records
remain explicit read/import inputs; they are validated against their immutable
schemas and are never rewritten as native events. Normal runtime paths and
environment names remain unchanged in this slice.

## Scanner state

Native state is UTF-8 JSON with two-space indentation, LF line endings, one
trailing newline, and a required top-level `state_schema_version: "1.0"`.
The existing fingerprint, baseline, source-observation, SQLite-cursor, and
install-inventory families remain present. A missing state file means empty
native state. Normal scanning rejects empty, malformed, unversioned,
duplicate-key, unknown-version, unknown-field, and raw network-host native
state with bounded guidance to the explicit migration command.

The migration command accepts the known legacy unversioned state shape or
native 1.0 for relocation. It recursively rejects duplicate keys and unknown
fields. It preserves fingerprints, cursor values and keys, baselines,
contributions, observations, timestamps, and inventory order. The only
normalizations are the existing unsalted SHA-256 network-host identity
normalization and promotion of the nested baseline store to its current
schema. It never rebuilds, drops, recomputes, or advances state.

The documented legacy compatibility window permits omitted
`source_instance_id` fields in source observations, SQLite cursors, and source
contributions, plus omitted optional inventory `path_hash` and baseline key
option fields. Native state permits none of those omissions: every serialized
field is required, the nested baseline version must be current, and every
persisted network host key must be exactly `sha256:` followed by 64 lowercase
hexadecimal characters.

The source is untouched. The destination is installed only when absent; an
existing destination succeeds only when its bytes are identical to the
deterministic expected bytes, otherwise the migration fails with a conflict.
Successful migration prints a deterministic value-free manifest containing
formats, SHA-256 hashes, byte totals, family counts, normalization count, and
completion status. `normalization_count` includes each raw or malformed host
key corrected during either legacy or native migration, as well as baseline
schema promotion. The companion is written atomically at
`<destination>.migration.json`; stdout repeats the same bytes but is not the
durable record. On Unix, the companion installation also syncs its parent
directory. On Windows, file contents are flushed and the rename uses
write-through semantics, but parent-directory durability is not asserted. A
rerun repairs a missing companion when destination bytes are identical, accepts
an identical companion as a no-op, and refuses conflicting destination or
companion bytes. It contains no paths, IDs, host values, or secrets.

State and sidecar locks are permanent and cross-process advisory locks. They
coordinate cooperating Telltale processes when the parent directories are
trusted; they do not protect against an arbitrary same-account process that
mutates files outside the protocol. Migration holds all participating state
and manifest locks through validation and no-clobber installation. Final
symlinks/reparse points, non-regular files, unsafe hardlinks, and source or
destination aliases are refused. Lock contention fails fast with a bounded
busy error.

Native state and migration manifests are created with owner-only permissions
(`0600`) on Unix. The local JSONL file is created no broader than `0640`.
State and log target namespaces, including sidecars and the migration
companion, must not overlap. Enabled local JSONL rotation also reserves its
`<stem>-*<extension>` namespace, including paths that do not exist yet, so
cleanup cannot remove state, migration, sidecar, or another local sink data.
Normal scans validate these relationships before processing. Dry-run scans read
a pinned, read-only snapshot and do not create a state parent or lock;
concurrent changes during that snapshot fail closed.

Filesystem guarantees use private platform helpers: Unix file identity is
device/inode plus modification/change times, and Linux no-replace installation
uses `renameat2`; macOS uses `renameatx_np`. Windows uses handle volume/file
IDs, reparse-point-safe opens, last-write evidence, writable file-handle flushes, and
`MoveFileExW` with write-through. Windows parent-directory flush is not
asserted because this implementation does not claim a supported local
directory-handle durability primitive. Unsupported platforms fail closed
rather than falling back to check-then-replace behavior. Conditional target
identity checks occur immediately before native replacement, but no portable
primitive makes that path check immune to an untrusted-directory race.
Missing path suffixes use native ordinal case-insensitive comparison on Windows.
macOS volume case sensitivity cannot be queried portably here, so ASCII
case-only aliases are rejected as aliases and differing non-ASCII spellings
fail closed; existing ancestors are canonicalized and existing file identities
are still compared. Other case-sensitive Unix filesystems retain exact
comparison.

Prepared files use unpredictable same-directory names and are removed on every
ordinary error path. A process crash can leave an ownerless temporary file;
these names are never considered state or manifests, are not adopted on a
later run, and may be safely removed by an operator after confirming no
migration is active.

## Historical events

- Inputs and outputs are explicit paths. Validation always carries each parsed
  `serde_json::Value` alongside its untouched raw JSONL record bytes from one
  stable source snapshot. Raw bytes and record order are always retained.
- Byte-identical duplicate records remain in their original order; the same
  event ID with non-byte-identical records fails.
- Historical event records must declare an exact supported `schema_version`.
  The immutable 1.0 and 2.0 schemas validate the original JSON value without
  deserializing it into native `Event`, regenerating IDs, or normalizing fields.
- Unknown fields and the original event ID are retained. One event ID with
  differing bodies is rejected; exact duplicate records remain valid.
- No historical record is rewritten to Event 3.0. Raw source bytes are always
  retained alongside the parsed values for byte-level provenance.

The runtime write path holds its state lock from load through parsing,
detection, durable delivery, and commit. It pre-serializes and syncs a
same-directory exclusive temporary file before delivery, then installs it only
after durable delivery succeeds. It validates before install, cleans up
temporary files on success and failure, atomically replaces the native state,
and syncs the parent directory where supported. On Windows, file contents are
flushed and the replacement uses write-through rename semantics; parent-
directory durability is not asserted. It does not probe retired path aliases
or silently create fresh replacement state.
