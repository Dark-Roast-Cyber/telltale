# Migration contract

The standalone state migration command is explicit and state-only:

```sh
telltale migrate state --from <OLD> --to <NEW>
```

Native scans emit and consume Event 3.0. Historical Event 1.0 and 2.0 records
remain explicit read/import inputs; they are validated against their immutable
schemas and are never rewritten as native events. Normal runtime paths and
environment names use the canonical `TELLTALE_*` contract in this slice.
Retired `ADR_*` runtime variables fail closed before command parsing or any
configuration, filesystem, or network activity. The explicit migration commands
below remain the only supported way to transform legacy files.

Legacy default files such as `adr-events.jsonl` and `adr-state.json` are not
probed, rewritten, or adopted by the canonical runtime. They remain byte-for-byte
untouched until an operator performs an explicit migration. Consequently, an
unmigrated first run starts with fresh canonical state and may re-emit detections
that were already represented in the legacy state or log.

Historical event files and environment files have separate explicit commands:

```sh
telltale migrate events --pair <OLD> <NEW> [--pair <OLD> <NEW> ...]
telltale migrate env --from <OLD> --to <NEW>
```

Event pairs are ordered. A destination may occur in more than one pair; its
output is the exact byte concatenation of its source contributions. The source
and destination compression must match (`.gz` selects gzip). The event command
streams source bytes through fixed buffers, validates decompressed JSONL frames
with a 16 MiB per-frame bound, and copies compressed input bytes unchanged.
Oversize frames fail with a static error; malformed gzip is rejected. A
concatenated gzip member sequence is one source contribution: member boundaries
are not destination-contribution boundaries and do not require an LF. LF
composition is checked only between explicit `--pair` contributions. Destination
bytes are spooled to synchronized, same-directory temporary files and are
installed only after every pair has validated.

For each destination, a nonempty contribution after another nonempty
contribution must have an LF boundary from the preceding contribution. A final
nonempty contribution may omit its final newline, but that contribution must be
the final nonempty contribution for that destination. The same rule is applied
to each complete explicit contribution, including a contribution made from
concatenated gzip members. Invalid joins fail before any destination or
manifest is installed.

The first pair's destination is the canonical event-manifest anchor and owns
`<destination>.migration.json`. The manifest retains aggregate source and
destination counts and hashes and also contains ordered destination entries
with an ordinal, compression, source byte count and hash, and destination byte
count and hash. It contains no paths, event IDs, or values. The complete
manifest is the recovery journal and is installed after destination files. A
matching manifest and its explicit source hashes permit a rerun to repair a
missing secondary destination, but only from the exact bytes recomputed from all
explicit pairs. A conflicting existing secondary, canonical destination, or
manifest fails without replacement. A canonical manifest without its canonical
destination is not silently adopted. Multi-file installation is therefore
recoverable and journaled, not globally atomic: a crash or failure between
destination installs can leave an incomplete subset, and a later identical run
repairs that subset without clobbering existing bytes or changing sources.

Environment migration streams and rewrites each bounded line while preserving
opaque right-hand sides, comments, line endings, and final-newline framing. It
uses one exact audited inventory of approved ADR product keys, including the
ATLAS, build, live-test, index, sourcetype, path, rotation, inventory,
process-chain, operational-alert, and risk-threshold mappings. The retired
`ADR_TRIAGE_TIMEOUT_MS` and `ADR_TRIAGE_MAX_RETRIES` keys are rejected exactly;
other non-inventory names are preserved verbatim. Environment output and its
manifest are owner-only on Unix. The source is digest-rechecked after
transformation and immediately before destination installation, so a same-length
source mutation fails before installation.

## Migration budgets

Event migration has fixed cumulative limits. Raw source bytes, including all
compressed bytes read from explicit pairs, are limited to 512 MiB. Decompressed
JSONL frame bytes, including blank frames and line endings, are limited to 512
MiB. The combined bytes written to destination spools and the disk-backed
collision-body spool are limited to 1 GiB. Nonblank records are limited to
1,000,000; total frames are limited to 1,000,000; blank frames are limited to
100,000; and unique event IDs retained in the in-memory collision index are
limited to 100,000. The collision bodies remain disk-backed, but that 100,000
ID cap is a hard in-memory index cap. Gzip expansion is separately limited to
256 MiB of decompressed bytes produced by gzip decoders, cumulative across all
members and pairs. The 16 MiB frame limit remains in force independently. At
most 64 explicit pairs and 32 unique destinations are accepted; these
structural caps are checked before path validation, lock creation, temporary
spools, or destination/manifest activity. They bound metadata and filesystem
fan-out that byte budgets do not measure. Pair and destination cap failures
return static errors and leave no migration side effects.

Environment migration limits the raw source to 16 MiB, rewritten output to 16
MiB, input lines to 1,000,000, each line to 1 MiB, and assignments to 100,000.
Counters use checked arithmetic and each over-limit condition returns a bounded
static error; migration never emits a `complete` manifest after a budget
failure. Temporary spools may be created and cleaned up while validation is in
progress, but no destination or manifest is installed after a failed budget
check. The existing status/export historical reader, which materializes a
historical JSONL file for compatibility, is outside this primitive's streaming
budget contract.

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
Before accepting exact-idempotent existing bytes, migration rejects an existing
event destination broader than `0640` and an existing state, environment, or
manifest target broader than `0600`; it never silently chmods an existing file.
On Unix, every existing migration destination and manifest must also be owned by
the effective UID. Windows currently fails closed with the bounded
`existing migration target ownership is unsupported on Windows` error whenever a
migration destination or manifest already exists; new targets can be installed,
but native owner/ACL support is required for Windows idempotent reruns.
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
- Duplicate records with the same event ID remain in their original order when
  their raw JSON object bytes match; LF, CRLF, and a missing final newline are
  framing differences and do not create a collision. A genuine object-byte
  difference for one event ID fails.
- Historical event records must declare an exact supported `schema_version`.
  The immutable 1.0 and 2.0 schemas validate the original JSON value without
  deserializing it into native `Event`, regenerating IDs, or normalizing fields.
- Unknown fields and the original event ID are retained. One event ID with
  differing raw object bodies is rejected; exact duplicate object bodies remain
  valid.
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
