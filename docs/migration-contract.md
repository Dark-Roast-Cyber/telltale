# Migration contract

This is the contract for the later explicit migration command. The current
scanner does not invoke it.

- Inputs and outputs are explicit paths. Validation always carries each parsed
  `serde_json::Value` alongside its untouched raw JSONL record bytes from one
  stable source snapshot. Raw bytes and record order are always retained.
  Byte-identical duplicate records remain in their original order; the same
  event ID with non-byte-identical records fails.
- Destination semantics are explicit: a normally absent destination is
  installed once, an existing destination with the identical expected hash is
  a no-op, and a conflicting destination fails without overwrite. The expected
  hash is SHA-256 over the complete deterministic destination bytes, calculated
  and compared while holding the destination lock. Concurrent installation must
  not clobber a destination.
- Historical event records must declare an exact supported `schema_version`.
  The immutable 1.0 and 2.0 schemas validate the original JSON value without
  deserializing it into native `Event`, regenerating IDs, or normalizing fields.
- Unknown fields and the original event ID are retained. One event ID with
  differing bodies is rejected; exact duplicate records remain valid.
- No historical record is rewritten to Event 3.0. Raw source bytes are always
  retained alongside the parsed values for byte-level provenance.
- Legacy `ScanState` is imported only by an explicit migration. Unknown fields
  are refused by that future import path; normal state load/save remains
  unchanged until then. The current legacy golden fixture is semantic evidence,
  not a byte-exact snapshot: existing raw baseline hosts are normalized to
  unsalted SHA-256 identities by the unchanged load path.

The later write path must hold its lock through commit, use a same-directory
exclusive temporary file, validate before install, clean up temporary files on
success and failure, flush/sync the file, atomically rename it, and sync the
parent directory. It must not probe retired path aliases or silently create
fresh replacement state.
