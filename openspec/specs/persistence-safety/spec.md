# persistence-safety Specification

## Purpose

Defines the persistence-lock verification behavior that protects Telltale state
and other lock-coordinated files from being silently accepted after mutation.

## Requirements

### Requirement: Strict verification fails closed on protected target mutation

The system SHALL provide a strict persistence-lock mode whose verification
compares the protected target with the state observed when the lock was
acquired. For an existing target, verification SHALL fail on an observed
identity, link-count, length, timestamp-metadata, deletion, replacement, or
content change. For a target absent at acquisition, verification SHALL fail if
the target is subsequently created.

#### Scenario: Unchanged target verifies successfully

- **WHEN** a strict persistence lock is acquired for an existing target and the
  target remains unchanged until verification
- **THEN** verification succeeds

#### Scenario: Same-length content mutation fails

- **WHEN** a strict persistence lock is held and the protected target is
  rewritten with different bytes of the same length
- **THEN** verification returns an error even if the target identity, length,
  and available timestamp metadata compare equal

#### Scenario: Different-length mutation fails

- **WHEN** a strict persistence lock is held and the protected target changes
  to a different length
- **THEN** verification returns an error

#### Scenario: Replacement identity change fails

- **WHEN** a strict persistence lock is held and the target path is replaced by
  another regular file
- **THEN** verification returns an error, including when the replacement has
  the same length or equal bytes

#### Scenario: Deletion and creation transitions fail

- **WHEN** a strict persistence lock is acquired for an existing target and
  that target is deleted, or is deleted and recreated before verification
- **THEN** verification returns an error

### Requirement: Windows strict verification does not rely on timestamps alone

On Windows, strict verification SHALL retain handle-derived identity and
metadata checks and SHALL compare the complete current content with a digest
captured at acquisition whenever the inexpensive metadata still compares equal.
The digest comparison SHALL use a pinned read observation with before/after
stability checks; an unstable read or digest mismatch SHALL fail closed.
Timestamp values, including `LastWriteTime` or an independently available
change-time value, SHALL NOT be treated as a complete mutation counter.

#### Scenario: Timestamp-coalesced same-length rewrite fails

- **WHEN** a Windows target is rewritten in place with different same-length
  bytes while the observed write timestamp remains equal or is restored to the
  acquisition value
- **THEN** strict verification returns an error because the content differs

#### Scenario: Unstable content observation fails closed

- **WHEN** the target changes while its content is being read for strict
  verification
- **THEN** verification returns an error rather than accepting the read as an
  unchanged baseline

### Requirement: Intentional mutation paths retain lock-only coordination

The system SHALL provide a lock-only mode for operations that intentionally
mutate a protected target while holding its sidecar lock. Lock-only operations
SHALL retain their existing target identity, append/replace, pinned-source,
post-write, and sidecar verification checks, and SHALL NOT be required to hash
an arbitrarily large mutable log merely to acquire its sidecar lock.

#### Scenario: JSONL append remains compatible

- **WHEN** the local JSONL sink acquires a lock, appends and flushes a batch,
  and performs its existing post-write checks
- **THEN** the append succeeds without strict immutable-target verification
  rejecting the intentional write

#### Scenario: Atomic state persistence remains compatible

- **WHEN** a state save acquires a strict lock, prepares a same-directory
  temporary file, verifies the destination immediately before replacement, and
  performs the existing atomic replacement
- **THEN** the replacement succeeds and the state lock continues to fail
  closed if the protected destination changed before commit

#### Scenario: Sidecar replacement remains detected

- **WHEN** the sidecar path is deleted or replaced while a lock object is held
- **THEN** sidecar verification returns the existing fail-fast lock-integrity
  error
