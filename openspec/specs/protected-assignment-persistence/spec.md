# protected-assignment-persistence Specification

## Purpose
Define the opt-in local durable store and replay-association contract for
Canonical Observation v2 protected assignments. The capability allocates and
verifies assignment identity without deriving a source coordinate, exporting
local identity state, or activating any adapter or detection path.
## Requirements
### Requirement: Replay association is stable, unambiguous, and protected

A caller MUST provide a bounded, versioned replay-association namespace and
opaque locator whose source contract proves that it remains attached to exactly
one source fact across every supported replay, insertion, deletion, reorder,
edit, truncation, source-root move, and artifact move. Distinct facts, including
semantic duplicates, MUST have distinct locators. Ambiguous association MUST
fail closed and MUST NOT use nearest, first, ordinal, timestamp, path, semantic
value, or unkeyed content-hash matching.

Raw association material MUST remain transient local evidence. Before lookup or
persistence the store MUST transform it into a domain-separated HMAC token bound
to adapter domain and association namespace. Adapter components MUST be selected
through a closed code-reviewed registry of non-sensitive identifiers; unknown or
dynamic source, tenant, path, session, or credential values MUST be rejected as
adapter identity. Only that protected token may be
stored or indexed as `replay_key`, and it MUST NOT be logged, displayed,
serialized for telemetry, or exported.

#### Scenario: Stable reviewed association replays

- **WHEN** the same source fact presents the same locator under the same
  versioned association namespace after a supported mutation
- **THEN** the protected lookup resolves its existing assignment without
  exposing or persisting the raw locator

#### Scenario: Mutable source candidate is not association

- **WHEN** a caller has only path, task directory, timestamp, mutable array
  ordinal, semantic content, unkeyed content hash, or bare sequence/offset
- **THEN** no safe replay association exists and assignment use remains blocked

#### Scenario: Duplicate facts require distinct association

- **WHEN** two source facts have identical complete semantic content
- **THEN** they can receive distinct assignments only when the source contract
  supplies distinct stable locators; content cannot disambiguate them

### Requirement: First assignment is one atomic claim-or-replay operation

The store MUST expose one operation that accepts a valid coordinate-less,
basis-less canonical builder plus an explicit replay association and either
creates one durable assignment or returns the existing assignment. Callers MUST
NOT choose the assignment reference or observation ID and MUST NOT be required
to perform a non-atomic lookup/generate/write sequence.

The uniqueness boundary MUST be adapter domain, protected replay key, and
canonical child ordinal. Concurrent workers for the same tuple MUST resolve to
one assignment and one observation ID. Commitment disagreement MUST be terminal
and privacy-safe. No assignment may be visible or returned before commit.

#### Scenario: Concurrent first claims converge

- **WHEN** two workers concurrently claim the same valid association and
  complete semantic fact
- **THEN** at most one row is created and both workers resolve to the same
  durable observation ID

#### Scenario: Concurrent disagreement is terminal

- **WHEN** concurrent claims share one association tuple but have different
  complete semantic commitments
- **THEN** one assignment may commit and the disagreeing claim returns
  `replay_collision` without replacing it or exposing content

#### Scenario: Stable coordinate is preferred

- **WHEN** a builder already has a valid native ID, identity-scoped sequence, or
  identity-scoped offset
- **THEN** protected claim rejects it rather than replacing coordinate identity

### Requirement: Assignment observation ID is allocated under durable authority

A new protected assignment observation ID MUST have the exact form
`obs:v2:sha256:<64 lowercase hexadecimal digits>`. It MUST be a domain-separated
SHA-256 result over 256 bits from an operating-system cryptographic random
source, and MUST NOT encode source path, timestamp, semantic values or hashes,
task directory, mutable ordinal, adapter version, or public content.

The random seed is not a source coordinate. The store MUST persist the resulting
observation ID in the same atomic transaction as the association and commitment,
MUST NOT return it before commit, and MUST never generate a replacement after an
assignment exists. Observation-ID or assignment-reference collision MUST retry
only a bounded number of times inside the same transaction and then fail closed.

#### Scenario: Crash before assignment commit

- **WHEN** the process fails before the claim transaction commits
- **THEN** no assignment is visible and a later claim may allocate the first
  assignment

#### Scenario: Crash after assignment commit

- **WHEN** the transaction commits but the process fails before returning the
  materialized observation
- **THEN** a later replay resolves the committed observation ID and does not
  allocate a replacement

### Requirement: Complete semantic commitment remains the replay authority

Every assignment MUST store a protected complete semantic commitment and its
comparison-key reference. Replay MUST recompute the commitment with that exact
retained key. Matching commitment MUST return the existing ID; changed complete
semantics MUST return `replay_collision`; missing assignment/key or ambiguous
association MUST return `replay_unverifiable`; malformed or tampered state MUST
fail closed.

The assignment record MUST bind adapter domain, protected replay key, and child
ordinal. A caller-supplied wrong assignment reference MUST NOT be accepted merely
because another assignment has identical semantics.

#### Scenario: Matching replay is idempotent

- **WHEN** one bound assignment is found and complete semantics match
- **THEN** replay returns its existing observation ID

#### Scenario: Semantic mutation collides

- **WHEN** one bound assignment is found but complete semantic content changed
- **THEN** replay returns `replay_collision` without writing a new assignment

#### Scenario: Wrong reference cannot alias equal content

- **WHEN** a persisted basis references an assignment bound to another replay
  key, domain, or child ordinal with otherwise identical semantic content
- **THEN** verification fails closed and does not return that observation ID

### Requirement: Comparison keys are private, durable, and rotatable

The local store MUST persist versioned key epochs outside assignment rows under
the private local-storage boundary. Root keys MUST come from the operating-system
cryptographic random source. Domain-separated subkeys MUST independently protect
association lookup, semantic commitments, and row integrity.

Exactly one epoch MUST be active for new assignments. Rotation MUST durably
create the new key before atomically activating it, retain all old referenced
epochs for replay, and MUST NOT rewrite existing observation IDs or commitments.
Missing, malformed, ambiguous, excessive, or deleted referenced key state MUST
fail closed. Automatic key deletion is forbidden in this capability.

#### Scenario: Replay survives key rotation

- **WHEN** an assignment created under a retired epoch is replayed after one or
  more supported rotations
- **THEN** lookup finds it using retained epochs and verifies it with its
  original comparison key

#### Scenario: New assignment uses active epoch

- **WHEN** a previously unseen valid association is claimed after rotation
- **THEN** its lookup, commitment, and row integrity use domain-separated
  subkeys from the new active epoch

#### Scenario: Referenced key is missing

- **WHEN** the database references an absent or corrupt key file
- **THEN** open/replay fails closed without regenerating a key or assignment

### Requirement: Local storage is transactional, versioned, and fail closed

The store MUST use a dedicated SQLite database and key directory, explicit
application/schema versions, foreign keys, full synchronous commits, rollback
journaling, bounded busy handling, and an immediate write transaction. On
supported Unix platforms its directories MUST be effective-user-owned mode
`0700`, and database/key files MUST be regular, single-link,
effective-user-owned mode `0600`. Symlinks, hard links, broad modes, failed
integrity checks, unexpected application IDs, unsupported/newer versions,
invalid rows, bad row authentication, and partial migrations MUST fail closed
without replacement or automatic deletion.

Initialization MUST be explicit and MUST refuse an existing store root. Reopen
MUST NOT create missing durable state. An authenticated append-only authority
and receipt chain outside SQLite MUST bind every committed assignment so row or
database deletion/rollback cannot be interpreted as a first claim. The store
MAY recover only an authenticated lone pre-commit or post-commit receipt state;
other row/receipt/authority disagreement MUST fail closed.

Network filesystems are unsupported. The durable assignment store is Linux-only; until
equivalent descriptor and private-ACL profiles are implemented, every other
platform, including Windows, MUST fail before creating, opening, or mutating
state. Disk-full, lock-timeout, and transaction errors MUST not expose partial
assignments.

#### Scenario: Durable reopen preserves assignments

- **WHEN** a committed store is closed and reopened with intact database and
  key state
- **THEN** all assignments retain their references, observation IDs, and replay
  verification behavior

#### Scenario: Corrupt or newer state is not repaired silently

- **WHEN** storage is corrupt, semantically tampered, partially migrated, or
  newer than the running implementation
- **THEN** opening fails with a bounded code and leaves state untouched

#### Scenario: Windows fails before activation

- **WHEN** durable assignment is opened on Windows under this capability
- **THEN** it returns the bounded unsupported-platform error and creates no
  database, key directory, or sidecar

### Requirement: Assignment state has a private non-export contract

The store MUST NOT persist raw association material, semantic values, source
content, transcripts, tool arguments/results, credentials, URLs, source paths,
task-directory values, timestamps, or source/session IDs. Errors and Debug
output MUST contain only stable bounded categories and MUST exclude storage
paths, SQLite text, keys, commitments, replay tokens, assignment references,
observation content, and caller locator bytes. The capability MUST emit no
assignment telemetry and provide no generic serialization path.

#### Scenario: Controlled marker remains private

- **WHEN** synthetic semantic and association values contain controlled secret,
  path, URL, and credential-shaped markers and an operation fails
- **THEN** errors, Debug output, database bytes, and SQLite indexes contain none
  of the raw markers

### Requirement: Assignment identity and session correlation remain separate

Protected assignment MUST establish only observation identity. It MUST NOT
populate or imply canonical `session_id`, workflow/correlation IDs, source
coordinates, Event IDs, adapter identity, or source provenance. A caller may set
session correlation only from its independently truthful source/configuration
contract.

RooCode's validated direct history ID MAY remain its session namespace but MUST
NOT become a per-message assignment association without new evidence. Legacy
KiloCode remains without a source session namespace. Both adapters MUST remain
blocked from canonical projection until a validated, mutation-stable,
duplicate-safe per-message replay association exists.

#### Scenario: Assignment does not fill session identity

- **WHEN** a coordinate-less observation receives a durable protected
  assignment and its source supplies no session namespace
- **THEN** observation identity is available but `session_id` remains absent

#### Scenario: Roo and Kilo remain blocked

- **WHEN** their current UI-message contracts are tested across edit,
  insertion, deletion, duplicate, reorder, and truncation
- **THEN** mutable ordinal, timestamp, content, path, and compatibility grouping
  fail the association contract and no projector is enabled

### Requirement: Existing production contracts do not regress

This capability MUST NOT modify Event 3.0 schema, IDs, serialization, privacy,
durable bytes, projection, JSONL first-write behavior, outbox tables, delivery,
parsers, exact parser ownership, production normalized records, deterministic
detection, Detection v2 algebra, shadow inputs, or production activation.

#### Scenario: Event and detection baselines remain exact

- **WHEN** the full regression and deterministic report checks run
- **THEN** Event 3 retains its frozen schema hash and Detection v2 retains its
  15-case, 17-session, 306-evaluation report and published report hash
