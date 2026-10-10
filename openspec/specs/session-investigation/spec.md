# session-investigation Specification

## Purpose

Define bounded, opportunistic, content-free local context for a consumed Event3.
This tranche supports existing direct JSONL sources (including single-object JSON
within those sources). Issue #42 remains incomplete: OpenCode investigation is
unavailable pending a genuinely read-only capability.

## Requirements

### Requirement: Exact identity and explicit availability

The backend MUST accept a consumed `Event3Record` and correlate only by exact
client plus existing source path hash, followed by source-reported terminal
session identity confirmation.
It MUST return typed `Found`, `SourceUnavailable`,
`SessionUnavailable`, or `NotLocallyResolvable`, with no paths, raw records,
record content, or raw diagnostics.
Missing correlation, unsupported providers,
and ambiguity MUST fail closed without session-ID-only or fuzzy lookup.

#### Scenario: Moved source and distinct clients

- **WHEN** a source moves or another client has the same session ID
- **THEN** only the exact client/path hash can correlate; a known lost source is
   unavailable and an unknown missing source is not locally resolvable

#### Scenario: Failure classification remains private and deterministic

- **WHEN** a source read, mapping, discovery, or ownership check fails with synthetic
  private path/content/diagnostic canaries
- **THEN** only closed reason values/codes are exposed, duplicate identical source
  candidates are deduplicated, distinct matching candidates remain ambiguous
  regardless of caller ordering, and a later valid invocation is unaffected

### Requirement: Investigation known-source snapshots remain caller-owned and bounded

A
caller-owned bounded known-source snapshot MAY distinguish lost sources from
never-resolvable sources, but MUST NOT become a persisted index.

#### Scenario: Investigation known-source snapshots remain caller-owned and bounded

- **WHEN** a known-source snapshot distinguishes lost sources
- **THEN** it does not become a persisted index

### Requirement: Investigation unavailability reasons are closed and privacy-safe

The three unavailable outcomes MUST carry closed reason enums and expose only
bounded static reason codes, including through Debug.
Reasons MUST distinguish
missing correlation, unsupported client/source, unknown source, ambiguous source
or session, conflicting ownership, invalid/event limits, and exact session absent
versus an attested session with no projectable timeline.

#### Scenario: Investigation unavailability reasons are closed and privacy-safe

- **WHEN** source/session resolution is unavailable
- **THEN** static reason enums distinguish precise causes without changing outcome names or Found payload

### Requirement: Investigation outcome names and Found payload remain stable

The four outcome names
and Found payload MUST remain unchanged; Rust unit-variant matches may require
payload-pattern updates.

#### Scenario: Investigation outcome names and Found payload remain stable

- **WHEN** closed unavailability reasons are added
- **THEN** outcome names and Found payload remain unchanged despite Rust payload-pattern updates

### Requirement: Current canonical acquisition remains authoritative

Existing supported JSONL identities MUST use bounded direct file reads and the
authoritative acquisition dispatcher/native mapper, including explicit call IDs.
Retired source layouts and parser/normalized record conversion MUST NOT return.

#### Scenario: Supported JSONL investigation uses canonical acquisition

- **WHEN** a supported JSONL source is investigated
- **THEN** it is read with bounded direct reads through the authoritative native
  mapper, with explicit call IDs and no record conversion

### Requirement: Investigation defers OpenCode before discovery or native I/O

Source-correlatable OpenCode requests MUST return `SourceUnavailable` before
discovery, source I/O, or native invocation.
This state denotes a deferred
provider, not proof of source existence.
Bounded direct acquisition MUST reject
OpenCode before I/O.

#### Scenario: Investigation defers OpenCode before discovery or native I/O

- **WHEN** a source-correlatable OpenCode record is investigated
- **THEN** SourceUnavailable denotes a deferred provider rather than proof of store existence

#### Scenario: OpenCode export cannot mutate investigation artifacts

- **WHEN** an OpenCode event is investigated with a fake executable available
- **THEN** no executable is launched, no database/sidecar is read or created, the
  result contains only the bounded provider reason, and synthetic DB/WAL/SHM bytes
  stay unchanged; Linux synthetic access probes observe no opens or reads

### Requirement: Investigation exposes no native export or SQLite fallback

The API MUST NOT expose native export acquisition or
executable configuration.
There MUST NOT be a SQLite/WAL/SHM fallback.
Native export initializes, checkpoints, and migrates the store; a genuinely
read-only OpenCode capability requires future accepted work.
Production OpenCode
scan/watch/acquisition MUST remain unchanged.

#### Scenario: Investigation exposes no native export or SQLite fallback

- **WHEN** read-only investigation would require native export
- **THEN** the provider remains deferred without native configuration or SQLite/WAL/SHM fallback

### Requirement: Investigation provider and direct-read reasons reflect observed capability

OpenCode deferral MUST use `ReadOnlyProviderUnavailable` and MUST NOT imply
missing, unreadable, permission-denied, or busy store state.
Direct read reasons
MUST use actual opened-object/OS failures rather than a pathname precheck or raw
diagnostic matching: missing, permission denied, other unreadable, rejected
non-regular opened object, limit exceeded, and malformed source.

#### Scenario: Investigation provider and direct-read reasons reflect observed capability

- **WHEN** OpenCode is deferred or a direct read fails
- **THEN** ReadOnlyProviderUnavailable is separate from actual opened-object errors

### Requirement: Investigation does not invent unobserved access diagnoses

Unobserved busy
or access diagnoses MUST NOT be invented.
Bounded acquisition MAY preserve these
closed classifications; production acquisition failure meaning MUST NOT change.

#### Scenario: Investigation does not invent unobserved access diagnoses

- **WHEN** a bounded acquisition classifies a failure
- **THEN** only observed closed classifications apply without changing production acquisition failure meaning

### Requirement: Timeline investigation contains no prose evidence

The backend MUST project Canonical Observation v2 directly into the existing
`ExportedSessionTimeline` shape with empty evidence on every entry and no
agent/model/provider content.
Existing transcript-export behavior MUST remain
unchanged.
Tool labels and session IDs MUST use the existing terminal identifier
policy; call IDs MUST be opaque.
Only one exact call and later result MAY link.

#### Scenario: Ordinary content survives normal redaction

- **WHEN** messages, arguments, results, or errors contain ordinary synthetic prose
- **THEN** no such content appears in investigation output, including Debug

### Requirement: Investigation anchors do not imply immutable history

Anchors MUST expose recorded indexes and optional current indexes only; Event3
remains authoritative and indexes MUST NOT imply immutable history or fuzzy
equivalence.

#### Scenario: Investigation anchors do not imply immutable history

- **WHEN** recorded and current timeline indexes differ
- **THEN** only exact indexes are exposed without fuzzy equivalence or overriding Event3

### Requirement: Finite read-only on-demand operation

The backend MUST create no persistence, index, watcher, runtime database, mutation,
or outbox.
Discovery MUST count all visited entries and fail without a partial
listing on budget/depth/traversal failure.
Direct reads MUST validate the opened
regular object, bound bytes including growth, and bound JSON depth and records.
Investigation MUST NOT run any native OpenCode command.
Bounds MAY only be lowered from documented
maxima.
OS filesystem I/O has no hard wall-clock bound.

#### Scenario: Synthetic preservation and direct read failure

- **WHEN** direct input is invalid, unavailable, or exceeds its budget
- **THEN** tests prove bounded failure, private errors, and
  unchanged synthetic source/database/sidecar artifacts
### Requirement: Investigation discovery failures have explicit bounded reasons

Event3, detection, provenance, LocalEventFeed, and UI semantics MUST be unchanged.
Discovery reasons MUST distinguish invalid/budget/depth limits, rejected symlink
search roots, observed permission denial, and other traversal failure, without
returning partial candidates or using known sources to bypass failed discovery.

#### Scenario: Investigation discovery failures have explicit bounded reasons

- **WHEN** discovery hits a limit, symlink root or traversal failure
- **THEN** it returns no partial candidates and does not bypass failure through known sources

### Requirement: Investigation remains stateless with safe operator guidance

The backend MUST remain stateless with no automatic retries.
Operator guidance
MUST map reason codes to local actions without suggesting weaker permissions,
raised maxima, native export fallback, or unsupported platform/version claims.

#### Scenario: Investigation remains stateless with safe operator guidance

- **WHEN** an operator handles an unavailability reason
- **THEN** no automatic retries, weakened permissions, raised maxima or native fallback are suggested
