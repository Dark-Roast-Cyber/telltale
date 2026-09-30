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
session identity confirmation. It MUST return typed `Found`, `SourceUnavailable`,
`SessionUnavailable`, or `NotLocallyResolvable`, with no paths, raw records,
record content, or raw diagnostics. Missing correlation, unsupported providers,
and ambiguity MUST fail closed without session-ID-only or fuzzy lookup. A
caller-owned bounded known-source snapshot MAY distinguish lost sources from
never-resolvable sources, but MUST NOT become a persisted index.

#### Scenario: Moved source and distinct clients

- **WHEN** a source moves or another client has the same session ID
- **THEN** only the exact client/path hash can correlate; a known lost source is
  unavailable and an unknown missing source is not locally resolvable

### Requirement: Current canonical acquisition remains authoritative

Existing supported JSONL identities MUST use bounded direct file reads and the
authoritative acquisition dispatcher/native mapper, including explicit call IDs.
Retired source layouts and parser/normalized record conversion MUST NOT return.
Source-correlatable OpenCode requests MUST return `SourceUnavailable` before
discovery, source I/O, or native invocation. This state denotes a deferred
provider, not proof of source existence. Bounded direct acquisition MUST reject
OpenCode before I/O. The API MUST NOT expose native export acquisition or
executable configuration. There MUST NOT be a SQLite/WAL/SHM fallback.
Native export initializes, checkpoints, and migrates the store; a genuinely
read-only OpenCode capability requires future accepted work. Production OpenCode
scan/watch/acquisition MUST remain unchanged.

#### Scenario: OpenCode export cannot mutate investigation artifacts

- **WHEN** an OpenCode event is investigated with a fake executable available
- **THEN** no executable is launched, no database/sidecar is read or created, the
  result is payload-free unavailable, and synthetic DB/WAL/SHM bytes stay unchanged

### Requirement: Timeline investigation contains no prose evidence

The backend MUST project Canonical Observation v2 directly into the existing
`ExportedSessionTimeline` shape with empty evidence on every entry and no
agent/model/provider content. Existing transcript-export behavior MUST remain
unchanged. Tool labels and session IDs MUST use the existing terminal identifier
policy; call IDs MUST be opaque. Only one exact call and later result MAY link.
Anchors MUST expose recorded indexes and optional current indexes only; Event3
remains authoritative and indexes MUST NOT imply immutable history or fuzzy
equivalence.

#### Scenario: Ordinary content survives normal redaction

- **WHEN** messages, arguments, results, or errors contain ordinary synthetic prose
- **THEN** no such content appears in investigation output, including Debug

### Requirement: Finite read-only on-demand operation

The backend MUST create no persistence, index, watcher, runtime database, mutation,
or outbox. Discovery MUST count all visited entries and fail without a partial
listing on budget/depth/traversal failure. Direct reads MUST validate the opened
regular object, bound bytes including growth, and bound JSON depth and records.
Investigation MUST NOT run any native OpenCode command. Bounds MAY only be lowered from documented
maxima. OS filesystem I/O has no hard wall-clock bound.
Event3, detection, provenance, LocalEventFeed, and UI semantics MUST be unchanged.

#### Scenario: Synthetic preservation and direct read failure

- **WHEN** direct input is invalid, unavailable, or exceeds its budget
- **THEN** tests prove bounded failure, private errors, and
  unchanged synthetic source/database/sidecar artifacts
