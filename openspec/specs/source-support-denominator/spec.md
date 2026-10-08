# source-support-denominator Specification

## Purpose

Define the authoritative built-in source-support denominator.

## Requirements

### Requirement: Built-in support contains eight exact identities

The built-in source registry and authoritative acquisition dispatcher MUST
contain only `claude.projects`, `codex.sessions`, `codex.archived_sessions`,
`codex.headless_sessions`, `opencode.sqlite`, `openclaw.agents`,
`qwen.projects`, and `copilot.process_log`. Every registered identity MUST have
fixture-backed discovery, canonical acquisition, and evaluation-corpus
representation.

#### Scenario: Registry and acquisition denominator agree

- **WHEN** built-in source definitions and acquisition routing are inspected
- **THEN** both sets contain the same eight exact `(ClientId, source_id)` pairs

### Requirement: Retired identities have no production machinery

`gemini.tmp`, `opencode.legacy_json`, `opencode.project_json`, `roocode.tasks`,
`kilocode.tasks`, and `codex.project_sessions` MUST NOT be registered,
discovered, parsed, canonically projected, or advertised as built-in support.

#### Scenario: Retired identity is supplied directly

- **WHEN** a caller supplies a retired source ID representable under a retained
  client
- **THEN** canonical acquisition returns `UnsupportedSourceIdentity` before
  reading the source path

### Requirement: One authoritative canonical acquisition boundary

The public `telltale-sources::acquisition` API MUST be the sole cross-source
Canonical Observation v2 acquisition authority.
Its explicit dispatcher MUST accept only
`claude.projects`, `codex.sessions`, `codex.archived_sessions`,
`codex.headless_sessions`, `opencode.sqlite`, `openclaw.agents`,
`qwen.projects`, and `copilot.process_log`, with their exact clients and
kinds.
Unsupported and retired identities MUST fail before
source I/O.

#### Scenario: All-eight acquisition has one owner

- **WHEN** a caller acquires any contracted source identity
- **THEN** the authoritative acquisition API invokes native extraction and the
  source-owned mapper without a second cross-source router, and the shared
  source runtime consumes that result without legacy parsing

#### Scenario: Acquisition failure cannot advance progress

- **WHEN** extraction, canonical mapping, or validation fails
- **THEN** the API returns only a bounded error, without observations or progress

#### Scenario: OpenCode controls cannot affect other acquisition families

- **WHEN** callers configure bounded OpenCode reads
- **THEN** those controls are accepted only by the OpenCode-specific entry point,
  which rejects other source families before I/O rather than ignoring the controls
### Requirement: Shared acquisition configuration is observation-time only

Shared acquisition options MUST contain only caller-owned observed
time; bounded SQLite read controls MUST remain exclusive to the OpenCode entry
point.
Each invocation reaching extraction MUST perform exactly one source-native
extraction and feed those facts directly to the source-owned canonical mapper.

#### Scenario: Shared acquisition configuration is observation-time only

- **WHEN** a non-OpenCode adapter is acquired
- **THEN** SQLite read controls remain OpenCode-only and one native extraction feeds direct mapping

### Requirement: Canonical acquisition never routes through flattened records

It MUST NOT convert through `ParsedRecord` or `NormalizedRecord` in either direction.
Canonical field semantics remain owned by adapter specifications.

#### Scenario: Canonical acquisition never routes through flattened records

- **WHEN** a native batch is mapped
- **THEN** adapter-owned canonical field semantics apply without ParsedRecord or NormalizedRecord conversion

### Requirement: Canonical batches separate observations from progress

`AcquisitionBatch` MUST keep canonical observations separate from operational
`AcquisitionProgress`.
Only OpenCode MAY return its selected extraction's part
high-water coordinate; all other identities MUST return `None`.
Progress MUST NOT
enter canonical identity, correlation, timestamps, provenance, metadata, or
capabilities.

#### Scenario: Canonical batches separate observations from progress

- **WHEN** an adapter returns an acquisition batch
- **THEN** only OpenCode may expose selected-part high-water and it never enters canonical semantics

### Requirement: Acquisition extraction state does not own scanner persistence

Copilot source extraction state MUST remain source-local and non-durable.
Acquisition MUST NOT own scanner checkpoint persistence, overlap, or retry policy.

#### Scenario: Acquisition extraction state does not own scanner persistence

- **WHEN** Copilot or another adapter extracts native facts
- **THEN** source-local state is non-durable and scanner checkpoint/overlap/retry policy stays outside acquisition

### Requirement: All adapters account the same native extraction

Each of the eight adapters MUST satisfy the authoritative canonical session
accounting contract from the same native extraction, separately from observations
and progress.
Detailed attestation, ownership, contribution, bounds, and privacy
semantics belong to that capability rather than this denominator.

#### Scenario: All adapters account the same native extraction

- **WHEN** a registered adapter acquires observations
- **THEN** canonical accounting is separate and its own capability owns detailed attestation and bounds

### Requirement: Canonical acquisition failures are typed private and atomic

Failures MUST distinguish unsupported identity, kind mismatch, source read,
canonical mapping, and canonical validation with bounded privacy-safe Display
and Debug.
Errors MUST NOT retain raw source errors or return partial successful
batches or checkpointable progress.

#### Scenario: Canonical acquisition failures are typed private and atomic

- **WHEN** source read, mapping or validation fails
- **THEN** bounded categories reveal no raw errors and return no partial successful progress

### Requirement: Production callers share canonical runtime and Detection v2

Scan, watch, and embedding MUST consume this boundary through the shared
canonical runtime and Detection v2.
Event4 MUST remain inactive.

#### Scenario: Production callers share canonical runtime and Detection v2

- **WHEN** scan, watch or embedding acquires supported sources
- **THEN** the authoritative boundary is consumed through one runtime with Event4 inactive

### Requirement: Investigation read limits remain separate from production admission

On-demand session investigation MAY lower finite direct JSONL read limits through
the same dispatcher and native mapping.
Bounded investigation acquisition MUST
reject `opencode.sqlite` before I/O: native export performs store initialization,
checkpointing, and migrations, so its read-only capability remains deferred.

#### Scenario: Investigation read limits remain separate from production admission

- **WHEN** on-demand session investigation lowers JSONL limits
- **THEN** it uses native mapping while OpenCode read-only investigation stays deferred

### Requirement: Investigation acquisition forbids native and retired-source fallbacks

It
MUST NOT invoke native OpenCode, interpret SQLite/WAL/SHM for investigation,
enable retired JSON identities, or produce source-backed normalized records.
Investigation read controls remain separate from production admission limits.

#### Scenario: Investigation acquisition forbids native and retired-source fallbacks

- **WHEN** investigation cannot resolve a source under bounded controls
- **THEN** it invokes no native OpenCode or SQLite sidecar fallback and creates no normalized records

### Requirement: Production JSONL admission has inclusive physical limits

Production JSONL acquisition MUST admit at most 8 MiB per physical record,
128 MiB of total acquired source bytes, and 100,000 nonblank native units,
with each boundary inclusive.
Physical and aggregate bytes MUST include LF/CRLF
terminators, whitespace, and blank records.
Blankness MUST retain Unicode
`str.trim()` semantics.

#### Scenario: Production JSONL admission has inclusive physical limits

- **WHEN** production JSONL reads records and blank lines
- **THEN** record/source-byte and nonblank-unit limits include terminators and Unicode-trim blankness

### Requirement: Production JSONL actual-read limits precede decoding and fail atomically

One shared bounded record accumulator MUST enforce
actual-read byte limits before UTF-8 and JSON decoding, including source growth;
it MUST NOT retain a whole raw source string.
Over-limit sources MUST fail
atomically as the existing privacy-safe `SourceRead` / `source_read`, without
successful observations, accounting, or checkpointable progress.

#### Scenario: Production JSONL actual-read limits precede decoding and fail atomically

- **WHEN** source growth or the next physical record exceeds admission
- **THEN** the bounded accumulator fails SourceRead before retaining partial observations/accounting/progress

### Requirement: Production JSONL admission adds no knobs or resource guarantees

These fixed
internal admission limits MUST NOT introduce knobs, truncation, an RSS guarantee,
or investigation no-follow/nonregular policy into production reads.
Copilot and
OpenCode behavior MUST remain unchanged.
No parallel cross-source canonical projection router, compatibility alias, or
wrapper MAY remain.
Roadmap steps 4 and 5 are complete.

#### Scenario: Production JSONL admission adds no knobs or resource guarantees

- **WHEN** fixed internal admission limits apply
- **THEN** no truncation, RSS claim or investigation file policy is added and other adapters remain unchanged
