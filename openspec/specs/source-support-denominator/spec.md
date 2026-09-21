# source-support-denominator Specification

## Purpose

Define the authoritative built-in source-support denominator.

## Requirements

### Requirement: Built-in support contains eight exact identities

The built-in source registry and exact parser registration table MUST contain
only `claude.projects`, `codex.sessions`, `codex.archived_sessions`,
`codex.headless_sessions`, `opencode.sqlite`, `openclaw.agents`,
`qwen.projects`, and `copilot.process_log`. Every registered identity MUST have
fixture-backed discovery, parsing, and evaluation-corpus representation.

#### Scenario: Registry and parser denominator agree

- **WHEN** built-in source definitions and parser registrations are inspected
- **THEN** both sets contain the same eight exact `(ClientId, source_id)` pairs

### Requirement: Retired identities have no production machinery

`gemini.tmp`, `opencode.legacy_json`, `opencode.project_json`, `roocode.tasks`,
`kilocode.tasks`, and `codex.project_sessions` MUST NOT be registered,
discovered, parsed, canonically projected, or advertised as built-in support.

#### Scenario: Retired identity is supplied directly

- **WHEN** a caller supplies a retired source ID representable under a retained
  client
- **THEN** exact parser lookup returns `UnsupportedSourceIdentity` before reading
  the source path

### Requirement: One authoritative canonical acquisition boundary

The public `telltale-sources::acquisition` API MUST be the sole cross-source
Canonical Observation v2 acquisition authority. Its explicit dispatcher MUST accept only
`claude.projects`, `codex.sessions`, `codex.archived_sessions`,
`codex.headless_sessions`, `opencode.sqlite`, `openclaw.agents`,
`qwen.projects`, and `copilot.process_log`, with their exact clients and
kinds. Unsupported and retired identities MUST fail before
source I/O. Shared acquisition options MUST contain only caller-owned observed
time; bounded SQLite read controls MUST remain exclusive to the OpenCode entry
point. Each invocation reaching extraction MUST perform exactly one source-native
extraction and feed those facts directly to the source-owned canonical mapper.
It MUST NOT convert through `ParsedRecord` or `NormalizedRecord` in either direction.
Canonical field semantics remain owned by adapter specifications.

`AcquisitionBatch` MUST keep canonical observations separate from operational
`AcquisitionProgress`. Only OpenCode MAY return its selected extraction's part
high-water coordinate; all other identities MUST return `None`. Progress MUST NOT
enter canonical identity, correlation, timestamps, provenance, metadata, or
capabilities. Copilot parser state MUST remain source-local and non-durable.
Acquisition MUST NOT own scanner checkpoint persistence, overlap, or retry policy.

Each of the eight adapters MUST satisfy the authoritative canonical session
accounting contract from the same native extraction, separately from observations
and progress. Detailed attestation, ownership, contribution, bounds, and privacy
semantics belong to that capability rather than this denominator.

Failures MUST distinguish unsupported identity, kind mismatch, source read,
canonical mapping, and canonical validation with bounded privacy-safe Display
and Debug. Errors MUST NOT retain raw source errors or return partial successful
batches or checkpointable progress.

Scan, watch, and embedding MUST consume this boundary through the shared
canonical runtime and Detection v2. Event4 MUST remain inactive.

No parallel cross-source canonical projection router, compatibility alias, or
wrapper MAY remain. Roadmap steps 4 and 5 are complete.

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
