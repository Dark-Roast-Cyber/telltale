# canonical-accounting-coverage Specification

## Purpose

Define replacement eligibility of native source accounting for the canonical
runtime. Coverage extends B3A accounting without changing its facts,
observation semantics, or the existing retained-source baseline model.

## Requirements

### Requirement: Coverage names the whole source-instance replacement scope

Source accounting MUST carry a closed coverage classification with exactly
`CompleteSource` and `PartialSource`.
Both MUST refer to the caller-owned source
instance: one acquired file or database, not a session, source family, directory,
batch population, or time window.
Coverage MUST NOT duplicate source identity.

#### Scenario: Replacement eligibility

- **WHEN** a later consumer considers replacing a retained source contribution
- **THEN** complete coverage of that same source instance is necessary
- **AND** partial accounting cannot replace it or be added as a replay workaround
- **AND** complete coverage alone does not authorize state mutation in this tranche

#### Scenario: Session and identity do not establish coverage

- **WHEN** a batch has a session identity, source path, timestamp, or no errors
- **THEN** those facts do not upgrade its explicit accounting coverage

### Requirement: Coverage preserves exact retained baseline ownership

The existing baseline owner remains the exact client, source ID, and path-hash
source-instance key.
It retains one latest contribution per key and rebuilds
aggregates from retained contributions; coverage MUST NOT change that model.

#### Scenario: Coverage preserves exact retained baseline ownership

- **WHEN** coverage is attached to source accounting
- **THEN** the exact client/source/path-hash baseline model remains unchanged

### Requirement: Complete coverage accounts the acquired source stream

`CompleteSource` SHALL mean all B3A-countable native units in the exhaustive
source read are accounted.
For files this is coverage of the acquired byte
stream, not an atomic filesystem revision or proof of immutable contents.

#### Scenario: Complete coverage accounts the acquired source stream

- **WHEN** an exhaustive file read reports CompleteSource
- **THEN** all countable units in the acquired stream are accounted without an immutable-revision claim

### Requirement: Partial coverage is the safe default

`PartialSource` SHALL mean that complete whole-source coverage is not established,
even if a particular batch happens to include all current applicable units.
Default accounting MUST be partial, never an implicit empty complete snapshot.

#### Scenario: Partial coverage is the safe default

- **WHEN** whole-source coverage has not been established
- **THEN** accounting remains PartialSource even for an apparently exhaustive batch

### Requirement: All eight identities have explicit acquisition coverage

Successful exhaustive acquisitions of `claude.projects`, `codex.sessions`,
`codex.archived_sessions`, `codex.headless_sessions`, `openclaw.agents`,
`qwen.projects`, and `copilot.process_log` MUST return CompleteSource.

#### Scenario: Exhaustive file succeeds

- **WHEN** a supported file is fully read and all extraction, accounting, mapping,
  and validation stages succeed
- **THEN** its returned accounting is complete for that acquired source read
- **AND** repeated acquisition under the same contract yields the same coverage

#### Scenario: File fails after valid units

- **WHEN** an admission-limit overflow, malformed tail, read failure, invalid attestation, capacity overflow,
  mapping failure, or validation failure occurs
- **THEN** no successful accounting or partial successful batch is returned

#### Scenario: Observation-free native units

- **WHEN** a valid Copilot file contains only a workspace initialization
- **THEN** accounting includes its unit with CompleteSource even with no observations

### Requirement: Exhaustive file accounting includes suppressed native units

These contracts MUST read one full selected file without selection or lower
bounds and account every B3A-countable unit, including metadata-only and unscoped
units.
JSONL blank lines and Copilot ordinary log lines/completion controls are
not countable native units; Copilot workspace initialization and every accumulated
output item are.
Canonical observation suppression MUST NOT remove accounting.

#### Scenario: Exhaustive file accounting includes suppressed native units

- **WHEN** a supported file contains metadata-only or observation-free units
- **THEN** all countable units remain in accounting

### Requirement: Production file coverage retains atomic admission limits

Production JSONL admission MUST enforce the inclusive 8 MiB physical-record,
128 MiB acquired-source-byte, and 100,000 nonblank-unit limits defined by
source-support-denominator.
Exceeding admission MUST fail the whole acquisition,
not return a truncated CompleteSource or successful PartialSource batch.

#### Scenario: Production file coverage retains atomic admission limits

- **WHEN** a physical JSONL record or acquired source exceeds admission
- **THEN** the entire acquisition fails rather than returning truncated or partial successful coverage

### Requirement: Every OpenCode acquisition retains partial coverage

Every current `opencode.sqlite` acquisition MUST return PartialSource, including
default, live, dry-run, backfill, empty, and oversized-limit reads.
No retired or
additional identity MAY enter the supported denominator.

#### Scenario: Every OpenCode acquisition retains partial coverage

- **WHEN** default, live, dry-run, backfill, empty or oversized-limit OpenCode reads succeed
- **THEN** coverage remains PartialSource and the eight-source denominator does not expand

### Requirement: OpenCode bounded batches do not prove replacement completeness

The current OpenCode read MUST preserve all-message extraction, selected text/tool
part filtering, the part limit, optional inclusive lower bound, ordering, and
selected-part high-water behavior.
Accounting MUST describe that acquired native
batch without a hidden second read.
Lack of a lower bound, a larger limit, an
empty result, or high-water advancement MUST NOT establish CompleteSource.

#### Scenario: Overlap would lose or duplicate contributions

- **WHEN** a previous read contains A+B and a later cursor-overlap read contains B+C
- **THEN** both are partial source accounting, not complete source replacements
- **AND** the later read cannot be added to train B twice or replace away A

#### Scenario: Mutable parts and alternative read bounds

- **WHEN** a part is reread after mutation or a dry-run/backfill removes the cursor
- **THEN** accounting remains partial regardless of native IDs or selected high-water
- **AND** no per-unit ownership, revision, deletion, or additive ledger is inferred

### Requirement: SQLite coherence does not imply replacement completeness

Schema checks, message extraction and selected part pages share one explicit
SQLite read transaction snapshot.
This coherence MUST NOT promote selected-part
accounting to complete database replacement coverage.
Any future operation
claiming complete database accounting MUST cover the entire replacement scope
and be separately specified and validated; no such operation is introduced here.

#### Scenario: SQLite coherence does not imply replacement completeness

- **WHEN** OpenCode acquisition evaluates whole-source replacement eligibility
- **THEN** selected-part accounting cannot establish complete database replacement coverage

### Requirement: Accounting coverage is independent of observations and progress

Accounting coverage MUST remain on source accounting, separate from canonical
observations, AcquisitionProgress, operational success, and VisibilityLimited.
Consumers MUST NOT infer accounting completeness from observation count,
observation visibility, session identity, observed time, cursor existence, or
checkpoint eligibility.

#### Scenario: Progress does not establish accounting completeness

- **WHEN** an OpenCode acquisition succeeds and returns a selected-part high-water
- **THEN** operational progress remains available independently of PartialSource
- **AND** the coverage classification does not install a cursor or mutate ScanState

### Requirement: Coverage does not change acquisition selection or failure meaning

This tranche MUST NOT change observation selection or
introduce a separate complete-accounting read.
Partial accounting MAY accompany
successful acquisition and MUST NOT by itself produce scanner_error.

#### Scenario: Coverage does not change acquisition selection or failure meaning

- **WHEN** successful acquisition returns partial accounting
- **THEN** selection is unchanged and partial coverage alone does not produce scanner_error

### Requirement: Coverage preserves privacy and accounting bounds

Coverage MUST contain no source-controlled strings, raw paths, session content,
host labels, raw native records, or sidecars. Debug output MUST use fixed variant
names only. B3A attested metadata, native counts, record counts, session ownership,
activity contributions, checked overflow, maximum attested sessions, and the
global contribution-key budget MUST remain unchanged. Coverage MUST add no
per-record map, source reread, or durable native-unit ledger.

#### Scenario: Bounded private extension

- **WHEN** coverage is attached to or rendered with source accounting
- **THEN** it adds only constant-size classification metadata
- **AND** existing contribution/session capacity failures remain failures, not truncation

### Requirement: Runtime activation preserves coverage semantics

The canonical runtime MUST use `CompleteSource` only for exact source-key
replacement and MUST treat `PartialSource` as `NoReplacement`. Activity MAY be
emitted for either successful coverage class. Baseline candidates and cursor
updates MUST remain staged until required local output is durable. Event3
compatibility and Event4 inactivity remain unchanged.

#### Scenario: Coverage controls activated replacement

- **WHEN** canonical processing succeeds for complete or partial source coverage
- **THEN** only complete coverage may replace the exact retained contribution
- **AND** partial coverage cannot replace or add to a retained population
