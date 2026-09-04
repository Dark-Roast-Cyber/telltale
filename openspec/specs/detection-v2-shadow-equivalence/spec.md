# detection-v2-shadow-equivalence Specification

## Purpose
This specification defines a deterministic, fixture-only comparison of current
Rule v1 session evaluation with the non-production Canonical Observation v2
compatibility path. It does not activate Detection v2 or change Event 3.0.
## Requirements
### Requirement: Canonical projection facade

The source layer MUST expose a provider-neutral projection entry point that
routes by the exact registered client and source identity, accepts caller-owned
observation time, and returns only Canonical Observation v2 values or one of the
bounded error codes `unsupported_source_identity`, `source_parse`,
`canonical_mapping`, and `canonical_validation`. It MUST route Claude projects,
the three supported Codex session identities, and OpenCode SQLite; Codex project
sessions MAY be characterized but MUST NOT be promoted. It MUST NOT route legacy
JSON, project JSON, or unrelated source identities.

#### Scenario: Exact identity selects the native projector

- **WHEN** a registered supported `(client, source_id)` pair is projected with a
  fixed observation time
- **THEN** the existing native projector is invoked without NormalizedRecord
  conversion and each returned observation retains that observation time.

#### Scenario: Unsupported identity fails closed

- **WHEN** an unregistered or explicitly non-v2 `(client, source_id)` pair is
  supplied
- **THEN** the call returns `unsupported_source_identity` without reading the
  source path or exposing it in Display or Debug output.

### Requirement: Source-free shadow comparison

The shadow comparator MUST accept one effective Compiled Rule v1 set, caller-
provided legacy records, and caller-provided canonical observations. It MUST NOT
depend on the source crate, perform source I/O, wire into scan/watch, emit Event
3/Event 4, or construct one representation from the other.

#### Scenario: No-default-features remains usable

- **WHEN** the Detection crate is built without its source-I/O feature
- **THEN** the shadow comparison API and its synthetic tests compile and run.

### Requirement: Truthful session alignment

Legacy records MUST be grouped by their current legacy session ID. Canonical
observations MUST be grouped only by a source-reported canonical session ID.
Fallback `unknown`, paths, row IDs, and database coordinates MUST NOT be used as
canonical identity. Unaligned sessions and unscoped observations MUST remain
explicitly reportable, and serialized session references MUST be deterministic
SHA-256 fingerprints rather than raw IDs.

#### Scenario: Unscoped observations are not assigned

- **WHEN** a canonical observation has no source-reported session ID and a legacy
  record has session ID `unknown`
- **THEN** the observation remains unscoped and the comparator does not align it
  to that legacy session.

### Requirement: Observation and session outcome semantics

Every applicable detector MUST evaluate each canonical observation independently.
Session aggregation MUST use the precedence match, detector error, indeterminate,
evaluated no-match, then not-applicable. Aggregates MUST retain counts for each
status and bounded sorted non-evaluation reason counts. An indeterminate result
MUST NOT be counted as both-no-match.

#### Scenario: Non-evaluation dominates evaluated no-match

- **WHEN** a detector has one evaluated no-match observation and one
  not-evaluated observation
- **THEN** the session outcome is indeterminate and both status counts remain
  visible.

#### Scenario: Match dominates detector health for the relation only

- **WHEN** one observation matches and another observation for the same detector
  is not evaluated
- **THEN** the session outcome is match while the non-evaluation count and reason
  remain in the report.

### Requirement: Atomic equivalence and compatibility aggregation

The primary comparison unit MUST be the effective atomic Rule v1 ID. Contribution
and risk comparison MUST remain shadow-only legacy compatibility accounting: each
matched Rule v1 rule contributes exactly once per session, and each triggered
modifier contributes exactly once per modifier/session. Contribution ledgers MUST
be compared as exact multisets of contribution ID, type, and points, with scores
computed using checked addition. Equal scores alone MUST NOT establish rule
equivalence. This accounting MUST NOT invent or change native Detection v2
aggregate risk, Signal, or Finding semantics. Modifiers MUST remain
measurement-only plans and MUST NOT become Detection v2 detector results, Signals,
or Findings. The comparator MUST distinguish
`both_match`, evaluated `both_no_match`, `legacy_only`, `v2_only`,
`v2_indeterminate`, and `v2_error`, with not-applicable retained separately.

#### Scenario: Empty legacy result is not a modifier match

- **WHEN** legacy evaluation returns no match and v2 evaluates an atomic detector
  to no-match
- **THEN** the relation is evaluated `both_no_match`, with no rule or modifier
  contribution fabricated.

#### Scenario: Modifier score is deduplicated

- **WHEN** multiple canonical observations match an atomic rule whose modifier
  conditions are satisfied
- **THEN** the v2 compatibility modifier appears once with its declared score,
  and no Detection v2 Finding is created for that modifier.

#### Scenario: Compatibility risk accounting is not native v2 risk

- **WHEN** a matched Rule v1 rule and a triggered modifier are present in one
  aligned session
- **THEN** the shadow ledger contains one contribution for each applicable rule
  or modifier, compares their ID/type/points entries with multiplicity, and does
  not alter native Detection v2 aggregate risk or Finding semantics.

### Requirement: Reconstructable compatibility metadata

Where reconstructable from the effective Rule v1 export, the comparator MUST
compare categories, detection classes, signal types, analytic intents, ATLAS
tags, and tags as compatibility metadata. It MUST NOT add legacy-only native-v2
fields, and MUST NOT require evidence order or evidence values for equivalence.

#### Scenario: Metadata comparison does not widen native v2

- **WHEN** Rule v1 metadata is reconstructable but the representations have
  different evidence order or evidence values
- **THEN** the comparison uses only the listed compatibility metadata, without
  adding legacy-only native-v2 fields or requiring evidence equality.

### Requirement: Privacy-safe deterministic report and gate

The shadow report MUST use a versioned, deterministic schema with bounded counts,
source/case/rule breakdowns, relation counts, mismatch classes, health, and
reviewed exceptions. It MUST contain no raw prompts, transcript text, arguments,
results, commands, paths, URLs, source paths, secrets, or legacy evidence
values. Repeating the same fixture inputs MUST produce byte-identical output.
Each expected mismatch MUST be identified by the exact case, session scope, rule
ID, relation, classification, and bounded reason code; multiplicity MUST be
retained in the expected mismatch multiset. The fixture check MUST compare the
actual and expected mismatch multisets exactly, fail for any new unexpected
mismatch or any disappeared expected mismatch until that exact mismatch is
reviewed, and reject wildcard, catch-all, or broad waiver entries.

#### Scenario: Report is repeatable and private

- **WHEN** the same synthetic cases are compared twice
- **THEN** the serialized `detection-v2-shadow-report.v1` bytes are identical and
  contain no forbidden raw content.

#### Scenario: Unexpected differences fail the gate

- **WHEN** the actual mismatch multiset contains a new entry, omits an expected
  entry, or changes its case/session scope, rule ID, relation, classification,
  bounded reason code, or multiplicity
- **THEN** the shadow check fails rather than silently accepting the result.

### Requirement: Production boundary

The harness MUST leave NormalizedRecordV1 production evaluation, Rule v1 regex,
scoring, parser ownership, selector/capability/provenance semantics, Event 3.0,
the frozen baseline report, and scanner/watch behavior unchanged.

#### Scenario: Shadow remains opt-in and non-production

- **WHEN** normal scan or watch is run
- **THEN** no Detection v2 shadow evaluation or shadow report is invoked.
