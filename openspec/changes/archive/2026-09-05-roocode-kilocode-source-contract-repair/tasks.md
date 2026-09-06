# Tasks: RooCode and KiloCode source-contract repair

## 1. Evidence and contract guardrails

- [x] 1.1 Reconfirm the exact local registrations and parser ownership for
  `roocode.tasks` and `kilocode.tasks`; preserve the `ui_messages.json` anchor.
- [x] 1.2 Pin the Roo evidence to commit
  `b867ec9145750d0ae1ff7f02d35406e9bf2a0b16`, the registered Kilo legacy writer
  to `Kilo-Org/kilocode-legacy@ae046acafd17993bdf12dce0f81d9ac948e17ee8`, and
  the current Kilo migration reader to
  `31f1f3118ccba73e9d9fdc6cac78f6644e9c23ef`; keep upstream citations stable and
  free of raw user content.
- [x] 1.3 Add characterization tests for current fallback order, source
  identity mismatch, malformed input, unknown variants, and no-fallback
  behavior before changing either parser.

## 2. RooCode source-owned parser

- [x] 2.1 Add a Roo-owned native `ClineMessage` interpretation for the exact
  array schema, verified ask/say subtype sets, ordered source records, numeric
  epoch-ms timestamps, and partial/final state.
- [x] 2.2 Project the native Roo records to legacy `ParsedRecord` kinds using
  only the approved actor/content/tool mapping; keep tool request/result
  distinct and do not infer execution outcome.
- [x] 2.3 Preserve exact parser ownership, use Roo's direct history namespace
  only when valid, and retain the legacy session fallback without treating the
  task path/parent as source identity; keep agent/provider/model absent unless
  direct source evidence proves a field.
- [x] 2.4 Add Roo tests for partial snapshots, duplicate timestamps, equal
  timestamps, middle deletion/insertion/reorder characterization, unknown
  subtypes, structural errors, tool correlation absence, and private errors.

## 3. Kilo legacy migration-store parser

- [x] 3.1 Add a Kilo-owned bounded candidate interpretation of the legacy
  `kilocode.kilo-code/tasks/**/ui_messages.json` store without routing current
  Kilo SQLite/server/CLI data.
- [x] 3.2 Establish that the pinned legacy Kilo writer only writes
  `ui_messages.json`; keep `api_conversation_history.json` as a separate
  non-selected alternate and do not import the current migration reader's Roo
  companions.
- [x] 3.3 Preserve the Kilo compatibility parent grouping value without
  promoting it, an index entry, history metadata, timestamp, or ordinal into
  source-reported or per-message identity.
- [x] 3.4 Add Kilo tests for the legacy-writer UI-only store, explicit alternate
  API non-selection, companion non-selection, unknown variants, partial records,
  and no proven session or message coordinate.

## 4. Realistic fixtures and support gates

- [x] 4.1 Replace or clearly separate the existing non-upstream-shaped UI
  fixtures with synthetic `ask`/`say` arrays that exercise each approved
  mapping without raw transcript or credential content.
- [x] 4.2 Add discovery, benign parse, truthful tool-request, truthful
  tool-result, UC-001 positive, negative/benign, and capability evidence for
  both exact identities; preserve deterministic detection as authoritative.
- [x] 4.3 Add identity-readiness vectors covering replay, append, edit, tail
  truncation, middle delete, insert, reorder, moves, missing coordinates, Roo
  direct-history/index corroboration, and Kilo's absent namespace; do not
  implement protected assignment.

## 5. Documentation and stop/review gates

- [x] 5.1 Update source/session, validation-matrix, capability, and adapter
  documentation to distinguish Roo current storage and direct history metadata,
  Kilo legacy-writer UI storage, source-reported metadata, and compatibility
  path fallback.
- [x] 5.2 Verify no Event 3.0, Event 4, canonical projector/facade,
  conformance, Detection v2/shadow case, current Kilo source, gateway,
  framework, or protected-assignment implementation entered the diff.
- [x] 5.3 The truthful tool/UC-001 gates are earned, the evaluation golden and
  Detection v2 shadow are unchanged, discovery remains bounded to
  `ui_messages.json`, and no foundational ownership/privacy/identity defect was
  found; no stop-for-review condition was triggered.

## 6. Bounded validation and closeout

- [x] 6.1 Run focused source/fixture checks after implementation, followed by
  the repository Rust validation ladder applicable to the completed behavior.
- [x] 6.2 Run strict OpenSpec validation and inspect the final diff for privacy,
  identity, no-fallback, and scope-boundary violations before closeout.
- [x] 6.3 Leave the change active and unarchived until the implementation and
  review gates are explicitly complete; do not commit, stage, push, publish, or
  archive as part of this change.

## 7. P17R-B provenance correction

- [x] 7.1 Adjudicate upstream writer evidence and the existing required
  `ParsedRecord.session_id` compatibility-grouping limitation; preserve the
  source-reported-versus-compatibility distinction without changing the core
  schema.
- [x] 7.2 Add the Roo `HistoryItem`/`TaskHistoryStore` companion model with
  direct-history authority, cache-only index corroboration, renamed-directory
  coverage, bounded structural failures, and safe debug tests.
- [x] 7.3 Correct Kilo to its pinned legacy-writer boundary, remove companion
  identity promotion and mirrored impossible fixtures, and retain only the
  explicit alternate-API non-selection coverage.
- [x] 7.4 Reconcile the affected source, capability, validation, and adapter
  documentation with namespace readiness, message readiness, and protected
  assignment boundaries; do not claim live validation or Canonical Observation
  v2 support.
- [x] 7.5 Run focused source/parity, CLI/detection, formatting, strict Clippy,
  diff, and supported strict OpenSpec validation; record results before
  closeout.
- [x] 7.6 Independent adversarial parent-session review of the final diff and
  provenance semantics.
