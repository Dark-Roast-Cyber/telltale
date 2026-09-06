# Proposal: RooCode and KiloCode source-contract repair

## Why

The accepted P17R workstream needs to repair two exact source registrations that
currently use the generic JSON-document parser. The registrations are already
correctly owned by `(ClientId, source_id)`, but the implementation does not yet
model the source contracts that are known upstream. That leaves the parser with
no explicit ask/say semantics, no bounded metadata policy, and no honest
identity readiness decision.

RooCode's authoritative message source is the registered VS Code global-storage
task tree, specifically `ui_messages.json` under
`ConfigHome/Code/User/globalStorage/rooveterinaryinc.roo-cline/tasks/**`.
Upstream commit `b867ec9145750d0ae1ff7f02d35406e9bf2a0b16` defines the persisted
`ClineMessage` shape as `ask | say` records with subtype, text, partial, and
numeric epoch-millisecond `ts` fields. It does not define an in-file task or
message ID. The pinned `TaskHistoryStore` also writes a full `history_item.json`
per task; its direct `id` is a stable source task/session namespace, while the
debounced `_index.json` is only a rebuilt cache. The upstream writer rewrites
the JSON array, and checkpoint/delete flows can remove records from the middle;
array ordinal is therefore not a truthful canonical coordinate.

KiloCode's in-scope evidence is the legacy VS Code store at
`kilocode.kilo-code/tasks/**/ui_messages.json`, not current Kilo SQLite,
server, or CLI storage. The registered identity was written by
`Kilo-Org/kilocode-legacy` at commit
`ae046acafd17993bdf12dce0f81d9ac948e17ee8` (publisher `kilocode`, package
`kilo-code`). Its `taskMessages.ts` writer persists the complete `ClineMessage[]`
array to `ui_messages.json`, including the ask/say subtype and MCP encodings.
Current `Kilo-Org/kilocode` at
`31f1f3118ccba73e9d9fdc6cac78f6644e9c23ef` only reads/diagnoses that legacy
file in `packages/kilo-vscode/src/legacy-migration/task-store.ts`; its current
SQLite/server/CLI stores remain out of scope. The legacy writer writes
`ui_messages.json` only for this contract and does not prove a stable native
session companion, per-message ID, or ordinal.

## What changes

This change owns the following bounded P17R scope for implementation in the
next stage:

- replace both exact generic JSON-document registrations with source-owned
  native interpretations while keeping `roocode.tasks` and `kilocode.tasks`
  exact and case-sensitive;
- retain `ui_messages.json` as the discovered source anchor and model the
  verified Roo and independently pinned Kilo legacy `ClineMessage` contracts;
  use only Roo's direct task-history metadata for Roo session provenance and no
  Roo companion identity logic for Kilo;
- define truthful actor/content/tool-request/tool-result mappings to existing
  `ParsedRecord` kinds, including timestamp and partial/final handling;
- add deterministic, bounded Roo history/index lookup and missing/malformed/
  duplicate/mismatch behavior without using paths as identity;
- add realistic synthetic fixtures, source parser tests, Roo and Kilo
  support-gate evidence, capability/source documentation, and identity-readiness
  tests;
- leave missing per-message coordinates explicit and ready for a separately
  reviewed protected-assignment decision.

The active change remains open for bounded final validation; it is intentionally
not ready to archive.

## Non-goals

- canonical Observation v2 projectors, a source facade, cross-adapter
  conformance, or canonical output activation;
- Detection v2 changes, live shadowing, shadow cases, golden-delta acceptance,
  or changes to deterministic detection authority;
- implementation of protected assignment, assignment storage, or a new identity
  service;
- current Kilo SQLite, Kilo server, Kilo CLI, or any new Kilo source bundle;
- Event 3.0/Event 4 changes, gateway behavior, policy/enforcement, telemetry,
  delivery, or a generic parser/framework/plugin abstraction;
- using a path, filename, parent directory, timestamp, content hash, random
  value, mutable ordinal, call/tool ID, or guessed metadata as canonical
  message identity;
- generic parser retry or fallback after a known Roo/Kilo schema failure;
- redesigning the discovered source bundle. If `ui_messages.json` cannot remain
  the anchor, implementation stops for review rather than silently expanding
  discovery.

## Compatibility and impact

The exact source registrations and `(ClientId, source_id)` ownership remain
unchanged. Legacy `NormalizedRecordV1` parsing remains available, but its
source-owned projection becomes explicit and must preserve the established
record order, session fallback, tool classification, and bounded failure
behavior for existing supported shapes. A known schema failure is terminal for
that source; it is never reinterpreted by the generic parser.

This change does not modify Event 3.0, persistence/delivery state, privacy
export boundaries, release behavior, or deterministic rule/scoring behavior.
All new fixtures and examples use synthetic values only.

## Capability delta

- **ADDED:** `roocode-kilocode-source-contract-repair`
- **MODIFIED:** none
- **REMOVED:** none
