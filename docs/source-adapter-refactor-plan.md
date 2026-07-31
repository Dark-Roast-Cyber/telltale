# Source Adapter Refactor Plan

This is the implementation plan for moving Telltale from centralized,
`SourceKind`-driven semantic parser dispatch toward explicit parser registration
for each `(ClientId, source_id)` source identity. The goal is to make built-in
agents easier to maintain without guessing a source's schema from its container
format.

This document is a post-0.2.0 planning handoff. It does not change runtime
behavior by itself and does not propose a trait, plugin, or parser framework.

## Why Refactor

Today, adding or changing one agent touches several files, with semantic
dispatch still centralized:

- `crates/telltale-schema/src/clients.rs` for `ClientId` and `SourceKind`, plus
  `crates/telltale-sources/src/sources/<agent>/mod.rs` for most static source
  definitions and adjacent per-agent install modules.
- `crates/telltale-sources/src/discovery.rs` for OS root resolution, project-local search behavior,
  fixture source discovery, and watch roots.
- `crates/telltale-sources/src/parser.rs` for `SourceKind` dispatch, shared
  extraction, and normalization, with selected source-specific parser helpers
  under `crates/telltale-sources/src/sources/<agent>/parser.rs`.
- `crates/telltale-sources/src/install_inventory.rs` for installed-agent inventory evidence.
- `tests/fixtures/session_stores/<client>/` for synthetic source fixtures.
- Public docs for session sources, capability matrices, validation status, and
  adding-agent guidance.

That layout is understandable with a small source list, but it scales poorly.
Codex, OpenCode, Copilot, RooCode, KiloCode, Gemini, Claude, Qwen, and OpenClaw
already have different source shapes. Antigravity or customer-specific agents
would add more branches to the same central files.

The migration should keep the public pipeline stable:

```text
discover -> parse -> normalize -> detect -> score -> triage -> emit
```

Only the internal organization and parser registration should change. Discovery,
normalization, detection, scoring, triage, emission, and install inventory keep
their current contracts.

## What We Learned From The Current Code

### Source registry

`crates/telltale-schema/src/clients.rs` owns the canonical `ClientId` and
`SourceKind` types. `crates/telltale-sources/src/clients.rs` owns discovery
configuration types such as `PathRoot` and `SourcePattern`, plus the
`supported_clients()` compatibility wrapper; `sources/registry.rs` owns the
static client registry:

- `ClientId` variants and `ClientId::as_str()` values.
- `PathRoot` variants: `CodexHome`, `Home`, `ConfigHome`, `DataHome`, and
  `ProjectLocal`.
- `SourceKind` variants: JSON, JSONL, archived JSONL, headless JSONL, SQLite,
  legacy JSON, UI messages JSON, and Copilot process logs.
- `SourcePattern` for extension, exact file, and filename-contains matching.
- `ClientSourceDef` and `ClientDef`.
- Static per-client arrays such as `codex::SOURCES`, `opencode::SOURCES`, and
  `copilot::SOURCES`, collected by the source registry.
- `supported_clients()` returning the static registry.

The registry is already a useful discovery contract. The per-agent source arrays
and install definitions have moved into source modules, while the shape of
`ClientDef` and `ClientSourceDef` remains stable. The next step is to register
the parser for each source identity rather than infer it from `SourceKind`.

### Discovery

`crates/telltale-sources/src/discovery.rs` depends on `supported_clients()` and is mostly generic. It
does not need to know Codex or OpenCode internals except through source
definitions. It should stay mostly unchanged during the first phase.

Discovery responsibilities to preserve:

- fixture roots use each source's `fixture_relative_path`;
- host roots resolve via `PathRoot` and OS-specific environment variables;
- project-local sources search bounded nested workspaces;
- watch roots can be filtered by client id;
- fixture scans remain deterministic and do not depend on host session stores.

### Parser

`crates/telltale-sources/src/parser.rs` is the primary coupling point. It currently dispatches by
`SourceKind`, not by the registered `(ClientId, source_id)` identity. That makes
generic source shapes easy, but it permits source-specific details for Codex,
Gemini, OpenCode SQLite, Copilot logs, Claude tool blocks, and VS Code UI
message files to be treated as one format family.

Important parser contracts to preserve:

- public `parse_source_records()` and `parse_source_records_with_options()`
  signatures;
- `ParseOptions` and `ParsedSourceRecords`, including OpenCode SQLite cursor
  metadata;
- `NormalizedRecord` fields and `RecordKind` values;
- source-specific parsing must not contain detection logic;
- parser errors must not print raw transcript bodies or secrets.

The target is explicit source registration. `SourceKind` remains container and
reporting metadata. Shared JSON, JSONL, and SQLite readers may remain shared,
but semantic extraction and classification belong to the registered source
parser. A generic parser is used only when a source explicitly opts into it
because it is not yet modeled. A known parser failure reports schema drift or
the parse error through the existing path; it never silently retries with a
different parser. Unknown record variants become `Other` records or explicit
diagnostics rather than guessed kinds.

### Install inventory

`crates/telltale-sources/src/install_inventory.rs` is separate from session-source discovery. That is the
right conceptual boundary. Install evidence definitions now live in per-agent
source modules and are collected by the static registry. Parser migration must
not change metadata-only behavior or hashed path signals.

### Fixtures and docs

Fixture-backed support is the source of truth for public support. The current
validation matrix requires discovery, benign parse, tool-call parse, tool-result
parse, positive detection, negative behavior, and capability documentation.

The source-module design should make those requirements easier to satisfy by
keeping fixtures and source-specific tests discoverable from the agent module
docs.

## Target Layout

Move built-in source support toward this structure:

```text
src/
  sources/
    mod.rs
    registry.rs
    common/
      mod.rs
      json.rs
      jsonl.rs
      sqlite.rs
      vscode.rs
    codex/
      mod.rs
      parser.rs
      install.rs
      tests.rs
    claude/
      mod.rs
      parser.rs
      install.rs
      tests.rs
    gemini/
      mod.rs
      parser.rs
      install.rs
      tests.rs
    opencode/
      mod.rs
      parser.rs
      install.rs
      tests.rs
    copilot/
      mod.rs
      parser.rs
      install.rs
      tests.rs
```

`mod.rs` may continue to own static `SOURCES` and `INSTALL` declarations. The
registry should additionally map each `(ClientId, source_id)` to its explicit
parser. The first implementation should not move every agent at once: establish
parity fixtures, then migrate the prioritized source families one at a time.

## Parser Registration Contract

Keep registration compiled in, static, and direct. Do not introduce an adapter
trait, dynamic plugin boundary, or generic manager for this migration.

The conceptual registration shape is:

```rust
type SourceParser = fn(&Source, ParseOptions) -> Result<ParsedSourceRecords, ParseError>;

// Keyed by (source.client, source.source_id), not SourceKind.
fn parser_for(source: &Source) -> Option<SourceParser>;
```

The exact Rust representation may differ to preserve existing visibility and
public signatures. The contract is:

- one source identity has one named semantic parser;
- shared low-level readers live under `src/sources/common/` only when their
  behavior is format-level and source-neutral;
- a generic parser is selected only by an explicit registration for an
  unmodeled source;
- parser errors are returned unchanged to the existing scanner error path;
- source definitions and install evidence remain compatible with discovery and
  inventory callers.

Keep compatibility wrappers during migration:

- `clients::supported_clients()` should continue to exist.
- `discovery` should continue to consume `ClientDef` / `ClientSourceDef`.
- `parser::parse_source_records_with_options()` should continue to exist.
- `install_inventory::collect_install_inventory()` should continue to emit the
  same event shape.

## Migration Principles

1. **Characterize before routing.** Add parity fixtures for records, events,
   ordering, errors, and state before changing dispatch.
2. **One source family at a time.** Migrate Claude, Codex, and OpenCode in the
   stated order; keep OpenCode legacy/project JSON separate from SQLite.
3. **No silent fallback.** A known source parser failure is a failure. Only an
   explicitly registered unmodeled source may use generic parsing.
4. **Keep detections untouched.** Source parsers produce normalized records;
   detection rules remain data-driven in `config/rules/`.
5. **Keep privacy and public interfaces unchanged.** No raw transcript emission,
   real session fixtures, raw install paths, CLI example renames, or public
   parser signature changes.
6. **Stop on parity loss.** Do not continue to the next source if normalized
   output, event ordering, deduplication, cursor/state behavior, or failure
   reporting changes without an intentional, separately reviewed decision.

## Proposed Phases

### Phase 0 — Characterization and parity fixtures

Inventory every registered `(ClientId, source_id)` identity and capture
synthetic parity for normalized records, event streams, ordering, diagnostics,
and source metadata. Add fixtures for known schema drift, unknown record
variants, and the explicit generic-fallback boundary. Do not change dispatch in
this phase.

Stop if the characterization fixtures depend on real transcripts, expose
secrets, or cannot distinguish a known-parser failure from an explicit generic
fallback.

### Phase 1 — Claude Code

Register and migrate `claude.projects` to an explicit parser. Preserve the
existing public parser signatures and JSONL behavior, then run focused fixture,
schema, detection, and bounded live-validation checks where safe.

### Phase 2 — Codex

Migrate `codex.sessions`, `codex.archived_sessions`,
`codex.headless_sessions`, and `codex.project_sessions` as one source family,
with parity for ordering, session metadata, and source provenance. Keep generic
readers shared only where they are format-level helpers.

### Phase 3 — OpenCode legacy and project JSON

Migrate `opencode.legacy_json` and `opencode.project_json` separately from the
database path. Preserve source preference and all existing normalized output.

### Phase 4 — OpenCode SQLite

Migrate `opencode.sqlite` last. Preserve `ParseOptions`, part limits,
`sqlite_part_max_time_updated`, lock errors, scan-unit behavior, cursor/state
writes, and the host preference for SQLite over legacy JSON. Stop before moving
on if parser, state, scan-unit, CLI cursor, lock, or fixture tests fail.

### Phase 5 — Lower-priority sources

Migrate OpenClaw, Qwen, and Copilot in separate bounded batches after the first
tranche is stable. Their current support remains unchanged while they wait.

### Phase 6 — Remaining supported sources

Assess Gemini, RooCode, and KiloCode after the priority tranche. They remain
supported; being outside the first tranche does not imply removal. New agents
such as Antigravity are a separate support decision, not a prerequisite for
this parser migration.

For every phase, run the focused source/parser/discovery/schema tests and a
client-scoped fixture dry run before proceeding. Run the full Rust quality gate
after each coherent source-family batch.

## Risks And Mitigations

| Risk | Mitigation |
| --- | --- |
| Behavior changes during mechanical moves | Preserve compatibility functions and add source-registry snapshot tests. |
| Parser refactor accidentally changes normalized output | Run schema conformance, focused parser tests, and fixture scans per client. |
| OpenCode SQLite cursor behavior regresses | Move OpenCode last; keep dedicated state/scan cursor tests. |
| Install inventory hash/order changes | Sort by stable agent id before hashing and assert snapshot behavior. |
| Public docs overstate support | Keep support claims tied to source validation matrix gates. |
| Generic fallback hides source schema drift | Register known source identities explicitly and test that parser errors do not retry through generic extraction. |

## Done Criteria For The Refactor

The explicit per-source parser refactor is complete when:

- built-in agents have source definitions under `src/sources/<agent>/`;
- each registered `(ClientId, source_id)` resolves to its named semantic parser;
- agent-specific parser code lives under the same source module, with shared
  low-level readers kept separate;
- shared parser helpers live under `src/sources/common/` or another clearly named
  shared module;
- install inventory definitions come from the existing static per-agent registry;
- `clients::supported_clients()` and the stable parser public APIs remain
  unchanged;
- known parser failures never silently fall back, and unknown record variants
  remain explicit `Other` records or diagnostics;
- all fixture-backed discovery, parser, schema, detection, scan, and install
  inventory tests pass;
- `docs/adding-agent-source.md` describes explicit parser registration for new
  contributors.
