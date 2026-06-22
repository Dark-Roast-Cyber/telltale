# Source Adapter Refactor Plan

This is the implementation plan for moving Telltale from centralized source
definitions and parser dispatch toward a `src/sources/$AGENT` design. The goal
is to make built-in agents easier to maintain and to create a clean path for
future agents such as Antigravity and eventually third-party parser adapters.

This document is a planning handoff for the next implementation session. It does
not change runtime behavior by itself.

## Why Refactor

Today, adding or changing one agent touches several centralized files:

- `src/clients.rs` for `ClientId`, `SourceKind`, source definitions, display
  names, and registry tests.
- `src/discovery.rs` for OS root resolution, project-local search behavior,
  fixture source discovery, and watch roots.
- `src/parser.rs` for source-kind dispatch and all parser implementation
  details.
- `src/install_inventory.rs` for installed-agent inventory evidence.
- `tests/fixtures/session_stores/<client>/` for synthetic source fixtures.
- Public docs for session sources, capability matrices, validation status, and
  adding-agent guidance.

That layout is understandable with a small source list, but it scales poorly.
Codex, OpenCode, Copilot, RooCode, KiloCode, Gemini, Claude, Qwen, and OpenClaw
already have different source shapes. Antigravity or customer-specific agents
would add more branches to the same central files.

The refactor should keep the public pipeline stable:

```text
discover -> parse -> normalize -> detect -> score -> triage -> emit
```

Only the internal organization behind discovery, parser dispatch, and install
inventory should change.

## What We Learned From The Current Code

### Source registry

`src/clients.rs` currently owns the stable supported-client registry:

- `ClientId` variants and `ClientId::as_str()` values.
- `PathRoot` variants: `CodexHome`, `Home`, `ConfigHome`, `DataHome`, and
  `ProjectLocal`.
- `SourceKind` variants: JSON, JSONL, archived JSONL, headless JSONL, SQLite,
  legacy JSON, UI messages JSON, and Copilot process logs.
- `SourcePattern` for extension, exact file, and filename-contains matching.
- `ClientSourceDef` and `ClientDef`.
- Static per-client arrays such as `CODEX_SOURCES`, `OPENCODE_SOURCES`, and
  `COPILOT_SOURCES`.
- `supported_clients()` returning the static registry.

The registry is already a good contract. The refactor should move the per-agent
arrays out of `clients.rs` while preserving the shape of `ClientDef` and
`ClientSourceDef` until callers are migrated.

### Discovery

`src/discovery.rs` depends on `supported_clients()` and is mostly generic. It
does not need to know Codex or OpenCode internals except through source
definitions. It should stay mostly unchanged during the first phase.

Discovery responsibilities to preserve:

- fixture roots use each source's `fixture_relative_path`;
- host roots resolve via `PathRoot` and OS-specific environment variables;
- project-local sources search bounded nested workspaces;
- watch roots can be filtered by client id;
- fixture scans remain deterministic and do not depend on host session stores.

### Parser

`src/parser.rs` is the largest coupling point. It dispatches by `SourceKind`, not
by agent. That makes generic source shapes easy, but it also means source-specific
details for Codex, Gemini, OpenCode SQLite, Copilot logs, Claude tool blocks, and
VS Code UI message files all accumulate in one file.

Important parser contracts to preserve:

- public `parse_source_records()` and `parse_source_records_with_options()`
  signatures;
- `ParseOptions` and `ParsedSourceRecords`, including OpenCode SQLite cursor
  metadata;
- `NormalizedRecord` fields and `RecordKind` values;
- source-specific parsing must not contain detection logic;
- parser errors must not print raw transcript bodies or secrets.

### Install inventory

`src/install_inventory.rs` is separate from session-source discovery. That is the
right conceptual boundary. It currently stores all agent evidence definitions in
one `INSTALL_DEFS` slice. The refactor should allow each source adapter to expose
optional install evidence while preserving metadata-only behavior and hashed
path signals.

### Fixtures and docs

Fixture-backed support is the source of truth for public support. The current
validation matrix requires discovery, benign parse, tool-call parse, tool-result
parse, positive detection, negative behavior, and capability documentation.

The adapter design should make those requirements easier to satisfy by keeping
fixtures and source-specific tests discoverable from the agent module docs.

## Target Layout

Move built-in source support toward this structure:

```text
src/
  sources/
    mod.rs
    adapter.rs
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
    antigravity/
      mod.rs
      parser.rs
      install.rs
      tests.rs
```

The first implementation should not move every agent at once. Start by
introducing the structure and migrating one low-risk source, then repeat.

## Adapter Contract

Start with a compiled-in adapter contract. Keep it simple and static before
introducing external plugins.

Recommended contract shape:

```rust
pub trait SourceAdapter {
    fn client(&self) -> ClientDef;
    fn parse(
        &self,
        source: &Source,
        options: ParseOptions,
    ) -> Result<ParsedSourceRecords, ParseError>;
    fn install_def(&self) -> Option<AgentInstallDef>;
}
```

That exact trait may need adjustment because `ClientDef` and source arrays are
currently `'static`, but the design goal should stay the same:

- one adapter owns one client id and display name;
- one adapter owns all source definitions for that client;
- one adapter owns parser dispatch for its source ids/kinds;
- one adapter may expose install inventory evidence;
- shared helpers live under `src/sources/common/` rather than in the agent
  modules.

Keep compatibility wrappers during migration:

- `clients::supported_clients()` should continue to exist.
- `discovery` should continue to consume `ClientDef` / `ClientSourceDef`.
- `parser::parse_source_records_with_options()` should continue to exist.
- `install_inventory::collect_install_inventory()` should continue to emit the
  same event shape.

## Migration Principles

1. **No behavior change in the first slice.** Introduce modules and route through
   compatibility wrappers before changing any parsing behavior.
2. **One agent at a time.** Do not move Codex, OpenCode, Copilot, and generic
   JSON parsing in the same commit.
3. **Prefer mechanical moves.** Use existing tests to prove the moved code is the
   same behavior before improving the parser design.
4. **Keep detections untouched.** Source adapters produce normalized records;
   detection rules remain data-driven in `config/rules/`.
5. **Keep privacy boundaries unchanged.** No new raw transcript emission, no real
   session fixture imports, and no raw install paths in inventory events.
6. **Avoid plugin complexity until adapters are stable.** Third-party parser
   support should come after built-in adapters have a clean internal contract.

## Proposed Phases

### Phase 0 — Planning and documentation

Status: this document.

Deliverables:

- contributor guide for adding an agent source;
- adapter refactor plan;
- `PLAN.md` note for the next implementation slice;
- clean committed worktree before code movement begins.

Validation:

- `git diff --check`;
- focused public-doc link/path test.

### Phase 1 — Introduce adapter scaffolding

Goal: add `src/sources/` without moving parser behavior yet.

Work:

- Add `src/sources/mod.rs`, `adapter.rs`, and `registry.rs`.
- Re-export or wrap existing `ClientDef`, `ClientSourceDef`, `ClientId`,
  `SourceKind`, `PathRoot`, and `SourcePattern` rather than redefining them.
- Add an internal built-in adapter registry that can return client definitions.
- Change `clients::supported_clients()` to delegate to the adapter registry while
  keeping its public signature unchanged.
- Add tests proving `supported_clients()` returns the exact same clients,
  source ids, source kinds, relative paths, fixture paths, and project-local
  metadata as before.

Validation:

```sh
cargo test clients::tests
cargo test discovery::tests
cargo test schema::tests::converts_all_fixture_sources_to_v1_contract
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

### Phase 2 — Move one simple agent source

Recommended first agent: Gemini or Claude.

Why not OpenCode first: OpenCode has SQLite plus cursor metadata and recent
part-table handling, so it is a poor first proof of the adapter scaffolding.

Why not Codex first: Codex has multiple source ids and headless/archive handling,
which is useful but more complex than a single-source move.

Work:

- Move the selected agent source definitions into `src/sources/<agent>/mod.rs`.
- Move parser helpers that are truly agent-specific into
  `src/sources/<agent>/parser.rs`.
- Keep generic JSON/JSONL helpers in the old parser module or move them to
  `src/sources/common/` only if the move is mechanical and well-tested.
- Add adapter-local tests for source definitions and parser behavior.
- Keep public function signatures unchanged.

Validation:

```sh
cargo test <agent>
cargo test parser::tests
cargo test discovery::tests
cargo test schema::tests::converts_all_fixture_sources_to_v1_contract
cargo run -- scan --once --dry-run --root tests/fixtures/session_stores --client <agent>
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

### Phase 3 — Move multi-source JSON/JSONL agents

Recommended order:

1. Claude or Gemini, whichever was not moved in Phase 2.
2. Qwen.
3. OpenClaw.
4. RooCode and KiloCode, sharing VS Code/globalStorage helpers.
5. Codex.

Work:

- Move source definitions and parser-specific tests into agent modules.
- Extract shared JSON, JSONL, and VS Code UI message helpers into
  `src/sources/common/` when at least two moved adapters need them.
- Keep `SourceKind` only for source format/routing when useful; prefer source id
  inside an adapter when behavior is truly agent-specific.

Validation:

- Run each agent's focused fixture scan after moving it.
- Run full quality gate after each coherent batch, not after every tiny file
  movement.

### Phase 4 — Move complex DB/log agents

Recommended order:

1. Copilot process logs.
2. OpenCode legacy JSON.
3. OpenCode SQLite.

OpenCode SQLite should move last because it involves:

- SQLite dependency and locked-database behavior;
- `ParseOptions` cursor/limit fields;
- `ParsedSourceRecords.sqlite_part_max_time_updated`;
- scan-state persistence of SQLite ingestion cursors;
- host-scan preference for SQLite over legacy host JSON sources.

Validation for OpenCode must include parser, state, scan-unit, and CLI cursor
tests, plus an OpenCode-only dry-run fixture scan.

### Phase 5 — Move install inventory definitions

Goal: each adapter exposes optional metadata-only install evidence.

Work:

- Make `AgentInstallDef` public within the crate if needed.
- Move per-agent install evidence into `src/sources/<agent>/install.rs`.
- Have `install_inventory` collect install definitions from the adapter
  registry.
- Preserve snapshot hash stability where possible. If ordering changes, sort by
  stable agent id before hashing.
- Preserve path hashing and confidence behavior.

Validation:

```sh
cargo test install_inventory
cargo test scan_once_writes_schema_shaped_health_jsonl
cargo test repeated_scans_suppress_duplicate_detections
cargo test scan_once_client_filter_limits_discovered_sources
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

### Phase 6 — Add Antigravity as the first new adapter

Only after at least one existing adapter migration has proven the structure.

Work:

- Research Antigravity source roots and install signals using metadata-only
  methods.
- Add `src/sources/antigravity/` with source definitions, parser, install hints,
  and focused tests.
- Add synthetic fixtures only; do not commit live transcript content.
- Keep support level `experimental` until all validation matrix gates pass.
- Update public docs and matrices.

Validation:

- Run Antigravity-focused parser/discovery/scan tests.
- Run full quality gate.

### Phase 7 — Custom and third-party parser path

Do this only after built-in adapters settle.

Recommended sequence:

1. **Config-only sources**: let operators declare additional source roots that
   use existing generic JSON/JSONL parsers.
2. **Subprocess parser plugins**: explicit command plugins that receive a source
   path and emit normalized JSON records on stdout.
3. **Optional WASM ABI**: only after the normalized schema, test harness, and
   trust boundary are stable.

Subprocess plugins should require:

- plugin name/version and supported client/source ids;
- deterministic normalized JSON output;
- timeout, memory/size, and stdout limits;
- stderr redaction;
- no network access by default;
- fixture conformance tests;
- telemetry marking external parser provenance.

## First Implementation Slice For Next Session

Start with Phase 1 only.

Concrete next tasks:

1. Create `src/sources/mod.rs`, `src/sources/adapter.rs`, and
   `src/sources/registry.rs`.
2. Move the existing static `CLIENTS` assembly behind `sources::registry` without
   moving individual agent parser code yet.
3. Keep `src/clients.rs` types and `supported_clients()` as compatibility API.
4. Add an equality/regression test that snapshots every current source id,
   source kind, root, relative path, fixture path, pattern, recursive flag, and
   project-local path before/after registry delegation.
5. Run focused registry/discovery/schema tests, then full `cargo fmt`, clippy,
   and `cargo test`.

Stop after Phase 1 if the diff grows beyond scaffolding and registry delegation.
The next commit after that can move the first simple adapter.

## Risks And Mitigations

| Risk | Mitigation |
| --- | --- |
| Behavior changes during mechanical moves | Preserve compatibility functions and add source-registry snapshot tests. |
| Parser refactor accidentally changes normalized output | Run schema conformance, focused parser tests, and fixture scans per client. |
| OpenCode SQLite cursor behavior regresses | Move OpenCode last; keep dedicated state/scan cursor tests. |
| Install inventory hash/order changes | Sort by stable agent id before hashing and assert snapshot behavior. |
| Public docs overstate support | Keep support claims tied to source validation matrix gates. |
| External parser plugins become unsafe | Defer plugins until compiled-in adapters are stable; prefer subprocess sandbox boundaries over in-process dynamic loading. |

## Done Criteria For The Refactor

The `src/sources/$AGENT` refactor is complete when:

- built-in agents have source definitions under `src/sources/<agent>/`;
- agent-specific parser code lives under the same agent module;
- shared parser helpers live under `src/sources/common/` or another clearly named
  shared module;
- install inventory definitions come from adapters or a similarly modular
  registry;
- `clients::supported_clients()` and parser public APIs remain stable or have a
  documented migration path;
- all fixture-backed discovery, parser, schema, detection, scan, and install
  inventory tests pass;
- `docs/adding-agent-source.md` describes the final adapter workflow for new
  contributors.
