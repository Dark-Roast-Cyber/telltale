# Source Adapter Architecture and Migration Record

This document records the implemented explicit per-source parser architecture.
It replaces the former plan to infer semantic parsing from `SourceKind`.

The public pipeline is unchanged:

```text
discover -> parse -> normalize -> detect -> score -> emit
```

Discovery, normalization, detection, scoring, emission, install inventory, Event
2.0 compatibility fields, state, and public parser signatures retain their
existing contracts.

## Implemented architecture

### Source definitions and ordering

The canonical `ClientId` and `SourceKind` types live in
`crates/telltale-schema/src/clients.rs`. Agent source modules under
`crates/telltale-sources/src/sources/<agent>/` own static source definitions,
install hints, parsers, and focused tests where practical.

`crates/telltale-sources/src/sources/registry.rs` collects static source
definitions and install ordering. It does not own parser registration and
`ClientSourceDef` does not contain a parser field. Discovery continues to use
the source definitions, OS-aware root helpers, and project-local paths.

The private exact registration table is centralized in
`crates/telltale-sources/src/parser.rs`. Lookup is case-sensitive by the pair
`(ClientId, source_id)`. `SourceKind` is checked only as expected container and
reporting metadata after identity lookup; it never selects semantic parsing.

Modeled parsers use the internal uniform function shape:

```text
fn(&Source, ParseOptions) -> Result<ExtractedSourceRecords, ParseError>
```

The public `parse_source_records()` and
`parse_source_records_with_options()` interfaces remain unchanged. Generic
parsing is not used by any registered identity. All 14 exact registrations
select a source-owned modeled parser; there is no generic JSON document or
JSONL fallback.

Neutral JSON decoding remains shared through `read_jsonl_values()` and
`read_json_document()`. Source modules own semantic extraction and
classification. A `sources/common/` directory is not required by the current
implementation and should not be invented for a single helper.

### Failure and privacy boundaries

A known parser or schema failure is terminal. It is returned through the normal
scanner diagnostic path and is never retried with generic or another
source-specific parsing. Explicit unknown record variants become
`RecordKind::Other` or a source-contract diagnostic; a known kind is never
guessed from coincidental fields in an explicitly unknown variant.

Errors and evidence must not expose raw transcript bodies, credentials,
encrypted content, or sensitive paths. Synthetic tests use portable
`Path`/`PathBuf` joins and temporary directories rather than separator or Unix
assumptions.

## Migration results

The source-maturity work was completed as bounded identity batches while
preserving normalized and emitted-event parity:

| Batch | Exact identities | Result |
| --- | --- | --- |
| Claude | `claude.projects` | Modeled parser; structural JSONL drift is terminal; unknown explicit variants are `Other`. |
| Codex | `codex.sessions`, `codex.archived_sessions`, `codex.headless_sessions`, `codex.project_sessions` | Modeled JSONL parser with metadata inheritance, project-local parity, and terminal schema/unknown boundaries. |
| OpenCode JSON | `opencode.legacy_json`, `opencode.project_json` | Modeled JSON-document parser; object/array order and failure boundaries preserved. |
| OpenCode SQLite | `opencode.sqlite` | Modeled existing SQLite parser; queries, 5-second busy timeout, locks, cursors, high-water marks, limits, state, and SQLite-over-legacy preference preserved. |
| OpenClaw | `openclaw.agents` | Modeled JSONL parser; filename and `.jsonl.deleted` discovery preserved. |
| Qwen | `qwen.projects` | Modeled JSONL parser with terminal schema and unknown boundaries. |
| Copilot | `copilot.process_log` | Modeled tolerant process-log parser; truncated logs remain recoverable, reasoning/message items remain ignored, and unknown future items produce safe `Other` summaries. |
| Gemini | `gemini.tmp` | Modeled JSON parser; missing `messages` remains the established `Empty` behavior. |
| RooCode | `roocode.tasks` | Modeled `ClineMessage` parser with direct `history_item.json.id` session namespace, cache-only `_index.json` corroboration, terminal subtype/schema failures, source timestamp conversion, exact MCP request/result text handling, and compatibility parent fallback. Per-message identity is not ready. |
| KiloCode | `kilocode.tasks` | Modeled legacy-writer `ClineMessage` parser with independently parsed MCP request/result shapes and a separate alternate-body boundary. The pinned writer has no Roo history/index companions; current SQLite/server/CLI stores remain out of scope, parent-directory grouping is compatibility-only, and session/per-message identity is not ready. |

Final parser maturity is 14 modeled identities and no generic fallbacks. All 14 registered identities, including the
project-local Codex and OpenCode candidates, have parser/parity fixture
coverage. That fact is separate from the public support matrix and from live
host validation.

## Compatibility preserved during migration

- `ClientSourceDef`, `ClientId`, source discovery, install metadata, and public
  parser signatures remain stable.
- Normalized fields, record order, source/event tuple identity, and native Event 3.0
  output remain parity-tested.
- Gemini's established missing-`messages` `Empty` result remains unchanged.
- Copilot retains plain-line tolerance, standalone JSON-array handling,
  workspace session boundaries, function-call results, and recoverable
  truncated JSON behavior.
- OpenCode SQLite retains its query shapes, selected-row order, part filters,
  limits, min-cursor overlap, maximum timestamp calculation, busy/lock error
  mapping, scan-state behavior, fingerprinting, and preference over legacy JSON.
- No trait, plugin ABI, dynamic/runtime registration, external parser
  configuration, factory, manager, or public parser extension API was added.

## Community addition shape

Future coding-agent or harness additions should follow this small compiled-in
sequence:

1. For a new client, add a canonical `ClientId` and its `ClientId::as_str()`
   arm; reuse both for an additional source from an existing client. Add stable
   source IDs in either case.
2. For a new client, create the agent module and declare it in `sources/mod.rs`;
   for another identity, extend the existing module with its paths and patterns.
3. Add a source-owned parser module for a new modeled client, or extend the
   existing client parser for another modeled identity.
4. For a new client, import the module and add its `ClientDef` to
   `sources/registry.rs`, preserving public client/install order; discovered
   `Source` results are sorted separately.
5. For a new client, define the per-client `AgentInstallDef`/`INSTALL`, even
   with empty signal lists, and add it to `INSTALL_DEFS` in matching order.
6. Add one exact private parser registration per identity and update hard-coded
   registry, parser-maturity, and client-count snapshots.
7. Reuse only neutral shared readers; keep semantic mapping source-owned.
8. Add synthetic discovered fixtures at registered paths and mirror them under
   a crate's `tests/fixtures` boundary when packaged unit tests reference them.
9. Add registry/integrity, positive/benign, drift/unknown/failure/no-fallback,
   event/source-order, and portable path tests.
10. Update support/capability documentation, then run focused and full Rust
    tests, package verification when applicable, and Linux/Windows/macOS CI.

Do not introduce runtime registration, external parser configuration, a public
extension API, or a parser trait/framework as part of a source addition.
