# Adding an Agent Source

This guide lists every project surface that normally changes when Telltale adds
support for a new coding agent or a new session source for an existing agent.
Use it as the checklist for agents such as Antigravity, new OpenCode storage
formats, or customer-contributed parsers.

Telltale's contract is: discover source files or databases, parse them into the
normalized record model, and let the existing detection/rule pipeline run
unchanged. Do not add source-specific detection logic unless a rule truly cannot
be expressed over normalized fields.

## Current Code Layout

The current implementation is intentionally simple, but it is centralized:

- `src/clients.rs` owns path roots, source patterns, and the static
  `supported_clients()` registry; the `ClientId` and `SourceKind` enums live in
  `crates/telltale-schema/src/clients.rs` and are re-exported from
  `src/clients.rs`.
- `src/discovery.rs` resolves OS-specific roots, project-local roots, watch
  roots, and fixture paths for every registered source.
- `src/parser.rs` dispatches by `SourceKind` and converts raw records into
  `NormalizedRecord`.
- `src/install_inventory.rs` separately answers "does this agent appear
  installed?" using metadata-only executable, package, extension, and
  globalStorage checks.

This is workable while the supported source list is small. As support expands,
the better target is an adapter layout that keeps each agent's source registry,
parser, install inventory hints, fixtures, and focused tests near each other.
See [Recommended Adapter Layout](#recommended-adapter-layout) below and the
[Source Adapter Refactor Plan](source-adapter-refactor-plan.md) for the detailed
migration plan.

## Support Levels

Use explicit support language while adding a source:

- **Research**: upstream format and paths are being investigated. No public
  support claim.
- **Experimental**: source is registered and parses synthetic fixtures, but live
  validation or capability docs are incomplete.
- **Supported**: fixture discovery, benign parse, tool-call parse, tool-result
  parse, at least one positive detection, at least one benign/negative scan, and
  documentation are complete.

Live host validation is helpful but is not required for public support. It must
remain bounded, redacted, and summarized; fixtures are the required support gate.

## Checklist

### 1. Research source and install signals

Record, in notes or docs, the difference between these two questions:

1. **Session-store discovery**: where can Telltale parse activity from?
2. **Installed-agent inventory**: what metadata-only evidence indicates the
   tool is installed?

For a new agent, identify:

- OS-specific session roots for Linux, macOS, and Windows.
- Whether sources are home-relative, config-relative, data-relative, or
  project-local.
- File/database format: JSONL, JSON array, SQLite, process log, or another
  bounded format.
- Stable source identifiers, for example `antigravity.sessions` or
  `antigravity.sqlite`.
- Install inventory signals: executable names, package IDs, VS Code-compatible
  extension IDs, globalStorage IDs, application support roots, or other
  metadata-only markers.
- Known privacy risks in the raw format, especially secrets, full prompts,
  credential files, or command output.

Do not read or publish real transcript content while researching. Prefer
metadata, file names, schema excerpts, synthetic examples, hashes, and redacted
summaries.

### 2. Update the source registry

Current files:

- `src/clients.rs`
- `src/discovery.rs` only if a new root or discovery behavior is needed

Required `src/clients.rs` updates:

- Add a `ClientId` variant.
- Add the lowercase stable id in `ClientId::as_str()`.
- Add or reuse a `SourceKind`.
- Add one or more `ClientSourceDef` entries with:
  - stable `id`, such as `antigravity.sessions`;
  - `kind`;
  - `root`;
  - `relative_path` for host discovery;
  - `fixture_relative_path` under `tests/fixtures/session_stores/<client>/`;
  - `pattern`;
  - `recursive`;
  - `project_relative_path` when `PathRoot::ProjectLocal` is used.
- Add the client to the `CLIENTS` slice returned by `supported_clients()`.
- Update registry tests in the same file.

Only edit `src/discovery.rs` when the source needs a new cross-platform root,
new bounded search behavior, or source matching that cannot be represented with
`SourcePattern`.

### 3. Add parser support

Current file:

- `src/parser.rs`

Parser requirements:

- Produce `NormalizedRecord` values with stable `session_id`, `client`, `kind`,
  and safe content fields.
- Preserve `agent`, `model`, `provider`, and `timestamp` when the raw source
  exposes them.
- Normalize user messages, assistant messages, tool calls, tool results, and
  session metadata when present.
- Keep source-specific parsing separate from detection. Rules should operate on
  the normalized output.
- Avoid logging raw transcripts or secrets in errors, tests, or debug output.
- For SQLite or append-only databases, consider state/cursor needs before
  scanning the entire database repeatedly.

If the new source can use an existing generic parser, document that explicitly.
If it needs a new parser branch, add focused unit tests next to the parser code.

### 4. Add install inventory support

Current file:

- `src/install_inventory.rs`

Add an install definition when the agent should appear in the metadata-only
installed-agent inventory:

- executable names on `PATH`;
- package IDs, such as Node package names;
- editor extension IDs;
- globalStorage IDs;
- any other safe metadata-only install roots.

Inventory events must not expose raw local paths. Use the existing hashed-path
signal model and confidence rules. Do not read session contents as part of
install inventory.

### 5. Add synthetic fixtures

Primary fixture root:

- `tests/fixtures/session_stores/<client>/...`

Every supported source needs fixtures for:

- benign user/assistant conversation records;
- at least one tool call;
- at least one tool result;
- at least one positive deterministic detection, preferably UC-001 when the
  source can represent it;
- at least one benign or negative fixture that stays quiet.

Fixture rules:

- Use synthetic prompts, file names, domains, tokens, and command output.
- Never copy real transcripts, `.env` values, auth files, session IDs, API keys,
  private paths, or customer data.
- Keep fixtures small enough that a reviewer can understand the parser behavior
  without opening a real agent store.

### 6. Update tests

At minimum, add or update tests covering:

- source registry entries in `src/clients.rs`;
- discovery for fixture paths and any new OS/path-root behavior in
  `src/discovery.rs`;
- parser extraction for benign records, tool calls, and tool results;
- the schema conformance test that discovers every fixture source and converts
  records into `NormalizedRecordV1`;
- a positive detection fixture proving bundled rules apply after normalization;
- a benign/negative fixture proving normal activity does not fire noisy rules;
- install inventory signal tests if new install evidence was added;
- CLI scan behavior when event counts, client filters, or source counts change.

Recommended verification order:

```sh
cargo test clients::tests
cargo test discovery::tests
cargo test parser::tests
cargo test schema::tests::converts_all_fixture_sources_to_v1_contract
cargo run -- scan --once --dry-run --no-local-config --root tests/fixtures/session_stores --client <client-id>
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

Use the narrowest relevant commands first; run the full suite before calling the
source supported.

### 7. Update public docs

Usually update:

- `docs/session-sources.md` — source paths, confidence, parser notes.
- `docs/source-validation-matrix.md` — fixture gates and live-validation status.
- `docs/client-capability-matrix.md` — normalized-field support and known gaps.
- `docs/agent-capability-profiles.md` — per-source raw field availability.
- `docs/telemetry-output.md` — only if emitted event shape or inventory behavior
  changes.
- `docs/CHANGELOG.md` — user-visible support or behavior changes.
- `README.md` — only after support is fixture-backed and ready to advertise.

Keep public docs clear about experimental status. Do not advertise Windows,
live-host, or source-format support beyond what fixtures and validation prove.

### 8. Update schemas/state only when required

Most new agents should not require schema changes. Update schema or state only
when the source reveals a genuinely cross-agent concept.

Examples that may require additional work:

- a new normalized field shared across multiple agents;
- invocation lineage, sub-agent role, or action lifecycle metadata;
- database cursors or per-table high-water marks;
- source-specific de-duplication beyond path fingerprints;
- new event types.

When adding normalized fields, make them additive and optional. Do not fork the
schema for one agent.

## Recommended Adapter Layout

The current centralized layout is not the best long-term shape. It is easy to
start with but it spreads one agent across `clients.rs`, `parser.rs`,
`install_inventory.rs`, docs, and tests. That makes adding agents like
Antigravity more error-prone. The step-by-step migration plan lives in
[Source Adapter Refactor Plan](source-adapter-refactor-plan.md).

A better internal organization is compiled-in source adapters:

```text
src/
  sources/
    mod.rs
    adapter.rs          # shared SourceAdapter contract/types
    registry.rs         # collects built-in adapters
    codex/
      mod.rs            # client id, source defs, parser dispatch
      parser.rs
      install.rs
      tests.rs
    opencode/
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

The stable adapter contract should expose roughly:

- client id and display name;
- source definitions;
- optional install inventory definitions;
- parser function for that agent's source kinds;
- fixture root and test helpers;
- capability metadata used by docs/tests.

The rest of the pipeline should continue to depend on stable interfaces:

```text
discover -> parse -> normalize -> detect -> score -> triage -> emit
```

This keeps `codex` code in `src/sources/codex/`, future `antigravity` code in
`src/sources/antigravity/`, and shared JSON/JSONL/SQLite helpers in common
modules.

## Plugin Strategy

External parsers are a good goal, but do not jump straight to arbitrary dynamic
loading. Parser plugins touch sensitive transcripts, so the trust boundary needs
to be explicit.

Recommended phases:

1. **Compiled-in adapters**: refactor built-in agents into per-agent modules
   while keeping the current Rust type safety and test coverage.
2. **Config-only custom sources**: allow operators to declare additional
   generic JSON/JSONL sources when an existing parser shape is enough.
3. **Subprocess parser plugins**: run external parsers as explicit commands that
   read a source path and emit normalized JSON records on stdout. This is easier
   to sandbox, version, and audit than in-process dynamic libraries.
4. **Optional WASM plugin ABI**: consider only after the normalized schema and
   plugin lifecycle are stable.

For third-party parsers, require:

- declared plugin name, version, supported client id, and source ids;
- deterministic stdout schema;
- stderr/error redaction rules;
- timeout and size limits;
- no network access by default;
- fixture conformance tests supplied by the plugin author;
- clear marking in telemetry that records came from an external parser.

## Antigravity Example Checklist

When adding Antigravity, keep it experimental until each item is complete:

- Confirm official product name and stable client id, likely `antigravity`.
- Identify session-store roots for Linux, macOS, and Windows without publishing
  private local paths or transcript contents.
- Decide whether sources are global, project-local, or both.
- Add `ClientId::Antigravity`, `antigravity.*` source definitions, and fixtures.
- Add parser support for benign messages, tool calls, tool results, and metadata.
- Add install inventory signals using metadata-only checks.
- Add synthetic positive and negative fixtures.
- Update validation and capability docs.
- Run focused tests and then the full quality gate.

Do not add Antigravity to public supported-client lists until fixture-backed
coverage passes and known gaps are documented.

## Definition of Done

A new agent source is done when:

- source discovery is deterministic and cross-platform behavior is documented;
- parsing produces normalized records without source-specific detection logic;
- fixtures cover benign records, tool calls, tool results, positive detection,
  and negative behavior;
- schema conformance passes for the fixture source;
- install inventory is added or explicitly marked not applicable;
- support level and known gaps are documented;
- `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, and
  `cargo test` pass.
