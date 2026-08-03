# Adding an Agent Source

This guide is the repository-native checklist for adding a bundled coding-agent
source. Telltale discovers source files or databases, parses them into
normalized records, and then uses the existing detection, scoring, triage, and
event pipeline. New source support must not add source-specific detection logic
unless a rule genuinely cannot use normalized fields.

This is not a runtime extension contract. Public parse entry points exist, and
operators can select scan roots and project roots through the CLI and project
configuration. Telltale does not support runtime source/client/parser
registration or a parser extension API through plugins, external parser
configuration, dynamic loading, or a trait ABI. New source support is a
compiled-in registry and parser change.

## Current architecture

- `crates/telltale-schema/src/clients.rs` owns the canonical `ClientId` and
  `SourceKind` types.
- `crates/telltale-sources/src/sources/<agent>/mod.rs` owns that agent's static
  `ClientSourceDef` values and install metadata. The static
  source registry in `sources/registry.rs` collects source definitions and
  preserves static client/install registration order; it does not own parser
  registration. Registry order is significant for public client/install
  snapshot stability, while discovered `Source` results are explicitly sorted
  for deterministic scans.
- `crates/telltale-sources/src/parser.rs` owns the private, exact,
  case-sensitive `(ClientId, source_id)` parser registration table. `SourceKind`
  is checked as expected container/reporting metadata after identity lookup; it
  never selects semantic parsing.
- Each modeled source parser uses the internal uniform shape
  `fn(&Source, ParseOptions) -> Result<ExtractedSourceRecords, ParseError>`.
  Public `parse_source_records()` and
  `parse_source_records_with_options()` signatures remain unchanged.
- `read_jsonl_values()` and `read_json_document()` are neutral shared readers.
  Semantic extraction and record classification stay in the source module.
  There is currently no `sources/common/` directory; do not create one just to
  house a single helper.
- A known parser or schema failure is terminal. It must not retry through a
  generic parser. Explicit unknown variants become `RecordKind::Other` or the
  source's documented diagnostic. There is no secondary fallback after failure.

The current table has 14 exact identities: 12 modeled parsers and two deliberate
exact generic JSON-document fallbacks, `roocode.tasks` and `kilocode.tasks`.
Parser maturity is not the same claim as live validation or full public support;
use the [validation matrix](source-validation-matrix.md) for that distinction.

## Support levels

- **Research**: format or paths are being investigated; do not claim support.
- **Experimental**: registered and fixture-tested, but live validation or
  capability documentation is incomplete.
- **Supported**: discovery, benign parse, tool-call parse, tool-result parse,
  positive detection, benign/negative behavior, and public capability notes all
  pass their gates.

Project-local candidates may have complete parser/parity coverage while still
remaining candidates in the support matrix. Do not promote them without the
existing support gates.

For a new source belonging to an existing `ClientId`, reuse that client's
module, registry entry, and install definition. Add only the new source
definition, parser registration, fixtures, tests, snapshots, and documentation
that the source requires. The client-level wiring below applies when adding an
entirely new coding agent or harness.

## Community source checklist

### 1. Add the identity and client wiring

- For a new client, add the canonical `ClientId` variant and matching
  `ClientId::as_str()` arm. Reuse the existing variant for another source from
  an already registered client.
- Add stable, case-sensitive source IDs.
- Keep IDs specific to a source identity, such as `agent.sessions` and
  `agent.sqlite`; do not add aliases.
- Record the expected `SourceKind`, but do not use it as semantic dispatch.

### 2. Declare source definitions and the source module

- For a new client, create `crates/telltale-sources/src/sources/<agent>/` and
  declare it in `sources/mod.rs`. For another identity from an existing client,
  extend that client's module.
- Add the required `ClientSourceDef` entries to the client module.
- Set `root`, `relative_path`, `fixture_relative_path`, `pattern`,
  `recursive`, and `project_relative_path` where applicable.
- Use existing OS-aware root helpers and `Path`/`PathBuf` joins. Do not encode
  separators, Unix permissions, `/tmp`, symlinks, or verbatim Windows prefixes.

### 3. Wire the static registry and install metadata

- For a new client, import the source module in `sources/registry.rs` and add
  its `ClientDef` in matching public client order.
- For a new client, define the per-client `AgentInstallDef`/`INSTALL` in the
  source module, even when signal lists are empty, and add it to `INSTALL_DEFS`
  in the matching order.
- Registry order is part of the public client/install snapshot contract; keep
  it stable. Discovery sorts returned `Source` values independently.

### 4. Add the parser module

- For modeled semantics, add `sources/<agent>/parser.rs` for a new client or
  extend the existing client parser module for another source identity.
- Implement the internal uniform Source/ParseOptions/ExtractedSourceRecords
  function shape.
- Keep semantic mapping and classification in the source module.
- Preserve public parse signatures and normalized fields.
- Treat malformed input and known schema failures as terminal; never retry with
  another parser.
- Define the source contract for missing or unknown discriminators. Do not infer
  a known kind from an explicit unknown variant.

### 5. Add exact private registration

- Add one obvious exact `(ClientId, source_id)` entry to the private table in
  `crates/telltale-sources/src/parser.rs`.
- Point modeled identities at their source-owned parser.
- Use `GenericFallback(JsonDocument)` only when the source is intentionally
  unmodeled and its generic shape is verified. There is no generic JSONL
  fallback in the current table.
- Do not add a parser field to public `ClientSourceDef`.
- Update hard-coded registry, parser-maturity, and client-count snapshots.

### 6. Use shared readers only

- Reuse `read_jsonl_values()` or `read_json_document()` for neutral I/O and
  JSON decoding.
- Do not create traits, factories, managers, plugin boundaries, runtime
  registration, external parser configuration, or a speculative common
  framework.

### 7. Add synthetic fixtures

- Put discovered source fixtures under
  `tests/fixtures/session_stores/<client>/...` at the registered relative path.
- Keep non-discovered drift/unknown/failure fixtures outside discovered roots.
- If packaged unit tests resolve fixtures under a crate boundary, mirror the
  exact synthetic files under `crates/<crate>/tests/fixtures/...`.
- Cover benign user/assistant records, tool calls, tool results, positive
  deterministic detections, and a quiet negative. UC-001 is the required
  cross-client conformance fixture for a new `ClientId`. Never use real
  transcripts, credentials, auth files, private paths, or customer data.

### 8. Add focused tests

Cover, as applicable:

- source-definition and bidirectional registry/integrity checks;
- exact identity, wrong-client, wrong-kind, and unknown-identity behavior;
- positive and benign normalized records, field inheritance, and order;
- schema drift, malformed input, empty input, explicit unknown variants, and
  no-fallback behavior;
- emitted source/event tuple identity and ordering;
- portable discovery, project-local paths, and suffix matching;
- state, cursor, lock, or source-preference behavior for database sources;
- detection fixtures proving normalized records reach existing rules.
- registry/install order and all hard-coded count snapshots;

Use `tempfile` and portable `Path`/`PathBuf` joins for synthetic path tests.
Avoid exact separators and Unix-only assumptions.

### 9. Update support documentation

- Update `docs/session-sources.md` and `docs/source-validation-matrix.md`.
- Update `docs/client-capability-matrix.md` and
  `docs/agent-capability-profiles.md` for user-visible field availability.
- Update telemetry or schema documentation only if a separately justified
  cross-agent contract changes. Do not fork normalized or event schemas for one
  source.
- Advertise support in `README.md` only after the fixture and capability gates
  pass.

### 10. Validate in repository order and on supported platforms

Run the narrowest relevant tests first, then the source and detection suites:

```sh
cargo test -p telltale-sources <agent-or-parser-filter>
cargo test -p telltale-sources
cargo test -p telltale-detect
cargo test --test cli parser_maturity
cargo run --bin telltale -- scan --once --dry-run --no-local-config \
  --root tests/fixtures/session_stores --client <client-id>
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
./scripts/package-verify
```

Package verification currently runs on Linux and macOS. Keep fixture scans
read-only or use an explicit development sink.

Run or retain Linux, Windows, and macOS CI coverage for path roots, discovery,
fixture parsing, and relevant source tests. Do not claim live source-store
support merely because a parser maturity test passes.

## Definition of done

A source is ready for its stated support level when discovery is deterministic,
the exact private parser registration is covered, normalized output and order
are characterized, known failures cannot fall through, fixtures are synthetic,
and the relevant install, detection, documentation, and platform gates pass.
