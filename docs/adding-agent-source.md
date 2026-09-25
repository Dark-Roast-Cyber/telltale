# Adding an Agent Source

This guide is the repository-native checklist for adding a bundled coding-agent
source. Telltale discovers source files or databases, extracts source-native
facts, and maps them to Canonical Observation v2. Scan, watch, and embedding
then use Detection v2 and the Event 3.0 projection. New source support must not
add source-specific detection logic unless a rule genuinely cannot use canonical
fields.

This is not a runtime extension contract. Operators can select scan roots and
project roots through the CLI and project configuration. Telltale does not
support runtime source/client registration or a parser extension API through
plugins, external configuration, dynamic loading, or a trait ABI. New source
support is a compiled-in registry and native-extractor change. Caller-supplied
`NormalizedRecord` evaluation stays a separate compatibility path and is not a
source adapter output.

## Current architecture

- `crates/telltale-schema/src/clients.rs` owns the canonical `ClientId` and
  `SourceKind` types.
- `crates/telltale-sources/src/sources/<agent>/mod.rs` owns that agent's static
  `ClientSourceDef` values and install metadata. The static
  source registry in `sources/registry.rs` collects source definitions and
  preserves static client/install registration order. Registry order is
  significant for public client/install snapshot stability, while discovered
  `Source` results are explicitly sorted for deterministic scans.
- `crates/telltale-sources/src/acquisition.rs` owns the public, cross-source
  Canonical Observation v2 acquisition router, batch types, and acquisition
  controls. Its route is source discovery -> native extraction -> native
  accounting/progress -> source-owned canonical mapping. Source mappers remain
  crate-private. `SourceKind` is container/reporting metadata; it never selects
  semantic extraction.
- `crates/telltale-sources/src/source_read.rs` owns shared JSONL reading and
  bounded read errors. It is not a parser, projection, or record model.
  Semantic extraction stays in the source module. There is currently no
  `sources/common/` directory; do not create one just to house a single helper.
- A known extraction or schema failure is terminal. It must not retry through a
  generic parser. There is no secondary fallback after failure, and no
  source-backed conversion into `NormalizedRecord`.

The current table has eight exact identities across six agent families, all
using modeled source-owned native extractors. There are no candidate or
compatibility registrations and no generic parser fallback. OpenCode is only
`opencode.sqlite`.
Extractor coverage is not the same claim as live validation or full public
support; use the [validation matrix](source-validation-matrix.md) for that
distinction.

## Support levels

- **Research**: format or paths are being investigated; do not claim support.
- **Experimental**: registered and fixture-tested, but live validation or
  capability documentation is incomplete.
- **Supported**: discovery, benign extraction, tool-call extraction, tool-result
  extraction, positive detection, benign/negative behavior, and public
  capability notes all pass their gates.

Project-local candidates may have complete fixture coverage while still
remaining candidates in the support matrix. Do not promote them without the
existing support gates.

For a new source belonging to an existing `ClientId`, reuse that client's
module, registry entry, and install definition. Add only the new source
definition, native extractor, acquisition route, fixtures, tests, snapshots,
and documentation that the source requires. The client-level wiring below
applies when adding an entirely new coding agent or harness.

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

### 4. Add native extraction and canonical mapping

- For a new client, add `sources/<agent>/native.rs` and
  `sources/<agent>/canonical.rs`, or extend the existing client modules for
  another source identity.
- Keep native structures crate-private. Derive accounting facts from structured
  native state. Do not add synchronized `legacy_*` fields or a flattened record
  projection.
- Treat malformed input and known schema failures as terminal; never retry with
  another extractor.
- Define the source contract for missing or unknown discriminators. Do not infer
  a known kind from an explicit unknown variant.
- Require a source-reported session id when canonical identity needs one. Do not
  fall back to a filename stem, path, or compatibility session.
- Add the exact identity to the single public acquisition router. Do not add a
  parallel cross-source facade or make the source mapper public.

### 5. Keep registry dispatch exact

- Acquisition dispatches the exact `(ClientId, source_id)` identity. `SourceKind`
  is checked as container metadata and does not select extraction.
- Do not add a parser field to public `ClientSourceDef`.
- Do not add a generic JSONL or JSON-document fallback.
- Update hard-coded registry and client-count snapshots.

### 6. Use shared readers only

- Reuse `read_jsonl_values()` for neutral JSONL decoding. SQLite sources own
  their read options directly.
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
- positive and benign canonical observations, field inheritance, and order;
- schema drift, malformed input, empty input, explicit unknown variants, and
  no-fallback behavior;
- emitted source/event tuple identity and ordering;
- portable discovery, project-local paths, and suffix matching;
- state, cursor, lock, or source-preference behavior for database sources;
- detection fixtures proving canonical observations reach Detection v2.
- registry/install order and all hard-coded count snapshots;

Use `tempfile` and portable `Path`/`PathBuf` joins for synthetic path tests.
Avoid exact separators and Unix-only assumptions.

### 9. Update support documentation

- Update `docs/session-sources.md` and `docs/source-validation-matrix.md`.
- Update `docs/agent-capability-profiles.md` for user-visible source
  visibility. Update `docs/normalization-schema.md` only if the separate
  caller-provided record compatibility contract changes.
- Update telemetry or schema documentation only if a separately justified
  cross-agent contract changes. Do not fork normalized or event schemas for one
  source.
- Advertise support in `README.md` only after the fixture and capability gates
  pass.

### 10. Validate in repository order and on supported platforms

Run the narrowest relevant tests first, then the source and detection suites:

```sh
cargo test -p telltale-sources <agent-or-source-filter>
cargo test -p telltale-sources
cargo test -p telltale-detect
cargo test --test cli scan_watch::scan_once_writes_schema_shaped_health_jsonl -- --exact
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
fixture acquisition, and relevant source tests. Do not claim live source-store
support merely because a fixture acquisition test passes.

## Definition of done

A source is ready for its stated support level when discovery is deterministic,
the exact acquisition identity is covered, canonical output and order are
characterized, known failures cannot fall through, fixtures are synthetic,
and the relevant install, detection, documentation, and platform gates pass.
