# Source Validation Matrix

This matrix is the canonical public record for source-support claims. It tracks
the eight supported source identities across discovery, native extraction,
canonical acquisition, detection coverage, live validation, and capability gaps.
README and installation guidance link here rather than assigning
subjective confidence labels. A source is only considered supported when the
required coverage gates below have fixture-backed proof; live validation is an
additional, bounded signal rather than broad source-store coverage.

The static registry and exact-identity acquisition router support these eight
identities. There are no hidden candidate or compatibility registrations.

## Legend

- ✅ — fixture-backed proof exists and passes
- ⚠️ — partial coverage or known gaps
- ❌ — not yet validated
- N/A — not applicable for this source

## Current acquisition and detection model

All eight exact source identities have source-owned native extraction and
Canonical Observation v2 adapters. Acquisition retains native accounting and
operational progress; canonical observations feed Detection v2 in the shared
scan/watch runtime. Synthetic adapter/conformance and detection/evaluation
fixtures establish support, not broad live-host validation. OpenClaw and Qwen
report ToolCall and UserContext **Supported**, ToolExecution **Unknown**;
Copilot reports ToolCall **Supported**, UserContext **Unsupported**, and
ToolExecution **Unknown**.

## Validation Matrix

| Client | Source Identity | Discovery | Native + canonical benign | Canonical tool call | Canonical tool result | UC-001 | UC-002 | UC-003 | Support Status / Live Validation | Capability gaps |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Codex | `codex.sessions` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ Fixture-backed + bounded live validation | Workspace conditional; process ID and exit code absent; call ID/error state/parts conditional |
| Codex | `codex.archived_sessions` | ✅ | ✅ | ✅ | ✅ | ✅ | — | — | ✅ Fixture-backed + bounded live validation | Same as `codex.sessions` |
| Codex | `codex.headless_sessions` | ✅ | ✅ | ✅ | ✅ | ✅ | — | — | ✅ Fixture-backed + bounded live validation | Same as `codex.sessions` |
| Claude Code | `claude.projects` | ✅ | ✅ | ✅ | ✅ | ✅ | — | — | ✅ Fixture-backed + bounded live validation | Workspace, process ID and exit code absent; timestamps and call ID/error state/parts conditional |
| OpenClaw | `openclaw.agents` | ✅ | ✅ | ✅ | ✅ | ✅ | — | — | ✅ Fixture-backed only | Workspace, process ID and exit code absent; ToolExecution unknown |
| Qwen CLI | `qwen.projects` | ✅ | ✅ | ✅ | ✅ | ✅ | — | — | ✅ Fixture-backed only | Workspace, process ID and exit code absent; ToolExecution unknown |
| OpenCode | `opencode.sqlite` | ✅ | ✅ | ✅ | ✅ | ✅ | — | — | ✅ Fixture-backed + bounded live validation | Workspace conditional; process ID and exit code absent; call ID/error state/parts conditional |
| Copilot | `copilot.process_log` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | — | ✅ Fixture-backed + bounded live validation | User context and content parts absent; tool results conditional; ToolExecution unknown |

## Coverage Gates

Every new agent source must pass these required gates before being marked supported in this matrix or advertised as supported in user-facing docs:

1. **Discovery**: fixture-backed source discovery finds the expected files.
2. **Native extraction and canonical acquisition**: a benign fixture is extracted and acquired without errors, with native accounting and progress checked.
3. **Canonical tool call**: a tool-call fixture maps to the expected canonical observation.
4. **Canonical tool result**: a tool-result fixture maps to the expected canonical observation.
5. **Adapter conformance and positive detection**: fixture-backed canonical adapter coverage and Detection v2/evaluation coverage establish the expected source identity, facts, and deterministic signals. Every new `ClientId` must include UC-001 coverage; the repository test `uc001_critical_fixture_coverage_includes_every_supported_client` enforces this cross-client gate.
6. **Negative detection**: at least one negative or benign source fixture stays quiet under bundled rules.
7. **Capability documentation**: known lossy, absent, or derived fields are recorded here and in [Agent Capability Profiles](agent-capability-profiles.md) when the source becomes user-visible.

Live host validation is an additional operational confidence signal, not a
support gate. Record it when safe and available, but do not scan large or
sensitive real session stores just to satisfy fixture coverage.

Windows discovery coverage includes deterministic Codex `CodexHome` tests. These
paths are not live-validated and are not by themselves public live-source
support; see [Session Sources](session-sources.md).

The v0.2.0 release archives and CI smoke checks establish binary packaging and
execution support on macOS and Windows. They do not prove broad live validation
of source stores on either platform. Clients marked **fixture-backed only** are
preview/experimental for live source-store use until bounded live validation is
recorded here.

## Public Validation Boundary

Public support claims should be backed by synthetic fixtures and deterministic
tests that can run from a clean checkout. Fixture scans may use
`tests/fixtures/session_stores` with `--dry-run` for read-only verification or
`--allow-fixtures` only when the output path is an explicit development sink.

Live host validation belongs in local operational notes. When it is useful to
record that a client has been checked on a real workstation, summarize the
client, source kind, bounded command shape, and pass/fail result without
publishing raw transcript excerpts, session-store paths, credentials, telemetry
logs, or machine-specific SIEM configuration.

Use `--client <id>` and `--max-sources <n>` when checking real stores for
acquisition health so validation remains deterministic and small enough to summarize
without exposing host-specific details. Keep exploratory live checks read-only
with `--dry-run`; reserve JSONL writes for intentional monitoring runs after the
bounded command shape is understood.

## New Source Checklist

When adding a source, include these repository-native artifacts in the same
change or keep the source marked experimental until they exist:

1. For a new client, a canonical `ClientId` variant and its
   `ClientId::as_str()` arm; reuse them for another source from an existing
   client. Add stable, case-sensitive source IDs in either case.
2. For a new client, a new `sources/<agent>/mod.rs` declaration in
   `sources/mod.rs`; for another identity, an update to the existing client
   module. Include path roots, patterns, fixture paths, recursion, and
   project-local metadata.
3. Source-owned native extraction and canonical mapping for a new modeled
   client, or an update to the existing client modules for another modeled
   identity. Do not add a flattened record projection.
4. For a new client, an import and `ClientDef` entry in
   `sources/registry.rs`, preserving public client/install order.
5. For a new client, a per-client `AgentInstallDef`/`INSTALL` definition,
   including empty signal lists when appropriate, plus the matching
   `INSTALL_DEFS` entry.
6. One exact identity in the public acquisition router. `SourceKind` does not
   select extraction.
7. Neutral shared reader use only; do not add a parser field to public
   `ClientSourceDef` or a public parser extension API.
8. Synthetic fixtures under the registered fixture-relative path, mirrored
   under a crate `tests/fixtures` boundary when packaged tests reference them.
9. Registry/integrity, positive/benign, drift/unknown/failure/no-fallback,
   source/event ordering, portable discovery/path tests, and updated hard-coded
   registry and client-count snapshots.
10. Support/capability documentation, focused/full/package validation, and
    Linux, Windows, and macOS CI coverage.

Use portable `Path`/`PathBuf` joins and platform-aware root helpers. Do not rely
on exact separators, Unix permissions, symlinks, `/tmp`, or verbatim Windows
path prefixes. Do not introduce traits, plugin ABI, dynamic/runtime
registration, or external parser configuration.

## Use-Case Coverage Summary

| Use Case | Description | Clients Covered | Status |
| --- | --- | --- | --- |
| UC-001 | Fake MCP prompt injection to controlled domain | All 6 supported clients (8 source identities) | ✅ Complete |
| UC-002 | Credential harvesting before package publish | Codex, Copilot | ✅ 2 clients |
| UC-003 | DNS exfiltration with encoded payload | Codex | ✅ 1 client |

## Live Validation Status

Codex, OpenCode, Claude Code, and Copilot have received bounded live validation:

- **Codex**: `~/.codex/sessions/`, `archived_sessions/`, and `headless/` (complete)
- **OpenCode**: Linux `$XDG_DATA_HOME/opencode/opencode.db` or `~/.local/share/opencode/opencode.db` (complete)
- **Copilot**: `logs/copilot/process-*.log` (complete)
- **Claude Code**: `~/.claude/projects/` (complete) — bounded `--client claude --max-sources 5 --dry-run` parsed 5 sources with 5 activities and 1 benign detection, zero scanner errors; repeated at cap 10 with consistent results.

Future live-validation notes should record the client filter and source cap
used, for example `--client codex --max-sources 5 --dry-run`, rather than exact
local source paths or transcript identifiers.

## Related Documents

- [Adding an Agent Source](adding-agent-source.md) — implementation checklist and native acquisition architecture
- [Agent Capability Profiles](agent-capability-profiles.md) — per-source field availability and known gaps
- [Client Capability Matrix](client-capability-matrix.md) — field-level availability per client
- [Canonical Observation v2](canonical-observation-v2.md) — current source observation contract
- [Detection Content Standard](detection-content-standard.md) — rule metadata and fixture expectations
- [Session Sources](session-sources.md) — path patterns and discovery notes
- [Use Cases](use-cases.md) — UC-001, UC-002, UC-003 definitions
