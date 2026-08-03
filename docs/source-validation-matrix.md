# Source Validation Matrix

This matrix is the canonical public record for source-support claims. It tracks
the 12 currently matrixed source identities across discovery, parsing, tool-call handling,
tool-result handling, use-case coverage, live validation status, and known lossy
fields. README and installation guidance link here rather than assigning
subjective confidence labels. A source is only considered supported when the
required coverage gates below have fixture-backed proof; live validation is an
additional, bounded signal rather than broad source-store coverage.

The static registry contains 14 exact identities, including two project-local
candidates,
`codex.project_sessions` and `opencode.project_json`. They are excluded from the
supported matrix until they pass every coverage gate. Their registered paths and
candidate status are documented in [Session Sources](session-sources.md).

## Legend

- ✅ — fixture-backed proof exists and passes
- ⚠️ — partial coverage or known gaps
- ❌ — not yet validated
- N/A — not applicable for this source

## Parser maturity assessment

Parser maturity is an implementation/parity statement, not a public support or
live-validation claim. All 14 registered identities have synthetic
parser/parity fixture coverage, including the project-local candidates. Twelve
identities are modeled source parsers. RooCode and KiloCode deliberately use
the exact generic JSON-document fallback because their verified UI-message
document shape is currently identical; they remain explicit fallbacks rather
than implicit format dispatch.

| Client | Exact source identity | Parser maturity | Parser/parity fixtures | Matrix support status |
| --- | --- | --- | --- | --- |
| Codex | `codex.sessions` | Modeled | ✅ | Supported |
| Codex | `codex.archived_sessions` | Modeled | ✅ | Supported |
| Codex | `codex.headless_sessions` | Modeled | ✅ | Supported |
| Codex | `codex.project_sessions` | Modeled | ✅ | Candidate; project-local gates remain separate |
| Claude Code | `claude.projects` | Modeled | ✅ | Supported |
| Gemini CLI | `gemini.tmp` | Modeled | ✅ | Supported |
| OpenClaw | `openclaw.agents` | Modeled | ✅ | Supported |
| Qwen CLI | `qwen.projects` | Modeled | ✅ | Supported |
| RooCode | `roocode.tasks` | Exact generic JSON-document fallback | ✅ | Supported |
| KiloCode | `kilocode.tasks` | Exact generic JSON-document fallback | ✅ | Supported |
| OpenCode | `opencode.sqlite` | Modeled | ✅ | Supported |
| OpenCode | `opencode.legacy_json` | Modeled | ✅ | Supported |
| OpenCode | `opencode.project_json` | Modeled | ✅ | Candidate; project-local gates remain separate |
| Copilot | `copilot.process_log` | Modeled | ✅ | Supported |

The matrix status above remains governed by the coverage gates below. A parser
being modeled does not by itself establish live host validation, and a complete
project-local parser fixture does not promote a candidate to Supported.

## Validation Matrix

| Client | Source Identity | Discovery | Parse Benign | Parse Tool Call | Parse Tool Result | UC-001 | UC-002 | UC-003 | Support Status / Live Validation | Known Lossy Fields |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Codex | `codex.sessions` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ Fixture-backed + bounded live validation | `call_id`, `is_error`, `content_parts` unavailable via legacy flat record |
| Codex | `codex.archived_sessions` | ✅ | ✅ | ✅ | ✅ | ✅ | — | — | ✅ Fixture-backed + bounded live validation | Same as `codex.sessions` |
| Codex | `codex.headless_sessions` | ✅ | ✅ | ✅ | ✅ | ✅ | — | — | ✅ Fixture-backed + bounded live validation | Same as `codex.sessions` |
| Claude Code | `claude.projects` | ✅ | ✅ | ✅ | ✅ | ✅ | — | — | ✅ Fixture-backed + bounded live validation | `call_id`, `is_error`, `content_parts` unavailable via legacy flat record |
| Gemini CLI | `gemini.tmp` | ✅ | ✅ | ✅ | ✅ | ✅ | — | — | ✅ Fixture-backed only | `call_id`, `is_error`, `content_parts` unavailable via legacy flat record |
| OpenClaw | `openclaw.agents` | ✅ | ✅ | ✅ | ✅ | ✅ | — | — | ✅ Fixture-backed only | `call_id`, `is_error`, `content_parts` unavailable via legacy flat record |
| Qwen CLI | `qwen.projects` | ✅ | ✅ | ✅ | ✅ | ✅ | — | — | ✅ Fixture-backed only | `call_id`, `is_error`, `content_parts` unavailable via legacy flat record |
| RooCode | `roocode.tasks` | ✅ | ✅ | ✅ | ✅ | ✅ | — | — | ✅ Fixture-backed only | `call_id`, `is_error`, `content_parts` unavailable via legacy flat record |
| KiloCode | `kilocode.tasks` | ✅ | ✅ | ✅ | ✅ | ✅ | — | — | ✅ Fixture-backed only | `call_id`, `is_error`, `content_parts` unavailable via legacy flat record |
| OpenCode | `opencode.sqlite` | ✅ | ✅ | ✅ | ✅ | ✅ | — | — | ✅ Fixture-backed + bounded live validation | `call_id`, `is_error`, workspace, `content_parts` unavailable via legacy flat record |
| OpenCode | `opencode.legacy_json` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | — | ✅ Fixture-backed + bounded live validation | Same as `opencode.sqlite` |
| Copilot | `copilot.process_log` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | — | ✅ Fixture-backed + bounded live validation | Process logs are lossy; user intent, `call_id`, `is_error`, workspace, `content_parts` unavailable |

## Coverage Gates

Every new agent source must pass these required gates before being marked supported in this matrix or advertised as supported in user-facing docs:

1. **Discovery**: fixture-backed source discovery finds the expected files.
2. **Benign parse**: at least one benign fixture parses without errors.
3. **Tool-call parse**: at least one fixture containing tool calls parses correctly.
4. **Tool-result parse**: at least one fixture containing tool results parses correctly.
5. **Positive detection**: at least one source fixture fires a deterministic detection rule. Every new `ClientId` must include UC-001 coverage; the repository test `uc001_critical_fixture_coverage_includes_every_supported_client` enforces this cross-client conformance gate.
6. **Negative detection**: at least one negative or benign fixture for the source stays quiet under the bundled rules.
7. **Capability documentation**: known lossy, absent, or derived fields are recorded here and in [Agent Capability Profiles](agent-capability-profiles.md) when the source becomes user-visible.

Live host validation is an additional operational confidence signal, not a
support gate. Record it when safe and available, but do not scan large or
sensitive real session stores just to satisfy fixture coverage.

Windows discovery coverage includes deterministic Codex `CodexHome` and VS Code
`globalStorage` tests for RooCode and KiloCode. These paths are not live-validated
and are not by themselves public live-source support; see [Session Sources](session-sources.md).

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
parser health so validation remains deterministic and small enough to summarize
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
3. A source-owned parser module for a new modeled client, or an update to the
   existing client parser for another modeled identity.
4. For a new client, an import and `ClientDef` entry in
   `sources/registry.rs`, preserving public client/install order.
5. For a new client, a per-client `AgentInstallDef`/`INSTALL` definition,
   including empty signal lists when appropriate, plus the matching
   `INSTALL_DEFS` entry.
6. One exact private parser registration per identity in `src/parser.rs`.
7. Neutral shared reader use only; do not add a parser field to public
   `ClientSourceDef` or a public parser extension API.
8. Synthetic fixtures under the registered fixture-relative path, mirrored
   under a crate `tests/fixtures` boundary when packaged tests reference them.
9. Registry/integrity, positive/benign, drift/unknown/failure/no-fallback,
   source/event ordering, portable discovery/path tests, and updated hard-coded
   registry, parser-maturity, and client-count snapshots.
10. Support/capability documentation, focused/full/package validation, and
    Linux, Windows, and macOS CI coverage.

Use portable `Path`/`PathBuf` joins and platform-aware root helpers. Do not rely
on exact separators, Unix permissions, symlinks, `/tmp`, or verbatim Windows
path prefixes. Do not introduce traits, plugin ABI, dynamic/runtime
registration, or external parser configuration.

## Use-Case Coverage Summary

| Use Case | Description | Clients Covered | Status |
| --- | --- | --- | --- |
| UC-001 | Fake MCP prompt injection to controlled domain | All 9 clients (12 matrixed source identities) | ✅ Complete |
| UC-002 | Credential harvesting before package publish | Codex, OpenCode (legacy_json), Copilot | ✅ 3 clients |
| UC-003 | DNS exfiltration with encoded payload | Codex | ✅ 1 client |

## Live Validation Status

Codex, OpenCode, Claude Code, and Copilot have received bounded live validation:

- **Codex**: `~/.codex/sessions/`, `archived_sessions/`, and `headless/` (complete)
- **OpenCode**: Linux `$XDG_DATA_HOME/opencode/opencode.db` or `~/.local/share/opencode/opencode.db`, plus `storage/message/` below the same root (complete)
- **Copilot**: `logs/copilot/process-*.log` (complete)
- **Claude Code**: `~/.claude/projects/` (complete) — bounded `--client claude --max-sources 5 --dry-run` parsed 5 sources with 5 activities and 1 benign detection, zero scanner errors; repeated at cap 10 with consistent results.

Future live-validation notes should record the client filter and source cap
used, for example `--client codex --max-sources 5 --dry-run`, rather than exact
local source paths or transcript identifiers.

## Related Documents

- [Adding an Agent Source](adding-agent-source.md) — implementation checklist and exact parser-registration architecture
- [Source Adapter Architecture](source-adapter-refactor-plan.md) — implemented architecture and migration record
- [Agent Capability Profiles](agent-capability-profiles.md) — per-source field availability and known gaps
- [Client Capability Matrix](client-capability-matrix.md) — field-level availability per client
- [Normalization Schema](normalization-schema.md) — `NormalizedRecordV1` contract
- [Detection Content Standard](detection-content-standard.md) — rule metadata and fixture expectations
- [Session Sources](session-sources.md) — path patterns and parser notes
- [Use Cases](use-cases.md) — UC-001, UC-002, UC-003 definitions
