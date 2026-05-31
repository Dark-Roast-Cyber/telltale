# Source Validation Matrix

This matrix tracks each supported agent source across discovery, parsing, tool-call handling, tool-result handling, use-case coverage, live validation status, and known lossy fields. A source is only considered supported when the required coverage gates below have fixture-backed proof.

## Legend

- ✅ — fixture-backed proof exists and passes
- ⚠️ — partial coverage or known gaps
- ❌ — not yet validated
- N/A — not applicable for this source

## Validation Matrix

| Client | Source Kind | Discovery | Parse Benign | Parse Tool Call | Parse Tool Result | UC-001 | UC-002 | UC-003 | Live Validation | Known Lossy Fields |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Codex | `codex.sessions` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ R01 complete | `call_id`, `is_error`, `content_parts` unavailable via legacy flat record |
| Codex | `codex.archived_sessions` | ✅ | ✅ | ✅ | ✅ | ✅ | — | — | ✅ R01 complete | Same as `codex.sessions` |
| Codex | `codex.headless_sessions` | ✅ | ✅ | ✅ | ✅ | ✅ | — | — | ✅ R01 complete | Same as `codex.sessions` |
| Claude Code | `claude.projects` | ✅ | ✅ | ✅ | ✅ | ✅ | — | — | ❌ No live sessions | `call_id`, `is_error`, `content_parts` unavailable via legacy flat record |
| Gemini CLI | `gemini.tmp` | ✅ | ✅ | ✅ | ✅ | ✅ | — | — | ❌ Not installed | `call_id`, `is_error`, `content_parts` unavailable via legacy flat record |
| OpenClaw | `openclaw.agents` | ✅ | ✅ | ✅ | ✅ | ✅ | — | — | ❌ Not installed | `call_id`, `is_error`, `content_parts` unavailable via legacy flat record |
| Qwen CLI | `qwen.projects` | ✅ | ✅ | ✅ | ✅ | ✅ | — | — | ❌ Not installed | `call_id`, `is_error`, `content_parts` unavailable via legacy flat record |
| RooCode | `roocode.tasks` | ✅ | ✅ | ✅ | ✅ | ✅ | — | — | ❌ Not installed | `call_id`, `is_error`, `content_parts` unavailable via legacy flat record |
| KiloCode | `kilocode.tasks` | ✅ | ✅ | ✅ | ✅ | ✅ | — | — | ❌ Not installed | `call_id`, `is_error`, `content_parts` unavailable via legacy flat record |
| OpenCode | `opencode.sqlite` | ✅ | ✅ | ✅ | ✅ | ✅ | — | — | ✅ R02 complete | `call_id`, `is_error`, workspace, `content_parts` unavailable via legacy flat record |
| OpenCode | `opencode.legacy_json` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | — | ✅ R02 complete | Same as `opencode.sqlite` |
| Copilot | `copilot.process_log` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | — | ✅ R03 complete | Process logs are lossy; user intent, `call_id`, `is_error`, workspace, `content_parts` unavailable |

## Coverage Gates

Every new agent source must pass these required gates before being marked supported in this matrix or advertised as supported in user-facing docs:

1. **Discovery**: fixture-backed source discovery finds the expected files.
2. **Benign parse**: at least one benign fixture parses without errors.
3. **Tool-call parse**: at least one fixture containing tool calls parses correctly.
4. **Tool-result parse**: at least one fixture containing tool results parses correctly.
5. **Positive detection**: at least one source fixture fires a deterministic detection rule. UC-001 is preferred because it is the cross-client conformance use case, but another documented high-signal use case may satisfy this gate when UC-001 is not representative of the source.
6. **Negative detection**: at least one negative or benign fixture for the source stays quiet under the bundled rules.
7. **Capability documentation**: known lossy, absent, or derived fields are recorded here and in [Agent Capability Profiles](agent-capability-profiles.md) when the source becomes user-visible.

Live host validation is an additional operational confidence signal, not a
support gate. Record it when safe and available, but do not scan large or
sensitive real session stores just to satisfy fixture coverage.

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

When adding a source adapter, include these artifacts in the same change or keep the source marked experimental until they exist:

- a `ClientId` variant and `ClientSourceDef` path pattern;
- a parser branch that produces normalized records without source-specific detection logic;
- a fixture directory under `tests/fixtures/session_stores/<client>/` or another documented fixture root;
- focused discovery and parser tests for benign, tool-call, and tool-result records;
- a positive detection fixture and assertion proving bundled rules apply after normalization;
- a negative or benign fixture assertion proving normal source activity stays quiet;
- source capability and lossy-field notes in this matrix and related capability docs.

## Use-Case Coverage Summary

| Use Case | Description | Clients Covered | Status |
| --- | --- | --- | --- |
| UC-001 | Fake MCP prompt injection to controlled domain | All 9 clients (12 source kinds) | ✅ Complete |
| UC-002 | Credential harvesting before package publish | Codex, OpenCode (legacy_json), Copilot | ✅ 3 clients |
| UC-003 | DNS exfiltration with encoded payload | Codex | ✅ 1 client |

## Live Validation Status

Codex, OpenCode, and Copilot have received bounded live validation:

- **Codex** (R01): `~/.codex/sessions/`, `archived_sessions/`, `headless/` (complete)
- **OpenCode** (R02): Linux `$XDG_DATA_HOME/opencode/opencode.db` or `~/.local/share/opencode/opencode.db`, plus `storage/message/` below the same root (complete)
- **Copilot** (R03): `logs/copilot/process-*.log` (complete)

Future live-validation notes should record the client filter and source cap
used, for example `--client codex --max-sources 5 --dry-run`, rather than exact
local source paths or transcript identifiers.

## Related Documents

- [Agent Capability Profiles](agent-capability-profiles.md) — per-source field availability and known gaps
- [Client Capability Matrix](client-capability-matrix.md) — field-level availability per client
- [Normalization Schema](normalization-schema.md) — `NormalizedRecordV1` contract
- [Detection Content Standard](detection-content-standard.md) — rule metadata and fixture expectations
- [Session Sources](session-sources.md) — path patterns and parser notes
- [Use Cases](use-cases.md) — UC-001, UC-002, UC-003 definitions
