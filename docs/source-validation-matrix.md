# Source Validation Matrix

This matrix is the canonical public record for source-support claims. It tracks
the eight registered source identities across discovery, native extraction,
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
fixtures characterize the implemented formats, not current-format compatibility
or broad live-host validation. OpenClaw and Qwen report ToolCall and UserContext
**Supported**, ToolExecution **Unknown**;
Copilot reports ToolCall **Supported**, UserContext **Unsupported**, and
ToolExecution **Unknown**.

## Validation Matrix

| Client | Source Identity | Discovery | Native + canonical benign | Canonical tool call | Canonical tool result | UC-001 | UC-002 | UC-003 | Support Status / Live Validation | Capability gaps |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Codex | `codex.sessions` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ Fixture-backed + bounded live validation | Workspace conditional; process ID absent; exit code only on completed commands; call ID/error state/parts conditional; bounded completed FileChange patch/result visibility is synthetic-conformance tested, not live-qualified |
| Codex | `codex.archived_sessions` | ✅ | ✅ | ✅ | ✅ | ✅ | — | — | ✅ Fixture-backed + bounded live validation | Same as `codex.sessions` |
| Codex | `codex.headless_sessions` | ✅ | ✅ | ✅ | ✅ | ✅ | — | — | ✅ Fixture-backed + bounded live validation | Same as `codex.sessions` |
| Claude Code | `claude.projects` | ✅ | ✅ | ✅ | ✅ | ✅ | — | — | ✅ Fixture-backed + bounded live validation | Workspace, process ID and exit code absent; timestamps and call ID/error state/parts conditional |
| OpenClaw | `openclaw.agents` | ✅ | ✅ | ✅ | ✅ | ✅ | — | — | ⚠️ Existing JSONL fixtures only; default SQLite-store compatibility deferred beyond 0.7 | Current runtime transcripts not discovered; workspace, process ID and exit code absent; ToolExecution unknown |
| Qwen CLI | `qwen.projects` | ✅ | ✅ | ✅ | ✅ | ✅ | — | — | ⚠️ Existing fixtures only; current-format compatibility deferred beyond 0.7 | Known v0.25.1 text/tool/system gaps; workspace, process ID and exit code absent; ToolExecution unknown |
| OpenCode | `opencode.sqlite` | ✅ | ✅ | ✅ | ✅ | ✅ | — | — | ✅ Fixture-backed + bounded live validation (legacy schema); bounded v2.0.28 shell-stage acquisition live-validated; v2 routine drain and full `--history all` pass live-validated after the request-side contribution fix, with oversized rows quarantined | Workspace conditional; process ID absent; exit code only for v2 shell commands and settled v2 `shell` tool calls; v2 tool-entry ToolExecution stays Unknown even when `executed: true` or a settled `shell` tool call emits an execution stage; v2 user shell commands report Supported; call ID/error state/parts conditional |
| Copilot | `copilot.process_log` | ✅ project-local; ⚠️ CLI home | ✅ existing format | ✅ | ✅ | ⚠️ | ✅ | — | ✅ Existing-format fixtures + historical bounded project-local live validation; v1.0.96 default logs unqualified | Home/COPILOT_HOME discovery blocked on current default-level format evidence; events.jsonl and session-store.db not acquired; UC-001 capability-indeterminate: UserContext unsupported; content parts absent; tool results conditional; ToolExecution unknown |

### OpenClaw compatibility boundary

The OpenClaw row describes existing synthetic JSONL adapter/conformance coverage,
not compatibility with current default stores. At the pinned v2026.10.2 revision,
runtime transcripts are stored in `agents/<agentId>/agent/openclaw-agent.sqlite`;
JSONL is the older migration source. Telltale discovers JSONL under
`~/.openclaw/agents` but does not discover that SQLite store. The
[SQLite-store case](../tests/upstream_formats/cases/openclaw/agent-sqlite-store.json)
remains `known_gap` (`selected_sources: 0`), not a passing support claim.

Default SQLite-store acquisition and live-store qualification are deferred
beyond 0.7 under the 0.7 release scope decision.
The `openclaw.agents` adapter remains registered with its existing fixture
checks. Current default-store and live OpenClaw use are unqualified; this
deferral neither retires the identity nor changes other sources' gates.

### Qwen Code compatibility boundary

The Qwen row's fixture checks describe existing synthetic adapter/conformance
coverage, not compatibility with current Qwen Code releases. At the pinned
v0.25.1 revision, the [plain-turn case](../tests/upstream_formats/cases/qwen/text-turn.json)
loses both messages' text; the [function-call/response case](../tests/upstream_formats/cases/qwen/function-call-parts.json)
and [system-record case](../tests/upstream_formats/cases/qwen/system-record.json)
reject acquisition. Those cases remain `known_gap`, not passing support claims.

Current-format repair and live-store qualification are deferred beyond 0.7 under
the 0.7 release scope decision.
The adapter remains registered and its existing conformance checks remain
required. Qwen live-store use is unqualified/experimental; no current-format
compatibility claim is made. This deferral does not retire the identity or change
other sources' coverage gates.

## Coverage Gates

Every new agent source must pass these required gates before being marked supported in this matrix or advertised as supported in user-facing docs:

1. **Discovery**: fixture-backed source discovery finds the expected files.
2. **Native extraction and canonical acquisition**: a benign fixture is extracted and acquired without errors, with native accounting and progress checked.
3. **Canonical tool call**: a tool-call fixture maps to the expected canonical observation.
4. **Canonical tool result**: a tool-result fixture maps to the expected canonical observation.
5. **Adapter conformance and detection**: fixture-backed canonical adapter coverage and Detection v2/evaluation coverage establish the exact `(ClientId, source_id, kind)`, facts, and deterministic signals. Every new source identity must include a UC-001 attack fixture with positive detection, or an explicit contract-backed capability gap that proves attack content survived acquisition and the expected indeterminate non-detection. A missing or empty fixture is not a visibility gap. `uc001_fixture_conformance_covers_every_supported_source_identity` in `tests/evaluation_corpus/main.rs` enforces all eight identities; run `cargo test --locked --test evaluation_corpus uc001_`.
6. **Negative detection**: at least one genuinely observed benign source fixture has no UC-001 matches. Other benign signals, such as `execution.shell`, may remain; absence of UC-001 matches under unsupported capabilities is not an efficacy true negative.
7. **Capability documentation**: known lossy, absent, or derived fields are recorded here and in [Agent Capability Profiles](agent-capability-profiles.md) when the source becomes user-visible.

Live host validation is an additional operational confidence signal, not a
support gate. Record it when safe and available, but do not scan large or
sensitive real session stores just to satisfy fixture coverage.

The UC-001 gate proves critical MCP injection plus controlled-domain egress in
one session for seven identities (five client families). Copilot's attack tool
result is preserved, but both atomic rules require UserContext, which its
adapter reports Unsupported. Both detectors are capability-indeterminate with
`required_capability_unsupported`; the chain cannot fire and evaluation is
VisibilityLimited. This is a tested visibility gap, not positive coverage or a
benign outcome. The same gate acquires and evaluates benign inputs for all
eight identities. `uc002_copilot_credential_publish_fixture_is_critical` in the
same module separately proves Copilot's credential-harvest/publish chain.
These are synthetic conformance checks, not new efficacy samples, historical
source parity, or live client-generated store qualification.

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

A new source needs registry wiring, exact-identity acquisition, portable
fixtures, tests, and package/platform validation. Keep the source experimental
until those artifacts and the coverage gates above exist in the same change.

## Use-Case Coverage Summary

| Use Case | Description | Clients Covered | Status |
| --- | --- | --- | --- |
| UC-001 | Fake MCP prompt injection to controlled domain | Positive: 5/6 client families, 7/8 source identities; conformance: all 8 identities | ⚠️ Copilot capability-indeterminate visibility gap |
| UC-002 | Credential harvesting before package publish | Codex, Copilot | ✅ 2 clients |
| UC-003 | DNS exfiltration with encoded payload | Codex | ✅ 1 client |

## Live Validation Status

Codex, OpenCode, Claude Code, and Copilot have received bounded live validation:

- **Codex**: `~/.codex/sessions/`, `archived_sessions/`, and `headless/` (complete)
  On 2026-10-14 a Windows 11 host had every Codex rollout fail acquisition:
  forked threads' `history_base`, new bookkeeping records, completed items the
  adapter did not know, and long tool output each failed the whole file. After
  the fix, a `--client codex --dry-run` re-validation parsed 25 of 26 sources
  (4,306 records; 440 units quarantined by themselves). The one remaining
  source is acquired but exceeds the per-source evaluation work budget.
- **OpenCode**: Linux `$XDG_DATA_HOME/opencode/opencode.db` or `~/.local/share/opencode/opencode.db` (complete)
- **Copilot**: historical bounded validation of project-local
  `logs/copilot/process-*.log`, not qualification of current Copilot CLI defaults.
  The current v1.0.101 pin's home logs and `COPILOT_HOME` remain known gaps, as in
  the historical v1.0.96 assessment: public upstream evidence
  establishes the paths but not the adapter-required records at default logging.
  See the [qualification evidence and unblock criteria](session-sources.md#copilot-cli-qualification-gap).
- **Claude Code**: `~/.claude/projects/` (complete) — bounded `--client claude --max-sources 5 --dry-run` parsed 5 sources with 5 activities and 1 benign detection, zero scanner errors; repeated at cap 10 with consistent results.
  On 2026-10-14 a Windows 11 audit found that Claude Code 2.1.x transcripts
  (CLI and desktop Code tab) no longer parsed: bookkeeping records, `thinking`
  blocks and nested or large tool inputs each failed the whole file. After the
  fix, a Windows `--client claude` re-validation parsed the session with
  complete coverage and no scanner errors.

Future live-validation notes should record the client filter and source cap
used, for example `--client codex --max-sources 5 --dry-run`, rather than exact
local source paths or transcript identifiers.

## Related Documents

- [Agent Capability Profiles](agent-capability-profiles.md) — per-source field availability and known gaps
- [Detection Content Standard](detection-content-standard.md) — rule metadata and fixture expectations
- [Session Sources](session-sources.md) — path patterns and discovery notes
