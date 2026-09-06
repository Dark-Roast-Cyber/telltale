# Agent Capability Profiles

This document tracks what each validated agent source can expose from its raw logs. Detection and analyst review context should reference these profiles instead of assuming every source has the same visibility into user intent, tool calls, model metadata, and session context.

## Why This Matters

Telltale's detection engine operates on normalized records, but the quality of those records depends on what the source logs actually contain. A rule that matches on `user_context` is only useful when the source preserves user messages. An analyst review that asks "what did the user request?" can only answer when user intent is available in the log.

These profiles document the gap between what Telltale would ideally see and what each source actually provides.

## Legend

- **Full**: field is reliably present in the source format and Telltale extracts it.
- **Partial**: field is sometimes present or extracted with caveats (see notes).
- **Absent**: field is not available in the source format.
- **Lossy**: field exists in the live agent but is not preserved in the log format Telltale reads.

## Capability Profiles

### Codex

**Source kinds**: `codex.sessions`, `codex.archived_sessions`, `codex.headless_sessions`
**Format**: JSONL (one JSON object per line)
**Store location**: `~/.codex/sessions/`, `archived_sessions/`, `headless/`

| Capability | Status | Notes |
| --- | --- | --- |
| User messages | Full | JSONL entries with `type: user_message` or role-based detection. |
| Assistant messages | Full | JSONL entries with `type: assistant_message`. |
| Tool calls | Full | JSONL entries with `type: tool_call`, `tool_name`, and `arguments`. |
| Tool results | Full | JSONL entries with `type: tool_result` and content. |
| Model | Full | `model` or `model_name` field on session or record. |
| Provider | Full | `model_provider` field on session meta. |
| Agent | Full | `agent_nickname` or `agent` field. |
| Workspace | Partial | Available in session meta for some session types; not on every record. |
| Timestamps | Full | `timestamp` field on each JSONL entry. |
| Session ID | Full | File stem or `session_id`/`sessionID` field. |
| Process ID | Absent | Not recorded in JSONL session format. |
| Exit code | Absent | Not recorded in JSONL session format. |
| Call ID | Lossy | `call_id` exists in live tool calls but is not preserved through the legacy flat record. |
| Is error | Lossy | Tool result error state is not preserved through the legacy flat record. |
| Content parts | Lossy | Structured content arrays are flattened to text in legacy conversion. |

**Known gaps**: Headless sessions marked by `session_meta.payload.source == "exec"`. Archived sessions use the same format but in a separate directory.

The implemented Codex Canonical Observation v2 reference adapter family covers
the four registered identities (`codex.sessions`, `codex.archived_sessions`,
`codex.headless_sessions`, and `codex.project_sessions`). Production still uses
the lossy legacy projection; filename/path session fallback is legacy-only and
is not used for v2 session identity. `codex.project_sessions` remains a
candidate source, and this mapping does not upgrade its support status.

---

### Claude Code

**Source kinds**: `claude.projects`
**Format**: JSONL (one JSON object per line)
**Store location**: Linux/macOS candidate `~/.claude/projects/`

| Capability | Status | Notes |
| --- | --- | --- |
| User messages | Full | Entries with `type: user` or `message.role: user`. |
| Assistant messages | Full | Entries with `type: assistant` or `message.role: assistant`. |
| Tool calls | Full | Content blocks with `type: tool_use` containing `name` and `input`. |
| Tool results | Full | Content blocks with `type: tool_result` containing result content. |
| Model | Full | `model` field or `message.model`. |
| Provider | Partial | Not always present in source; Telltale derives when possible. |
| Agent | Partial | Not always explicitly labeled; defaults to client name. |
| Workspace | Absent | Not available in the JSONL format. |
| Timestamps | Partial | May be present on individual entries; not guaranteed. |
| Session ID | Full | File stem or `session_id` field. |
| Process ID | Absent | Not recorded. |
| Exit code | Absent | Not recorded. |
| Call ID | Lossy | Exists in live tool calls but not preserved through legacy conversion. |
| Is error | Lossy | Not preserved through legacy conversion. |
| Content parts | Lossy | Structured content arrays are flattened. |

**Known gaps**: Claude Code JSONL uses `message.content` arrays with mixed block types (`text`, `tool_use`, `tool_result`). The parser handles these but the legacy flat record cannot preserve the structure.

The implemented Claude Code (`claude.projects`) Canonical Observation v2
reference projection preserves call IDs, explicit `is_error`, and ordered
content parts. Production still uses the lossy legacy projection; filename
session fallback is legacy-only and is not used for v2 session identity.

---

### Gemini CLI

**Source kinds**: `gemini.tmp`
**Format**: JSON (single JSON object per file with `messages` array)
**Store location**: Linux/macOS candidate `~/.gemini/tmp/`

| Capability | Status | Notes |
| --- | --- | --- |
| User messages | Full | `type: user` entries in the `messages` array. |
| Assistant messages | Full | `type: gemini` or `type: model` entries. |
| Tool calls | Full | Tool call entries with `name` and `arguments`. |
| Tool results | Full | Tool result entries with content. |
| Model | Full | `model` field at file or message level. |
| Provider | Full | Hardcoded `google` in parser; source may not explicitly state it. |
| Agent | Full | Hardcoded `gemini` in parser. |
| Workspace | Absent | Not available in the JSON format. |
| Timestamps | Partial | `timestamp` on messages, `lastUpdated` or `startTime` at file level. |
| Session ID | Full | `sessionId` at file level, or file stem as fallback. |
| Process ID | Absent | Not recorded. |
| Exit code | Absent | Not recorded. |
| Call ID | Lossy | Not preserved through legacy conversion. |
| Is error | Lossy | Not preserved through legacy conversion. |
| Content parts | Lossy | Flattened to text. |

**Known gaps**: `call_id`, `is_error`, and structured content parts are lossy through the legacy flat record.

---

### OpenClaw

**Source kinds**: `openclaw.agents`
**Format**: JSONL (including `.jsonl.deleted`, `.jsonl.archived`, `.jsonl.reset` suffixes)
**Store location**: Linux/macOS candidate `~/.openclaw/agents/` (still needs stronger upstream confirmation)

| Capability | Status | Notes |
| --- | --- | --- |
| User messages | Full | Entries with `role: user` or `type: user`. |
| Assistant messages | Full | Entries with `role: assistant` or `type: assistant`. |
| Tool calls | Full | Tool call entries with `tool_name` and `arguments`. |
| Tool results | Full | Tool result entries with content. |
| Model | Full | `model` field on records. |
| Provider | Full | `provider` field on records. |
| Agent | Full | `agent` field on records. |
| Workspace | Absent | Not available. |
| Timestamps | Partial | May be present on individual entries. |
| Session ID | Full | `session_id` or `sessionId` field, or file stem. |
| Process ID | Absent | Not recorded. |
| Exit code | Absent | Not recorded. |
| Call ID | Lossy | Not preserved through legacy conversion. |
| Is error | Lossy | Not preserved through legacy conversion. |
| Content parts | Lossy | Flattened to text. |

**Known gaps**: OpenClaw uses non-standard file suffixes (`.jsonl.deleted`, `.jsonl.archived`, `.jsonl.reset`). The discovery layer handles these via `FileNameContains(".jsonl")`.

---

### Qwen CLI

**Source kinds**: `qwen.projects`
**Format**: JSONL
**Store location**: Linux/macOS candidate `~/.qwen/projects/` (still needs stronger upstream confirmation)

| Capability | Status | Notes |
| --- | --- | --- |
| User messages | Full | Entries with `type: user` or `role: user`. |
| Assistant messages | Full | Entries with `type: assistant` or `role: assistant`. |
| Tool calls | Full | Tool call entries with tool name and arguments. |
| Tool results | Full | Tool result entries with content. |
| Model | Full | `model` field on records (e.g., `qwen3-coder-plus`). |
| Provider | Full | `provider` field on records. |
| Agent | Full | `agent` field, defaults to `qwen`. |
| Workspace | Absent | Not available. |
| Timestamps | Partial | `timestamp` field when present. |
| Session ID | Full | `session_id`/`sessionId` field or file stem. |
| Process ID | Absent | Not recorded. |
| Exit code | Absent | Not recorded. |
| Call ID | Lossy | Not preserved through legacy conversion. |
| Is error | Lossy | Not preserved through legacy conversion. |
| Content parts | Lossy | Flattened to text. |

**Known gaps**: Qwen JSONL may also include `usageMetadata` fields that Telltale does not currently extract.

---

### Canonical Observation v2 reference coverage

The `openclaw.agents` and `qwen.projects` Canonical Observation v2 reference
adapters are implemented as non-production projections. Their capability context
marks `ToolCall` and `UserContext` as **Supported** and `ToolExecution` as
**Unknown**; JSONL tool requests and results do not establish execution. The
Copilot `copilot.process_log` projection reports ToolCall **Supported**,
UserContext **Unsupported**, and ToolExecution **Unknown**. Offline
deterministic shadow coverage now covers 15 cases, 17 reviewed sessions, and 306
detector evaluations with five
reviewed match-set differences plus 28 reviewed capability-driven indeterminate
outcomes and zero unexplained differences. Production remains
on `NormalizedRecordV1` and Rule v1; this is not live shadow, production parity,
or an all-client migration.

---

### RooCode

**Source kinds**: `roocode.tasks`
**Format**: JSON (array of message objects in `ui_messages.json`)
**Store location**: Linux `~/.config/Code/User/globalStorage/rooveterinaryinc.roo-cline/tasks/`; macOS `~/Library/Application Support/Code/User/globalStorage/rooveterinaryinc.roo-cline/tasks/`

| Capability | Status | Notes |
| --- | --- | --- |
| User messages | Full | `say:user_feedback` and `say:user_feedback_diff` are mapped as user content. |
| Assistant messages | Full | `say:text`, completion/subtask results, and `ask:followup` are mapped as assistant content. |
| Tool calls | Partial | Explicit `ask:command`, structured `ask:tool`, and the pinned `ask:use_mcp_server` JSON request; completed arguments are stringified and partial snapshots preserve the object. |
| Tool results | Partial | Explicit command output and pinned `say:mcp_server_response` plain text only; no source tool name or execution outcome is inferred. |
| Model | Absent | The verified `ClineMessage` shape does not report a model. |
| Provider | Absent | The verified `ClineMessage` shape does not report a provider. |
| Agent | Absent | The client name is not copied into source-reported agent provenance. |
| Workspace | Absent | Not available. |
| Timestamps | Full | Required numeric epoch-millisecond `ts`, converted deterministically to UTC RFC3339. |
| Session ID | Partial | READY from a direct non-empty `history_item.json.id`; `_index.json` only corroborates it. Without valid history metadata, the parent directory is a compatibility grouping fallback only. |
| Process ID | Absent | Not recorded. |
| Exit code | Absent | Not recorded. |
| Call ID | Absent | No stable native call/message ID is proven by the verified shape. |
| Is error | Lossy | The legacy flat record does not preserve execution outcome. |
| Content parts | Lossy | Flattened to text. |

**Known gaps**: RooCode stores sessions as `ui_messages.json` files in VS Code extension task directories. The pinned `TaskHistoryStore` writes the direct `history_item.json` source of truth and a debounced `_index.json` cache. A valid direct history ID survives a renamed directory; malformed, empty, or conflicting metadata fails closed. The parent-directory value is a compatibility grouping key, not canonical identity. Array order, ordinal, timestamp, content, path, and tool payload values are not approved per-message identity. Protected assignment remains required for future canonical projection.

---

### KiloCode

**Source kinds**: `kilocode.tasks`
**Format**: Legacy-writer `ClineMessage[]` in `ui_messages.json`, read within
the current product's bounded migration-store layout.
**Store location**: Linux `~/.config/Code/User/globalStorage/kilocode.kilo-code/tasks/`; macOS `~/Library/Application Support/Code/User/globalStorage/kilocode.kilo-code/tasks/`

| Capability | Status | Notes |
| --- | --- | --- |
| User messages | Full | `say:user_feedback` and `say:user_feedback_diff` are mapped as user content. |
| Assistant messages | Full | `say:text`, completion/subtask results, and `ask:followup` are mapped as assistant content. |
| Tool calls | Partial | Explicit `ask:command`, structured `ask:tool`, and the independently pinned legacy `ask:use_mcp_server` request; completed arguments are stringified and partial snapshots preserve the object. |
| Tool results | Partial | Explicit command output and legacy `say:mcp_server_response` plain text only; no source tool name or execution outcome is inferred. |
| Model | Absent | The legacy `ClineMessage` shape does not report a model. |
| Provider | Absent | The legacy `ClineMessage` shape does not report a provider. |
| Agent | Absent | The client name is not copied into source-reported agent provenance. |
| Workspace | Absent | Not available. |
| Timestamps | Full | Required numeric epoch-millisecond `ts`, converted deterministically to UTC RFC3339. |
| Session ID | Partial | The legacy writer reports no session companion. The parent directory is a compatibility grouping fallback only; no source-reported namespace is READY. |
| Process ID | Absent | Not recorded. |
| Exit code | Absent | Not recorded. |
| Call ID | Absent | No stable native call/message ID is proven in the legacy migration UI store. |
| Is error | Lossy | The legacy flat record does not preserve execution outcome. |
| Content parts | Lossy | Flattened to text. |

**Known gaps**: This support is bounded to the legacy-writer
`ui_messages.json` anchor. The pinned writer does not write Roo's
`history_item.json` or `_index.json`; current Kilo's migration reader is not
source evidence for this adapter. `api_conversation_history.json` is a separate
alternate body and is never merged. Current Kilo SQLite/server/CLI data is
outside this source. No session namespace or per-message coordinate is approved:
the writer rewrites the whole array and no middle-delete stability proof exists.
Protected assignment remains required for future canonical projection.

---

### OpenCode

**Source kinds**: `opencode.sqlite`, `opencode.legacy_json`
**Format**: SQLite database + legacy JSON files
**Store location**: Linux `$XDG_DATA_HOME/opencode/...` or `~/.local/share/opencode/...`; macOS `~/Library/Application Support/opencode/...`

| Capability | Status | Notes |
| --- | --- | --- |
| User messages | Full | `role: user` in JSON payload or SQLite `data` column. |
| Assistant messages | Full | `role: assistant` in JSON payload. |
| Tool calls | Full | `type: tool_call` entries with tool name and arguments. |
| Tool results | Full | `type: tool_result` entries with content. |
| Model | Full | `modelID` or `model` field. |
| Provider | Full | `providerID` or `provider` field. |
| Agent | Full | `agent` field (e.g., `build`). |
| Workspace | Lossy | May exist in live OpenCode data but not preserved through legacy conversion. |
| Timestamps | Full | `time` or `timestamp` field. SQLite stores also have `session_id` column. |
| Session ID | Full | `session_id`/`sessionID`/`sessionId` field, or SQLite `session_id` column. |
| Process ID | Absent | Not recorded. |
| Exit code | Absent | Not recorded. |
| Call ID | Lossy | Not preserved through legacy conversion. |
| Is error | Lossy | Not preserved through legacy conversion. |
| Content parts | Lossy | Flattened to text. |

**Known gaps**: The SQLite source stores JSON in a `data` column which Telltale parses and merges with the row-level `session_id`. Legacy JSON files are one file per message.

The implemented `opencode.sqlite` Canonical Observation v2 reference projection
is non-production. `opencode.legacy_json` remains supported and its v2 migration
has not started; `opencode.project_json` remains Candidate and its v2 migration
has not started. Production remains `NormalizedRecordV1`; Canonical Observation
v2 cutover and production Detection v2 have not started. The experimental
Detection v2 foundation implements only `observation_match`,
`DetectorResult` -> `Signal` -> atomic `Finding`, and the Rule v1 compiler; the
fixture-only offline shadow harness is an offline measurement seam, not a
production shadow or activation path. Advanced detector runtime and Detection
Content v2 loader are not implemented. Event4 and telemetry/output v2 have not
started. The `compat.v1.url` view remains truthfully absent; focused synthetic
harness coverage demonstrates the compatibility gap.

---

### GitHub Copilot

**Source kinds**: `copilot.process_log`
**Format**: Process log (timestamped text lines with embedded JSON arrays)
**Store location**: `logs/copilot/process-*.log`

| Capability | Status | Notes |
| --- | --- | --- |
| User messages | Lossy | User prompts are not recorded in process logs. Only tool calls and workspace events are logged. |
| Assistant messages | Lossy | Assistant text responses are not directly logged. |
| Tool calls | Full | JSON arrays with `type: function_call`, `name`, `arguments`, and optional `call_id`. |
| Tool results | Partial | Extracted from `message` field on `function_call` entries when present. Not all tool calls have results. |
| Model | Partial | `model` or `modelID` field on function call entries when the provider includes it. |
| Provider | Partial | `provider` or `providerID` on function call entries; defaults to `github`. |
| Agent | Full | Hardcoded `copilot` in parser. |
| Workspace | Partial | Workspace UUID extracted from "Workspace initialized:" lines. |
| Timestamps | Partial | Extracted from a leading RFC3339 timestamp token when present. |
| Session ID | Full | Extracted from "Workspace initialized: <uuid>" lines. |
| Process ID | Partial | The log filename may contain a PID (e.g., `process-12345.log`), but Telltale does not currently extract it. |
| Exit code | Absent | Not recorded in process logs. |
| Call ID | Full | `call_id` field on function call entries. |
| Is error | Absent | Not recorded. |
| Content parts | Absent | Process logs do not contain structured content arrays. |

**Known gaps**: Copilot process logs are the most limited source. User intent is invisible — Telltale cannot tell what the user asked for. Only tool calls and workspace initialization events are logged. Model and provider fields are not always populated on every function call entry. Log lines without a leading RFC3339 timestamp token remain untimestamped.

The implemented `copilot.process_log` Canonical Observation v2 reference
projection is non-production. Its native capability context reports ToolCall
**Supported**, UserContext **Unsupported**, and ToolExecution **Unknown**.
Offline shadow coverage includes Copilot in 15 cases, 17 reviewed sessions, and
306 detector evaluations. The reviewed differences are five match-set
differences plus 28 capability-driven indeterminate outcomes, with zero
unexplained differences. Production remains `NormalizedRecordV1`; there is no
live shadow or Detection v2 production activation, and Event 3.0 is unchanged.

---

## Cross-Source Summary

| Capability | Codex | Claude | Gemini | OpenClaw | Qwen | RooCode | KiloCode | OpenCode | Copilot |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| User messages | Full | Full | Full | Full | Full | Full | Full | Full | **Lossy** |
| Assistant messages | Full | Full | Full | Full | Full | Full | Full | Full | **Lossy** |
| Tool calls | Full | Full | Full | Full | Full | **Partial** | **Partial** | Full | Full |
| Tool results | Full | Full | Full | Full | Full | **Partial** | **Partial** | Full | Partial |
| Model | Full | Full | Full | Full | Full | **Absent** | **Absent** | Full | Partial |
| Provider | Full | Partial | Full | Full | Full | **Absent** | **Absent** | Full | Partial |
| Agent | Full | Partial | Full | Full | Full | **Absent** | **Absent** | Full | Full |
| Workspace | Partial | Absent | Absent | Absent | Absent | Absent | Absent | Lossy | Partial |
| Timestamps | Full | Partial | Partial | Partial | Partial | **Full** | **Full** | Full | Partial |
| Session ID | Full | Full | Full | Full | Full | **Partial** | **Partial** | Full | Full |
| Process ID | Absent | Absent | Absent | Absent | Absent | Absent | Absent | Absent | Partial |
| Exit code | Absent | Absent | Absent | Absent | Absent | Absent | Absent | Absent | Absent |
| Call ID | Lossy | Lossy | Lossy | Lossy | Lossy | **Absent** | **Absent** | Lossy | Full |
| Is error | Lossy | Lossy | Lossy | Lossy | Lossy | Lossy | Lossy | Lossy | Absent |
| Content parts | Lossy | Lossy | Lossy | Lossy | Lossy | Lossy | Lossy | Lossy | Absent |

## Implications for Detection

- **User intent context**: Available for 8 of 9 sources; Copilot detections cannot rely on user-context matching. Rules targeting `user_context` will silently skip records without that evidence.
- **Model/provider attribution**: Weaker for Copilot, Claude, RooCode, and KiloCode. Cross-session correlation by model/provider is unreliable for these sources.
- **Workspace correlation**: Only Codex and Copilot provide workspace hints. Other sources require session-level grouping.
- **Error detection**: `is_error` is universally lossy through the legacy conversion. Error-based detection rules need a future schema upgrade to be effective.
- **Call ID linking**: Only Copilot preserves `call_id` natively. Tool-call/tool-result pairing for other sources relies on ordering and tool name matching.

## Implications for Analyst Review

- Review workflows should check source capabilities before relying on user intent.
- For Copilot sessions, review should note that user intent is unavailable and rely on tool-call patterns only.
- Model/provider fields should be marked as "unavailable" when the source cannot provide them.

## Related Documents

- [Client Capability Matrix](client-capability-matrix.md) — normalization-level field availability
- [Source Validation Matrix](source-validation-matrix.md) — fixture and detection coverage status
- [Normalization Schema](normalization-schema.md) — `NormalizedRecordV1` contract
- [Detection Model](detection-model.md) — detection engine behavior
- [Trust Boundaries](trust-boundaries.md) — untrusted content sources
- [Session Sources](session-sources.md) — path patterns and parser notes
