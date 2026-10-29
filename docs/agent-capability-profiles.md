# Agent Capability Profiles

This document records what each supported source can expose from its raw store.
Detection and analyst review must not assume every source has the same visibility.

Legend: **Full** is reliably present and extracted, **Partial** is conditional,
**Absent** is not present, and **Lossy** exists upstream but canonical mapping
does not preserve it as a structured fact.

## Supported sources

### Codex

Sources: `codex.sessions`, `codex.archived_sessions`,
`codex.headless_sessions` (JSONL).

| Capability | Status | Notes |
| --- | --- | --- |
| User and assistant messages | Full | Role and event-message records are parsed. |
| Tool calls and results | Full | Tool names, arguments, and result content are parsed. |
| Model, provider, agent | Full | Inherited from session metadata when needed. |
| Workspace | Partial | Present in some session metadata. |
| Timestamp and session ID | Full | Source-reported values only. A missing session id fails closed. |
| Process ID and exit code | Partial | Process ID is absent. A completed command preserves `exit_code` as `tool.exit_code`. |
| Call ID, error state, content parts | Partial | Preserved when the source reports them. Missing IDs are not fabricated. |
| Completed file changes | Partial | Exact `item_completed` / `FileChange` maps to one reported Tool result: structured add/delete content, update diff/move path, optional terminal status and diagnostic fields. Field-labeled result text is searchable; no filesystem execution or file state is inferred. Existing structured and search bounds apply. |

The Canonical Observation v2 adapter covers all three
registered Codex identities. It does not use filename/path fallback for v2
identity.

### Claude Code

Source: `claude.projects` (JSONL).

| Capability | Status | Notes |
| --- | --- | --- |
| User and assistant messages | Full | Mixed `message.content` blocks are parsed. |
| Tool calls and results | Full | `tool_use` and `tool_result` blocks are parsed. |
| Model | Full | Preserved from source records. |
| Provider and agent | Partial | Not always source-reported. |
| Workspace | Absent | Not available in this source contract. |
| Timestamp | Partial | Not guaranteed on every entry. |
| Session ID | Full | Source-reported value only. A missing session id is replay unverifiable. |
| Process ID and exit code | Absent | Not reported. |
| Call ID, error state, content parts | Partial | Preserved when the source reports them. Missing IDs are not fabricated. |

### OpenClaw

Source: `openclaw.agents` (existing JSONL fixtures, including archived/reset
suffixes). This profile does not describe the current default SQLite store,
which is not discovered or qualified; see the [OpenClaw compatibility
boundary](source-validation-matrix.md#openclaw-compatibility-boundary).

| Capability | Status | Notes |
| --- | --- | --- |
| User and assistant messages | Full | Role-based records are parsed. |
| Tool calls and results | Full | Tool names, arguments, and result content are parsed. |
| Model, provider, agent | Full | Preserved when reported; the agent has a source-specific default. |
| Workspace | Absent | Not available. |
| Timestamp | Partial | Present on some records. |
| Session ID | Full | Source-reported value only. A missing session id is replay unverifiable. |
| Process ID and exit code | Absent | Not reported. |
| Call ID, error state, content parts | Partial | Preserved when the source reports them. Missing IDs are not fabricated. |

The canonical adapter reports ToolCall and UserContext **Supported**
and ToolExecution **Unknown**.

### Qwen CLI

Source: `qwen.projects` (JSONL).

| Capability | Status | Notes |
| --- | --- | --- |
| User and assistant messages | Full | Role-based records are parsed. |
| Tool calls and results | Full | Tool names, arguments, and result content are parsed. |
| Model, provider, agent | Full | Preserved when reported. |
| Workspace | Absent | Not available. |
| Timestamp | Partial | Present on some records. |
| Session ID | Full | Source-reported value only. A missing session id is replay unverifiable. |
| Process ID and exit code | Absent | Not reported. |
| Call ID, error state, content parts | Partial | Preserved when the source reports them. Missing IDs are not fabricated. |

The canonical adapter reports ToolCall and UserContext **Supported**
and ToolExecution **Unknown**.

### OpenCode

Source: `opencode.sqlite`.

| Capability | Status | Notes |
| --- | --- | --- |
| User and assistant messages | Full | Legacy message and part data, or OpenCode v2 `session_message` user text and assistant text entries. Reasoning is not retained. |
| Tool calls and results | Full | Legacy tool parts keep their direct lifecycle. v2 tool entries emit a request and, when terminal, a returned result; long authored text (commands, patches, file bodies, prompts) keeps a 64 KB budget, and v2 file tools report their `path`. Rows still over a bound are quarantined and reported by coordinates. |
| Model, provider, agent | Full | Preserved from source JSON and, for v2, the session row. |
| Workspace | Partial | Preserved only when the SQLite row reports it. |
| Timestamp and session ID | Full | SQLite rows provide source timing and session context. |
| Process ID and exit code | Partial | PID is never reported. Exit code is reported only for v2 user shell (`!`) commands and settled v2 agent `shell` tool calls. |
| Tool execution | Partial | Legacy `running`/terminal parts report execution. v2 tool entries claim execution when `executed: true` or when a completed agent `shell` tool reports how its command settled; other local tools stay Unknown. v2 shell commands report it. |
| Call ID, error state, content parts | Partial | Reported call IDs and error states are preserved. |

The `opencode.sqlite` canonical adapter feeds the production Detection v2 source
runtime. Caller-supplied record evaluation was removed; use the
[embedding surface](embedding.md) for source scans.

### GitHub Copilot

Source: `copilot.process_log`.

The capabilities below describe the existing accumulated-output process-log
adapter, not every current Copilot CLI log. The current v1.0.101 pin's default-level
record format remains unqualified; the historical v1.0.96 runtime assessment does
not qualify it. Home and `COPILOT_HOME` discovery remain disabled and their
upstream cases remain known gaps. `events.jsonl` and `session-store.db` are not
acquired. See [qualification evidence](session-sources.md#copilot-cli-qualification-gap).

| Capability | Status | Notes |
| --- | --- | --- |
| User and assistant messages | Lossy | Process logs do not contain full conversation context. |
| Tool calls | Full | Function-call arrays provide name, arguments, and optional call ID. |
| Tool results | Partial | Present only on some function-call records. |
| Model and provider | Partial | Not populated on every record. |
| Agent | Full | The adapter identifies Copilot. |
| Workspace | Partial | Workspace initialization records provide a UUID. |
| Timestamp | Partial | Leading RFC3339 timestamps are preserved when present. |
| Session ID | Full | Derived from workspace initialization. |
| Process ID | Partial | May be present in the filename but is not extracted. |
| Exit code and error state | Absent | Not reported. |
| Call ID | Full | Preserved when reported. |
| Content parts | Absent | Not present in process logs. |

The canonical adapter reports ToolCall **Supported**, UserContext
**Unsupported**, and ToolExecution **Unknown**.

## Cross-source implications

- Copilot detections cannot rely on user-context matching.
- Model/provider attribution is weaker for Copilot and Claude Code.
- Workspace correlation is available only from some Codex and Copilot records.
- Error-based detection remains limited by each source's canonical evidence.
- Call-ID availability remains source-dependent; missing IDs are not fabricated.

## Related documents

- [Source Validation Matrix](source-validation-matrix.md)
- [Session Sources](session-sources.md)
