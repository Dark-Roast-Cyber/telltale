# Agent Capability Profiles

This document records what each supported source can expose from its raw store.
Detection and analyst review must not assume every source has the same visibility.

Legend: **Full** is reliably present and extracted, **Partial** is conditional,
**Absent** is not present, and **Lossy** exists upstream but is not preserved by
the current production `NormalizedRecordV1` path.

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
| Timestamp and session ID | Full | Source values are used; legacy parsing may use the file stem as a session fallback. |
| Process ID and exit code | Absent | Not reported by this store. |
| Call ID, error state, content parts | Lossy | Not preserved through the production legacy projection. |

The non-production Canonical Observation v2 reference projector covers all three
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
| Session ID | Full | Source value or legacy file-stem fallback. |
| Process ID and exit code | Absent | Not reported. |
| Call ID, error state, content parts | Lossy | The v2 reference projector preserves more structure than the production path. |

### OpenClaw

Source: `openclaw.agents` (JSONL, including archived/reset suffixes).

| Capability | Status | Notes |
| --- | --- | --- |
| User and assistant messages | Full | Role-based records are parsed. |
| Tool calls and results | Full | Tool names, arguments, and result content are parsed. |
| Model, provider, agent | Full | Preserved when reported; the agent has a source-specific default. |
| Workspace | Absent | Not available. |
| Timestamp | Partial | Present on some records. |
| Session ID | Full | Source value or legacy file-stem fallback. |
| Process ID and exit code | Absent | Not reported. |
| Call ID, error state, content parts | Lossy | Not preserved by the production legacy projection. |

The non-production v2 projector reports ToolCall and UserContext **Supported**
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
| Session ID | Full | Source value or legacy file-stem fallback. |
| Process ID and exit code | Absent | Not reported. |
| Call ID, error state, content parts | Lossy | Not preserved by the production legacy projection. |

The non-production v2 projector reports ToolCall and UserContext **Supported**
and ToolExecution **Unknown**.

### OpenCode

Source: `opencode.sqlite`.

| Capability | Status | Notes |
| --- | --- | --- |
| User and assistant messages | Full | Parsed from SQLite message and part data. |
| Tool calls and results | Full | Selected tool parts preserve their direct lifecycle facts. |
| Model, provider, agent | Full | Preserved from source JSON. |
| Workspace | Lossy | Not preserved through the production legacy projection. |
| Timestamp and session ID | Full | SQLite rows provide source timing and session context. |
| Process ID and exit code | Absent | Not reported. |
| Call ID, error state, content parts | Lossy | The v2 reference projector preserves more structure than the production path. |

The `opencode.sqlite` v2 projector is non-production. Production remains on
`NormalizedRecordV1`; no Detection v2 cutover is included in source convergence.

### GitHub Copilot

Source: `copilot.process_log`.

| Capability | Status | Notes |
| --- | --- | --- |
| User and assistant messages | Lossy | Process logs do not contain full conversation context. |
| Tool calls | Full | Function-call arrays provide name, arguments, and optional call ID. |
| Tool results | Partial | Present only on some function-call records. |
| Model and provider | Partial | Not populated on every record. |
| Agent | Full | The parser identifies Copilot. |
| Workspace | Partial | Workspace initialization records provide a UUID. |
| Timestamp | Partial | Leading RFC3339 timestamps are preserved when present. |
| Session ID | Full | Derived from workspace initialization. |
| Process ID | Partial | May be present in the filename but is not extracted. |
| Exit code and error state | Absent | Not reported. |
| Call ID | Full | Preserved when reported. |
| Content parts | Absent | Not present in process logs. |

The non-production v2 projector reports ToolCall **Supported**, UserContext
**Unsupported**, and ToolExecution **Unknown**.

## Cross-source implications

- Copilot detections cannot rely on user-context matching.
- Model/provider attribution is weaker for Copilot and Claude Code.
- Workspace correlation is available only from some Codex and Copilot records.
- Error-based detection remains limited by the production legacy projection.
- Only Copilot preserves call IDs on the current source path; other production
  pairing relies on ordering and tool name.

## Related documents

- [Client Capability Matrix](client-capability-matrix.md)
- [Source Validation Matrix](source-validation-matrix.md)
- [Normalization Schema](normalization-schema.md)
- [Session Sources](session-sources.md)
