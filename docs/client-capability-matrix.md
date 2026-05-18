# Client Capability Matrix

This matrix documents what ADR's fixture-backed sources can currently normalize into `NormalizedRecordV1`.

Legend:

- `required`: canonical metadata ADR expects on every normalized record.
- `optional`: field is preserved when present in the source.
- `derived`: ADR derives the field during legacy conversion.
- `unavailable`: the current source or legacy conversion cannot expose the field reliably.

## Cross-Client Coverage

| Client | Fixture source ids | Conversation records | Tool calls | Tool results | Session metadata | Model/provider | Provenance | Known gaps |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Codex | `codex.sessions`, `codex.archived_sessions`, `codex.headless_sessions` | required | optional | optional | optional | optional | derived | `call_id`, `is_error`, and `content_parts` are unavailable through the legacy flat record. |
| Claude Code | `claude.projects` | required | optional | optional | unavailable | optional | derived | `call_id`, `is_error`, and `content_parts` are unavailable through the legacy flat record. |
| Gemini CLI | `gemini.tmp` | required | optional | optional | unavailable | optional | derived | `call_id`, `is_error`, and `content_parts` are unavailable through the legacy flat record. |
| OpenClaw | `openclaw.agents` | required | optional | optional | unavailable | optional | derived | `call_id`, `is_error`, and `content_parts` are unavailable through the legacy flat record. |
| Qwen CLI | `qwen.projects` | required | optional | optional | unavailable | optional | derived | `call_id`, `is_error`, and `content_parts` are unavailable through the legacy flat record. |
| RooCode | `roocode.tasks` | required | optional | optional | unavailable | optional | derived | `call_id`, `is_error`, and `content_parts` are unavailable through the legacy flat record. |
| KiloCode | `kilocode.tasks` | required | optional | optional | unavailable | optional | derived | `call_id`, `is_error`, and `content_parts` are unavailable through the legacy flat record. |
| OpenCode | `opencode.sqlite`, `opencode.legacy_json` | required | optional | optional | unavailable | optional | derived | `call_id`, `is_error`, workspace, and `content_parts` are unavailable through the legacy flat record. |
| GitHub Copilot | `copilot.process_log` | optional | optional | optional | unavailable | optional | derived | Process logs are lossy; user intent, `call_id`, `is_error`, workspace, and `content_parts` are unavailable through the legacy flat record. |

## Normalized Field Expectations

| `NormalizedRecordV1` field | Status | Notes |
| --- | --- | --- |
| `meta.session_id` | required | Must be non-empty for every fixture-backed converted record. |
| `meta.client` | required | Must match the source registry client id. |
| `meta.agent` | optional | Preserved when the source exposes an agent or parser default. |
| `meta.model` | optional | Preserved when the source exposes model metadata. |
| `meta.provider` | optional | Preserved when the source exposes provider metadata. |
| `meta.timestamp` | optional | Preserved as a source-native string when present. |
| `meta.provenance` | derived | The conformance test supplies deterministic fixture provenance for conversion coverage. |
| `meta.extensions.legacy_record_kind` | derived | Required on every record converted through `from_legacy()`. |
| `meta.extensions.lossy_fields` | derived | Present when legacy conversion cannot preserve canonical fields. |
| `content_parts` | unavailable | The legacy `NormalizedRecord` shape only carries flat text content. |
| `ToolCall.arguments` | derived | Parsed from legacy argument strings when they are valid JSON. |
| `ToolCall.arguments_string` | optional | Preserves the legacy argument string for search and audit. |
| `ToolCall.call_id` | unavailable | Not exposed by the legacy flat record. |
| `ToolResult.result` | derived | Parsed from legacy result content when it is valid JSON. |
| `ToolResult.result_string` | optional | Preserves the legacy result string for search and audit. |
| `ToolResult.call_id` | unavailable | Not exposed by the legacy flat record. |
| `ToolResult.is_error` | unavailable | Not exposed by the legacy flat record. |
| `SessionMeta.workspace` | unavailable | Not exposed by the legacy flat record. |

The fixture-backed conformance test in `src/schema.rs` verifies that every source id in `supported_clients()` is discovered from `tests/fixtures/session_stores`, parses at least one record, converts into `NormalizedRecordV1`, preserves required metadata, and records the legacy kind extension.

## Related Documents

- [Agent Capability Profiles](agent-capability-profiles.md) — per-source raw log field availability and known gaps
- [Source Validation Matrix](source-validation-matrix.md) — fixture and detection coverage status
- [Normalization Schema](normalization-schema.md) — `NormalizedRecordV1` contract
