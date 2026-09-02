# Normalization Schema V1

> **Website:** For an approachable overview of schemas and normalization, see [AgentArchaeology.ai/resources/schemas](https://agentarchaeology.ai/resources/schemas/).

Telltale's internal normalization contract is `NormalizedRecordV1` in `crates/telltale-schema/src/canonical.rs`. It sits between source-specific parsers and downstream detection, deterministic review metadata, and export code.

[Canonical Observation v2](canonical-observation-v2.md) is the accepted future
internal evidence contract. It is not implemented; `NormalizedRecordV1` and its
loss-aware compatibility path remain current.

This contract is separate from the SIEM event schema. It preserves typed transcript data that the legacy flat `NormalizedRecord` shape can only represent as strings.

The source pipeline now has a distinct extraction step in `crates/telltale-sources/src/parser.rs` before records are normalized into the legacy flat shape for downstream compatibility.

## Schema Versioning

- Current schema version: `1`.
- `SCHEMA_VERSION` is the compatibility marker for the canonical normalization contract.
- Additive changes should keep the same major schema version when they only add optional fields or extension data.
- Breaking changes to required fields, variant meaning, or metadata layout require a new schema version and an explicit migration path.
- `NormalizedRecordV1::from_legacy()` is the conversion bridge from the current parser output into this contract.

## Shared Metadata

Every `NormalizedRecordV1` variant carries `RecordMeta`:

- `session_id`: required source session identifier.
- `client`: required client id such as `codex`, `opencode`, or `copilot`.
- `agent`: optional agent name when the source distinguishes it from the client.
- `model`: optional model id.
- `provider`: optional provider id.
- `timestamp`: optional source timestamp string.
- `provenance`: required provenance bundle with source path hash, optional source event id, and optional offset/fingerprint.
- `extensions`: source-specific or conversion-specific extra data.

`extensions` is the escape hatch for data that does not fit the canonical fields. The legacy conversion currently uses it for `legacy_record_kind`, lossy-field markers, and a few recovered legacy values.

## Variants

### `UserMessage`

Represents a user-authored conversation message.

Required:

- `meta`
- `content`

Optional:

- `content_parts`

Lossy today:

- `content_parts` is currently unavailable from legacy `NormalizedRecord` conversion.

### `AssistantMessage`

Represents an assistant-authored conversation message.

Required:

- `meta`
- `content`

Optional:

- `content_parts`

Lossy today:

- `content_parts` is currently unavailable from legacy `NormalizedRecord` conversion.

### `ToolCall`

Represents a model-requested tool invocation.

Required:

- `meta`
- `tool_name`

Optional:

- `arguments`
- `arguments_string`
- `call_id`

Derived:

- `arguments` is parsed from the legacy string when the source payload is valid JSON.
- `arguments_string` preserves the original legacy string for search and auditing.

Lossy today:

- `call_id` is not available from the legacy parser shape.
- If `arguments` is not valid JSON, Telltale preserves the string form and marks the value as string-only.

### `ToolResult`

Represents a tool response returned to the model.

Required:

- `meta`

Optional:

- `tool_name`
- `result`
- `result_string`
- `call_id`
- `is_error`

Derived:

- `result` is parsed from the legacy content string when it is valid JSON.
- `result_string` preserves the original legacy content.
- Legacy tool-call arguments recovered during conversion may be stored in `meta.extensions` for context.

Lossy today:

- `call_id` is not available from the legacy parser shape.
- `is_error` is not available from the legacy parser shape.
- If `result` is not valid JSON, Telltale preserves the string form and marks the value as string-only.

### `SessionMeta`

Represents session-level metadata.

Required:

- `meta`

Optional:

- `workspace`
- `fields`

Lossy today:

- `workspace` is not available from the legacy parser shape.
- Legacy content is preserved in `fields.legacy_content` when present.

### `Other`

Catch-all variant for source shapes that are not yet typed.

Required:

- `meta`
- `content`

Optional:

- `kind_hint`

## Legacy Conversion Notes

`NormalizedRecordV1::from_legacy()` keeps the legacy record kind in `meta.extensions["legacy_record_kind"]`.

It also records a `lossy_fields` list when the flat legacy shape cannot preserve:

- conversation content parts;
- tool call ids;
- tool result call ids;
- tool result error state;
- workspace metadata;
- string-only arguments or results that failed JSON parsing.

This makes the contract explicit for downstream consumers: typed fields are preferred, but conversion never silently discards the source shape.

## Practical Rules

- Use `NormalizedRecordV1` for all new pipeline stages.
- Treat `NormalizedRecord` as a legacy ingestion shape only.
- Add new source-specific data through `RecordMeta.extensions` or a typed variant field when the field is stable enough to standardize.
- If a source cannot expose a field, document the gap instead of inventing a placeholder.
