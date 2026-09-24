# Client Capability Matrix

Production sources do not normalize into `NormalizedRecordV1`. Scan, watch, and
embedding acquire Canonical Observation v2 and evaluate it with Detection v2.
Per-source visibility lives in
[Agent Capability Profiles](agent-capability-profiles.md) and the canonical
adapter specs. This page records only the caller-supplied
`NormalizedRecordV1::from_legacy()` conversion contract.

There is no source-backed schema conformance test. `src/schema.rs` is gone.
Source fixtures are acquired through `acquire_source`, not converted into
normalized records.

## Direct-record conversion fields

Legend:

- `required`: metadata `from_legacy()` expects on every converted record.
- `optional`: field is preserved when the caller record has it.
- `derived`: produced by the conversion, not copied from a source adapter.
- `unavailable`: the flat `NormalizedRecord` shape cannot expose the field.

| `NormalizedRecordV1` field | Status | Notes |
| --- | --- | --- |
| `meta.session_id` | required | Caller-supplied. Conversion does not invent one. |
| `meta.client` | required | Caller-supplied label. It does not register a source. |
| `meta.agent` | optional | Preserved when the caller record has it. |
| `meta.model` | optional | Preserved when the caller record has it. |
| `meta.provider` | optional | Preserved when the caller record has it. |
| `meta.timestamp` | optional | Preserved when the caller record has it. |
| `meta.provenance` | derived | Supplied by the conversion caller, not by source acquisition. |
| `meta.extensions.legacy_record_kind` | derived | Set on every record converted through `from_legacy()`. |
| `meta.extensions.lossy_fields` | derived | Present when the flat shape cannot preserve a typed field. |
| `content_parts` | unavailable | The flat record carries only text content. |
| `ToolCall.arguments` | derived | Parsed from argument strings when they are valid JSON. |
| `ToolCall.arguments_string` | optional | Preserves the caller argument string. |
| `ToolCall.call_id` | unavailable | Not present on the flat record. |
| `ToolResult.result` | derived | Parsed from result content when it is valid JSON. |
| `ToolResult.result_string` | optional | Preserves the caller result string. |
| `ToolResult.call_id` | unavailable | Not present on the flat record. |
| `ToolResult.is_error` | unavailable | Not present on the flat record. |
| `SessionMeta.workspace` | unavailable | Not present on the flat record. |

## Related Documents

- [Agent Capability Profiles](agent-capability-profiles.md) — per-source canonical visibility and known gaps
- [MCP Tool Inventory](mcp-tool-inventory.md) — static MCP configuration inventory support and gaps
- [Source Validation Matrix](source-validation-matrix.md) — fixture and detection coverage status
- [Normalization Schema](normalization-schema.md) — `NormalizedRecordV1` direct-record contract
