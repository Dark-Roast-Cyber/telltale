//! Canonical normalized transcript schema v1.
//!
//! This module defines ADR's internal normalization contract, separate from the
//! emitted SIEM event schema. The V1 schema preserves structured data (typed
//! tool arguments, tool results, provenance) that the flat `NormalizedRecord`
//! currently discards too early.
//!
//! The existing `NormalizedRecord` and parser pipeline remain unchanged.
//! Conversion from `NormalizedRecord` → `NormalizedRecordV1` will be added
//! in a follow-up iteration.

#![allow(dead_code)] // Types consumed incrementally as the pipeline migrates.

use serde_json::Value;
use std::collections::BTreeMap;

use crate::parser::{NormalizedRecord, RecordKind};

/// Schema version identifier for the canonical normalization contract.
pub const SCHEMA_VERSION: u32 = 1;

/// Canonical normalized record covering all event shapes across supported
/// agent harnesses. Each variant carries only the fields relevant to its
/// kind, with shared metadata in [`RecordMeta`].
#[derive(Debug, Clone)]
pub enum NormalizedRecordV1 {
    /// A user-authored message in a conversation.
    UserMessage(ConversationMessage),
    /// An assistant-authored message in a conversation.
    AssistantMessage(ConversationMessage),
    /// A tool invocation requested by the model.
    ToolCall(ToolCallRecord),
    /// A tool result returned to the model.
    ToolResult(ToolResultRecord),
    /// Session-level metadata (model info, workspace, provider, etc.).
    SessionMeta(SessionMetaRecord),
    /// Any other record shape not yet typed.
    Other(OtherRecord),
}

/// Shared metadata present on every normalized record.
#[derive(Debug, Clone)]
pub struct RecordMeta {
    /// Opaque session identifier from the source harness.
    pub session_id: String,
    /// Client harness identifier (e.g., "codex", "opencode", "copilot").
    pub client: String,
    /// Agent name, if distinguishable from client.
    pub agent: Option<String>,
    /// Model identifier, if available.
    pub model: Option<String>,
    /// Provider identifier, if available.
    pub provider: Option<String>,
    /// Event timestamp in RFC 3339 or source-native format.
    pub timestamp: Option<String>,
    /// Provenance: where this record came from.
    pub provenance: Provenance,
    /// Source-specific extension fields that do not fit the canonical schema.
    pub extensions: BTreeMap<String, Value>,
}

/// Provenance tracking for audit and deduplication.
#[derive(Debug, Clone)]
pub struct Provenance {
    /// Hash of the source file path (not the content).
    pub source_path_hash: String,
    /// Source-native event identifier, if available (e.g., event UUID, row ID).
    pub source_event_id: Option<String>,
    /// Byte offset or fingerprint for incremental scanning.
    pub offset: Option<String>,
}

/// A conversation message (user or assistant).
#[derive(Debug, Clone)]
pub struct ConversationMessage {
    pub meta: RecordMeta,
    /// The message content/text.
    pub content: String,
    /// Structured content parts, if the source provides them (e.g., multimodal).
    pub content_parts: Option<Vec<ContentPart>>,
}

/// A content part within a conversation message.
#[derive(Debug, Clone)]
pub enum ContentPart {
    Text(String),
    ImageUrl(String),
    /// Source-specific structured content.
    Other(Value),
}

/// A tool call requested by the model.
#[derive(Debug, Clone)]
pub struct ToolCallRecord {
    pub meta: RecordMeta,
    /// Tool name as invoked.
    pub tool_name: String,
    /// Structured arguments as parsed JSON, preserving types.
    pub arguments: Option<Value>,
    /// Stringified arguments for detection/search (derived from `arguments`).
    pub arguments_string: Option<String>,
    /// Tool call identifier for correlating with tool results.
    pub call_id: Option<String>,
}

/// A tool result returned to the model.
#[derive(Debug, Clone)]
pub struct ToolResultRecord {
    pub meta: RecordMeta,
    /// Tool name that produced this result.
    pub tool_name: Option<String>,
    /// Structured result content as parsed JSON.
    pub result: Option<Value>,
    /// Stringified result for detection/search (derived from `result`).
    pub result_string: Option<String>,
    /// Tool call identifier this result corresponds to.
    pub call_id: Option<String>,
    /// Whether the tool execution reported an error.
    pub is_error: Option<bool>,
}

/// Session-level metadata.
#[derive(Debug, Clone)]
pub struct SessionMetaRecord {
    pub meta: RecordMeta,
    /// Workspace or project path, if available.
    pub workspace: Option<String>,
    /// Additional session-level key-value pairs.
    pub fields: BTreeMap<String, Value>,
}

/// Catch-all for record shapes not yet typed.
#[derive(Debug, Clone)]
pub struct OtherRecord {
    pub meta: RecordMeta,
    /// Raw content string.
    pub content: String,
    /// Original record kind hint, if available.
    pub kind_hint: Option<String>,
}

impl NormalizedRecordV1 {
    /// Converts the current flat parser record into the canonical V1 shape.
    ///
    /// This adapter is intentionally conservative: it preserves string-only
    /// legacy fields alongside any JSON values it can recover, and records
    /// lossy/unavailable mappings in `meta.extensions`.
    pub fn from_legacy(record: NormalizedRecord, provenance: Provenance) -> Self {
        let kind = record.kind;
        let mut meta = RecordMeta::from_legacy(&record, provenance);
        add_legacy_conversion_extensions(&mut meta, &record);

        match kind {
            RecordKind::UserMessage => NormalizedRecordV1::UserMessage(ConversationMessage {
                meta,
                content: record.content,
                content_parts: None,
            }),
            RecordKind::AssistantMessage => {
                NormalizedRecordV1::AssistantMessage(ConversationMessage {
                    meta,
                    content: record.content,
                    content_parts: None,
                })
            }
            RecordKind::ToolCall => {
                let arguments = record.arguments.as_deref().and_then(parse_json_string);
                NormalizedRecordV1::ToolCall(ToolCallRecord {
                    meta,
                    tool_name: record.tool_name.unwrap_or_else(|| "unknown".to_string()),
                    arguments,
                    arguments_string: record.arguments,
                    call_id: None,
                })
            }
            RecordKind::ToolResult => {
                let result = parse_json_string(&record.content);
                NormalizedRecordV1::ToolResult(ToolResultRecord {
                    meta,
                    tool_name: record.tool_name,
                    result,
                    result_string: Some(record.content),
                    call_id: None,
                    is_error: None,
                })
            }
            RecordKind::SessionMeta => {
                let mut fields = BTreeMap::new();
                if !record.content.is_empty() {
                    fields.insert("legacy_content".to_string(), Value::String(record.content));
                }
                NormalizedRecordV1::SessionMeta(SessionMetaRecord {
                    meta,
                    workspace: None,
                    fields,
                })
            }
            RecordKind::Other => NormalizedRecordV1::Other(OtherRecord {
                meta,
                content: record.content,
                kind_hint: Some(record_kind_name(kind).to_string()),
            }),
        }
    }

    /// Returns the shared metadata for any variant.
    pub fn meta(&self) -> &RecordMeta {
        match self {
            NormalizedRecordV1::UserMessage(m) => &m.meta,
            NormalizedRecordV1::AssistantMessage(m) => &m.meta,
            NormalizedRecordV1::ToolCall(r) => &r.meta,
            NormalizedRecordV1::ToolResult(r) => &r.meta,
            NormalizedRecordV1::SessionMeta(r) => &r.meta,
            NormalizedRecordV1::Other(r) => &r.meta,
        }
    }

    /// Returns the session ID.
    pub fn session_id(&self) -> &str {
        &self.meta().session_id
    }

    /// Returns the client identifier.
    pub fn client(&self) -> &str {
        &self.meta().client
    }

    /// Returns the tool name, if this is a tool call or tool result.
    pub fn tool_name(&self) -> Option<&str> {
        match self {
            NormalizedRecordV1::ToolCall(r) => Some(&r.tool_name),
            NormalizedRecordV1::ToolResult(r) => r.tool_name.as_deref(),
            _ => None,
        }
    }

    /// Returns the schema version.
    pub fn schema_version(&self) -> u32 {
        SCHEMA_VERSION
    }
}

impl RecordMeta {
    fn from_legacy(record: &NormalizedRecord, provenance: Provenance) -> Self {
        RecordMeta {
            session_id: record.session_id.clone(),
            client: record.client.clone(),
            agent: record.agent.clone(),
            model: record.model.clone(),
            provider: record.provider.clone(),
            timestamp: record.timestamp.clone(),
            provenance,
            extensions: BTreeMap::new(),
        }
    }
}

fn add_legacy_conversion_extensions(meta: &mut RecordMeta, record: &NormalizedRecord) {
    meta.extensions.insert(
        "legacy_record_kind".to_string(),
        Value::String(record_kind_name(record.kind).to_string()),
    );

    let mut lossy_fields = Vec::new();
    match record.kind {
        RecordKind::UserMessage | RecordKind::AssistantMessage => {
            lossy_fields.push("content_parts_unavailable");
        }
        RecordKind::ToolCall => {
            lossy_fields.push("tool_call.call_id_unavailable");
            if record
                .arguments
                .as_deref()
                .is_some_and(parse_json_string_failed)
            {
                lossy_fields.push("tool_call.arguments_string_only");
            }
        }
        RecordKind::ToolResult => {
            lossy_fields.push("tool_result.call_id_unavailable");
            lossy_fields.push("tool_result.error_state_unavailable");
            if parse_json_string_failed(&record.content) {
                lossy_fields.push("tool_result.result_string_only");
            }
            if let Some(arguments) = &record.arguments {
                meta.extensions.insert(
                    "legacy_arguments_string".to_string(),
                    Value::String(arguments.clone()),
                );
                if let Some(value) = parse_json_string(arguments) {
                    meta.extensions
                        .insert("legacy_arguments_json".to_string(), value);
                }
            }
        }
        RecordKind::SessionMeta => {
            lossy_fields.push("session_meta.workspace_unavailable");
        }
        RecordKind::Other => {}
    }

    if !lossy_fields.is_empty() {
        meta.extensions.insert(
            "lossy_fields".to_string(),
            Value::Array(
                lossy_fields
                    .into_iter()
                    .map(|field| Value::String(field.to_string()))
                    .collect(),
            ),
        );
    }
}

fn record_kind_name(kind: RecordKind) -> &'static str {
    match kind {
        RecordKind::UserMessage => "user_message",
        RecordKind::AssistantMessage => "assistant_message",
        RecordKind::ToolCall => "tool_call",
        RecordKind::ToolResult => "tool_result",
        RecordKind::SessionMeta => "session_meta",
        RecordKind::Other => "other",
    }
}

fn parse_json_string(input: &str) -> Option<Value> {
    serde_json::from_str(input).ok()
}

fn parse_json_string_failed(input: &str) -> bool {
    !input.trim().is_empty() && parse_json_string(input).is_none()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::path::Path;

    use crate::clients::{ClientId, supported_clients};
    use crate::discovery::discover_sources;
    use crate::parser::parse_source_records;

    use super::*;

    fn test_meta() -> RecordMeta {
        RecordMeta {
            session_id: "test-session".into(),
            client: "test-client".into(),
            agent: Some("test-agent".into()),
            model: Some("gpt-4".into()),
            provider: Some("openai".into()),
            timestamp: Some("2026-05-06T00:00:00Z".into()),
            provenance: Provenance {
                source_path_hash: "sha256:abc123".into(),
                source_event_id: Some("evt-001".into()),
                offset: None,
            },
            extensions: BTreeMap::new(),
        }
    }

    #[test]
    fn user_message_variant_carries_meta() {
        let msg = NormalizedRecordV1::UserMessage(ConversationMessage {
            meta: test_meta(),
            content: "hello".into(),
            content_parts: None,
        });
        assert_eq!(msg.session_id(), "test-session");
        assert_eq!(msg.client(), "test-client");
        assert_eq!(msg.schema_version(), 1);
        assert_eq!(msg.tool_name(), None);
    }

    #[test]
    fn tool_call_variant_preserves_structured_arguments() {
        let args = serde_json::json!({"command": "ls -la", "workdir": "/tmp"});
        let call = NormalizedRecordV1::ToolCall(ToolCallRecord {
            meta: test_meta(),
            tool_name: "bash".into(),
            arguments: Some(args.clone()),
            arguments_string: Some(r#"{"command":"ls -la","workdir":"/tmp"}"#.into()),
            call_id: Some("call-001".into()),
        });
        assert_eq!(call.tool_name(), Some("bash"));
        if let NormalizedRecordV1::ToolCall(r) = &call {
            assert_eq!(r.arguments, Some(args));
            assert_eq!(r.call_id.as_deref(), Some("call-001"));
        } else {
            panic!("expected ToolCall variant");
        }
    }

    #[test]
    fn tool_result_variant_preserves_structured_result() {
        let result_val = serde_json::json!({"output": "file1.txt\nfile2.txt", "exit_code": 0});
        let result = NormalizedRecordV1::ToolResult(ToolResultRecord {
            meta: test_meta(),
            tool_name: Some("bash".into()),
            result: Some(result_val.clone()),
            result_string: Some("file1.txt\nfile2.txt".into()),
            call_id: Some("call-001".into()),
            is_error: Some(false),
        });
        assert_eq!(result.tool_name(), Some("bash"));
        if let NormalizedRecordV1::ToolResult(r) = &result {
            assert_eq!(r.result, Some(result_val));
            assert_eq!(r.is_error, Some(false));
        } else {
            panic!("expected ToolResult variant");
        }
    }

    #[test]
    fn session_meta_variant_carries_workspace() {
        let mut fields = BTreeMap::new();
        fields.insert("runtime".into(), serde_json::json!("node"));
        let meta_rec = NormalizedRecordV1::SessionMeta(SessionMetaRecord {
            meta: test_meta(),
            workspace: Some("/home/user/project".into()),
            fields,
        });
        if let NormalizedRecordV1::SessionMeta(r) = &meta_rec {
            assert_eq!(r.workspace.as_deref(), Some("/home/user/project"));
            assert_eq!(r.fields.get("runtime").unwrap(), &serde_json::json!("node"));
        } else {
            panic!("expected SessionMeta variant");
        }
    }

    #[test]
    fn other_variant_preserves_content() {
        let other = NormalizedRecordV1::Other(OtherRecord {
            meta: test_meta(),
            content: "unknown shape".into(),
            kind_hint: Some("custom_event".into()),
        });
        if let NormalizedRecordV1::Other(r) = &other {
            assert_eq!(r.content, "unknown shape");
            assert_eq!(r.kind_hint.as_deref(), Some("custom_event"));
        } else {
            panic!("expected Other variant");
        }
    }

    #[test]
    fn extensions_bag_round_trips() {
        let mut ext = BTreeMap::new();
        ext.insert("codex_run_id".into(), serde_json::json!("run-abc"));
        ext.insert("headless".into(), serde_json::json!(true));
        let msg = NormalizedRecordV1::UserMessage(ConversationMessage {
            meta: RecordMeta {
                extensions: ext,
                ..test_meta()
            },
            content: "test".into(),
            content_parts: None,
        });
        let m = msg.meta();
        assert_eq!(
            m.extensions.get("codex_run_id").unwrap(),
            &serde_json::json!("run-abc")
        );
        assert_eq!(
            m.extensions.get("headless").unwrap(),
            &serde_json::json!(true)
        );
    }

    fn test_provenance() -> Provenance {
        Provenance {
            source_path_hash: "sha256:path".into(),
            source_event_id: Some("evt-7".into()),
            offset: Some("42".into()),
        }
    }

    fn legacy_record(kind: RecordKind) -> NormalizedRecord {
        NormalizedRecord {
            session_id: "legacy-session".into(),
            client: "codex".into(),
            agent: Some("agent".into()),
            model: Some("model".into()),
            provider: Some("provider".into()),
            timestamp: Some("2026-05-06T00:00:00Z".into()),
            kind,
            tool_name: None,
            arguments: None,
            content: "legacy content".into(),
        }
    }

    #[test]
    fn converts_legacy_user_message_to_v1() {
        let record = legacy_record(RecordKind::UserMessage);
        let converted = NormalizedRecordV1::from_legacy(record, test_provenance());

        if let NormalizedRecordV1::UserMessage(message) = converted {
            assert_eq!(message.content, "legacy content");
            assert_eq!(message.meta.session_id, "legacy-session");
            assert_eq!(message.meta.client, "codex");
            assert_eq!(
                message.meta.extensions.get("legacy_record_kind"),
                Some(&serde_json::json!("user_message"))
            );
            assert_eq!(
                message.meta.extensions.get("lossy_fields"),
                Some(&serde_json::json!(["content_parts_unavailable"]))
            );
            assert_eq!(
                message.meta.provenance.source_event_id.as_deref(),
                Some("evt-7")
            );
        } else {
            panic!("expected UserMessage variant");
        }
    }

    #[test]
    fn converts_legacy_tool_call_with_json_arguments_to_v1() {
        let mut record = legacy_record(RecordKind::ToolCall);
        record.tool_name = Some("bash".into());
        record.arguments = Some(r#"{"command":"ls","timeout":10}"#.into());

        let converted = NormalizedRecordV1::from_legacy(record, test_provenance());

        if let NormalizedRecordV1::ToolCall(call) = converted {
            assert_eq!(call.tool_name, "bash");
            assert_eq!(
                call.arguments,
                Some(serde_json::json!({"command": "ls", "timeout": 10}))
            );
            assert_eq!(
                call.arguments_string.as_deref(),
                Some(r#"{"command":"ls","timeout":10}"#)
            );
            assert_eq!(call.call_id, None);
            assert_eq!(
                call.meta.extensions.get("lossy_fields"),
                Some(&serde_json::json!(["tool_call.call_id_unavailable"]))
            );
        } else {
            panic!("expected ToolCall variant");
        }
    }

    #[test]
    fn converts_legacy_tool_call_with_string_arguments_lossily() {
        let mut record = legacy_record(RecordKind::ToolCall);
        record.tool_name = Some("shell".into());
        record.arguments = Some("echo hello".into());

        let converted = NormalizedRecordV1::from_legacy(record, test_provenance());

        if let NormalizedRecordV1::ToolCall(call) = converted {
            assert_eq!(call.arguments, None);
            assert_eq!(call.arguments_string.as_deref(), Some("echo hello"));
            assert_eq!(
                call.meta.extensions.get("lossy_fields"),
                Some(&serde_json::json!([
                    "tool_call.call_id_unavailable",
                    "tool_call.arguments_string_only"
                ]))
            );
        } else {
            panic!("expected ToolCall variant");
        }
    }

    #[test]
    fn converts_legacy_tool_result_and_preserves_legacy_arguments_extension() {
        let mut record = legacy_record(RecordKind::ToolResult);
        record.tool_name = Some("bash".into());
        record.arguments = Some(r#"{"command":"cat file"}"#.into());
        record.content = r#"{"stdout":"done","exit_code":0}"#.into();

        let converted = NormalizedRecordV1::from_legacy(record, test_provenance());

        if let NormalizedRecordV1::ToolResult(result) = converted {
            assert_eq!(result.tool_name.as_deref(), Some("bash"));
            assert_eq!(
                result.result,
                Some(serde_json::json!({"stdout": "done", "exit_code": 0}))
            );
            assert_eq!(
                result.result_string.as_deref(),
                Some(r#"{"stdout":"done","exit_code":0}"#)
            );
            assert_eq!(result.call_id, None);
            assert_eq!(result.is_error, None);
            assert_eq!(
                result.meta.extensions.get("legacy_arguments_json"),
                Some(&serde_json::json!({"command": "cat file"}))
            );
            assert_eq!(
                result.meta.extensions.get("lossy_fields"),
                Some(&serde_json::json!([
                    "tool_result.call_id_unavailable",
                    "tool_result.error_state_unavailable"
                ]))
            );
        } else {
            panic!("expected ToolResult variant");
        }
    }

    #[test]
    fn converts_legacy_session_meta_to_v1_fields() {
        let converted = NormalizedRecordV1::from_legacy(
            legacy_record(RecordKind::SessionMeta),
            test_provenance(),
        );

        if let NormalizedRecordV1::SessionMeta(session) = converted {
            assert_eq!(session.workspace, None);
            assert_eq!(
                session.fields.get("legacy_content"),
                Some(&serde_json::json!("legacy content"))
            );
            assert_eq!(
                session.meta.extensions.get("lossy_fields"),
                Some(&serde_json::json!(["session_meta.workspace_unavailable"]))
            );
        } else {
            panic!("expected SessionMeta variant");
        }
    }

    #[test]
    fn converts_all_fixture_sources_to_v1_contract() {
        let fixture_root = Path::new("tests/fixtures/session_stores");
        let sources = discover_sources(fixture_root);
        let discovered_clients: BTreeSet<_> = sources.iter().map(|source| source.client).collect();
        let expected_clients: BTreeSet<_> =
            supported_clients().iter().map(|client| client.id).collect();

        assert_eq!(discovered_clients, expected_clients);

        let mut covered_clients = BTreeSet::new();
        for source in &sources {
            let records = parse_source_records(source)
                .unwrap_or_else(|err| panic!("failed to parse {}: {err}", source.source_id));
            assert!(
                !records.is_empty(),
                "fixture source {} produced no records",
                source.source_id
            );
            covered_clients.insert(source.client);

            for (idx, record) in records.into_iter().enumerate() {
                assert_eq!(record.client, source.client.as_str());
                assert!(
                    !record.session_id.trim().is_empty(),
                    "record {idx} from {} has empty session_id",
                    source.source_id
                );

                let legacy_kind = record_kind_name(record.kind);
                let source_event_id = format!("{}:{idx}", source.source_id);
                let converted = NormalizedRecordV1::from_legacy(
                    record,
                    Provenance {
                        source_path_hash: format!("fixture:{}", source.source_id),
                        source_event_id: Some(source_event_id.clone()),
                        offset: Some(idx.to_string()),
                    },
                );

                assert_eq!(converted.schema_version(), SCHEMA_VERSION);
                assert_eq!(converted.client(), source.client.as_str());
                assert!(!converted.session_id().trim().is_empty());
                assert_eq!(
                    converted.meta().provenance.source_event_id.as_deref(),
                    Some(source_event_id.as_str())
                );
                assert_eq!(
                    converted.meta().extensions.get("legacy_record_kind"),
                    Some(&serde_json::json!(legacy_kind))
                );

                match converted {
                    NormalizedRecordV1::UserMessage(message)
                    | NormalizedRecordV1::AssistantMessage(message) => {
                        assert!(
                            !message.content.trim().is_empty(),
                            "message record {idx} from {} has empty content",
                            source.source_id
                        );
                    }
                    NormalizedRecordV1::ToolCall(call) => {
                        assert!(
                            !call.tool_name.trim().is_empty(),
                            "tool call record {idx} from {} has empty tool_name",
                            source.source_id
                        );
                    }
                    NormalizedRecordV1::ToolResult(result) => {
                        assert!(
                            result.result.is_some()
                                || result
                                    .result_string
                                    .as_deref()
                                    .is_some_and(|text| { !text.trim().is_empty() }),
                            "tool result record {idx} from {} has no result content",
                            source.source_id
                        );
                    }
                    NormalizedRecordV1::SessionMeta(session) => {
                        assert!(
                            !session.fields.is_empty()
                                || !session.meta.extensions.is_empty()
                                || session.workspace.is_some(),
                            "session meta record {idx} from {} has no metadata",
                            source.source_id
                        );
                    }
                    NormalizedRecordV1::Other(other) => {
                        assert!(
                            !other.content.trim().is_empty(),
                            "other record {idx} from {} has empty content",
                            source.source_id
                        );
                    }
                }
            }
        }

        let expected_clients: BTreeSet<_> =
            supported_clients().iter().map(|client| client.id).collect();
        assert_eq!(covered_clients, expected_clients);
        assert_eq!(covered_clients.len(), 9);
        assert!(covered_clients.contains(&ClientId::Codex));
        assert!(covered_clients.contains(&ClientId::Copilot));
    }
}
