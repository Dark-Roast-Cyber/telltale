use serde_json::Value;

use crate::parser::{
    ExtractedSourceRecords, ParseError, ParseOptions, ParsedRecord, arguments_field,
    default_source_file_stem, read_jsonl_values, record_content, session_id_with_fallback,
    string_field,
};
use telltale_schema::record::RecordKind;
use telltale_schema::source::Source;

pub(crate) fn extract_claude_jsonl_source(
    source: &Source,
    _options: ParseOptions,
) -> Result<ExtractedSourceRecords, ParseError> {
    let values = read_jsonl_values(source)?;
    let default_session_id = default_source_file_stem(source);
    let mut records = Vec::with_capacity(values.len());
    let mut agent = None;
    let mut provider = None;
    let mut model = None;

    for value in values {
        if !value.is_object() {
            return Err(ParseError::SchemaDrift {
                client: source.client,
                source_id: source.source_id.clone(),
                detail: "JSONL record envelope must be an object",
            });
        }

        agent = agent
            .or_else(|| string_field(&value, "agent_nickname"))
            .or_else(|| string_field(&value, "agent"));
        provider = provider
            .or_else(|| string_field(&value, "model_provider"))
            .or_else(|| string_field(&value, "providerID"))
            .or_else(|| string_field(&value, "provider"));
        model = model
            .or_else(|| string_field(&value, "model"))
            .or_else(|| string_field(&value, "model_name"))
            .or_else(|| string_field(&value, "modelID"));

        let arguments = arguments_field(&value).or_else(|| claude_tool_input_as_string(&value));
        records.push(ParsedRecord {
            session_id: session_id_with_fallback(&value, &default_session_id),
            agent: agent.clone(),
            model: model.clone(),
            provider: provider.clone(),
            timestamp: string_field(&value, "timestamp"),
            kind: claude_record_kind(&value),
            tool_name: claude_tool_name(&value),
            arguments,
            content: record_content(&value),
        });
    }

    Ok(ExtractedSourceRecords::records(records))
}

fn claude_record_kind(value: &Value) -> RecordKind {
    let discriminator = claude_discriminator(value);
    if discriminator.is_some_and(|kind| !is_known_claude_discriminator(kind)) {
        return RecordKind::Other;
    }

    if content_blocks(value).is_some_and(|blocks| {
        blocks
            .iter()
            .any(|block| block.get("type").and_then(Value::as_str) == Some("tool_use"))
    }) {
        return RecordKind::ToolCall;
    }
    if content_blocks(value).is_some_and(|blocks| {
        blocks
            .iter()
            .any(|block| block.get("type").and_then(Value::as_str) == Some("tool_result"))
    }) {
        return RecordKind::ToolResult;
    }

    match discriminator {
        Some("user_message" | "user") => RecordKind::UserMessage,
        Some("assistant_message" | "assistant" | "gemini" | "model") => {
            RecordKind::AssistantMessage
        }
        Some("text") if value.get("role").and_then(Value::as_str) == Some("user") => {
            RecordKind::UserMessage
        }
        Some("text")
            if matches!(
                value.get("role").and_then(Value::as_str),
                Some("assistant" | "model")
            ) =>
        {
            RecordKind::AssistantMessage
        }
        Some("tool_call") => RecordKind::ToolCall,
        Some("tool_result") => RecordKind::ToolResult,
        Some("tool") if claude_tool_part_is_result(value) => RecordKind::ToolResult,
        Some("tool") => RecordKind::ToolCall,
        Some("session_meta") => RecordKind::SessionMeta,
        _ if value.get("session_meta").is_some() => RecordKind::SessionMeta,
        _ => RecordKind::Other,
    }
}

fn claude_discriminator(value: &Value) -> Option<&str> {
    value
        .get("payload")
        .and_then(|payload| payload.get("type"))
        .and_then(Value::as_str)
        .or_else(|| {
            value
                .get("payload")
                .and_then(|payload| payload.get("payload"))
                .and_then(|payload| payload.get("type"))
                .and_then(Value::as_str)
        })
        .or_else(|| value.get("type").and_then(Value::as_str))
        .or_else(|| value.get("role").and_then(Value::as_str))
        .or_else(|| {
            value
                .get("message")
                .and_then(|message| message.get("role"))
                .and_then(Value::as_str)
        })
}

fn is_known_claude_discriminator(kind: &str) -> bool {
    matches!(
        kind,
        "user_message"
            | "user"
            | "assistant_message"
            | "assistant"
            | "gemini"
            | "model"
            | "text"
            | "tool_call"
            | "tool_result"
            | "tool"
            | "session_meta"
    )
}

fn claude_tool_part_is_result(value: &Value) -> bool {
    value
        .get("state")
        .and_then(|state| state.get("status"))
        .and_then(Value::as_str)
        .is_some_and(|status| matches!(status, "completed" | "error"))
        || value
            .get("state")
            .and_then(|state| state.get("output").or_else(|| state.get("error")))
            .is_some()
}

fn content_blocks(value: &Value) -> Option<&Vec<Value>> {
    value
        .get("message")
        .and_then(|message| message.get("content"))
        .or_else(|| value.get("content"))
        .and_then(Value::as_array)
}

fn claude_tool_name(value: &Value) -> Option<String> {
    string_field(value, "tool_name")
        .or_else(|| string_field(value, "tool"))
        .or_else(|| string_field(value, "name"))
        .or_else(|| {
            content_blocks(value)?
                .iter()
                .find(|block| block.get("type").and_then(Value::as_str) == Some("tool_use"))?
                .get("name")?
                .as_str()
                .map(ToString::to_string)
        })
}

fn claude_tool_input_as_string(value: &Value) -> Option<String> {
    let input = content_blocks(value)?
        .iter()
        .find(|block| block.get("type").and_then(Value::as_str) == Some("tool_use"))?
        .get("input")?;
    match input {
        Value::String(item) => Some(item.clone()),
        Value::Null => None,
        item => serde_json::to_string(item).ok(),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::extract_claude_jsonl_source;
    use crate::parser::ParseOptions;
    use telltale_schema::clients::{ClientId, SourceKind};
    use telltale_schema::record::RecordKind;
    use telltale_schema::source::Source;

    #[test]
    fn rejects_non_object_claude_record_envelopes_as_schema_drift() {
        let source = Source {
            client: ClientId::Claude,
            kind: SourceKind::Jsonl,
            source_id: "claude.projects".to_string(),
            path: crate::test_fixture_path("parser_maturity/non_discovered/schema-drift.jsonl"),
        };

        let error = extract_claude_jsonl_source(&source, ParseOptions::default())
            .expect_err("array envelope should be schema drift");

        let message = error.to_string();
        assert!(matches!(
            error,
            crate::parser::ParseError::SchemaDrift { .. }
        ));
        assert!(message.contains("schema drift"));
        assert!(!message.contains("Synthetic schema envelope drift"));
    }

    #[test]
    fn preserves_claude_tool_input_arguments_and_order() {
        let source = Source {
            client: ClientId::Claude,
            kind: SourceKind::Jsonl,
            source_id: "claude.projects".to_string(),
            path: crate::test_fixture_path(
                "session_stores/claude/projects/project-b/session-tool-use.jsonl",
            ),
        };

        let records = extract_claude_jsonl_source(&source, ParseOptions::default())
            .expect("Claude records")
            .records;

        assert_eq!(records.len(), 3);
        assert_eq!(records[0].kind, RecordKind::UserMessage);
        assert_eq!(records[1].kind, RecordKind::ToolCall);
        assert_eq!(records[1].tool_name.as_deref(), Some("Read"));
        assert_eq!(
            records[1].arguments.as_deref(),
            Some("{\"file_path\":\"README.md\"}")
        );
        assert_eq!(records[2].kind, RecordKind::ToolResult);
    }

    #[test]
    fn preserves_legacy_tool_discriminator_result_classification() {
        let temp = tempdir().expect("tempdir");
        let path = temp.path().join("claude-tools.jsonl");
        fs::write(
            &path,
            b"{\"type\":\"tool\",\"state\":{\"status\":\"running\"}}\n{\"type\":\"tool\",\"state\":{\"status\":\"completed\"}}\n",
        )
        .expect("Claude tool fixture");
        let source = Source {
            client: ClientId::Claude,
            kind: SourceKind::Jsonl,
            source_id: "claude.projects".to_string(),
            path,
        };

        let records = extract_claude_jsonl_source(&source, ParseOptions::default())
            .expect("Claude records")
            .records;

        assert_eq!(records.len(), 2);
        assert_eq!(records[0].kind, RecordKind::ToolCall);
        assert_eq!(records[1].kind, RecordKind::ToolResult);
    }

    #[test]
    fn unknown_discriminators_override_shape_inference() {
        let source = Source {
            client: ClientId::Claude,
            kind: SourceKind::Jsonl,
            source_id: "claude.projects".to_string(),
            path: crate::test_fixture_path(
                "parser_maturity/non_discovered/unknown-shaped-discriminators.jsonl",
            ),
        };

        let records = extract_claude_jsonl_source(&source, ParseOptions::default())
            .expect("Claude records")
            .records;

        assert_eq!(records.len(), 3);
        assert!(
            records
                .iter()
                .all(|record| record.kind == RecordKind::Other)
        );
        assert!(records[0].content.contains("future_tool"));
        assert!(records[1].content.contains("Synthetic future result"));
        assert!(records[2].content.contains("future-agent"));
    }
}
