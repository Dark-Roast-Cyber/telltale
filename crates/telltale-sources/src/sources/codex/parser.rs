use serde_json::Value;

use crate::parser::{
    ExtractedSourceRecords, ParseError, ParseOptions, ParsedRecord, arguments_field,
    default_source_file_stem, read_jsonl_values, record_content, session_id_with_fallback,
    string_field,
};
use telltale_schema::record::RecordKind;
use telltale_schema::source::Source;

pub(crate) fn extract_codex_jsonl_source(
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

        let record_value = codex_record_value(&value);

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

        records.push(ParsedRecord {
            session_id: session_id_with_fallback(&value, &default_session_id),
            agent: agent.clone(),
            model: model.clone(),
            provider: provider.clone(),
            timestamp: string_field(&value, "timestamp"),
            kind: codex_record_kind(record_value),
            tool_name: codex_tool_name(record_value),
            arguments: arguments_field(record_value)
                .or_else(|| codex_tool_input_as_string(record_value)),
            content: record_content(record_value),
        });
    }

    Ok(ExtractedSourceRecords::records(records))
}

fn codex_record_value(value: &Value) -> &Value {
    if value.get("type").and_then(Value::as_str) == Some("response_item") {
        value
            .get("payload")
            .filter(|payload| payload.is_object())
            .unwrap_or(value)
    } else {
        value
    }
}

fn codex_record_kind(value: &Value) -> RecordKind {
    let discriminator = codex_discriminator(value);
    if discriminator.is_some_and(|kind| !is_known_codex_discriminator(kind)) {
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
        Some("message") if value.get("role").and_then(Value::as_str) == Some("user") => {
            RecordKind::UserMessage
        }
        Some("message")
            if matches!(
                value.get("role").and_then(Value::as_str),
                Some("assistant" | "model")
            ) =>
        {
            RecordKind::AssistantMessage
        }
        Some("tool_call") => RecordKind::ToolCall,
        Some("tool_result") => RecordKind::ToolResult,
        Some("custom_tool_call") => RecordKind::ToolCall,
        Some("custom_tool_call_output") => RecordKind::ToolResult,
        Some("tool") if codex_tool_part_is_result(value) => RecordKind::ToolResult,
        Some("tool") => RecordKind::ToolCall,
        Some("session_meta") => RecordKind::SessionMeta,
        _ if value.get("session_meta").is_some() => RecordKind::SessionMeta,
        _ => RecordKind::Other,
    }
}

fn codex_discriminator(value: &Value) -> Option<&str> {
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

fn is_known_codex_discriminator(kind: &str) -> bool {
    matches!(
        kind,
        "user_message"
            | "user"
            | "assistant_message"
            | "assistant"
            | "gemini"
            | "model"
            | "text"
            | "message"
            | "tool_call"
            | "tool_result"
            | "custom_tool_call"
            | "custom_tool_call_output"
            | "tool"
            | "session_meta"
    )
}

fn content_blocks(value: &Value) -> Option<&Vec<Value>> {
    value
        .get("message")
        .and_then(|message| message.get("content"))
        .or_else(|| value.get("content"))
        .and_then(Value::as_array)
}

fn codex_tool_part_is_result(value: &Value) -> bool {
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

fn codex_tool_name(value: &Value) -> Option<String> {
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

fn codex_tool_input_as_string(value: &Value) -> Option<String> {
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

    use super::extract_codex_jsonl_source;
    use crate::parser::{ParseError, ParseOptions, parse_source_records};
    use telltale_schema::clients::{ClientId, SourceKind};
    use telltale_schema::record::RecordKind;
    use telltale_schema::source::Source;

    const CODEX_IDENTITIES: &[(&str, SourceKind)] = &[
        ("codex.sessions", SourceKind::Jsonl),
        ("codex.archived_sessions", SourceKind::ArchivedJsonl),
        ("codex.headless_sessions", SourceKind::HeadlessJsonl),
        ("codex.project_sessions", SourceKind::Jsonl),
    ];

    fn source(source_id: &str, kind: SourceKind, fixture: &str) -> Source {
        Source {
            client: ClientId::Codex,
            kind,
            source_id: source_id.to_string(),
            path: crate::test_fixture_path(fixture),
        }
    }

    #[test]
    fn codex_failure_boundary_is_terminal_for_all_registered_identities() {
        for &(source_id, kind) in CODEX_IDENTITIES {
            let drift = source(
                source_id,
                kind,
                "parser_maturity/non_discovered/schema-drift.jsonl",
            );
            assert!(matches!(
                parse_source_records(&drift),
                Err(ParseError::SchemaDrift { .. })
            ));

            let malformed = source(
                source_id,
                kind,
                "parser_maturity/non_discovered/malformed-known-parser.jsonl",
            );
            assert!(matches!(
                parse_source_records(&malformed),
                Err(ParseError::Json(_))
            ));
        }
    }

    #[test]
    fn unknown_discriminators_override_nested_codex_shapes() {
        let source = source(
            "codex.sessions",
            SourceKind::Jsonl,
            "parser_maturity/non_discovered/unknown-shaped-discriminators.jsonl",
        );

        let records = parse_source_records(&source).expect("Codex records");

        assert_eq!(records.len(), 3);
        assert!(
            records
                .iter()
                .all(|record| record.kind == RecordKind::Other)
        );
    }

    #[test]
    fn preserves_known_codex_content_block_tool_semantics() {
        let temp = tempdir().expect("tempdir");
        let path = temp.path().join("codex-tool-shapes.jsonl");
        fs::write(
            &path,
            b"{\"type\":\"user\",\"session_id\":\"codex-tool-shapes\",\"content\":\"Inspect repository.\"}\n{\"type\":\"assistant\",\"session_id\":\"codex-tool-shapes\",\"content\":[{\"type\":\"tool_use\",\"name\":\"repo_status\",\"input\":{\"format\":\"json\"}}]}\n{\"type\":\"assistant\",\"session_id\":\"codex-tool-shapes\",\"content\":[{\"type\":\"tool_result\",\"content\":\"status ok\"}]}\n",
        )
        .expect("Codex tool shape fixture");
        let source = Source {
            client: ClientId::Codex,
            kind: SourceKind::Jsonl,
            source_id: "codex.sessions".to_string(),
            path,
        };

        let records = parse_source_records(&source).expect("Codex records");

        assert_eq!(records.len(), 3);
        assert_eq!(records[0].kind, RecordKind::UserMessage);
        assert_eq!(records[1].kind, RecordKind::ToolCall);
        assert_eq!(records[1].tool_name.as_deref(), Some("repo_status"));
        assert_eq!(
            records[1].arguments.as_deref(),
            Some("{\"format\":\"json\"}")
        );
        assert_eq!(records[2].kind, RecordKind::ToolResult);
        assert_eq!(records[2].tool_name.as_deref(), None);
    }

    #[test]
    fn parses_codex_app_response_item_envelopes() {
        let temp = tempdir().expect("tempdir");
        let path = temp.path().join("codex-app-response-items.jsonl");
        fs::write(
            &path,
            br#"{"type":"session_meta","payload":{"session_id":"codex-app-session","model_provider":"openai"}}
{"timestamp":"2026-08-24T20:31:53Z","type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"Inspect the repository."}]}}
{"timestamp":"2026-08-24T20:31:54Z","type":"response_item","payload":{"type":"message","role":"assistant","content":[{"type":"output_text","text":"I will inspect it."}]}}
{"timestamp":"2026-08-24T20:31:55Z","type":"response_item","payload":{"type":"custom_tool_call","name":"exec","call_id":"call-1","input":"{\"cmd\":\"git status\"}"}}
{"timestamp":"2026-08-24T20:31:56Z","type":"response_item","payload":{"type":"custom_tool_call_output","call_id":"call-1","output":"clean"}}
"#,
        )
        .expect("Codex app response-item fixture");
        let source = Source {
            client: ClientId::Codex,
            kind: SourceKind::Jsonl,
            source_id: "codex.sessions".to_string(),
            path,
        };

        let records = extract_codex_jsonl_source(&source, ParseOptions::default())
            .expect("Codex app records")
            .records;

        assert_eq!(records.len(), 5);
        assert_eq!(records[0].kind, RecordKind::SessionMeta);
        assert_eq!(records[1].kind, RecordKind::UserMessage);
        assert!(records[1].content.contains("Inspect the repository."));
        assert_eq!(records[2].kind, RecordKind::AssistantMessage);
        assert!(records[2].content.contains("I will inspect it."));
        assert_eq!(records[3].kind, RecordKind::ToolCall);
        assert_eq!(records[3].tool_name.as_deref(), Some("exec"));
        assert_eq!(
            records[3].arguments.as_deref(),
            Some("{\"cmd\":\"git status\"}")
        );
        assert_eq!(records[4].kind, RecordKind::ToolResult);
        assert!(records[4].content.contains("clean"));
    }

    #[test]
    fn preserves_codex_tool_discriminator_result_classification() {
        let temp = tempdir().expect("tempdir");
        let path = temp.path().join("codex-tools.jsonl");
        fs::write(
            &path,
            b"{\"type\":\"tool\",\"state\":{\"status\":\"running\"}}\n{\"type\":\"tool\",\"state\":{\"status\":\"completed\"}}\n",
        )
        .expect("Codex tool fixture");
        let source = Source {
            client: ClientId::Codex,
            kind: SourceKind::Jsonl,
            source_id: "codex.sessions".to_string(),
            path,
        };

        let records = extract_codex_jsonl_source(&source, ParseOptions::default())
            .expect("Codex records")
            .records;

        assert_eq!(records[0].kind, RecordKind::ToolCall);
        assert_eq!(records[1].kind, RecordKind::ToolResult);
    }
}
