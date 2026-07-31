use std::fs;

use serde_json::Value;

use crate::parser::{
    ParseError, ParsedRecord, arguments_field, default_source_file_stem, extract_json_source,
    record_content, record_kind, string_field, tool_name,
};
use telltale_schema::clients::ClientId;
use telltale_schema::source::Source;

pub(crate) fn extract_gemini_json_source(source: &Source) -> Result<Vec<ParsedRecord>, ParseError> {
    if source.client != ClientId::Gemini {
        return extract_json_source(source);
    }

    let raw = fs::read_to_string(&source.path)?;
    let value = serde_json::from_str::<Value>(&raw)?;
    let default_session_id = default_source_file_stem(source);
    let session_id = string_field(&value, "sessionId").unwrap_or(default_session_id);
    let model = string_field(&value, "model");

    let messages = value
        .get("messages")
        .and_then(Value::as_array)
        .ok_or(ParseError::Empty)?;
    let records = messages
        .iter()
        .map(|message| ParsedRecord {
            session_id: session_id.clone(),
            agent: Some("gemini".to_string()),
            model: string_field(message, "model").or_else(|| model.clone()),
            provider: Some("google".to_string()),
            timestamp: string_field(message, "timestamp")
                .or_else(|| string_field(&value, "lastUpdated"))
                .or_else(|| string_field(&value, "startTime")),
            kind: record_kind(message),
            tool_name: tool_name(message),
            arguments: arguments_field(message),
            content: record_content(message),
        })
        .collect();

    Ok(records)
}

#[cfg(test)]
mod tests {
    use crate::clients::{PathRoot, SourcePattern};
    use crate::parser::extract_json_source;
    use telltale_schema::clients::{ClientId, SourceKind};
    use telltale_schema::record::RecordKind;
    use telltale_schema::source::Source;

    use super::super::SOURCES;
    use super::extract_gemini_json_source;

    #[test]
    fn gemini_source_definition_matches_registry_contract() {
        assert_eq!(SOURCES.len(), 1);
        let source = SOURCES[0];

        assert_eq!(source.id, "gemini.tmp");
        assert_eq!(source.kind, SourceKind::Json);
        assert_eq!(source.root, PathRoot::Home);
        assert_eq!(source.relative_path, ".gemini/tmp");
        assert_eq!(source.fixture_relative_path, "gemini/tmp");
        assert_eq!(source.pattern, SourcePattern::Extension("json"));
        assert!(source.recursive);
        assert_eq!(source.project_relative_path, None);
    }

    #[test]
    fn parses_gemini_fixture_records() {
        let source = Source {
            client: ClientId::Gemini,
            kind: SourceKind::Json,
            source_id: "gemini.tmp".to_string(),
            path: crate::test_fixture_path("session_stores/gemini/tmp/session-a.json"),
        };

        let records = extract_gemini_json_source(&source).expect("records");

        assert_eq!(records.len(), 2);
        assert_eq!(records[0].session_id, "gemini-session-a");
        assert_eq!(records[0].agent.as_deref(), Some("gemini"));
        assert_eq!(records[0].model.as_deref(), Some("gemini-fixture-model"));
        assert_eq!(records[0].provider.as_deref(), Some("google"));
        assert_eq!(records[0].kind, RecordKind::UserMessage);
        assert_eq!(records[1].kind, RecordKind::AssistantMessage);
    }

    #[test]
    fn non_gemini_sources_use_generic_json_fallback() {
        let source = Source {
            client: ClientId::OpenCode,
            kind: SourceKind::LegacyJson,
            source_id: "opencode.legacy_json".to_string(),
            path: crate::test_fixture_path(
                "session_stores/opencode/storage/message/session-a/message-a.json",
            ),
        };

        let fallback_records = extract_gemini_json_source(&source).expect("fallback records");
        let generic_records = extract_json_source(&source).expect("generic records");

        assert_eq!(fallback_records.len(), generic_records.len());
        assert_eq!(
            fallback_records[0].session_id,
            generic_records[0].session_id
        );
        assert_eq!(fallback_records[0].agent, generic_records[0].agent);
        assert_eq!(fallback_records[0].model, generic_records[0].model);
        assert_eq!(fallback_records[0].provider, generic_records[0].provider);
        assert_eq!(fallback_records[0].timestamp, generic_records[0].timestamp);
        assert_eq!(fallback_records[0].kind, generic_records[0].kind);
        assert_eq!(fallback_records[0].tool_name, generic_records[0].tool_name);
        assert_eq!(fallback_records[0].arguments, generic_records[0].arguments);
        assert_eq!(fallback_records[0].content, generic_records[0].content);
    }
}
