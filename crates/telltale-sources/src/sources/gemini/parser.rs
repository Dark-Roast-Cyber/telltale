use serde_json::Value;

use crate::parser::{
    ExtractedSourceRecords, ParseError, ParseOptions, ParsedRecord, arguments_field,
    default_source_file_stem, read_json_document, record_content, record_kind, string_field,
    tool_name,
};
use telltale_schema::source::Source;

pub(crate) fn extract_gemini_json_source(
    source: &Source,
    _options: ParseOptions,
) -> Result<ExtractedSourceRecords, ParseError> {
    let value = read_json_document(source)?;
    if !value.is_object() {
        return Err(ParseError::SchemaDrift {
            client: source.client,
            source_id: source.source_id.clone(),
            detail: "Gemini JSON document envelope must be an object",
        });
    }

    let default_session_id = default_source_file_stem(source);
    let session_id = string_field(&value, "sessionId").unwrap_or(default_session_id);
    let model = string_field(&value, "model");

    let messages = match value.get("messages") {
        None => return Err(ParseError::Empty),
        Some(Value::Array(messages)) => messages,
        Some(_) => {
            return Err(ParseError::SchemaDrift {
                client: source.client,
                source_id: source.source_id.clone(),
                detail: "Gemini messages must be an array",
            });
        }
    };
    if messages.iter().any(|message| !message.is_object()) {
        return Err(ParseError::SchemaDrift {
            client: source.client,
            source_id: source.source_id.clone(),
            detail: "Gemini message records must be objects",
        });
    }

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

    Ok(ExtractedSourceRecords::records(records))
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use crate::clients::{PathRoot, SourcePattern};
    use crate::parser::{ParseError, ParseOptions, parse_source_records};
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

        let records = extract_gemini_json_source(&source, ParseOptions::default())
            .expect("records")
            .records;

        assert_eq!(records.len(), 2);
        assert_eq!(records[0].session_id, "gemini-session-a");
        assert_eq!(records[0].agent.as_deref(), Some("gemini"));
        assert_eq!(records[0].model.as_deref(), Some("gemini-fixture-model"));
        assert_eq!(records[0].provider.as_deref(), Some("google"));
        assert_eq!(records[0].kind, RecordKind::UserMessage);
        assert_eq!(records[1].kind, RecordKind::AssistantMessage);
    }

    #[test]
    fn preserves_gemini_empty_session_behavior() {
        let source = Source {
            client: ClientId::Gemini,
            kind: SourceKind::Json,
            source_id: "gemini.tmp".to_string(),
            path: crate::test_fixture_path("session_stores/gemini/tmp/empty-session.json"),
        };

        assert!(matches!(
            parse_source_records(&source),
            Err(ParseError::Empty)
        ));
    }

    #[test]
    fn gemini_schema_and_unknown_boundaries_are_terminal() {
        let temp = tempdir().expect("tempdir");
        let cases = [
            ("top-level-array.json", "[]", "schema"),
            (
                "wrong-messages.json",
                "{\"messages\":\"not-an-array\"}",
                "schema",
            ),
            (
                "non-object-message.json",
                "{\"messages\":[{\"type\":\"user\"},\"not-an-object\"]}",
                "schema",
            ),
            ("malformed.json", "{\"messages\":", "json"),
            (
                "unknown.json",
                "{\"sessionId\":\"gemini-unknown\",\"messages\":[{\"type\":\"future_variant\",\"content\":[{\"type\":\"tool_use\"}],\"session_meta\":{\"agent\":\"future\"}}]}",
                "other",
            ),
            ("empty-messages.json", "{\"messages\":[]}", "empty"),
        ];

        for (file_name, contents, expected) in cases {
            let path = temp.path().join(file_name);
            fs::write(&path, contents).expect("Gemini boundary fixture");
            let source = Source {
                client: ClientId::Gemini,
                kind: SourceKind::Json,
                source_id: "gemini.tmp".to_string(),
                path,
            };
            let result = parse_source_records(&source);

            match expected {
                "schema" => assert!(matches!(result, Err(ParseError::SchemaDrift { .. }))),
                "json" => assert!(matches!(result, Err(ParseError::Json(_)))),
                "empty" => assert!(result.expect("empty messages").is_empty()),
                "other" => {
                    let records = result.expect("unknown message");
                    assert_eq!(records.len(), 1);
                    assert_eq!(records[0].kind, RecordKind::Other);
                }
                _ => unreachable!("test case marker"),
            }
        }
    }
}
