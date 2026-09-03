use crate::parser::{ExtractedSourceRecords, ParseError, ParseOptions, ParsedRecord};
use telltale_schema::source::Source;

pub(crate) fn extract_claude_jsonl_source(
    source: &Source,
    _options: ParseOptions,
) -> Result<ExtractedSourceRecords, ParseError> {
    let native_records = super::native::extract_claude_native_records(source)?;
    let records = native_records
        .into_iter()
        .map(|record| ParsedRecord {
            session_id: record.legacy_session_id,
            agent: record.agent,
            model: record.model,
            provider: record.provider,
            timestamp: record.timestamp,
            kind: record.legacy_kind,
            tool_name: record.legacy_tool_name,
            arguments: record.legacy_arguments,
            content: record.legacy_content,
        })
        .collect();

    Ok(ExtractedSourceRecords::records(records))
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
