use crate::parser::{ExtractedSourceRecords, ParseError, ParseOptions, ParsedRecord};
use telltale_schema::source::Source;

pub(crate) fn extract_codex_jsonl_source(
    source: &Source,
    _options: ParseOptions,
) -> Result<ExtractedSourceRecords, ParseError> {
    let records = super::native::extract_codex_native_records(source)?
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
