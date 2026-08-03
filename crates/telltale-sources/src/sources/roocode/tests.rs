use std::fs;

use tempfile::tempdir;

use crate::discovery::discover_sources_best_effort;
use crate::parser::{ParseError, parse_source_records};
use telltale_schema::clients::{ClientId, SourceKind};
use telltale_schema::record::RecordKind;
use telltale_schema::source::Source;

#[test]
fn parses_roocode_ui_messages_json_records() {
    let source = discover_sources_best_effort(&crate::test_fixture_path("session_stores"))
        .into_iter()
        .find(|source| {
            source.client == ClientId::RooCode
                && source.kind == SourceKind::UiMessagesJson
                && source.path.file_name().and_then(|name| name.to_str())
                    == Some("ui_messages.json")
        })
        .expect("fixture source");

    let records = parse_source_records(&source).expect("records");

    assert_eq!(records.len(), 2);
    assert!(
        records.iter().all(|record| {
            record.session_id == "roocode-session-a" && record.client == "roocode"
        })
    );
    assert_eq!(records[0].kind, RecordKind::UserMessage);
    assert_eq!(records[0].agent.as_deref(), Some("roocode"));
    assert_eq!(records[0].provider.as_deref(), Some("anthropic"));
    assert_eq!(records[1].kind, RecordKind::AssistantMessage);
    assert_eq!(records[1].model.as_deref(), Some("claude-fixture-model"));
    assert!(
        records[1]
            .content
            .contains("benign RooCode fixture response")
    );
}

#[test]
fn parses_roocode_ui_messages_tool_call_and_result_records() {
    let source = discover_sources_best_effort(&crate::test_fixture_path("session_stores"))
        .into_iter()
        .find(|source| {
            source.client == ClientId::RooCode
                && source.kind == SourceKind::UiMessagesJson
                && source
                    .path
                    .parent()
                    .and_then(|path| path.file_name())
                    .and_then(|name| name.to_str())
                    == Some("task-b")
        })
        .expect("fixture source");

    let records = parse_source_records(&source).expect("records");

    assert_eq!(records.len(), 3);
    assert!(records.iter().all(|record| {
        record.session_id == "roocode-uc001-tool-result" && record.client == "roocode"
    }));
    assert_eq!(records[0].kind, RecordKind::UserMessage);
    assert_eq!(records[1].kind, RecordKind::ToolCall);
    assert_eq!(records[1].tool_name.as_deref(), Some("repo_status"));
    assert_eq!(
        records[1].arguments.as_deref(),
        Some("{\"format\":\"json\"}")
    );
    assert_eq!(records[2].kind, RecordKind::ToolResult);
    assert_eq!(records[2].tool_name.as_deref(), Some("repo_status"));
    assert!(records[2].content.contains("darkroastcyber.io/mcp-lab"));
}

#[test]
fn roocode_json_document_fallback_has_terminal_error_and_unknown_boundaries() {
    let temp = tempdir().expect("tempdir");
    let malformed_path = temp.path().join("malformed.json");
    fs::write(&malformed_path, b"{\"type\":").expect("malformed fixture");
    let malformed_source = Source {
        client: ClientId::RooCode,
        kind: SourceKind::UiMessagesJson,
        source_id: "roocode.tasks".to_string(),
        path: malformed_path,
    };
    assert!(matches!(
        parse_source_records(&malformed_source),
        Err(ParseError::Json(_))
    ));

    let unknown_path = temp.path().join("unknown.json");
    fs::write(
        &unknown_path,
        b"{\"type\":\"future_variant\",\"content\":[{\"type\":\"tool_use\"}],\"session_meta\":{\"agent\":\"future\"}}",
    )
    .expect("unknown fixture");
    let unknown_source = Source {
        client: ClientId::RooCode,
        kind: SourceKind::UiMessagesJson,
        source_id: "roocode.tasks".to_string(),
        path: unknown_path,
    };
    let records = parse_source_records(&unknown_source).expect("unknown record");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].kind, RecordKind::Other);
}
