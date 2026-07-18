use std::path::Path;

use crate::clients::{ClientId, SourceKind};
use crate::discovery::discover_sources;
use crate::parser::{RecordKind, parse_source_records};

#[test]
fn parses_kilocode_ui_messages_json_records() {
    let source = discover_sources(Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/session_stores"
    )))
    .into_iter()
    .find(|source| {
        source.client == ClientId::KiloCode
            && source.kind == SourceKind::UiMessagesJson
            && source
                .path
                .parent()
                .and_then(|path| path.file_name())
                .and_then(|name| name.to_str())
                == Some("task-a")
    })
    .expect("fixture source");

    let records = parse_source_records(&source).expect("records");

    assert_eq!(records.len(), 2);
    assert!(records.iter().all(|record| {
        record.session_id == "kilocode-session-a" && record.client == "kilocode"
    }));
    assert_eq!(records[0].kind, RecordKind::UserMessage);
    assert_eq!(records[0].agent.as_deref(), Some("kilocode"));
    assert_eq!(records[0].provider.as_deref(), Some("anthropic"));
    assert_eq!(records[1].kind, RecordKind::AssistantMessage);
    assert_eq!(records[1].model.as_deref(), Some("claude-fixture-model"));
    assert!(
        records[1]
            .content
            .contains("benign KiloCode fixture response")
    );
}

#[test]
fn parses_kilocode_ui_messages_tool_call_and_result_records() {
    let source = discover_sources(Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/session_stores"
    )))
    .into_iter()
    .find(|source| {
        source.client == ClientId::KiloCode
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
        record.session_id == "kilocode-uc001-tool-result" && record.client == "kilocode"
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
