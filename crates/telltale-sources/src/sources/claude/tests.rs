use std::path::Path;

use crate::clients::{ClientId, SourceKind};
use crate::discovery::discover_sources;
use crate::parser::{RecordKind, parse_source_records};

#[test]
fn parses_claude_code_jsonl_records() {
    let source = discover_sources(Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/session_stores"
    )))
    .into_iter()
    .find(|source| {
        source.client == ClientId::Claude
            && source.kind == SourceKind::Jsonl
            && source.path.file_name().and_then(|name| name.to_str()) == Some("session-a.jsonl")
    })
    .expect("fixture source");

    let records = parse_source_records(&source).expect("records");

    assert_eq!(records.len(), 2);
    assert_eq!(records[0].session_id, "session-a");
    assert_eq!(records[0].client, "claude");
    assert_eq!(records[0].kind, RecordKind::UserMessage);
    assert_eq!(records[0].model.as_deref(), Some("claude-fixture-model"));
    assert_eq!(records[1].kind, RecordKind::AssistantMessage);
    assert!(records[1].content.contains("benign fixture response"));
}

#[test]
fn parses_claude_code_tool_use_and_tool_result_blocks() {
    let source = discover_sources(Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/session_stores"
    )))
    .into_iter()
    .find(|source| {
        source.client == ClientId::Claude
            && source.kind == SourceKind::Jsonl
            && source.path.file_name().and_then(|name| name.to_str())
                == Some("session-tool-use.jsonl")
    })
    .expect("fixture source");

    let records = parse_source_records(&source).expect("records");

    assert_eq!(records.len(), 3);
    assert!(
        records
            .iter()
            .all(|record| { record.session_id == "claude-tool-use" && record.client == "claude" })
    );
    assert_eq!(records[0].kind, RecordKind::UserMessage);
    assert_eq!(records[1].kind, RecordKind::ToolCall);
    assert_eq!(records[1].tool_name.as_deref(), Some("Read"));
    assert_eq!(
        records[1].arguments.as_deref(),
        Some("{\"file_path\":\"README.md\"}")
    );
    assert_eq!(records[1].model.as_deref(), Some("claude-fixture-model"));
    assert_eq!(records[2].kind, RecordKind::ToolResult);
    assert!(records[2].content.contains("Synthetic README excerpt"));
}
