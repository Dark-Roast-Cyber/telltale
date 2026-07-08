use std::path::Path;

use crate::clients::{ClientId, SourceKind};
use crate::discovery::discover_sources;
use crate::parser::{RecordKind, parse_source_records};

#[test]
fn parses_openclaw_jsonl_suffix_records() {
    let source = discover_sources(Path::new("tests/fixtures/session_stores"))
        .into_iter()
        .find(|source| {
            source.client == ClientId::OpenClaw
                && source.kind == SourceKind::Jsonl
                && source.path.file_name().and_then(|name| name.to_str())
                    == Some("session-a.jsonl.deleted")
        })
        .expect("fixture source");

    let records = parse_source_records(&source).expect("records");

    assert_eq!(records.len(), 2);
    assert!(records.iter().all(|record| {
        record.session_id == "openclaw-session-a" && record.client == "openclaw"
    }));
    assert_eq!(records[0].kind, RecordKind::UserMessage);
    assert_eq!(records[0].agent.as_deref(), Some("openclaw"));
    assert_eq!(records[0].provider.as_deref(), Some("openclaw"));
    assert_eq!(records[1].kind, RecordKind::AssistantMessage);
    assert_eq!(records[1].model.as_deref(), Some("openclaw-fixture-model"));
    assert!(
        records[1]
            .content
            .contains("benign OpenClaw fixture response")
    );
}

#[test]
fn parses_openclaw_jsonl_tool_call_and_result_records() {
    let source = discover_sources(Path::new("tests/fixtures/session_stores"))
        .into_iter()
        .find(|source| {
            source.client == ClientId::OpenClaw
                && source.kind == SourceKind::Jsonl
                && source.path.file_name().and_then(|name| name.to_str())
                    == Some("uc001-openclaw-tool-result.jsonl")
        })
        .expect("fixture source");

    let records = parse_source_records(&source).expect("records");

    assert_eq!(records.len(), 3);
    assert!(records.iter().all(|record| {
        record.session_id == "openclaw-uc001-tool-result" && record.client == "openclaw"
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
