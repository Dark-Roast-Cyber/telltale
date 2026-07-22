use crate::clients::{ClientId, SourceKind};
use crate::discovery::discover_sources;
use crate::parser::{RecordKind, parse_source_records};

#[test]
fn parses_jsonl_records_in_order_with_session_metadata() {
    let source = discover_sources(&crate::test_fixture_path("session_stores"))
        .into_iter()
        .find(|source| {
            source.client == ClientId::Codex
                && source.kind == SourceKind::Jsonl
                && source.path.file_name().and_then(|name| name.to_str())
                    == Some("uc001-positive.jsonl")
        })
        .expect("fixture source");

    let records = parse_source_records(&source).expect("records");

    assert_eq!(records.len(), 3);
    assert_eq!(records[0].session_id, "uc001-positive");
    assert_eq!(records[0].kind, RecordKind::SessionMeta);
    assert_eq!(records[0].agent.as_deref(), Some("fixture-agent"));
    assert_eq!(records[0].model.as_deref(), Some("fixture-model"));
    assert_eq!(records[0].provider.as_deref(), Some("fixture-provider"));
    assert_eq!(records[1].kind, RecordKind::UserMessage);
    assert_eq!(records[2].kind, RecordKind::AssistantMessage);
    assert!(records[2].content.contains("darkroastcyber.io/mcp-lab"));
}

#[test]
fn parses_headless_jsonl_as_single_session_meta_record() {
    let source = discover_sources(&crate::test_fixture_path("session_stores"))
        .into_iter()
        .find(|source| {
            source.client == ClientId::Codex
                && source.kind == SourceKind::HeadlessJsonl
                && source.path.file_name().and_then(|name| name.to_str())
                    == Some("headless-a.jsonl")
        })
        .expect("fixture source");

    let records = parse_source_records(&source).expect("records");

    assert_eq!(records.len(), 1);
    assert_eq!(records[0].session_id, "headless-a");
    assert_eq!(records[0].kind, RecordKind::SessionMeta);
    assert_eq!(records[0].agent.as_deref(), Some("codex-headless"));
    assert_eq!(records[0].provider.as_deref(), Some("openai"));
    assert_eq!(records[0].model.as_deref(), None);
    assert!(records[0].content.contains("Headless Codex session"));
}

#[test]
fn parses_archived_jsonl_as_single_session_meta_record() {
    let source = discover_sources(&crate::test_fixture_path("session_stores"))
        .into_iter()
        .find(|source| {
            source.client == ClientId::Codex
                && source.kind == SourceKind::ArchivedJsonl
                && source.path.file_name().and_then(|name| name.to_str()) == Some("session-b.jsonl")
        })
        .expect("fixture source");

    let records = parse_source_records(&source).expect("records");

    assert_eq!(records.len(), 1);
    assert_eq!(records[0].session_id, "session-b");
    assert_eq!(records[0].client, "codex");
    assert_eq!(records[0].kind, RecordKind::SessionMeta);
    assert_eq!(records[0].agent.as_deref(), Some("fixture-agent"));
    assert_eq!(records[0].provider.as_deref(), Some("fixture"));
    assert_eq!(
        records[0].timestamp.as_deref(),
        Some("2026-04-02T00:00:00Z")
    );
}

#[test]
fn parses_nested_codex_tool_call_payload_fields() {
    let source = crate::discovery::Source {
        client: crate::clients::ClientId::Codex,
        kind: crate::clients::SourceKind::Jsonl,
        source_id: "codex-payload-arguments-injection".to_string(),
        path: crate::test_fixture_path("rule_samples/codex-payload-arguments-injection.jsonl")
            .to_path_buf(),
    };

    let records = parse_source_records(&source).expect("records");

    assert_eq!(records.len(), 2);
    assert_eq!(records[1].session_id, "codex-payload-arguments-injection");
    assert_eq!(records[1].kind, RecordKind::ToolCall);
    assert_eq!(records[1].tool_name.as_deref(), Some("repo_status"));
    let arguments = records[1].arguments.as_deref().expect("arguments");
    assert!(arguments.contains("MCP tools/list"));
    assert!(arguments.contains("darkroastcyber.io/mcp-lab"));
    assert!(arguments.contains(".env"));
}
