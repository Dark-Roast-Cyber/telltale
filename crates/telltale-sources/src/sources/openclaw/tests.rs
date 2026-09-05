use std::fs;

use tempfile::tempdir;

use crate::discovery::discover_sources_best_effort;
use crate::parser::{ParseError, parse_source_records};
use telltale_schema::clients::{ClientId, SourceKind};
use telltale_schema::record::RecordKind;
use telltale_schema::source::Source;

fn openclaw_source(path: std::path::PathBuf) -> Source {
    Source {
        client: ClientId::OpenClaw,
        kind: SourceKind::Jsonl,
        source_id: "openclaw.agents".to_string(),
        path,
    }
}

#[test]
fn parses_openclaw_jsonl_suffix_records() {
    let source = discover_sources_best_effort(&crate::test_fixture_path("session_stores"))
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
    let source = discover_sources_best_effort(&crate::test_fixture_path("session_stores"))
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

#[test]
fn preserves_openclaw_metadata_inheritance_and_empty_jsonl() {
    let temp = tempdir().expect("tempdir");
    let path = temp.path().join("metadata.jsonl");
    fs::write(
        &path,
        b"{\"type\":\"session_meta\",\"sessionId\":\"openclaw-metadata\",\"agent\":\"fixture-agent\",\"provider\":\"fixture-provider\",\"model\":\"fixture-model\",\"timestamp\":\"2026-05-04T00:00:00Z\"}\n{\"type\":\"assistant\",\"sessionId\":\"openclaw-metadata\",\"content\":\"Inherited metadata response.\"}\n",
    )
    .expect("metadata fixture");

    let records = parse_source_records(&openclaw_source(path)).expect("records");
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].kind, RecordKind::SessionMeta);
    assert_eq!(records[1].kind, RecordKind::AssistantMessage);
    assert_eq!(records[1].agent.as_deref(), Some("fixture-agent"));
    assert_eq!(records[1].provider.as_deref(), Some("fixture-provider"));
    assert_eq!(records[1].model.as_deref(), Some("fixture-model"));

    let empty_path = temp.path().join("empty.jsonl");
    fs::write(&empty_path, b"\n  \n").expect("empty fixture");
    assert!(
        parse_source_records(&openclaw_source(empty_path))
            .expect("empty records")
            .is_empty()
    );
}

#[test]
fn native_openclaw_projection_preserves_legacy_direct_tool_call_shape() {
    let temp = tempdir().expect("tempdir");
    let path = temp.path().join("native-parity.jsonl");
    fs::write(
        &path,
        b"{\"type\":\"session_meta\",\"agent\":\"fixture-agent\",\"provider\":\"fixture-provider\",\"model\":\"fixture-model\"}\n{\"type\":\"assistant\",\"content\":\"Synthetic response.\",\"tool_calls\":[{\"id\":\"fixture-call\",\"name\":\"read_file\",\"arguments\":{\"path\":\"synthetic.txt\"}}]}\n",
    )
    .expect("native parity fixture");
    let source = openclaw_source(path);

    let native = super::native::extract_openclaw_native_records(&source).expect("native records");
    assert_eq!(native.len(), 2);
    assert_eq!(native[0].source_sequence, 0);
    assert_eq!(native[1].source_sequence, 1);
    assert_eq!(native[1].reported_agent, None);
    assert_eq!(
        native[1].legacy_effective_agent.as_deref(),
        Some("fixture-agent")
    );
    assert_eq!(native[1].tool_calls.len(), 1);
    assert_eq!(
        native[1].tool_calls[0].call_id.as_deref(),
        Some("fixture-call")
    );

    let records = parse_source_records(&source).expect("legacy records");
    assert_eq!(records.len(), 2);
    assert_eq!(records[1].kind, RecordKind::AssistantMessage);
    assert_eq!(records[1].tool_name, None);
    assert_eq!(records[1].arguments, None);
    assert_eq!(records[1].agent.as_deref(), Some("fixture-agent"));
    assert_eq!(records[1].provider.as_deref(), Some("fixture-provider"));
    assert_eq!(records[1].model.as_deref(), Some("fixture-model"));
}

#[test]
fn openclaw_parser_has_terminal_failure_and_unknown_boundaries() {
    let cases = [
        (
            "parser_maturity/non_discovered/schema-drift.jsonl",
            "schema",
        ),
        (
            "parser_maturity/non_discovered/malformed-known-parser.jsonl",
            "json",
        ),
        (
            "parser_maturity/non_discovered/unknown-shaped-discriminators.jsonl",
            "other",
        ),
    ];

    for (fixture, expected) in cases {
        let result = parse_source_records(&openclaw_source(crate::test_fixture_path(fixture)));
        match expected {
            "schema" => assert!(matches!(result, Err(ParseError::SchemaDrift { .. }))),
            "json" => assert!(matches!(result, Err(ParseError::Json(_)))),
            "other" => {
                let records = result.expect("unknown discriminator records");
                assert_eq!(records.len(), 3);
                assert!(
                    records
                        .iter()
                        .all(|record| record.kind == RecordKind::Other)
                );
            }
            _ => unreachable!("test case marker"),
        }
    }
}
