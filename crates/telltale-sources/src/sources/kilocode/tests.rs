use std::fs;

use tempfile::tempdir;

use crate::discovery::discover_sources_best_effort;
use crate::parser::{ParseError, parse_source_records};
use telltale_schema::clients::{ClientId, SourceKind};
use telltale_schema::record::RecordKind;
use telltale_schema::source::Source;

fn source(path: std::path::PathBuf) -> Source {
    Source {
        client: ClientId::KiloCode,
        kind: SourceKind::UiMessagesJson,
        source_id: "kilocode.tasks".to_string(),
        path,
    }
}

#[test]
fn parses_kilocode_legacy_ui_messages_with_legacy_parent_grouping() {
    let source = discover_sources_best_effort(&crate::test_fixture_path("session_stores"))
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
        record.session_id == "task-a"
            && record.client == "kilocode"
            && record.agent.is_none()
            && record.provider.is_none()
            && record.model.is_none()
    }));
    assert_eq!(records[0].kind, RecordKind::UserMessage);
    assert_eq!(records[1].kind, RecordKind::AssistantMessage);
    assert_eq!(
        records[1].timestamp.as_deref(),
        Some("2026-04-27T19:00:01Z")
    );
}

#[test]
fn parses_kilocode_mcp_request_and_result_without_inventing_correlation() {
    let source = discover_sources_best_effort(&crate::test_fixture_path("session_stores"))
        .into_iter()
        .find(|source| {
            source.client == ClientId::KiloCode
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
    assert!(
        records
            .iter()
            .all(|record| { record.session_id == "task-b" && record.client == "kilocode" })
    );
    assert_eq!(records[0].kind, RecordKind::UserMessage);
    assert_eq!(records[1].kind, RecordKind::ToolCall);
    assert_eq!(records[1].tool_name.as_deref(), Some("repo_status"));
    assert_eq!(
        records[1].arguments.as_deref(),
        Some("{\"format\":\"json\"}")
    );
    assert_eq!(records[2].kind, RecordKind::ToolResult);
    assert_eq!(records[2].tool_name, None);
    assert!(records[2].content.contains("synthetic marker"));
    assert!(
        !records
            .iter()
            .any(|record| record.content.contains("alternate body"))
    );
}

#[test]
fn parses_kilocode_partial_mcp_request_writer_shape() {
    let temp = tempdir().expect("tempdir");
    let path = temp.path().join("legacy-task").join("ui_messages.json");
    fs::create_dir_all(path.parent().expect("task parent")).expect("task directory");
    fs::write(
        &path,
        r#"[
          {"type":"ask","ask":"use_mcp_server","ts":1,"partial":true,"text":"{\"type\":\"use_mcp_tool\",\"serverName\":\"synthetic-mcp\",\"toolName\":\"repo_status\",\"arguments\":{\"format\":\"json\"}}"}
        ]"#,
    )
    .expect("source");

    let records = parse_source_records(&source(path)).expect("records");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].kind, RecordKind::ToolCall);
    assert_eq!(records[0].tool_name.as_deref(), Some("repo_status"));
    assert_eq!(
        records[0].arguments.as_deref(),
        Some("{\"format\":\"json\"}")
    );
}

#[test]
fn parses_kilocode_mcp_resource_request_writer_shape() {
    let temp = tempdir().expect("tempdir");
    let path = temp.path().join("legacy-task").join("ui_messages.json");
    fs::create_dir_all(path.parent().expect("task parent")).expect("task directory");
    fs::write(
        &path,
        r#"[
          {"type":"ask","ask":"use_mcp_server","ts":1,"text":"{\"type\":\"access_mcp_resource\",\"serverName\":\"synthetic-mcp\",\"uri\":\"synthetic://resource\"}"}
        ]"#,
    )
    .expect("source");

    let records = parse_source_records(&source(path)).expect("records");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].kind, RecordKind::ToolCall);
    assert_eq!(records[0].tool_name.as_deref(), Some("access_mcp_resource"));
    assert_eq!(records[0].arguments, None);
}

#[test]
fn rejects_kilocode_invalid_mcp_payloads_without_generic_retry() {
    let temp = tempdir().expect("tempdir");
    let cases = [
        (
            "wrong-type",
            r#"[{"type":"ask","ask":"use_mcp_server","ts":1,"text":"{\"type\":\"other\"}"}]"#,
        ),
        (
            "partial-object-without-partial",
            r#"[{"type":"ask","ask":"use_mcp_server","ts":1,"text":"{\"type\":\"use_mcp_tool\",\"serverName\":\"synthetic-mcp\",\"toolName\":\"repo_status\",\"arguments\":{}}"}]"#,
        ),
        (
            "missing-resource-uri",
            r#"[{"type":"ask","ask":"use_mcp_server","ts":1,"text":"{\"type\":\"access_mcp_resource\",\"serverName\":\"synthetic-mcp\"}"}]"#,
        ),
    ];
    for (name, body) in cases {
        let path = temp.path().join(format!("{name}.json"));
        fs::write(&path, body).expect("source");
        let error = parse_source_records(&source(path)).expect_err("invalid MCP payload");
        assert!(matches!(error, ParseError::SourceContract { .. }));
        assert!(error.to_string().contains("invalid_mcp_request"));
    }
}

#[test]
fn accepts_kilocode_control_subtype_extras_and_rejects_roo_only_says() {
    let temp = tempdir().expect("tempdir");
    let path = temp.path().join("legacy-task").join("ui_messages.json");
    fs::create_dir_all(path.parent().expect("task parent")).expect("task directory");
    fs::write(
        &path,
        r#"[
          {"type":"ask","ask":"payment_required_prompt","ts":1},
          {"type":"say","say":"browser_action","ts":2},
          {"type":"say","say":"tool","ts":3}
        ]"#,
    )
    .expect("source");
    let error = parse_source_records(&source(path)).expect_err("Roo-only subtype");
    assert!(matches!(error, ParseError::SourceContract { .. }));
    assert!(error.to_string().contains("unknown_subtype"));
}

#[test]
fn missing_kilocode_metadata_keeps_only_legacy_parent_fallback() {
    let temp = tempdir().expect("tempdir");
    let path = temp.path().join("legacy-task").join("ui_messages.json");
    fs::create_dir_all(path.parent().expect("task parent")).expect("task directory");
    fs::write(
        &path,
        r#"[{"type":"say","say":"text","ts":0,"text":"synthetic"}]"#,
    )
    .expect("source");
    let records = parse_source_records(&source(path)).expect("records");
    assert_eq!(records[0].session_id, "legacy-task");
}

#[test]
fn kilo_does_not_promote_roo_companions_into_identity() {
    let temp = tempdir().expect("tempdir");
    let tasks = temp.path().join("tasks");
    let task = tasks.join("legacy-task");
    fs::create_dir_all(&task).expect("task directory");
    fs::write(
        task.join("ui_messages.json"),
        r#"[{"type":"say","say":"text","ts":0,"text":"synthetic"}]"#,
    )
    .expect("source");
    fs::write(
        task.join("history_item.json"),
        r#"{"id":"roo-companion-must-not-select"}"#,
    )
    .expect("Roo-shaped history");
    fs::write(
        tasks.join("_index.json"),
        r#"{"version":1,"updatedAt":1,"entries":[{"id":"roo-companion-must-not-select"}]}"#,
    )
    .expect("Roo-shaped index");
    let records = parse_source_records(&source(task.join("ui_messages.json"))).expect("records");
    assert_eq!(records[0].session_id, "legacy-task");
}

#[test]
fn preserves_partial_order_and_does_not_promote_array_ordinal_to_identity() {
    let temp = tempdir().expect("tempdir");
    let path = temp.path().join("task").join("ui_messages.json");
    fs::create_dir_all(path.parent().expect("task parent")).expect("task directory");
    fs::write(
        &path,
        r#"[
          {"type":"say","say":"text","ts":0,"text":"first","partial":true},
          {"type":"say","say":"text","ts":0,"text":"second","partial":false}
        ]"#,
    )
    .expect("source");
    let native = super::native::extract_kilocode_native_records(&source(path)).expect("native");
    assert_eq!(native.len(), 2);
    assert_eq!(native[0].source_sequence, 0);
    assert_eq!(native[1].source_sequence, 1);
    assert_eq!(native[0].partial, Some(true));
    assert_eq!(native[1].partial, Some(false));
    assert_eq!(native[0].timestamp, native[1].timestamp);
}

#[test]
fn alternate_api_body_is_not_selected_by_kilocode_ui_parser() {
    let temp = tempdir().expect("tempdir");
    let tasks = temp.path().join("tasks");
    let task = tasks.join("task");
    fs::create_dir_all(&task).expect("task directory");
    fs::write(
        task.join("ui_messages.json"),
        r#"[{"type":"say","say":"text","ts":0,"text":"SECRET_MARKER"}]"#,
    )
    .expect("ui source");
    fs::write(
        task.join("api_conversation_history.json"),
        r#"[{"role":"assistant","content":"alternate body"}]"#,
    )
    .expect("alternate body");

    let records = parse_source_records(&source(task.join("ui_messages.json"))).expect("records");
    assert_eq!(records[0].session_id, "task");
    assert!(!records[0].content.contains("alternate body"));
}

#[test]
fn rejects_kilocode_unknown_and_structural_variants_without_generic_retry() {
    let temp = tempdir().expect("tempdir");
    let cases = [
        (
            "root",
            r#"{"type":"say","say":"text","ts":1}"#,
            "root_not_array",
        ),
        ("record", r#"[1]"#, "record_not_object"),
        (
            "unknown",
            r#"[{"type":"ask","ask":"future_variant","ts":1}]"#,
            "unknown_subtype",
        ),
    ];
    for (name, body, category) in cases {
        let path = temp.path().join(format!("{name}.json"));
        fs::write(&path, body).expect("source");
        let error = parse_source_records(&source(path.clone())).expect_err("terminal error");
        assert!(matches!(error, ParseError::SourceContract { .. }));
        assert!(error.to_string().contains(category));
        assert!(!error.to_string().contains(path.to_string_lossy().as_ref()));
    }
}

#[test]
fn malformed_json_is_bounded_even_when_generic_json_would_have_returned_other() {
    let temp = tempdir().expect("tempdir");
    let path = temp.path().join("malformed.json");
    fs::write(
        &path,
        br#"[{"type":"say","say":"text","ts":1,"text":"SECRET_MARKER""#,
    )
    .expect("fixture");
    let error = parse_source_records(&source(path.clone())).expect_err("malformed source");
    assert!(matches!(
        error,
        ParseError::SourceContract {
            category: "malformed_json"
        }
    ));
    assert_eq!(error.to_string(), "source contract failure: malformed_json");
    assert_eq!(
        format!("{error:?}"),
        r#"SourceContract { category: "malformed_json" }"#
    );
    assert!(!error.to_string().contains("SECRET_MARKER"));
    assert!(!format!("{error:?}").contains("SECRET_MARKER"));
    assert!(!error.to_string().contains(path.to_string_lossy().as_ref()));
    assert!(!format!("{error:?}").contains("line"));
    assert!(!format!("{error:?}").contains("column"));
}

#[test]
fn native_debug_redacts_kilocode_message_metadata_and_tool_fields() {
    let temp = tempdir().expect("tempdir");
    let tasks = temp.path().join("tasks");
    let task = tasks.join("debug-task");
    fs::create_dir_all(&task).expect("task directory");
    fs::write(
        task.join("ui_messages.json"),
        r#"[
          {"type":"ask","ask":"tool","ts":1777314901000,"text":"{\"tool\":\"SECRET_TOOL\",\"arguments\":{\"secret\":\"SECRET_ARGUMENT\"}}"},
          {"type":"say","say":"command_output","ts":1777314902000,"text":"SECRET_RESULT"}
        ]"#,
    )
    .expect("source");
    let native =
        super::native::extract_kilocode_native_records(&source(task.join("ui_messages.json")))
            .expect("native");
    let debug = format!("{native:?}");
    for marker in [
        "SECRET_TOOL",
        "SECRET_ARGUMENT",
        "SECRET_RESULT",
        "1777314901000",
        "1777314902000",
    ] {
        assert!(!debug.contains(marker), "debug leaked {marker}");
    }
}
