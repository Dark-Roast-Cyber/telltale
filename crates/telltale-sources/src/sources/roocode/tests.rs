use std::fs;

use serde_json::json;
use tempfile::tempdir;

use crate::discovery::discover_sources_best_effort;
use crate::parser::{ParseError, parse_source_records};
use telltale_schema::clients::{ClientId, SourceKind};
use telltale_schema::record::RecordKind;
use telltale_schema::source::Source;

fn source(path: std::path::PathBuf) -> Source {
    Source {
        client: ClientId::RooCode,
        kind: SourceKind::UiMessagesJson,
        source_id: "roocode.tasks".to_string(),
        path,
    }
}

#[test]
fn parses_roocode_upstream_shaped_ui_messages_with_direct_history_identity() {
    let source = discover_sources_best_effort(&crate::test_fixture_path("session_stores"))
        .into_iter()
        .find(|source| {
            source.client == ClientId::RooCode
                && source.kind == SourceKind::UiMessagesJson
                && source.path.file_name().and_then(|name| name.to_str())
                    == Some("ui_messages.json")
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
        record.session_id == "roocode-session-a"
            && record.client == "roocode"
            && record.agent.is_none()
            && record.provider.is_none()
            && record.model.is_none()
    }));
    assert_eq!(records[0].kind, RecordKind::UserMessage);
    assert_eq!(
        records[0].timestamp.as_deref(),
        Some("2026-04-27T18:30:00Z")
    );
    assert_eq!(records[1].kind, RecordKind::AssistantMessage);
    assert_eq!(
        records[1].timestamp.as_deref(),
        Some("2026-04-27T18:30:01Z")
    );
}

#[test]
fn parses_roocode_direct_history_identity_and_not_the_directory_name() {
    let source = discover_sources_best_effort(&crate::test_fixture_path("session_stores"))
        .into_iter()
        .find(|source| {
            source.client == ClientId::RooCode
                && source
                    .path
                    .parent()
                    .and_then(|path| path.file_name())
                    .and_then(|name| name.to_str())
                    == Some("task-b")
        })
        .expect("fixture source");

    let (metadata, _) =
        super::native::extract_roocode_native_records(&source).expect("native records");
    assert_eq!(
        metadata.session_namespace.as_deref(),
        Some("roocode-uc001-tool-result")
    );
    let records = parse_source_records(&source).expect("records");
    assert!(
        records
            .iter()
            .all(|record| record.session_id == "roocode-uc001-tool-result")
    );
}

#[test]
fn direct_roocode_history_identity_survives_equal_and_renamed_directories() {
    let temp = tempdir().expect("tempdir");
    for (directory, history_id) in [("same-id", "same-id"), ("renamed-task", "stable-id")] {
        let task = temp.path().join("tasks").join(directory);
        fs::create_dir_all(&task).expect("task directory");
        fs::write(
            task.join("ui_messages.json"),
            r#"[{"type":"say","say":"text","ts":0,"text":"synthetic"}]"#,
        )
        .expect("source");
        fs::write(
            task.join("history_item.json"),
            format!(r#"{{"id":"{history_id}","futureField":"ignored"}}"#),
        )
        .expect("history");

        let records =
            parse_source_records(&source(task.join("ui_messages.json"))).expect("records");
        assert_eq!(records[0].session_id, history_id);
    }
}

#[test]
fn roocode_ui_messages_parse_without_companion_metadata() {
    let temp = tempdir().expect("tempdir");
    let task = temp.path().join("task-without-history");
    fs::create_dir_all(&task).expect("task directory");
    fs::write(
        task.join("ui_messages.json"),
        r#"[{"type":"say","say":"text","ts":0,"text":"synthetic"}]"#,
    )
    .expect("source");

    let records = parse_source_records(&source(task.join("ui_messages.json"))).expect("records");
    assert_eq!(records[0].session_id, "task-without-history");
}

#[test]
fn roocode_metadata_failures_are_bounded_and_never_use_index_identity() {
    let temp = tempdir().expect("tempdir");
    let task = temp.path().join("metadata-task");
    let tasks = task.parent().expect("tasks directory");
    fs::create_dir_all(&task).expect("task directory");
    let ui_path = task.join("ui_messages.json");
    fs::write(
        &ui_path,
        r#"[{"type":"say","say":"text","ts":0,"text":"SECRET_MARKER"}]"#,
    )
    .expect("source");

    fs::write(task.join("history_item.json"), b"{").expect("malformed history");
    let error = parse_source_records(&source(ui_path.clone())).expect_err("malformed history");
    assert!(error.to_string().contains("metadata_history"));
    assert!(!error.to_string().contains("SECRET_MARKER"));
    assert!(!error.to_string().contains(task.to_string_lossy().as_ref()));

    fs::write(task.join("history_item.json"), r#"{"id":""}"#).expect("empty history ID");
    let error = parse_source_records(&source(ui_path.clone())).expect_err("empty history ID");
    assert!(error.to_string().contains("metadata_history_id"));

    fs::remove_file(task.join("history_item.json")).expect("remove history");
    fs::write(
        tasks.join("_index.json"),
        r#"{"version":1,"updatedAt":1,"entries":[{"id":"index-only"}]}"#,
    )
    .expect("index");
    let records = parse_source_records(&source(ui_path.clone())).expect("index-only records");
    assert_eq!(records[0].session_id, "metadata-task");

    fs::write(tasks.join("_index.json"), b"{").expect("malformed index");
    let error = parse_source_records(&source(ui_path.clone())).expect_err("malformed index");
    assert!(error.to_string().contains("metadata_index"));

    fs::write(task.join("history_item.json"), r#"{"id":"direct-history"}"#).expect("history");
    fs::write(
        tasks.join("_index.json"),
        r#"{"version":1,"updatedAt":1,"entries":[{"id":"direct-history"},{"id":"direct-history"}]}"#,
    )
    .expect("duplicate index");
    let error = parse_source_records(&source(ui_path.clone())).expect_err("duplicate index");
    assert!(error.to_string().contains("metadata_index_duplicate"));

    fs::write(
        tasks.join("_index.json"),
        r#"{"version":1,"updatedAt":1,"entries":[{"id":"different-index"}]}"#,
    )
    .expect("conflicting index");
    let error = parse_source_records(&source(ui_path)).expect_err("conflicting index");
    assert!(error.to_string().contains("metadata_disagreement"));
    assert!(!error.to_string().contains("different-index"));
}

#[test]
fn parses_roocode_mcp_request_and_result_without_inventing_correlation() {
    let source = discover_sources_best_effort(&crate::test_fixture_path("session_stores"))
        .into_iter()
        .find(|source| {
            source.client == ClientId::RooCode
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
    assert_eq!(records[0].session_id, "roocode-uc001-tool-result");
    assert_eq!(records[0].kind, RecordKind::UserMessage);
    assert_eq!(records[1].kind, RecordKind::ToolCall);
    assert_eq!(records[1].tool_name.as_deref(), Some("repo_status"));
    assert_eq!(
        records[1].arguments.as_deref(),
        Some("{\"format\":\"json\"}")
    );
    assert_eq!(
        records[1].content,
        "{\"type\":\"use_mcp_tool\",\"serverName\":\"synthetic-mcp\",\"toolName\":\"repo_status\",\"arguments\":\"{\\\"format\\\":\\\"json\\\"}\"}"
    );
    assert_eq!(records[2].kind, RecordKind::ToolResult);
    assert_eq!(records[2].tool_name, None);
    assert!(records[2].content.contains("synthetic marker"));
}

#[test]
fn parses_roocode_partial_mcp_request_writer_shape() {
    let temp = tempdir().expect("tempdir");
    let path = temp.path().join("task").join("ui_messages.json");
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
fn parses_roocode_mcp_resource_request_writer_shape() {
    let temp = tempdir().expect("tempdir");
    let path = temp.path().join("task").join("ui_messages.json");
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
fn preserves_partial_records_and_equal_timestamps_in_source_order() {
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

    let native = super::native::extract_roocode_native_records(&source(path.clone()))
        .expect("native")
        .1;
    assert_eq!(native.len(), 2);
    assert_eq!(native[0].source_sequence, 0);
    assert_eq!(native[1].source_sequence, 1);
    assert_eq!(native[0].partial, Some(true));
    assert_eq!(native[1].partial, Some(false));
    assert_eq!(native[0].timestamp, "1970-01-01T00:00:00Z");
    assert_eq!(native[0].timestamp, native[1].timestamp);
    assert_eq!(native[0].text.as_deref(), Some("first"));
    assert_eq!(native[1].text.as_deref(), Some("second"));
}

#[test]
fn identity_readiness_vectors_reject_unsafe_roocode_coordinates() {
    let temp = tempdir().expect("tempdir");
    let base = vec![
        json!({"type":"say","say":"text","ts":1,"text":"first"}),
        json!({"type":"say","say":"text","ts":2,"text":"second"}),
        json!({"type":"say","say":"text","ts":3,"text":"third"}),
    ];
    let variants = [
        base.clone(),
        base.iter()
            .cloned()
            .chain([json!({"type":"say","say":"text","ts":4,"text":"fourth"})])
            .collect(),
        vec![
            json!({"type":"say","say":"text","ts":1,"text":"edited"}),
            base[1].clone(),
        ],
        vec![base[0].clone(), base[1].clone()],
        vec![base[0].clone(), base[2].clone()],
        vec![
            base[0].clone(),
            json!({"type":"say","say":"text","ts":3,"text":"inserted"}),
            base[1].clone(),
        ],
        vec![base[2].clone(), base[1].clone(), base[0].clone()],
        vec![base[1].clone()],
    ];
    for (index, variant) in variants.into_iter().enumerate() {
        let task = temp.path().join(format!("task-{index}"));
        fs::create_dir_all(&task).expect("task directory");
        let path = task.join("ui_messages.json");
        fs::write(&path, serde_json::to_vec(&variant).expect("JSON")).expect("source");
        let native = super::native::extract_roocode_native_records(&source(path))
            .expect("native")
            .1;
        assert!(native.iter().enumerate().all(|(ordinal, record)| {
            record.source_sequence == ordinal && record.subtype == "text"
        }));
        assert!(
            native
                .iter()
                .all(|record| record.semantic == super::native::RooSemantic::AssistantMessage)
        );
    }

    let first_task = temp.path().join("move-a");
    let second_task = temp.path().join("move-b");
    fs::create_dir_all(&first_task).expect("first task");
    fs::create_dir_all(&second_task).expect("second task");
    let body = serde_json::to_vec(&base).expect("JSON");
    fs::write(first_task.join("ui_messages.json"), &body).expect("first source");
    fs::write(second_task.join("ui_messages.json"), body).expect("second source");
    let first =
        parse_source_records(&source(first_task.join("ui_messages.json"))).expect("first records");
    let second = parse_source_records(&source(second_task.join("ui_messages.json")))
        .expect("second records");
    assert_eq!(first[0].content, second[0].content);
    assert_ne!(first[0].session_id, second[0].session_id);
}

#[test]
fn rejects_roocode_structure_unknown_variants_and_invalid_timestamps_without_fallback() {
    let temp = tempdir().expect("tempdir");
    let cases = [
        (
            "root",
            r#"{"type":"say","say":"text","ts":1,"text":"SECRET_MARKER"}"#,
            "root_not_array",
        ),
        ("record", r#"["SECRET_MARKER"]"#, "record_not_object"),
        (
            "unknown",
            r#"[{"type":"say","say":"future_variant","ts":1,"text":"SECRET_MARKER"}]"#,
            "unknown_subtype",
        ),
        (
            "timestamp",
            r#"[{"type":"say","say":"text","ts":1.5,"text":"SECRET_MARKER"}]"#,
            "invalid_timestamp",
        ),
        (
            "timestamp-range",
            r#"[{"type":"say","say":"text","ts":9223372036854775807,"text":"SECRET_MARKER"}]"#,
            "timestamp_out_of_range",
        ),
    ];
    for (name, body, category) in cases {
        let path = temp.path().join(format!("{name}.json"));
        fs::write(&path, body).expect("source");
        let error = parse_source_records(&source(path.clone())).expect_err("terminal error");
        assert!(matches!(error, ParseError::SourceContract { .. }));
        assert!(error.to_string().contains(category));
        assert!(!error.to_string().contains("SECRET_MARKER"));
        assert!(!format!("{error:?}").contains("SECRET_MARKER"));
        assert!(!error.to_string().contains(path.to_string_lossy().as_ref()));
    }
}

#[test]
fn malformed_json_is_terminal_even_when_generic_json_would_have_returned_other() {
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
fn native_debug_redacts_roocode_message_and_tool_fields() {
    let temp = tempdir().expect("tempdir");
    let path = temp.path().join("task").join("ui_messages.json");
    fs::create_dir_all(path.parent().expect("task parent")).expect("task directory");
    fs::write(
        &path,
        r#"[
          {"type":"ask","ask":"use_mcp_server","ts":1777314901000,"text":"{\"type\":\"use_mcp_tool\",\"serverName\":\"SECRET_SERVER\",\"toolName\":\"SECRET_TOOL\",\"arguments\":\"{\\\"secret\\\":\\\"SECRET_ARGUMENT\\\"}\"}"},
          {"type":"say","say":"mcp_server_response","ts":1777314902000,"text":"SECRET_RESULT"}
        ]"#,
    )
    .expect("source");
    fs::write(
        path.parent()
            .expect("task directory")
            .join("history_item.json"),
        r#"{"id":"SECRET_SESSION"}"#,
    )
    .expect("history");

    let native = super::native::extract_roocode_native_records(&source(path)).expect("native");
    let debug = format!("{native:?}");
    for marker in [
        "SECRET_SERVER",
        "SECRET_TOOL",
        "SECRET_ARGUMENT",
        "SECRET_RESULT",
        "SECRET_SESSION",
        "1777314901000",
        "1777314902000",
    ] {
        assert!(!debug.contains(marker), "debug leaked {marker}");
    }
}
