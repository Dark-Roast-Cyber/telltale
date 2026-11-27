use rusqlite::Connection;
use telltale_schema::clients::{ClientId, SourceKind};
use telltale_schema::observation::{
    CapabilityAvailability, CapabilityId, Fidelity, IngestionMode, JsonValue, MessageRole,
    ObservationBody, ObservationFamily, ObservationStage, ObservedAt, ToolStatus,
};
use telltale_schema::source::Source;
use tempfile::tempdir;

use super::super::native::OpenCodeSqliteReadOptions;
use super::project_opencode_native_records;

const OBSERVED_AT: &str = "2026-09-03T12:00:00Z";

fn source(path: std::path::PathBuf) -> Source {
    Source {
        client: ClientId::OpenCode,
        kind: SourceKind::Sqlite,
        source_id: "opencode.sqlite".to_owned(),
        path,
    }
}

fn project(path: std::path::PathBuf) -> Vec<telltale_schema::observation::CanonicalObservationV2> {
    project_opencode_native_records(
        &super::super::native::extract_sqlite_native_source(
            &source(path),
            OpenCodeSqliteReadOptions::default(),
        )
        .unwrap()
        .records,
        &ObservedAt::new(OBSERVED_AT).unwrap(),
    )
    .expect("canonical observations")
}

fn database(schema: &str) -> (tempfile::TempDir, Connection, Source) {
    let directory = tempdir().unwrap();
    let path = directory.path().join("synthetic-opencode.db");
    let connection = Connection::open(&path).unwrap();
    connection.execute_batch(schema).unwrap();
    let source = source(path);
    (directory, connection, source)
}

fn message_schema() -> &'static str {
    "create table message (id text, session_id text, time_created integer, time_updated integer, data text);"
}

fn part_schema() -> &'static str {
    "create table message (id text, session_id text, time_created integer, time_updated integer, data text);
         create table part (id text, message_id text, session_id text, time_created integer, time_updated integer, data text);"
}

fn insert_part(
    connection: &Connection,
    id: &str,
    message_id: &str,
    updated: i64,
    data: serde_json::Value,
) {
    connection
            .execute(
                "insert into part (id, message_id, session_id, time_created, time_updated, data) values (?1, ?2, ?3, ?4, ?5, ?6)",
                (id, message_id, "sqlite-test-session", updated, updated, data.to_string()),
            )
            .unwrap();
}

#[test]
fn text_parts_use_joined_role_without_an_envelope_duplicate() {
    let (_directory, connection, source) = database(part_schema());
    connection
        .execute(
            "insert into message values (?1, ?2, ?3, ?4, ?5)",
            (
                "message-text",
                "sqlite-session",
                1_000_i64,
                9_999_i64,
                r#"{"role":"assistant","modelID":"fixture-model"}"#,
            ),
        )
        .unwrap();
    insert_part(
        &connection,
        "part-text",
        "message-text",
        2_000,
        serde_json::json!({"type":"text","text":"Synthetic text","time":{"start":1775000000000_i64}}),
    );
    let observations = project(source.path);
    assert_eq!(observations.len(), 1);
    let ObservationBody::Message(message) = observations[0].body() else {
        panic!("expected message")
    };
    assert_eq!(message.role(), Some(MessageRole::Assistant));
    assert_eq!(
        message.content(),
        Some(&JsonValue::string("Synthetic text"))
    );
    assert_eq!(observations[0].identity_basis().child_ordinal(), 0);
    assert_eq!(observations[0].source().native_id(), Some("part-text"));
    assert_eq!(
        observations[0].session_id().unwrap().value(),
        "sqlite-test-session"
    );
    assert_eq!(
        observations[0].occurred_at().unwrap().as_str(),
        "2026-03-31T23:33:20Z"
    );
}

#[test]
fn canonical_projection_preserves_part_cursor_and_limit() {
    let (_directory, connection, source) = database(part_schema());
    connection
        .execute(
            "insert into message values (?1, ?2, ?3, ?4, ?5)",
            (
                "message-cursor",
                "sqlite-session",
                1_000_i64,
                1_000_i64,
                r#"{"role":"assistant"}"#,
            ),
        )
        .unwrap();
    insert_part(
        &connection,
        "part-old",
        "message-cursor",
        1_000,
        serde_json::json!({"type":"text","text":"old"}),
    );
    insert_part(
        &connection,
        "part-new",
        "message-cursor",
        2_000,
        serde_json::json!({"type":"text","text":"new"}),
    );

    let native = super::super::native::extract_sqlite_native_source(
        &source,
        OpenCodeSqliteReadOptions {
            part_min_time_updated: Some(1_001),
            part_limit: 1,
            resume_high_water: None,
            ..Default::default()
        },
    )
    .unwrap();
    let observations =
        project_opencode_native_records(&native.records, &ObservedAt::new(OBSERVED_AT).unwrap())
            .unwrap();
    assert_eq!(observations.len(), 1);
    let ObservationBody::Message(message) = observations[0].body() else {
        panic!("expected message")
    };
    assert_eq!(message.content(), Some(&JsonValue::string("new")));
    assert_eq!(observations[0].source().native_id(), Some("part-new"));
}

#[test]
fn native_ids_ignore_content_path_rowid_and_cursor_time() {
    let (_first_dir, first, first_source) = database(part_schema());
    let (_second_dir, second, second_source) = database(part_schema());
    for connection in [&first, &second] {
        connection
            .execute(
                "insert into message values (?1, ?2, ?3, ?4, ?5)",
                (
                    "message-context",
                    "sqlite-test-session",
                    1_000_i64,
                    1_000_i64,
                    r#"{"role":"assistant"}"#,
                ),
            )
            .unwrap();
    }
    for (connection, id, text, updated) in [
        (&first, "part-stable", "first content", 10_i64),
        (&second, "part-stable", "changed content", 20_i64),
    ] {
        insert_part(
            connection,
            id,
            "message-context",
            updated,
            serde_json::json!({"type":"text","text":text}),
        );
    }
    let left = project(first_source.path);
    let right = project(second_source.path);
    assert_eq!(left[0].observation_id(), right[0].observation_id());
    assert_ne!(
        left[0]
            .semantic_comparison()
            .compare(right[0].semantic_comparison()),
        telltale_schema::observation::SemanticReplayVerdict::Equivalent
    );
    assert_eq!(left[0].source().native_id(), Some("part-stable"));
    assert_eq!(right[0].source().native_id(), Some("part-stable"));
    assert_eq!(left[0].identity_basis().child_ordinal(), 0);
    assert_eq!(right[0].identity_basis().child_ordinal(), 0);
}

#[test]
fn missing_part_id_fails_closed_without_content_substitution() {
    let (_directory, connection, source) = database(part_schema());
    connection
        .execute(
            "insert into message values (?1, ?2, ?3, ?4, ?5)",
            (
                "message-context",
                "sqlite-test-session",
                1_000_i64,
                1_000_i64,
                r#"{"role":"assistant"}"#,
            ),
        )
        .unwrap();
    insert_part(
        &connection,
        "",
        "message-context",
        1,
        serde_json::json!({"type":"text","text":"Synthetic secret marker"}),
    );
    let error = project_opencode_native_records(
        &super::super::native::extract_sqlite_native_source(
            &source,
            OpenCodeSqliteReadOptions::default(),
        )
        .unwrap()
        .records,
        &ObservedAt::new(OBSERVED_AT).unwrap(),
    )
    .unwrap_err();
    assert_eq!(error.code(), "replay_unverifiable");
    assert!(!error.to_string().contains("Synthetic secret marker"));
}

#[test]
fn tool_states_emit_only_the_directly_reported_lifecycle() {
    let (_directory, connection, source) = database(part_schema());
    for (id, status, extra) in [
        (
            "part-pending",
            "pending",
            serde_json::json!({"input":{"command":"echo pending"}}),
        ),
        (
            "part-running",
            "running",
            serde_json::json!({"input":{"command":"echo running"},"time":{"start":1775000000000_i64}}),
        ),
        (
            "part-completed",
            "completed",
            serde_json::json!({"input":{"command":"echo complete"},"output":{"ok":true},"time":{"start":1775000000000_i64,"end":1775000001000_i64}}),
        ),
        (
            "part-error",
            "error",
            serde_json::json!({"error":{"message":"Synthetic failure"}}),
        ),
    ] {
        insert_part(
                &connection,
                id,
                "missing-message",
                id.len() as i64,
                serde_json::Value::Object(serde_json::json!({"type":"tool","tool":"shell","callID":id,"state":{"status":status}}).as_object().unwrap().iter().chain(extra.as_object().unwrap().iter()).map(|(k,v)| (k.clone(),v.clone())).collect::<serde_json::Map<_,_>>()),
            );
    }
    let observations = project(source.path);
    assert_eq!(
        observations
            .iter()
            .filter(|item| item.stage() == ObservationStage::ToolRequested)
            .count(),
        1
    );
    assert_eq!(
        observations
            .iter()
            .filter(|item| item.stage() == ObservationStage::ToolExecutionStarted)
            .count(),
        1
    );
    assert_eq!(
        observations
            .iter()
            .filter(|item| item.stage() == ObservationStage::ToolExecutionCompleted)
            .count(),
        2
    );
    assert_eq!(
        observations
            .iter()
            .filter(|item| item.stage() == ObservationStage::ToolResultReturned)
            .count(),
        2
    );
    assert!(
        observations
            .iter()
            .all(|item| item.stage() != ObservationStage::ToolProposed)
    );
    assert!(observations.iter().all(|item| item.stage()
        != ObservationStage::ToolExecutionCompleted
        || item.body().kind() == ObservationFamily::Tool));
    let completed = observations
        .iter()
        .find(|item| {
            item.source().native_id() == Some("part-completed")
                && item.stage() == ObservationStage::ToolExecutionCompleted
        })
        .unwrap();
    let ObservationBody::Tool(tool) = completed.body() else {
        panic!("expected tool")
    };
    assert_eq!(tool.reported_status(), None);
    assert_eq!(
        tool.result(),
        Some(&JsonValue::object([(String::from("ok"), JsonValue::Bool(true))]).unwrap())
    );
    let error = observations
        .iter()
        .find(|item| {
            item.source().native_id() == Some("part-error")
                && item.stage() == ObservationStage::ToolExecutionCompleted
        })
        .unwrap();
    let ObservationBody::Tool(tool) = error.body() else {
        panic!("expected tool")
    };
    assert_eq!(tool.reported_status(), Some(ToolStatus::Failed));
    assert_eq!(
        tool.result(),
        Some(
            &JsonValue::object([(
                String::from("message"),
                JsonValue::string("Synthetic failure")
            )])
            .unwrap()
        )
    );
}

#[test]
fn source_json_string_arguments_remain_strings_without_parsed_facets() {
    let (_directory, connection, source) = database(part_schema());
    let encoded_arguments = r#"{"command":"printf synthetic","file_path":"synthetic.txt","url":"https://example.invalid"}"#;
    insert_part(
        &connection,
        "part-string-arguments",
        "missing-message",
        1,
        serde_json::json!({
            "type": "tool",
            "tool": "shell",
            "state": {"status": "pending", "input": encoded_arguments}
        }),
    );

    let observations = project(source.path);
    assert_eq!(observations.len(), 1);
    let ObservationBody::Tool(tool) = observations[0].body() else {
        panic!("expected tool observation")
    };
    assert_eq!(
        tool.arguments(),
        Some(&JsonValue::string(encoded_arguments))
    );
    assert!(!observations[0].facets().contains_key("command.text"));
    assert!(!observations[0].facets().contains_key("resource.path"));
    assert!(!observations[0].facets().contains_key("network.destination"));
    assert!(
        observations
            .iter()
            .all(|item| item.kind() != ObservationFamily::Network)
    );
}

#[test]
fn missing_tool_status_does_not_fabricate_a_request() {
    let (_directory, connection, source) = database(part_schema());
    insert_part(
        &connection,
        "part-missing-status",
        "missing-message",
        1,
        serde_json::json!({
            "type": "tool",
            "tool": "shell",
            "state": {"input": {"command": "printf synthetic"}}
        }),
    );

    let observations = project(source.path);
    assert!(observations.is_empty());
}

#[test]
fn empty_or_ambiguous_tool_status_fails_closed_without_a_request() {
    for (index, status) in ["", "queued"].into_iter().enumerate() {
        let (_directory, connection, source) = database(part_schema());
        insert_part(
            &connection,
            &format!("part-invalid-status-{index}"),
            "missing-message",
            index as i64 + 1,
            serde_json::json!({
                "type": "tool",
                "tool": "shell",
                "state": {"status": status}
            }),
        );

        let error = project_opencode_native_records(
            &super::super::native::extract_sqlite_native_source(
                &source,
                OpenCodeSqliteReadOptions::default(),
            )
            .unwrap()
            .records,
            &ObservedAt::new(OBSERVED_AT).unwrap(),
        )
        .unwrap_err();
        assert_eq!(error.code(), "unknown_tool_status");
    }
}

#[test]
fn malformed_tool_state_fails_closed_without_leaking_source_values() {
    let (_directory, connection, source) = database(part_schema());
    insert_part(
        &connection,
        "part-invalid-state",
        "missing-message",
        1,
        serde_json::json!({
            "type":"tool",
            "tool":"shell",
            "state":"Synthetic malformed state"
        }),
    );

    let error = project_opencode_native_records(
        &super::super::native::extract_sqlite_native_source(
            &source,
            OpenCodeSqliteReadOptions::default(),
        )
        .unwrap()
        .records,
        &ObservedAt::new(OBSERVED_AT).unwrap(),
    )
    .unwrap_err();
    assert_eq!(error.code(), "invalid_tool_state");
    assert!(!error.to_string().contains("Synthetic malformed state"));
}

#[test]
fn terminal_pair_reuses_native_id_and_child_zero_with_structured_values_and_facets() {
    let (_directory, connection, source) = database(part_schema());
    insert_part(
        &connection,
        "part-terminal",
        "missing-message",
        1,
        serde_json::json!({
            "type":"tool","tool":"shell","callID":"call-terminal",
            "state":{"status":"completed","input":{"command":"git status","file_path":"synthetic.txt"},"output":{"status":"ok"}}
        }),
    );
    let observations = project(source.path);
    assert_eq!(observations.len(), 2);
    assert_ne!(
        observations[0].observation_id(),
        observations[1].observation_id()
    );
    assert_eq!(observations[0].source().native_id(), Some("part-terminal"));
    assert_eq!(observations[1].source().native_id(), Some("part-terminal"));
    assert_eq!(observations[0].identity_basis().child_ordinal(), 0);
    assert_eq!(observations[1].identity_basis().child_ordinal(), 0);
    assert_eq!(
        observations[0].correlation().call_id().unwrap().value(),
        "call-terminal"
    );
    assert_eq!(
        observations[1].correlation().call_id().unwrap().origin(),
        telltale_schema::observation::CorrelationOrigin::SourceReported
    );
    assert_eq!(
        observations[0].facets()["command.text"].value(),
        &JsonValue::string("git status")
    );
    assert_eq!(
        observations[0].facets()["resource.path"].value(),
        &JsonValue::string("synthetic.txt")
    );
    assert!(observations.iter().all(|item| !matches!(
        item.kind(),
        ObservationFamily::File | ObservationFamily::Process | ObservationFamily::Network
    )));
}

#[test]
fn message_only_rows_map_content_and_keep_session_source_reported() {
    let (_directory, connection, source) = database(message_schema());
    connection
        .execute(
            "insert into message values (?1, ?2, ?3, ?4, ?5)",
            (
                "message-only",
                "message-session",
                1_000_i64,
                50_000_i64,
                r#"{"type":"user","time":"2026-04-27T12:00:00Z","content":"Synthetic prompt"}"#,
            ),
        )
        .unwrap();
    let observations = project(source.path);
    assert_eq!(observations.len(), 1);
    assert_eq!(observations[0].source().native_id(), Some("message-only"));
    assert_eq!(
        observations[0].session_id().unwrap().value(),
        "message-session"
    );
    assert_eq!(observations[0].observed_at().as_str(), OBSERVED_AT);
    assert_eq!(
        observations[0].occurred_at().unwrap().as_str(),
        "2026-04-27T12:00:00Z"
    );
}

#[test]
fn provenance_capabilities_and_missing_call_id_are_explicit() {
    let (_directory, connection, source) = database(part_schema());
    insert_part(
        &connection,
        "part-no-call",
        "missing-message",
        1,
        serde_json::json!({"type":"tool","tool":"shell","state":{"status":"pending","input":{"command":"printf synthetic"}}}),
    );
    let observations = project(source.path);
    let observation = &observations[0];
    assert_eq!(observation.correlation().call_id(), None);
    assert_eq!(
        observation.source().ingestion_mode(),
        IngestionMode::SessionStore
    );
    assert_eq!(observation.source().adapter_type(), "opencode");
    assert_eq!(observation.source().adapter_id(), "opencode.sqlite");
    assert_eq!(observation.source().adapter_version(), None);
    assert_eq!(observation.source().source_path_hash(), None);
    assert_eq!(observation.source().fidelity(), Fidelity::PartialStructured);
    let capabilities = observation.capability_context().unwrap();
    assert_eq!(
        capabilities.resolve(CapabilityId::ToolCall),
        CapabilityAvailability::Supported
    );
    assert_eq!(
        capabilities.resolve(CapabilityId::UserContext),
        CapabilityAvailability::Supported
    );
    assert_eq!(
        capabilities.resolve(CapabilityId::ToolExecution),
        CapabilityAvailability::Supported
    );
}

#[test]
fn empty_source_session_is_omitted_instead_of_reported() {
    let (_directory, connection, source) = database(part_schema());
    connection
        .execute(
            "insert into part values (?1, ?2, ?3, ?4, ?5, ?6)",
            (
                "part-empty-session",
                "missing-message",
                "",
                1_i64,
                1_i64,
                serde_json::json!({
                    "type":"tool",
                    "tool":"shell",
                    "state":{"status":"pending"}
                })
                .to_string(),
            ),
        )
        .unwrap();

    let observations = project(source.path);
    assert_eq!(observations.len(), 1);
    assert_eq!(observations[0].session_id(), None);
}
