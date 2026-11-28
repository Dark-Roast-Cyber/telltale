use super::*;

#[test]
fn malformed_unsupported_and_identity_less_rows_fail_without_leaking_payloads() {
    let secret = "synthetic-secret-marker";
    let unsupported: Vec<(&str, Value, &str)> = vec![
        (
            "future",
            json!({"type": "future-variant", "text": secret, "time": {"created": T0}}),
            "unknown_message_variant",
        ),
        (
            "content",
            assistant(json!([{"type": "future-content", "text": secret}]), T0),
            "unknown_content_variant",
        ),
        (
            "status",
            assistant(
                json!([tool_entry(
                    "call",
                    None,
                    json!({"status": "queued", "input": {"command": secret}}),
                    json!({"created": T0})
                )]),
                T0,
            ),
            "unknown_tool_status",
        ),
        (
            "state",
            assistant(
                json!([tool_entry(
                    "call",
                    None,
                    json!(secret),
                    json!({"created": T0})
                )]),
                T0,
            ),
            "invalid_tool_state",
        ),
        (
            "executed",
            assistant(
                json!([{"type": "tool", "id": "call", "name": "bash", "executed": "yes",
            "state": {"status": "running", "input": {"command": secret}, "metadata": {}}, "time": {"created": T0}}]),
                T0,
            ),
            "invalid_tool_state",
        ),
        (
            "empty_result",
            assistant(
                json!([tool_entry(
                    "call",
                    None,
                    json!({"status": "completed", "input": {}, "content": []}),
                    json!({"created": T0})
                )]),
                T0,
            ),
            "invalid_tool_state",
        ),
        (
            "no_tool_id",
            assistant(
                json!([{"type": "tool", "name": "bash", "state": {"status": "streaming", "input": secret}, "time": {"created": T0}}]),
                T0,
            ),
            "missing_tool_id",
        ),
        (
            "no_tool_name",
            assistant(
                json!([{"type": "tool", "id": "call", "state": {"status": "streaming", "input": secret}, "time": {"created": T0}}]),
                T0,
            ),
            "missing_tool_name",
        ),
        (
            "content_type",
            json!({"type": "assistant", "content": secret, "time": {"created": T0}}),
            "invalid_assistant_content",
        ),
        (
            "user_text",
            json!({"type": "user", "text": {"secret": secret}, "time": {"created": T0}}),
            "invalid_message_text",
        ),
        (
            "shell_status",
            json!({"type": "shell", "shellID": "sh", "command": secret, "status": "paused", "time": {"created": T0}}),
            "unknown_shell_status",
        ),
        (
            "shell_command",
            json!({"type": "shell", "shellID": "sh", "status": "running", "time": {"created": T0}}),
            "invalid_shell_state",
        ),
    ];
    for (name, data, code) in unsupported {
        let store = Store::v2();
        store.message("msg_bad", 1, T0, data);
        let error = store.acquire_default_error();
        assert_eq!(mapping_code(error), code, "{name}");
        assert!(!format!("{error} {error:?}").contains(secret), "{name}");
    }

    let store = Store::v2();
    store.message("", 1, T0, user(secret, T0));
    assert_eq!(
        mapping_code(store.acquire_default_error()),
        "replay_unverifiable"
    );

    for (name, statement) in [
        (
            "not json",
            "insert into session_message values ('m','ses_synthetic','user',1,1,1,'not json synthetic-secret-marker')",
        ),
        (
            "array data",
            "insert into session_message values ('m','ses_synthetic','user',1,1,1,'[\"synthetic-secret-marker\"]')",
        ),
        (
            "id in data",
            "insert into session_message values ('m','ses_synthetic','user',1,1,1,'{\"id\":\"other\",\"text\":\"synthetic-secret-marker\"}')",
        ),
        (
            "type in data",
            "insert into session_message values ('m','ses_synthetic','user',1,1,1,'{\"type\":\"user\",\"text\":\"synthetic-secret-marker\"}')",
        ),
        (
            "text seq",
            "insert into session_message values ('m','ses_synthetic','user','one',1,1,'{\"text\":\"synthetic-secret-marker\"}')",
        ),
        (
            "negative seq",
            "insert into session_message values ('m','ses_synthetic','user',-1,1,1,'{\"text\":\"synthetic-secret-marker\"}')",
        ),
        (
            "text time",
            "insert into session_message values ('m','ses_synthetic','user',1,1,'late','{\"text\":\"synthetic-secret-marker\"}')",
        ),
        (
            "null type",
            "insert into session_message values ('m','ses_synthetic',null,1,1,1,'{\"text\":\"synthetic-secret-marker\"}')",
        ),
    ] {
        let store = Store::new(&V2_SCHEMA.replace("NOT NULL", ""));
        store.session("ses_synthetic");
        store.connection.execute(statement, []).unwrap();
        let error = store.acquire_default_error();
        assert_eq!(error, AcquisitionError::SourceRead, "{name}");
        assert!(!format!("{error} {error:?}").contains(secret), "{name}");
    }

    let store = Store::new(&V2_SCHEMA.replace("NOT NULL", ""));
    store.session("ses_synthetic");
    store
        .connection
        .execute(
            "insert into session_message values ('m',null,'user',1,1,1,'{\"text\":\"t\"}')",
            [],
        )
        .unwrap();
    assert_eq!(
        mapping_code(store.acquire_default_error()),
        "missing_session_id"
    );

    let store = Store::new(&V2_SCHEMA.replace(
        "`id` text PRIMARY KEY, `session_id`",
        "`id` text, `session_id`",
    ));
    store.session("ses_synthetic");
    store.message("msg_dup", 1, T0, user("first", T0));
    store.message("msg_dup", 2, T0, user("second", T0));
    assert_eq!(
        mapping_code(store.acquire_default_error()),
        "ambiguous_source_identity"
    );
}

#[test]
fn schema_selection_is_deterministic_and_never_falls_back_to_legacy() {
    let legacy_rows = |store: &Store| {
        store
            .connection
            .execute_batch(
                "insert into message values ('legacy-message','ses_legacy',1,1,'{\"role\":\"user\"}');
                 insert into part values ('legacy-part','legacy-message','ses_legacy',1,9999999999999,'{\"type\":\"text\",\"text\":\"stale legacy text\"}');",
            )
            .unwrap();
    };

    // Mixed store: v2 wins even when legacy rows look newer.
    let mixed = Store::new(&format!("{V2_SCHEMA}{LEGACY_SCHEMA}"));
    mixed.session("ses_synthetic");
    legacy_rows(&mixed);
    mixed.message("msg_v2", 1, T0, user("current v2 text", T0));
    let batch = mixed.acquire_default();
    assert_eq!(
        shape(&batch),
        vec![("msg_v2".to_owned(), 0, ObservationStage::MessageObserved)]
    );
    assert_eq!(
        batch.progress,
        AcquisitionProgress::OpenCodeSessionMessages {
            message_max_time_updated: Some(T0),
            window_complete: true,
        }
    );
    assert_eq!(batch.accounting.sessions.len(), 1);

    // An empty v2 schema beside legacy rows is still the v2 schema.
    let migrated = Store::new(&format!("{V2_SCHEMA}{LEGACY_SCHEMA}"));
    legacy_rows(&migrated);
    let batch = migrated.acquire_default();
    assert!(batch.observations.is_empty());
    assert_eq!(
        batch.progress,
        AcquisitionProgress::OpenCodeSessionMessages {
            message_max_time_updated: None,
            window_complete: true,
        }
    );

    // Legacy-only stores keep the legacy path and progress coordinate.
    let legacy = Store::new(LEGACY_SCHEMA);
    legacy_rows(&legacy);
    let batch = legacy.acquire_default();
    assert_eq!(batch.observations.len(), 1);
    assert_eq!(
        batch.progress,
        AcquisitionProgress::OpenCodeSqlite {
            part_max_time_updated: Some(9_999_999_999_999)
        }
    );

    // Partial or column-incomplete v2 schemas fail, with or without legacy tables.
    for schema in [
        "create table session_message (id text, session_id text, type text, seq integer, time_updated integer, data text);".to_owned(),
        "create table session_v2 (id text, agent text, model text);".to_owned(),
        format!("create table session_message (id text, session_id text, type text, seq integer, time_updated integer, data text);{LEGACY_SCHEMA}"),
        "create table session_message (id text, session_id text, type text, time_updated integer, data text);
         create table session_v2 (id text, agent text, model text);".to_owned(),
        "create table session_message (id text, session_id text, type text, seq integer, time_updated integer, data text);
         create table session_v2 (id text, agent text);".to_owned(),
    ] {
        let store = Store::new(&schema);
        if schema.contains("create table part") {
            legacy_rows(&store);
        }
        let error = store.acquire_default_error();
        assert_eq!(error, AcquisitionError::UnsupportedSourceSchema, "{schema}");
        assert_eq!(error.code(), "unsupported_source_schema");
    }
}

#[test]
fn admission_caps_and_canonical_budgets_reject_atomically() {
    // Unselected session columns and other tables are never admitted.
    let store = Store::v2();
    store
        .connection
        .execute_batch(
            "update session_v2 set metadata = cast(zeroblob(8388609) as text), directory = cast(zeroblob(8388609) as text);
             insert into credential values ('cred','i','label',cast(zeroblob(8388609) as text),null,null,1,1,1);",
        )
        .unwrap();
    store.message("msg_ok", 1, T0, user("fits", T0));
    assert_eq!(store.acquire_default().observations.len(), 1);

    // Joined session context is charged on every selected occurrence.
    store
        .connection
        .execute(
            "update session_v2 set agent = cast(zeroblob(8388609) as text)",
            [],
        )
        .unwrap();
    assert_eq!(store.acquire_default_error(), AcquisitionError::SourceRead);

    let store = Store::v2();
    for seq in 1..=3 {
        store.message(&format!("msg_{seq}"), seq, T0, user("row", T0));
    }
    let mut rows = SqliteAdmission::with_limits(usize::MAX, 2);
    assert!(
        extract_incremental_messages(&store.connection, T0, 10, 2, &mut rows, usize::MAX).is_err()
    );
    let mut exact = SqliteAdmission::with_limits(usize::MAX, 3);
    assert!(
        extract_incremental_messages(&store.connection, T0, 10, 2, &mut exact, usize::MAX).is_ok()
    );

    // All-text results use the direct-text budget; results with file parts
    // stay structured and keep ordinary nested string bounds.
    let long = "x".repeat(60_000);
    let store = Store::v2();
    store.message(
        "msg_long",
        1,
        T0,
        assistant(
            json!([completed_tool(
                "call",
                "bash",
                json!({"command": "cat"}),
                &long,
                T0
            )]),
            T0,
        ),
    );
    assert_eq!(store.acquire_default().observations.len(), 2);
    let store = Store::v2();
    store.message(
        "msg_parts",
        1,
        T0,
        assistant(
            json!([tool_entry(
                "call",
                Some(false),
                json!({"status": "completed", "input": {}, "content": [
                {"type": "text", "text": "z"},
                {"type": "file", "uri": "file:///synthetic", "mime": "text/plain", "name": "y".repeat(5_000)}]}),
                json!({"created": T0})
            )]),
            T0,
        ),
    );
    // A result over its bound is replaced and recorded; the row is projected.
    let replaced_bound = |store: &Store, native_id: &str, marker: &str| {
        let batch = store.acquire_default();
        assert!(batch.quarantined.is_empty(), "{:?}", batch.quarantined);
        let [unit] = batch.bounded.as_slice() else {
            panic!("expected one bounded unit: {:?}", batch.bounded)
        };
        assert_eq!(
            (
                unit.native_id.as_str(),
                unit.source_sequence,
                unit.target,
                unit.dimension
            ),
            (
                native_id,
                1,
                telltale_schema::observation::BoundedTarget::Result,
                BoundDimension::StringBytes
            )
        );
        assert!(!format!("{:?}", batch.bounded).contains(marker));
        let replaced = batch
            .observations
            .iter()
            .filter_map(|observation| match observation.body() {
                ObservationBody::Tool(tool) => Some(tool.bounded_values().to_vec()),
                _ => None,
            })
            .flatten()
            .map(|value| (value.target(), value.dimension()))
            .collect::<Vec<_>>();
        let [(target, dimension)] = replaced.as_slice() else {
            panic!("expected one replaced value: {replaced:?}")
        };
        assert_eq!(*target, telltale_schema::observation::BoundedTarget::Result);
        *dimension
    };
    assert_eq!(
        replaced_bound(&store, "msg_parts", &"y".repeat(16)),
        BoundDimension::StringBytes
    );
    let store = Store::v2();
    store.message(
        "msg_huge",
        1,
        T0,
        assistant(
            json!([completed_tool(
                "call",
                "bash",
                json!({"command": "cat"}),
                &"x".repeat(65_537),
                T0
            )]),
            T0,
        ),
    );
    assert_eq!(
        replaced_bound(&store, "msg_huge", &"x".repeat(16)),
        BoundDimension::StringBytes
    );
}
