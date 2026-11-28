use super::*;

#[test]
fn persists_sqlite_ingestion_cursors_by_source_and_table() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("sqlite-cursor-state.json");
    let source = Source {
        client: ClientId::OpenCode,
        kind: SourceKind::Sqlite,
        source_id: "opencode.sqlite".to_string(),
        path: Path::new("/home/user/.local/share/opencode/opencode.db").to_path_buf(),
    };

    let mut state = ScanState::default();
    state.observe_sqlite_ingestion_cursor(&source, "part", 1_775_000_001_000, 1234);
    state.save(&path).expect("save");

    let reloaded = ScanState::load(&path).expect("reload");
    assert_eq!(
        reloaded.sqlite_ingestion_cursor_time_updated(&source, "part"),
        Some(1_775_000_001_000)
    );
    assert_eq!(
        reloaded.sqlite_ingestion_cursor_time_updated(&source, "message"),
        None
    );
}

#[test]
fn sqlite_cursor_high_water_cannot_regress_after_successful_observation() {
    let source = Source {
        client: ClientId::OpenCode,
        kind: SourceKind::Sqlite,
        source_id: "opencode.sqlite".into(),
        path: "synthetic.db".into(),
    };
    let mut state = ScanState::default();
    state.observe_sqlite_ingestion_cursor(&source, "part", 1_000, 1);
    state.observe_sqlite_ingestion_cursor(&source, "part", 900, 2);
    assert_eq!(
        state.sqlite_ingestion_cursor_time_updated(&source, "part"),
        Some(1_000)
    );
}

#[test]
fn sqlite_unfinished_overlap_state_is_validated_and_migrates_without_losing_the_cut() {
    let source = Source {
        client: ClientId::OpenCode,
        kind: SourceKind::Sqlite,
        source_id: "opencode.sqlite".into(),
        path: Path::new("/synthetic/overlap.db").to_path_buf(),
    };
    let mut state = ScanState::default();
    state.observe_sqlite_ingestion_cursor(&source, "session_message", 1_000_000, 1);
    state.observe_sqlite_ingestion_drain(&source, "session_message", 600_000, 2);
    let bytes = state.canonical_bytes().unwrap();
    let loaded = ScanState::validate_native_bytes(&bytes).unwrap();
    assert_eq!(loaded.canonical_bytes().unwrap(), bytes);
    assert_eq!(
        loaded.sqlite_ingestion_continue_after(&source, "session_message"),
        Some(600_000)
    );
    let value: Value = serde_json::from_slice(&bytes).unwrap();
    let key = value["sqlite_ingestion_cursors"]
        .as_object()
        .unwrap()
        .keys()
        .next()
        .unwrap()
        .clone();
    for cut in [i64::MIN, -1, 0] {
        let mut signed = value.clone();
        signed["sqlite_ingestion_cursors"][&key]["last_time_updated"] = 0.into();
        signed["sqlite_ingestion_cursors"][&key]["continue_after_time_updated"] = cut.into();
        let bytes = serde_json::to_vec(&signed).unwrap();
        let loaded = ScanState::validate_native_bytes(&bytes).unwrap();
        assert_eq!(
            loaded.sqlite_ingestion_continue_after(&source, "session_message"),
            Some(cut)
        );
        let repeated =
            ScanState::validate_native_bytes(&loaded.canonical_bytes().unwrap()).unwrap();
        assert_eq!(
            repeated.sqlite_ingestion_continue_after(&source, "session_message"),
            Some(cut)
        );
    }
    for (field, invalid) in [
        ("continue_after_time_updated", serde_json::json!(1_000_001)),
        ("continue_after_time_updated", Value::Null),
        ("continue_after_time_updated", serde_json::json!("600000")),
        ("draining", serde_json::json!(false)),
        ("table", serde_json::json!("part")),
        ("client", serde_json::json!("codex")),
        ("source_id", serde_json::json!("opencode.sqlite.lookalike")),
    ] {
        let mut bad = value.clone();
        bad["sqlite_ingestion_cursors"][&key][field] = invalid;
        let error =
            ScanState::validate_native_bytes(&serde_json::to_vec(&bad).unwrap()).expect_err(field);
        let message = error.to_string();
        assert!(message.contains("invalid"), "{field}: {message}");
        assert!(!message.contains("v0.7.0"), "{field}: {message}");
    }
    // Old drain state remains readable, but has no trustworthy strict cut.
    let mut old = value;
    old["sqlite_ingestion_cursors"][&key]
        .as_object_mut()
        .unwrap()
        .remove("continue_after_time_updated");
    let old = ScanState::validate_native_bytes(&serde_json::to_vec(&old).unwrap()).unwrap();
    let cursor = old
        .sqlite_ingestion_cursors
        .values()
        .next()
        .expect("old drain cursor");
    assert!(cursor.draining);
    assert!(cursor.continue_after_time_updated.is_none());
    assert_eq!(
        old.sqlite_ingestion_continue_after(&source, "session_message"),
        None
    );
    assert_eq!(
        old.sqlite_ingestion_cursor_time_updated(&source, "session_message"),
        Some(1_000_000)
    );
}
