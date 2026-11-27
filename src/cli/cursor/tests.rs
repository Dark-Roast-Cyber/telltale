use super::*;
use telltale_schema::clients::{ClientId, SourceKind};
use telltale_schema::source::Source;

fn fixture(path: &Path) -> SqliteIngestionCursor {
    let source = Source {
        client: ClientId::OpenCode,
        kind: SourceKind::Sqlite,
        source_id: "opencode.sqlite".into(),
        path: "synthetic-not-a-live-store.db".into(),
    };
    let mut state = ScanState::default();
    state.observe_sqlite_ingestion_cursor(&source, "session_message", 100, 1);
    state.observe_sqlite_ingestion_drain(&source, "session_message", 50, 2);
    state.observe_sqlite_ingestion_cursor(&source, "part", 200, 3);
    state.observe_sources(std::slice::from_ref(&source), 4);
    state.seen_detection_fingerprints.insert("retained".into());
    state
        .record_baseline_source_contribution(
            &source,
            "retained".into(),
            vec![crate::baseline::BaselineSummary::default()],
        )
        .unwrap();
    state
        .rebuild_baseline_snapshots_from_source_contributions()
        .unwrap();
    let cursor = state
        .sqlite_ingestion_cursors
        .values()
        .find(|cursor| cursor.table == "session_message")
        .unwrap()
        .clone();
    state.save(path).unwrap();
    cursor
}

fn reset(path: &Path, cursor: &SqliteIngestionCursor, abandon: bool) -> CursorCommand {
    CursorCommand::Reset {
        state_path: path.into(),
        source_instance_id: cursor.source_instance_id.clone(),
        table: cursor.table.clone(),
        expect_cursor: digest(cursor).unwrap(),
        accept_history_gap: true,
        abandon_incomplete_drain: abandon,
    }
}

#[test]
fn cursor_reset_preserves_every_other_state_family_and_schema() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("state.json");
    for legacy_drain in [false, true] {
        let mut cursor = fixture(&path);
        if legacy_drain {
            cursor.continue_after_time_updated = None;
            let mut state = ScanState::load(&path).unwrap();
            let key = sqlite_ingestion_cursor_key_for_instance(
                "opencode",
                "opencode.sqlite",
                &cursor.source_instance_id,
                "session_message",
            );
            state.sqlite_ingestion_cursors.insert(key, cursor.clone());
            state.save(&path).unwrap();
        }
        let before = std::fs::read(&path).unwrap();
        let error = run_with_output(reset(&path, &cursor, false), &mut Vec::new()).unwrap_err();
        assert_eq!(error.to_string(), "cursor_drain_abandonment_required");
        assert_eq!(std::fs::read(&path).unwrap(), before);
        let mut expected: serde_json::Value = serde_json::from_slice(&before).unwrap();
        expected["sqlite_ingestion_cursors"]
            .as_object_mut()
            .unwrap()
            .retain(|_, value| value["table"] != "session_message");
        let mut output = Vec::new();
        run_with_output(reset(&path, &cursor, true), &mut output).unwrap();
        let result: serde_json::Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(result["abandoned_incomplete_drain"], true);
        let actual: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(actual, expected);
    }
}

#[test]
fn cursor_reset_ack_failure_is_explicitly_committed() {
    struct BrokenOutput;
    impl Write for BrokenOutput {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::ErrorKind::BrokenPipe.into())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("state.json");
    let cursor = fixture(&path);
    let error = run_with_output(reset(&path, &cursor, true), &mut BrokenOutput).unwrap_err();
    assert!(
        error
            .to_string()
            .starts_with("cursor_reset_committed_ack_failed;")
    );
    let state = ScanState::load(&path).unwrap();
    assert_eq!(state.sqlite_ingestion_cursors.len(), 1);
    assert_eq!(
        state
            .sqlite_ingestion_cursors
            .values()
            .next()
            .unwrap()
            .table,
        "part"
    );
    let before = std::fs::read(&path).unwrap();
    let error = run_with_output(reset(&path, &cursor, true), &mut Vec::new()).unwrap_err();
    assert!(error.to_string().starts_with("cursor_not_found;"));
    assert_eq!(std::fs::read(&path).unwrap(), before);
}

#[test]
fn cursor_digest_binds_both_coordinates_and_observation() {
    let temp = tempfile::tempdir().unwrap();
    let cursor = fixture(&temp.path().join("state.json"));
    let mut changed = cursor.clone();
    changed.last_time_updated += 1;
    assert_ne!(digest(&cursor).unwrap(), digest(&changed).unwrap());
    changed = cursor.clone();
    changed.continue_after_time_updated = Some(49);
    assert_ne!(digest(&cursor).unwrap(), digest(&changed).unwrap());
    changed = cursor.clone();
    changed.observed_at_unix_ms += 1;
    assert_ne!(digest(&cursor).unwrap(), digest(&changed).unwrap());
    changed = cursor.clone();
    changed.continue_after_time_updated = None;
    assert_ne!(digest(&cursor).unwrap(), digest(&changed).unwrap());
}
