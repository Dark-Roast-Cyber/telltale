use super::*;

#[test]
fn opencode_sqlite_scan_options_use_cursor_overlap_for_live_scans() {
    let source = opencode_test_source();
    let mut state = ScanState::default();
    state.observe_sqlite_ingestion_cursor(&source, OPENCODE_SQLITE_PART_TABLE, 1_000_000, 42);

    let live_options = opencode_read_options_for_scan_source(&source, &state, false, false);
    assert_eq!(live_options.part_limit, 25_000);
    assert_eq!(
        live_options.part_min_time_updated,
        Some(1_000_000 - telltale_sources::acquisition::OPENCODE_SQLITE_RESUME_OVERLAP_MS)
    );

    let dry_run_options = opencode_read_options_for_scan_source(&source, &state, false, true);
    assert_eq!(dry_run_options.part_min_time_updated, None);
    assert_eq!(dry_run_options.part_limit, 5_000);

    let backfill_options = opencode_read_options_for_scan_source(&source, &state, true, false);
    assert_eq!(backfill_options.part_min_time_updated, None);
    assert_eq!(backfill_options.part_limit, 5_000);
    assert_eq!(
        opencode_read_options_for_scan_source(&source, &ScanState::default(), false, false)
            .part_limit,
        5_000
    );
}

#[test]
fn opencode_sqlite_scan_options_require_exact_source_identity() {
    let source = opencode_test_source();
    let mut wrong_client = source.clone();
    wrong_client.client = ClientId::Codex;
    let mut wrong_kind = source.clone();
    wrong_kind.kind = SourceKind::Jsonl;
    let mut wrong_id = source.clone();
    wrong_id.source_id = "opencode.sqlite.lookalike".into();
    for source in [wrong_client, wrong_kind, wrong_id] {
        let mut state = ScanState::default();
        state.observe_sqlite_ingestion_cursor(
            &source,
            OPENCODE_SQLITE_SESSION_MESSAGE_TABLE,
            1_000_000,
            42,
        );
        assert!(!is_opencode_sqlite_source(&source), "{source:?}");
        assert_eq!(
            opencode_read_options_for_scan_source(&source, &state, false, false),
            OpenCodeSqliteReadOptions::default(),
            "{source:?}"
        );
    }
}

#[test]
fn opencode_v2_scan_options_preserve_stored_monotone_watermark_and_drain_mode() {
    let source = opencode_test_source();
    let mut state = ScanState::default();
    // Save/load preserves both the monotone checkpoint and the raw cut.
    for (high_water, draining) in [(1_000_000, false), (900_000, true), (800_000, false)] {
        if draining {
            state.observe_sqlite_ingestion_drain(
                &source,
                OPENCODE_SQLITE_SESSION_MESSAGE_TABLE,
                high_water,
                42,
            );
        } else {
            state.observe_sqlite_ingestion_cursor(
                &source,
                OPENCODE_SQLITE_SESSION_MESSAGE_TABLE,
                high_water,
                42,
            );
        }
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("state.json");
        state.save(&path).unwrap();
        state = ScanState::load(&path).unwrap();
        let expected = if draining {
            OpenCodeSqliteReadOptions::default()
                .resume_session_messages_after(1_000_000)
                .continue_session_messages_after(high_water)
        } else {
            OpenCodeSqliteReadOptions::default().resume_session_messages_after(1_000_000)
        };
        assert_eq!(
            opencode_read_options_for_scan_source(&source, &state, false, false),
            expected
        );
        for (backfill, dry_run) in [(true, false), (false, true)] {
            assert_eq!(
                opencode_read_options_for_scan_source(&source, &state, backfill, dry_run),
                OpenCodeSqliteReadOptions::default()
            );
        }
        let mut other_source = source.clone();
        other_source.path = PathBuf::from("/synthetic/other.db");
        assert_eq!(
            opencode_read_options_for_scan_source(&other_source, &state, false, false),
            OpenCodeSqliteReadOptions::default()
        );
    }
}

#[test]
fn explicit_roots_report_unused_session_store_variables_for_selected_clients() {
    let env = |pairs: &'static [(&'static str, &'static str)]| {
        move |name: &str| {
            pairs
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| std::ffi::OsString::from(value))
        }
    };
    let codex = env(&[("CODEX_HOME", "/synthetic/codex")]);
    let opencode = env(&[("OPENCODE_DB", "relocated.db")]);
    let unset = env(&[("CODEX_HOME", ""), ("OPENCODE_DB", ":memory:")]);
    let root = Path::new("/synthetic/root");
    assert!(!session_store_environment_ignored(
        Path::new("."),
        &[],
        &codex
    ));
    assert!(!session_store_environment_ignored(
        Path::new("./"),
        &[],
        &opencode
    ));
    assert!(session_store_environment_ignored(root, &[], &codex));
    assert!(session_store_environment_ignored(root, &[], &opencode));
    assert!(!session_store_environment_ignored(root, &[], &unset));
    assert!(!session_store_environment_ignored(
        root,
        &[ClientId::Claude],
        &codex
    ));
    assert!(session_store_environment_ignored(
        root,
        &[ClientId::OpenCode],
        &opencode
    ));
}
