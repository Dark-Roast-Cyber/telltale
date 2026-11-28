use super::*;

#[test]
fn normalize_watch_event_path_handles_sqlite_sidecars() {
    let wal = Path::new("/data/opencode/opencode.db-wal");
    assert_eq!(
        normalize_watch_event_path(wal),
        Some(PathBuf::from("/data/opencode/opencode.db"))
    );

    assert_eq!(
        normalize_watch_event_path(Path::new("/data/opencode/opencode.db-shm")),
        None
    );
    assert_eq!(
        normalize_watch_event_path(Path::new("/data/opencode/opencode.db-journal")),
        None
    );

    let jsonl = Path::new("/home/user/.codex/sessions/session-a.jsonl");
    assert_eq!(normalize_watch_event_path(jsonl), Some(jsonl.to_path_buf()));

    // Non-SQLite names that merely end in a sidecar-like suffix are kept.
    let lookalike = Path::new("/home/user/.codex/sessions/notes-wal");
    assert_eq!(
        normalize_watch_event_path(lookalike),
        Some(lookalike.to_path_buf())
    );
}

#[test]
fn pending_changes_dedupe_sqlite_db_and_wal_to_one_target() {
    let db_source = Source {
        client: ClientId::OpenCode,
        kind: SourceKind::Sqlite,
        source_id: "opencode.sqlite".to_string(),
        path: PathBuf::from("/watch-test/opencode/opencode.db"),
    };
    let index = BTreeMap::from([(db_source.path.clone(), db_source.clone())]);

    let mut pending = PendingWatchChanges::default();
    let event = NotifyEvent {
        kind: EventKind::Modify(notify::event::ModifyKind::Any),
        paths: vec![
            PathBuf::from("/watch-test/opencode/opencode.db"),
            PathBuf::from("/watch-test/opencode/opencode.db-wal"),
            PathBuf::from("/watch-test/opencode/opencode.db-shm"),
        ],
        attrs: Default::default(),
    };
    pending.absorb(&event);

    assert!(!pending.is_empty());
    match pending.scan_action(&index) {
        WatchScanAction::Targeted(targets) => assert_eq!(targets, vec![db_source]),
        _ => panic!("expected targeted scan"),
    }
}

#[test]
fn pending_changes_target_arbitrarily_named_sqlite_wal() {
    let source = Source {
        client: ClientId::OpenCode,
        kind: SourceKind::Sqlite,
        source_id: "opencode.sqlite".into(),
        path: "/watch-test/custom-store.sqlite".into(),
    };
    let index = BTreeMap::from([(source.path.clone(), source.clone())]);
    let mut pending = PendingWatchChanges::default();
    pending.absorb_with_override(
        &change("/watch-test/custom-store.sqlite-wal".into()),
        Some(&source.path),
    );
    match pending.scan_action(&index) {
        WatchScanAction::Targeted(sources) => assert_eq!(sources, [source]),
        _ => panic!("configured SQLite WAL must target its exact main file"),
    }
}

#[test]
fn configured_sqlite_names_take_precedence_over_sidecar_suffixes() {
    for name in [
        "custom.sqlite",
        "actual.db-wal",
        "actual.db-shm",
        "actual.db-journal",
    ] {
        let database = Path::new("/watch-test").join(name);
        assert_eq!(
            normalize_watch_event_path_with_override(&database, Some(&database)),
            Some(database.clone())
        );
        assert_eq!(
            normalize_watch_event_path_with_override(
                &PathBuf::from(format!("{}-wal", database.display())),
                Some(&database)
            ),
            Some(database.clone())
        );
        for suffix in ["-shm", "-journal"] {
            assert_eq!(
                normalize_watch_event_path_with_override(
                    &PathBuf::from(format!("{}{suffix}", database.display())),
                    Some(&database)
                ),
                None
            );
        }
        let (tx, rx) = mpsc::sync_channel(1);
        let (errors, _receive_errors) = mpsc::sync_channel(1);
        let overflow = AtomicBool::new(false);
        for _ in 0..WATCH_NOTIFICATION_CAPACITY * 2 {
            admit_watch_event_with_override(
                &tx,
                &errors,
                &overflow,
                Ok(change(format!("{}-shm", database.display()).into())),
                Some(&database),
            );
        }
        assert!(rx.try_recv().is_err());
        assert!(!overflow.load(Ordering::SeqCst));
    }
    let unrelated = Path::new("/watch-test/unrelated-wal");
    assert_eq!(
        normalize_watch_event_path_with_override(
            unrelated,
            Some(Path::new("/watch-test/custom.sqlite"))
        ),
        Some(unrelated.to_path_buf())
    );
}

#[test]
fn configured_reader_sidecar_removals_do_not_reconcile() {
    for suffix in ["-shm", "-journal"] {
        let database = Path::new("/watch-test/custom.sqlite");
        let event = NotifyEvent::new(EventKind::Remove(notify::event::RemoveKind::Any))
            .add_path(format!("{}{suffix}", database.display()).into());
        let mut pending = PendingWatchChanges::default();
        pending.absorb_with_override(&event, Some(database));
        assert!(matches!(
            pending.scan_action(&BTreeMap::new()),
            WatchScanAction::Skip
        ));
    }
}

#[cfg(windows)]
#[test]
fn configured_windows_notifications_preserve_native_case_aliases() {
    let database = Path::new(r"C:\synthetic\Store-Σ.sqlite");
    assert_eq!(
        normalize_watch_event_path_with_override(
            Path::new(r"C:\synthetic\store-σ.sqlite-wal"),
            Some(database)
        ),
        Some(database.to_path_buf())
    );
    assert_eq!(
        normalize_watch_event_path_with_override(
            Path::new(r"C:\synthetic\STORE-Σ.SQLITE-shm"),
            Some(database)
        ),
        None
    );
}

#[cfg(unix)]
#[test]
fn configured_non_utf8_and_symlink_sidecars_use_their_names_not_targets() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;
    let database = PathBuf::from(OsString::from_vec(
        b"/watch-test/custom\xff.sqlite".to_vec(),
    ));
    let mut sidecar = database.as_os_str().to_os_string();
    sidecar.push("-shm");
    assert_eq!(
        normalize_watch_event_path_with_override(Path::new(&sidecar), Some(&database)),
        None
    );
    let temp = tempfile::tempdir().unwrap();
    let database = temp.path().join("custom.sqlite");
    std::fs::write(&database, b"synthetic metadata only").unwrap();
    let sidecar = temp.path().join("custom.sqlite-shm");
    std::os::unix::fs::symlink(&database, &sidecar).unwrap();
    assert_eq!(
        normalize_watch_event_path_with_override(&sidecar, Some(&database)),
        None
    );
}

#[test]
fn pending_changes_ignore_access_events_and_sidecar_only_writes() {
    let mut pending = PendingWatchChanges::default();
    pending.absorb(&NotifyEvent {
        kind: EventKind::Access(notify::event::AccessKind::Any),
        paths: vec![PathBuf::from("/watch-test/codex/sessions/session-a.jsonl")],
        attrs: Default::default(),
    });
    pending.absorb(&NotifyEvent {
        kind: EventKind::Modify(notify::event::ModifyKind::Any),
        paths: vec![PathBuf::from("/watch-test/opencode/opencode.db-shm")],
        attrs: Default::default(),
    });
    assert!(pending.is_empty());
}
