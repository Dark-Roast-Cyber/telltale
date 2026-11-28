use super::super::discovery::ProjectConfigurationAccounting;
use super::*;
use telltale_schema::clients::{ClientId, SourceKind};

fn change(path: PathBuf) -> NotifyEvent {
    NotifyEvent::new(EventKind::Modify(notify::event::ModifyKind::Any)).add_path(path)
}

#[test]
fn watch_heartbeat_forward_clock_jump_is_due_before_the_startup_deadline() {
    let started = Instant::now();
    let last = 100_000;
    let heartbeat = WatchHeartbeat {
        interval_seconds: 60,
        last_health_unix_ms: Some(last),
        retry_started: None,
    };
    let old_deadline = started + health_heartbeat_wait(Some(last), last, 60);
    assert!(!heartbeat.is_due(last, started));
    let next_wakeup = started + WATCH_SHUTDOWN_POLL;
    assert!(next_wakeup < old_deadline);
    assert!(!heartbeat.is_due(last + 200, next_wakeup));
    assert!(heartbeat.is_due(last + 60_000, next_wakeup));
}

#[test]
fn watch_heartbeat_backward_clock_jump_is_due_before_the_startup_deadline() {
    let started = Instant::now();
    let last = 100_000;
    let heartbeat = WatchHeartbeat {
        interval_seconds: 60,
        last_health_unix_ms: Some(last),
        retry_started: None,
    };
    let old_deadline = started + health_heartbeat_wait(Some(last), last, 60);
    assert!(!heartbeat.is_due(last, started));
    let next_wakeup = started + WATCH_SHUTDOWN_POLL;
    assert!(next_wakeup < old_deadline);
    assert!(heartbeat.is_due(last - 1, next_wakeup));
}

#[test]
fn watch_heartbeat_scan_result_restarts_the_in_memory_interval_including_dry_run() {
    let started = Instant::now();
    let mut heartbeat = WatchHeartbeat {
        interval_seconds: 60,
        last_health_unix_ms: None,
        retry_started: None,
    };
    assert!(heartbeat.is_due(100_000, started));
    // Dry-run returns this time without persisting a marker. Watch must use
    // the result, not reread the absent marker and immediately scan again.
    heartbeat.after_scan(Some(100_000), true, 100_000, started);
    assert!(!heartbeat.is_due(100_000, started));
    assert!(!heartbeat.is_due(159_999, started + Duration::from_millis(59_999)));
    assert!(heartbeat.is_due(160_000, started + Duration::from_secs(60)));
    // A later scan that emitted health for another reason also resets it.
    heartbeat.after_scan(
        Some(160_000),
        false,
        160_000,
        started + Duration::from_secs(60),
    );
    assert!(!heartbeat.is_due(219_999, started + Duration::from_secs(61)));
    assert!(heartbeat.is_due(159_999, started + Duration::from_secs(61)));
}

#[test]
fn watch_heartbeat_still_due_after_scan_waits_a_monotonic_interval_before_retry() {
    let completed = Instant::now();
    for last in [None, Some(1)] {
        let mut heartbeat = WatchHeartbeat {
            interval_seconds: 60,
            last_health_unix_ms: last,
            retry_started: None,
        };
        assert!(heartbeat.is_due(100_000, completed));
        heartbeat.after_scan(last, true, 100_000, completed);
        for wall_time in [0, 100_000, 1_000_000] {
            assert!(!heartbeat.is_due(wall_time, completed + Duration::from_secs(59)));
            assert!(heartbeat.is_due(wall_time, completed + Duration::from_secs(60)));
        }
    }
}

#[test]
fn watch_heartbeat_huge_interval_never_requires_an_instant_deadline() {
    let now = Instant::now();
    let mut heartbeat = WatchHeartbeat {
        interval_seconds: u64::MAX,
        last_health_unix_ms: Some(0),
        retry_started: None,
    };
    assert!(!heartbeat.is_due(0, now));
    assert!(!heartbeat.is_due(1_000, now + Duration::from_secs(1)));
    heartbeat.last_health_unix_ms = None;
    assert!(heartbeat.is_due(1_000, now));
    heartbeat.after_scan(None, true, 1_000, now);
    assert!(!heartbeat.is_due(u64::MAX, now + Duration::from_secs(1)));
}

#[test]
fn watch_admission_flood_retains_overflow_outside_stalled_queue() {
    let (tx, rx) = mpsc::sync_channel(WATCH_NOTIFICATION_CAPACITY);
    let (error_tx, errors) = mpsc::sync_channel(1);
    let overflow = Arc::new(AtomicBool::new(false));
    for i in 0..WATCH_NOTIFICATION_CAPACITY * 10 {
        admit_watch_event(
            &tx,
            &error_tx,
            &overflow,
            Ok(change(format!("/watch-test/{i}").into())),
        );
    }
    assert_eq!(rx.try_iter().count(), WATCH_NOTIFICATION_CAPACITY);
    let inbox = WatchInbox {
        rx,
        errors,
        overflow,
        filter: WatchPathFilter::default(),
    };
    let mut pending = PendingWatchChanges::default();
    inbox.take_signals(&mut pending).unwrap();
    assert!(matches!(
        pending.scan_action(&BTreeMap::new()),
        WatchScanAction::Full
    ));
    let mut next = PendingWatchChanges::default();
    inbox.take_signals(&mut next).unwrap();
    assert!(next.is_empty(), "quiescence must not repeatedly reconcile");
    // Overflow after the consumer's swap belongs to the next reconciliation.
    inbox.overflow.store(true, Ordering::SeqCst);
    inbox.take_signals(&mut next).unwrap();
    assert!(matches!(
        next.scan_action(&BTreeMap::new()),
        WatchScanAction::Full
    ));
}

#[test]
fn watch_admission_ignored_event_flood_does_not_queue_or_reconcile() {
    let (tx, rx) = mpsc::sync_channel(WATCH_NOTIFICATION_CAPACITY);
    let (error_tx, errors) = mpsc::sync_channel(1);
    let overflow = Arc::new(AtomicBool::new(false));
    for kind in [
        EventKind::Access(notify::event::AccessKind::Open(
            notify::event::AccessMode::Read,
        )),
        EventKind::Modify(notify::event::ModifyKind::Any),
    ] {
        for path_count in [1, WATCH_EVENT_PATH_CAPACITY + 1] {
            for _ in 0..WATCH_NOTIFICATION_CAPACITY * 2 {
                let mut event = NotifyEvent::new(kind);
                event.paths = (0..path_count)
                    .map(|i| match kind {
                        EventKind::Access(_) => format!("/watch-test/{i}.jsonl").into(),
                        _ => format!("/watch-test/{i}.db-shm").into(),
                    })
                    .collect();
                admit_watch_event(&tx, &error_tx, &overflow, Ok(event));
            }
        }
        assert!(
            rx.try_recv().is_err(),
            "irrelevant events must not occupy the queue"
        );
        assert!(
            !overflow.load(Ordering::SeqCst),
            "irrelevant floods must not request reconciliation"
        );
    }
    let inbox = WatchInbox {
        rx,
        errors,
        overflow,
        filter: WatchPathFilter::default(),
    };
    let mut pending = PendingWatchChanges::default();
    inbox.take_signals(&mut pending).unwrap();
    assert!(matches!(
        pending.scan_action(&BTreeMap::new()),
        WatchScanAction::Skip
    ));
}

#[test]
fn watch_admission_relevance_preserves_rescan_remove_and_mixed_paths() {
    let (tx, rx) = mpsc::sync_channel(WATCH_NOTIFICATION_CAPACITY);
    let (error_tx, _errors) = mpsc::sync_channel(1);
    let overflow = AtomicBool::new(false);
    for event in [
        NotifyEvent::new(EventKind::Access(notify::event::AccessKind::Any))
            .set_flag(notify::event::Flag::Rescan),
        NotifyEvent::new(EventKind::Remove(notify::event::RemoveKind::Any))
            .add_path("/watch-test/database.db-shm".into()),
    ] {
        admit_watch_event(&tx, &error_tx, &overflow, Ok(event));
        let mut pending = PendingWatchChanges::default();
        pending.absorb(&rx.try_recv().unwrap());
        assert!(matches!(
            pending.scan_action(&BTreeMap::new()),
            WatchScanAction::Full
        ));
    }
    let mut mixed = change("/watch-test/real.jsonl".into());
    mixed.paths.extend(
        (0..=WATCH_EVENT_PATH_CAPACITY)
            .map(|i| PathBuf::from(format!("/watch-test/{i}.db-journal"))),
    );
    admit_watch_event(&tx, &error_tx, &overflow, Ok(mixed));
    let admitted = rx.try_recv().unwrap();
    assert_eq!(
        admitted.paths,
        vec![PathBuf::from("/watch-test/real.jsonl")]
    );
    assert!(!overflow.load(Ordering::SeqCst));
    let mut large_mixed = change("/watch-test/ignored.db-shm".into());
    large_mixed.paths.extend(
        (0..=WATCH_EVENT_PATH_CAPACITY).map(|i| PathBuf::from(format!("/watch-test/{i}.jsonl"))),
    );
    admit_watch_event(&tx, &error_tx, &overflow, Ok(large_mixed));
    assert!(rx.try_recv().is_err());
    assert!(
        overflow.load(Ordering::SeqCst),
        "too many relevant paths must still reconcile"
    );
}

#[test]
fn watch_admission_oversized_event_and_errors_bypass_full_queue() {
    let (tx, rx) = mpsc::sync_channel(1);
    let (error_tx, errors) = mpsc::sync_channel(1);
    let overflow = Arc::new(AtomicBool::new(false));
    let mut large = change("/watch-test/0".into());
    large.paths = (0..=WATCH_EVENT_PATH_CAPACITY)
        .map(|i| format!("/watch-test/{i}").into())
        .collect();
    admit_watch_event(&tx, &error_tx, &overflow, Ok(large));
    assert!(rx.try_recv().is_err(), "large events must not be retained");
    assert!(overflow.load(Ordering::SeqCst));
    admit_watch_event(
        &tx,
        &error_tx,
        &overflow,
        Ok(change("/watch-test/queued".into())),
    );
    for _ in 0..10 {
        admit_watch_event(
            &tx,
            &error_tx,
            &overflow,
            Err(notify::Error::generic("synthetic watcher failure")),
        );
    }
    let inbox = WatchInbox {
        rx,
        errors,
        overflow,
        filter: WatchPathFilter::default(),
    };
    assert!(
        inbox
            .take_signals(&mut PendingWatchChanges::default())
            .unwrap_err()
            .to_string()
            .contains("synthetic watcher failure")
    );
}

#[test]
fn pending_path_budget_counts_distinct_normalized_paths() {
    let mut pending = PendingWatchChanges::default();
    for i in 0..WATCH_PENDING_PATH_CAPACITY {
        let event = change(format!("/watch-test/{i}.db-wal").into());
        pending.absorb(&event);
        pending.absorb(&event);
    }
    assert_eq!(pending.paths.len(), WATCH_PENDING_PATH_CAPACITY);
    assert!(!pending.saw_rescan);
    pending.absorb(&change("/watch-test/over-budget".into()));
    assert!(
        pending.paths.is_empty(),
        "full reconciliation no longer needs paths"
    );
    assert!(matches!(
        pending.scan_action(&BTreeMap::new()),
        WatchScanAction::Full
    ));
    pending.absorb(&change("/watch-test/later".into()));
    assert!(pending.paths.is_empty());
}

#[test]
fn collect_watch_overflow_without_queued_events_survives_zero_window_and_disconnect() {
    let (tx, rx) = mpsc::sync_channel(WATCH_NOTIFICATION_CAPACITY);
    let (_error_tx, errors) = mpsc::sync_channel(1);
    let inbox = WatchInbox {
        rx,
        errors,
        overflow: Arc::new(AtomicBool::new(true)),
        filter: WatchPathFilter::default(),
    };
    drop(tx);
    let mut pending = PendingWatchChanges::default();
    collect_watch_events_for(
        &inbox,
        &mut pending,
        Duration::ZERO,
        &AtomicBool::new(false),
    )
    .unwrap();
    assert!(matches!(
        pending.scan_action(&BTreeMap::new()),
        WatchScanAction::Full
    ));
    let mut next = PendingWatchChanges::default();
    collect_watch_events_for(
        &inbox,
        &mut next,
        Duration::from_secs(5),
        &AtomicBool::new(false),
    )
    .unwrap();
    assert!(next.is_empty());
}

#[test]
fn collect_watch_saturated_error_is_not_hidden_by_shutdown_or_zero_window() {
    let (tx, rx) = mpsc::sync_channel(1);
    let (error_tx, errors) = mpsc::sync_channel(1);
    let overflow = Arc::new(AtomicBool::new(false));
    admit_watch_event(
        &tx,
        &error_tx,
        &overflow,
        Ok(change("/watch-test/queued".into())),
    );
    admit_watch_event(
        &tx,
        &error_tx,
        &overflow,
        Err(notify::Error::generic("synthetic failure")),
    );
    let inbox = WatchInbox {
        rx,
        errors,
        overflow,
        filter: WatchPathFilter::default(),
    };
    assert!(
        collect_watch_events_for(
            &inbox,
            &mut PendingWatchChanges::default(),
            Duration::ZERO,
            &AtomicBool::new(true)
        )
        .is_err()
    );
}

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
fn pending_rescan_without_paths_requires_full_scan_even_when_coalesced() {
    let source = Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "codex.sessions".to_string(),
        path: PathBuf::from("/watch-test/codex/sessions/session-a.jsonl"),
    };
    let index = BTreeMap::from([(source.path.clone(), source.clone())]);
    let mut pending = PendingWatchChanges::default();
    pending.absorb(&NotifyEvent::new(EventKind::Other).set_flag(notify::event::Flag::Rescan));
    assert!(!pending.is_empty(), "rescan must wake the pending loop");
    assert!(matches!(pending.scan_action(&index), WatchScanAction::Full));

    pending.absorb(
        &NotifyEvent::new(EventKind::Modify(notify::event::ModifyKind::Any)).add_path(source.path),
    );
    assert!(matches!(pending.scan_action(&index), WatchScanAction::Full));
}

#[test]
fn pending_rescan_flag_precedes_kind_filter_but_plain_other_is_ignored() {
    let index = BTreeMap::new();
    let mut pending = PendingWatchChanges::default();
    pending.absorb(
        &NotifyEvent::new(EventKind::Other).add_path(PathBuf::from("/watch-test/ignored.jsonl")),
    );
    assert!(pending.is_empty());
    assert!(matches!(pending.scan_action(&index), WatchScanAction::Skip));

    pending.absorb(
        &NotifyEvent::new(EventKind::Access(notify::event::AccessKind::Any))
            .set_flag(notify::event::Flag::Rescan),
    );
    assert!(!pending.is_empty());
    assert!(matches!(pending.scan_action(&index), WatchScanAction::Full));
}

#[test]
fn pending_changes_fall_back_to_full_scan_for_unknown_paths_and_removes() {
    let source = Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "codex.sessions".to_string(),
        path: PathBuf::from("/watch-test/codex/sessions/session-a.jsonl"),
    };
    let index = BTreeMap::from([(source.path.clone(), source)]);

    let mut unknown = PendingWatchChanges::default();
    unknown
        .paths
        .insert(PathBuf::from("/watch-test/codex/sessions/new-file.jsonl"));
    assert!(matches!(unknown.scan_action(&index), WatchScanAction::Full));

    let removed = PendingWatchChanges {
        saw_remove: true,
        ..Default::default()
    };
    assert!(matches!(removed.scan_action(&index), WatchScanAction::Full));

    let idle = PendingWatchChanges::default();
    assert!(matches!(idle.scan_action(&index), WatchScanAction::Skip));
}

#[test]
fn sqlite_rechecks_sample_every_indexed_store_for_a_full_or_widened_scan() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let first = root.join("first.sqlite");
    let second = root.join("second.sqlite");
    let jsonl = root.join("session.jsonl");
    std::fs::write(sqlite_sidecar_path(&first, "-shm"), [1; 96]).unwrap();
    std::fs::write(sqlite_sidecar_path(&second, "-shm"), [2; 96]).unwrap();
    std::fs::write(sqlite_sidecar_path(&jsonl, "-shm"), [3; 96]).unwrap();
    let source = |path: &Path, kind| Source {
        path: path.to_path_buf(),
        client: ClientId::OpenCode,
        source_id: "synthetic".into(),
        kind,
    };
    let index = BTreeMap::from([
        (first.clone(), source(&first, SourceKind::Sqlite)),
        (second.clone(), source(&second, SourceKind::Sqlite)),
        (jsonl.clone(), source(&jsonl, SourceKind::Jsonl)),
    ]);
    let expected = vec![(first.clone(), [1; 96]), (second.clone(), [2; 96])];
    let mut rechecks = BTreeMap::new();
    // A heartbeat widens a scan woken by one store's WAL write.
    let mut woken = PendingWatchChanges::default();
    woken.paths.insert(first.clone());
    assert_eq!(
        sample_sqlite_sources(&woken, true, &index, &mut rechecks),
        expected
    );
    // Overflow and rescan notifications clear the changed paths.
    let mut rescan = PendingWatchChanges::default();
    rescan.require_full_scan();
    assert_eq!(
        sample_sqlite_sources(&rescan, false, &index, &mut rechecks),
        expected
    );
}

#[test]
fn sqlite_rechecks_sample_a_new_store_beside_its_shm() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let new_store = root.join("new.sqlite");
    let no_shm = root.join("no-shm.sqlite");
    std::fs::write(&new_store, b"synthetic").unwrap();
    std::fs::write(sqlite_sidecar_path(&new_store, "-shm"), [4; 96]).unwrap();
    let mut pending = PendingWatchChanges::default();
    pending.paths.insert(new_store.clone());
    pending.paths.insert(no_shm);
    assert_eq!(
        sample_sqlite_sources(&pending, false, &BTreeMap::new(), &mut BTreeMap::new()),
        vec![(new_store, [4; 96])]
    );
}

#[test]
fn sqlite_recheck_of_an_unchanged_store_ends_after_its_last_delay() {
    let temp = tempfile::tempdir().unwrap();
    let database = temp.path().join("store.sqlite");
    std::fs::write(sqlite_sidecar_path(&database, "-shm"), [7; 136]).unwrap();
    let scanned = Instant::now();
    let mut rechecks = BTreeMap::from([(
        database.clone(),
        SqliteCommitRecheck {
            sample: [7; SQLITE_COMMIT_SAMPLE_LEN],
            scanned,
            next: 0,
        },
    )]);
    let mut pending = PendingWatchChanges::default();
    take_due_sqlite_rechecks(
        &mut rechecks,
        &mut pending,
        scanned + Duration::from_millis(249),
    );
    assert_eq!(
        next_sqlite_recheck(&rechecks),
        Some(scanned + Duration::from_millis(250))
    );
    take_due_sqlite_rechecks(
        &mut rechecks,
        &mut pending,
        scanned + Duration::from_millis(250),
    );
    // SQLite truncates and rebuilds `-shm` when a first connection reopens;
    // an unreadable sample does not end the window.
    std::fs::write(sqlite_sidecar_path(&database, "-shm"), [7; 10]).unwrap();
    take_due_sqlite_rechecks(
        &mut rechecks,
        &mut pending,
        scanned + Duration::from_secs(1),
    );
    assert_eq!(
        next_sqlite_recheck(&rechecks),
        Some(scanned + Duration::from_secs(3))
    );
    std::fs::write(sqlite_sidecar_path(&database, "-shm"), [7; 136]).unwrap();
    take_due_sqlite_rechecks(
        &mut rechecks,
        &mut pending,
        scanned + Duration::from_secs(3),
    );
    assert_eq!(
        next_sqlite_recheck(&rechecks),
        Some(scanned + Duration::from_secs(10))
    );
    take_due_sqlite_rechecks(
        &mut rechecks,
        &mut pending,
        scanned + Duration::from_secs(10),
    );
    assert!(pending.is_empty());
    assert!(rechecks.is_empty());
    assert_eq!(next_sqlite_recheck(&rechecks), None);
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

#[test]
fn watch_snapshot_count_matches_canonical_path_index_for_duplicate_projects() {
    let path = PathBuf::from("duplicate-project/session.jsonl");
    let first = Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "project-one".to_string(),
        path: path.clone(),
    };
    let second = Source {
        source_id: "project-two".to_string(),
        ..first.clone()
    };
    let discovery = SourceDiscoveryAccounting {
        checked_status: "succeeded",
        first_error_category: None,
        best_effort_fallback_used: false,
        returned_source_count: 2,
        operational_source_count: 2,
        project_configuration: ProjectConfigurationAccounting::none(),
    };
    let (index, snapshot) = watch_index_from_sources(vec![first, second], discovery);
    assert_eq!(index.len(), 1);
    assert_eq!(snapshot.operational_source_count, index.len());
}

#[test]
fn collect_watch_events_coalesces_queued_changes_before_disconnect() {
    let (tx, rx) = mpsc::sync_channel(WATCH_NOTIFICATION_CAPACITY);
    let (_error_tx, errors) = mpsc::sync_channel(1);
    let inbox = WatchInbox {
        rx,
        errors,
        overflow: Arc::new(AtomicBool::new(false)),
        filter: WatchPathFilter::default(),
    };
    let mut pending = PendingWatchChanges::default();
    let shutdown = AtomicBool::new(false);

    let event = NotifyEvent {
        kind: EventKind::Modify(notify::event::ModifyKind::Any),
        paths: vec![PathBuf::from("/watch-test/codex/sessions/session-a.jsonl")],
        attrs: Default::default(),
    };
    tx.send(event.clone()).expect("send first event");
    tx.send(event).expect("send second event");
    drop(tx);

    collect_watch_events_for(&inbox, &mut pending, Duration::from_secs(5), &shutdown)
        .expect("collect should succeed");

    assert_eq!(pending.paths.len(), 1);
    assert!(
        pending
            .paths
            .contains(Path::new("/watch-test/codex/sessions/session-a.jsonl"))
    );
    assert!(!pending.saw_remove);
}
