use super::*;

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
