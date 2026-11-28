use super::*;

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
