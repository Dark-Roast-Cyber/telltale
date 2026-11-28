use super::*;

#[test]
fn sink_failure_episode_tracks_current_identity_and_keeps_other_classes_visible() {
    let sink = "https://synthetic.invalid/private:authentication_blocked:401";
    let mut state = ScanState::default();
    state.seen_detection_fingerprints.insert(format!(
        "telltale:sink_failure_episode:{sink}:authentication_blocked:401"
    ));
    state.seen_detection_fingerprints.insert(format!(
        "telltale:sink_failure_episode:{sink}:authentication_blocked:403"
    ));
    for status in [401, 403, 401] {
        let failure = blocked_failure(sink, status);
        let selection =
            select_sink_failure_alerts(&state, &[failure.clone(), failure.clone()], true);
        assert_eq!(selection.alerts.len(), 1, "transition to {status}");
        for (sink, identity) in selection.episode_keys {
            record_sink_failure_episode(&mut state, &sink, identity.as_deref(), None);
        }
        assert!(
            select_sink_failure_alerts(&state, &[failure], true)
                .alerts
                .is_empty()
        );
        assert_eq!(state.seen_detection_fingerprints.len(), 1);
    }
    assert!(
        !String::from_utf8(state.canonical_bytes().unwrap())
            .unwrap()
            .contains(sink)
    );
    let mut transient = blocked_failure(sink, 401);
    transient.class = DeliveryErrorClass::UnknownInternal;
    let selection = select_sink_failure_alerts(&state, &[transient.clone(), transient], true);
    assert_eq!(selection.alerts.len(), 2);
    for (sink, identity) in selection.episode_keys {
        record_sink_failure_episode(&mut state, &sink, identity.as_deref(), None);
    }
    assert!(!sink_failure_episode_open(
        &state,
        sink,
        "authentication_blocked:401"
    ));
    record_sink_failure_episode(&mut state, sink, Some("sink_response_blocked"), None);
    assert_eq!(
        select_sink_failure_alerts(&state, &[blocked_failure(sink, 401)], true)
            .alerts
            .len(),
        1
    );
    assert!(clear_sink_failure_episodes(&mut state, sink));
    assert_eq!(
        select_sink_failure_alerts(&state, &[blocked_failure(sink, 401)], true)
            .alerts
            .len(),
        1
    );
}

#[test]
fn sink_failure_episode_collapses_each_identity_but_remembers_last_failure() {
    let mut state = ScanState::default();
    let failures = [
        blocked_failure("synthetic", 401),
        blocked_failure("synthetic", 403),
        blocked_failure("synthetic", 401),
    ];
    let selection = select_sink_failure_alerts(&state, &failures, true);
    assert_eq!(selection.alerts.len(), 2);
    for (sink, identity) in selection.episode_keys {
        record_sink_failure_episode(&mut state, &sink, identity.as_deref(), None);
    }
    assert!(sink_failure_episode_open(
        &state,
        "synthetic",
        "authentication_blocked:401"
    ));
    assert!(!sink_failure_episode_open(
        &state,
        "synthetic",
        "authentication_blocked:403"
    ));
    let mixed = select_sink_failure_alerts(&state, &failures, true);
    assert_eq!(
        mixed.alerts.len(),
        2,
        "with 401 already open, select both the 403 transition and the renewed 401"
    );
    assert_eq!(
        mixed.episode_keys.get("synthetic"),
        Some(&Some("authentication_blocked:401".to_string())),
        "the last failure identity must remain current"
    );
    assert!(
        select_sink_failure_alerts(&state, &failures[..1], true)
            .alerts
            .is_empty()
    );
    assert_eq!(
        select_sink_failure_alerts(&state, &failures[1..2], true)
            .alerts
            .len(),
        1
    );
}

#[test]
fn sink_failure_episode_save_failure_leaves_reloaded_state_unlatched() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("state.json");
    ScanState::default().save(&path).unwrap();
    let lock = StateLock::acquire(&path).unwrap();
    let backup = temp.path().join("original-state.json");
    fs::rename(&path, &backup).unwrap();
    fs::create_dir(&path).unwrap();
    let mut state = ScanState::default();
    record_sink_failure_episode(
        &mut state,
        "synthetic",
        Some("authentication_blocked:401"),
        None,
    );
    save_sink_failure_episode_latch(&state, &path, Some(&lock));
    fs::remove_dir(&path).unwrap();
    fs::rename(&backup, &path).unwrap();
    let restored = ScanState::load_snapshot(&path).unwrap();
    assert_eq!(
        select_sink_failure_alerts(&restored, &[blocked_failure("synthetic", 401)], true)
            .alerts
            .len(),
        1
    );
}

#[test]
fn sink_failure_episode_success_reference_survives_idle_dispatch_and_state_reload() {
    let mut state = ScanState::default();
    record_sink_failure_episode(
        &mut state,
        "synthetic",
        Some("authentication_blocked:401"),
        Some(100),
    );
    let mut state = ScanState::validate_native_bytes(&state.canonical_bytes().unwrap()).unwrap();
    assert!(!clear_sinks_with_new_success(
        &mut state,
        &BTreeMap::from([("synthetic".into(), Some(100))])
    ));
    assert!(clear_sinks_with_new_success(
        &mut state,
        &BTreeMap::from([("synthetic".into(), Some(200))])
    ));
    assert_eq!(
        select_sink_failure_alerts(&state, &[blocked_failure("synthetic", 401)], true)
            .alerts
            .len(),
        1
    );
}

#[cfg(not(windows))]
#[test]
fn sink_failure_episode_unordered_success_fails_open_only_for_its_sink() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("private-outbox/outbox.sqlite");
    drop(crate::sink::outbox::Outbox::open(&path).unwrap());
    let connection = rusqlite::Connection::open(&path).unwrap();
    connection.execute_batch("INSERT INTO sink_health (sink_id, last_success_at, last_error_at) VALUES ('unordered', 100, 100), ('ordered', 150, 100);").unwrap();
    drop(connection);
    let snapshot = snapshot_durable_sink_success(Some(&path)).unwrap();
    assert_eq!(snapshot.unordered, BTreeSet::from(["unordered".into()]));
    assert_eq!(snapshot.success.get("ordered"), Some(&Some(150)));
}

#[test]
fn sink_failure_episode_canonical_alert_write_failure_never_latches() {
    let fixture = Fixture::new();
    let mut sinks = SinkSet::new();
    sinks.add_canonical_first_write(
        "jsonl",
        Box::new(AlertWriteFailure(LocalJsonlSink::with_rotation(
            &fixture.log,
            crate::sink::RotationConfig::disabled(),
        ))),
    );
    sinks.add_best_effort("splunk_hec", Box::new(AuthenticationFailure));
    assert!(fixture.scan(&sinks, false, false, false).is_err());
    assert!(!sink_failure_episode_open(
        &fixture.load(),
        "synthetic-remote",
        "authentication_blocked:401"
    ));
    assert!(
        !fixture
            .events()
            .iter()
            .any(|event| event["check_name"] == "sink_delivery")
    );
    assert!(
        fixture
            .events()
            .iter()
            .any(|event| event["event_type"] == "activity")
    );
}
