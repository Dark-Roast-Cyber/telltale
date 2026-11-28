use super::*;

#[test]
fn required_output_failure_preserves_entire_state_then_success_installs_baseline_and_cursor() {
    let fixture = Fixture::new();
    let before = fs::read(&fixture.state).unwrap();
    let mut failed = SinkSet::new();
    failed.add_canonical_first_write("jsonl", Box::new(RequiredFailure));
    assert!(fixture.scan(&failed, false, false, false).is_err());
    assert_eq!(fs::read(&fixture.state).unwrap(), before);
    fixture.scan(&fixture.sinks(), false, false, false).unwrap();
    let state = fixture.load();
    assert_eq!(
        state.sqlite_ingestion_cursor_time_updated(&fixture.sources[1], "part"),
        Some(10)
    );
    assert_eq!(state.baseline_source_contributions.len(), 1);
    assert_eq!(
        state
            .baseline_snapshots
            .snapshots
            .values()
            .next()
            .unwrap()
            .observations
            .records,
        1
    );
    let events = fixture.events();
    assert!(events.iter().any(|event| event["event_type"] == "activity"));
    assert!(
        !events
            .iter()
            .any(|event| event["event_type"] == "scanner_error")
    );
}

#[test]
fn watch_shared_path_replaces_empty_but_partial_source_retains_its_contribution() {
    let fixture = Fixture::new();
    fixture.scan(&fixture.sinks(), true, false, false).unwrap();
    let mut state = fixture.load();
    let partial_summary = BaselineSummary {
        key: BaselineKey {
            client: "opencode".into(),
            ..BaselineKey::default()
        },
        ..BaselineSummary::default()
    };
    state
        .record_baseline_source_contribution(
            &fixture.sources[1],
            "retained".into(),
            vec![partial_summary],
        )
        .unwrap();
    state
        .rebuild_baseline_snapshots_from_source_contributions()
        .unwrap();
    state.save(&fixture.state).unwrap();
    let retained = state
        .baseline_source_contributions
        .values()
        .find(|value| value.client == "opencode")
        .unwrap()
        .clone();
    // Complete source with no eligible population requests Replace(empty).
    fs::write(
        &fixture.sources[0].path,
        "{\"type\":\"session_meta\",\"payload\":{}}\n",
    )
    .unwrap();
    fixture.scan(&fixture.sinks(), true, false, false).unwrap();
    let state = fixture.load();
    assert_eq!(
        state
            .baseline_source_contributions
            .values()
            .find(|value| value.client == "opencode"),
        Some(&retained)
    );
    assert!(
        state
            .baseline_source_contributions
            .values()
            .find(|value| value.client == "codex")
            .unwrap()
            .snapshots
            .is_empty()
    );
    assert_eq!(state.baseline_snapshots.snapshots.len(), 1);
}

#[test]
fn aggregate_overflow_blocks_all_persistence_and_progress() {
    let fixture = Fixture::new();
    fixture.scan(&fixture.sinks(), true, false, false).unwrap();
    let mut state = fixture.load();
    let mut summary = state
        .baseline_snapshots
        .snapshots
        .values()
        .next()
        .unwrap()
        .clone();
    summary.observations.records = u64::MAX;
    let other = Source {
        path: fixture.dir.path().join("unscanned.jsonl"),
        ..fixture.sources[0].clone()
    };
    state
        .record_baseline_source_contribution(&other, "retained".into(), vec![summary])
        .unwrap();
    state.save(&fixture.state).unwrap();
    let before = fs::read(&fixture.state).unwrap();
    let output_before = fs::read(&fixture.log).unwrap();
    let error = fixture
        .scan(&fixture.sinks(), true, false, false)
        .err()
        .unwrap();
    assert!(error.downcast_ref::<RiskAccountingError>().is_some());
    assert_eq!(fs::read(&fixture.state).unwrap(), before);
    assert_eq!(fs::read(&fixture.log).unwrap(), output_before);
}

#[test]
fn dry_run_and_backfill_never_install_baseline_or_cursor() {
    for (dry_run, backfill) in [(true, false), (false, true)] {
        let fixture = Fixture::new();
        fixture
            .scan(&fixture.sinks(), false, dry_run, backfill)
            .unwrap();
        let state = fixture.load();
        assert!(state.baseline_source_contributions.is_empty());
        assert!(state.baseline_snapshots.snapshots.is_empty());
        assert!(state.sqlite_ingestion_cursors.is_empty());
    }
}

#[test]
fn late_canonical_failure_has_no_success_output_or_progress_for_that_source() {
    let fixture = Fixture::new();
    // A valid first part cannot escape a later conflicting ownership failure.
    let conn = rusqlite::Connection::open(&fixture.sources[1].path).unwrap();
    conn.execute_batch(r#"INSERT INTO part VALUES ('late','m','s',20,'{"type":"tool","sessionID":"different","tool":"shell","callID":"late","state":{"status":"running","input":{"command":"echo synthetic"}}}');"#).unwrap();
    drop(conn);
    fixture.scan(&fixture.sinks(), true, false, false).unwrap();
    let state = fixture.load();
    assert!(state.sqlite_ingestion_cursors.is_empty());
    assert!(
        state
            .baseline_source_contributions
            .values()
            .all(|value| value.client != "opencode")
    );
    let events = fixture
        .events()
        .into_iter()
        .filter(|event| event["client"] == "opencode")
        .collect::<Vec<_>>();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["event_type"], "scanner_error");
}
