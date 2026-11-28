use super::*;

#[test]
fn simulated_windows_durable_scan_rejects_before_state_progress_or_best_effort_fallback() {
    let temp = tempfile::tempdir().expect("tempdir");
    let root = temp.path().join("synthetic-root");
    fs::create_dir_all(&root).expect("synthetic root");
    let log_path = temp.path().join("events.jsonl");
    let state_path = temp.path().join("state.json");
    let outbox_path = temp.path().join("private").join("outbox.sqlite");

    let mut initial_state = ScanState::default();
    initial_state
        .seen_source_fingerprints
        .insert("synthetic-existing-fingerprint".to_string());
    initial_state.save(&state_path).expect("save initial state");
    let state_before = fs::read(&state_path).expect("read initial state");

    let delivery_calls = Arc::new(AtomicUsize::new(0));
    let mut sinks = SinkSet::new();
    sinks.add_canonical_first_write_path_with_rotation(
        "jsonl",
        Box::new(LocalJsonlSink::with_rotation(
            &log_path,
            RotationConfig::disabled(),
        )),
        log_path.clone(),
        None,
    );
    sinks.add_best_effort(
        "synthetic",
        Box::new(CountingSink {
            calls: Arc::clone(&delivery_calls),
        }),
    );
    sinks.enable_persistent_replay_with_capacity(
        outbox_path.clone(),
        vec!["synthetic".to_string()],
        crate::sink::outbox::CapacityLimits::default(),
    );

    let rule_pack_paths = RulePackPaths::default();
    let rule_paths = Vec::new();
    let override_paths = Vec::new();
    let project_config_paths = Vec::new();
    let clients = Vec::new();
    let runtime = serde_json::json!({});
    let effective_configuration = serde_json::json!({});
    let config = ScanConfig {
        history: false,
        execution: ScanExecutionConfig {
            root: &root,
            log_path: &log_path,
            sinks: &sinks,
            state_path: &state_path,
            dry_run: false,
            emit_activity: false,
            emit_session_risk_summary: false,
            allow_fixtures: true,
            rule_pack_paths: &rule_pack_paths,
            rule_paths: &rule_paths,
            override_paths: &override_paths,
            rule_load_mode: RuleLoadMode::IncludeDefault,
            policy_path: None,
            allowlist_path: None,
            baseline_deviation_scoring: false,
            clients: &clients,
            project_config_paths: &project_config_paths,
            install_inventory_interval_seconds: None,
            health_heartbeat_interval_seconds: None,
            process_chain: true,
            operational_alerts: Default::default(),
            runtime: &runtime,
            effective_configuration: &effective_configuration,
        },
        backfill: false,
        rebuild_baselines: false,
        max_sources: None,
        diagnostics: None,
    };

    let error = match run_scan_for_platform(
        config,
        ScanTargets::Full,
        StateSavePolicy::Always,
        true,
        &mut ScanRecorder::disabled(),
    ) {
        Ok(_) => panic!("Windows durable scan must be rejected"),
        Err(error) => error,
    };
    let delivery = error
        .downcast_ref::<DeliveryError>()
        .expect("platform rejection must be structured");
    assert_eq!(delivery.class, DeliveryErrorClass::DurableStorage);
    assert_eq!(delivery.attempts, 0);
    assert_eq!(
        delivery.message,
        crate::sink::outbox::WINDOWS_DURABLE_STORAGE_UNSUPPORTED
    );

    assert_eq!(
        fs::read(&state_path).expect("read state after rejection"),
        state_before
    );
    assert!(!log_path.exists());
    assert!(!outbox_path.parent().expect("outbox parent").exists());
    assert!(!outbox_path.exists());
    assert_eq!(delivery_calls.load(Ordering::SeqCst), 0);
}

#[test]
fn state_change_probe_detects_durable_changes_only() {
    let source = Source {
        client: ClientId::OpenCode,
        kind: SourceKind::Sqlite,
        source_id: "opencode.sqlite".to_string(),
        path: PathBuf::from("/watch-test/opencode/opencode.db"),
    };
    let mut state = ScanState::default();
    state.observe_sources(std::slice::from_ref(&source), 1_000);
    state.observe_sqlite_ingestion_cursor(&source, OPENCODE_SQLITE_PART_TABLE, 5_000, 1_000);

    let probe = StateChangeProbe::capture(&state);
    assert!(!probe.changed(&state));

    // Refreshing the observation timestamp for a known source is not durable.
    state.observe_sources(std::slice::from_ref(&source), 2_000);
    assert!(!probe.changed(&state));

    // Advancing a SQLite ingestion cursor is durable.
    state.observe_sqlite_ingestion_cursor(&source, OPENCODE_SQLITE_PART_TABLE, 6_000, 2_000);
    assert!(probe.changed(&state));

    // A newly observed source is durable.
    let probe = StateChangeProbe::capture(&state);
    let new_source = test_source("/watch-test/codex/sessions/session-b.jsonl");
    state.observe_sources(std::slice::from_ref(&new_source), 3_000);
    assert!(probe.changed(&state));

    // New fingerprints (emitted events / baseline contributions) are durable.
    let probe = StateChangeProbe::capture(&state);
    state
        .seen_source_fingerprints
        .insert("fingerprint".to_string());
    assert!(probe.changed(&state));

    // A new or changed install inventory snapshot is durable.
    let probe = StateChangeProbe::capture(&state);
    state.install_inventory = Some(InstallInventorySnapshot {
        observed_at_unix_ms: 4_000,
        hash: "hash-a".to_string(),
        agents: vec![],
    });
    assert!(probe.changed(&state));

    // An unchanged install inventory snapshot is not durable.
    let probe = StateChangeProbe::capture(&state);
    state.install_inventory = Some(InstallInventorySnapshot {
        observed_at_unix_ms: 4_000,
        hash: "hash-a".to_string(),
        agents: vec![],
    });
    assert!(!probe.changed(&state));

    // Changing the install inventory hash is durable.
    let probe = StateChangeProbe::capture(&state);
    state.install_inventory = Some(InstallInventorySnapshot {
        observed_at_unix_ms: 6_000,
        hash: "hash-b".to_string(),
        agents: vec![],
    });
    assert!(probe.changed(&state));
}
