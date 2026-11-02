use super::*;
use crate::baseline::{BaselineKey, BaselineSummary};
use crate::sink::{EventSink, LocalJsonlSink};
use std::fs;

fn blocked_failure(sink: &str, status: u16) -> SinkFailure {
    SinkFailure {
        name: sink.into(),
        kind: "splunk_hec".into(),
        class: DeliveryErrorClass::AuthenticationBlocked { status },
        attempts: 1,
        error: "synthetic authentication failure".into(),
        prior_attempts: 0,
        prior_error_class: None,
    }
}

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
fn detection_evidence_uses_loaded_custom_and_package_severities_not_aggregate_risk() {
    let temp = tempfile::tempdir().unwrap();
    let local = temp.path().join("rules.yaml");
    fs::write(
        &local,
        r#"version: 1
description: Synthetic severity rules.
defaults: {case_insensitive: false, enabled: true}
modifiers: []
rules:
  - id: synthetic.low
    category: test
    severity: low
    score: 1
    targets: [command]
    regex: synthetic
    tags: [test]
    explanation: Synthetic low rule.
  - id: synthetic.medium
    category: test
    severity: medium
    score: 1
    targets: [command]
    regex: synthetic
    tags: [test]
    explanation: Synthetic medium rule.
"#,
    )
    .unwrap();
    let package = temp.path().join("package.yaml");
    fs::write(
        &package,
        r#"format: telltale-rule-package/v1
id: synthetic.package
version: "1.0.0"
publisher: Synthetic
license: Apache-2.0
rule_namespace: packaged
documents:
  - version: 1
    description: Synthetic packaged severity rules.
    defaults: {case_insensitive: false, enabled: true}
    modifiers: []
    rules:
      - id: packaged.high
        category: test
        severity: high
        score: 1
        targets: [command]
        regex: synthetic
        tags: [test]
        explanation: Synthetic package rule.
"#,
    )
    .unwrap();
    let resolved = resolve_rule_set_from_pack_paths_with_mode_override_paths_and_replacements(
        &RulePackPaths {
            packages: vec![package],
            ..RulePackPaths::default()
        },
        &[local],
        None,
        RuleLoadMode::CustomOnly,
        &[],
        &[],
    )
    .unwrap();
    let routine = routine_evidence_rule_ids(&resolved.rule_set);
    assert_eq!(routine, BTreeSet::from(["synthetic.low".into()]));
    let source = Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "codex.sessions".into(),
        path: temp.path().join("synthetic.jsonl"),
    };
    for rule in [
        Some("synthetic.low"),
        Some("synthetic.medium"),
        Some("packaged.high"),
        Some("native.unknown"),
        Some("network.download"),
        None,
    ] {
        let mut event = crate::event::detection_event(crate::event::DetectionEventInput {
            client: ClientId::Codex,
            agent: None,
            model: None,
            provider: None,
            session_id: "synthetic".into(),
            source_path_hash: "synthetic".into(),
            tool_name: Some("shell".into()),
            rule_ids: vec![rule.unwrap_or("native.unknown").into()],
            categories: vec!["test".into()],
            detection_classes: vec!["security_detection".into()],
            signal_types: vec!["atomic".into()],
            analytic_intents: vec!["alert".into()],
            atlas_tags: Vec::new(),
            tags: Vec::new(),
            evidence: vec![Evidence {
                field: "command".into(),
                redacted_value: "synthetic-one".into(),
                hash: None,
                rule_id: rule.map(str::to_string),
            }],
            risk_contributions: Vec::new(),
            event_time: None,
        })
        .unwrap();
        assert!(matches!(event.severity.as_str(), "informational" | "low"));
        let mut state = ScanState::default();
        assert!(state.should_emit(&source, &event, &routine));
        event.evidence[0].redacted_value = "synthetic-two".into();
        assert_eq!(
            state.should_emit(&source, &event, &routine),
            rule != Some("synthetic.low"),
            "{rule:?}"
        );
    }
}

struct Fixture {
    dir: tempfile::TempDir,
    sources: Vec<Source>,
    state: PathBuf,
    log: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".codex/sessions/synthetic.jsonl");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, "{\"type\":\"user\",\"session_id\":\"synthetic\",\"model\":\"model\",\"provider\":\"provider\",\"content\":\"hello\"}\n").unwrap();
        let opencode = telltale_sources::clients::supported_clients()
            .iter()
            .find(|client| client.id == ClientId::OpenCode)
            .unwrap();
        let sqlite = opencode
            .sources
            .iter()
            .find(|source| source.id == "opencode.sqlite")
            .unwrap();
        let db = telltale_sources::discovery::source_search_root(dir.path(), *sqlite);
        fs::create_dir_all(db.parent().unwrap()).unwrap();
        let conn = rusqlite::Connection::open(&db).unwrap();
        conn.execute_batch(r#"CREATE TABLE message (id TEXT, session_id TEXT, data TEXT);
            CREATE TABLE part (id TEXT, message_id TEXT, session_id TEXT, time_updated INTEGER, data TEXT);
            INSERT INTO message VALUES ('m','s','{"role":"assistant"}');
            INSERT INTO part VALUES ('p','m','s',10,'{"type":"tool","tool":"shell","callID":"c","state":{"status":"running","input":{"command":"echo synthetic"}}}');"#).unwrap();
        drop(conn);
        let state = dir.path().join("state.json");
        let log = dir.path().join("events.jsonl");
        let sources = vec![
            Source {
                client: ClientId::Codex,
                kind: SourceKind::Jsonl,
                source_id: "codex.sessions".into(),
                path,
            },
            Source {
                client: ClientId::OpenCode,
                kind: SourceKind::Sqlite,
                source_id: "opencode.sqlite".into(),
                path: db,
            },
        ];
        ScanState::default().save(&state).unwrap();
        Self {
            dir,
            sources,
            state,
            log,
        }
    }

    fn sinks(&self) -> SinkSet {
        let mut sinks = SinkSet::new();
        sinks.add_canonical_first_write(
            "jsonl",
            Box::new(LocalJsonlSink::with_rotation(
                &self.log,
                crate::sink::RotationConfig::disabled(),
            )),
        );
        sinks
    }

    fn scan(
        &self,
        sinks: &SinkSet,
        targeted: bool,
        dry_run: bool,
        backfill: bool,
    ) -> Result<ScanRunResult, Box<dyn std::error::Error>> {
        let packs = RulePackPaths::default();
        let value = serde_json::json!({});
        let config = ScanConfig {
            history: false,
            execution: ScanExecutionConfig {
                root: self.dir.path(),
                log_path: &self.log,
                sinks,
                state_path: &self.state,
                dry_run,
                emit_activity: true,
                emit_session_risk_summary: false,
                allow_fixtures: true,
                rule_pack_paths: &packs,
                rule_paths: &[],
                override_paths: &[],
                rule_load_mode: RuleLoadMode::IncludeDefault,
                policy_path: None,
                allowlist_path: None,
                baseline_deviation_scoring: false,
                clients: &[ClientId::Codex, ClientId::OpenCode],
                project_config_paths: &[],
                install_inventory_interval_seconds: None,
                process_chain: true,
                operational_alerts: Default::default(),
                runtime: &value,
                effective_configuration: &value,
            },
            backfill,
            rebuild_baselines: false,
            max_sources: None,
        };
        if targeted {
            // Exactly the production watch dispatch: same targets and save policy.
            run_scan(
                config,
                ScanTargets::Targeted {
                    sources: self.sources.clone(),
                    discovery: SourceDiscoveryAccounting {
                        checked_status: "complete",
                        first_error_category: None,
                        best_effort_fallback_used: false,
                        returned_source_count: self.sources.len(),
                        operational_source_count: self.sources.len(),
                        project_configuration: discovery::ProjectConfigurationAccounting::none(),
                    },
                },
                StateSavePolicy::OnChange,
            )
        } else {
            run_scan(config, ScanTargets::Full, StateSavePolicy::Always)
        }
    }

    fn load(&self) -> ScanState {
        ScanState::load(&self.state).unwrap()
    }

    fn events(&self) -> Vec<serde_json::Value> {
        fs::read_to_string(&self.log)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }
}

struct RequiredFailure;
impl EventSink for RequiredFailure {
    fn name(&self) -> &str {
        "synthetic-required-failure"
    }
    fn emit(&self, _: &[Event]) -> Result<(), Box<dyn std::error::Error>> {
        Err("synthetic output failure".into())
    }
}

struct AlertWriteFailure(LocalJsonlSink);

impl EventSink for AlertWriteFailure {
    fn name(&self) -> &str {
        "synthetic-canonical"
    }
    fn emit(&self, events: &[Event]) -> Result<(), Box<dyn std::error::Error>> {
        if events
            .iter()
            .any(|event| event.check_name.as_deref() == Some("sink_delivery"))
        {
            return Err("synthetic canonical alert write failure".into());
        }
        self.0.emit(events)
    }
}

struct AuthenticationFailure;

impl EventSink for AuthenticationFailure {
    fn name(&self) -> &str {
        "synthetic-remote"
    }
    fn emit(&self, _: &[Event]) -> Result<(), Box<dyn std::error::Error>> {
        Err(crate::sink::DeliveryError::new(
            DeliveryErrorClass::AuthenticationBlocked { status: 401 },
            1,
            "synthetic authentication failure",
        )
        .into())
    }
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

struct ThresholdHarness {
    dir: tempfile::TempDir,
    log: PathBuf,
    state: PathBuf,
    packs: RulePackPaths,
    runtime: serde_json::Value,
    clients: Vec<ClientId>,
    sources: Vec<Source>,
}

impl ThresholdHarness {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let malformed = dir.path().join(".codex/sessions/malformed-source.jsonl");
        fs::create_dir_all(malformed.parent().expect("sessions parent")).expect("sessions dir");
        fs::write(
            &malformed,
            include_str!("../../../tests/fixtures/rule_samples/malformed-source.jsonl"),
        )
        .expect("malformed fixture");
        let clients = vec![ClientId::Codex];
        let (sources, _) = discover_operational_sources(
            dir.path(),
            &clients,
            None,
            &[],
            &discovery::ProjectConfigurationAccounting::none(),
        );
        assert_eq!(
            sources.len(),
            1,
            "synthetic malformed fixture should be the only source"
        );
        assert_eq!(sources[0].path, malformed);
        Self {
            log: dir.path().join("events.jsonl"),
            state: dir.path().join("state.json"),
            packs: RulePackPaths::default(),
            runtime: serde_json::json!({}),
            clients,
            sources,
            dir,
        }
    }

    fn scan(&self, max_scanner_errors: u32, targeted: bool, backfill: bool) {
        let mut sinks = SinkSet::new();
        sinks.add_canonical_first_write(
            "jsonl",
            Box::new(LocalJsonlSink::with_rotation(
                &self.log,
                crate::sink::RotationConfig::disabled(),
            )),
        );
        let config = ScanConfig {
            history: false,
            execution: ScanExecutionConfig {
                root: self.dir.path(),
                log_path: &self.log,
                sinks: &sinks,
                state_path: &self.state,
                dry_run: false,
                emit_activity: false,
                emit_session_risk_summary: false,
                allow_fixtures: true,
                rule_pack_paths: &self.packs,
                rule_paths: &[],
                override_paths: &[],
                rule_load_mode: RuleLoadMode::IncludeDefault,
                policy_path: None,
                allowlist_path: None,
                baseline_deviation_scoring: false,
                clients: &self.clients,
                project_config_paths: &[],
                install_inventory_interval_seconds: None,
                process_chain: false,
                operational_alerts: OperationalAlertConfig {
                    max_scanner_errors,
                    max_scan_duration_ms: u64::MAX,
                },
                runtime: &self.runtime,
                effective_configuration: &self.runtime,
            },
            backfill,
            rebuild_baselines: false,
            max_sources: None,
        };
        let result = if targeted {
            run_scan(
                config,
                ScanTargets::Targeted {
                    sources: self.sources.clone(),
                    discovery: SourceDiscoveryAccounting {
                        checked_status: "complete",
                        first_error_category: None,
                        best_effort_fallback_used: false,
                        returned_source_count: self.sources.len(),
                        operational_source_count: self.sources.len(),
                        project_configuration: discovery::ProjectConfigurationAccounting::none(),
                    },
                },
                StateSavePolicy::OnChange,
            )
        } else {
            run_scan(config, ScanTargets::Full, StateSavePolicy::Always)
        };
        result.unwrap_or_else(|error| panic!("scan failed: {error}"));
    }

    fn take_events(&self) -> Vec<serde_json::Value> {
        let events = fs::read_to_string(&self.log)
            .unwrap_or_default()
            .lines()
            .filter(|line| !line.is_empty())
            .map(|line| serde_json::from_str(line).expect("event json"))
            .collect();
        if self.log.exists() {
            fs::write(&self.log, "").expect("truncate log");
        }
        events
    }

    fn latched(&self) -> bool {
        ScanState::load(&self.state)
            .expect("load state")
            .scanner_error_threshold_latched()
    }
}

fn threshold_alerts(events: &[serde_json::Value]) -> usize {
    events
        .iter()
        .filter(|event| event["check_name"] == "scanner_error_threshold")
        .count()
}

fn health_events(events: &[serde_json::Value]) -> usize {
    events
        .iter()
        .filter(|event| event["event_type"] == "health")
        .count()
}

#[test]
fn scanner_error_threshold_alerts_on_the_first_full_scan_crossing_only() {
    let harness = ThresholdHarness::new();
    let above = 0;

    harness.scan(above, false, false);
    let first = harness.take_events();
    assert_eq!(
        threshold_alerts(&first),
        1,
        "first full scan above the threshold alerts once: {first:?}"
    );
    assert_eq!(
        health_events(&first),
        1,
        "first full scan writes one health event"
    );
    assert!(
        first
            .iter()
            .any(|event| event["event_type"] == "scanner_error"),
        "new scanner_error documents still emit"
    );
    let scanner_error_count = first
        .iter()
        .find(|event| event["event_type"] == "health")
        .expect("health")["scanner_error_count"]
        .as_u64()
        .expect("scanner_error_count");
    assert!(
        scanner_error_count > above.into(),
        "pre-dedup count is above"
    );
    assert!(harness.latched(), "first crossing sets the latch");

    harness.scan(above, false, false);
    let second = harness.take_events();
    assert_eq!(
        threshold_alerts(&first) + threshold_alerts(&second),
        1,
        "two full scans over the same above-threshold set emit one threshold alert"
    );
    assert_eq!(
        health_events(&first) + health_events(&second),
        1,
        "those scans emit one health event"
    );
    assert_eq!(
        threshold_alerts(&second),
        0,
        "the second scan does not re-alert: {second:?}"
    );
    assert_eq!(
        health_events(&second),
        0,
        "a suppressed repeat does not force a health event"
    );
    assert!(
        !second
            .iter()
            .any(|event| event["event_type"] == "scanner_error"),
        "unchanged scanner_error documents still dedup"
    );
    assert!(harness.latched(), "a later full scan above keeps the latch");

    let at_threshold = u32::try_from(scanner_error_count).expect("count fits u32");
    harness.scan(at_threshold, false, false);
    let recovered = harness.take_events();
    assert_eq!(
        threshold_alerts(&recovered),
        0,
        "a full scan at the threshold does not alert"
    );
    assert!(
        !harness.latched(),
        "a full scan at or below the threshold clears the latch"
    );

    harness.scan(above, false, false);
    let again = harness.take_events();
    assert_eq!(
        threshold_alerts(&again),
        1,
        "the next full scan above alerts again: {again:?}"
    );
    assert_eq!(
        health_events(&again),
        1,
        "a threshold alert that fires writes a health event"
    );
    assert!(harness.latched(), "the new crossing sets the latch again");

    harness.scan(above, true, false);
    let targeted = harness.take_events();
    assert_eq!(
        threshold_alerts(&targeted),
        0,
        "a targeted scan does not emit the threshold alert: {targeted:?}"
    );
    assert!(
        harness.latched(),
        "a targeted scan does not clear a latch set by a full scan"
    );

    harness.scan(above, false, false);
    let after_targeted = harness.take_events();
    assert_eq!(
        threshold_alerts(&after_targeted),
        0,
        "targeted scan must not clear the latch: {after_targeted:?}"
    );
    assert_eq!(
        health_events(&after_targeted),
        0,
        "a suppressed repeat after a targeted scan does not force health"
    );

    harness.scan(above, false, true);
    let backfill = harness.take_events();
    assert_eq!(
        threshold_alerts(&backfill),
        1,
        "backfill while above repeats the alert once: {backfill:?}"
    );
    assert!(harness.latched(), "backfill does not clear the latch");

    harness.scan(above, false, false);
    let after_backfill = harness.take_events();
    assert_eq!(
        threshold_alerts(&after_backfill),
        0,
        "backfill must not clear the latch: {after_backfill:?}"
    );
    assert_eq!(
        health_events(&after_backfill),
        0,
        "a suppressed repeat after backfill does not force health"
    );
}
