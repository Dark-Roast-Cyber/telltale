use crate::event::scanner_error_event;
use std::fs;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use telltale_sources::acquisition::{
    AcquisitionError, AcquisitionProgress, RecordCounts, SessionAccounting, SourceAccounting,
};

use super::discovery::ProjectConfigurationAccounting;
use super::*;
use crate::install_inventory::InstallInventorySnapshot;
use crate::sink::{DeliveryError, DeliveryErrorClass, EventSink, LocalJsonlSink, RotationConfig};

#[test]
fn scanner_health_alert_thresholds_are_strict_and_error_alert_precedes_duration_alert() {
    let config = OperationalAlertConfig {
        max_scanner_errors: 3,
        max_scan_duration_ms: 100,
    };
    for (errors, duration, expected) in [
        (2, 99, vec![]),
        (3, 100, vec![]),
        (4, 100, vec!["scanner_error_threshold"]),
        (3, 101, vec!["scan_duration_threshold"]),
        (
            4,
            101,
            vec!["scanner_error_threshold", "scan_duration_threshold"],
        ),
    ] {
        // The scan path applies the latch. This locks the strict comparison.
        let alerts = scanner_health_alerts(&config, errors, duration, true);
        assert_eq!(
            alerts
                .iter()
                .map(|event| event.check_name.as_deref().unwrap())
                .collect::<Vec<_>>(),
            expected,
            "errors={errors}, duration={duration}",
        );
    }
}

#[test]
fn source_parse_outage_alerts_only_when_every_source_of_a_client_fails() {
    let outcomes = client_parse_outcomes([
        (ClientId::Claude, true),
        (ClientId::Codex, true),
        (ClientId::Claude, true),
        (ClientId::Codex, false),
        (ClientId::Qwen, false),
    ]);
    assert_eq!(
        outcomes,
        vec![
            (ClientId::Claude, 2, true),
            (ClientId::Codex, 2, false),
            (ClientId::Qwen, 1, false),
        ]
    );
    assert!(client_parse_outcomes([]).is_empty());

    // New outage alerts; unchanged stays quiet; recovery re-arms it.
    let mut state = ScanState::default();
    assert!(state.enter_source_outage("claude"));
    assert!(!state.enter_source_outage("claude"));
    assert!(state.enter_source_outage("codex"));
    state.clear_source_outage("claude");
    assert!(state.enter_source_outage("claude"));
    assert!(!state.enter_source_outage("codex"));

    let alert = &source_parse_outage_alert(ClientId::Claude, 2);
    assert_eq!(alert.event_type, "operational_alert");
    assert_eq!(alert.severity, "warning");
    assert_eq!(alert.check_name.as_deref(), Some("operational_alert"));
    assert_eq!(alert.status.as_deref(), Some("degraded"));
    let evidence = |field: &str| {
        alert
            .evidence
            .iter()
            .find(|evidence| evidence.field == field)
            .map(|evidence| evidence.redacted_value.as_str())
    };
    assert_eq!(evidence("alert_type"), Some("source_parse_outage"));
    assert_eq!(
        evidence("actual_value"),
        Some("client=claude; selected_sources=2; processed_sources=0")
    );
    assert!(
        telltale_schema::event::Event3Record::from_json(&serde_json::to_vec(alert).unwrap())
            .is_ok()
    );
}

#[test]
fn source_event_selection_preserves_order_accounting_and_backfill_state() {
    let source = Source {
        client: ClientId::OpenCode,
        kind: SourceKind::Sqlite,
        source_id: "synthetic-selection".to_string(),
        path: PathBuf::from("synthetic-selection.db"),
    };
    let error = scanner_error_event(&source, &AcquisitionError::SourceRead);
    let event = |kind: &str| {
        let mut event = error.clone();
        event.event_type = kind.to_string();
        (source.clone(), event)
    };
    let activities = vec![event("activity")];
    let detections = vec![
        event("detection"),
        event("detection"),
        event("scanner_error"),
        event("process_chain"),
    ];
    let summaries = vec![event("session_risk_summary")];
    let mut state = ScanState::default();
    let first = select_source_events(
        &mut state,
        false,
        activities.clone(),
        detections.clone(),
        summaries.clone(),
        &BTreeSet::new(),
    );
    assert_eq!(
        first
            .events
            .iter()
            .map(|event| event.event_type.as_str())
            .collect::<Vec<_>>(),
        [
            "activity",
            "detection",
            "scanner_error",
            "process_chain",
            "session_risk_summary"
        ],
    );
    assert_eq!(first.emitted_detection_count, 1);
    assert_eq!(first.deduplicated_detection_count, 1);
    assert!(first.scanner_error_emitted);
    let recorded_state = state.canonical_bytes().unwrap();
    let repeated = select_source_events(
        &mut state,
        false,
        activities.clone(),
        detections.clone(),
        summaries.clone(),
        &BTreeSet::new(),
    );
    assert!(repeated.events.is_empty());
    assert_eq!(repeated.emitted_detection_count, 0);
    assert_eq!(repeated.deduplicated_detection_count, 2);
    assert!(!repeated.scanner_error_emitted);
    assert_eq!(state.canonical_bytes().unwrap(), recorded_state);

    for mut state in [state, ScanState::default()] {
        let before = state.canonical_bytes().unwrap();
        let backfill = select_source_events(
            &mut state,
            true,
            activities.clone(),
            detections.clone(),
            summaries.clone(),
            &BTreeSet::new(),
        );
        assert_eq!(backfill.events.len(), 6);
        assert_eq!(backfill.emitted_detection_count, 2);
        assert_eq!(backfill.deduplicated_detection_count, 0);
        assert!(backfill.scanner_error_emitted);
        assert_eq!(state.canonical_bytes().unwrap(), before);
    }
}

#[test]
fn second_shell_occurrence_does_not_reemit_until_download_or_api_key_evidence() {
    use crate::event::{DetectionEventInput, detection_event};

    let rule_set = crate::rules::load_default_rule_set().expect("default rules");
    let routine_rules = routine_evidence_rule_ids(&rule_set);
    assert!(!routine_rules.contains("credential.api_key.pattern"));
    assert!(routine_rules.contains("execution.shell"));
    assert!(!routine_rules.contains("network.download"));

    let source = Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "synthetic-session".to_string(),
        path: PathBuf::from("synthetic-session.jsonl"),
    };
    let evidence = |rule_id: &str, marker: &str| Evidence {
        field: "command".to_string(),
        redacted_value: marker.to_string(),
        hash: Some(format!("hash-{marker}")),
        rule_id: Some(rule_id.to_string()),
    };
    let detection = |items: Vec<Evidence>, event_time: &str| {
        detection_event(DetectionEventInput {
            client: ClientId::Codex,
            agent: None,
            model: None,
            provider: None,
            session_id: "synthetic-session".to_string(),
            source_path_hash: "synthetic-path".to_string(),
            tool_name: Some("shell".to_string()),
            rule_ids: vec!["execution.shell".to_string()],
            categories: vec!["execution".to_string()],
            detection_classes: vec!["security_detection".to_string()],
            signal_types: vec!["atomic".to_string()],
            analytic_intents: vec!["alert".to_string()],
            atlas_tags: Vec::new(),
            tags: vec!["synthetic".to_string()],
            evidence: items,
            risk_contributions: Vec::new(),
            event_time: Some(event_time.to_string()),
        })
        .expect("detection")
    };
    let selected = |state: &mut ScanState, event: Event| {
        select_source_events(
            state,
            false,
            Vec::new(),
            vec![(source.clone(), event)],
            Vec::new(),
            &routine_rules,
        )
    };

    let mut state = ScanState::default();
    let first = selected(
        &mut state,
        detection(
            vec![evidence("execution.shell", "shell-1")],
            "2026-05-01T00:00:00.000Z",
        ),
    );
    assert_eq!(first.emitted_detection_count, 1);
    assert_eq!(first.events.len(), 1);

    let second = selected(
        &mut state,
        detection(
            vec![evidence("execution.shell", "shell-2")],
            "2026-05-01T00:01:00.000Z",
        ),
    );
    assert!(second.events.is_empty());
    assert_eq!(second.emitted_detection_count, 0);
    assert_eq!(second.deduplicated_detection_count, 1);

    let download = selected(
        &mut state,
        detection(
            vec![
                evidence("execution.shell", "shell-2"),
                evidence("network.download", "synthetic-download"),
            ],
            "2026-05-01T00:02:00.000Z",
        ),
    );
    assert_eq!(download.emitted_detection_count, 1);
    assert_eq!(download.events.len(), 1);

    let api_key = selected(
        &mut state,
        detection(
            vec![
                evidence("execution.shell", "shell-2"),
                evidence("credential.api_key.pattern", "synthetic-token"),
            ],
            "2026-05-01T00:03:00.000Z",
        ),
    );
    assert_eq!(api_key.emitted_detection_count, 1);
    assert_eq!(api_key.events.len(), 1);
}

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

fn opencode_test_source() -> Source {
    Source {
        client: ClientId::OpenCode,
        kind: SourceKind::Sqlite,
        source_id: "opencode.sqlite".to_string(),
        path: PathBuf::from("/synthetic/opencode.db"),
    }
}

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

struct CountingSink {
    calls: Arc<AtomicUsize>,
}

impl EventSink for CountingSink {
    fn name(&self) -> &str {
        "synthetic"
    }

    fn emit(&self, _events: &[Event]) -> Result<(), Box<dyn std::error::Error>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    fn emit_canonical_once(&self, _payload: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

fn test_source(path: &str) -> Source {
    Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "codex.sessions".to_string(),
        path: PathBuf::from(path),
    }
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

fn test_discovery_accounting() -> SourceDiscoveryAccounting {
    SourceDiscoveryAccounting {
        checked_status: "succeeded",
        first_error_category: None,
        best_effort_fallback_used: false,
        returned_source_count: 0,
        operational_source_count: 0,
        project_configuration: ProjectConfigurationAccounting::none(),
    }
}

#[test]
fn source_processing_sums_tool_table_counts_across_sources_and_names_nothing() {
    use telltale_sources::acquisition::ToolTableCounts;

    let result =
        |unclassified_tool_calls, tool_operand_drift| canonical::CanonicalProcessingResult {
            events: vec![],
            status: SourceProcessingStatus::Succeeded,
            progress: AcquisitionProgress::None,
            completion: None,
            failure: None,
            accounting: vec![SourceAccounting {
                tool_table: ToolTableCounts {
                    unclassified_tool_calls,
                    tool_operand_drift,
                },
                ..Default::default()
            }],
            baseline_replacement: BaselineReplacement::NoReplacement,
            policy_accounting: None,
            quarantined: Vec::new(),
            bounded: Vec::new(),
        };
    let summary = source_processing_accounting(&[result(2, 1), result(3, 0)])
        .unwrap()
        .json();
    assert_eq!(summary["unclassified_tool_calls"], 5);
    assert_eq!(summary["tool_operand_drift"], 1);
    let quiet = source_processing_accounting(&[result(0, 0)])
        .unwrap()
        .json();
    assert_eq!(quiet["unclassified_tool_calls"], 0);
    assert_eq!(quiet["tool_operand_drift"], 0);
}

/// A bounded unit as an adapter reports it (the type is not
/// constructible outside its crate), moved to the given coordinates.
fn bounded_entry(
    native_id: &str,
    source_sequence: u64,
    target: telltale_schema::observation::BoundedTarget,
) -> (String, telltale_sources::acquisition::BoundedUnit) {
    use telltale_schema::clients::{ClientId, SourceKind};
    use telltale_schema::observation::ObservedAt;
    use telltale_sources::acquisition::{AcquisitionOptions, acquire_source};

    let temp = tempfile::tempdir().unwrap();
    let source = Source {
        client: ClientId::Codex,
        source_id: "codex.sessions".into(),
        kind: SourceKind::Jsonl,
        path: temp.path().join("synthetic-bounded.jsonl"),
    };
    let record = serde_json::json!({"type": "tool_result", "session_id": "synthetic",
            "name": "exec", "output": ["x".repeat(4_097)]});
    std::fs::write(&source.path, format!("{record}\n")).unwrap();
    let options = AcquisitionOptions::new(ObservedAt::new("2026-09-18T12:00:00Z").unwrap());
    let batch = acquire_source(&source, options).unwrap();
    let [unit] = batch.bounded.as_slice() else {
        panic!("expected one bounded unit: {:?}", batch.bounded)
    };
    let mut unit = unit.clone();
    unit.native_id = native_id.to_string();
    unit.source_sequence = source_sequence;
    unit.target = target;
    ("synthetic-source".to_string(), unit)
}

#[test]
fn bounded_value_units_count_each_unit_once_however_its_entries_are_spread() {
    use telltale_schema::observation::BoundedTarget;

    // A later drain window appends a second entry of `call-a` after the
    // entry of another unit.
    let entries = vec![
        bounded_entry("call-a", 1, BoundedTarget::Arguments),
        bounded_entry("call-b", 2, BoundedTarget::Result),
        bounded_entry("call-a", 1, BoundedTarget::Result),
    ];
    let result = canonical::CanonicalProcessingResult {
        events: vec![],
        status: SourceProcessingStatus::Succeeded,
        progress: AcquisitionProgress::None,
        completion: None,
        failure: None,
        accounting: vec![SourceAccounting::default()],
        baseline_replacement: BaselineReplacement::NoReplacement,
        policy_accounting: None,
        quarantined: Vec::new(),
        bounded: entries.clone(),
    };
    let summary = source_processing_accounting(&[result]).unwrap().json();
    assert_eq!(summary["bounded_value_unit_count"], 2);
    let listed = summary["bounded_value_units"].as_array().unwrap();
    let listed: Vec<_> = listed
        .iter()
        .map(|entry| {
            (
                entry["native_id"].as_str().unwrap(),
                entry["target"].as_str().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        listed,
        [
            ("call-a", "arguments"),
            ("call-b", "result"),
            ("call-a", "result")
        ]
    );

    // The cap counts units, not entries: every entry of a listed unit is
    // kept, and a count above the distinct units listed shows the cut.
    let (count, reported) = bounded_value_units(&entries, 1);
    assert_eq!(count, 2);
    let reported: Vec<_> = reported
        .iter()
        .map(|entry| {
            (
                entry["native_id"].as_str().unwrap(),
                entry["target"].as_str().unwrap(),
            )
        })
        .collect();
    assert_eq!(reported, [("call-a", "arguments"), ("call-a", "result")]);
    let (count, reported) = bounded_value_units(&entries, 2);
    assert_eq!((count, reported.len()), (2, 3));
}

fn warning_codes(warnings: &[serde_json::Value]) -> Vec<&str> {
    warnings
        .iter()
        .map(|warning| warning["code"].as_str().expect("warning code"))
        .collect()
}

#[test]
fn source_processing_counts_empty_successes_across_sessions_and_unscoped_records() {
    use telltale_schema::observation::CorrelationId;

    let result = |accounting: Option<SourceAccounting>| canonical::CanonicalProcessingResult {
        events: vec![],
        status: if accounting.is_some() {
            SourceProcessingStatus::Succeeded
        } else {
            SourceProcessingStatus::Failed
        },
        progress: AcquisitionProgress::None,
        completion: None,
        failure: None,
        accounting: accounting.into_iter().collect(),
        baseline_replacement: BaselineReplacement::NoReplacement,
        policy_accounting: None,
        quarantined: Vec::new(),
        bounded: Vec::new(),
    };
    let mut nonempty = SourceAccounting::default();
    nonempty.sessions.push(SessionAccounting {
        session_id: CorrelationId::source_reported("synthetic-session").unwrap(),
        metadata: Default::default(),
        counts: Default::default(),
    });
    nonempty.sessions[0].counts.record_counts = RecordCounts {
        user_message: 1,
        tool_call: 2,
        ..Default::default()
    };
    nonempty.unscoped.record_counts = RecordCounts {
        other: 3,
        ..Default::default()
    };
    for (source, successes, empties, errors, records) in [
        (Some(SourceAccounting::default()), 1, 1, 0, 0),
        (Some(nonempty.clone()), 1, 0, 0, 6),
        (None, 0, 0, 1, 0),
    ] {
        let counts = source_processing_accounting(&[result(source)]).unwrap();
        assert_eq!(counts.selected_source_count, 1);
        assert_eq!(counts.parse_success_source_count, successes);
        assert_eq!(counts.empty_source_count, empties);
        assert_eq!(counts.parse_error_source_count, errors);
        assert_eq!(counts.parsed_record_count, records);
    }

    let counts = source_processing_accounting(&[
        result(Some(SourceAccounting::default())),
        result(Some(nonempty)),
        result(None),
    ])
    .unwrap();
    assert_eq!(counts.selected_source_count, 3);
    assert_eq!(counts.parse_success_source_count, 2);
    assert_eq!(counts.empty_source_count, 1);
    assert_eq!(counts.parse_error_source_count, 1);
    assert_eq!(counts.parsed_record_count, 6);
    assert_eq!(counts.record_kind_counts["user_message"], 1);
    assert_eq!(counts.record_kind_counts["tool_call"], 2);
    assert_eq!(counts.record_kind_counts["other"], 3);
    let flow = DetectionFlowAccounting {
        effective_detection_candidate_count: 0,
        matched_rule_id_count: 0,
        allowlist_marked_detection_count: 0,
        state_deduplicated_detection_count: 0,
        emitted_detection_count: 0,
        policy_match_accounting: PolicyMatchAccountingState::NotApplicable,
    };
    assert_eq!(
        warning_codes(&diagnostic_warnings(
            &test_discovery_accounting(),
            &counts,
            &flow,
            18
        )),
        vec![
            "source_parse_error_observed",
            "source_coverage_partial",
            "no_effective_detection_candidates"
        ]
    );
}

#[test]
fn policy_accounting_without_pre_policy_results_is_unavailable() {
    let state = compute_policy_match_accounting(true, false, &[]);
    let flow = DetectionFlowAccounting {
        effective_detection_candidate_count: 0,
        matched_rule_id_count: 0,
        allowlist_marked_detection_count: 0,
        state_deduplicated_detection_count: 0,
        emitted_detection_count: 0,
        policy_match_accounting: state,
    };
    let accounting = flow.json()["policy_match_accounting"].clone();
    assert_eq!(accounting["status"], "unavailable");
    assert!(accounting["pre_policy_detection_candidate_count"].is_null());
    assert!(accounting["fully_filtered_detection_candidate_count"].is_null());
    assert!(accounting["filtered_rule_id_count"].is_null());
}

#[test]
fn suspicious_zero_warning_predicates_keep_empty_and_dedup_cases_distinct() {
    let discovery = test_discovery_accounting();
    let flow = DetectionFlowAccounting {
        effective_detection_candidate_count: 0,
        matched_rule_id_count: 0,
        allowlist_marked_detection_count: 0,
        state_deduplicated_detection_count: 0,
        emitted_detection_count: 0,
        policy_match_accounting: PolicyMatchAccountingState::NotApplicable,
    };
    let no_sources = SourceProcessingAccounting {
        selected_source_count: 0,
        parse_success_source_count: 0,
        empty_source_count: 0,
        parse_error_source_count: 0,
        parsed_record_count: 0,
        record_kind_counts: BTreeMap::new(),
        ..Default::default()
    };
    assert_eq!(
        warning_codes(&diagnostic_warnings(&discovery, &no_sources, &flow, 18)),
        vec!["no_sources_selected"]
    );

    let empty_sources = SourceProcessingAccounting {
        selected_source_count: 2,
        parse_success_source_count: 2,
        empty_source_count: 2,
        parse_error_source_count: 0,
        parsed_record_count: 0,
        record_kind_counts: BTreeMap::new(),
        ..Default::default()
    };
    assert_eq!(
        warning_codes(&diagnostic_warnings(&discovery, &empty_sources, &flow, 18)),
        vec!["selected_sources_produced_no_records"]
    );

    let productive_sources = SourceProcessingAccounting {
        selected_source_count: 2,
        parse_success_source_count: 2,
        empty_source_count: 1,
        parse_error_source_count: 0,
        parsed_record_count: 1,
        record_kind_counts: BTreeMap::from([("user_message".to_string(), 1)]),
        ..Default::default()
    };
    assert_eq!(
        warning_codes(&diagnostic_warnings(
            &discovery,
            &productive_sources,
            &flow,
            18
        )),
        vec![
            "no_tool_records_observed",
            "no_effective_detection_candidates"
        ]
    );
    assert!(
        !warning_codes(&diagnostic_warnings(
            &discovery,
            &productive_sources,
            &flow,
            0,
        ))
        .contains(&"no_effective_detection_candidates")
    );

    let repeated_positive = DetectionFlowAccounting {
        effective_detection_candidate_count: 1,
        state_deduplicated_detection_count: 1,
        ..flow
    };
    assert!(
        !warning_codes(&diagnostic_warnings(
            &discovery,
            &SourceProcessingAccounting {
                selected_source_count: 1,
                parse_success_source_count: 1,
                empty_source_count: 0,
                parse_error_source_count: 0,
                parsed_record_count: 1,
                record_kind_counts: BTreeMap::from([("tool_call".to_string(), 1)]),
                ..Default::default()
            },
            &repeated_positive,
            18,
        ))
        .contains(&"no_effective_detection_candidates")
    );
}

#[test]
fn session_summary_unions_exact_contributions_by_source_identity() {
    use crate::event::{ActivityEventInput, activity_event};
    use crate::scoring::{RiskContribution, RiskContributionType};

    let contribution = || {
        RiskContribution::new(
            "baseline.synthetic",
            RiskContributionType::BaselineDeviation,
            30,
            "synthetic rule match",
        )
        .expect("contribution")
    };
    let event = || {
        activity_event(ActivityEventInput {
            client: ClientId::Codex,
            agent: None,
            model: None,
            provider: None,
            session_id: "session-union".to_string(),
            source_path_hash: "path".to_string(),
            tool_name: Some("shell".to_string()),
            tags: vec!["activity".to_string()],
            evidence: Vec::new(),
            risk_contributions: vec![contribution()],
            event_time: None,
        })
        .expect("build activity event")
    };
    let source_a = Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "source-a".to_string(),
        path: PathBuf::from("a.jsonl"),
    };
    let source_b = Source {
        source_id: "source-b".to_string(),
        path: PathBuf::from("b.jsonl"),
        ..source_a.clone()
    };
    let source_alias = Source {
        path: PathBuf::from("alias.jsonl"),
        ..source_a.clone()
    };
    let mut first_event = event();
    first_event.agent = Some("first-agent".to_string());
    first_event.timestamp = "2026-05-01T00:00:00Z".to_string();
    let mut later_event = event();
    later_event.agent = Some("later-agent".to_string());
    later_event.timestamp = "2026-05-02T00:00:00Z".to_string();

    let summaries = summarize_session_risk_events(
        &[
            (source_b, event()),
            (source_a.clone(), first_event),
            (source_alias, later_event),
        ],
        &[],
    )
    .expect("summary");
    assert_eq!(summaries.len(), 2);
    assert_eq!(summaries[0].0, source_a);
    assert_eq!(summaries[1].0.source_id, "source-b");
    assert_eq!(summaries[0].1.agent.as_deref(), Some("first-agent"));
    assert_eq!(summaries[0].1.timestamp, "2026-05-02T00:00:00.000Z");
    assert!(
        summaries
            .iter()
            .all(|(_, summary)| summary.risk_score == 30)
    );
    assert!(
        summaries
            .iter()
            .all(|(_, summary)| summary.risk_contributions.len() == 1)
    );
    let serialized = serde_json::to_value(&summaries[0].1).expect("serialize summary");
    assert_eq!(serialized["risk_score"], 30);
    assert_eq!(
        serialized["risk_contributions"][0]["id"],
        "baseline.synthetic"
    );
}

#[test]
fn session_summary_rejects_conflicting_contribution_metadata() {
    use crate::event::{ActivityEventInput, activity_event};
    use crate::scoring::{RiskContribution, RiskContributionType};

    let source = Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "source-conflict".to_string(),
        path: PathBuf::from("conflict.jsonl"),
    };
    let make_event = |points| {
        activity_event(ActivityEventInput {
            client: ClientId::Codex,
            agent: None,
            model: None,
            provider: None,
            session_id: "session-conflict".to_string(),
            source_path_hash: "path".to_string(),
            tool_name: None,
            tags: Vec::new(),
            evidence: Vec::new(),
            risk_contributions: vec![
                RiskContribution::new(
                    "baseline.synthetic",
                    RiskContributionType::BaselineDeviation,
                    points,
                    "synthetic rule match",
                )
                .expect("contribution"),
            ],
            event_time: None,
        })
        .expect("build activity event")
    };

    let result = summarize_session_risk_events(
        &[(source.clone(), make_event(30)), (source, make_event(31))],
        &[],
    );
    assert!(matches!(
        result,
        Err(RiskAccountingError::ConflictingContribution(id)) if id == "baseline.synthetic"
    ));
}

#[test]
fn session_risk_summary_default_is_off_and_growth_dedups_until_a_rule_id_is_added() {
    use crate::event::{ActivityEventInput, DetectionEventInput, activity_event, detection_event};
    use crate::scoring::{RiskContribution, RiskContributionType};

    let emit_session_risk_summary = crate::settings::Settings::default()
        .emit_session_risk_summary
        .value;
    assert!(!emit_session_risk_summary);

    let source = Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "synthetic-session".to_string(),
        path: PathBuf::from("synthetic-session.jsonl"),
    };
    let contribution = RiskContribution::new(
        "rule.synthetic",
        RiskContributionType::DeterministicRule,
        30,
        "synthetic rule match",
    )
    .expect("contribution");
    let activity = |tool_calls: u64, event_time: &str| {
        (
            source.clone(),
            activity_event(ActivityEventInput {
                client: ClientId::Codex,
                agent: Some("synthetic-agent".to_string()),
                model: Some("synthetic-model".to_string()),
                provider: Some("synthetic-provider".to_string()),
                session_id: "synthetic-session".to_string(),
                source_path_hash: "synthetic-path".to_string(),
                tool_name: Some("shell".to_string()),
                tags: vec!["activity".to_string()],
                evidence: vec![Evidence {
                    field: "record_counts".to_string(),
                    redacted_value: format!(r#"{{"tool_call":{tool_calls}}}"#),
                    hash: None,
                    rule_id: None,
                }],
                risk_contributions: Vec::new(),
                event_time: Some(event_time.to_string()),
            })
            .expect("activity"),
        )
    };
    let detection =
        |rule_id: &str, contributions: Vec<RiskContribution>, event_time: &str, marker: &str| {
            (
                source.clone(),
                detection_event(DetectionEventInput {
                    client: ClientId::Codex,
                    agent: Some("synthetic-agent".to_string()),
                    model: Some("synthetic-model".to_string()),
                    provider: Some("synthetic-provider".to_string()),
                    session_id: "synthetic-session".to_string(),
                    source_path_hash: "synthetic-path".to_string(),
                    tool_name: Some("shell".to_string()),
                    rule_ids: vec![rule_id.to_string()],
                    categories: vec!["execution".to_string()],
                    detection_classes: vec!["security_detection".to_string()],
                    signal_types: vec!["atomic".to_string()],
                    analytic_intents: vec!["alert".to_string()],
                    atlas_tags: Vec::new(),
                    tags: vec!["synthetic".to_string()],
                    evidence: vec![Evidence {
                        field: "match".to_string(),
                        redacted_value: marker.to_string(),
                        hash: None,
                        rule_id: None,
                    }],
                    risk_contributions: contributions,
                    event_time: Some(event_time.to_string()),
                })
                .expect("detection"),
            )
        };
    let initial = (
        vec![activity(1, "2026-05-01T00:00:00Z")],
        vec![detection(
            "rule.synthetic",
            vec![contribution.clone()],
            "2026-05-01T00:00:01Z",
            "one",
        )],
    );
    let grown = (
        vec![activity(4, "2026-05-02T00:00:00Z")],
        vec![
            detection(
                "rule.synthetic",
                vec![contribution.clone()],
                "2026-05-01T00:00:01Z",
                "one",
            ),
            detection(
                "rule.synthetic",
                vec![contribution],
                "2026-05-02T00:00:01Z",
                "two",
            ),
        ],
    );
    let added_rule = (grown.0.clone(), {
        let mut detections = grown.1.clone();
        detections.push(detection(
            "rule.added",
            Vec::new(),
            "2026-05-03T00:00:00Z",
            "three",
        ));
        detections
    });

    fn emitted_summaries(
        state: &mut ScanState,
        emit: bool,
        activities: Vec<(Source, Event)>,
        detections: Vec<(Source, Event)>,
    ) -> Vec<Event> {
        let summaries =
            session_risk_summaries_for_scan(emit, &activities, &detections).expect("summaries");
        select_source_events(
            state,
            false,
            activities,
            detections,
            summaries,
            &BTreeSet::new(),
        )
        .events
        .into_iter()
        .filter(|event| event.event_type == "session_risk_summary")
        .collect()
    }
    fn built_summary(activities: &[(Source, Event)], detections: &[(Source, Event)]) -> Event {
        let mut summaries = summarize_session_risk_events(activities, detections).expect("summary");
        assert_eq!(summaries.len(), 1);
        summaries.pop().expect("summary").1
    }

    let mut state = ScanState::default();
    assert!(
        emitted_summaries(
            &mut state,
            emit_session_risk_summary,
            initial.0.clone(),
            initial.1.clone(),
        )
        .is_empty()
    );

    let first = emitted_summaries(&mut state, true, initial.0.clone(), initial.1.clone());
    assert_eq!(first.len(), 1);
    let built = built_summary(&initial.0, &initial.1);
    let evidence = |event: &Event| serde_json::to_value(&event.evidence).expect("evidence");
    assert_eq!(evidence(&first[0]), evidence(&built));
    assert_eq!(first[0].event_time, built.event_time);
    assert!(first[0].event_time.is_some());
    assert!(first[0].evidence.iter().any(|item| {
        matches!(
            item.field.as_str(),
            "event_counts" | "risky_action_count" | "tool_call_count"
        )
    }));

    let grown_summary = built_summary(&grown.0, &grown.1);
    assert_eq!(grown_summary.severity, first[0].severity);
    assert_eq!(grown_summary.risk_score, first[0].risk_score);
    assert_eq!(grown_summary.rule_ids, first[0].rule_ids);
    assert_ne!(evidence(&grown_summary), evidence(&first[0]));
    assert_ne!(grown_summary.event_time, first[0].event_time);
    assert!(emitted_summaries(&mut state, true, grown.0, grown.1).is_empty());

    let second = emitted_summaries(&mut state, true, added_rule.0, added_rule.1);
    assert_eq!(second.len(), 1);
    assert_eq!(second[0].severity, first[0].severity);
    assert_eq!(second[0].risk_score, first[0].risk_score);
    assert_eq!(
        second[0].rule_ids,
        vec!["rule.added".to_string(), "rule.synthetic".to_string()]
    );
}

#[test]
fn operational_json_omits_hostile_sink_names() {
    let sink_name = "https://sink-owner.example.invalid/private";
    let alert = sink_failure_alert_event(&SinkFailure {
        name: sink_name.to_string(),
        kind: "splunk_hec".to_string(),
        class: crate::sink::DeliveryErrorClass::UnknownInternal,
        attempts: 1,
        error: "connection refused".to_string(),
        prior_attempts: 0,
        prior_error_class: None,
    });
    let alert_bytes = serde_json::to_vec(&alert).expect("serialize sink alert");
    assert!(
        !String::from_utf8_lossy(&alert_bytes).contains(sink_name),
        "operational alert exposed a hostile sink name"
    );
}

#[test]
fn status_json_omits_hostile_health_fields() {
    let marker = "sk-abcdefgh";
    let hostile_health = serde_json::json!({
        "schema_version": "3.0",
        "event_type": "health",
        "timestamp": "2026-05-01T00:00:00Z",
        "component": marker,
        "check_name": marker,
        "status": marker,
        "active_policy_name": marker,
        "source_counts": { marker: 1 },
    });
    let status = status_json(
        "ok",
        Some(&hostile_health),
        0,
        std::path::Path::new("/tmp/telltale-events.jsonl"),
        std::path::Path::new("/tmp/telltale-state.json"),
        serde_json::json!({"mode": "not_configured", "sinks": {}}),
    );
    let status_bytes = serde_json::to_vec(&status).expect("serialize status");
    assert!(
        !String::from_utf8_lossy(&status_bytes).contains(marker),
        "status output exposed hostile health metadata"
    );
    assert_eq!(
        status["durable_queue_health"],
        serde_json::json!({"mode": "not_configured", "sinks": {}})
    );
    assert_eq!(status["attention_required"], serde_json::Value::Null);
}

#[test]
fn scanner_error_counts_are_positive_in_every_numeric_form() {
    let health = |count: &str| {
        serde_json::from_str::<serde_json::Value>(&format!(r#"{{"scanner_error_count":{count}}}"#))
            .expect("health json")
    };
    assert_eq!(scanner_errors_recorded(&health("0")), Some(false));
    assert_eq!(scanner_errors_recorded(&health("3")), Some(true));
    assert_eq!(
        scanner_errors_recorded(&health("18446744073709551616")),
        Some(true)
    );
    assert_eq!(scanner_errors_recorded(&health("2.0e19")), Some(true));
    assert_eq!(scanner_errors_recorded(&health("\"1\"")), None);
    assert_eq!(scanner_errors_recorded(&health("null")), None);
    assert_eq!(scanner_errors_recorded(&serde_json::json!({})), None);
}

#[test]
fn iteration_budget_counts_down_without_wrapping() {
    let mut unlimited = None;
    assert!(!iteration_budget_exhausted(&mut unlimited));
    let mut two = Some(2);
    assert!(!iteration_budget_exhausted(&mut two));
    assert!(iteration_budget_exhausted(&mut two));
    assert!(iteration_budget_exhausted(&mut Some(1)));
    // The CLI rejects zero; the counter still never wraps.
    let mut zero = Some(0);
    assert!(iteration_budget_exhausted(&mut zero));
    assert_eq!(zero, Some(0));
}

#[test]
fn health_heartbeat_is_due_once_the_interval_elapses_and_never_waits_on_a_clock_rollback() {
    let wait = health_heartbeat_wait;
    // Nothing recorded yet.
    assert_eq!(wait(None, 10_000, 60), Duration::ZERO);
    // Sooner than the interval: wait out the remainder.
    assert_eq!(wait(Some(10_000), 10_000, 60), Duration::from_secs(60));
    assert_eq!(wait(Some(10_000), 69_999, 60), Duration::from_millis(1));
    // Exactly one interval, and later, are due.
    assert_eq!(wait(Some(10_000), 70_000, 60), Duration::ZERO);
    assert_eq!(wait(Some(10_000), 10_000_000, 60), Duration::ZERO);
    // A recorded time ahead of the clock is due rather than silent.
    assert_eq!(wait(Some(10_001), 10_000, 60), Duration::ZERO);
    // Huge intervals saturate instead of overflowing.
    assert_eq!(wait(Some(0), 0, u64::MAX), Duration::from_millis(u64::MAX));
}

#[test]
fn operational_alert_reasons_are_closed_codes() {
    let alert = |alert_type: &str| {
        serde_json::json!({
            "event_type": "operational_alert",
            "evidence": [{"field": "alert_type", "redacted_value": alert_type}],
        })
    };
    assert_eq!(
        operational_alert_reason(&alert("source_parse_outage")),
        "source_parse_outage"
    );
    assert_eq!(
        operational_alert_reason(&alert("sk-abcdefgh")),
        "operational_alert"
    );
    assert_eq!(
        operational_alert_reason(&serde_json::json!({"evidence": "sk-abcdefgh"})),
        "operational_alert"
    );
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

#[cfg(test)]
mod activation;
