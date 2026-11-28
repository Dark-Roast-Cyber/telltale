#[test]
fn fingerprints_stream_valid_bytes_and_do_not_read_oversized_sources() {
    use sha2::{Digest, Sha256};
    let dir = tempfile::tempdir().unwrap();
    let source = telltale_schema::source::Source {
        client: telltale_schema::clients::ClientId::Copilot,
        kind: telltale_schema::clients::SourceKind::CopilotProcessLog,
        source_id: "copilot.process_log".into(),
        path: dir.path().join("synthetic.log"),
    };
    let bytes = vec![b'x'; 8193];
    std::fs::write(&source.path, &bytes).unwrap();
    let mut expected = Sha256::new();
    expected.update(source.path.to_string_lossy().as_bytes());
    let path_hash = hex::encode(expected.clone().finalize());
    expected.update(bytes);
    assert_eq!(
        super::source_fingerprint(&source),
        hex::encode(expected.finalize())
    );
    std::fs::File::create(&source.path)
        .unwrap()
        .set_len(128 * 1024 * 1024 + 1)
        .unwrap();
    assert_eq!(super::source_fingerprint(&source), path_hash);
}
use std::collections::BTreeSet;
use std::path::Path;

use serde_json::Value;

use crate::baseline::{
    BASELINE_HOST_HASH_PREFIX, BaselineKey, BaselineObservationTotals, BaselineSummary, PathClass,
    baseline_host_identity,
};
use crate::event::{DetectionEventInput, Evidence, detection_event};
use telltale_schema::clients::{ClientId, SourceKind};
use telltale_schema::source::Source;

use super::{
    BASELINE_STATE_VERSION, STATE_SCHEMA_VERSION, ScanState, baseline_snapshot_id,
    detection_fingerprint, source_fingerprint, state_field_names,
};

#[test]
fn emission_fingerprints_preserve_classification_changes_and_migrate_exact_legacy_events() {
    let source = Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "codex.sessions".into(),
        path: "synthetic-fingerprint.jsonl".into(),
    };
    let mut event = detection_event(DetectionEventInput {
        client: ClientId::Codex,
        agent: None,
        model: None,
        provider: None,
        session_id: "synthetic-fingerprint".into(),
        source_path_hash: "synthetic-path".into(),
        tool_name: Some("shell".into()),
        rule_ids: vec!["synthetic.medium".into()],
        categories: vec!["execution".into()],
        detection_classes: vec!["security_detection".into()],
        signal_types: vec!["atomic".into()],
        analytic_intents: vec!["alert".into()],
        atlas_tags: Vec::new(),
        tags: Vec::new(),
        evidence: vec![Evidence {
            field: "command".into(),
            redacted_value: "synthetic-one".into(),
            hash: None,
            rule_id: Some("synthetic.medium".into()),
        }],
        risk_contributions: Vec::new(),
        event_time: None,
    })
    .unwrap();
    for kind in ["detection", "session_risk_summary"] {
        event.event_type = kind.into();
        let mut state = ScanState::default();
        state
            .seen_detection_fingerprints
            .insert(detection_fingerprint(&event, &source_fingerprint(&source)));
        let mut historical_evidence = event.clone();
        historical_evidence.evidence[0].redacted_value = "synthetic-previously-seen".into();
        state
            .seen_detection_fingerprints
            .insert(detection_fingerprint(
                &historical_evidence,
                &source_fingerprint(&source),
            ));
        assert!(
            !state.should_emit(&source, &event, &BTreeSet::new()),
            "{kind}: legacy replay"
        );
        // Reloaded state has learned the new key, not just a transient suppression.
        let mut state =
            ScanState::validate_native_bytes(&state.canonical_bytes().unwrap()).unwrap();
        assert!(!state.should_emit(&source, &event, &BTreeSet::new()));
        let mut still_unchanged =
            ScanState::validate_native_bytes(&state.canonical_bytes().unwrap()).unwrap();
        assert!(!still_unchanged.should_emit(&source, &historical_evidence, &BTreeSet::new()));
        for field in [
            "detection_classes",
            "signal_types",
            "analytic_intents",
            "atlas_tags",
        ] {
            let mut changed = event.clone();
            changed.evidence = historical_evidence.evidence.clone();
            match field {
                "detection_classes" => changed.detection_classes.push("policy_violation".into()),
                "signal_types" => changed.signal_types.push("correlation".into()),
                "analytic_intents" => changed.analytic_intents.push("audit".into()),
                _ => changed.atlas_tags.push("atlas:AML.T0000".into()),
            }
            assert!(
                state.should_emit(&source, &changed, &BTreeSet::new()),
                "{kind}: {field}"
            );
            assert!(!state.should_emit(&source, &changed, &BTreeSet::new()));
        }
        let mut changed = event.clone();
        changed.evidence[0].redacted_value = "synthetic-two".into();
        changed.timestamp = "2026-05-02T00:00:00Z".into();
        assert_eq!(
            state.should_emit(&source, &changed, &BTreeSet::new()),
            kind == "detection"
        );
    }
}

#[test]
fn suppresses_duplicate_detections_for_same_source_content() {
    let source = Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "source".to_string(),
        path: Path::new(
            "tests/fixtures/session_stores/codex/sessions/2026/04/uc001-positive.jsonl",
        )
        .to_path_buf(),
    };
    let event = detection_event(DetectionEventInput {
        client: ClientId::Codex,
        agent: None,
        model: None,
        provider: None,
        session_id: "session".to_string(),
        source_path_hash: "hash".to_string(),
        tool_name: Some("repo_status".to_string()),
        rule_ids: vec!["rule.test".to_string()],
        categories: vec!["category".to_string()],
        detection_classes: vec!["security_detection".to_string()],
        signal_types: vec!["atomic".to_string()],
        analytic_intents: vec!["alert".to_string()],
        atlas_tags: Vec::new(),
        tags: vec!["tag".to_string()],
        evidence: vec![Evidence {
            field: "field".to_string(),
            redacted_value: "value".to_string(),
            hash: Some("abc".to_string()),
            rule_id: None,
        }],
        risk_contributions: Vec::new(),
        event_time: Some("2026-05-01T00:00:00.000Z".to_string()),
    })
    .expect("build detection event");

    let mut state = ScanState::default();
    let no_medium_rules = BTreeSet::new();
    assert!(state.should_emit(&source, &event, &no_medium_rules));
    assert!(!state.should_emit(&source, &event, &no_medium_rules));
    assert_eq!(state.seen_source_fingerprints.len(), 1);
    assert_eq!(state.seen_detection_fingerprints.len(), 1);
    assert_eq!(
        detection_fingerprint(&event, &source_fingerprint(&source)),
        detection_fingerprint(&event, &source_fingerprint(&source))
    );
    let mut wide_score = event.clone();
    wide_score.risk_score = u64::from(u32::MAX) + 1;
    assert_ne!(
        detection_fingerprint(&event, &source_fingerprint(&source)),
        detection_fingerprint(&wide_score, &source_fingerprint(&source))
    );
}

#[test]
fn stable_event_source_hash_dedup_ignores_container_fingerprint_churn() {
    let event = detection_event(DetectionEventInput {
        client: ClientId::OpenCode,
        agent: Some("build".to_string()),
        model: Some("gpt-5.4".to_string()),
        provider: Some("github-copilot".to_string()),
        session_id: "ses_stable".to_string(),
        source_path_hash: "stable-source-hash".to_string(),
        tool_name: None,
        rule_ids: vec!["rule.test".to_string()],
        categories: vec!["category".to_string()],
        detection_classes: vec!["security_detection".to_string()],
        signal_types: vec!["atomic".to_string()],
        analytic_intents: vec!["alert".to_string()],
        atlas_tags: Vec::new(),
        tags: vec!["activity".to_string(), "session".to_string()],
        evidence: vec![Evidence {
            field: "record_counts".to_string(),
            redacted_value: r#"{"assistant_message":2,"user_message":1}"#.to_string(),
            hash: Some("abc".to_string()),
            rule_id: None,
        }],
        risk_contributions: Vec::new(),
        event_time: Some("2026-05-01T00:00:00.000Z".to_string()),
    })
    .expect("build detection event");

    assert_eq!(
        detection_fingerprint(&event, "container-fingerprint-a"),
        detection_fingerprint(&event, "container-fingerprint-b")
    );
}

#[test]
fn older_baseline_schema_is_rejected_without_reset_and_current_state_round_trips() {
    let mut state = ScanState::default();
    state
        .seen_source_fingerprints
        .insert("synthetic-source".into());
    state
        .seen_detection_fingerprints
        .insert("synthetic-detection".into());
    let source = Source {
        client: ClientId::OpenCode,
        kind: SourceKind::Sqlite,
        source_id: "opencode.sqlite".into(),
        path: "synthetic.db".into(),
    };
    state.observe_sources(std::slice::from_ref(&source), 12);
    state.observe_sqlite_ingestion_cursor(&source, "part", 42, 12);
    state
        .record_baseline_source_contribution(
            &source,
            "old".into(),
            vec![BaselineSummary::default()],
        )
        .unwrap();
    state
        .rebuild_baseline_snapshots_from_source_contributions()
        .unwrap();
    let current = state.canonical_bytes().unwrap();
    let reloaded = ScanState::validate_native_bytes(&current).unwrap();
    assert_eq!(reloaded.baseline_snapshots.schema_version, 3);
    assert_eq!(reloaded.baseline_source_contributions.len(), 1);
    assert_eq!(reloaded.canonical_bytes().unwrap(), current);

    let mut legacy: Value = serde_json::from_slice(&current).unwrap();
    legacy["baseline_snapshots"]["schema_version"] = 2.into();
    let bytes = serde_json::to_vec(&legacy).unwrap();
    let error = ScanState::validate_native_bytes(&bytes).unwrap_err();
    assert!(error.to_string().contains("older format"));
    assert!(error.to_string().contains("v0.7.0"));
    assert!(error.to_string().contains("was not changed"));
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("schema2.json");
    std::fs::write(&path, &bytes).expect("write older state");
    assert!(ScanState::load(&path).is_err());
    assert_eq!(std::fs::read(&path).expect("unchanged"), bytes);
}

#[test]
fn aggregate_overflow_does_not_replace_snapshot() {
    let mut state = ScanState::default();
    let mut summary = BaselineSummary::default();
    summary.observations.records = u64::MAX;
    let source = Source {
        client: ClientId::Claude,
        kind: SourceKind::Jsonl,
        source_id: "claude.projects".into(),
        path: "one.jsonl".into(),
    };
    state
        .record_baseline_source_contribution(&source, "one".into(), vec![summary.clone()])
        .unwrap();
    state
        .rebuild_baseline_snapshots_from_source_contributions()
        .unwrap();
    let before = state.baseline_snapshots.clone();
    summary.observations.records = 1;
    let other = Source {
        path: "two.jsonl".into(),
        ..source
    };
    state
        .record_baseline_source_contribution(&other, "two".into(), vec![summary])
        .unwrap();
    assert!(
        state
            .rebuild_baseline_snapshots_from_source_contributions()
            .is_err()
    );
    assert_eq!(state.baseline_snapshots, before);
}

#[test]
fn missing_state_initializes_without_creating_a_file_until_save() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("missing.json");
    let state = ScanState::load_snapshot(&path).expect("missing state initializes");
    assert!(state.seen_source_fingerprints.is_empty());
    assert!(!path.exists());
    state.save(&path).expect("save initialized state");
    let bytes = std::fs::read(&path).expect("saved state");
    assert!(ScanState::validate_native_bytes(&bytes).is_ok());
    assert_eq!(
        std::fs::read(&path).expect("unchanged after validation"),
        bytes
    );
}

#[test]
fn rejects_empty_state_file_without_rewriting_it() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("empty-state.json");
    std::fs::write(&path, "").expect("write empty");

    let error = ScanState::load(&path).expect_err("empty state must fail");
    assert!(error.to_string().contains("invalid"));
    assert!(error.to_string().contains("was not changed"));
    assert!(!error.to_string().contains("v0.7.0"));
    assert_eq!(std::fs::read(&path).expect("unchanged"), b"");
}

#[test]
fn legacy_scan_state_fixture_is_rejected_without_rewriting_or_echoing_hosts() {
    let bytes = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/state/legacy-scan-state.json"
    ));
    let fixture: Value = serde_json::from_slice(bytes).expect("legacy state fixture");
    for field in [
        "seen_source_fingerprints",
        "seen_detection_fingerprints",
        "baseline_snapshots",
        "baseline_source_contributions",
        "source_observations",
        "sqlite_ingestion_cursors",
        "install_inventory",
    ] {
        assert!(fixture.get(field).is_some(), "missing state family {field}");
    }
    assert!(fixture.get("state_schema_version").is_none());

    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("legacy-scan-state.json");
    std::fs::write(&path, bytes).expect("write state fixture");
    let error = ScanState::load(&path).expect_err("older fixture must fail");
    let message = error.to_string();
    assert!(message.contains("older format"));
    assert!(message.contains("v0.7.0"));
    assert!(message.contains("was not changed"));
    assert!(!message.contains("internal.example.test"));
    assert_eq!(std::fs::read(&path).expect("unchanged"), bytes);
}

#[test]
fn persists_sqlite_ingestion_cursors_by_source_and_table() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("sqlite-cursor-state.json");
    let source = Source {
        client: ClientId::OpenCode,
        kind: SourceKind::Sqlite,
        source_id: "opencode.sqlite".to_string(),
        path: Path::new("/home/user/.local/share/opencode/opencode.db").to_path_buf(),
    };

    let mut state = ScanState::default();
    state.observe_sqlite_ingestion_cursor(&source, "part", 1_775_000_001_000, 1234);
    state.save(&path).expect("save");

    let reloaded = ScanState::load(&path).expect("reload");
    assert_eq!(
        reloaded.sqlite_ingestion_cursor_time_updated(&source, "part"),
        Some(1_775_000_001_000)
    );
    assert_eq!(
        reloaded.sqlite_ingestion_cursor_time_updated(&source, "message"),
        None
    );
}

#[test]
fn sqlite_cursor_high_water_cannot_regress_after_successful_observation() {
    let source = Source {
        client: ClientId::OpenCode,
        kind: SourceKind::Sqlite,
        source_id: "opencode.sqlite".into(),
        path: "synthetic.db".into(),
    };
    let mut state = ScanState::default();
    state.observe_sqlite_ingestion_cursor(&source, "part", 1_000, 1);
    state.observe_sqlite_ingestion_cursor(&source, "part", 900, 2);
    assert_eq!(
        state.sqlite_ingestion_cursor_time_updated(&source, "part"),
        Some(1_000)
    );
}

#[test]
fn sqlite_unfinished_overlap_state_is_validated_and_migrates_without_losing_the_cut() {
    let source = Source {
        client: ClientId::OpenCode,
        kind: SourceKind::Sqlite,
        source_id: "opencode.sqlite".into(),
        path: Path::new("/synthetic/overlap.db").to_path_buf(),
    };
    let mut state = ScanState::default();
    state.observe_sqlite_ingestion_cursor(&source, "session_message", 1_000_000, 1);
    state.observe_sqlite_ingestion_drain(&source, "session_message", 600_000, 2);
    let bytes = state.canonical_bytes().unwrap();
    let loaded = ScanState::validate_native_bytes(&bytes).unwrap();
    assert_eq!(loaded.canonical_bytes().unwrap(), bytes);
    assert_eq!(
        loaded.sqlite_ingestion_continue_after(&source, "session_message"),
        Some(600_000)
    );
    let value: Value = serde_json::from_slice(&bytes).unwrap();
    let key = value["sqlite_ingestion_cursors"]
        .as_object()
        .unwrap()
        .keys()
        .next()
        .unwrap()
        .clone();
    for cut in [i64::MIN, -1, 0] {
        let mut signed = value.clone();
        signed["sqlite_ingestion_cursors"][&key]["last_time_updated"] = 0.into();
        signed["sqlite_ingestion_cursors"][&key]["continue_after_time_updated"] = cut.into();
        let bytes = serde_json::to_vec(&signed).unwrap();
        let loaded = ScanState::validate_native_bytes(&bytes).unwrap();
        assert_eq!(
            loaded.sqlite_ingestion_continue_after(&source, "session_message"),
            Some(cut)
        );
        let repeated =
            ScanState::validate_native_bytes(&loaded.canonical_bytes().unwrap()).unwrap();
        assert_eq!(
            repeated.sqlite_ingestion_continue_after(&source, "session_message"),
            Some(cut)
        );
    }
    for (field, invalid) in [
        ("continue_after_time_updated", serde_json::json!(1_000_001)),
        ("continue_after_time_updated", Value::Null),
        ("continue_after_time_updated", serde_json::json!("600000")),
        ("draining", serde_json::json!(false)),
        ("table", serde_json::json!("part")),
        ("client", serde_json::json!("codex")),
        ("source_id", serde_json::json!("opencode.sqlite.lookalike")),
    ] {
        let mut bad = value.clone();
        bad["sqlite_ingestion_cursors"][&key][field] = invalid;
        let error =
            ScanState::validate_native_bytes(&serde_json::to_vec(&bad).unwrap()).expect_err(field);
        let message = error.to_string();
        assert!(message.contains("invalid"), "{field}: {message}");
        assert!(!message.contains("v0.7.0"), "{field}: {message}");
    }
    // Old drain state remains readable, but has no trustworthy strict cut.
    let mut old = value;
    old["sqlite_ingestion_cursors"][&key]
        .as_object_mut()
        .unwrap()
        .remove("continue_after_time_updated");
    let old = ScanState::validate_native_bytes(&serde_json::to_vec(&old).unwrap()).unwrap();
    let cursor = old
        .sqlite_ingestion_cursors
        .values()
        .next()
        .expect("old drain cursor");
    assert!(cursor.draining);
    assert!(cursor.continue_after_time_updated.is_none());
    assert_eq!(
        old.sqlite_ingestion_continue_after(&source, "session_message"),
        None
    );
    assert_eq!(
        old.sqlite_ingestion_cursor_time_updated(&source, "session_message"),
        Some(1_000_000)
    );
}

#[test]
fn persists_and_reloads_versioned_baseline_snapshots() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("state-with-baselines.json");
    let key = BaselineKey {
        client: "codex".to_string(),
        agent: Some("codex-agent".to_string()),
        model: Some("o3".to_string()),
        provider: Some("openai".to_string()),
    };
    let mut summary = BaselineSummary {
        key: key.clone(),
        observations: BaselineObservationTotals {
            records: 3,
            user_messages: 1,
            assistant_messages: 0,
            tool_calls: 2,
            tool_results: 0,
            session_meta: 0,
            other: 0,
        },
        ..BaselineSummary::default()
    };
    summary.tool_call_counts.insert("shell".to_string(), 2);
    summary.path_class_counts.insert(PathClass::Source, 1);
    summary
        .network_host_counts
        .insert("docs.example.test".to_string(), 1);

    let mut state = ScanState::default();
    state.replace_baseline_snapshots(vec![summary]);
    state.save(&path).expect("save");

    let reloaded = ScanState::load(&path).expect("reload");
    let persisted = reloaded.baseline_snapshot(&key).expect("baseline snapshot");

    assert_eq!(
        reloaded.baseline_snapshots.schema_version,
        BASELINE_STATE_VERSION
    );
    assert!(
        reloaded
            .baseline_snapshots
            .snapshots
            .contains_key(&baseline_snapshot_id(&key))
    );
    assert_eq!(persisted.observations.records, 3);
    assert_eq!(persisted.tool_call_counts.get("shell"), Some(&2));
    assert_eq!(
        persisted
            .network_host_counts
            .get(&baseline_host_identity("docs.example.test")),
        Some(&1)
    );
    assert!(
        persisted
            .network_host_counts
            .keys()
            .all(|host| host.starts_with(BASELINE_HOST_HASH_PREFIX))
    );
    assert!(
        !persisted
            .network_host_counts
            .contains_key("docs.example.test")
    );
}

#[test]
fn replaces_baseline_source_contribution_for_same_source() {
    let source = Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "sessions/source-a.jsonl".to_string(),
        path: Path::new("tests/fixtures/session_stores/codex/sessions/source-a.jsonl")
            .to_path_buf(),
    };
    let key = BaselineKey {
        client: "codex".to_string(),
        agent: Some("codex-agent".to_string()),
        model: Some("o3".to_string()),
        provider: Some("openai".to_string()),
    };
    let first = BaselineSummary {
        key: key.clone(),
        observations: BaselineObservationTotals {
            records: 1,
            user_messages: 0,
            assistant_messages: 0,
            tool_calls: 1,
            tool_results: 0,
            session_meta: 0,
            other: 0,
        },
        ..BaselineSummary::default()
    };
    let second = BaselineSummary {
        key: key.clone(),
        observations: BaselineObservationTotals {
            records: 2,
            user_messages: 0,
            assistant_messages: 0,
            tool_calls: 2,
            tool_results: 0,
            session_meta: 0,
            other: 0,
        },
        ..BaselineSummary::default()
    };

    let mut state = ScanState::default();
    state
        .record_baseline_source_contribution(&source, "fingerprint-before".to_string(), vec![first])
        .unwrap();
    state
        .record_baseline_source_contribution(&source, "fingerprint-after".to_string(), vec![second])
        .unwrap();
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("state-with-source-contribution.json");
    state.save(&path).expect("save state");

    let reloaded = ScanState::load(&path).expect("reload state");
    assert_eq!(reloaded.baseline_source_contributions.len(), 1);
    let contribution = reloaded
        .baseline_source_contributions
        .values()
        .next()
        .expect("source contribution");
    assert_eq!(contribution.client, "codex");
    assert_eq!(contribution.source_id, "sessions/source-a.jsonl");
    assert!(!contribution.source_instance_id.is_empty());
    assert_eq!(contribution.source_fingerprint, "fingerprint-after");
    assert_eq!(
        contribution.snapshots[&baseline_snapshot_id(&key)]
            .observations
            .records,
        2
    );
}

#[test]
fn keeps_distinct_contributions_for_sources_in_same_bucket() {
    let mut state = ScanState::default();
    let source_a = Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "codex.sessions".to_string(),
        path: Path::new("tests/fixtures/session_stores/codex/sessions/source-a.jsonl")
            .to_path_buf(),
    };
    let source_b = Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "codex.sessions".to_string(),
        path: Path::new("tests/fixtures/session_stores/codex/sessions/source-b.jsonl")
            .to_path_buf(),
    };
    state.observe_sources(&[source_a.clone(), source_b.clone()], 1_000);
    assert_eq!(state.source_observations.len(), 2);

    let key = BaselineKey {
        client: "codex".to_string(),
        agent: Some("codex-agent".to_string()),
        model: Some("o3".to_string()),
        provider: Some("openai".to_string()),
    };
    let summary = BaselineSummary {
        key,
        observations: BaselineObservationTotals {
            records: 1,
            user_messages: 0,
            assistant_messages: 0,
            tool_calls: 1,
            tool_results: 0,
            session_meta: 0,
            other: 0,
        },
        ..BaselineSummary::default()
    };
    state
        .record_baseline_source_contribution(
            &source_a,
            "fingerprint-a".to_string(),
            vec![summary.clone()],
        )
        .unwrap();
    state
        .record_baseline_source_contribution(&source_b, "fingerprint-b".to_string(), vec![summary])
        .unwrap();
    assert_eq!(state.baseline_source_contributions.len(), 2);
}

#[test]
fn summarizes_source_inventory_changes_without_paths() {
    let mut state = ScanState::default();
    let source_a = Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "codex.sessions".to_string(),
        path: Path::new("tests/fixtures/session_stores/codex/sessions/source-a.jsonl")
            .to_path_buf(),
    };
    let source_b = Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "codex.sessions".to_string(),
        path: Path::new("tests/fixtures/session_stores/codex/sessions/source-b.jsonl")
            .to_path_buf(),
    };

    let first = state.source_inventory_change_summary(&[source_a.clone(), source_b.clone()]);
    assert!(first.baseline);
    assert_eq!(first.added, 2);
    assert_eq!(first.removed, 0);
    assert_eq!(first.unchanged, 0);
    assert_eq!(first.hash.len(), 64);

    state.observe_sources(&[source_a.clone(), source_b], 1_000);
    let second = state.source_inventory_change_summary(std::slice::from_ref(&source_a));
    assert!(!second.baseline);
    assert_eq!(second.added, 0);
    assert_eq!(second.removed, 1);
    assert_eq!(second.unchanged, 1);
    assert_eq!(second.hash.len(), 64);

    state.replace_source_observations(std::slice::from_ref(&source_a), 2_000);
    let third = state.source_inventory_change_summary(std::slice::from_ref(&source_a));
    assert!(!third.baseline);
    assert_eq!(third.added, 0);
    assert_eq!(third.removed, 0);
    assert_eq!(third.unchanged, 1);
}

#[test]
fn native_state_requires_version_and_rejects_recursive_unknown_fields() {
    let state = ScanState::default();
    let native = state.canonical_bytes().expect("native bytes");
    assert!(ScanState::validate_native_bytes(&native).is_ok());

    let mut observed = ScanState::default();
    observed.source_observations.insert(
        "source".to_string(),
        super::SourceObservation {
            client: "codex".to_string(),
            source_id: "source".to_string(),
            source_instance_id: "instance".to_string(),
            last_seen_unix_ms: 1,
        },
    );
    let mut missing_nested = serde_json::to_value(&observed).expect("state value");
    missing_nested["source_observations"]["source"]
        .as_object_mut()
        .expect("observation")
        .remove("source_instance_id");
    missing_nested["state_schema_version"] = Value::String(STATE_SCHEMA_VERSION.to_string());
    assert!(
        ScanState::validate_native_bytes(
            &serde_json::to_vec(&missing_nested).expect("missing nested bytes")
        )
        .is_err()
    );

    let unversioned = serde_json::to_value(&state).expect("state value");
    assert!(
        ScanState::validate_native_bytes(
            &serde_json::to_vec(&unversioned).expect("unversioned bytes")
        )
        .is_err()
    );

    let mut versioned =
        serde_json::from_slice::<Value>(&state.canonical_bytes().unwrap()).expect("native value");
    versioned["baseline_snapshots"]["unexpected"] = Value::Bool(true);
    let unknown =
        ScanState::validate_native_bytes(&serde_json::to_vec(&versioned).expect("unknown bytes"))
            .expect_err("unknown field");
    assert!(unknown.to_string().contains("invalid"));
    assert!(!unknown.to_string().contains("v0.7.0"));

    versioned["not_a_state_family"] = Value::Bool(true);
    let unknown_family = ScanState::validate_native_bytes(
        &serde_json::to_vec(&versioned).expect("unknown family bytes"),
    )
    .expect_err("unknown family");
    assert!(unknown_family.to_string().contains("invalid"));
    assert!(!unknown_family.to_string().contains("v0.7.0"));

    let duplicate = br#"{"seen_source_fingerprints":[],"seen_source_fingerprints":[]}"#;
    let duplicate_error = ScanState::validate_native_bytes(duplicate).expect_err("duplicate");
    assert!(duplicate_error.to_string().contains("invalid"));
    assert!(!duplicate_error.to_string().contains("v0.7.0"));

    let native = String::from_utf8(state.canonical_bytes().expect("native bytes")).unwrap();
    let native_duplicate = native.replacen(
        "\"state_schema_version\"",
        "\"state_schema_version\":\"1.0\",\"state_schema_version\"",
        1,
    );
    let native_duplicate = ScanState::validate_native_bytes(native_duplicate.as_bytes())
        .expect_err("native duplicate");
    assert!(native_duplicate.to_string().contains("invalid"));
    assert!(!native_duplicate.to_string().contains("v0.7.0"));
}

#[test]
fn health_heartbeat_marker_round_trips_and_replaces_without_a_schema_change() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("state.json");
    let mut state = ScanState::default();
    assert_eq!(state.last_health_heartbeat_unix_ms(), None);
    state
        .seen_detection_fingerprints
        .insert("telltale:health_heartbeat_v1@not-a-time".to_string());
    // A damaged marker reads as none, so the heartbeat is due.
    assert_eq!(state.last_health_heartbeat_unix_ms(), None);

    state.record_health_heartbeat(1_000);
    state.record_health_heartbeat(2_000);
    assert_eq!(state.last_health_heartbeat_unix_ms(), Some(2_000));
    assert_eq!(state.seen_detection_fingerprints.len(), 1);

    state.save(&path).expect("save state");
    let bytes = std::fs::read(&path).expect("state bytes");
    let reloaded = ScanState::validate_native_bytes(&bytes).expect("native state");
    assert_eq!(reloaded.last_health_heartbeat_unix_ms(), Some(2_000));
    let value: Value = serde_json::from_slice(&bytes).expect("state json");
    let mut fields = value
        .as_object()
        .expect("state object")
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    fields.sort();
    let mut expected = state_field_names()
        .iter()
        .map(|field| field.to_string())
        .chain(["state_schema_version".to_string()])
        .collect::<Vec<_>>();
    expected.sort();
    assert_eq!(fields, expected, "the heartbeat must not add a state field");
}

#[test]
fn marker_rejection_does_not_claim_malformed_old_input_is_migratable() {
    let secret = "not-an-object";
    let unversioned = format!(
        r#"{{"seen_source_fingerprints":[],"sqlite_ingestion_cursors":{{"k":"{secret}"}}}}"#
    );
    assert_unqualified_marker_rejection(unversioned.as_bytes(), secret);

    for schema in [1, 2] {
        let mut unknown = native_state_value();
        unknown["baseline_snapshots"]["schema_version"] = schema.into();
        unknown["baseline_snapshots"]["not_a_baseline_field"] = Value::Bool(true);
        assert_unqualified_marker_rejection(
            &serde_json::to_vec(&unknown).unwrap(),
            "not_a_baseline_field",
        );

        let mut missing = native_state_value();
        missing["baseline_snapshots"]["schema_version"] = schema.into();
        missing["baseline_snapshots"]
            .as_object_mut()
            .unwrap()
            .remove("snapshots");
        assert_unqualified_marker_rejection(&serde_json::to_vec(&missing).unwrap(), "snapshots");

        let mut cut = native_state_value();
        cut["baseline_snapshots"]["schema_version"] = schema.into();
        cut["sqlite_ingestion_cursors"]["cursor"] = serde_json::json!({
            "client": "opencode",
            "source_id": "opencode.sqlite",
            "source_instance_id": "instance",
            "table": "session_message",
            "last_time_updated": 10,
            "observed_at_unix_ms": 1,
            "draining": true,
            "continue_after_time_updated": 11
        });
        assert_unqualified_marker_rejection(&serde_json::to_vec(&cut).unwrap(), "continue_after");
    }
}

#[test]
fn baseline_schema_2_is_older_state_not_a_host_rejection() {
    let mut value = native_state_value();
    value["baseline_snapshots"]["schema_version"] = 2.into();
    value["baseline_snapshots"]["snapshots"]["id"] =
        host_summary("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    let error = ScanState::validate_native_bytes(&serde_json::to_vec(&value).unwrap())
        .expect_err("schema 2");
    assert!(error.to_string().contains("older format"));
    assert!(error.to_string().contains("v0.7.0"));
}

#[test]
fn current_baseline_rejects_plaintext_and_malformed_hosts_in_both_families() {
    let valid = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let cases = ["internal.example", "sha256:ABC", "sha256:gg"];
    for host in cases {
        for family in ["baseline_snapshots", "baseline_source_contributions"] {
            let mut value = native_state_value();
            assert_eq!(value["baseline_snapshots"]["schema_version"], 3);
            let summary = host_summary(host);
            if family == "baseline_snapshots" {
                value["baseline_snapshots"]["snapshots"]["id"] = summary;
            } else {
                value["baseline_source_contributions"]["source"] = serde_json::json!({
                    "client": "codex",
                    "source_id": "codex.sessions",
                    "source_instance_id": "instance",
                    "source_fingerprint": "fingerprint",
                    "snapshots": {"id": summary}
                });
            }
            let bytes = serde_json::to_vec(&value).unwrap();
            let error = ScanState::validate_native_bytes(&bytes).expect_err(family);
            let message = error.to_string();
            assert!(message.contains("invalid"), "{family} {host}: {message}");
            assert!(!message.contains("v0.7.0"), "{family} {host}: {message}");
            assert!(!message.contains(host), "{family} echoed {host}");
            let temp = tempfile::tempdir().expect("tempdir");
            let path = temp.path().join("state.json");
            std::fs::write(&path, &bytes).expect("write");
            assert!(ScanState::load(&path).is_err());
            assert_eq!(std::fs::read(&path).expect("unchanged"), bytes);
        }
    }
    let mut accepted = native_state_value();
    accepted["baseline_snapshots"]["snapshots"]["id"] = host_summary(valid);
    assert!(
        ScanState::validate_native_bytes(&serde_json::to_vec(&accepted).unwrap()).is_ok(),
        "current hashed hosts remain valid"
    );
    let text = serde_json::to_string(&accepted).unwrap();
    let nested_duplicate = text.replacen(
        &format!("\"{valid}\":1"),
        &format!("\"{valid}\":1,\"{valid}\":1"),
        1,
    );
    let nested = ScanState::validate_native_bytes(nested_duplicate.as_bytes())
        .expect_err("nested duplicate host key");
    assert!(nested.to_string().contains("invalid"));
    assert!(!nested.to_string().contains("v0.7.0"));
}

fn assert_unqualified_marker_rejection(bytes: &[u8], echoed: &str) {
    let error = ScanState::validate_native_bytes(bytes).expect_err("marker rejection");
    let message = error.to_string();
    assert!(message.contains("older format"), "{message}");
    assert!(message.contains("was not changed"), "{message}");
    assert!(
        message.contains("or be invalid"),
        "missing qualification: {message}"
    );
    assert!(
        message.contains("eligibility has not been validated"),
        "missing qualification: {message}"
    );
    assert!(message.contains("not invalid data"), "{message}");
    assert!(!message.contains(echoed), "echoed input: {message}");
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("state.json");
    std::fs::write(&path, bytes).expect("write");
    let loaded = ScanState::load(&path).expect_err("load must reject");
    assert_eq!(loaded.to_string(), message);
    assert_eq!(std::fs::read(&path).expect("unchanged"), bytes);
}

fn native_state_value() -> Value {
    serde_json::from_slice(&ScanState::default().canonical_bytes().unwrap()).unwrap()
}

fn host_summary(host: &str) -> Value {
    serde_json::json!({
        "key": {"client": "codex", "agent": null, "model": null, "provider": null},
        "observations": {
            "records": 1,
            "user_messages": 0,
            "assistant_messages": 0,
            "tool_calls": 1,
            "tool_results": 0,
            "session_meta": 0,
            "other": 0
        },
        "tool_call_counts": {},
        "path_class_counts": {},
        "network_host_counts": {host: 1}
    })
}
