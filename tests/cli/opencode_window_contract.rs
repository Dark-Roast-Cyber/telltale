use super::*;
use rusqlite::Connection;

#[test]
fn opencode_window_transition_reemits_changed_aggregates_without_cursor_retreat() {
    let temp = tempdir().unwrap();
    let root = temp.path().join("stores");
    fs::create_dir_all(root.join("opencode")).unwrap();
    let database = root.join("opencode/opencode.db");
    let writer = Connection::open(&database).unwrap();
    writer
        .execute_batch(
            "pragma journal_mode=WAL; pragma wal_autocheckpoint=0;
        create table part (id text primary key, session_id text, time_updated integer, data text);",
        )
        .unwrap();
    let high_water = 1_775_002_000_000_i64;
    for (id, time, command) in [
        ("old", high_water - 1_200_000, "echo synthetic-window-old"),
        ("recent", high_water, "echo synthetic-window-recent"),
    ] {
        writer.execute("insert into part values (?1,'window-session',?2,?3)", rusqlite::params![id, time,
            serde_json::json!({"type":"tool","tool":"bash","callID":id,"state":{"status":"completed","input":{"command":command},"output":"ok","time":{"start":time,"end":time}}}).to_string()]).unwrap();
    }
    let rules = temp.path().join("rules.yaml");
    fs::write(
        &rules,
        r#"
version: 1
description: Synthetic selected-window coverage.
defaults: { case_insensitive: false, enabled: true }
modifiers: []
rules:
  - id: synthetic.window
    title: Synthetic selected-window match
    tags: [synthetic]
    category: synthetic
    severity: high
    score: 70
    detection:
      selection:
        command: 'synthetic-window-'
      condition: selection
    explanation: Synthetic test.
"#,
    )
    .unwrap();
    let log = temp.path().join("events.jsonl");
    let state = temp.path().join("state.json");
    let database_bytes = fs::read(&database).unwrap();
    let wal_bytes = fs::read(database.with_extension("db-wal")).unwrap();
    // Public embedding scans are stateless: both calls select the same full
    // bootstrap window, unlike the stateful CLI transition exercised below.
    let pipeline = telltale_core::Pipeline::builder()
        .without_bundled_defaults()
        .rules_document(fs::read_to_string(&rules).unwrap())
        .build()
        .unwrap();
    let source = Source {
        client: ClientId::OpenCode,
        kind: SourceKind::Sqlite,
        source_id: "opencode.sqlite".into(),
        path: database.clone(),
    };
    let detailed = || {
        pipeline
            .scan_sources_detailed(
                std::slice::from_ref(&source),
                &telltale_core::DetailedEvaluationOptions::default(),
            )
            .unwrap()
            .remove(0)
    };
    let full_first = detailed();
    let full_second = detailed();
    assert_eq!(full_first.events.len(), 2);
    assert_eq!(full_second.events.len(), full_first.events.len());
    for (first, second) in full_first.events.iter().zip(&full_second.events) {
        assert_ne!(first.event_id, second.event_id);
        let stable = |event: &telltale_core::Event| {
            let mut wire = serde_json::to_value(event).unwrap();
            assert!(event_schema_validator().is_valid(&wire));
            for field in ["event_id", "observed_at", "ingested_at"] {
                wire.as_object_mut().unwrap().remove(field);
            }
            if event.event_time.is_none() {
                wire.as_object_mut().unwrap().remove("timestamp");
            }
            wire
        };
        assert_eq!(stable(first), stable(second));
    }
    assert_eq!(full_first.action_findings.len(), 2);
    assert_eq!(full_first.action_findings, full_second.action_findings);
    for action in &full_first.action_findings {
        assert!(action.replay_identity().is_some());
        assert!(action.occurred_at().is_some());
    }
    assert_ne!(
        full_first.action_findings[0].coordinate(),
        full_first.action_findings[1].coordinate()
    );
    assert_ne!(
        full_first.action_findings[0].replay_identity(),
        full_first.action_findings[1].replay_identity()
    );
    assert!(!state.exists());
    assert!(!log.exists());
    let scan = || {
        let result = Command::new(env!("CARGO_BIN_EXE_telltale"))
            .env_clear()
            .current_dir(temp.path())
            .args([
                "scan",
                "--once",
                "--client",
                "opencode",
                "--no-local-config",
                "--emit-activity",
                "--install-inventory-disabled",
                "--no-default-rules",
                "--root",
            ])
            .arg(&root)
            .arg("--rules")
            .arg(&rules)
            .arg("--log-path")
            .arg(&log)
            .arg("--state-path")
            .arg(&state)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let summary: Value = serde_json::from_slice(&result.stdout).unwrap();
        assert_eq!(summary["source_counts"]["opencode.sqlite"], 1);
        assert_eq!(summary["source_processing"]["parse_error_source_count"], 0);
        let saved: Value = serde_json::from_slice(&fs::read(&state).unwrap()).unwrap();
        assert!(
            saved["baseline_snapshots"]["snapshots"]
                .as_object()
                .unwrap()
                .is_empty(),
            "PartialSource must not install a whole-source baseline"
        );
        assert!(
            saved["baseline_source_contributions"]
                .as_object()
                .unwrap()
                .is_empty()
        );
        let cursors = saved["sqlite_ingestion_cursors"].as_object().unwrap();
        assert_eq!(cursors.len(), 1);
        assert_eq!(
            cursors.values().next().unwrap()["last_time_updated"],
            high_water
        );
        (summary, saved)
    };
    let semantic_state = |mut saved: Value| {
        for (key, timestamp) in [
            ("sqlite_ingestion_cursors", "observed_at_unix_ms"),
            ("source_observations", "last_seen_unix_ms"),
        ] {
            for value in saved[key].as_object_mut().unwrap().values_mut() {
                value.as_object_mut().unwrap().remove(timestamp);
            }
        }
        saved
    };
    let (bootstrap, first_state) = scan();
    assert_eq!(bootstrap["source_processing"]["parsed_record_count"], 2);
    assert_eq!(bootstrap["emitted_count"], 2);
    let first_log = fs::read_to_string(&log).unwrap();
    let (incremental, second_state) = scan();
    assert_eq!(incremental["source_processing"]["parsed_record_count"], 1);
    assert_eq!(incremental["emitted_count"], 2);
    let first_state = semantic_state(first_state);
    let second_state = semantic_state(second_state);
    assert_eq!(
        first_state["sqlite_ingestion_cursors"],
        second_state["sqlite_ingestion_cursors"]
    );
    let fingerprints = |saved: &Value| {
        saved["seen_detection_fingerprints"]
            .as_array()
            .unwrap()
            .clone()
    };
    assert_eq!(fingerprints(&first_state).len(), 2);
    assert_eq!(fingerprints(&second_state).len(), 4);
    assert!(
        fingerprints(&first_state)
            .iter()
            .all(|f| fingerprints(&second_state).contains(f))
    );
    let transitioned_log = fs::read_to_string(&log).unwrap();
    assert!(transitioned_log.starts_with(&first_log));
    let events = transitioned_log
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .filter(|event| matches!(event["event_type"].as_str(), Some("activity" | "detection")))
        .collect::<Vec<_>>();
    assert_eq!(events.len(), 4);
    for event in &events {
        assert!(event_schema_validator().is_valid(event));
        assert_eq!(event["session_id"], "window-session");
    }
    let detections = events
        .iter()
        .filter(|event| event["event_type"] == "detection")
        .collect::<Vec<_>>();
    assert_eq!(detections.len(), 2);
    for event in &detections {
        assert_eq!(event["rule_ids"], serde_json::json!(["synthetic.window"]));
    }
    assert_ne!(
        detections[0]["evidence"], detections[1]["evidence"],
        "repeat is changed selected-window evidence, not a newly observed action"
    );
    let (settled, third_state) = scan();
    assert_eq!(settled["source_processing"]["parsed_record_count"], 1);
    assert_eq!(settled["emitted_count"], 0);
    assert_eq!(semantic_state(third_state), second_state);
    assert_eq!(fs::read_to_string(&log).unwrap(), transitioned_log);
    assert_eq!(fs::read(&database).unwrap(), database_bytes);
    assert_eq!(
        fs::read(database.with_extension("db-wal")).unwrap(),
        wal_bytes
    );
}
