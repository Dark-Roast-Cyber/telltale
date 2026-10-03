use serde_json::{Value, json};
use std::{fs, process::Command};
use telltale_core::Pipeline;
use telltale_schema::{
    clients::{ClientId, SourceKind},
    source::Source,
};
use telltale_sources::acquisition::{AcquisitionOptions, acquire_source};

const RULES: &str = r#"version: 1
description: synthetic
defaults: {enabled: true, case_insensitive: false}
rules:
  - id: synthetic.user
    category: synthetic
    severity: low
    score: 3
    targets: [user_context]
    regex: needle
    tags: [synthetic]
    explanation: synthetic
  - id: synthetic.assistant
    category: synthetic
    severity: low
    score: 3
    targets: [assistant_context]
    regex: needle
    tags: [synthetic]
    explanation: synthetic
  - id: synthetic.command
    category: synthetic
    severity: low
    score: 3
    targets: [command]
    regex: printf synthetic
    tags: [synthetic]
    explanation: synthetic
modifiers: []
"#;

fn input() -> String {
    let text = format!(
        "api_key=SYNTHETIC-COMPLETED-SECRET {}needle",
        "ordinary ".repeat(600)
    );
    let mut values = [
        json!({"type":"session_meta","payload":{"id":"child","session_id":"root","history_mode":"paginated"}}),
        json!({"type":"world_state","payload":{"full":false,"state":{"type":"item_completed","session_id":"state-poison","model":"PRIVATE-WORLD","message":{"role":"user","content":"PRIVATE-WORLD needle"},"tool":{"name":"PRIVATE-WORLD","command":"printf synthetic"}}}}),
        json!({"type":"response_item","payload":{"type":"message","role":"user","id":"raw-user","internal_chat_message_metadata_passthrough":{"turn_id":"turn-a"},"content":[{"type":"input_text","text":text}]}}),
        json!({"type":"event_msg","payload":{"type":"item_completed","thread_id":"child","turn_id":"turn-a","item":{"type":"UserMessage","id":"different-user-id","content":[{"type":"text","text":text}]}}}),
        json!({"type":"response_item","payload":{"type":"message","role":"assistant","id":"assistant-id","internal_chat_message_metadata_passthrough":{"turn_id":"turn-a"},"content":[{"type":"output_text","text":"assistant needle"}]}}),
        json!({"type":"event_msg","payload":{"type":"item_completed","thread_id":"child","turn_id":"turn-a","item":{"type":"AgentMessage","id":"assistant-id","content":[{"type":"Text","text":"assistant needle"}]}}}),
        json!({"type":"event_msg","payload":{"type":"item_completed","thread_id":"child","turn_id":"turn-a","item":{"type":"Reasoning","id":"reason-id","summary_text":["PRIVATE-REASONING needle"],"raw_content":["PRIVATE-REASONING needle"]}}}),
        json!({"type":"response_item","payload":{"type":"function_call","id":"response-not-call","call_id":"call-id","name":"exec","arguments":{"command":"printf synthetic"}}}),
        json!({"type":"event_msg","payload":{"type":"item_completed","thread_id":"child","turn_id":"turn-a","item":{"type":"CommandExecution","id":"call-id","command":["/bin/sh","-c","printf synthetic",""],"cwd":"/synthetic","status":"declined","exit_code":-1,"aggregated_output":"PRIVATE-DIAGNOSTIC"}}}),
    ];
    for (ordinal, value) in values.iter_mut().enumerate() {
        value["ordinal"] = json!(ordinal);
    }
    format!(
        "{}\n",
        values
            .iter()
            .map(Value::to_string)
            .collect::<Vec<_>>()
            .join("\n")
    )
}

#[test]
fn completed_actual_cli_embedding_privacy_timeline_and_late_atomic_failure() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("stores");
    let rules = temp.path().join("rules.yaml");
    fs::write(&rules, RULES).unwrap();
    let pipeline = Pipeline::builder()
        .without_bundled_defaults()
        .rules_document(RULES)
        .build()
        .unwrap();
    let mut sources = Vec::new();
    for (directory, source_id, kind) in [
        ("sessions", "codex.sessions", SourceKind::Jsonl),
        (
            "archived_sessions",
            "codex.archived_sessions",
            SourceKind::ArchivedJsonl,
        ),
        (
            "headless",
            "codex.headless_sessions",
            SourceKind::HeadlessJsonl,
        ),
    ] {
        let dir = root.join("codex").join(directory);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("synthetic.jsonl");
        fs::write(&path, input()).unwrap();
        sources.push(Source {
            client: ClientId::Codex,
            source_id: source_id.into(),
            kind,
            path,
        });
    }
    let scans = pipeline.scan_root_with_occurrences(&root).unwrap();
    assert_eq!(scans.len(), 3);
    for scan in &scans {
        assert_eq!(
            scan.occurrences.len(),
            3,
            "mirrors or reasoning duplicated analytics"
        );
        assert!(scan.events.iter().all(|e| e.event_type != "scanner_error"));
        let rendered = serde_json::to_string(&scan.events).unwrap();
        for marker in [
            "PRIVATE-WORLD",
            "SYNTHETIC-COMPLETED-SECRET",
            "PRIVATE-REASONING",
            "PRIVATE-DIAGNOSTIC",
        ] {
            assert!(!rendered.contains(marker));
        }
        let source = sources
            .iter()
            .find(|s| s.source_id == scan.source.source_id)
            .unwrap();
        let batch = acquire_source(
            source,
            AcquisitionOptions::new(
                telltale_schema::observation::ObservedAt::new("2026-10-03T12:00:00Z").unwrap(),
            ),
        )
        .unwrap();
        assert_eq!(batch.accounting.sessions.len(), 1);
        assert_eq!(batch.accounting.sessions[0].counts.native_units, 9);
        assert_eq!(batch.accounting.sessions[0].counts.record_counts.other, 2);
        let timeline = telltale_detect::timeline::build_content_free_canonical_timeline(
            &batch.observations,
            "codex",
        )
        .unwrap();
        let timeline = serde_json::to_value(timeline).unwrap();
        assert_eq!(timeline["entries"][2]["event_type"], "tool_call");
        assert_eq!(timeline["entries"][3]["event_type"], "tool_result");
        assert_eq!(timeline["entries"][3]["linked_entry_index"], 2);
    }
    let log = temp.path().join("events.jsonl");
    let state = temp.path().join("state.json");
    let scan = || {
        let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
            .env_clear()
            .env("HOME", temp.path())
            .env("XDG_CONFIG_HOME", temp.path().join("config"))
            .env("XDG_STATE_HOME", temp.path().join("state-home"))
            .args([
                "scan",
                "--once",
                "--allow-fixtures",
                "--no-local-config",
                "--no-default-rules",
                "--emit-activity",
                "--client",
                "codex",
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
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice::<Value>(&output.stdout).unwrap()
    };
    assert_eq!(scan()["activity_count"], 3);
    let persisted = fs::read_to_string(&log).unwrap();
    let events = persisted
        .lines()
        .map(|l| serde_json::from_str::<Value>(l).unwrap())
        .collect::<Vec<_>>();
    let detections = events
        .iter()
        .filter(|e| e["event_type"] == "detection")
        .collect::<Vec<_>>();
    assert_eq!(detections.len(), 3);
    for event in detections {
        assert_eq!(event["timeline_anchors"].as_array().unwrap().len(), 3);
    }
    for marker in [
        "PRIVATE-WORLD",
        "SYNTHETIC-COMPLETED-SECRET",
        "PRIVATE-REASONING",
        "PRIVATE-DIAGNOSTIC",
    ] {
        assert!(!persisted.contains(marker));
    }
    let before: Value = serde_json::from_slice(&fs::read(&state).unwrap()).unwrap();
    let offset = persisted.len();
    for source in &sources {
        fs::write(&source.path,format!("{}{{\"type\":\"event_msg\",\"ordinal\":9,\"payload\":{{\"type\":\"item_completed\",\"thread_id\":\"child\",\"turn_id\":\"turn-a\",\"item\":{{\"type\":\"Future\",\"id\":\"unknown\"}}}}}}\n",input())).unwrap();
    }
    let failed = pipeline.scan_root_with_occurrences(&root).unwrap();
    for scan in failed {
        assert!(scan.occurrences.is_empty());
        assert!(scan.events.iter().all(|e| e.event_type == "scanner_error"));
    }
    assert_eq!(scan()["activity_count"], 0);
    let after: Value = serde_json::from_slice(&fs::read(&state).unwrap()).unwrap();
    for key in [
        "baseline_snapshots",
        "baseline_source_contributions",
        "sqlite_ingestion_cursors",
    ] {
        assert_eq!(before[key], after[key]);
    }
    let persisted = fs::read_to_string(&log).unwrap();
    let late = persisted[offset..]
        .lines()
        .map(|l| serde_json::from_str::<Value>(l).unwrap())
        .collect::<Vec<_>>();
    assert!(late.iter().any(|e| e["event_type"] == "scanner_error"));
    assert!(
        !late
            .iter()
            .any(|e| e["event_type"] == "detection" || e["event_type"] == "activity")
    );
}
