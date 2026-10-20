//! Synthetic compatibility gates; no personal transcript or command is executed.
use serde_json::{Value, json};
use std::{fs, process::Command};
use telltale_core::{Pipeline, SourceCoverage};
use telltale_schema::{
    clients::{ClientId, SourceKind},
    observation::ObservedAt,
    source::Source,
};
use telltale_sources::acquisition::{
    AccountingCoverage, AcquisitionOptions, AcquisitionProgress, acquire_source,
};

const PRIVATE: &str = "SYNTHETIC-PRIVATE-METADATA";
const RULES: &str = r#"version: 1
description: Synthetic compatibility gate.
defaults: {enabled: true, case_insensitive: false}
rules:
  - id: synthetic.result
    category: synthetic
    severity: low
    score: 3
    targets: [tool_result]
    regex: compatible-result-marker
    tags: [synthetic]
    explanation: Synthetic.
modifiers: []
"#;

fn command(id: &str, output: String) -> Value {
    json!({"type":"event_msg","payload":{"type":"item_completed","thread_id":"child-a","turn_id":"turn-a","item":{"type":"CommandExecution","id":id,"command":["inert","synthetic"],"status":"completed","exit_code":0,"aggregated_output":output}}})
}

fn transcript(suffix: bool) -> Vec<Value> {
    let mut metadata = json!({"type":"session_meta","payload":{"id":"child-a","session_id":"root-a","history_mode":"paginated"}});
    if suffix {
        metadata["payload"]["history_base"] =
            json!({"thread_id":"child-a","end_ordinal_exclusive":40,"end_byte_offset":4096});
    }
    let mut values = vec![
        metadata,
        json!({"type":"token_usage_record","payload":{"thread_id":"child-a","session_id":"root-a","usage":{"command":PRIVATE}}}),
        json!({"type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"synthetic conversation"}]}}),
        json!({"type":"event_msg","payload":{"type":"thread_settings_applied","thread_id":"child-a","thread_settings":{"message":{"role":"user","content":PRIVATE},"permissions":{"command":PRIVATE}}}}),
        json!({"type":"response_item","payload":{"type":"function_call","call_id":"call-a","name":"exec","arguments":"synthetic"}}),
        command(
            "call-a",
            format!("{} compatible-result-marker", "x".repeat(5_120)),
        ),
        json!({"type":"compacted","payload":{"message":PRIVATE,"replacement_history":[{"type":"user","content":PRIVATE}],"retained_context":{"path":PRIVATE}}}),
    ];
    if suffix {
        for kind in ["FileChange", "McpToolCall", "Extension"] {
            let mut value = json!({"type":"event_msg","payload":{"type":"item_completed","thread_id":"child-a","turn_id":"turn-a","item":{"type":kind,"id":kind,"private":PRIVATE}}});
            if kind == "FileChange" {
                // Known FileChange fields are supported; an unknown change kind
                // must still quarantine this unit without hiding its neighbors.
                value["payload"]["item"]["changes"] =
                    json!({"/synthetic/future":{"type":"future","content":PRIVATE}});
            }
            values.push(value);
        }
        values.push(command("oversize", "x".repeat(65_537)));
        values.push(json!({"type":"response_item","payload":{"type":"message","role":"assistant","content":[{"type":"output_text","text":"supported neighbor survives"}]}}));
    }
    let first = if suffix { 40 } else { 0 };
    for (offset, value) in values.iter_mut().enumerate() {
        value["ordinal"] = json!(first + offset as u64);
    }
    values
}

fn write(path: &std::path::Path, values: &[Value]) {
    fs::write(
        path,
        values
            .iter()
            .map(Value::to_string)
            .collect::<Vec<_>>()
            .join("\n")
            + "\n",
    )
    .unwrap();
}

#[test]
fn suffix_and_quarantine_survive_acquisition_embedding_cli_and_replay() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("stores");
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
        let directory = root.join("codex").join(directory);
        fs::create_dir_all(&directory).unwrap();
        let source = Source {
            client: ClientId::Codex,
            source_id: source_id.into(),
            kind,
            path: directory.join("synthetic.jsonl"),
        };
        write(&source.path, &transcript(false));
        sources.push(source);
    }
    let rules = temporary.path().join("rules.yaml");
    fs::write(&rules, RULES).unwrap();
    let log = temporary.path().join("events.jsonl");
    let state = temporary.path().join("state.json");
    let cli = || {
        let result = Command::new(env!("CARGO_BIN_EXE_telltale"))
            .env_clear()
            .env("HOME", temporary.path())
            .env("XDG_CONFIG_HOME", temporary.path().join("config"))
            .env("XDG_STATE_HOME", temporary.path().join("runtime"))
            .args([
                "scan",
                "--once",
                "--allow-fixtures",
                "--no-local-config",
                "--no-default-rules",
                "--install-inventory-disabled",
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
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        serde_json::from_slice::<Value>(&result.stdout).unwrap()
    };
    let initial = cli();
    assert_eq!(
        initial["source_processing"]["accounting_complete_source_count"],
        3
    );
    assert_eq!(
        initial["source_processing"]["accounting_partial_source_count"],
        0
    );
    assert_eq!(initial["source_processing"]["parse_error_source_count"], 0);
    let complete_state: Value = serde_json::from_slice(&fs::read(&state).unwrap()).unwrap();
    assert!(
        !complete_state["baseline_snapshots"]["snapshots"]
            .as_object()
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        complete_state["baseline_source_contributions"]
            .as_object()
            .unwrap()
            .len(),
        3
    );
    let pipeline = Pipeline::builder()
        .without_bundled_defaults()
        .rules_document(RULES)
        .build()
        .unwrap();
    for source in &sources {
        write(&source.path, &transcript(true));
    }
    let evaluations = pipeline.scan_sources_with_occurrences(&sources).unwrap();
    for evaluation in &evaluations {
        assert!(evaluation.failure().is_none());
        assert_eq!(evaluation.coverage(), Some(SourceCoverage::Partial));
        assert_eq!(evaluation.quarantined().len(), 4);
        assert!(evaluation.resume_token().is_none());
        let batch = acquire_source(
            &evaluation.source,
            AcquisitionOptions::new(ObservedAt::new("2026-10-15T12:00:00Z").unwrap()),
        )
        .unwrap();
        assert_eq!(batch.accounting.coverage, AccountingCoverage::PartialSource);
        assert_eq!(batch.progress, AcquisitionProgress::None);
        assert_eq!(batch.observations.len(), 4);
        assert_eq!(batch.observations[0].source().source_sequence(), Some(42));
        assert_eq!(batch.quarantined.len(), 4);
        assert_eq!(
            batch
                .quarantined
                .iter()
                .map(|unit| unit.code)
                .collect::<Vec<_>>(),
            [
                "unsupported_completed_item",
                "unsupported_completed_item",
                "unsupported_completed_item",
                "unbounded_value"
            ]
        );
        assert!(!format!("{:?} {:?}", batch.observations, batch.quarantined).contains(PRIVATE));
    }
    let partial = cli();
    assert_eq!(
        partial["source_processing"]["parse_success_source_count"],
        3
    );
    assert_eq!(partial["source_processing"]["parse_error_source_count"], 0);
    assert_eq!(
        partial["source_processing"]["selected_source_coverage"],
        "partial"
    );
    assert_eq!(
        partial["source_processing"]["quarantined_units"]
            .as_array()
            .unwrap()
            .len(),
        12
    );
    let partial_state: Value = serde_json::from_slice(&fs::read(&state).unwrap()).unwrap();
    for key in ["baseline_snapshots", "baseline_source_contributions"] {
        assert_eq!(complete_state[key], partial_state[key]);
    }
    assert_eq!(cli()["detection_flow"]["emitted_detection_count"], 0);
    for source in &sources {
        let mut appended = transcript(true);
        let mut new = command("new-call", "new compatible-result-marker".into());
        new["ordinal"] = json!(40 + appended.len() as u64);
        appended.push(new);
        write(&source.path, &appended);
    }
    assert!(
        cli()["detection_flow"]["emitted_detection_count"]
            .as_u64()
            .unwrap()
            > 0
    );
    let schema: Value = serde_json::from_str(include_str!("../schemas/event.schema.json")).unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    let persisted = fs::read_to_string(&log).unwrap();
    assert!(!persisted.contains(PRIVATE));
    for line in persisted.lines() {
        let event: Value = serde_json::from_str(line).unwrap();
        assert!(validator.is_valid(&event), "{event}");
    }
}

#[test]
fn native_watch_preserves_suffix_quarantine_and_supported_activity() {
    use std::process::Stdio;
    use std::time::{Duration, Instant};
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("stores");
    let directory = root.join("codex/sessions");
    fs::create_dir_all(&directory).unwrap();
    let source = directory.join("synthetic.jsonl");
    write(&source, &transcript(true));
    let rules = temp.path().join("rules.yaml");
    fs::write(&rules, RULES).unwrap();
    let log = temp.path().join("events.jsonl");
    let state = temp.path().join("state.json");
    let mut child = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .env_clear()
        .env("HOME", temp.path())
        .env("XDG_CONFIG_HOME", temp.path().join("config"))
        .args([
            "watch",
            "--iterations",
            "1",
            "--debounce-ms",
            "50",
            "--min-scan-interval-ms",
            "0",
            "--allow-fixtures",
            "--no-local-config",
            "--no-default-rules",
            "--install-inventory-disabled",
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
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // Match the repository's portable process-boundary readiness gate. Retry
    // the same complete source so delayed registration cannot lose the update.
    std::thread::sleep(Duration::from_secs(2));
    let mut changed = transcript(true);
    let mut appended = command("watch-command", "compatible-result-marker".into());
    appended["ordinal"] = json!(40 + changed.len() as u64);
    changed.push(appended);
    let deadline = Instant::now() + Duration::from_secs(30);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() >= deadline {
            let _ = child.kill();
            let output = child.wait_with_output().unwrap();
            panic!(
                "watch timed out: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        write(&source, &changed);
        std::thread::sleep(Duration::from_millis(250));
    }
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    let summary: Value =
        serde_json::from_str(stdout.lines().find(|line| line.starts_with('{')).unwrap()).unwrap();
    assert_eq!(summary["source_processing"]["parse_error_source_count"], 0);
    assert_eq!(summary["source_processing"]["quarantined_unit_count"], 4);
    assert_eq!(
        summary["source_processing"]["selected_source_coverage"],
        "partial"
    );
    assert!(
        summary["detection_flow"]["emitted_detection_count"]
            .as_u64()
            .unwrap()
            > 0
    );
    let schema: Value = serde_json::from_str(include_str!("../schemas/event.schema.json")).unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    let persisted = fs::read_to_string(log).unwrap();
    assert!(!persisted.contains(PRIVATE));
    for line in persisted.lines() {
        assert!(validator.is_valid(&serde_json::from_str::<Value>(line).unwrap()));
    }
}
