//! Pinned synthetic Codex shapes through acquisition, deterministic evaluation,
//! and the real scan/output/state boundary. No session capture or tool execution.
use serde_json::{Value, json};
use std::{fs, process::Command};
use telltale_core::Pipeline;
use telltale_schema::{
    clients::{ClientId, SourceKind},
    observation::ObservedAt,
    source::Source,
};
use telltale_sources::acquisition::{
    AccountingCoverage, AcquisitionOptions, AcquisitionProgress, acquire_source,
};

const PRIVATE: &str = "SYNTHETIC-GAPS-PRIVATE";
const RULES: &str = r#"version: 1
description: Synthetic Codex record conformance, not an efficacy label.
defaults: {enabled: true, case_insensitive: false}
rules:
  - id: synthetic.search
    category: synthetic
    severity: low
    score: 3
    targets: [arguments]
    regex: gap-search-needle
    tags: [synthetic]
    explanation: Synthetic search action.
  - id: synthetic.assistant
    category: synthetic
    severity: low
    score: 3
    targets: [assistant_context]
    regex: gap-assistant-needle
    tags: [synthetic]
    explanation: Synthetic assistant text.
modifiers: []
"#;

fn write(source: &Source, values: &[Value]) {
    fs::write(
        &source.path,
        values.iter().map(|v| format!("{v}\n")).collect::<String>(),
    )
    .unwrap();
}

fn acquire(source: &Source) -> telltale_sources::acquisition::AcquisitionBatch {
    acquire_source(
        source,
        AcquisitionOptions::new(ObservedAt::new("2026-10-13T12:00:00Z").unwrap()),
    )
    .unwrap()
}

#[test]
fn pinned_cases_have_exact_content_counts_and_complete_accounting_for_each_identity() {
    let temp = tempfile::tempdir().unwrap();
    let cases = [
        (
            include_str!("upstream_formats/cases/codex/web-search-call-item.json"),
            3,
            1,
        ),
        (
            include_str!("upstream_formats/cases/codex/item-completed-plan.json"),
            3,
            0,
        ),
        (
            include_str!("upstream_formats/cases/codex/legacy-agent-message-event.json"),
            2,
            0,
        ),
    ];
    for (case, expected, calls) in cases {
        let case: Value = serde_json::from_str(case).unwrap();
        let mut identities = Vec::<String>::new();
        for (source_id, kind) in [
            ("codex.sessions", SourceKind::Jsonl),
            ("codex.archived_sessions", SourceKind::ArchivedJsonl),
            ("codex.headless_sessions", SourceKind::HeadlessJsonl),
        ] {
            let source = Source {
                client: ClientId::Codex,
                source_id: source_id.into(),
                kind,
                path: temp.path().join("synthetic.jsonl"),
            };
            write(&source, case["acquire"]["jsonl"].as_array().unwrap());
            let batch = acquire(&source);
            assert_eq!(batch.observations.len(), expected);
            assert!(batch.quarantined.is_empty());
            assert_eq!(
                batch.accounting.coverage,
                AccountingCoverage::CompleteSource
            );
            assert_eq!(batch.progress, AcquisitionProgress::None);
            let counts = &batch.accounting.sessions[0].counts;
            assert_eq!(counts.native_units, 4);
            assert_eq!(counts.record_counts.tool_call, calls);
            assert_eq!(
                counts.record_counts.assistant_message,
                if expected == 2 || calls == 0 { 2 } else { 1 }
            );
            for observation in &batch.observations {
                assert_eq!(observation.source().adapter_id(), source_id);
                assert!(
                    !identities
                        .iter()
                        .any(|id| id == observation.observation_id())
                );
                identities.push(observation.observation_id().to_owned());
            }
            let replay = acquire(&source);
            for (a, b) in batch.observations.iter().zip(replay.observations) {
                assert_eq!(a.observation_id(), b.observation_id());
                assert_eq!(a.semantic_comparison(), b.semantic_comparison());
            }
        }
    }
}

fn transcript(matching: bool) -> Vec<Value> {
    let text = if matching {
        format!("gap-assistant-needle api_key={PRIVATE}")
    } else {
        "ordinary assistant text".into()
    };
    let query = if matching {
        format!("gap-search-needle api_key={PRIVATE}")
    } else {
        "ordinary synthetic search".into()
    };
    let mut values = vec![
        json!({"type":"session_meta","payload":{"id":"synthetic-thread","history_mode":"legacy"}}),
        json!({"type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"ordinary user"}]}}),
        json!({"type":"response_item","payload":{"type":"web_search_call","status":"completed","action":{"type":"search","query":query}}}),
        json!({"type":"event_msg","payload":{"type":"item_completed","thread_id":"synthetic-thread","turn_id":"turn-a","item":{"type":"Plan","id":"plan-a","text":text}}}),
        json!({"type":"event_msg","payload":{"type":"agent_message","message":text}}),
        json!({"type":"response_item","payload":{"type":"message","role":"assistant","content":[{"type":"output_text","text":text}]}}),
        json!({"type":"event_msg","payload":{"type":"agent_message","message":format!("unique {text}")}}),
        json!({"type":"response_item","payload":{"type":"message","role":"assistant","content":[{"type":"output_text","text":"ordinary final"}]}}),
    ];
    // Process-rule visibility requires source time on tool facts. Pinned
    // rollout records have timestamps; omitting them would be a real limitation.
    for (index, value) in values.iter_mut().enumerate() {
        value["timestamp"] = json!(format!("2026-10-13T00:00:{index:02}Z"));
    }
    values
}

#[test]
fn record_gaps_reach_production_detection_once_with_privacy_and_atomic_failure() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("stores");
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
        let directory = root.join("codex").join(directory);
        fs::create_dir_all(&directory).unwrap();
        let source = Source {
            client: ClientId::Codex,
            source_id: source_id.into(),
            kind,
            path: directory.join("synthetic.jsonl"),
        };
        write(&source, &transcript(false));
        let benign = pipeline
            .scan_sources_with_occurrences(std::slice::from_ref(&source))
            .unwrap();
        assert!(benign[0].occurrences.is_empty());
        write(&source, &transcript(true));
        let batch = acquire(&source);
        assert_eq!(batch.observations.len(), 6);
        assert_eq!(
            batch
                .observations
                .iter()
                .map(|o| o.sequence().unwrap())
                .collect::<Vec<_>>(),
            [1, 2, 3, 5, 6, 7]
        );
        assert_eq!(batch.accounting.sessions[0].counts.native_units, 8);
        assert_eq!(
            batch.accounting.sessions[0]
                .counts
                .record_counts
                .assistant_message,
            5
        );
        let scan = pipeline
            .scan_sources_with_occurrences(std::slice::from_ref(&source))
            .unwrap()
            .remove(0);
        assert!(scan.failure().is_none());
        let mut counts = std::collections::BTreeMap::<&str, usize>::new();
        for occurrence in &scan.occurrences {
            for rule in &occurrence.rule_ids {
                *counts.entry(rule).or_default() += 1;
            }
        }
        assert_eq!(
            counts,
            std::collections::BTreeMap::from([("synthetic.assistant", 3), ("synthetic.search", 1)])
        );
        assert!(
            !serde_json::to_string(&scan.events)
                .unwrap()
                .contains(PRIVATE)
        );
        sources.push(source);
    }
    let rules = temp.path().join("rules.yaml");
    fs::write(&rules, RULES).unwrap();
    let log = temp.path().join("events.jsonl");
    let state = temp.path().join("state.json");
    let cli = || {
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
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!String::from_utf8_lossy(&output.stdout).contains(PRIVATE));
        assert!(!String::from_utf8_lossy(&output.stderr).contains(PRIVATE));
        serde_json::from_slice::<Value>(&output.stdout).unwrap()
    };
    let initial = cli();
    assert_eq!(initial["detection_count"], 3);
    assert_eq!(
        initial["source_processing"]["selected_source_coverage"], "complete",
        "{initial}"
    );
    assert_eq!(
        initial["source_processing"]["accounting_complete_source_count"],
        3
    );
    assert_eq!(initial["source_processing"]["quarantined_unit_count"], 0);
    assert_eq!(cli()["detection_flow"]["emitted_detection_count"], 0);
    let before: Value = serde_json::from_slice(&fs::read(&state).unwrap()).unwrap();
    let offset = fs::metadata(&log).unwrap().len() as usize;
    for source in &sources {
        let mut broken = transcript(true);
        let mut bad = broken[3].clone();
        bad["payload"]["item"]["text"] = json!({"private":PRIVATE});
        broken.push(bad);
        write(source, &broken);
    }
    let failed = cli();
    assert_eq!(failed["source_processing"]["parse_error_source_count"], 3);
    assert_eq!(failed["activity_count"], 0);
    let after: Value = serde_json::from_slice(&fs::read(&state).unwrap()).unwrap();
    for key in [
        "baseline_snapshots",
        "baseline_source_contributions",
        "sqlite_ingestion_cursors",
    ] {
        assert_eq!(before[key], after[key]);
    }
    let persisted = fs::read_to_string(&log).unwrap();
    let validator = jsonschema::validator_for(
        &serde_json::from_str::<Value>(include_str!("../schemas/event.schema.json")).unwrap(),
    )
    .unwrap();
    let mut detections = 0;
    for line in persisted.lines() {
        let event: Value = serde_json::from_str(line).unwrap();
        assert!(validator.is_valid(&event));
        if event["event_type"] == "detection" {
            detections += 1;
            assert_eq!(event["risk_score"], 6);
            assert_eq!(
                event["rule_ids"],
                json!(["synthetic.assistant", "synthetic.search"])
            );
            assert_eq!(event["timeline_anchors"].as_array().unwrap().len(), 4);
        }
    }
    assert_eq!(detections, 3);
    let late = persisted[offset..]
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect::<Vec<_>>();
    assert!(
        late.iter()
            .any(|event| event["event_type"] == "scanner_error")
    );
    assert!(
        late.iter()
            .all(|event| event["event_type"] != "detection" && event["event_type"] != "activity")
    );
    assert!(!persisted.contains(PRIVATE));
    assert!(!String::from_utf8_lossy(&fs::read(state).unwrap()).contains(PRIVATE));
}
