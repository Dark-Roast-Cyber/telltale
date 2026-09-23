use super::*;
use telltale_detect::v2::activity::BaselineReplacement;
use telltale_schema::observation::ObservedAt;
use telltale_sources::acquisition::{AccountingCoverage, AcquisitionProgress};

const RULE: &str = "version: 1\ndescription: synthetic\ndefaults:\n  case_insensitive: false\n  enabled: true\nrules:\n  - id: synthetic.target\n    category: synthetic\n    detection_class: security_detection\n    signal_type: atomic\n    analytic_intent: alert\n    severity: low\n    score: 1\n    targets: [user_context]\n    regex: needle\n    tags: [synthetic]\n    explanation: synthetic\nmodifiers: []\n";

fn clock() -> ObservedAt {
    ObservedAt::new("2026-09-19T00:00:00Z").unwrap()
}

#[test]
fn canonical_embedding_is_stateless_and_deterministic() {
    let root = tempfile::tempdir().unwrap();
    let directory = root.path().join(".claude/projects/synthetic");
    std::fs::create_dir_all(&directory).unwrap();
    let path = directory.join("session.jsonl");
    std::fs::write(&path, "{\"type\":\"user\",\"sessionId\":\"synthetic\",\"message\":{\"role\":\"user\",\"content\":\"needle\"}}\n").unwrap();
    let pipeline = Pipeline::builder()
        .without_bundled_defaults()
        .rules_document(RULE)
        .build()
        .unwrap();
    let sources = telltale_sources::discovery::discover_sources(root.path()).unwrap();
    assert_eq!(sources.len(), 1);
    let public = pipeline.scan_root(root.path()).unwrap();
    assert_eq!(
        public
            .iter()
            .map(|(_, event)| event.event_type.as_str())
            .collect::<Vec<_>>(),
        ["detection", "activity"]
    );
    let first = pipeline.scan_canonical_sources(&sources, clock()).unwrap();
    let second = pipeline.scan_canonical_sources(&sources, clock()).unwrap();
    let result = first[0].1.as_ref().unwrap();
    assert_eq!(
        result
            .events
            .iter()
            .map(|e| e.event_type.as_str())
            .collect::<Vec<_>>(),
        ["detection", "activity"]
    );
    assert_eq!(
        result.accounting.coverage,
        AccountingCoverage::CompleteSource
    );
    assert_eq!(result.progress, AcquisitionProgress::None);
    assert!(matches!(
        result.baseline_replacement,
        BaselineReplacement::Replace(_)
    ));
    assert_eq!(result.events[0].rule_ids, ["synthetic.target"]);
    assert_eq!(result.events[0].severity, "informational");
    assert_eq!(result.events[0].risk_score, 1);
    assert_eq!(result.events[0].session_id, "synthetic");
    assert_eq!(
        result.events[0].source_path_hash.as_deref(),
        Some(telltale_schema::event::path_hash(&sources[0].path).as_str())
    );
    let evidence = |event: &Event| {
        event
            .evidence
            .iter()
            .filter(|item| item.field == "user_context")
            .map(|item| serde_json::to_value(item).unwrap())
            .collect::<Vec<_>>()
    };
    assert_eq!(evidence(&result.events[0]).len(), 1);
    assert_eq!(evidence(&result.events[0])[0]["redacted_value"], "needle");
    assert_eq!(
        evidence(&result.events[0])[0]["rule_id"],
        "synthetic.target"
    );
    assert_eq!(
        evidence(&result.events[0])[0]["hash"],
        telltale_schema::event::evidence_hash("needle")
    );
    assert!(
        public
            .iter()
            .find(|(_, event)| event.event_type == "detection")
            .unwrap()
            .1
            .evidence
            .iter()
            .any(|item| item.field == "canonical_observation_id")
    );
    // Serialization applies the frozen Event3 terminal validation boundary.
    serde_json::to_value(&result.events).unwrap();
    assert_eq!(result.events[1].risk_score, 0);
    // Event3 constructors own fresh envelope IDs/clocks; semantic order is stable.
    for (a, b) in result
        .events
        .iter()
        .zip(&second[0].1.as_ref().unwrap().events)
    {
        assert_eq!(a.event_type, b.event_type);
        assert_eq!(a.rule_ids, b.rule_ids);
        assert_eq!(a.session_id, b.session_id);
        assert_eq!(a.severity, b.severity);
        assert_eq!(
            serde_json::to_value(&a.evidence).unwrap(),
            serde_json::to_value(&b.evidence).unwrap()
        );
    }
    assert_eq!(std::fs::read_dir(&directory).unwrap().count(), 1);

    let disabled = Pipeline::builder()
        .without_bundled_defaults()
        .rules_document(RULE)
        .policy_document("version: 1\ndisabled_rules: [synthetic.target]\n")
        .build()
        .unwrap();
    let disabled_public = disabled.scan_root(root.path()).unwrap();
    assert_eq!(disabled_public.len(), 1);
    assert_eq!(disabled_public[0].1.event_type, "activity");
    let disabled = disabled.scan_canonical_sources(&sources, clock()).unwrap();
    assert_eq!(disabled[0].1.as_ref().unwrap().events.len(), 1);
    assert_eq!(
        disabled[0].1.as_ref().unwrap().events[0].event_type,
        "activity"
    );
    let additive = Pipeline::builder()
        .rules_document(RULE)
        .build()
        .unwrap()
        .scan_canonical_sources(&sources, clock())
        .unwrap();
    assert!(additive[0].1.as_ref().unwrap().events.iter().any(|event| {
        event.event_type == "detection" && event.rule_ids.iter().any(|id| id == "synthetic.target")
    }));
}

#[test]
fn canonical_embedding_opencode_remains_partial_without_persisting_progress() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("synthetic.db");
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute_batch(r#"CREATE TABLE message (id TEXT, session_id TEXT, data TEXT);
        CREATE TABLE part (id TEXT, message_id TEXT, session_id TEXT, time_updated INTEGER, data TEXT);
        INSERT INTO message VALUES ('m','s','{"role":"assistant"}');
        INSERT INTO part VALUES ('p','m','s',10,'{"type":"tool","tool":"shell","callID":"call-a","state":{"status":"running","input":{"command":"echo synthetic"}}}');"#).unwrap();
    drop(conn);
    let before = std::fs::read(&path).unwrap();
    let sources = [Source {
        client: ClientId::OpenCode,
        source_id: "opencode.sqlite".into(),
        kind: SourceKind::Sqlite,
        path: path.clone(),
    }];
    let result = Pipeline::builder()
        .build()
        .unwrap()
        .scan_canonical_sources(&sources, clock())
        .unwrap();
    assert_eq!(
        result[0].1.as_ref().unwrap().accounting.coverage,
        AccountingCoverage::PartialSource
    );
    assert_eq!(
        result[0].1.as_ref().unwrap().baseline_replacement,
        BaselineReplacement::NoReplacement
    );
    assert!(
        result[0]
            .1
            .as_ref()
            .unwrap()
            .events
            .iter()
            .any(|event| event.event_type == "activity")
    );
    assert_eq!(std::fs::read(path).unwrap(), before);
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
}

#[test]
fn canonical_embedding_rejects_retired_identity_without_successful_output() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("synthetic.jsonl");
    std::fs::write(&path, "{}\n").unwrap();
    let source = Source {
        client: ClientId::Codex,
        source_id: "codex.project_sessions".into(),
        kind: SourceKind::Jsonl,
        path,
    };
    let pipeline = Pipeline::builder().build().unwrap();
    let results = pipeline.scan_canonical_sources(&[source], clock()).unwrap();
    let error = results[0].1.as_ref().err().unwrap();
    assert_eq!(error.stage, canonical_runtime::FailureStage::Acquisition);
    assert_eq!(
        error.acquisition,
        Some(telltale_sources::acquisition::AcquisitionError::UnsupportedSourceIdentity)
    );
}

#[test]
fn scan_root_returns_scanner_error_for_malformed_synthetic_source() {
    let root = tempfile::tempdir().unwrap();
    let directory = root.path().join(".claude/projects/synthetic");
    std::fs::create_dir_all(&directory).unwrap();
    std::fs::write(directory.join("malformed.jsonl"), "not-json\n").unwrap();

    let events = Pipeline::builder()
        .build()
        .unwrap()
        .scan_root(root.path())
        .unwrap();

    assert_eq!(events.len(), 1);
    assert_eq!(events[0].1.event_type, "scanner_error");
}
