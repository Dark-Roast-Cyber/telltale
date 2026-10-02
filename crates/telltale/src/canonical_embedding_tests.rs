use super::*;
use telltale_detect::v2::activity::BaselineReplacement;
use telltale_schema::observation::ObservedAt;
use telltale_sources::acquisition::{AccountingCoverage, AcquisitionProgress};

const RULE: &str = "version: 1\ndescription: synthetic\ndefaults:\n  case_insensitive: false\n  enabled: true\nrules:\n  - id: synthetic.target\n    category: synthetic\n    detection_class: security_detection\n    signal_type: atomic\n    analytic_intent: alert\n    severity: low\n    score: 1\n    targets: [user_context]\n    regex: needle\n    tags: [synthetic]\n    explanation: synthetic\nmodifiers: []\n";

fn clock() -> ObservedAt {
    ObservedAt::new("2026-09-19T00:00:00Z").unwrap()
}

fn tree_snapshot(root: &Path) -> std::collections::BTreeMap<std::path::PathBuf, Option<Vec<u8>>> {
    fn visit(
        root: &Path,
        directory: &Path,
        entries: &mut std::collections::BTreeMap<std::path::PathBuf, Option<Vec<u8>>>,
    ) {
        for entry in std::fs::read_dir(directory).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            let relative = path.strip_prefix(root).unwrap().to_path_buf();
            if entry.file_type().unwrap().is_dir() {
                entries.insert(relative, None);
                visit(root, &path, entries);
            } else {
                assert!(entry.file_type().unwrap().is_file());
                entries.insert(relative, Some(std::fs::read(path).unwrap()));
            }
        }
    }
    let mut entries = std::collections::BTreeMap::new();
    visit(root, root, &mut entries);
    entries
}

#[test]
fn canonical_embedding_scan_sources_selects_exact_source_without_writes() {
    let root = tempfile::tempdir().unwrap();
    let directory = root.path().join(".claude/projects/synthetic");
    std::fs::create_dir_all(&directory).unwrap();
    let selected_path = directory.join("selected.jsonl");
    std::fs::write(&selected_path, concat!(
        "{\"type\":\"user\",\"sessionId\":\"selected\",\"message\":{\"role\":\"user\",\"content\":\"needle first\"}}\n",
        "{\"type\":\"user\",\"sessionId\":\"selected\",\"message\":{\"role\":\"user\",\"content\":\"needle second\"}}\n"
    )).unwrap();
    std::fs::write(directory.join("sibling.jsonl"), "{\"type\":\"user\",\"sessionId\":\"sibling\",\"message\":{\"role\":\"user\",\"content\":\"needle sibling\"}}\n").unwrap();
    let before = tree_snapshot(root.path());
    let sources = telltale_sources::discovery::discover_sources(root.path()).unwrap();
    assert_eq!(sources.len(), 2);
    let selected = sources
        .iter()
        .find(|source| source.path == selected_path)
        .unwrap();
    let pipeline = Pipeline::builder()
        .without_bundled_defaults()
        .rules_document(RULE)
        .build()
        .unwrap();
    let root_events = pipeline.scan_root(root.path()).unwrap();
    assert!(
        root_events
            .iter()
            .any(|(source, event)| source != selected && event.session_id == "sibling")
    );
    let events = pipeline
        .scan_sources(std::slice::from_ref(selected))
        .unwrap();
    assert_eq!(events.len(), 2);
    assert!(
        events
            .iter()
            .all(|(source, event)| source == selected && event.session_id == "selected")
    );
    let filtered = root_events
        .iter()
        .filter(|(source, _)| source == selected)
        .collect::<Vec<_>>();
    assert_eq!(events.len(), filtered.len());
    for ((_, event), (_, expected)) in events.iter().zip(filtered) {
        assert_eq!(event.event_type, expected.event_type);
        assert_eq!(event.rule_ids, expected.rule_ids);
        assert_eq!(
            serde_json::to_value(&event.timeline_anchors).unwrap(),
            serde_json::to_value(&expected.timeline_anchors).unwrap()
        );
    }
    let detection = &events[0].1;
    assert_eq!(detection.event_type, "detection");
    assert_eq!(detection.rule_ids, ["synthetic.target"]);
    // Two matching actions remain one session detection with occurrence anchors.
    assert_eq!(detection.timeline_anchors.len(), 2);
    for (index, anchor) in detection.timeline_anchors.iter().enumerate() {
        assert_eq!(anchor.entry_index, index);
        assert_eq!(anchor.rule_ids, ["synthetic.target"]);
        assert_eq!(anchor.evidence_fields, ["user_context"]);
    }
    assert_eq!(events[1].1.event_type, "activity");
    assert!(events[1].1.timeline_anchors.is_empty());
    assert!(pipeline.scan_sources(&[]).unwrap().is_empty());
    assert_eq!(tree_snapshot(root.path()), before);
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
    let before = tree_snapshot(dir.path());
    let sources = [Source {
        client: ClientId::OpenCode,
        source_id: "opencode.sqlite".into(),
        kind: SourceKind::Sqlite,
        path: path.clone(),
    }];
    let pipeline = Pipeline::builder().build().unwrap();
    let result = pipeline.scan_canonical_sources(&sources, clock()).unwrap();
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
    let public = pipeline.scan_sources(&sources).unwrap();
    assert!(public.iter().all(|(source, _)| source == &sources[0]));
    assert!(
        public
            .iter()
            .any(|(_, event)| event.event_type == "activity")
    );
    assert_eq!(tree_snapshot(dir.path()), before);
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

    let before = tree_snapshot(root.path());
    let sources = telltale_sources::discovery::discover_sources(root.path()).unwrap();
    let pipeline = Pipeline::builder().build().unwrap();
    let events = pipeline.scan_root(root.path()).unwrap();

    assert_eq!(events.len(), 1);
    assert_eq!(events[0].1.event_type, "scanner_error");
    let selected = pipeline.scan_sources(&sources).unwrap();
    assert_eq!(selected.len(), 1);
    assert_eq!(selected[0].0, events[0].0);
    assert_eq!(selected[0].1.event_type, events[0].1.event_type);
    assert_eq!(selected[0].1.rule_ids, events[0].1.rule_ids);
    assert_eq!(
        serde_json::to_value(&selected[0].1.evidence).unwrap(),
        serde_json::to_value(&events[0].1.evidence).unwrap()
    );
    assert_eq!(tree_snapshot(root.path()), before);
}
