use super::*;
use crate::test_support::tree_snapshot;
use telltale_detect::v2::activity::BaselineReplacement;
use telltale_schema::observation::ObservedAt;
use telltale_sources::acquisition::{AccountingCoverage, AcquisitionProgress};

const RULE: &str = "version: 1\ndescription: synthetic\ndefaults:\n  case_insensitive: false\n  enabled: true\nrules:\n  - id: synthetic.target\n    category: synthetic\n    detection_class: security_detection\n    signal_type: atomic\n    analytic_intent: alert\n    severity: low\n    score: 1\n    targets: [user_context]\n    regex: needle\n    tags: [synthetic]\n    explanation: synthetic\nmodifiers: []\n";

fn clock() -> ObservedAt {
    ObservedAt::new("2026-09-19T00:00:00Z").unwrap()
}

#[test]
fn long_message_embedding_suffix_privacy_and_retention_failure_are_read_only() {
    let root = tempfile::tempdir().unwrap();
    let directory = root.path().join(".claude/projects/synthetic");
    std::fs::create_dir_all(&directory).unwrap();
    let path = directory.join("long.jsonl");
    let text = format!(
        "api_key=SYNTHETIC-EMBED-SECRET {}needle",
        "ordinary ".repeat(1_000)
    );
    let record = serde_json::json!({"type":"user", "sessionId":"synthetic-session", "message":{"role":"user", "content":text}});
    std::fs::write(&path, format!("{record}\n")).unwrap();
    let before = tree_snapshot(root.path());
    let pipeline = Pipeline::builder()
        .without_bundled_defaults()
        .rules_document(RULE)
        .build()
        .unwrap();
    let events = pipeline.scan_root(root.path()).unwrap();
    assert!(
        events
            .iter()
            .any(|(_, event)| event.event_type == "detection")
    );
    let json =
        serde_json::to_string(&events.iter().map(|(_, event)| event).collect::<Vec<_>>()).unwrap();
    assert!(!json.contains("SYNTHETIC-EMBED-SECRET"));
    assert_eq!(before, tree_snapshot(root.path()));
    let large = serde_json::json!({"type":"user", "sessionId":"synthetic-session", "message":{"role":"user", "content":"x".repeat(65_528)}}).to_string();
    std::fs::write(&path, format!("{}\n", vec![large; 129].join("\n"))).unwrap();
    let before = tree_snapshot(root.path());
    let events = pipeline.scan_root(root.path()).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].1.event_type, "scanner_error");
    assert_eq!(before, tree_snapshot(root.path()));
}

fn occurrence_fixture() -> (tempfile::TempDir, Source, Pipeline) {
    let root = tempfile::tempdir().unwrap();
    let directory = root.path().join(".claude/projects/synthetic");
    std::fs::create_dir_all(&directory).unwrap();
    let path = directory.join("occurrences.jsonl");
    std::fs::write(&path, concat!(
        "{\"type\":\"user\",\"sessionId\":\"occurrence-session\",\"timestamp\":\"2026-09-17T00:00:00Z\",\"message\":{\"role\":\"user\",\"content\":\"needle\"}}\n",
        "{\"type\":\"user\",\"sessionId\":\"occurrence-session\",\"message\":{\"role\":\"user\",\"content\":\"needle\"}}\n"
    )).unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink("occurrences.jsonl", directory.join("synthetic.link")).unwrap();
    let source = Source {
        client: ClientId::Claude,
        source_id: "claude.projects".into(),
        kind: SourceKind::Jsonl,
        path: path.clone(),
    };
    let pipeline = Pipeline::builder()
        .without_bundled_defaults()
        .rules_document(RULE)
        .build()
        .unwrap();
    (root, source, pipeline)
}

#[test]
fn canonical_embedding_occurrence_identities_are_private_and_stable() {
    let (root, source, pipeline) = occurrence_fixture();
    let before = tree_snapshot(root.path());
    let first = pipeline
        .scan_sources_with_occurrences(std::slice::from_ref(&source))
        .unwrap();
    let second = pipeline
        .scan_sources_with_occurrences(std::slice::from_ref(&source))
        .unwrap();
    assert_eq!(first.len(), 1);
    let scan = &first[0];
    assert_eq!(scan.source, source);
    assert_eq!(
        scan.events
            .iter()
            .map(|e| e.event_type.as_str())
            .collect::<Vec<_>>(),
        ["detection", "activity"]
    );
    assert_eq!(scan.occurrences.len(), 2);
    assert_ne!(scan.occurrences[0].identity, scan.occurrences[1].identity);
    let detection = &scan.events[0];
    let identity_evidence = detection
        .evidence
        .iter()
        .filter(|item| item.field == "canonical_observation_id")
        .collect::<Vec<_>>();
    for (index, occurrence) in scan.occurrences.iter().enumerate() {
        let id = occurrence.identity.as_str();
        assert!(telltale_schema::observation::valid_observation_id(id));
        for excluded in [
            "needle",
            "occurrence-session",
            "occurrences.jsonl",
            source.path.to_str().unwrap(),
        ] {
            assert!(!id.contains(excluded));
        }
        // Event3 keeps its existing redacted snippet and hash linkage contract.
        assert_eq!(
            identity_evidence[index].hash.as_deref(),
            Some(telltale_schema::event::evidence_hash(id).as_str())
        );
        assert_eq!(
            identity_evidence[index].redacted_value,
            telltale_schema::event::redact_sensitive_text(id)
        );
        assert_eq!(occurrence.identity, second[0].occurrences[index].identity);
        assert_ne!(id, detection.event_id);
        assert_ne!(id, second[0].events[0].event_id);
    }
    assert_ne!(detection.event_id, second[0].events[0].event_id);
    assert_eq!(tree_snapshot(root.path()), before);
}

#[test]
fn canonical_embedding_occurrences_link_to_session_timeline_and_source_time() {
    let (_root, source, pipeline) = occurrence_fixture();
    let scans = pipeline.scan_sources_with_occurrences(&[source]).unwrap();
    let scan = &scans[0];
    let detection = &scan.events[0];
    assert_eq!(scan.occurrences.len(), 2);
    for (index, occurrence) in scan.occurrences.iter().enumerate() {
        assert_eq!(occurrence.finding_index, 0);
        assert_eq!(occurrence.session_id, detection.session_id);
        assert_eq!(occurrence.timeline_index, Some(index));
        let anchor = &detection.timeline_anchors[index];
        assert_eq!(occurrence.timeline_index, Some(anchor.entry_index));
        assert_eq!(occurrence.rule_ids, anchor.rule_ids);
        assert_eq!(occurrence.categories, anchor.categories);
        assert_eq!(occurrence.evidence_fields, anchor.evidence_fields);
    }
    assert_eq!(
        scan.occurrences[0].occurred_at.as_deref(),
        Some("2026-09-17T00:00:00Z")
    );
    assert_eq!(scan.occurrences[1].occurred_at, None);
}

#[test]
fn canonical_embedding_occurrence_and_flattened_apis_share_the_session_projection_without_writes() {
    let (root, source, pipeline) = occurrence_fixture();
    let before = tree_snapshot(root.path());
    let scans = pipeline
        .scan_sources_with_occurrences(std::slice::from_ref(&source))
        .unwrap();
    let scan = &scans[0];
    let richer_root = pipeline.scan_root_with_occurrences(root.path()).unwrap();
    assert_eq!(
        richer_root[0].occurrences[0].identity,
        scan.occurrences[0].identity
    );
    for flattened in [
        pipeline
            .scan_sources(std::slice::from_ref(&source))
            .unwrap(),
        pipeline.scan_root(root.path()).unwrap(),
    ] {
        assert_eq!(flattened.len(), scan.events.len());
        for ((returned_source, event), expected) in flattened.iter().zip(&scan.events) {
            assert_eq!(returned_source, &source);
            assert_eq!(event.event_type, expected.event_type);
            assert_eq!(event.session_id, expected.session_id);
            assert_eq!(event.rule_ids, expected.rule_ids);
            assert_eq!(event.timeline_anchors, expected.timeline_anchors);
            assert_eq!(
                serde_json::to_value(&event.evidence).unwrap(),
                serde_json::to_value(&expected.evidence).unwrap()
            );
        }
    }
    assert!(
        pipeline
            .scan_sources_with_occurrences(&[])
            .unwrap()
            .is_empty()
    );
    assert_eq!(tree_snapshot(root.path()), before);
}

#[test]
fn canonical_embedding_malformed_source_has_no_public_occurrences() {
    let (root, source, pipeline) = occurrence_fixture();
    std::fs::write(&source.path, "not-json\n").unwrap();
    let before = tree_snapshot(root.path());
    let failed = pipeline.scan_sources_with_occurrences(&[source]).unwrap();
    assert_eq!(failed[0].events.len(), 1);
    assert_eq!(failed[0].events[0].event_type, "scanner_error");
    assert!(failed[0].occurrences.is_empty());
    assert_eq!(tree_snapshot(root.path()), before);
}

#[test]
fn canonical_embedding_invalid_occurrence_identity_fails_source_closed() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("synthetic.jsonl");
    std::fs::write(&path, "{\"type\":\"user\",\"sessionId\":\"synthetic\",\"message\":{\"role\":\"user\",\"content\":\"needle\"}}\n").unwrap();
    let source = Source {
        client: ClientId::Claude,
        source_id: "claude.projects".into(),
        kind: SourceKind::Jsonl,
        path,
    };
    let pipeline = Pipeline::builder()
        .without_bundled_defaults()
        .rules_document(RULE)
        .build()
        .unwrap();
    let (_, mut result) = pipeline
        .scan_canonical_sources(std::slice::from_ref(&source), clock())
        .unwrap()
        .pop()
        .unwrap();
    result.as_mut().unwrap().occurrences[0].observation_id = "unchecked synthetic identity".into();
    let scan = SourceScan::from_result(source, result, None);
    assert_eq!(scan.events.len(), 1);
    assert_eq!(scan.events[0].event_type, "scanner_error");
    assert!(scan.occurrences.is_empty());
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

    // Disabling the only rule leaves nothing to detect and is refused.
    assert!(matches!(
        Pipeline::builder()
            .without_bundled_defaults()
            .rules_document(RULE)
            .policy_document("version: 1\ndisabled_rules: [synthetic.target]\n")
            .build(),
        Err(PipelineError::EmptyRuleSet)
    ));
    let disabled = Pipeline::builder()
        .without_bundled_defaults()
        .rules_document(RULE)
        .rules_document(
            RULE.replace("synthetic.target", "synthetic.never")
                .replace("regex: needle", "regex: NEVER-MATCH"),
        )
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
#[cfg(feature = "opencode-sqlite")]
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
fn canonical_embedding_bound_context_survives_without_event3_changes() {
    use telltale_schema::observation::{
        BoundDimension, CanonicalBoundContext, CanonicalFieldCategory,
    };
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("synthetic-private-bound.jsonl");
    let marker = "SYNTHETIC-PRIVATE-BOUND-";
    let prefix = serde_json::json!({"type":"user", "session_id":marker, "content":"ok"});
    let rejected = serde_json::json!({"type":"user", "session_id":marker, "content":format!("{marker}{}", "x".repeat(65_537))});
    std::fs::write(&path, format!("{prefix}\n{rejected}\n")).unwrap();
    let pipeline = Pipeline::builder().build().unwrap();
    for (source_id, kind) in [
        ("codex.sessions", SourceKind::Jsonl),
        ("codex.archived_sessions", SourceKind::ArchivedJsonl),
        ("codex.headless_sessions", SourceKind::HeadlessJsonl),
    ] {
        let source = Source {
            client: ClientId::Codex,
            source_id: source_id.into(),
            kind,
            path: path.clone(),
        };
        let results = pipeline
            .scan_canonical_sources(std::slice::from_ref(&source), clock())
            .unwrap();
        let failure = results[0]
            .1
            .as_ref()
            .err()
            .expect("source-atomic rejection");
        assert_eq!(
            failure.progress,
            telltale_sources::acquisition::AcquisitionProgress::None
        );
        assert_eq!(
            failure.acquisition.unwrap().bound_context(),
            Some(CanonicalBoundContext {
                category: CanonicalFieldCategory::MessageContent,
                dimension: BoundDimension::StringBytes
            })
        );
        let diagnostic = format!("{failure:?} {failure}");
        assert!(!diagnostic.contains(marker), "runtime diagnostic leaked");
        let events = pipeline
            .scan_sources(std::slice::from_ref(&source))
            .unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].1.event_type, "scanner_error");
        let event = serde_json::to_string(&events[0].1).unwrap();
        assert!(event.contains("canonical_acquisition_failed"));
        for forbidden in [
            marker,
            "synthetic-private-bound",
            "MessageContent",
            "StringBytes",
            "unbounded_value",
        ] {
            assert!(
                !event.contains(forbidden),
                "frozen Event3 projection changed or leaked"
            );
        }
    }
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

#[cfg(not(feature = "opencode-sqlite"))]
#[test]
fn disabled_opencode_mixed_scan_retains_jsonl_success_and_safe_source_failure() {
    let dir = tempfile::tempdir().unwrap();
    let jsonl = dir.path().join("synthetic.jsonl");
    std::fs::write(&jsonl, "{\"type\":\"user\",\"sessionId\":\"synthetic\",\"message\":{\"role\":\"user\",\"content\":\"needle\"}}\n").unwrap();
    let database = dir.path().join("private-database-marker.db");
    let conn = rusqlite::Connection::open(&database).unwrap();
    conn.execute_batch("CREATE TABLE message (id TEXT, session_id TEXT, data TEXT); INSERT INTO message VALUES ('m','s','{\"role\":\"assistant\",\"content\":\"private-payload-marker\"}');").unwrap();
    drop(conn);
    let sources = [
        Source {
            client: ClientId::Claude,
            source_id: "claude.projects".into(),
            kind: SourceKind::Jsonl,
            path: jsonl,
        },
        Source {
            client: ClientId::OpenCode,
            source_id: "opencode.sqlite".into(),
            kind: SourceKind::Sqlite,
            path: database.clone(),
        },
    ];
    let before = tree_snapshot(dir.path());
    let modified = std::fs::metadata(&database).unwrap().modified().unwrap();
    let pipeline = Pipeline::builder()
        .without_bundled_defaults()
        .rules_document(RULE)
        .build()
        .unwrap();
    let canonical = pipeline.scan_canonical_sources(&sources, clock()).unwrap();
    assert!(
        canonical[0]
            .1
            .as_ref()
            .unwrap()
            .events
            .iter()
            .any(|event| event.event_type == "detection")
    );
    let failure = canonical[1].1.as_ref().err().unwrap();
    assert_eq!(
        failure.acquisition,
        Some(telltale_sources::acquisition::AcquisitionError::CapabilityNotCompiled)
    );
    let public = pipeline.scan_sources(&sources).unwrap();
    assert!(
        public
            .iter()
            .any(|(source, event)| source == &sources[0] && event.event_type == "detection")
    );
    let errors = public
        .iter()
        .filter(|(source, _)| source == &sources[1])
        .collect::<Vec<_>>();
    assert_eq!(errors.len(), 1);
    assert_eq!(errors[0].1.event_type, "scanner_error");
    assert!(
        !serde_json::to_string(&errors[0].1)
            .unwrap()
            .contains("private-")
    );
    assert_eq!(tree_snapshot(dir.path()), before);
    assert_eq!(
        std::fs::metadata(&database).unwrap().modified().unwrap(),
        modified
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
