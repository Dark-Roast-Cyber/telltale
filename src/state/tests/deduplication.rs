use super::*;

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
        super::super::source_fingerprint(&source),
        hex::encode(expected.finalize())
    );
    std::fs::File::create(&source.path)
        .unwrap()
        .set_len(128 * 1024 * 1024 + 1)
        .unwrap();
    assert_eq!(super::super::source_fingerprint(&source), path_hash);
}

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
