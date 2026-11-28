use super::*;

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
