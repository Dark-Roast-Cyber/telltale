use super::*;

#[test]
fn investigation_jsonl_is_content_free_and_preserves_artifacts() {
    let dir = tempdir();
    let source = codex(dir.path(), JSONL);
    let input = event(&source, "synthetic-session");
    let backend = SessionInvestigator::new(InvestigationConfig::new(dir.path()));
    let result = backend.investigate(&input);
    let InvestigationResult::Found(found) = &result else {
        panic!("{result:?}")
    };
    assert_eq!(found.timeline.entry_count, 2);
    assert_eq!(found.timeline.entries[0].linked_entry_index, Some(1));
    assert_eq!(found.timeline.entries[1].linked_entry_index, Some(0));
    assert!(found.timeline.entries.iter().all(|e| e.evidence.is_empty()));
    assert_eq!(result.reason_code(), None);
    let public = format!(
        "{result:?} {}",
        serde_json::to_string(&found.timeline).unwrap()
    );
    for canary in [
        "ordinary_content_canary",
        "OUTPUT_CANARY",
        "EXPLICIT_CALL_CANARY",
        dir.path().to_str().unwrap(),
    ] {
        assert!(!public.contains(canary));
    }
    assert_eq!(backend.investigate(&input), result);
    assert_eq!(fs::read_to_string(&source.path).unwrap(), JSONL);
    assert!(!source.path.with_extension("jsonl-wal").exists());
}

#[test]
fn investigation_exact_identity_and_known_source_loss() {
    let dir = tempdir();
    let source = codex(dir.path(), JSONL);
    let mut config = InvestigationConfig::new(dir.path());
    config.known_sources = vec![source.clone()];
    let backend = SessionInvestigator::new(config);
    assert_eq!(
        backend.investigate(&event(&source, "different-session")),
        InvestigationResult::SessionUnavailable(SessionUnavailableReason::ExactSessionAbsent)
    );
    let mut other_client = source.clone();
    other_client.client = ClientId::Claude;
    assert_eq!(
        backend.investigate(&event(&other_client, "synthetic-session")),
        InvestigationResult::NotLocallyResolvable(NotLocallyResolvableReason::UnknownSource)
    );
    fs::rename(&source.path, source.path.with_file_name("moved.jsonl")).unwrap();
    assert_eq!(
        backend.investigate(&event(&source, "synthetic-session")),
        InvestigationResult::SourceUnavailable(SourceUnavailableReason::Missing)
    );
    let fresh = SessionInvestigator::new(InvestigationConfig::new(dir.path()));
    assert_eq!(
        fresh.investigate(&event(&source, "synthetic-session")),
        InvestigationResult::NotLocallyResolvable(NotLocallyResolvableReason::UnknownSource)
    );
}

#[test]
fn investigation_duplicate_selection_is_order_independent() {
    let dir = tempdir();
    let source = codex(dir.path(), JSONL);
    let input = event(&source, "synthetic-session");
    let mut conflicting = source.clone();
    conflicting.source_id = "PRIVATE_SOURCE_ID_CANARY".into();
    for sources in [
        vec![source.clone(), source.clone()],
        vec![source.clone(), conflicting.clone()],
        vec![conflicting, source.clone()],
    ] {
        let ambiguous = sources[0] != sources[1];
        let mut config = InvestigationConfig::new(dir.path());
        config.known_sources = sources;
        let result = SessionInvestigator::new(config).investigate(&input);
        if ambiguous {
            assert_eq!(
                result,
                InvestigationResult::NotLocallyResolvable(
                    NotLocallyResolvableReason::AmbiguousSource
                )
            );
        } else {
            assert!(matches!(result, InvestigationResult::Found(_)));
        }
        assert!(!format!("{result:?}").contains("PRIVATE_SOURCE_ID_CANARY"));
    }
}

#[test]
fn investigation_event_correlation_and_metadata_only_session_are_explicit() {
    use telltale_schema::event::{HealthEventInput, health_event_with_metadata};
    let dir = tempdir();
    let source = codex(dir.path(), JSONL);
    let backend = SessionInvestigator::new(InvestigationConfig::new(dir.path()));
    let health = health_event_with_metadata(HealthEventInput {
        sources: &[],
        source_inventory_change: None,
        scan_duration_ms: 0,
        rule_count: 0,
        threshold_config: telltale_schema::scoring::RiskThresholds {
            low: 1,
            medium: 2,
            high: 3,
            critical: 4,
        },
        active_policy_name: None,
        emitted_count: 0,
        suppressed_count: 0,
        scanner_error_count: 0,
    });
    let health = Event3Record::from_json(&serde_json::to_vec(&health).unwrap()).unwrap();
    assert_eq!(
        backend.investigate(&health),
        InvestigationResult::NotLocallyResolvable(NotLocallyResolvableReason::MissingCorrelation)
    );
    let mut value: serde_json::Value =
        serde_json::from_slice(&event_json(&source, "synthetic-session")).unwrap();
    value["client"] = "PRIVATE_CLIENT_CANARY".into();
    let unknown = Event3Record::from_json(&serde_json::to_vec(&value).unwrap()).unwrap();
    assert_eq!(
        backend.investigate(&unknown),
        InvestigationResult::NotLocallyResolvable(NotLocallyResolvableReason::UnsupportedClient)
    );
    fs::write(
        &source.path,
        "{\"type\":\"session_meta\",\"payload\":{\"session_id\":\"synthetic-session\"}}\n",
    )
    .unwrap();
    assert_eq!(
        backend.investigate(&event(&source, "synthetic-session")),
        InvestigationResult::SessionUnavailable(SessionUnavailableReason::NoTimeline)
    );
}

#[test]
fn investigation_anchors_are_only_recorded_and_current_indexes() {
    let dir = tempdir();
    let source = codex(dir.path(), JSONL);
    let mut value =
        serde_json::from_slice::<serde_json::Value>(&event_json(&source, "synthetic-session"))
            .unwrap();
    value["event_type"] = "detection".into();
    value["rule_ids"] = serde_json::json!(["synthetic.rule"]);
    value["categories"] = serde_json::json!(["synthetic"]);
    value["detection_classes"] = serde_json::json!(["security_detection"]);
    value["signal_types"] = serde_json::json!(["atomic"]);
    value["analytic_intents"] = serde_json::json!(["alert"]);
    value["atlas_tags"] = serde_json::json!([]);
    value["response"] = serde_json::json!({"recommended_action":"monitor", "response_playbook":"telltale-playbook-synthetic",
        "investigation_summary":"Synthetic investigation", "escalation":"routine_review"});
    value["timeline_anchors"] = serde_json::json!([
        {"entry_index":0,"rule_ids":["synthetic.rule"],"categories":["synthetic"],"evidence_fields":["arguments"]},
        {"entry_index":99,"rule_ids":["synthetic.rule"],"categories":["synthetic"],"evidence_fields":["arguments"]}
    ]);
    let input = Event3Record::from_json(&serde_json::to_vec(&value).unwrap()).unwrap();
    let InvestigationResult::Found(found) =
        SessionInvestigator::new(InvestigationConfig::new(dir.path())).investigate(&input)
    else {
        panic!("missing session");
    };
    assert_eq!(
        found.anchors,
        vec![
            InvestigationAnchor {
                recorded_entry_index: 0,
                current_entry_index: Some(0)
            },
            InvestigationAnchor {
                recorded_entry_index: 99,
                current_entry_index: None
            }
        ]
    );
}

#[test]
fn investigation_json_object_and_jsonl_with_same_session_keep_clients_separate() {
    let dir = tempdir();
    let codex_source = codex(dir.path(), JSONL);
    fs::create_dir_all(dir.path().join("claude/projects")).unwrap();
    let payload = r#"{"type":"user","sessionId":"synthetic-session","message":{"role":"user","content":[{"type":"text","text":"CLAUDE_CONTENT_CANARY"}]}}"#;
    fs::write(dir.path().join("claude/projects/synthetic.jsonl"), payload).unwrap();
    let claude_source = discover_sources(dir.path())
        .unwrap()
        .into_iter()
        .find(|s| s.source_id == "claude.projects")
        .unwrap();
    let backend = SessionInvestigator::new(InvestigationConfig::new(dir.path()));
    for source in [&codex_source, &claude_source] {
        let result = backend.investigate(&event(source, "synthetic-session"));
        let InvestigationResult::Found(found) = &result else {
            panic!("{result:?}")
        };
        assert_eq!(found.timeline.client, source.client.as_str());
        assert_eq!(
            found.timeline.entry_count,
            if source.client == ClientId::Codex {
                2
            } else {
                1
            }
        );
        assert!(!format!("{result:?}").contains("CLAUDE_CONTENT_CANARY"));
    }
    let mut wrong_client = codex_source.clone();
    wrong_client.client = ClientId::Claude;
    assert_eq!(
        backend.investigate(&event(&wrong_client, "synthetic-session")),
        InvestigationResult::NotLocallyResolvable(NotLocallyResolvableReason::UnknownSource)
    );
    assert_eq!(fs::read_to_string(&claude_source.path).unwrap(), payload);
}
