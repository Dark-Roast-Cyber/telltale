use telltale_schema::event::Event;

use super::*;

fn detection_event(
    session_id: &str,
    timestamp: &str,
    rule_ids: &[&str],
    model: Option<&str>,
    risk_score: u64,
) -> Event {
    let event_number = session_id.bytes().fold(0_u64, |total, byte| {
        total.wrapping_mul(31).wrapping_add(u64::from(byte))
    });
    Event {
        timestamp: timestamp.to_string(),
        event_time: Some(timestamp.to_string()),
        observed_at: timestamp.to_string(),
        ingested_at: timestamp.to_string(),
        time_source: "source".to_string(),
        time_confidence: "high".to_string(),
        time_override_reason: None,
        schema_version: "3.0".to_string(),
        event_id: format!("telltale-00000000-0000-4000-8000-{event_number:012x}"),
        telltale_version: env!("CARGO_PKG_VERSION").to_string(),
        event_type: "detection".to_string(),
        severity: "high".to_string(),
        risk_score,
        risk_contributions: Vec::new(),
        client: "codex".to_string(),
        agent: Some("codex".to_string()),
        model: model.map(ToOwned::to_owned),
        provider: Some("openai".to_string()),
        session_id: session_id.to_string(),
        source_path_hash: Some("sha256:source".to_string()),
        tool_name: Some("shell".to_string()),
        rule_ids: rule_ids
            .iter()
            .map(|rule_id| (*rule_id).to_string())
            .collect(),
        categories: vec!["mcp_prompt_injection".to_string()],
        detection_classes: vec!["security_detection".to_string()],
        signal_types: vec!["atomic".to_string()],
        analytic_intents: vec!["alert".to_string()],
        atlas_tags: vec!["atlas:AML.T0051".to_string()],
        tags: vec!["mcp".to_string()],
        evidence: Vec::new(),
        timeline_anchors: Vec::new(),
        response: None,
        source_counts: None,
        component: None,
        check_name: None,
        status: None,
        scan_duration_ms: None,
        rule_count: None,
        threshold_config: None,
        active_policy_name: None,
        emitted_count: None,
        suppressed_count: None,
        scanner_error_count: None,
        informational: None,
        confidence: None,
        detection_reason: None,
        mitre_attack_techniques: Vec::new(),
        risk_entity_type: None,
        risk_entity_value: None,
        process: None,
    }
}

#[test]
fn correlates_matching_detections_across_sessions_in_window() {
    let events = vec![
        detection_event(
            "session-a",
            "2026-05-10T10:00:00Z",
            &["mcp.tool_metadata.prompt_injection"],
            Some("gpt-5"),
            90,
        ),
        detection_event(
            "session-b",
            "2026-05-10T10:20:00Z",
            &[
                "mcp.tool_metadata.prompt_injection",
                "network.controlled_test_domain.darkroast",
            ],
            Some("gpt-5"),
            95,
        ),
    ];

    let correlations = correlate_detection_events(&events, &CorrelationConfig::default());

    assert_eq!(correlations.len(), 1);
    assert_eq!(correlations[0].actor.client, "codex");
    assert_eq!(correlations[0].actor.model.as_deref(), Some("gpt-5"));
    assert_eq!(
        correlations[0].shared_rule_ids,
        vec!["mcp.tool_metadata.prompt_injection".to_string()]
    );
    assert_eq!(correlations[0].sessions.len(), 2);
    assert_eq!(correlations[0].max_risk_score, 95);
}

#[test]
fn ignores_repeated_rule_hits_in_same_session() {
    let events = vec![
        detection_event(
            "session-a",
            "2026-05-10T10:00:00Z",
            &["mcp.tool_metadata.prompt_injection"],
            Some("gpt-5"),
            90,
        ),
        detection_event(
            "session-a",
            "2026-05-10T10:10:00Z",
            &["mcp.tool_metadata.prompt_injection"],
            Some("gpt-5"),
            95,
        ),
    ];

    let correlations = correlate_detection_events(&events, &CorrelationConfig::default());

    assert!(correlations.is_empty());
}

#[test]
fn requires_matching_actor_and_window() {
    let events = vec![
        detection_event(
            "session-a",
            "2026-05-10T10:00:00Z",
            &["mcp.tool_metadata.prompt_injection"],
            Some("gpt-5"),
            90,
        ),
        detection_event(
            "session-b",
            "2026-05-10T10:30:00Z",
            &["mcp.tool_metadata.prompt_injection"],
            Some("other-model"),
            95,
        ),
        detection_event(
            "session-c",
            "2026-05-10T12:30:00Z",
            &["mcp.tool_metadata.prompt_injection"],
            Some("gpt-5"),
            95,
        ),
    ];

    let correlations = correlate_detection_events(&events, &CorrelationConfig::default());

    assert!(correlations.is_empty());
}

#[test]
fn ignores_low_risk_and_malformed_timestamp_events() {
    let events = vec![
        detection_event(
            "session-a",
            "2026-05-10T10:00:00Z",
            &["mcp.tool_metadata.prompt_injection"],
            Some("gpt-5"),
            40,
        ),
        detection_event(
            "session-b",
            "not-a-timestamp",
            &["mcp.tool_metadata.prompt_injection"],
            Some("gpt-5"),
            95,
        ),
    ];

    let correlations = correlate_detection_events(&events, &CorrelationConfig::default());

    assert!(correlations.is_empty());
}

#[test]
fn aggregates_shared_rule_ids_for_identical_actor_windows() {
    let events = vec![
        detection_event(
            "session-a",
            "2026-05-10T10:00:00Z",
            &[
                "mcp.tool_metadata.prompt_injection",
                "network.controlled_test_domain.darkroast",
            ],
            Some("gpt-5"),
            90,
        ),
        detection_event(
            "session-b",
            "2026-05-10T10:20:00Z",
            &[
                "mcp.tool_metadata.prompt_injection",
                "network.controlled_test_domain.darkroast",
            ],
            Some("gpt-5"),
            95,
        ),
    ];

    let correlations = correlate_detection_events(&events, &CorrelationConfig::default());

    assert_eq!(correlations.len(), 1);
    assert_eq!(
        correlations[0].shared_rule_ids,
        vec![
            "mcp.tool_metadata.prompt_injection".to_string(),
            "network.controlled_test_domain.darkroast".to_string(),
        ]
    );
    assert_eq!(correlations[0].sessions.len(), 2);
}

#[test]
fn builds_schema_shaped_correlation_events() {
    let detections = vec![
        detection_event(
            "session-a",
            "2026-05-10T10:00:00Z",
            &[
                "mcp.tool_metadata.prompt_injection",
                "network.controlled_test_domain.darkroast",
            ],
            Some("gpt-5"),
            90,
        ),
        detection_event(
            "session-b",
            "2026-05-10T10:20:00Z",
            &[
                "mcp.tool_metadata.prompt_injection",
                "network.controlled_test_domain.darkroast",
            ],
            Some("gpt-5"),
            95,
        ),
    ];

    let events = correlation_events_from_detections(&detections, &CorrelationConfig::default())
        .expect("correlation events");

    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event_type, "correlation");
    assert_eq!(events[0].client, "codex");
    assert_eq!(events[0].session_id, "correlation");
    assert_eq!(
        events[0].rule_ids,
        vec![
            "mcp.tool_metadata.prompt_injection",
            "network.controlled_test_domain.darkroast",
        ]
    );
    assert_eq!(events[0].categories, vec!["cross_session_correlation"]);
    assert_eq!(events[0].risk_score, 95);
    assert_eq!(
        events[0]
            .evidence
            .iter()
            .filter(|item| item.field == "related_detection")
            .count(),
        2
    );
}
