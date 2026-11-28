use super::*;

#[test]
fn detection_event_scored_90_is_critical_and_keeps_its_source_time() {
    let event = detection_event(DetectionEventInput {
        client: ClientId::Codex,
        agent: None,
        model: None,
        provider: None,
        session_id: "session".to_string(),
        source_path_hash: "hash".to_string(),
        tool_name: None,
        rule_ids: vec!["rule.test".to_string()],
        categories: vec!["category".to_string()],
        detection_classes: vec!["security_detection".to_string()],
        signal_types: vec!["atomic".to_string()],
        analytic_intents: vec!["alert".to_string()],
        atlas_tags: Vec::new(),
        tags: vec!["tag".to_string()],
        evidence: Vec::new(),
        risk_contributions: test_contribution(90),
        event_time: Some("2026-05-01T00:00:00Z".to_string()),
    })
    .expect("build detection event");

    assert_eq!(event.severity, "critical");
    assert_eq!(event.timestamp, "2026-05-01T00:00:00.000Z");
    assert_eq!(
        event.event_time.as_deref(),
        Some("2026-05-01T00:00:00.000Z")
    );
    assert_eq!(event.time_source, "source");
    assert_eq!(event.time_confidence, "high");
}

#[test]
fn detection_event_without_contributions_is_informational() {
    let event = detection_event(DetectionEventInput {
        client: ClientId::Codex,
        agent: None,
        model: None,
        provider: None,
        session_id: "session".to_string(),
        source_path_hash: "hash".to_string(),
        tool_name: None,
        rule_ids: vec!["rule.test".to_string()],
        categories: vec!["category".to_string()],
        detection_classes: vec!["security_detection".to_string()],
        signal_types: vec!["atomic".to_string()],
        analytic_intents: vec!["alert".to_string()],
        atlas_tags: Vec::new(),
        tags: vec!["tag".to_string()],
        evidence: Vec::new(),
        risk_contributions: Vec::new(),
        event_time: Some("2026-05-01T00:00:00Z".to_string()),
    })
    .expect("build detection event");

    assert_eq!(event.severity, "informational");
}

#[test]
fn detection_event_populates_response_metadata() {
    let event = detection_event(DetectionEventInput {
        client: ClientId::Codex,
        agent: None,
        model: None,
        provider: None,
        session_id: "session".to_string(),
        source_path_hash: "hash".to_string(),
        tool_name: None,
        rule_ids: vec!["mcp.tool_metadata.prompt_injection".to_string()],
        categories: vec!["mcp_prompt_injection".to_string()],
        detection_classes: vec!["security_detection".to_string()],
        signal_types: vec!["atomic".to_string()],
        analytic_intents: vec!["alert".to_string()],
        atlas_tags: vec!["atlas:AML.T0051".to_string()],
        tags: vec!["tag".to_string()],
        evidence: Vec::new(),
        risk_contributions: vec![
            RiskContribution::new(
                "mcp.tool_metadata.prompt_injection",
                RiskContributionType::DeterministicRule,
                90,
                "test rationale",
            )
            .expect("contribution"),
        ],
        event_time: Some("2026-05-01T00:00:00Z".to_string()),
    })
    .expect("build detection event");

    let response = event.response.expect("response metadata");
    assert_eq!(response.recommended_action, "investigate_immediately");
    assert_eq!(
        response.response_playbook,
        "telltale-playbook-mcp-prompt-injection"
    );
    assert_eq!(response.escalation, "security_review_required");
    assert!(response.investigation_summary.contains("critical"));
    assert!(
        response
            .investigation_summary
            .contains("mcp.tool_metadata.prompt_injection")
    );
    assert_eq!(event.detection_classes, vec!["security_detection"]);
    assert_eq!(event.signal_types, vec!["atomic"]);
    assert_eq!(event.analytic_intents, vec!["alert"]);
    assert_eq!(event.atlas_tags, vec!["atlas:AML.T0051"]);
}

#[test]
fn event_builder_sanitizes_null_string_tool_name() {
    let event = detection_event(DetectionEventInput {
        client: ClientId::Codex,
        agent: None,
        model: None,
        provider: None,
        session_id: "session".to_string(),
        source_path_hash: "hash".to_string(),
        tool_name: Some("null".to_string()),
        rule_ids: vec!["rule.test".to_string()],
        categories: vec!["category".to_string()],
        detection_classes: vec!["security_detection".to_string()],
        signal_types: vec!["atomic".to_string()],
        analytic_intents: vec!["alert".to_string()],
        atlas_tags: Vec::new(),
        tags: vec!["tag".to_string()],
        evidence: Vec::new(),
        risk_contributions: Vec::new(),
        event_time: Some("2026-05-01T00:00:00Z".to_string()),
    })
    .expect("build detection event");

    assert_eq!(event.tool_name, None);
}

#[test]
fn detection_event_falls_back_to_observed_time_for_future_source_timestamp() {
    let event = detection_event(DetectionEventInput {
        client: ClientId::Codex,
        agent: None,
        model: None,
        provider: None,
        session_id: "session".to_string(),
        source_path_hash: "hash".to_string(),
        tool_name: None,
        rule_ids: vec!["rule.test".to_string()],
        categories: vec!["category".to_string()],
        detection_classes: vec!["security_detection".to_string()],
        signal_types: vec!["atomic".to_string()],
        analytic_intents: vec!["alert".to_string()],
        atlas_tags: Vec::new(),
        tags: vec!["tag".to_string()],
        evidence: Vec::new(),
        risk_contributions: Vec::new(),
        event_time: Some("2999-01-01T00:00:00Z".to_string()),
    })
    .expect("build detection event");

    assert_eq!(event.time_source, "override");
    assert_eq!(event.time_confidence, "low");
    assert_eq!(
        event.time_override_reason.as_deref(),
        Some("source_timestamp_future_skew")
    );
    assert_eq!(
        event.event_time.as_deref(),
        Some("2999-01-01T00:00:00.000Z")
    );
    assert_eq!(event.timestamp, event.observed_at);
    assert_eq!(event.ingested_at, event.observed_at);
}

#[test]
fn detection_event_falls_back_to_observed_time_for_missing_source_timestamp() {
    let event = detection_event(DetectionEventInput {
        client: ClientId::Codex,
        agent: None,
        model: None,
        provider: None,
        session_id: "session".to_string(),
        source_path_hash: "hash".to_string(),
        tool_name: None,
        rule_ids: vec!["rule.test".to_string()],
        categories: vec!["category".to_string()],
        detection_classes: vec!["security_detection".to_string()],
        signal_types: vec!["atomic".to_string()],
        analytic_intents: vec!["alert".to_string()],
        atlas_tags: Vec::new(),
        tags: vec!["tag".to_string()],
        evidence: Vec::new(),
        risk_contributions: Vec::new(),
        event_time: None,
    })
    .expect("build detection event");

    assert_eq!(event.time_source, "observed");
    assert_eq!(event.time_confidence, "low");
    assert_eq!(
        event.time_override_reason.as_deref(),
        Some("missing_source_timestamp")
    );
    assert_eq!(event.event_time, None);
    assert_eq!(event.timestamp, event.observed_at);
    assert_eq!(event.ingested_at, event.observed_at);
}

#[test]
fn detection_event_normalizes_non_utc_source_timestamp() {
    let event = detection_event(DetectionEventInput {
        client: ClientId::Codex,
        agent: None,
        model: None,
        provider: None,
        session_id: "session".to_string(),
        source_path_hash: "hash".to_string(),
        tool_name: None,
        rule_ids: vec!["rule.test".to_string()],
        categories: vec!["category".to_string()],
        detection_classes: vec!["security_detection".to_string()],
        signal_types: vec!["atomic".to_string()],
        analytic_intents: vec!["alert".to_string()],
        atlas_tags: Vec::new(),
        tags: vec!["tag".to_string()],
        evidence: Vec::new(),
        risk_contributions: Vec::new(),
        event_time: Some("2026-05-01T12:00:00+02:00".to_string()),
    })
    .expect("build detection event");

    assert_eq!(event.time_source, "source");
    assert_eq!(event.time_confidence, "high");
    assert_eq!(event.time_override_reason, None);
    assert_eq!(
        event.event_time.as_deref(),
        Some("2026-05-01T10:00:00.000Z")
    );
    assert_eq!(event.timestamp, "2026-05-01T10:00:00.000Z");
}
