use super::*;

#[test]
fn activity_event_emits_canonical_contribution_order_and_sum() {
    let z = RiskContribution::new(
        "baseline.z",
        RiskContributionType::BaselineDeviation,
        3,
        "z",
    )
    .expect("contribution");
    let a = RiskContribution::new(
        "baseline.a",
        RiskContributionType::BaselineDeviation,
        4,
        "a",
    )
    .expect("contribution");
    let event = activity_event(ActivityEventInput {
        client: ClientId::Codex,
        agent: None,
        model: None,
        provider: None,
        session_id: "session".to_string(),
        source_path_hash: "hash".to_string(),
        tool_name: Some("shell".to_string()),
        tags: Vec::new(),
        evidence: Vec::new(),
        risk_contributions: vec![z.clone(), a.clone(), z],
        event_time: None,
    })
    .expect("build activity event");

    assert_eq!(event.risk_score, 7);
    assert_eq!(event.risk_contributions.len(), 2);
    assert_eq!(event.risk_contributions[0], a);
    assert_eq!(event.risk_contributions[1].id(), "baseline.z");
}

#[test]
fn risk_accounting_scope_rejects_invalid_types_and_rule_links() {
    let deterministic = RiskContribution::new(
        "rule.detected",
        RiskContributionType::DeterministicRule,
        1,
        "detected",
    )
    .expect("contribution");
    let baseline = RiskContribution::new(
        "baseline.deviation",
        RiskContributionType::BaselineDeviation,
        1,
        "baseline",
    )
    .expect("contribution");

    assert!(matches!(
        validate_risk_accounting_scope("activity", &[], std::slice::from_ref(&deterministic)),
        Err(crate::scoring::RiskAccountingError::ContributionTypeNotAllowed { .. })
    ));
    assert!(matches!(
        validate_risk_accounting_scope("detection", &[], std::slice::from_ref(&baseline)),
        Err(crate::scoring::RiskAccountingError::ContributionTypeNotAllowed { .. })
    ));
    assert!(matches!(
        validate_risk_accounting_scope("detection", &[], std::slice::from_ref(&deterministic)),
        Err(crate::scoring::RiskAccountingError::ContributionRuleIdMissing(id))
            if id == "rule.detected"
    ));
    assert!(
        validate_risk_accounting_scope(
            "detection",
            &["rule.detected".to_string()],
            std::slice::from_ref(&deterministic)
        )
        .is_ok()
    );
    assert!(
        validate_risk_accounting_scope(
            "session_risk_summary",
            &["rule.detected".to_string()],
            &[deterministic]
        )
        .is_ok()
    );
}

#[test]
fn event_builders_enforce_contribution_scope() {
    let invalid_activity = activity_event(ActivityEventInput {
        client: ClientId::Codex,
        agent: None,
        model: None,
        provider: None,
        session_id: "session".to_string(),
        source_path_hash: "hash".to_string(),
        tool_name: None,
        tags: Vec::new(),
        evidence: Vec::new(),
        risk_contributions: vec![
            RiskContribution::new(
                "rule.activity",
                RiskContributionType::DeterministicRule,
                1,
                "invalid",
            )
            .expect("contribution"),
        ],
        event_time: None,
    });
    assert!(invalid_activity.is_err());

    let invalid_detection = detection_event(DetectionEventInput {
        client: ClientId::Codex,
        agent: None,
        model: None,
        provider: None,
        session_id: "session".to_string(),
        source_path_hash: "hash".to_string(),
        tool_name: None,
        rule_ids: vec!["rule".to_string()],
        categories: Vec::new(),
        detection_classes: Vec::new(),
        signal_types: Vec::new(),
        analytic_intents: Vec::new(),
        atlas_tags: Vec::new(),
        tags: Vec::new(),
        evidence: Vec::new(),
        risk_contributions: Vec::new(),
        event_time: None,
    });
    assert!(matches!(
        invalid_detection,
        Err(crate::scoring::RiskAccountingError::InvalidRuleId(id)) if id == "rule"
    ));

    let invalid_summary = session_risk_summary_event(SessionRiskSummaryEventInput {
        client: "codex".to_string(),
        agent: None,
        model: None,
        provider: None,
        session_id: "session".to_string(),
        source_path_hash: None,
        rule_ids: vec!["rule".to_string()],
        categories: Vec::new(),
        detection_classes: Vec::new(),
        signal_types: Vec::new(),
        analytic_intents: Vec::new(),
        atlas_tags: Vec::new(),
        tags: Vec::new(),
        evidence: Vec::new(),
        risk_contributions: Vec::new(),
        event_time: None,
    });
    assert!(matches!(
        invalid_summary,
        Err(crate::scoring::RiskAccountingError::InvalidRuleId(id)) if id == "rule"
    ));

    let invalid_correlation = correlation_event(CorrelationEventInput {
        client: "codex".to_string(),
        agent: None,
        model: None,
        provider: None,
        shared_rule_ids: vec!["rule".to_string()],
        sessions: Vec::new(),
        window_start: "2026-05-01T00:00:00Z".to_string(),
        window_end: "2026-05-01T00:00:00Z".to_string(),
        max_risk_score: 0,
    });
    assert!(matches!(
        invalid_correlation,
        Err(crate::scoring::RiskAccountingError::InvalidRuleId(id)) if id == "rule"
    ));

    let valid_session = session_risk_summary_event(SessionRiskSummaryEventInput {
        client: "codex".to_string(),
        agent: None,
        model: None,
        provider: None,
        session_id: "session".to_string(),
        source_path_hash: None,
        rule_ids: vec!["rule.session".to_string()],
        categories: Vec::new(),
        detection_classes: Vec::new(),
        signal_types: Vec::new(),
        analytic_intents: Vec::new(),
        atlas_tags: Vec::new(),
        tags: Vec::new(),
        evidence: Vec::new(),
        risk_contributions: vec![
            RiskContribution::new(
                "rule.session",
                RiskContributionType::DeterministicRule,
                1,
                "valid",
            )
            .expect("contribution"),
        ],
        event_time: None,
    });
    assert!(valid_session.is_ok());
}

#[test]
fn native_detection_process_and_correlation_inputs_require_dimensions() {
    let invalid_detection = detection_event(DetectionEventInput {
        client: ClientId::Codex,
        agent: None,
        model: None,
        provider: None,
        session_id: "session".to_string(),
        source_path_hash: "hash".to_string(),
        tool_name: None,
        rule_ids: vec!["rule.test".to_string()],
        categories: Vec::new(),
        detection_classes: vec!["security_detection".to_string()],
        signal_types: vec!["atomic".to_string()],
        analytic_intents: vec!["alert".to_string()],
        atlas_tags: Vec::new(),
        tags: vec!["test".to_string()],
        evidence: Vec::new(),
        risk_contributions: Vec::new(),
        event_time: None,
    })
    .expect_err("empty detection categories");
    assert!(matches!(
        invalid_detection,
        crate::scoring::RiskAccountingError::EmptyEventField {
            event_type: "detection",
            field: "categories"
        }
    ));

    let invalid_process = process_chain_event(ProcessChainEventInput {
        client: ClientId::Codex,
        agent: None,
        model: None,
        provider: None,
        session_id: "session".to_string(),
        source_path_hash: "hash".to_string(),
        tool_name: None,
        rule_ids: vec!["rule.test".to_string()],
        categories: vec!["process_chain".to_string()],
        detection_classes: Vec::new(),
        signal_types: vec!["chain".to_string()],
        analytic_intents: vec!["alert".to_string()],
        tags: vec!["test".to_string()],
        evidence: Vec::new(),
        risk_contributions: Vec::new(),
        event_time: None,
        confidence: "low".to_string(),
        detection_reason: "test".to_string(),
        mitre_attack_techniques: Vec::new(),
        risk_entity_type: "session".to_string(),
        risk_entity_value: Some("session".to_string()),
        process: ProcessContext {
            host: None,
            user: None,
            source_process_name: "parent".to_string(),
            source_process_path: None,
            source_process_id: None,
            source_process_command_line: None,
            target_process_name: "child".to_string(),
            target_process_path: None,
            target_process_id: None,
            target_process_command_line: None,
            parent_process_name: None,
            parent_process_path: None,
            source_event_id: None,
            source_process_inferred: true,
            rule_name: "test".to_string(),
            secondary_rule_ids: Vec::new(),
            investigation_fields: Vec::new(),
            falsepositives: Vec::new(),
            dedup_key: "test".to_string(),
            suppression_window_seconds: 0,
            rule_severity: "low".to_string(),
            risk_adjustment: None,
        },
    })
    .expect_err("empty process detection classes");
    assert!(matches!(
        invalid_process,
        crate::scoring::RiskAccountingError::EmptyEventField {
            event_type: "process_chain",
            field: "detection_classes"
        }
    ));

    let invalid_correlation = correlation_event(CorrelationEventInput {
        client: "codex".to_string(),
        agent: None,
        model: None,
        provider: None,
        shared_rule_ids: Vec::new(),
        sessions: vec![CorrelationSessionInput {
            session_id: "one".to_string(),
            event_id: "event-one".to_string(),
            timestamp: "2026-05-01T00:00:00Z".to_string(),
            severity: "high".to_string(),
            risk_score: 70,
        }],
        window_start: "2026-05-01T00:00:00Z".to_string(),
        window_end: "2026-05-01T00:00:00Z".to_string(),
        max_risk_score: 70,
    })
    .expect_err("empty correlation shared IDs");
    assert!(matches!(
        invalid_correlation,
        crate::scoring::RiskAccountingError::EmptyEventField {
            event_type: "correlation",
            field: "shared_rule_ids"
        }
    ));

    let invalid_cardinality = correlation_event(CorrelationEventInput {
        client: "codex".to_string(),
        agent: None,
        model: None,
        provider: None,
        shared_rule_ids: vec!["rule.test".to_string()],
        sessions: vec![CorrelationSessionInput {
            session_id: "one".to_string(),
            event_id: "event-one".to_string(),
            timestamp: "2026-05-01T00:00:00Z".to_string(),
            severity: "high".to_string(),
            risk_score: 70,
        }],
        window_start: "2026-05-01T00:00:00Z".to_string(),
        window_end: "2026-05-01T00:00:00Z".to_string(),
        max_risk_score: 70,
    })
    .expect_err("one-session correlation");
    assert!(matches!(
        invalid_cardinality,
        crate::scoring::RiskAccountingError::InvalidCorrelationCardinality { actual: 1 }
    ));
}
