use super::*;

#[test]
fn serialized_privacy_corpus_covers_all_current_event_families() {
    use crate::clients::SourceKind;
    use crate::source::Source;
    use std::path::PathBuf;

    let marker = "TT_PRIVACY_EVENT_25";
    let raw_evidence = format!("API_KEY=\"{marker}\"; command=inspect");
    let evidence = Evidence {
        field: "arguments".to_string(),
        redacted_value: raw_evidence.clone(),
        hash: Some(evidence_hash(&raw_evidence)),
        rule_id: Some("rule.privacy".to_string()),
    };
    let detection = detection_event(DetectionEventInput {
        client: ClientId::Codex,
        agent: Some(marker.to_string()),
        model: Some(marker.to_string()),
        provider: Some(marker.to_string()),
        session_id: "opaque-session".to_string(),
        source_path_hash: "source-hash".to_string(),
        tool_name: Some(marker.to_string()),
        rule_ids: vec!["rule.privacy".to_string()],
        categories: vec!["privacy".to_string()],
        detection_classes: vec!["security_detection".to_string()],
        signal_types: vec!["atomic".to_string()],
        analytic_intents: vec!["alert".to_string()],
        atlas_tags: Vec::new(),
        tags: vec![marker.to_string()],
        evidence: vec![evidence],
        risk_contributions: Vec::new(),
        event_time: None,
    })
    .expect("detection event");
    assert_eq!(detection.agent.as_deref(), Some(marker));
    assert_eq!(detection.model.as_deref(), Some(marker));
    assert_eq!(detection.provider.as_deref(), Some(marker));
    assert_eq!(detection.tool_name.as_deref(), Some(marker));
    assert_eq!(
        detection.evidence[0].hash.as_deref(),
        Some(evidence_hash(&raw_evidence).as_str())
    );
    assert!(detection.evidence[0].redacted_value.contains("API_KEY"));

    let activity = activity_event(ActivityEventInput {
        client: ClientId::Codex,
        agent: None,
        model: None,
        provider: None,
        session_id: "opaque-session".to_string(),
        source_path_hash: "source-hash".to_string(),
        tool_name: Some("shell".to_string()),
        tags: Vec::new(),
        evidence: vec![Evidence {
            field: "tool_result".to_string(),
            redacted_value: format!("token: {marker}; result=ok"),
            hash: None,
            rule_id: None,
        }],
        risk_contributions: Vec::new(),
        event_time: None,
    })
    .expect("activity event");

    let source_path = PathBuf::from(format!("/home/{marker}/.local/state/session.db"));
    let source = Source {
        client: ClientId::OpenCode,
        kind: SourceKind::Sqlite,
        source_id: "fixture.source".to_string(),
        path: source_path.clone(),
    };
    let health = health_event_with_metadata(HealthEventInput {
        sources: std::slice::from_ref(&source),
        source_inventory_change: None,
        scan_duration_ms: 1,
        rule_count: 1,
        threshold_config: crate::scoring::load_thresholds(),
        active_policy_name: Some(marker),
        emitted_count: 0,
        suppressed_count: 0,
        scanner_error_count: 0,
    });
    let mut scanner_error = scanner_error_event(
        &source,
        &format!(
            "parse failed at /home/{marker}/.config/state.db using https://user:{marker}@example.invalid/?token={marker}"
        ),
    );
    scanner_error.evidence.push(Evidence {
        field: "error".to_string(),
        redacted_value: format!("TOKEN={marker}"),
        hash: None,
        rule_id: None,
    });
    assert_eq!(
        scanner_error.source_path_hash.as_deref(),
        Some(path_hash(&source_path).as_str())
    );

    let operational = operational_alert_event(OperationalAlertInput {
        alert_type: "sink_delivery_failure".to_string(),
        threshold: "attempts_made=1".to_string(),
        actual_value: format!("error=https://user:{marker}@example.invalid/?SECRET={marker}"),
        scan_duration_ms: None,
        scanner_error_count: None,
    });

    let session_summary = session_risk_summary_event(SessionRiskSummaryEventInput {
        client: "codex".to_string(),
        agent: None,
        model: None,
        provider: None,
        session_id: "opaque-session".to_string(),
        source_path_hash: Some("source-hash".to_string()),
        rule_ids: vec!["rule.privacy".to_string()],
        categories: vec!["privacy".to_string()],
        detection_classes: vec!["security_detection".to_string()],
        signal_types: vec!["atomic".to_string()],
        analytic_intents: vec!["alert".to_string()],
        atlas_tags: Vec::new(),
        tags: Vec::new(),
        evidence: vec![Evidence {
            field: "session_summary".to_string(),
            redacted_value: format!("password: {marker}"),
            hash: None,
            rule_id: None,
        }],
        risk_contributions: Vec::new(),
        event_time: None,
    })
    .expect("session summary event");

    let correlation = correlation_event(CorrelationEventInput {
        client: "codex".to_string(),
        agent: None,
        model: None,
        provider: None,
        shared_rule_ids: vec!["rule.privacy".to_string()],
        sessions: vec![
            CorrelationSessionInput {
                session_id: format!("TOKEN={marker}"),
                event_id: "opaque-event-a".to_string(),
                timestamp: "2026-05-01T00:00:00Z".to_string(),
                severity: "informational".to_string(),
                risk_score: 0,
            },
            CorrelationSessionInput {
                session_id: "opaque-session-b".to_string(),
                event_id: "opaque-event-b".to_string(),
                timestamp: "2026-05-01T00:01:00Z".to_string(),
                severity: "informational".to_string(),
                risk_score: 0,
            },
        ],
        window_start: "2026-05-01T00:00:00Z".to_string(),
        window_end: "2026-05-01T00:01:00Z".to_string(),
        max_risk_score: 0,
    })
    .expect("correlation event");
    assert!(
        correlation
            .evidence
            .iter()
            .any(|item| item.field == "related_detection")
    );

    let process_chain = process_chain_event(ProcessChainEventInput {
        client: ClientId::Codex,
        agent: None,
        model: None,
        provider: None,
        session_id: "opaque-session".to_string(),
        source_path_hash: "source-hash".to_string(),
        tool_name: Some("shell".to_string()),
        rule_ids: vec!["rule.privacy".to_string()],
        categories: vec!["privacy".to_string()],
        detection_classes: vec!["security_detection".to_string()],
        signal_types: vec!["chain".to_string()],
        analytic_intents: vec!["alert".to_string()],
        tags: Vec::new(),
        evidence: vec![Evidence {
            field: "command".to_string(),
            redacted_value: format!("export TOKEN={marker}"),
            hash: None,
            rule_id: Some("rule.privacy".to_string()),
        }],
        risk_contributions: Vec::new(),
        event_time: None,
        confidence: "low".to_string(),
        detection_reason: "privacy fixture".to_string(),
        mitre_attack_techniques: Vec::new(),
        risk_entity_type: "host".to_string(),
        risk_entity_value: Some(marker.to_string()),
        process: ProcessContext {
            host: Some(marker.to_string()),
            user: Some(marker.to_string()),
            source_process_name: "shell".to_string(),
            source_process_path: Some(format!("C:\\Users\\{marker}\\.ssh\\id_ed25519")),
            source_process_id: Some(1),
            source_process_command_line: Some(format!("TOKEN={marker} run")),
            target_process_name: "curl".to_string(),
            target_process_path: None,
            target_process_id: Some(2),
            target_process_command_line: None,
            parent_process_name: None,
            parent_process_path: None,
            source_event_id: Some("opaque-source-event".to_string()),
            source_process_inferred: false,
            rule_name: "privacy fixture".to_string(),
            secondary_rule_ids: Vec::new(),
            investigation_fields: Vec::new(),
            falsepositives: Vec::new(),
            dedup_key: marker.to_string(),
            suppression_window_seconds: 0,
            rule_severity: "low".to_string(),
            risk_adjustment: None,
        },
    })
    .expect("process chain event");
    let process = process_chain.process.as_ref().expect("raw process context");
    assert_eq!(process.host.as_deref(), Some(marker));
    assert_eq!(process.user.as_deref(), Some(marker));
    assert_eq!(process.dedup_key, marker);
    assert_eq!(process_chain.risk_entity_value.as_deref(), Some(marker));
    assert!(
        process
            .source_process_command_line
            .as_deref()
            .is_some_and(|line| line.contains(marker))
    );

    let install_inventory = install_inventory_event(vec![Evidence {
        field: "install_inventory".to_string(),
        redacted_value: format!("credential={marker}"),
        hash: None,
        rule_id: None,
    }])
    .expect("install inventory event");

    let markers = [ControlledMarker {
        id: "event-marker",
        value: marker,
    }];
    let events = [
        ("detection", detection),
        ("activity_standard", activity),
        ("health", health),
        ("scanner_error", scanner_error),
        ("operational_alert", operational),
        ("session_risk_summary", session_summary),
        ("correlation", correlation),
        ("process_chain", process_chain),
        ("install_inventory_activity", install_inventory),
    ];
    let covered_families = events
        .iter()
        .map(|(family, _)| *family)
        .collect::<std::collections::BTreeSet<_>>();
    let expected_families = NATIVE_EVENT_CONSTRUCTOR_FAMILIES
        .iter()
        .map(|family| family.name)
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(covered_families, expected_families);
    let covered_event_types = events
        .iter()
        .map(|(_, event)| event.event_type.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    let expected_event_types = NATIVE_EVENT_CONSTRUCTOR_FAMILIES
        .iter()
        .map(|family| family.event_type)
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        super::super::TEXT_BEARING_EVENT_TYPES
            .iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>(),
        expected_event_types,
        "wire event-type inventory must track the constructor registry"
    );
    assert_eq!(covered_event_types, expected_event_types);
    for (family_name, event) in events {
        let family = NATIVE_EVENT_CONSTRUCTOR_FAMILIES
            .iter()
            .find(|family| family.name == family_name)
            .unwrap_or_else(|| panic!("privacy corpus family {family_name} is not registered"));
        assert_eq!(
            event.event_type, family.event_type,
            "privacy corpus family {family_name} has the wrong wire event type"
        );
        let case_id = family_name;
        assert!(
            raw_event_contains_marker(&event, marker),
            "privacy corpus case {case_id} must exercise a raw controlled marker"
        );
        let bytes = serde_json::to_vec(&event.emittable()).expect("serialize event");
        assert_eq!(
            serde_json::to_vec(&event.emittable()).expect("serialize event again"),
            bytes,
            "terminal serialization must be route-independent"
        );
        assert!(
            check_serialized_event_markers(&bytes, case_id, &markers).is_ok(),
            "privacy marker remained in {case_id}"
        );
        let mut historical = serde_json::to_value(&event).expect("serialize raw event value");
        sanitize_serialized_event(&mut historical);
        let historical_bytes =
            serde_json::to_vec(&historical).expect("serialize sanitized historical event");
        assert!(
            check_serialized_event_markers(&historical_bytes, case_id, &markers).is_ok(),
            "privacy marker remained in historical {case_id}"
        );
        if case_id == "process_chain" {
            let emitted: serde_json::Value =
                serde_json::from_slice(&bytes).expect("emittable process event");
            assert_eq!(
                emitted["risk_entity_value"], emitted["process"]["host"],
                "host risk entities must use the process host representation"
            );
            assert_eq!(
                emitted["process"]["host"],
                format!("[host:{}]", evidence_hash(marker)),
                "host identities must be hashed exactly once"
            );
        }
    }
}

#[test]
fn direct_event_serialization_sanitizes_raw_text_and_preserves_fields() {
    let event_time_marker = "tt_privacy_terminal_event_time_25";
    let source_hash_marker = "TT_PRIVACY_TERMINAL_SOURCE_HASH_30";
    let mitre_marker = "TT_PRIVACY_TERMINAL_MITRE_30";
    let agent_marker = "tt_privacy_terminal_agent_25";
    let model_marker = "tt_privacy_terminal_model_25";
    let provider_marker = "tt_privacy_terminal_provider_25";
    let response_marker = "tt_privacy_terminal_response_25";
    let rationale_marker = "tt_privacy_terminal_rationale_25";
    let rule_name_marker = "tt_privacy_terminal_rule_name_25";
    let investigation_marker = "tt_privacy_terminal_investigation_25";
    let falsepositive_marker = "tt_privacy_terminal_falsepositive_25";
    let adjustment_marker = "tt_privacy_terminal_adjustment_25";
    let policy_marker = "tt_privacy_terminal_policy_25";
    let contribution = RiskContribution::new(
        "rule.privacy",
        RiskContributionType::DeterministicRule,
        1,
        format!("TOKEN={rationale_marker}"),
    )
    .expect("synthetic contribution");
    let mut event = process_chain_event(ProcessChainEventInput {
        client: ClientId::Codex,
        agent: Some(agent_marker.to_string()),
        model: Some(model_marker.to_string()),
        provider: Some(provider_marker.to_string()),
        session_id: "opaque-session".to_string(),
        source_path_hash: source_hash_marker.to_string(),
        tool_name: Some("shell".to_string()),
        rule_ids: vec!["rule.privacy".to_string()],
        categories: vec!["privacy".to_string()],
        detection_classes: vec!["security_detection".to_string()],
        signal_types: vec!["chain".to_string()],
        analytic_intents: vec!["alert".to_string()],
        tags: Vec::new(),
        evidence: Vec::new(),
        risk_contributions: vec![contribution],
        event_time: Some(event_time_marker.to_string()),
        confidence: "low".to_string(),
        detection_reason: "privacy fixture".to_string(),
        mitre_attack_techniques: vec![mitre_marker.to_string(), "T1059.001".to_string()],
        risk_entity_type: "session".to_string(),
        risk_entity_value: Some("opaque-session".to_string()),
        process: ProcessContext {
            host: None,
            user: None,
            source_process_name: "shell".to_string(),
            source_process_path: None,
            source_process_id: None,
            source_process_command_line: None,
            target_process_name: "curl".to_string(),
            target_process_path: None,
            target_process_id: None,
            target_process_command_line: None,
            parent_process_name: None,
            parent_process_path: None,
            source_event_id: Some("source-event".to_string()),
            source_process_inferred: false,
            rule_name: rule_name_marker.to_string(),
            secondary_rule_ids: Vec::new(),
            investigation_fields: vec![investigation_marker.to_string()],
            falsepositives: vec![falsepositive_marker.to_string()],
            dedup_key: "dedup".to_string(),
            suppression_window_seconds: 0,
            rule_severity: "low".to_string(),
            risk_adjustment: Some(adjustment_marker.to_string()),
        },
    })
    .expect("process event");
    event
        .response
        .as_mut()
        .expect("process event response")
        .recommended_action = "investigate_immediately".to_string();
    let response = event.response.as_mut().expect("process event response");
    response.response_playbook = "telltale-playbook-credential-access".to_string();
    response.investigation_summary = format!("TOKEN={response_marker}");
    response.escalation = "security_review_required".to_string();

    // Source-derived actor values remain available to in-process matching
    // and correlation; only terminal bytes become opaque.
    assert!(
        event
            .agent
            .as_deref()
            .is_some_and(|value| value == agent_marker)
    );
    assert!(
        event
            .model
            .as_deref()
            .is_some_and(|value| value == model_marker)
    );
    assert!(
        event
            .provider
            .as_deref()
            .is_some_and(|value| value == provider_marker)
    );

    let markers = [
        ControlledMarker {
            id: "event-time",
            value: event_time_marker,
        },
        ControlledMarker {
            id: "source-hash",
            value: source_hash_marker,
        },
        ControlledMarker {
            id: "mitre-technique",
            value: mitre_marker,
        },
        ControlledMarker {
            id: "agent",
            value: agent_marker,
        },
        ControlledMarker {
            id: "model",
            value: model_marker,
        },
        ControlledMarker {
            id: "provider",
            value: provider_marker,
        },
        ControlledMarker {
            id: "response",
            value: response_marker,
        },
        ControlledMarker {
            id: "rationale",
            value: rationale_marker,
        },
        ControlledMarker {
            id: "rule-name",
            value: rule_name_marker,
        },
        ControlledMarker {
            id: "investigation",
            value: investigation_marker,
        },
        ControlledMarker {
            id: "falsepositive",
            value: falsepositive_marker,
        },
        ControlledMarker {
            id: "adjustment",
            value: adjustment_marker,
        },
        ControlledMarker {
            id: "policy",
            value: policy_marker,
        },
    ];
    let direct_bytes = serde_json::to_vec(&event).expect("direct event serialization");
    let emittable_bytes =
        serde_json::to_vec(&event.emittable()).expect("emittable event serialization");
    assert_eq!(direct_bytes, emittable_bytes);
    assert_eq!(
        serde_json::to_vec(&event).expect("repeat direct event serialization"),
        direct_bytes,
        "terminal serialization must be deterministic and idempotent"
    );
    assert!(check_serialized_event_markers(&direct_bytes, "terminal-event", &markers).is_ok());
    let emitted: serde_json::Value =
        serde_json::from_slice(&direct_bytes).expect("directly serialized event");
    let emittable = emitted.clone();
    assert_eq!(
        emitted["source_path_hash"],
        evidence_hash(source_hash_marker),
        "source path hashes must preserve only canonical digest values"
    );
    assert_eq!(
        emitted["mitre_attack_techniques"][0],
        format!("mitre:{}", evidence_hash(mitre_marker)),
        "unsafe technique values must use a deterministic opaque fallback"
    );
    assert_eq!(
        emitted["mitre_attack_techniques"][1], "T1059.001",
        "canonical ATT&CK technique values remain readable"
    );
    let mut canonical_hash_event = event.clone();
    let canonical_source_hash = "a".repeat(64);
    canonical_hash_event.source_path_hash = Some(canonical_source_hash.clone());
    let canonical_emitted = serde_json::to_value(canonical_hash_event.emittable())
        .expect("canonical source hash event");
    assert_eq!(canonical_emitted["source_path_hash"], canonical_source_hash);
    assert_eq!(event.agent.as_deref(), Some(agent_marker));
    assert_eq!(
        event
            .response
            .as_ref()
            .expect("raw response metadata")
            .recommended_action,
        "investigate_immediately"
    );
    assert_eq!(
        event
            .process
            .as_ref()
            .expect("raw process context")
            .rule_name,
        rule_name_marker
    );
    assert_eq!(
        emittable["risk_contributions"][0]["rationale"], "TOKEN redacted-secret",
        "terminal rationale remains useful rather than becoming an opaque marker"
    );
    assert_eq!(
        emittable["process"]["source_event_id"],
        format!("[source-event:{}]", evidence_hash("source-event"))
    );
    assert_eq!(
        emittable["process"]["dedup_key"],
        format!("[dedup:{}]", evidence_hash("dedup"))
    );
    let raw = serde_json::to_value(&event).expect("direct event");
    assert_eq!(
        raw.as_object().expect("raw object").len(),
        emittable.as_object().expect("emittable object").len(),
        "terminal sanitization must not change Event 3.0 shape"
    );

    let mut historical = raw;
    sanitize_serialized_event(&mut historical);
    let historical_bytes = serde_json::to_vec(&historical).expect("historical bytes");
    assert!(
        check_serialized_event_markers(&historical_bytes, "historical-event", &markers).is_ok()
    );

    let health = health_event_with_metadata(HealthEventInput {
        sources: &[],
        source_inventory_change: None,
        scan_duration_ms: 1,
        rule_count: 1,
        threshold_config: crate::scoring::load_thresholds(),
        active_policy_name: Some(policy_marker),
        emitted_count: 0,
        suppressed_count: 0,
        scanner_error_count: 0,
    });
    let health_bytes = serde_json::to_vec(&health.emittable()).expect("emittable health");
    assert!(check_serialized_event_markers(&health_bytes, "terminal-health", &markers).is_ok());

    let mut valid_time = event.clone();
    valid_time.event_time = Some("2026-05-01T12:00:00+02:00".to_string());
    let valid_emitted = serde_json::to_value(valid_time.emittable()).expect("valid time event");
    assert_eq!(
        valid_emitted["event_time"], "2026-05-01T12:00:00+02:00",
        "valid RFC3339 event_time values are terminally unchanged"
    );
}
