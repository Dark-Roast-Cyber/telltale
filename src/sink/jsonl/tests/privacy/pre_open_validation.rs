use super::*;

#[test]
fn canonical_jsonl_rejects_invalid_controlled_fields_before_opening_file() {
    let marker = |field: &str| format!("TT_PRIVACY_JSONL_CONTROLLED_{field}_31");
    let mut cases = Vec::new();

    let mut event = health_event_with_metadata(HealthEventInput {
        sources: &[],
        source_inventory_change: None,
        scan_duration_ms: 0,
        rule_count: 0,
        threshold_config: telltale_schema::scoring::load_thresholds(),
        active_policy_name: None,
        emitted_count: 0,
        suppressed_count: 0,
        scanner_error_count: 0,
    });
    event.time_source = marker("time_source");
    cases.push(("time_source", marker("time_source"), event));

    let mut event = health_event_with_metadata(HealthEventInput {
        sources: &[],
        source_inventory_change: None,
        scan_duration_ms: 0,
        rule_count: 0,
        threshold_config: telltale_schema::scoring::load_thresholds(),
        active_policy_name: None,
        emitted_count: 0,
        suppressed_count: 0,
        scanner_error_count: 0,
    });
    event.time_confidence = marker("time_confidence");
    cases.push(("time_confidence", marker("time_confidence"), event));

    let mut event = health_event_with_metadata(HealthEventInput {
        sources: &[],
        source_inventory_change: None,
        scan_duration_ms: 0,
        rule_count: 0,
        threshold_config: telltale_schema::scoring::load_thresholds(),
        active_policy_name: None,
        emitted_count: 0,
        suppressed_count: 0,
        scanner_error_count: 0,
    });
    event.event_type = marker("event_type");
    cases.push(("event_type", marker("event_type"), event));

    let mut event = health_event_with_metadata(HealthEventInput {
        sources: &[],
        source_inventory_change: None,
        scan_duration_ms: 0,
        rule_count: 0,
        threshold_config: telltale_schema::scoring::load_thresholds(),
        active_policy_name: None,
        emitted_count: 0,
        suppressed_count: 0,
        scanner_error_count: 0,
    });
    event.severity = marker("severity");
    cases.push(("severity", marker("severity"), event));

    let mut event = health_event_with_metadata(HealthEventInput {
        sources: &[],
        source_inventory_change: None,
        scan_duration_ms: 0,
        rule_count: 0,
        threshold_config: telltale_schema::scoring::load_thresholds(),
        active_policy_name: None,
        emitted_count: 0,
        suppressed_count: 0,
        scanner_error_count: 0,
    });
    event.schema_version = marker("schema_version");
    cases.push(("schema_version", marker("schema_version"), event));

    let mut event = health_event_with_metadata(HealthEventInput {
        sources: &[],
        source_inventory_change: None,
        scan_duration_ms: 0,
        rule_count: 0,
        threshold_config: telltale_schema::scoring::load_thresholds(),
        active_policy_name: None,
        emitted_count: 0,
        suppressed_count: 0,
        scanner_error_count: 0,
    });
    event.detection_classes = vec![marker("detection_classes")];
    cases.push(("detection_classes", marker("detection_classes"), event));

    let mut event = health_event_with_metadata(HealthEventInput {
        sources: &[],
        source_inventory_change: None,
        scan_duration_ms: 0,
        rule_count: 0,
        threshold_config: telltale_schema::scoring::load_thresholds(),
        active_policy_name: None,
        emitted_count: 0,
        suppressed_count: 0,
        scanner_error_count: 0,
    });
    event.signal_types = vec![marker("signal_types")];
    cases.push(("signal_types", marker("signal_types"), event));

    let mut event = health_event_with_metadata(HealthEventInput {
        sources: &[],
        source_inventory_change: None,
        scan_duration_ms: 0,
        rule_count: 0,
        threshold_config: telltale_schema::scoring::load_thresholds(),
        active_policy_name: None,
        emitted_count: 0,
        suppressed_count: 0,
        scanner_error_count: 0,
    });
    event.analytic_intents = vec![marker("analytic_intents")];
    cases.push(("analytic_intents", marker("analytic_intents"), event));

    let mut event = correlation_event(CorrelationEventInput {
        client: "codex".to_string(),
        agent: None,
        model: None,
        provider: None,
        shared_rule_ids: vec!["rule.synthetic".to_string()],
        sessions: vec![
            CorrelationSessionInput {
                session_id: "jsonl-session-a".to_string(),
                event_id: "jsonl-event-a".to_string(),
                timestamp: "2026-05-01T00:00:00Z".to_string(),
                severity: "low".to_string(),
                risk_score: 1,
            },
            CorrelationSessionInput {
                session_id: "jsonl-session-b".to_string(),
                event_id: "jsonl-event-b".to_string(),
                timestamp: "2026-05-01T00:01:00Z".to_string(),
                severity: "low".to_string(),
                risk_score: 2,
            },
        ],
        window_start: "2026-05-01T00:00:00Z".to_string(),
        window_end: "2026-05-01T00:01:00Z".to_string(),
        max_risk_score: 2,
    })
    .expect("controlled correlation event");
    event.categories = vec![marker("correlation_category")];
    cases.push((
        "correlation.categories",
        marker("correlation_category"),
        event,
    ));

    let mut process_event = process_chain_event(ProcessChainEventInput {
        client: telltale_schema::clients::ClientId::Codex,
        agent: None,
        model: None,
        provider: None,
        session_id: "jsonl-controlled-process".to_string(),
        source_path_hash: "jsonl-controlled-source".to_string(),
        tool_name: Some("shell".to_string()),
        rule_ids: vec!["rule.synthetic".to_string()],
        categories: vec!["execution".to_string()],
        detection_classes: vec!["security_detection".to_string()],
        signal_types: vec!["chain".to_string()],
        analytic_intents: vec!["alert".to_string()],
        tags: Vec::new(),
        evidence: Vec::new(),
        risk_contributions: Vec::new(),
        event_time: None,
        confidence: "low".to_string(),
        detection_reason: "synthetic JSONL controlled-field fixture".to_string(),
        mitre_attack_techniques: Vec::new(),
        risk_entity_type: "session".to_string(),
        risk_entity_value: Some("jsonl-controlled-process".to_string()),
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
            source_event_id: None,
            source_process_inferred: false,
            rule_name: "synthetic".to_string(),
            secondary_rule_ids: Vec::new(),
            investigation_fields: Vec::new(),
            falsepositives: Vec::new(),
            dedup_key: "jsonl-controlled-process".to_string(),
            suppression_window_seconds: 0,
            rule_severity: "low".to_string(),
            risk_adjustment: None,
        },
    })
    .expect("controlled process event");
    process_event.confidence = Some(marker("confidence"));
    cases.push(("confidence", marker("confidence"), process_event));

    let mut process_event = process_chain_event(ProcessChainEventInput {
        client: telltale_schema::clients::ClientId::Codex,
        agent: None,
        model: None,
        provider: None,
        session_id: "jsonl-controlled-risk".to_string(),
        source_path_hash: "jsonl-controlled-risk-source".to_string(),
        tool_name: Some("shell".to_string()),
        rule_ids: vec!["rule.synthetic".to_string()],
        categories: vec!["execution".to_string()],
        detection_classes: vec!["security_detection".to_string()],
        signal_types: vec!["chain".to_string()],
        analytic_intents: vec!["alert".to_string()],
        tags: Vec::new(),
        evidence: Vec::new(),
        risk_contributions: Vec::new(),
        event_time: None,
        confidence: "low".to_string(),
        detection_reason: "synthetic JSONL controlled-field fixture".to_string(),
        mitre_attack_techniques: Vec::new(),
        risk_entity_type: "session".to_string(),
        risk_entity_value: Some("jsonl-controlled-risk".to_string()),
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
            source_event_id: None,
            source_process_inferred: false,
            rule_name: "synthetic".to_string(),
            secondary_rule_ids: Vec::new(),
            investigation_fields: Vec::new(),
            falsepositives: Vec::new(),
            dedup_key: "jsonl-controlled-risk".to_string(),
            suppression_window_seconds: 0,
            rule_severity: "low".to_string(),
            risk_adjustment: None,
        },
    })
    .expect("controlled process event");
    process_event.risk_entity_type = Some(marker("risk_entity_type"));
    cases.push((
        "risk_entity_type",
        marker("risk_entity_type"),
        process_event,
    ));

    let mut process_event = process_chain_event(ProcessChainEventInput {
        client: telltale_schema::clients::ClientId::Codex,
        agent: None,
        model: None,
        provider: None,
        session_id: "jsonl-controlled-rule".to_string(),
        source_path_hash: "jsonl-controlled-rule-source".to_string(),
        tool_name: Some("shell".to_string()),
        rule_ids: vec!["rule.synthetic".to_string()],
        categories: vec!["execution".to_string()],
        detection_classes: vec!["security_detection".to_string()],
        signal_types: vec!["chain".to_string()],
        analytic_intents: vec!["alert".to_string()],
        tags: Vec::new(),
        evidence: Vec::new(),
        risk_contributions: Vec::new(),
        event_time: None,
        confidence: "low".to_string(),
        detection_reason: "synthetic JSONL controlled-field fixture".to_string(),
        mitre_attack_techniques: Vec::new(),
        risk_entity_type: "session".to_string(),
        risk_entity_value: Some("jsonl-controlled-rule".to_string()),
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
            source_event_id: None,
            source_process_inferred: false,
            rule_name: "synthetic".to_string(),
            secondary_rule_ids: Vec::new(),
            investigation_fields: Vec::new(),
            falsepositives: Vec::new(),
            dedup_key: "jsonl-controlled-rule".to_string(),
            suppression_window_seconds: 0,
            rule_severity: "low".to_string(),
            risk_adjustment: None,
        },
    })
    .expect("controlled process event");
    process_event
        .process
        .as_mut()
        .expect("process context")
        .rule_severity = marker("rule_severity");
    cases.push((
        "process.rule_severity",
        marker("rule_severity"),
        process_event,
    ));

    let mut process_event = process_chain_event(ProcessChainEventInput {
        client: telltale_schema::clients::ClientId::Codex,
        agent: None,
        model: None,
        provider: None,
        session_id: "jsonl-controlled-response".to_string(),
        source_path_hash: "jsonl-controlled-response-source".to_string(),
        tool_name: Some("shell".to_string()),
        rule_ids: vec!["rule.synthetic".to_string()],
        categories: vec!["execution".to_string()],
        detection_classes: vec!["security_detection".to_string()],
        signal_types: vec!["chain".to_string()],
        analytic_intents: vec!["alert".to_string()],
        tags: Vec::new(),
        evidence: Vec::new(),
        risk_contributions: Vec::new(),
        event_time: None,
        confidence: "low".to_string(),
        detection_reason: "synthetic JSONL controlled-field fixture".to_string(),
        mitre_attack_techniques: Vec::new(),
        risk_entity_type: "session".to_string(),
        risk_entity_value: Some("jsonl-controlled-response".to_string()),
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
            source_event_id: None,
            source_process_inferred: false,
            rule_name: "synthetic".to_string(),
            secondary_rule_ids: Vec::new(),
            investigation_fields: Vec::new(),
            falsepositives: Vec::new(),
            dedup_key: "jsonl-controlled-response".to_string(),
            suppression_window_seconds: 0,
            rule_severity: "low".to_string(),
            risk_adjustment: None,
        },
    })
    .expect("controlled process event");
    process_event
        .response
        .as_mut()
        .expect("process response")
        .recommended_action = marker("recommended_action");
    cases.push((
        "response.recommended_action",
        marker("recommended_action"),
        process_event,
    ));

    let mut process_event = process_chain_event(ProcessChainEventInput {
        client: telltale_schema::clients::ClientId::Codex,
        agent: None,
        model: None,
        provider: None,
        session_id: "jsonl-controlled-escalation".to_string(),
        source_path_hash: "jsonl-controlled-escalation-source".to_string(),
        tool_name: Some("shell".to_string()),
        rule_ids: vec!["rule.synthetic".to_string()],
        categories: vec!["execution".to_string()],
        detection_classes: vec!["security_detection".to_string()],
        signal_types: vec!["chain".to_string()],
        analytic_intents: vec!["alert".to_string()],
        tags: Vec::new(),
        evidence: Vec::new(),
        risk_contributions: Vec::new(),
        event_time: None,
        confidence: "low".to_string(),
        detection_reason: "synthetic JSONL controlled-field fixture".to_string(),
        mitre_attack_techniques: Vec::new(),
        risk_entity_type: "session".to_string(),
        risk_entity_value: Some("jsonl-controlled-escalation".to_string()),
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
            source_event_id: None,
            source_process_inferred: false,
            rule_name: "synthetic".to_string(),
            secondary_rule_ids: Vec::new(),
            investigation_fields: Vec::new(),
            falsepositives: Vec::new(),
            dedup_key: "jsonl-controlled-escalation".to_string(),
            suppression_window_seconds: 0,
            rule_severity: "low".to_string(),
            risk_adjustment: None,
        },
    })
    .expect("controlled process event");
    process_event
        .response
        .as_mut()
        .expect("process response")
        .escalation = marker("escalation");
    cases.push(("response.escalation", marker("escalation"), process_event));

    let mut event = health_event_with_metadata(HealthEventInput {
        sources: &[],
        source_inventory_change: None,
        scan_duration_ms: 0,
        rule_count: 0,
        threshold_config: telltale_schema::scoring::load_thresholds(),
        active_policy_name: None,
        emitted_count: 0,
        suppressed_count: 0,
        scanner_error_count: 0,
    });
    event.component = Some(marker("component"));
    cases.push(("component", marker("component"), event));

    let mut event = health_event_with_metadata(HealthEventInput {
        sources: &[],
        source_inventory_change: None,
        scan_duration_ms: 0,
        rule_count: 0,
        threshold_config: telltale_schema::scoring::load_thresholds(),
        active_policy_name: None,
        emitted_count: 0,
        suppressed_count: 0,
        scanner_error_count: 0,
    });
    event.check_name = Some(marker("check_name"));
    cases.push(("check_name", marker("check_name"), event));

    let mut event = health_event_with_metadata(HealthEventInput {
        sources: &[],
        source_inventory_change: None,
        scan_duration_ms: 0,
        rule_count: 0,
        threshold_config: telltale_schema::scoring::load_thresholds(),
        active_policy_name: None,
        emitted_count: 0,
        suppressed_count: 0,
        scanner_error_count: 0,
    });
    event.status = Some(marker("status"));
    cases.push(("status", marker("status"), event));

    let mut event = install_inventory_event(vec![Evidence {
        field: "inventory".to_string(),
        redacted_value: "synthetic".to_string(),
        hash: None,
        rule_id: None,
    }])
    .expect("controlled install inventory event");
    event.client = marker("client");
    cases.push(("client", marker("client"), event));

    let mut event = install_inventory_event(vec![Evidence {
        field: "inventory".to_string(),
        redacted_value: "synthetic".to_string(),
        hash: None,
        rule_id: None,
    }])
    .expect("controlled install inventory event");
    event.session_id = marker("session_id");
    cases.push(("session_id", marker("session_id"), event));

    let mut event = install_inventory_event(vec![Evidence {
        field: "inventory".to_string(),
        redacted_value: "synthetic".to_string(),
        hash: None,
        rule_id: None,
    }])
    .expect("controlled install inventory event");
    event.tags[0] = marker("install_tag");
    cases.push(("install.tags", marker("install_tag"), event));

    let directory = tempdir().expect("temporary directory");
    for (field, marker, event) in cases {
        let path = directory.path().join(format!("{field}.jsonl"));
        let error = append_jsonl_events(&path, &[event]).expect_err(field);
        let message = error.to_string();
        assert!(
            message.contains("event contains invalid controlled metadata"),
            "{field} did not fail with the generic controlled-field error: {message}"
        );
        assert!(
            !message.contains(&marker),
            "{field} echoed its marker: {message}"
        );
        assert!(!path.exists(), "{field} opened or wrote its JSONL target");
    }
}

#[test]
fn canonical_jsonl_rejects_invalid_event_identity_and_timestamps_before_opening_file() {
    let marker = |field: &str| format!("TT_PRIVACY_JSONL_CANONICAL_{field}_32");
    let mut cases = Vec::new();
    for field in ["event_id", "timestamp", "observed_at", "ingested_at"] {
        let mut event = health_event_with_metadata(HealthEventInput {
            sources: &[],
            source_inventory_change: None,
            scan_duration_ms: 0,
            rule_count: 0,
            threshold_config: telltale_schema::scoring::load_thresholds(),
            active_policy_name: None,
            emitted_count: 0,
            suppressed_count: 0,
            scanner_error_count: 0,
        });
        let value = marker(field);
        match field {
            "event_id" => event.event_id = value.clone(),
            "timestamp" => event.timestamp = value.clone(),
            "observed_at" => event.observed_at = value.clone(),
            "ingested_at" => event.ingested_at = value.clone(),
            _ => unreachable!("canonical field test case is exhaustive"),
        }
        cases.push((field, value, event));
    }

    let directory = tempdir().expect("temporary directory");
    for (field, marker, event) in cases {
        let path = directory.path().join(format!("{field}.jsonl"));
        let valid_event = health_event_with_metadata(HealthEventInput {
            sources: &[],
            source_inventory_change: None,
            scan_duration_ms: 0,
            rule_count: 0,
            threshold_config: telltale_schema::scoring::load_thresholds(),
            active_policy_name: None,
            emitted_count: 0,
            suppressed_count: 0,
            scanner_error_count: 0,
        });
        let error = append_jsonl_events(&path, &[valid_event, event]).expect_err(field);
        let message = error.to_string();
        assert_eq!(message, "event contains invalid controlled metadata");
        assert!(!message.contains(&marker));
        assert!(!path.exists(), "{field} opened or wrote its JSONL target");
    }
}

#[test]
fn canonical_jsonl_batch_rejects_unreviewed_response_playbooks_before_opening_file() {
    let cases = [
        (
            "telltale-playbook-unreviewed-operator-escalation",
            "unreviewed",
        ),
        (
            "telltale-playbook-credential-access-ghp_AbCdEfGhIjKlMnOpQrStUvWxYz12",
            "sensitive",
        ),
    ];
    let directory = tempdir().expect("temporary directory");

    for (playbook, case_name) in cases {
        let mut event = process_chain_event(ProcessChainEventInput {
            client: telltale_schema::clients::ClientId::Codex,
            agent: None,
            model: None,
            provider: None,
            session_id: format!("jsonl-response-{case_name}"),
            source_path_hash: format!("jsonl-response-{case_name}-source"),
            tool_name: Some("shell".to_string()),
            rule_ids: vec!["rule.synthetic".to_string()],
            categories: vec!["execution".to_string()],
            detection_classes: vec!["security_detection".to_string()],
            signal_types: vec!["chain".to_string()],
            analytic_intents: vec!["alert".to_string()],
            tags: Vec::new(),
            evidence: Vec::new(),
            risk_contributions: Vec::new(),
            event_time: None,
            confidence: "low".to_string(),
            detection_reason: "synthetic JSONL controlled-field fixture".to_string(),
            mitre_attack_techniques: Vec::new(),
            risk_entity_type: "session".to_string(),
            risk_entity_value: Some(format!("jsonl-response-{case_name}")),
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
                source_event_id: None,
                source_process_inferred: false,
                rule_name: "synthetic".to_string(),
                secondary_rule_ids: Vec::new(),
                investigation_fields: Vec::new(),
                falsepositives: Vec::new(),
                dedup_key: format!("jsonl-response-{case_name}"),
                suppression_window_seconds: 0,
                rule_severity: "low".to_string(),
                risk_adjustment: None,
            },
        })
        .expect("controlled process event");
        let valid_event = event.clone();
        event
            .response
            .as_mut()
            .expect("process response")
            .response_playbook = playbook.to_string();
        let path = directory.path().join(format!("response-{case_name}.jsonl"));

        let error = append_jsonl_events(&path, &[valid_event, event]).expect_err(case_name);
        assert_eq!(
            error.to_string(),
            "event contains invalid controlled metadata"
        );
        assert!(!error.to_string().contains(playbook));
        assert!(
            !path.exists(),
            "{case_name} opened or wrote its JSONL target"
        );
    }
}
