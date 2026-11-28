use super::*;

#[test]
fn activity_event_serialization_omits_unset_optional_fields() {
    let event = serde_json::to_value(
        activity_event(ActivityEventInput {
            client: ClientId::Codex,
            agent: None,
            model: None,
            provider: None,
            session_id: "session".to_string(),
            source_path_hash: "hash".to_string(),
            tool_name: Some("shell".to_string()),
            tags: vec!["tag".to_string()],
            evidence: vec![Evidence {
                field: "activity".to_string(),
                redacted_value: "summary".to_string(),
                hash: None,
                rule_id: None,
            }],
            risk_contributions: Vec::new(),
            event_time: None,
        })
        .expect("build activity event"),
    )
    .expect("serialize activity event");

    assert_no_top_level_nulls(&event);
    assert_eq!(event["event_type"], "activity");
    assert_eq!(event["risk_score"], 0);
    assert_eq!(event["risk_contributions"], serde_json::json!([]));
    assert_eq!(event["source_path_hash"], evidence_hash("hash"));
    assert_eq!(event["tool_name"], "shell");
    assert!(event.get("agent").is_none());
    assert!(event.get("component").is_none());
    for field in [
        "rule_ids",
        "categories",
        "detection_classes",
        "signal_types",
        "analytic_intents",
        "atlas_tags",
    ] {
        assert!(event.get(field).is_none(), "{field} should be omitted");
    }
    assert!(event["evidence"][0].get("hash").is_none());
    assert!(event["evidence"][0].get("rule_id").is_none());
}

#[test]
fn workspace_is_not_a_top_level_field_but_workspace_evidence_stays_path_safe() {
    let marker = "TT_PRIVACY_WORKSPACE_EVIDENCE_30";
    let event = activity_event(ActivityEventInput {
        client: ClientId::Codex,
        agent: None,
        model: None,
        provider: None,
        session_id: "workspace-evidence-session".to_string(),
        source_path_hash: "workspace-evidence-source".to_string(),
        tool_name: None,
        tags: Vec::new(),
        evidence: vec![Evidence {
            field: "workspace".to_string(),
            redacted_value: format!("/home/{marker}/.ssh/id_rsa"),
            hash: None,
            rule_id: None,
        }],
        risk_contributions: Vec::new(),
        event_time: None,
    })
    .expect("activity event");
    let bytes = serde_json::to_vec(&event).expect("terminal activity event");
    let emitted: serde_json::Value = serde_json::from_slice(&bytes).expect("event JSON");

    assert!(emitted.get("workspace").is_none());
    assert_eq!(emitted["evidence"][0]["field"], "workspace");
    assert_eq!(emitted["evidence"][0]["redacted_value"], "[sensitive-path]");
    assert!(
        check_serialized_event_markers(
            &bytes,
            "workspace-evidence",
            &[ControlledMarker {
                id: "workspace-marker",
                value: marker,
            }],
        )
        .is_ok()
    );
}

#[test]
fn detection_event_serialization_omits_unset_optional_fields() {
    let event = serde_json::to_value(
        detection_event(DetectionEventInput {
            client: ClientId::Codex,
            agent: Some("agent".to_string()),
            model: Some("model".to_string()),
            provider: Some("provider".to_string()),
            session_id: "session".to_string(),
            source_path_hash: "hash".to_string(),
            tool_name: None,
            rule_ids: vec!["rule.test".to_string()],
            categories: vec!["category".to_string()],
            detection_classes: vec!["security_detection".to_string()],
            signal_types: vec!["atomic".to_string()],
            analytic_intents: vec!["alert".to_string()],
            atlas_tags: vec!["atlas:AML.T0051".to_string()],
            tags: vec!["tag".to_string()],
            evidence: vec![Evidence {
                field: "matched_field".to_string(),
                redacted_value: "redacted".to_string(),
                hash: Some("evidence-hash".to_string()),
                rule_id: Some("rule.test".to_string()),
            }],
            risk_contributions: Vec::new(),
            event_time: Some("2026-05-01T00:00:00Z".to_string()),
        })
        .expect("build detection event"),
    )
    .expect("serialize detection event");

    assert_no_top_level_nulls(&event);
    assert_eq!(event["event_type"], "detection");
    assert_eq!(
        event["agent"],
        format!("[agent:{}]", evidence_hash("agent"))
    );
    assert_eq!(event["event_time"], "2026-05-01T00:00:00.000Z");
    assert_eq!(event["rule_ids"][0], "rule.test");
    assert_eq!(event["categories"][0], "category");
    assert_eq!(event["detection_classes"][0], "security_detection");
    assert_eq!(event["signal_types"][0], "atomic");
    assert_eq!(event["analytic_intents"][0], "alert");
    assert_eq!(event["atlas_tags"][0], "atlas:AML.T0051");
    assert_eq!(event["evidence"][0]["hash"], evidence_hash("evidence-hash"));
    assert_eq!(event["evidence"][0]["rule_id"], "rule.test");
    assert!(event["schema_version"] == "3.0");
    assert!(
        event["event_id"]
            .as_str()
            .is_some_and(|value| value.starts_with("telltale-"))
    );
    assert!(event["telltale_version"].is_string());
    assert!(event.get("tool_name").is_none());
    assert!(event.get("source_counts").is_none());
}

#[test]
fn health_event_serialization_omits_unset_optional_fields() {
    let event = serde_json::to_value(health_event_with_metadata(HealthEventInput {
        sources: &[],
        source_inventory_change: None,
        scan_duration_ms: 7,
        rule_count: 3,
        threshold_config: crate::scoring::load_thresholds(),
        active_policy_name: None,
        emitted_count: 0,
        suppressed_count: 0,
        scanner_error_count: 0,
    }))
    .expect("serialize health event");

    assert_no_top_level_nulls(&event);
    assert_eq!(event["event_type"], "health");
    assert_eq!(event["component"], "scanner");
    assert_eq!(event["scan_duration_ms"], 7);
    assert!(event["source_counts"].is_object());
    assert!(event.get("agent").is_none());
    assert!(event.get("active_policy_name").is_none());
    for field in [
        "rule_ids",
        "categories",
        "detection_classes",
        "signal_types",
        "analytic_intents",
        "atlas_tags",
    ] {
        assert!(event.get(field).is_none(), "{field} should be omitted");
    }
    assert!(event["evidence"][0]["hash"].is_string());
    assert!(event["evidence"][0].get("rule_id").is_none());
}

#[test]
fn health_event_constructor_omits_blank_policy_names() {
    for active_policy_name in [Some(""), Some(" \t\n ")] {
        let event = health_event_with_metadata(HealthEventInput {
            sources: &[],
            source_inventory_change: None,
            scan_duration_ms: 0,
            rule_count: 0,
            threshold_config: crate::scoring::load_thresholds(),
            active_policy_name,
            emitted_count: 0,
            suppressed_count: 0,
            scanner_error_count: 0,
        });

        assert_eq!(event.active_policy_name, None);
    }
}
