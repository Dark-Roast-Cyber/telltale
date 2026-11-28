use super::*;

#[test]
fn serialized_sanitization_keeps_rule_identifiers_wherever_one_is_expected() {
    let nested = |event: &serde_json::Value| {
        [
            event["rule_ids"][0].clone(),
            event["risk_contributions"][0]["id"].clone(),
            event["evidence"][0]["rule_id"].clone(),
            event["timeline_anchors"][0]["rule_ids"][0].clone(),
            event["process"]["secondary_rule_ids"][0].clone(),
        ]
    };
    let event_with = |rule_id: &str| {
        serde_json::json!({
            "schema_version": "3.0",
            "event_type": "detection",
            "rule_ids": [rule_id],
            "risk_contributions": [{
                "id": rule_id,
                "type": "deterministic_rule",
                "points": 40,
                "rationale": "synthetic",
            }],
            "evidence": [{ "field": "command", "redacted_value": "safe", "rule_id": rule_id }],
            "timeline_anchors": [{
                "rule_ids": [rule_id],
                "categories": [],
                "evidence_fields": [],
            }],
            "process": { "secondary_rule_ids": [rule_id] },
        })
    };

    // Identifiers that contain a word the prose sanitizer treats as a label.
    for rule_id in [
        "credential.api_key.pattern",
        "credential.cloud_harvest",
        "rule.test",
    ] {
        let mut event = event_with(rule_id);
        sanitize_serialized_event(&mut event);
        for value in nested(&event) {
            assert_eq!(value, rule_id);
        }
        let once = event.clone();
        sanitize_serialized_event(&mut event);
        assert_eq!(event, once);
    }

    // Anything else in those positions is still replaced, in every one of them.
    let token = format!("rule.ghp_{}", "a1b2c3d4".repeat(4));
    for unsafe_value in [token.as_str(), "Credential Access"] {
        let mut event = event_with(unsafe_value);
        sanitize_serialized_event(&mut event);
        for value in nested(&event) {
            let value = value.as_str().expect("identifier");
            assert_ne!(value, unsafe_value);
            assert!(
                crate::scoring::is_canonical_contribution_id(value),
                "{value}"
            );
        }
        assert!(!event.to_string().contains("ghp_"));
        // A replacement stays what it is on a second pass.
        let once = event.clone();
        sanitize_serialized_event(&mut event);
        assert_eq!(event, once);
    }
}

#[test]
fn historical_rule_replacements_are_not_preserved_in_unrelated_fields() {
    let marker = "redacted.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let mut event = serde_json::json!({
        "schema_version": "3.0",
        "response": { "id": marker },
        "evidence": [{ "field": "command", "redacted_value": "safe", "id": marker }],
        "extension": { "rule_ids": [marker] },
    });
    sanitize_serialized_event(&mut event);
    assert!(
        event["response"]["id"] == "redacted.[encoded-blob]",
        "response.id"
    );
    assert!(
        event["evidence"][0]["id"] == "redacted.[encoded-blob]",
        "evidence.id"
    );
    assert!(
        event["extension"]["rule_ids"][0] == "redacted.[encoded-blob]",
        "extension.rule_ids"
    );
    assert!(
        !event.to_string().contains(marker),
        "misplaced marker escaped"
    );
}

#[test]
fn historical_rule_replacement_near_misses_are_hashed() {
    let uppercase = "redacted.0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";
    let short = "redacted.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde";
    let suffixed = "redacted.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0";
    let prefixed = "rule.redacted.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let mut event = serde_json::json!({
        "schema_version": "3.0",
        "rule_ids": [uppercase, short, suffixed, prefixed],
    });
    sanitize_serialized_event(&mut event);
    assert!(event["rule_ids"][0] != uppercase, "uppercase replacement");
    assert!(event["rule_ids"][1] != short, "short replacement");
    assert!(event["rule_ids"][2] != suffixed, "suffixed replacement");
    assert!(event["rule_ids"][3] != prefixed, "prefixed replacement");
    let once = event.clone();
    sanitize_serialized_event(&mut event);
    assert!(
        event == once,
        "historical replacement near misses are not idempotent"
    );
    let mut ordinary = serde_json::json!({
        "schema_version": "3.0",
        "rule_ids": ["redacted.abc"],
    });
    sanitize_serialized_event(&mut ordinary);
    assert_eq!(ordinary["rule_ids"][0], "redacted.abc");
}

#[test]
fn historical_rule_replacements_require_the_actual_slot_shape() {
    let marker = "redacted.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let mut event = serde_json::json!({
        "schema_version": "3.0",
        "rule_ids": marker,
        "evidence": { "rule_id": marker },
        "risk_contributions": [{ "id": [marker] }],
        "timeline_anchors": [{ "rule_ids": [[marker]] }],
        "process": [{ "secondary_rule_ids": [marker] }],
    });
    sanitize_serialized_event(&mut event);
    assert!(
        !event.to_string().contains(marker),
        "malformed rule slot preserved a marker"
    );
}

#[test]
fn noncanonical_evidence_without_a_field_still_hashes_source_rule_ids() {
    let marker = "redacted.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let mut event = serde_json::json!({
        "schema_version": "2.0",
        "evidence": [{ "rule_id": marker, "redacted_value": "safe" }],
    });
    sanitize_serialized_event(&mut event);
    assert!(
        !event.to_string().contains(marker),
        "untransformed native marker escaped"
    );
}

#[test]
fn historical_known_fields_do_not_use_generic_marker_preservation() {
    let marker = opaque_identifier("session", "wrong typed marker");
    let canonical_hash = "a".repeat(64);
    let mut historical = serde_json::json!({
        "schema_version": "3.0",
        "event_id": marker,
        "timestamp": marker,
        "observed_at": marker,
        "ingested_at": marker,
        "event_type": marker,
        "severity": marker,
        "time_source": marker,
        "time_confidence": marker,
        "source_path_hash": marker,
        "detection_classes": [marker],
        "signal_types": [marker],
        "analytic_intents": [marker],
        "extension": marker,
        "response": {"extension": marker},
        "evidence": [{
            "field": "test",
            "redacted_value": "safe",
            "hash": canonical_hash,
        }],
    });

    sanitize_serialized_event(&mut historical);

    for field in [
        "event_id",
        "timestamp",
        "observed_at",
        "ingested_at",
        "event_type",
        "severity",
        "time_source",
        "time_confidence",
        "source_path_hash",
    ] {
        assert_ne!(
            historical[field], marker,
            "known field preserved wrong marker"
        );
    }
    for field in ["detection_classes", "signal_types", "analytic_intents"] {
        assert_ne!(
            historical[field][0], marker,
            "known enum preserved wrong marker"
        );
    }
    assert_eq!(historical["extension"], marker);
    assert_eq!(historical["response"]["extension"], marker);
    assert_eq!(historical["evidence"][0]["hash"], canonical_hash);

    let once = historical.clone();
    sanitize_serialized_event(&mut historical);
    assert_eq!(historical, once);
}

#[test]
fn credential_shaped_schema_identifiers_are_rejected_before_emission() {
    let credential_rule = "rule.ghp_abcdefghijklmnop".to_string();
    assert!(validate_rule_ids(std::slice::from_ref(&credential_rule)).is_err());
    assert!(
        RiskContribution::new(
            &credential_rule,
            RiskContributionType::DeterministicRule,
            1,
            "safe rationale",
        )
        .is_err()
    );

    let invalid_evidence = detection_event(DetectionEventInput {
        client: ClientId::Codex,
        agent: None,
        model: None,
        provider: None,
        session_id: "session".to_string(),
        source_path_hash: "hash".to_string(),
        tool_name: None,
        rule_ids: vec!["rule.safe".to_string()],
        categories: vec!["test".to_string()],
        detection_classes: vec!["security_detection".to_string()],
        signal_types: vec!["atomic".to_string()],
        analytic_intents: vec!["alert".to_string()],
        atlas_tags: Vec::new(),
        tags: Vec::new(),
        evidence: vec![Evidence {
            field: "safe_field".to_string(),
            redacted_value: "safe".to_string(),
            hash: None,
            rule_id: Some(credential_rule.clone()),
        }],
        risk_contributions: vec![
            RiskContribution::new(
                "rule.safe",
                RiskContributionType::DeterministicRule,
                1,
                "safe",
            )
            .expect("contribution"),
        ],
        event_time: None,
    });
    assert!(invalid_evidence.is_err());

    let invalid_atlas_tag = detection_event(DetectionEventInput {
        client: ClientId::Codex,
        agent: None,
        model: None,
        provider: None,
        session_id: "session".to_string(),
        source_path_hash: "hash".to_string(),
        tool_name: None,
        rule_ids: vec!["rule.test".to_string()],
        categories: vec!["test".to_string()],
        detection_classes: vec!["security_detection".to_string()],
        signal_types: vec!["atomic".to_string()],
        analytic_intents: vec!["alert".to_string()],
        atlas_tags: vec!["atlas:ghp_abcdefghijklmnop".to_string()],
        tags: Vec::new(),
        evidence: Vec::new(),
        risk_contributions: test_contribution(1),
        event_time: None,
    });
    assert!(invalid_atlas_tag.is_err());
}
