use super::*;

#[test]
fn accepts_detection_whose_evidence_omission_is_marked() {
    let rule = "rule.consumer.atomic".to_string();
    let mut detection = detection_event(DetectionEventInput {
        client: ClientId::Claude,
        agent: None,
        model: None,
        provider: None,
        session_id: "consumer-omitted-session".to_string(),
        source_path_hash: "a".repeat(64),
        tool_name: None,
        rule_ids: vec![rule.clone()],
        categories: vec!["execution".to_string()],
        detection_classes: vec!["security_detection".to_string()],
        signal_types: vec!["atomic".to_string()],
        analytic_intents: vec!["alert".to_string()],
        atlas_tags: Vec::new(),
        tags: Vec::new(),
        evidence: vec![
            Evidence {
                field: "command".to_string(),
                redacted_value: "synthetic command".to_string(),
                hash: Some("b".repeat(64)),
                rule_id: Some(rule.clone()),
            },
            Evidence {
                field: crate::event::EVIDENCE_OMITTED_FIELD.to_string(),
                redacted_value: "42".to_string(),
                hash: None,
                rule_id: Some(rule.clone()),
            },
        ],
        risk_contributions: vec![
            RiskContribution::new(
                &rule,
                RiskContributionType::DeterministicRule,
                5,
                "consumer atomic",
            )
            .expect("contribution"),
        ],
        event_time: Some("2026-05-01T00:00:00Z".to_string()),
    })
    .expect("detection");
    // Anchors are not cross-checked against evidence items: the anchor of
    // an occurrence whose evidence was omitted stays valid.
    detection.timeline_anchors = [0, 7]
        .into_iter()
        .map(|entry_index| crate::event::TimelineAnchor {
            entry_index,
            rule_ids: vec![rule.clone()],
            categories: vec!["execution".to_string()],
            evidence_fields: vec!["command".to_string()],
        })
        .collect();
    let bytes = serde_json::to_vec(&detection).expect("serialize");
    let mut without = detection.clone();
    let marker = without.evidence.pop().expect("marker");
    let shorter = serde_json::to_vec(&without).expect("serialize").len();
    assert_eq!(
        crate::event::emitted_evidence_bytes(&marker).map(|item| item + 1),
        Some(bytes.len() - shorter)
    );
    let record = Event3Record::from_json(&bytes).expect("strict consumer accepts the marker");
    assert!(matches!(record.family(), Event3Family::Detection(_)));
    let wire: Value = serde_json::from_slice(&bytes).expect("json");
    assert_eq!(
        wire["evidence"][1],
        serde_json::json!({
            "field": "evidence_omitted",
            "redacted_value": "42",
            "rule_id": "rule.consumer.atomic"
        })
    );
}

#[test]
fn consumes_actual_terminal_bytes_without_native_deserialization() {
    let record = Event3Record::from_json(&health_bytes()).expect("typed health record");
    assert_eq!(record.event_type(), "health");
    assert!(matches!(record.family(), Event3Family::Health(_)));
    assert_eq!(record.common().session_id, "scanner");
}

#[test]
fn preserves_source_and_fallback_time_and_valid_suppressed_detection() {
    let corpus = positive_constructor_corpus();
    let detection = corpus
        .iter()
        .find(|(name, _)| *name == "detection")
        .expect("detection corpus")
        .1
        .clone();
    let source = Event3Record::from_json(&serde_json::to_vec(&detection).expect("bytes"))
        .expect("source-time detection");
    assert_eq!(
        source.common().time_source,
        super::super::Event3TimeSource::Source
    );
    assert_eq!(
        source.common().event_time.as_deref(),
        Some("2026-05-01T00:00:00.000Z")
    );

    let activity = corpus
        .into_iter()
        .find(|(name, _)| *name == "activity_standard")
        .expect("activity corpus")
        .1;
    let fallback = Event3Record::from_json(&serde_json::to_vec(&activity).expect("bytes"))
        .expect("observed-time activity");
    assert_eq!(
        fallback.common().time_source,
        super::super::Event3TimeSource::Observed
    );
    assert_eq!(
        fallback.common().time_confidence,
        super::super::Event3TimeConfidence::Low
    );

    let mut suppressed = detection_event(DetectionEventInput {
        client: ClientId::Codex,
        agent: None,
        model: None,
        provider: None,
        session_id: "consumer-suppressed".to_string(),
        source_path_hash: "consumer-suppressed-source".to_string(),
        tool_name: None,
        rule_ids: vec!["rule.consumer.suppressed".to_string()],
        categories: vec!["execution".to_string()],
        detection_classes: vec!["security_detection".to_string()],
        signal_types: vec!["atomic".to_string()],
        analytic_intents: vec!["audit".to_string()],
        atlas_tags: Vec::new(),
        tags: vec!["suppressed".to_string()],
        evidence: vec![Evidence {
            field: "command".to_string(),
            redacted_value: "synthetic suppressed evidence".to_string(),
            hash: None,
            rule_id: Some("rule.consumer.suppressed".to_string()),
        }],
        risk_contributions: Vec::new(),
        event_time: None,
    })
    .expect("suppressed detection");
    suppressed.response = None;
    let suppressed = Event3Record::from_json(&serde_json::to_vec(&suppressed).expect("bytes"))
        .expect("valid suppressed detection");
    assert!(matches!(suppressed.family(), Event3Family::Detection(_)));
    assert_eq!(suppressed.common().risk_score, 0);
}

#[test]
fn accepts_override_timing_with_retained_event_time() {
    let event = detection_event(DetectionEventInput {
        client: ClientId::Codex,
        agent: None,
        model: None,
        provider: None,
        session_id: "consumer-override-session".to_string(),
        source_path_hash: "consumer-override-source".to_string(),
        tool_name: None,
        rule_ids: vec!["rule.consumer.override".to_string()],
        categories: vec!["execution".to_string()],
        detection_classes: vec!["security_detection".to_string()],
        signal_types: vec!["atomic".to_string()],
        analytic_intents: vec!["alert".to_string()],
        atlas_tags: Vec::new(),
        tags: vec!["consumer".to_string()],
        evidence: Vec::new(),
        risk_contributions: Vec::new(),
        event_time: Some("2999-01-01T00:00:00Z".to_string()),
    })
    .expect("detection event");
    let record = Event3Record::from_json(&serde_json::to_vec(&event).expect("terminal bytes"))
        .expect("override timing");

    assert_eq!(
        record.common().time_source,
        super::super::Event3TimeSource::Override
    );
    assert_eq!(
        record.common().time_confidence,
        super::super::Event3TimeConfidence::Low
    );
    assert_eq!(
        record.common().time_override_reason.as_deref(),
        Some("source_timestamp_future_skew")
    );
    assert_eq!(
        record.common().event_time.as_deref(),
        Some("2999-01-01T00:00:00.000Z")
    );
    assert_eq!(record.common().timestamp, record.common().observed_at);
}
