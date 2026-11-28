use std::collections::{BTreeMap, BTreeSet};

use super::{
    ActivityEventInput, ControlledMarker, CorrelationEventInput, CorrelationSessionInput,
    DetectionEventInput, Evidence, HealthEventInput, INVALID_CONTROLLED_EVENT_ERROR,
    NATIVE_EVENT_CONSTRUCTOR_FAMILIES, NativeEventConstructorFamily, OperationalAlertInput,
    ProcessChainEventInput, ProcessContext, SessionRiskSummaryEventInput, TELLTALE_VERSION,
    VALID_RESPONSE_PLAYBOOKS, activity_event, check_serialized_event_markers, correlation_event,
    detection_event, evidence_hash, health_event_with_metadata, install_inventory_event,
    is_canonical_opaque_identifier_for_kind, opaque_identifier, operational_alert_event, path_hash,
    process_chain_event, sanitize_serialized_event, scanner_error_event,
    serialize_event_for_emission, session_risk_summary_event, terminal_identifier,
    terminal_product_metadata, terminal_session_id, validate_risk_accounting_scope,
    validate_rule_ids,
};
use crate::clients::ClientId;
use crate::event::SanitizationContext;
use crate::scoring::{RiskContribution, RiskContributionType};

fn test_contribution(points: u64) -> Vec<RiskContribution> {
    vec![
        RiskContribution::new(
            "rule.test",
            RiskContributionType::DeterministicRule,
            points,
            "test rationale",
        )
        .expect("contribution"),
    ]
}

fn assert_no_top_level_nulls(event: &serde_json::Value) {
    let fields = event.as_object().expect("serialized event object");
    assert!(
        fields.values().all(|value| !value.is_null()),
        "serialized event contains a top-level null: {event}"
    );
}

fn truncated_tail_input(tail: &str) -> (String, String) {
    const INPUT_CAP: usize = 4096;
    let start = INPUT_CAP - 10;
    let input = format!(
        "safe-prefix{}{}",
        " ".repeat(start - "safe-prefix".len()),
        tail
    );
    (input, tail[..INPUT_CAP - start].to_string())
}

fn controlled_health_event() -> super::Event {
    health_event_with_metadata(HealthEventInput {
        sources: &[],
        source_inventory_change: None,
        scan_duration_ms: 0,
        rule_count: 0,
        threshold_config: crate::scoring::load_thresholds(),
        active_policy_name: None,
        emitted_count: 0,
        suppressed_count: 0,
        scanner_error_count: 0,
    })
}

fn controlled_process_event() -> super::Event {
    process_chain_event(ProcessChainEventInput {
        client: ClientId::Codex,
        agent: None,
        model: None,
        provider: None,
        session_id: "controlled-process-session".to_string(),
        source_path_hash: "controlled-process-source".to_string(),
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
        detection_reason: "synthetic controlled-field fixture".to_string(),
        mitre_attack_techniques: Vec::new(),
        risk_entity_type: "session".to_string(),
        risk_entity_value: Some("controlled-process-session".to_string()),
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
            dedup_key: "controlled-process".to_string(),
            suppression_window_seconds: 0,
            rule_severity: "low".to_string(),
            risk_adjustment: None,
        },
    })
    .expect("controlled process event")
}

fn controlled_install_inventory_event() -> super::Event {
    install_inventory_event(vec![Evidence {
        field: "inventory".to_string(),
        redacted_value: "synthetic".to_string(),
        hash: None,
        rule_id: None,
    }])
    .expect("controlled install inventory event")
}

fn controlled_correlation_event() -> super::Event {
    correlation_event(CorrelationEventInput {
        client: "codex".to_string(),
        agent: None,
        model: None,
        provider: None,
        shared_rule_ids: vec!["rule.synthetic".to_string()],
        sessions: vec![
            CorrelationSessionInput {
                session_id: "session-a".to_string(),
                event_id: "event-a".to_string(),
                timestamp: "2026-05-01T00:00:00Z".to_string(),
                severity: "low".to_string(),
                risk_score: 1,
            },
            CorrelationSessionInput {
                session_id: "session-b".to_string(),
                event_id: "event-b".to_string(),
                timestamp: "2026-05-01T00:01:00Z".to_string(),
                severity: "low".to_string(),
                risk_score: 2,
            },
        ],
        window_start: "2026-05-01T00:00:00Z".to_string(),
        window_end: "2026-05-01T00:01:00Z".to_string(),
        max_risk_score: 2,
    })
    .expect("controlled correlation event")
}

fn schema_event_type_consts(value: &serde_json::Value, event_types: &mut BTreeSet<String>) {
    match value {
        serde_json::Value::Array(values) => {
            for value in values {
                schema_event_type_consts(value, event_types);
            }
        }
        serde_json::Value::Object(values) => {
            if let Some(event_type) = values
                .get("event_type")
                .and_then(|event_type| event_type.get("const"))
                .and_then(|value| value.as_str())
            {
                event_types.insert(event_type.to_string());
            }
            for value in values.values() {
                schema_event_type_consts(value, event_types);
            }
        }
        _ => {}
    }
}

#[test]
fn detection_severities_exclude_warning_without_changing_operational_events() {
    let schema: serde_json::Value =
        serde_json::from_str(super::EVENT3_SCHEMA).expect("frozen schema");
    assert_eq!(
        schema["$defs"]["detection"]["allOf"][1]["properties"]["severity"]["enum"],
        serde_json::json!(super::VALID_DETECTION_SEVERITIES)
    );
    assert_eq!(
        schema["$defs"]["eventCore"]["properties"]["severity"]["enum"],
        serde_json::json!(super::VALID_SEVERITIES)
    );
    assert!(!super::VALID_DETECTION_SEVERITIES.contains(&"warning"));
    let event = operational_alert_event(OperationalAlertInput {
        alert_type: "scanner_error_threshold_exceeded".to_string(),
        threshold: "max_scanner_errors=3".to_string(),
        actual_value: "scanner_error_count=5".to_string(),
        scan_duration_ms: None,
        scanner_error_count: Some(5),
    });
    let wire = serde_json::to_value(&event).expect("operational warning terminal serialization");
    assert_eq!(wire["severity"], "warning");
    jsonschema::validator_for(&schema)
        .expect("event schema validator")
        .validate(&wire)
        .expect("operational warning remains schema-valid");
}

fn raw_event_contains_marker(event: &super::Event, marker: &str) -> bool {
    event
        .agent
        .as_deref()
        .is_some_and(|value| value.contains(marker))
        || event
            .model
            .as_deref()
            .is_some_and(|value| value.contains(marker))
        || event
            .provider
            .as_deref()
            .is_some_and(|value| value.contains(marker))
        || event.session_id.contains(marker)
        || event
            .tool_name
            .as_deref()
            .is_some_and(|value| value.contains(marker))
        || event.tags.iter().any(|value| value.contains(marker))
        || event
            .evidence
            .iter()
            .any(|value| value.redacted_value.contains(marker))
        || event
            .active_policy_name
            .as_deref()
            .is_some_and(|value| value.contains(marker))
        || event
            .risk_entity_value
            .as_deref()
            .is_some_and(|value| value.contains(marker))
        || event.process.as_ref().is_some_and(|process| {
            process
                .host
                .as_deref()
                .is_some_and(|value| value.contains(marker))
                || process
                    .user
                    .as_deref()
                    .is_some_and(|value| value.contains(marker))
                || process.dedup_key.contains(marker)
                || process
                    .source_process_command_line
                    .as_deref()
                    .is_some_and(|value| value.contains(marker))
        })
}

mod contribution_scope;
mod controlled_fields;
mod detection_events;
mod encoded_urls;
mod operational_events;
mod optional_fields;
mod privacy_corpus;
mod rule_identifiers;
mod session_markers;
mod terminalization;
