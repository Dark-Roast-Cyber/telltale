use super::{
    EVENT3_MAX_INPUT_BYTES, EVENT3_SCHEMA, EVENT3_SCHEMA_SHA256, Event3Activity,
    Event3ErrorCategory, Event3Family, Event3Record,
};
use crate::clients::ClientId;
use crate::event::{
    ActivityEventInput, CorrelationEventInput, CorrelationSessionInput, DetectionEventInput,
    Evidence, HealthEventInput, OperationalAlertInput, ProcessChainEventInput, ProcessContext,
    SessionRiskSummaryEventInput, activity_event, correlation_event, detection_event,
    health_event_with_metadata, install_inventory_event, operational_alert_event,
    process_chain_event, scanner_error_event, session_risk_summary_event,
};
use crate::scoring::{RiskContribution, RiskContributionType, load_thresholds};
use crate::source::Source;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::PathBuf;

fn health_bytes() -> Vec<u8> {
    let event = health_event_with_metadata(HealthEventInput {
        sources: &[],
        source_inventory_change: None,
        scan_duration_ms: 0,
        rule_count: 0,
        threshold_config: load_thresholds(),
        active_policy_name: None,
        emitted_count: 0,
        suppressed_count: 0,
        scanner_error_count: 0,
    });
    serde_json::to_vec(&event).expect("terminal health bytes")
}

fn positive_constructor_corpus() -> Vec<(&'static str, crate::event::Event)> {
    let contributions = vec![
        RiskContribution::new(
            "rule.consumer.atomic",
            RiskContributionType::DeterministicRule,
            2,
            "consumer atomic",
        )
        .expect("contribution"),
        RiskContribution::new(
            "rule.consumer.chain",
            RiskContributionType::ChainModifier,
            3,
            "consumer chain",
        )
        .expect("contribution"),
    ];
    let mut detection = detection_event(DetectionEventInput {
        client: ClientId::Codex,
        agent: Some("codex".to_string()),
        model: Some("gpt-4o".to_string()),
        provider: Some("openai".to_string()),
        session_id: "consumer-detection-session".to_string(),
        source_path_hash: "consumer-detection-source".to_string(),
        tool_name: Some("shell".to_string()),
        rule_ids: vec![
            "rule.consumer.atomic".to_string(),
            "rule.consumer.chain".to_string(),
        ],
        categories: vec!["execution".to_string(), "network".to_string()],
        detection_classes: vec!["security_detection".to_string()],
        signal_types: vec!["atomic".to_string(), "chain".to_string()],
        analytic_intents: vec!["alert".to_string()],
        atlas_tags: vec!["atlas:execution".to_string()],
        tags: vec!["consumer".to_string()],
        evidence: vec![Evidence {
            field: "command".to_string(),
            redacted_value: "synthetic command redacted".to_string(),
            hash: Some("a".repeat(64)),
            rule_id: Some("rule.consumer.atomic".to_string()),
        }],
        risk_contributions: contributions.clone(),
        event_time: Some("2026-05-01T00:00:00Z".to_string()),
    })
    .expect("detection");
    detection.timeline_anchors = vec![crate::event::TimelineAnchor {
        entry_index: 0,
        rule_ids: vec!["rule.consumer.atomic".to_string()],
        categories: vec!["execution".to_string()],
        evidence_fields: vec!["command".to_string()],
    }];

    let summary = session_risk_summary_event(SessionRiskSummaryEventInput {
        client: "codex".to_string(),
        agent: Some("codex".to_string()),
        model: Some("gpt-4o".to_string()),
        provider: Some("openai".to_string()),
        session_id: "consumer-summary-session".to_string(),
        source_path_hash: Some("consumer-summary-source".to_string()),
        rule_ids: vec![
            "rule.consumer.atomic".to_string(),
            "rule.consumer.chain".to_string(),
        ],
        categories: vec!["execution".to_string()],
        detection_classes: vec!["security_detection".to_string()],
        signal_types: vec!["chain".to_string()],
        analytic_intents: vec!["alert".to_string()],
        atlas_tags: vec!["atlas:execution".to_string()],
        tags: vec!["consumer".to_string()],
        evidence: vec![Evidence {
            field: "summary".to_string(),
            redacted_value: "synthetic summary".to_string(),
            hash: None,
            rule_id: None,
        }],
        risk_contributions: contributions.clone(),
        event_time: Some("2026-05-01T00:00:00Z".to_string()),
    })
    .expect("summary");

    let process = process_chain_event(ProcessChainEventInput {
        client: ClientId::Codex,
        agent: Some("codex".to_string()),
        model: Some("gpt-4o".to_string()),
        provider: Some("openai".to_string()),
        session_id: "consumer-process-session".to_string(),
        source_path_hash: "consumer-process-source".to_string(),
        tool_name: Some("shell".to_string()),
        rule_ids: vec!["rule.consumer.atomic".to_string()],
        categories: vec!["execution".to_string()],
        detection_classes: vec!["security_detection".to_string()],
        signal_types: vec!["chain".to_string()],
        analytic_intents: vec!["alert".to_string()],
        tags: vec!["consumer".to_string()],
        evidence: vec![Evidence {
            field: "command".to_string(),
            redacted_value: "synthetic command".to_string(),
            hash: None,
            rule_id: Some("rule.consumer.atomic".to_string()),
        }],
        risk_contributions: vec![
            RiskContribution::new(
                "rule.consumer.atomic",
                RiskContributionType::DeterministicRule,
                2,
                "consumer process",
            )
            .expect("contribution"),
        ],
        event_time: Some("2026-05-01T00:00:00Z".to_string()),
        confidence: "high".to_string(),
        detection_reason: "synthetic process reason".to_string(),
        mitre_attack_techniques: vec!["T1059".to_string(), "T1059.001".to_string()],
        risk_entity_type: "host".to_string(),
        risk_entity_value: Some("synthetic-host".to_string()),
        process: ProcessContext {
            host: Some("synthetic-host".to_string()),
            user: None,
            source_process_name: "shell".to_string(),
            source_process_path: None,
            source_process_id: Some(10),
            source_process_command_line: Some("synthetic command".to_string()),
            target_process_name: "curl".to_string(),
            target_process_path: None,
            target_process_id: Some(11),
            target_process_command_line: None,
            parent_process_name: None,
            parent_process_path: None,
            source_event_id: Some("synthetic-source-event".to_string()),
            source_process_inferred: false,
            rule_name: "synthetic-rule".to_string(),
            secondary_rule_ids: Vec::new(),
            investigation_fields: Vec::new(),
            falsepositives: Vec::new(),
            dedup_key: "synthetic-dedup".to_string(),
            suppression_window_seconds: 60,
            rule_severity: "high".to_string(),
            risk_adjustment: None,
        },
    })
    .expect("process chain");

    let correlation = correlation_event(CorrelationEventInput {
        client: "codex".to_string(),
        agent: Some("codex".to_string()),
        model: Some("gpt-4o".to_string()),
        provider: Some("openai".to_string()),
        shared_rule_ids: vec!["rule.consumer.atomic".to_string()],
        sessions: vec![
            CorrelationSessionInput {
                session_id: "consumer-a".to_string(),
                event_id: "consumer-event-a".to_string(),
                timestamp: "2026-05-01T00:00:00Z".to_string(),
                severity: "low".to_string(),
                risk_score: 2,
            },
            CorrelationSessionInput {
                session_id: "consumer-b".to_string(),
                event_id: "consumer-event-b".to_string(),
                timestamp: "2026-05-01T00:01:00Z".to_string(),
                severity: "medium".to_string(),
                risk_score: 3,
            },
        ],
        window_start: "2026-05-01T00:00:00Z".to_string(),
        window_end: "2026-05-01T00:01:00Z".to_string(),
        max_risk_score: 3,
    })
    .expect("correlation");

    let source = Source {
        client: ClientId::Codex,
        kind: crate::clients::SourceKind::Jsonl,
        source_id: "consumer-source".to_string(),
        path: PathBuf::from("synthetic://consumer"),
    };
    vec![
        ("detection", detection),
        (
            "activity_standard",
            activity_event(ActivityEventInput {
                client: ClientId::Codex,
                agent: None,
                model: None,
                provider: None,
                session_id: "consumer-activity".to_string(),
                source_path_hash: "consumer-activity-source".to_string(),
                tool_name: Some("shell".to_string()),
                tags: vec!["consumer".to_string()],
                evidence: vec![Evidence {
                    field: "tool_result".to_string(),
                    redacted_value: "synthetic result".to_string(),
                    hash: None,
                    rule_id: None,
                }],
                risk_contributions: Vec::new(),
                event_time: None,
            })
            .expect("activity"),
        ),
        (
            "install_inventory_activity",
            install_inventory_event(vec![Evidence {
                field: "inventory".to_string(),
                redacted_value: "synthetic inventory".to_string(),
                hash: None,
                rule_id: None,
            }])
            .expect("inventory"),
        ),
        ("session_risk_summary", summary),
        (
            "health",
            health_event_with_metadata(HealthEventInput {
                sources: &[],
                source_inventory_change: None,
                scan_duration_ms: 1,
                rule_count: 2,
                threshold_config: load_thresholds(),
                active_policy_name: Some("synthetic-policy"),
                emitted_count: 1,
                suppressed_count: 0,
                scanner_error_count: 0,
            }),
        ),
        (
            "scanner_error",
            scanner_error_event(&source, &std::io::Error::other("synthetic parse failure")),
        ),
        (
            "operational_alert",
            operational_alert_event(OperationalAlertInput {
                alert_type: "sink_delivery_failure".to_string(),
                threshold: "synthetic threshold".to_string(),
                actual_value: "synthetic actual".to_string(),
                scan_duration_ms: Some(1),
                scanner_error_count: Some(1),
            }),
        ),
        ("process_chain", process),
        ("correlation", correlation),
    ]
}

#[cfg(test)]
mod field_inventory;

mod accepted_events;
mod rejection;
mod rule_replacements;
mod taxonomy;
