use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use jsonschema::validator_for;
#[cfg(target_os = "linux")]
use rusqlite::Connection;
use serde_json::Value;
use sha2::Digest;
use telltale_schema::clients::{ClientId, SourceKind};
use telltale_schema::event::{
    ActivityEventInput, CorrelationEventInput, CorrelationSessionInput, DetectionEventInput,
    Evidence, HealthEventInput, OperationalAlertInput, ProcessChainEventInput, ProcessContext,
    SessionRiskSummaryEventInput, activity_event, correlation_event, detection_event,
    evidence_hash, health_event_with_metadata, install_inventory_event, operational_alert_event,
    path_hash, process_chain_event, scanner_error_event, session_risk_summary_event,
};
use telltale_schema::scoring::{RiskContribution, RiskContributionType};
use telltale_schema::source::Source;
use tempfile::tempdir;

fn native_test_event(
    event_type: &str,
    event_id: &str,
    timestamp: &str,
    severity: &str,
    client: &str,
    session_id: &str,
    rule_ids: &[&str],
) -> Value {
    let client_id = match client {
        "claude" => ClientId::Claude,
        "codex" => ClientId::Codex,
        "opencode" => ClientId::OpenCode,
        _ => ClientId::Codex,
    };
    let string_rule_ids = rule_ids
        .iter()
        .map(|rule_id| (*rule_id).to_string())
        .collect();
    let contribution = |score: u64| {
        if score == 0 {
            Vec::new()
        } else {
            vec![
                RiskContribution::new(
                    rule_ids.first().copied().unwrap_or("rule.test"),
                    RiskContributionType::DeterministicRule,
                    score,
                    "synthetic test event",
                )
                .expect("test contribution"),
            ]
        }
    };
    let score = match severity {
        "low" => 20,
        "medium" => 50,
        "high" => 70,
        "critical" => 90,
        _ => 0,
    };
    let event = match event_type {
        "activity" => activity_event(ActivityEventInput {
            client: client_id,
            agent: None,
            model: None,
            provider: None,
            session_id: session_id.to_string(),
            source_path_hash: "synthetic-source-hash".to_string(),
            tool_name: None,
            tags: vec!["synthetic".to_string()],
            evidence: vec![Evidence {
                field: "synthetic".to_string(),
                redacted_value: "fixture".to_string(),
                hash: None,
                rule_id: None,
            }],
            risk_contributions: Vec::new(),
            event_time: Some(timestamp.to_string()),
        })
        .expect("activity event"),
        "detection" => detection_event(DetectionEventInput {
            client: client_id,
            agent: None,
            model: None,
            provider: None,
            session_id: session_id.to_string(),
            source_path_hash: "synthetic-source-hash".to_string(),
            tool_name: None,
            rule_ids: string_rule_ids,
            categories: vec!["synthetic".to_string()],
            detection_classes: vec!["security_detection".to_string()],
            signal_types: vec!["atomic".to_string()],
            analytic_intents: vec!["alert".to_string()],
            atlas_tags: Vec::new(),
            tags: vec!["synthetic".to_string()],
            evidence: Vec::new(),
            risk_contributions: contribution(score),
            event_time: Some(timestamp.to_string()),
        })
        .expect("detection event"),
        "session_risk_summary" => session_risk_summary_event(SessionRiskSummaryEventInput {
            client: client.to_string(),
            agent: None,
            model: None,
            provider: None,
            session_id: session_id.to_string(),
            source_path_hash: Some("synthetic-source-hash".to_string()),
            rule_ids: string_rule_ids,
            categories: Vec::new(),
            detection_classes: Vec::new(),
            signal_types: Vec::new(),
            analytic_intents: Vec::new(),
            atlas_tags: Vec::new(),
            tags: vec!["synthetic".to_string()],
            evidence: Vec::new(),
            risk_contributions: contribution(score),
            event_time: Some(timestamp.to_string()),
        })
        .expect("session summary event"),
        "health" => health_event_with_metadata(HealthEventInput {
            sources: &[],
            source_inventory_change: None,
            scan_duration_ms: 0,
            rule_count: 0,
            threshold_config: telltale_schema::scoring::RiskThresholds {
                low: 20,
                medium: 50,
                high: 70,
                critical: 90,
            },
            active_policy_name: None,
            emitted_count: 0,
            suppressed_count: 0,
            scanner_error_count: 0,
        }),
        "scanner_error" => scanner_error_event(
            &Source {
                client: client_id,
                kind: SourceKind::Jsonl,
                source_id: "synthetic".to_string(),
                path: std::path::PathBuf::from("synthetic.jsonl"),
            },
            &"synthetic scanner error",
        ),
        "operational_alert" => operational_alert_event(OperationalAlertInput {
            alert_type: "sink_delivery_failure".to_string(),
            threshold: "attempts_made=1".to_string(),
            actual_value: "synthetic failure".to_string(),
            scan_duration_ms: None,
            scanner_error_count: None,
        }),
        "process_chain" => process_chain_event(ProcessChainEventInput {
            client: client_id,
            agent: None,
            model: None,
            provider: None,
            session_id: session_id.to_string(),
            source_path_hash: "synthetic-source-hash".to_string(),
            tool_name: None,
            rule_ids: string_rule_ids,
            categories: vec!["process_chain".to_string()],
            detection_classes: vec!["security_detection".to_string()],
            signal_types: vec!["chain".to_string()],
            analytic_intents: vec!["alert".to_string()],
            tags: vec!["synthetic".to_string()],
            evidence: Vec::new(),
            risk_contributions: contribution(score),
            event_time: Some(timestamp.to_string()),
            confidence: "low".to_string(),
            detection_reason: "synthetic test event".to_string(),
            mitre_attack_techniques: Vec::new(),
            risk_entity_type: "session".to_string(),
            risk_entity_value: Some(session_id.to_string()),
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
                rule_name: "synthetic".to_string(),
                secondary_rule_ids: Vec::new(),
                investigation_fields: Vec::new(),
                falsepositives: Vec::new(),
                dedup_key: "synthetic".to_string(),
                suppression_window_seconds: 0,
                rule_severity: "low".to_string(),
                risk_adjustment: None,
            },
        })
        .expect("process-chain event"),
        "correlation" => correlation_event(CorrelationEventInput {
            client: client.to_string(),
            agent: None,
            model: None,
            provider: None,
            shared_rule_ids: string_rule_ids,
            sessions: vec![
                CorrelationSessionInput {
                    session_id: "correlation-session-a".to_string(),
                    event_id: "telltale-00000000-0000-4000-8000-000000000101".to_string(),
                    timestamp: timestamp.to_string(),
                    severity: severity.to_string(),
                    risk_score: score,
                },
                CorrelationSessionInput {
                    session_id: "correlation-session-b".to_string(),
                    event_id: "telltale-00000000-0000-4000-8000-000000000102".to_string(),
                    timestamp: timestamp.to_string(),
                    severity: severity.to_string(),
                    risk_score: score,
                },
            ],
            window_start: timestamp.to_string(),
            window_end: timestamp.to_string(),
            max_risk_score: score,
        })
        .expect("correlation event"),
        other => panic!("unsupported native test event type: {other}"),
    };

    let mut value = serde_json::to_value(&event).expect("serialize native test event");
    value["event_id"] = serde_json::Value::String(event_id.to_string());
    value["timestamp"] = serde_json::Value::String(timestamp.to_string());
    value["observed_at"] = serde_json::Value::String(timestamp.to_string());
    value["ingested_at"] = serde_json::Value::String(timestamp.to_string());
    value["severity"] = serde_json::Value::String(severity.to_string());
    value
}

#[test]
fn every_native_event_constructor_emits_schema_valid_json() {
    let schema: Value =
        serde_json::from_str(include_str!("../schemas/event.schema.json")).expect("event schema");
    let validator = validator_for(&schema).expect("event schema validator");
    let evidence = || {
        vec![Evidence {
            field: "synthetic".to_string(),
            redacted_value: "fixture".to_string(),
            hash: Some("evidence-hash".to_string()),
            rule_id: Some("rule.synthetic".to_string()),
        }]
    };
    let contribution = || {
        vec![
            RiskContribution::new(
                "rule.synthetic",
                RiskContributionType::DeterministicRule,
                90,
                "synthetic constructor event",
            )
            .expect("risk contribution"),
        ]
    };
    let source = Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "synthetic-source".to_string(),
        path: std::path::PathBuf::from("synthetic.jsonl"),
    };
    let process = || ProcessContext {
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
        rule_name: "synthetic".to_string(),
        secondary_rule_ids: Vec::new(),
        investigation_fields: Vec::new(),
        falsepositives: Vec::new(),
        dedup_key: "synthetic".to_string(),
        suppression_window_seconds: 60,
        rule_severity: "high".to_string(),
        risk_adjustment: None,
    };
    let timestamp = "2026-05-01T00:00:00Z";
    let events = vec![
        serde_json::to_value(
            activity_event(ActivityEventInput {
                client: ClientId::Codex,
                agent: Some("codex".to_string()),
                model: Some("synthetic-model".to_string()),
                provider: Some("synthetic-provider".to_string()),
                session_id: "activity-session".to_string(),
                source_path_hash: "source-hash".to_string(),
                tool_name: Some("shell".to_string()),
                tags: vec!["activity".to_string()],
                evidence: evidence(),
                risk_contributions: Vec::new(),
                event_time: Some(timestamp.to_string()),
            })
            .expect("activity constructor"),
        )
        .expect("serialize activity"),
        serde_json::to_value(
            install_inventory_event(vec![Evidence {
                field: "install_inventory_summary".to_string(),
                redacted_value: "agents=0; installed=0; partial=0; absent=0".to_string(),
                hash: Some("inventory-hash".to_string()),
                rule_id: None,
            }])
            .expect("install inventory constructor"),
        )
        .expect("serialize install inventory"),
        serde_json::to_value(
            detection_event(DetectionEventInput {
                client: ClientId::Codex,
                agent: Some("codex".to_string()),
                model: Some("synthetic-model".to_string()),
                provider: Some("synthetic-provider".to_string()),
                session_id: "detection-session".to_string(),
                source_path_hash: "source-hash".to_string(),
                tool_name: Some("shell".to_string()),
                rule_ids: vec!["rule.synthetic".to_string()],
                categories: vec!["synthetic".to_string()],
                detection_classes: vec!["security_detection".to_string()],
                signal_types: vec!["atomic".to_string()],
                analytic_intents: vec!["alert".to_string()],
                atlas_tags: Vec::new(),
                tags: vec!["detection".to_string()],
                evidence: evidence(),
                risk_contributions: contribution(),
                event_time: Some(timestamp.to_string()),
            })
            .expect("detection constructor"),
        )
        .expect("serialize detection"),
        serde_json::to_value(
            session_risk_summary_event(SessionRiskSummaryEventInput {
                client: "codex".to_string(),
                agent: Some("codex".to_string()),
                model: Some("synthetic-model".to_string()),
                provider: Some("synthetic-provider".to_string()),
                session_id: "summary-session".to_string(),
                source_path_hash: Some("source-hash".to_string()),
                rule_ids: vec!["rule.synthetic".to_string()],
                categories: vec!["synthetic".to_string()],
                detection_classes: vec!["security_detection".to_string()],
                signal_types: vec!["atomic".to_string()],
                analytic_intents: vec!["alert".to_string()],
                atlas_tags: Vec::new(),
                tags: vec!["summary".to_string()],
                evidence: evidence(),
                risk_contributions: contribution(),
                event_time: Some(timestamp.to_string()),
            })
            .expect("session summary constructor"),
        )
        .expect("serialize session summary"),
        serde_json::to_value(health_event_with_metadata(HealthEventInput {
            sources: &[],
            source_inventory_change: None,
            scan_duration_ms: 1,
            rule_count: 1,
            threshold_config: telltale_schema::scoring::RiskThresholds {
                low: 20,
                medium: 50,
                high: 70,
                critical: 90,
            },
            active_policy_name: Some("synthetic-policy"),
            emitted_count: 1,
            suppressed_count: 0,
            scanner_error_count: 0,
        }))
        .expect("serialize health"),
        serde_json::to_value(scanner_error_event(&source, &"synthetic parse error"))
            .expect("serialize scanner error"),
        serde_json::to_value(operational_alert_event(OperationalAlertInput {
            alert_type: "scanner_error_threshold_exceeded".to_string(),
            threshold: "max_scanner_errors=3".to_string(),
            actual_value: "scanner_error_count=4".to_string(),
            scan_duration_ms: Some(1),
            scanner_error_count: Some(4),
        }))
        .expect("serialize operational alert"),
        serde_json::to_value(
            process_chain_event(ProcessChainEventInput {
                client: ClientId::Codex,
                agent: Some("codex".to_string()),
                model: Some("synthetic-model".to_string()),
                provider: Some("synthetic-provider".to_string()),
                session_id: "process-session".to_string(),
                source_path_hash: "source-hash".to_string(),
                tool_name: Some("shell".to_string()),
                rule_ids: vec!["rule.synthetic".to_string()],
                categories: vec!["execution".to_string()],
                detection_classes: vec!["security_detection".to_string()],
                signal_types: vec!["chain".to_string()],
                analytic_intents: vec!["alert".to_string()],
                tags: vec!["process_chain".to_string()],
                evidence: evidence(),
                risk_contributions: contribution(),
                event_time: Some(timestamp.to_string()),
                confidence: "high".to_string(),
                detection_reason: "synthetic process chain".to_string(),
                mitre_attack_techniques: vec!["T1059".to_string()],
                risk_entity_type: "session".to_string(),
                risk_entity_value: Some("process-session".to_string()),
                process: process(),
            })
            .expect("process-chain constructor"),
        )
        .expect("serialize process chain"),
        serde_json::to_value(
            correlation_event(CorrelationEventInput {
                client: "codex".to_string(),
                agent: Some("codex".to_string()),
                model: Some("synthetic-model".to_string()),
                provider: Some("synthetic-provider".to_string()),
                shared_rule_ids: vec!["rule.synthetic".to_string()],
                sessions: vec![
                    CorrelationSessionInput {
                        session_id: "correlation-a".to_string(),
                        event_id: "telltale-00000000-0000-4000-8000-000000000201".to_string(),
                        timestamp: timestamp.to_string(),
                        severity: "high".to_string(),
                        risk_score: 90,
                    },
                    CorrelationSessionInput {
                        session_id: "correlation-b".to_string(),
                        event_id: "telltale-00000000-0000-4000-8000-000000000202".to_string(),
                        timestamp: timestamp.to_string(),
                        severity: "critical".to_string(),
                        risk_score: 90,
                    },
                ],
                window_start: timestamp.to_string(),
                window_end: timestamp.to_string(),
                max_risk_score: 90,
            })
            .expect("correlation constructor"),
        )
        .expect("serialize correlation"),
    ];

    for event in events {
        assert!(
            event
                .as_object()
                .expect("native event object")
                .values()
                .all(|value| !value.is_null()),
            "native constructor emitted a JSON null: {event}"
        );
        assert!(
            validator.is_valid(&event),
            "native constructor emitted schema-invalid event: {event}"
        );
    }
}

#[test]
fn health_constructor_normalizes_blank_policy_names_for_schema() {
    let schema: Value =
        serde_json::from_str(include_str!("../schemas/event.schema.json")).expect("event schema");
    let validator = validator_for(&schema).expect("event schema validator");

    for active_policy_name in [Some(""), Some(" \t\n ")] {
        let event = serde_json::to_value(health_event_with_metadata(HealthEventInput {
            sources: &[],
            source_inventory_change: None,
            scan_duration_ms: 0,
            rule_count: 0,
            threshold_config: telltale_schema::scoring::load_thresholds(),
            active_policy_name,
            emitted_count: 0,
            suppressed_count: 0,
            scanner_error_count: 0,
        }))
        .expect("serialize health event");

        assert!(event.get("active_policy_name").is_none());
        assert!(
            validator.is_valid(&event),
            "health event failed schema validation"
        );
    }
}

#[path = "cli/export.rs"]
mod export;
#[path = "cli/migration.rs"]
mod migration;
#[path = "cli/parser_maturity.rs"]
mod parser_maturity;
#[path = "cli/release_public_boundary.rs"]
mod release_public_boundary;
#[path = "cli/rules_config.rs"]
mod rules_config;
#[path = "cli/scan_watch.rs"]
mod scan_watch;
#[path = "cli/sinks.rs"]
mod sinks;
