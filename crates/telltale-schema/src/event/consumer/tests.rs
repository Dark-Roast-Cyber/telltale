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

#[test]
fn schema_asset_matches_frozen_event3_hash() {
    assert_eq!(
        hex::encode(Sha256::digest(EVENT3_SCHEMA.as_bytes())),
        EVENT3_SCHEMA_SHA256
    );
    let root =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../schemas/event.schema.json");
    if root.is_file() {
        assert_eq!(
            std::fs::read(root).expect("root schema"),
            EVENT3_SCHEMA.as_bytes()
        );
        let historical = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../schemas/historical/event-3.0.schema.json");
        assert_eq!(
            std::fs::read(historical).expect("historical schema"),
            EVENT3_SCHEMA.as_bytes()
        );
    }
}

#[test]
fn consumes_actual_terminal_bytes_without_native_deserialization() {
    let record = Event3Record::from_json(&health_bytes()).expect("typed health record");
    assert_eq!(record.event_type(), "health");
    assert!(matches!(record.family(), Event3Family::Health(_)));
    assert_eq!(record.common().session_id, "scanner");
}

#[test]
fn historical_rule_replacements_round_trip_with_accounting_and_references() {
    let (_, event) = positive_constructor_corpus()
        .into_iter()
        .find(|(family, _)| *family == "detection")
        .expect("detection fixture");
    let replacement = "redacted.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let mut wire = serde_json::to_value(&event).expect("event");
    wire["rule_ids"][0] = replacement.into();
    wire["risk_contributions"][0]["id"] = replacement.into();
    wire["evidence"][0]["rule_id"] = replacement.into();
    wire["timeline_anchors"][0]["rule_ids"][0] = replacement.into();

    crate::event::sanitize_serialized_event(&mut wire);
    assert!(wire["rule_ids"][0] == replacement, "historical.rule_ids");
    assert!(
        wire["risk_contributions"][0]["id"] == replacement,
        "historical.contribution.id"
    );
    assert!(
        wire["evidence"][0]["rule_id"] == replacement,
        "historical.evidence.rule_id"
    );
    assert!(
        wire["timeline_anchors"][0]["rule_ids"][0] == replacement,
        "historical.anchor.rule_ids"
    );
    let once = wire.clone();
    crate::event::sanitize_serialized_event(&mut wire);
    assert!(
        wire == once,
        "historical rule references are not idempotent"
    );

    let record = Event3Record::from_json(&serde_json::to_vec(&wire).expect("wire"))
        .expect("terminal replacements remain consumable");
    assert_eq!(record.common().risk_score, 5);
    assert!(
        record.common().risk_contributions[0].id() == replacement,
        "consumer.contribution.id"
    );
    assert_eq!(record.common().risk_contributions[0].points(), 2);
}

#[test]
fn historical_derived_rule_replacements_keep_every_process_reference() {
    let (_, mut event) = positive_constructor_corpus()
        .into_iter()
        .find(|(family, _)| *family == "process_chain")
        .expect("process fixture");
    let replacement = "redacted.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    event.rule_ids = vec![replacement.to_string()];
    event.evidence[0].rule_id = Some(replacement.to_string());
    let contribution = crate::scoring::historical_risk_contribution(&serde_json::json!({
        "id": replacement,
        "type": "deterministic_rule",
        "points": 2,
        "rationale": "synthetic process"
    }));
    assert!(contribution.is_ok(), "historical contribution was rejected");
    assert!(
        serde_json::from_value::<RiskContribution>(serde_json::json!({
            "id": replacement,
            "type": "deterministic_rule",
            "points": 2,
            "rationale": "synthetic process"
        }))
        .is_err(),
        "generic deserialization admitted a historical replacement"
    );
    assert!(
        contribution
            .as_ref()
            .expect("checked contribution")
            .validate()
            .is_err(),
        "native validation must not admit a terminal replacement"
    );
    event.risk_contributions = vec![contribution.expect("checked contribution")];
    event.process.as_mut().expect("process").secondary_rule_ids = vec![replacement.to_string()];

    let wire = serde_json::to_value(event.historical_derived()).expect("historical event");
    assert!(wire["rule_ids"][0] == replacement, "derived.rule_ids");
    assert!(
        wire["risk_contributions"][0]["id"] == replacement,
        "derived.contribution.id"
    );
    assert!(
        wire["evidence"][0]["rule_id"] == replacement,
        "derived.evidence.rule_id"
    );
    assert!(
        wire["process"]["secondary_rule_ids"][0] == replacement,
        "derived.process.secondary_rule_ids"
    );
    let record = Event3Record::from_json(&serde_json::to_vec(&wire).expect("wire"))
        .expect("historical process remains consumable");
    assert_eq!(record.common().risk_score, 2);
}

#[test]
fn native_emission_does_not_trust_marker_shaped_rule_identifiers() {
    let (_, mut event) = positive_constructor_corpus()
        .into_iter()
        .find(|(family, _)| *family == "process_chain")
        .expect("process fixture");
    let replacement = "redacted.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    event.rule_ids = vec![replacement.to_string()];
    event.evidence[0].rule_id = Some(replacement.to_string());
    event.timeline_anchors = vec![crate::event::TimelineAnchor {
        entry_index: 0,
        rule_ids: vec![replacement.to_string()],
        categories: vec!["execution".to_string()],
        evidence_fields: vec!["command".to_string()],
    }];
    event.process.as_mut().expect("process").secondary_rule_ids = vec![replacement.to_string()];

    let wire = serde_json::to_value(&event).expect("native event");
    assert!(wire["rule_ids"][0] != replacement, "native.rule_ids");
    assert!(
        wire["evidence"][0]["rule_id"] == wire["rule_ids"][0],
        "native.evidence.rule_id"
    );
    assert!(
        wire["timeline_anchors"][0]["rule_ids"][0] == wire["rule_ids"][0],
        "native.anchor.rule_ids"
    );
    assert!(
        wire["process"]["secondary_rule_ids"][0] == wire["rule_ids"][0],
        "native.process.secondary_rule_ids"
    );
    assert!(
        !wire.to_string().contains(replacement),
        "native marker escaped"
    );
    assert!(
        crate::event::validate_rule_ids(&[replacement.to_string()]).is_err(),
        "native rule admission must remain strict"
    );
    assert!(
        RiskContribution::new(
            replacement,
            RiskContributionType::DeterministicRule,
            2,
            "synthetic process",
        )
        .is_err(),
        "native contribution admission must remain strict"
    );
}

#[test]
fn terminal_consumer_rejects_credential_shaped_anchor_rule_identifiers() {
    let (_, event) = positive_constructor_corpus()
        .into_iter()
        .find(|(family, _)| *family == "detection")
        .expect("detection fixture");
    let mut wire = serde_json::to_value(&event).expect("event");
    wire["timeline_anchors"][0]["rule_ids"][0] = "rule.ghp_abcdefghijklmnopqrstuvwx".into();
    let result = Event3Record::from_json(&serde_json::to_vec(&wire).expect("wire"))
        .map(|_| ())
        .map_err(|error| error.code());
    assert_eq!(result, Err("invalid_timeline_anchor"));
}

#[test]
fn terminal_consumer_rejects_credential_shaped_secondary_rule_identifiers() {
    let (_, event) = positive_constructor_corpus()
        .into_iter()
        .find(|(family, _)| *family == "process_chain")
        .expect("process fixture");
    let mut wire = serde_json::to_value(&event).expect("event");
    wire["process"]["secondary_rule_ids"] =
        serde_json::json!(["rule.ghp_abcdefghijklmnopqrstuvwx"]);
    let result = Event3Record::from_json(&serde_json::to_vec(&wire).expect("wire"))
        .map(|_| ())
        .map_err(|error| error.code());
    assert_eq!(result, Err("invalid_process_rule_id"));
}

#[test]
fn historical_rule_replacement_restores_contribution_order() {
    let (_, event) = positive_constructor_corpus()
        .into_iter()
        .find(|(family, _)| *family == "detection")
        .expect("detection fixture");
    let first = "rule.ghp_aaaaaaaaaaaaaaaaaaaaaaaa";
    let second = "rule.ghp_bbbbbbbbbbbbbbbbbbbbbbbb";
    let mut wire = serde_json::to_value(&event).expect("event");
    wire["rule_ids"] = serde_json::json!([first, second, "aaa.chain"]);
    wire["risk_score"] = 9.into();
    wire["risk_contributions"] = serde_json::json!([
        { "id": first, "type": "deterministic_rule", "points": 2, "rationale": "synthetic alpha" },
        { "id": second, "type": "deterministic_rule", "points": 3, "rationale": "synthetic beta" },
        { "id": "aaa.chain", "type": "chain_modifier", "points": 4, "rationale": "synthetic chain" },
    ]);
    wire["evidence"][0]["rule_id"] = first.into();
    wire["timeline_anchors"][0]["rule_ids"][0] = first.into();

    crate::event::sanitize_serialized_event(&mut wire);
    assert!(
        wire["risk_contributions"][0]["id"]
            == "redacted.80b3d63c8ede5999727c55daa34623102171012766c3a337ab8adc0e43eeb017",
        "historical.contribution_order"
    );
    assert_eq!(wire["risk_contributions"][0]["points"], 3);
    assert!(
        wire["risk_contributions"][1]["id"]
            == "redacted.9f28179bb9eb6878b1673e3ab7fc523b789a8a91bd053448f8494787668fc5de",
        "historical.contribution_order"
    );
    assert_eq!(wire["risk_contributions"][1]["points"], 2);
    assert_eq!(wire["risk_contributions"][2]["id"], "aaa.chain");
    assert_eq!(wire["risk_contributions"][2]["points"], 4);
    assert!(
        wire["evidence"][0]["rule_id"] == wire["risk_contributions"][1]["id"],
        "historical.evidence.rule_id"
    );
    let record = Event3Record::from_json(&serde_json::to_vec(&wire).expect("wire"))
        .expect("canonical historical contribution order");
    assert_eq!(record.common().risk_score, 9);
    assert_eq!(record.common().risk_contributions.len(), 3);
    let once = wire.clone();
    crate::event::sanitize_serialized_event(&mut wire);
    assert!(
        wire == once,
        "historical contribution order changed on readback"
    );
}

#[test]
fn native_rule_replacement_restores_contribution_order() {
    let (_, mut event) = positive_constructor_corpus()
        .into_iter()
        .find(|(family, _)| *family == "detection")
        .expect("detection fixture");
    let first = format!("redacted.{}", "1".repeat(64));
    let second = format!("redacted.{}", "f".repeat(64));
    event.rule_ids = vec![first.clone(), second.clone()];
    event.evidence[0].rule_id = Some(first.clone());
    event.timeline_anchors[0].rule_ids = vec![first.clone()];
    let contributions = serde_json::json!([
        { "id": first, "type": "deterministic_rule", "points": 2, "rationale": "synthetic alpha" },
        { "id": second, "type": "deterministic_rule", "points": 3, "rationale": "synthetic beta" },
    ])
    .as_array()
    .expect("contribution array")
    .iter()
    .map(crate::scoring::historical_risk_contribution)
    .collect::<Result<Vec<_>, _>>();
    assert!(contributions.is_ok(), "terminal contribution input");
    assert!(
        serde_json::from_value::<RiskContribution>(serde_json::json!({
            "id": first,
            "type": "deterministic_rule",
            "points": 2,
            "rationale": "synthetic alpha"
        }))
        .is_err(),
        "generic deserialization admitted a historical replacement"
    );
    event.risk_contributions = contributions.expect("checked contributions");

    let mut wire = serde_json::to_value(&event).expect("native event");
    assert!(
        wire["risk_contributions"][0]["id"]
            == "redacted.53451715918c77f7e6706fac3adbf0fb15dfd573425bed296d54d95c479270f4",
        "native.contribution_order"
    );
    assert_eq!(wire["risk_contributions"][0]["points"], 3);
    assert!(
        wire["risk_contributions"][1]["id"]
            == "redacted.ba0fb5ed1f56bfd7533f67a029295a1ba3cd0360b66461844dc8aa787bfa7fd5",
        "native.contribution_order"
    );
    assert_eq!(wire["risk_contributions"][1]["points"], 2);
    assert!(
        wire["evidence"][0]["rule_id"] == wire["risk_contributions"][1]["id"],
        "native.evidence.rule_id"
    );
    let record = Event3Record::from_json(&serde_json::to_vec(&wire).expect("wire"))
        .expect("canonical native contribution order");
    assert_eq!(record.common().risk_score, 5);
    assert_eq!(record.common().risk_contributions.len(), 2);
    let once = wire.clone();
    crate::event::sanitize_serialized_event(&mut wire);
    assert!(
        wire == once,
        "native contribution order changed on readback"
    );
}

#[test]
fn unchanged_unordered_contributions_are_not_repaired_by_terminalization() {
    let (_, mut event) = positive_constructor_corpus()
        .into_iter()
        .find(|(family, _)| *family == "detection")
        .expect("detection fixture");
    event.risk_contributions.reverse();
    let mut wire = serde_json::to_value(&event).expect("native event");
    let native = Event3Record::from_json(&serde_json::to_vec(&wire).expect("wire"))
        .map(|_| ())
        .map_err(|error| error.code());
    assert_eq!(native, Err("noncanonical_risk_contributions"));

    let contributions = wire["risk_contributions"].clone();
    crate::event::sanitize_serialized_event(&mut wire);
    assert!(
        wire["risk_contributions"] == contributions,
        "unchanged contribution order was repaired"
    );
    let historical = Event3Record::from_json(&serde_json::to_vec(&wire).expect("wire"))
        .map(|_| ())
        .map_err(|error| error.code());
    assert_eq!(historical, Err("noncanonical_risk_contributions"));
}

#[test]
fn historical_rule_replacement_preserves_duplicate_contributions_for_rejection() {
    let (_, event) = positive_constructor_corpus()
        .into_iter()
        .find(|(family, _)| *family == "detection")
        .expect("detection fixture");
    let mut wire = serde_json::to_value(&event).expect("event");
    wire["rule_ids"] = serde_json::json!([
        "rule.ghp_aaaaaaaaaaaaaaaaaaaaaaaa",
        "redacted.9f28179bb9eb6878b1673e3ab7fc523b789a8a91bd053448f8494787668fc5de"
    ]);
    wire["risk_contributions"] = serde_json::json!([
        { "id": "rule.ghp_aaaaaaaaaaaaaaaaaaaaaaaa", "type": "deterministic_rule", "points": 2, "rationale": "synthetic first" },
        { "id": "redacted.9f28179bb9eb6878b1673e3ab7fc523b789a8a91bd053448f8494787668fc5de", "type": "deterministic_rule", "points": 3, "rationale": "synthetic second" }
    ]);
    wire["evidence"] = serde_json::json!([]);
    wire["timeline_anchors"] = serde_json::json!([]);

    crate::event::sanitize_serialized_event(&mut wire);
    assert_eq!(
        wire["risk_contributions"].as_array().expect("array").len(),
        2
    );
    assert!(
        wire["risk_contributions"][0]["id"] == wire["risk_contributions"][1]["id"],
        "historical duplicate contribution identity"
    );
    assert_eq!(wire["risk_contributions"][0]["points"], 2);
    assert_eq!(wire["risk_contributions"][1]["points"], 3);
    assert_eq!(
        wire["risk_contributions"][0]["rationale"],
        "synthetic first"
    );
    assert_eq!(
        wire["risk_contributions"][1]["rationale"],
        "synthetic second"
    );
    let result = Event3Record::from_json(&serde_json::to_vec(&wire).expect("wire"))
        .map(|_| ())
        .map_err(|error| error.code());
    assert_eq!(result, Err("invalid_risk_contributions"));
}

#[test]
fn historical_rule_replacement_does_not_reorder_extended_contributions() {
    let mut wire = serde_json::json!({
        "schema_version": "3.0",
        "risk_contributions": [
            { "id": "rule.ghp_aaaaaaaaaaaaaaaaaaaaaaaa", "type": "deterministic_rule", "points": 2, "rationale": "synthetic first", "extra": 17 },
            { "id": "rule.ghp_bbbbbbbbbbbbbbbbbbbbbbbb", "type": "deterministic_rule", "points": 3, "rationale": "synthetic second" }
        ]
    });

    crate::event::sanitize_serialized_event(&mut wire);
    assert!(
        wire["risk_contributions"][0]["id"]
            == "redacted.9f28179bb9eb6878b1673e3ab7fc523b789a8a91bd053448f8494787668fc5de",
        "historical extended contribution identity"
    );
    assert_eq!(wire["risk_contributions"][0]["points"], 2);
    assert_eq!(wire["risk_contributions"][0]["extra"], 17);
    assert!(
        wire["risk_contributions"][1]["id"]
            == "redacted.80b3d63c8ede5999727c55daa34623102171012766c3a337ab8adc0e43eeb017",
        "historical extended contribution order"
    );
    assert_eq!(wire["risk_contributions"][1]["points"], 3);
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

#[test]
fn taxonomy_agrees_across_frozen_schema_producer_import_and_typed_consumer() {
    let schema: Value = serde_json::from_str(EVENT3_SCHEMA).expect("frozen schema");
    let mut event = positive_constructor_corpus().remove(0).1;
    event.detection_classes = crate::event::VALID_DETECTION_CLASSES
        .iter()
        .map(|value| value.to_string())
        .collect();
    event.signal_types = crate::event::VALID_SIGNAL_TYPES
        .iter()
        .map(|value| value.to_string())
        .collect();
    event.analytic_intents = crate::event::VALID_ANALYTIC_INTENTS
        .iter()
        .map(|value| value.to_string())
        .collect();
    let native = serde_json::to_value(&event).expect("all taxonomy values emit");
    for field in ["detection_classes", "signal_types", "analytic_intents"] {
        assert_eq!(
            native[field],
            schema["$defs"]["detection"]["allOf"][1]["properties"][field]["items"]["enum"],
            "{field}"
        );
    }
    let mut imported = native.clone();
    crate::event::sanitize_serialized_event(&mut imported);
    for field in ["detection_classes", "signal_types", "analytic_intents"] {
        assert_eq!(imported[field], native[field], "{field}");
    }
    let record = Event3Record::from_json(&serde_json::to_vec(&imported).expect("JSON"))
        .expect("all taxonomy values consume");
    let Event3Family::Detection(detection) = record.family() else {
        panic!("expected detection");
    };
    assert_eq!(
        detection.detection_classes.len(),
        event.detection_classes.len()
    );
    assert_eq!(detection.signal_types.len(), event.signal_types.len());
    assert_eq!(
        detection.analytic_intents.len(),
        event.analytic_intents.len()
    );
}

#[test]
fn taxonomy_rejects_unknown_empty_and_near_miss_values_at_each_boundary() {
    let event = positive_constructor_corpus().remove(0).1;
    for (field, kind) in [
        ("detection_classes", "detection-class"),
        ("signal_types", "signal-type"),
        ("analytic_intents", "analytic-intent"),
    ] {
        for invalid in ["", "unknown", "ALERT", "atomic ", " alert", "alert\u{a0}"] {
            let mut native = event.clone();
            match field {
                "detection_classes" => native.detection_classes = vec![invalid.to_string()],
                "signal_types" => native.signal_types = vec![invalid.to_string()],
                "analytic_intents" => native.analytic_intents = vec![invalid.to_string()],
                _ => unreachable!(),
            }
            assert!(serde_json::to_vec(&native).is_err(), "{field}");
            let mut imported = serde_json::to_value(&event).expect("detection JSON");
            imported[field] = serde_json::json!([invalid]);
            let error = Event3Record::from_json(&serde_json::to_vec(&imported).expect("JSON"))
                .expect_err("unknown taxonomy");
            assert_eq!(error.category(), Event3ErrorCategory::Semantic, "{field}");
            crate::event::sanitize_serialized_event(&mut imported);
            assert_eq!(
                imported[field],
                serde_json::json!([crate::event::opaque_identifier(kind, invalid)]),
                "{field}"
            );
            assert!(
                Event3Record::from_json(&serde_json::to_vec(&imported).expect("JSON")).is_err()
            );
        }
    }
}

#[test]
fn taxonomy_family_profiles_remain_narrower_than_the_shared_vocabulary() {
    for (name, event) in positive_constructor_corpus()
        .into_iter()
        .filter(|(name, _)| matches!(*name, "operational_alert" | "correlation"))
    {
        for field in ["detection_classes", "signal_types", "analytic_intents"] {
            let mut native = event.clone();
            // Valid global values, but outside each of these family profiles.
            match field {
                "detection_classes" => {
                    native.detection_classes = vec!["threat_hunting".to_string()]
                }
                "signal_types" => native.signal_types = vec!["baseline_deviation".to_string()],
                "analytic_intents" => native.analytic_intents = vec!["hunt".to_string()],
                _ => unreachable!(),
            }
            assert!(serde_json::to_vec(&native).is_err(), "{name}: {field}");
            let mut wire = serde_json::to_value(&event).expect("family JSON");
            wire[field] = match field {
                "detection_classes" => serde_json::json!(native.detection_classes),
                "signal_types" => serde_json::json!(native.signal_types),
                "analytic_intents" => serde_json::json!(native.analytic_intents),
                _ => unreachable!(),
            };
            assert!(
                Event3Record::from_json(&serde_json::to_vec(&wire).expect("JSON")).is_err(),
                "{name}: {field}"
            );
        }
    }
}

#[test]
fn actual_terminal_constructor_corpus_covers_all_nine_families() {
    let corpus = positive_constructor_corpus();
    let registered = crate::event::NATIVE_EVENT_CONSTRUCTOR_FAMILIES
        .iter()
        .map(|family| family.name)
        .collect::<std::collections::BTreeSet<_>>();
    let covered = corpus
        .iter()
        .map(|(name, _)| *name)
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(covered, registered);
    for (name, event) in corpus {
        let bytes = serde_json::to_vec(&event).expect("terminal bytes");
        let record = Event3Record::from_json(&bytes)
            .unwrap_or_else(|error| panic!("constructor family {name} did not consume: {error}"));
        assert_eq!(record.event_type(), event.event_type);
        match (name, record.family()) {
            ("detection", Event3Family::Detection(detection)) => {
                assert_eq!(detection.rule_ids.len(), 2);
                assert_eq!(detection.timeline_anchors.len(), 1);
                assert!(detection.response.is_some());
                assert_eq!(
                    record.common().evidence[0].hash.as_ref().map(String::len),
                    Some(64)
                );
            }
            ("activity_standard", Event3Family::Activity(Event3Activity::Standard(activity))) => {
                assert_eq!(activity.source_path_hash.len(), 64);
                assert!(activity.event_time.is_none());
            }
            (
                "install_inventory_activity",
                Event3Family::Activity(Event3Activity::InstallInventory(activity)),
            ) => {
                assert_eq!(activity.component, "scanner");
                assert_eq!(activity.check_name, "install_inventory");
                assert_eq!(activity.status, "ok");
            }
            ("session_risk_summary", Event3Family::SessionRiskSummary(summary)) => {
                assert_eq!(summary.rule_ids.len(), 2);
                assert_eq!(summary.source_path_hash.as_ref().map(String::len), Some(64));
            }
            ("health", Event3Family::Health(health)) => {
                assert_eq!(health.emitted_count, 1);
                assert!(
                    health
                        .active_policy_name
                        .as_deref()
                        .is_some_and(|name| name.starts_with("[policy:"))
                );
            }
            ("scanner_error", Event3Family::ScannerError(error)) => {
                assert_eq!(error.check_name, "source_parse");
                assert_eq!(error.status, "degraded");
            }
            ("operational_alert", Event3Family::OperationalAlert(alert)) => {
                assert_eq!(alert.scan_duration_ms, Some(1));
                assert_eq!(alert.scanner_error_count, None);
            }
            ("process_chain", Event3Family::ProcessChain(process)) => {
                assert!(!process.informational);
                assert_eq!(process.process.target_process_name, "curl");
                assert_eq!(process.response.recommended_action, "monitor");
            }
            ("correlation", Event3Family::Correlation(correlation)) => {
                assert_eq!(correlation.event_time, "2026-05-01T00:01:00.000Z");
            }
            (family, actual) => panic!("family {family} projected as {actual:?}"),
        }
    }
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
    assert_eq!(source.common().time_source, super::Event3TimeSource::Source);
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
        super::Event3TimeSource::Observed
    );
    assert_eq!(
        fallback.common().time_confidence,
        super::Event3TimeConfidence::Low
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
fn errors_are_classified_and_do_not_echo_input() {
    let canary = "TT_EVENT3_CONSUMER_SECRET_CANARY";
    let malformed =
        Event3Record::from_json(format!("{{{canary}").as_bytes()).expect_err("malformed");
    assert_eq!(malformed.category(), Event3ErrorCategory::Malformed);
    assert!(!malformed.to_string().contains(canary));
    assert!(!format!("{malformed:?}").contains(canary));

    let mut missing = serde_json::from_slice::<Value>(&health_bytes()).expect("health JSON");
    missing
        .as_object_mut()
        .expect("object")
        .remove("session_id");
    let error = Event3Record::from_json(&serde_json::to_vec(&missing).expect("JSON"))
        .expect_err("missing common field");
    assert_eq!(error.category(), Event3ErrorCategory::Structure);

    let mut invalid_id = serde_json::from_slice::<Value>(&health_bytes()).expect("health JSON");
    invalid_id["event_id"] = Value::String(canary.to_string());
    let error = Event3Record::from_json(&serde_json::to_vec(&invalid_id).expect("JSON"))
        .expect_err("invalid identity");
    assert_eq!(error.category(), Event3ErrorCategory::Identity);
    assert!(!error.to_string().contains(canary));
}

#[test]
fn event_id_must_be_a_lowercase_prefixed_uuid_v4() {
    for event_id in [
        "00000000-0000-4000-8000-000000000000",
        "event-00000000-0000-4000-8000-000000000000",
        "telltale-0000000A-0000-4000-8000-000000000000",
        "telltale-00000000-0000-1000-8000-000000000000",
        "telltale-00000000-0000-4000-c000-000000000000",
        "telltale-00000000-0000-4000-8000-00000000000",
        "telltale-00000000000040008000000000000000",
    ] {
        let mut value = serde_json::from_slice::<Value>(&health_bytes()).expect("health JSON");
        value["event_id"] = Value::String(event_id.to_string());
        let error = Event3Record::from_json(&serde_json::to_vec(&value).expect("JSON"))
            .expect_err(event_id);
        assert_eq!(
            (error.category(), error.code()),
            (Event3ErrorCategory::Identity, "invalid_identity_or_time"),
            "{event_id}"
        );
    }
}

#[test]
fn oversized_input_is_rejected_before_json_parsing() {
    let canary = "TT_EVENT3_OVERSIZED_INPUT_CANARY";
    let mut oversized = vec![b' '; EVENT3_MAX_INPUT_BYTES + 1];
    oversized.extend_from_slice(canary.as_bytes());
    let error = Event3Record::from_json(&oversized).expect_err("oversized input");
    assert_eq!(error.category(), Event3ErrorCategory::Structure);
    assert_eq!(error.code(), "input_too_large");
    assert!(!error.to_string().contains(canary));
    assert!(!format!("{error:?}").contains(canary));
}

#[test]
fn unknown_property_is_rejected_before_projection() {
    let mut value = serde_json::from_slice::<Value>(&health_bytes()).expect("health JSON");
    value["unexpected"] = Value::String("synthetic".to_string());
    let error = Event3Record::from_json(&serde_json::to_vec(&value).expect("JSON"))
        .expect_err("unknown property");
    assert_eq!(error.category(), Event3ErrorCategory::Structure);

    let mut nested = serde_json::from_slice::<Value>(&health_bytes()).expect("health JSON");
    nested["evidence"][0]["unexpected"] = Value::String("synthetic".to_string());
    let error = Event3Record::from_json(&serde_json::to_vec(&nested).expect("JSON"))
        .expect_err("nested unknown property");
    assert_eq!(error.category(), Event3ErrorCategory::Structure);
}

#[test]
fn adversarial_version_taxonomy_family_anchor_and_semantic_failures_are_classified() {
    let non_object = Event3Record::from_json(b"[]").expect_err("non-object");
    assert_eq!(non_object.category(), Event3ErrorCategory::Structure);

    let mut version = serde_json::from_slice::<Value>(&health_bytes()).expect("health JSON");
    version["schema_version"] = Value::String("4.0".to_string());
    let error = Event3Record::from_json(&serde_json::to_vec(&version).expect("JSON"))
        .expect_err("version failure");
    assert_eq!(error.category(), Event3ErrorCategory::Version);

    let mut taxonomy = serde_json::from_slice::<Value>(&health_bytes()).expect("health JSON");
    taxonomy["time_source"] = Value::String("synthetic-taxonomy".to_string());
    let error = Event3Record::from_json(&serde_json::to_vec(&taxonomy).expect("JSON"))
        .expect_err("taxonomy failure");
    assert_eq!(error.category(), Event3ErrorCategory::Semantic);

    let mut family = serde_json::from_slice::<Value>(&health_bytes()).expect("health JSON");
    family["event_type"] = Value::String("detection".to_string());
    let error = Event3Record::from_json(&serde_json::to_vec(&family).expect("JSON"))
        .expect_err("family failure");
    assert_eq!(error.category(), Event3ErrorCategory::Family);

    let mut missing_family_field =
        serde_json::from_slice::<Value>(&health_bytes()).expect("health JSON");
    missing_family_field
        .as_object_mut()
        .expect("object")
        .remove("component");
    let error = Event3Record::from_json(&serde_json::to_vec(&missing_family_field).expect("JSON"))
        .expect_err("missing family field");
    assert_eq!(error.category(), Event3ErrorCategory::Family);

    let mut detection = serde_json::to_value(
        &positive_constructor_corpus()
            .into_iter()
            .find(|(name, _)| *name == "detection")
            .expect("detection corpus")
            .1,
    )
    .expect("detection JSON");
    detection["risk_score"] = Value::Number(99.into());
    let error = Event3Record::from_json(&serde_json::to_vec(&detection).expect("JSON"))
        .expect_err("semantic risk failure");
    assert_eq!(error.category(), Event3ErrorCategory::Semantic);

    let mut process = serde_json::to_value(
        &positive_constructor_corpus()
            .into_iter()
            .find(|(name, _)| *name == "process_chain")
            .expect("process-chain corpus")
            .1,
    )
    .expect("process-chain JSON");
    process["risk_contributions"][0]["type"] = Value::String("baseline_deviation".to_string());
    let error = Event3Record::from_json(&serde_json::to_vec(&process).expect("JSON"))
        .expect_err("process-chain risk scope failure");
    assert_eq!(error.category(), Event3ErrorCategory::Semantic);

    let anchors = detection["timeline_anchors"]
        .as_array_mut()
        .expect("anchors");
    anchors.push(serde_json::json!({
        "entry_index": 0,
        "rule_ids": ["rule.consumer.chain"],
        "categories": ["network"],
        "evidence_fields": ["command"]
    }));
    detection["risk_score"] = Value::Number(5.into());
    let error = Event3Record::from_json(&serde_json::to_vec(&detection).expect("JSON"))
        .expect_err("anchor failure");
    assert_eq!(error.category(), Event3ErrorCategory::Semantic);
}

#[test]
fn rejects_inconsistent_timing_relationships() {
    let mut source_without_event_time =
        serde_json::from_slice::<Value>(&health_bytes()).expect("health JSON");
    source_without_event_time["time_source"] = Value::String("source".to_string());
    let error =
        Event3Record::from_json(&serde_json::to_vec(&source_without_event_time).expect("JSON"))
            .expect_err("source timing must retain event time");
    assert_eq!(error.category(), Event3ErrorCategory::Semantic);
    assert_eq!(error.code(), "invalid_time_relationship");

    let mut unrelated_observed_timestamp =
        serde_json::from_slice::<Value>(&health_bytes()).expect("health JSON");
    unrelated_observed_timestamp["timestamp"] =
        Value::String("2026-05-01T00:00:00.000Z".to_string());
    let error =
        Event3Record::from_json(&serde_json::to_vec(&unrelated_observed_timestamp).expect("JSON"))
            .expect_err("observed timing must use observation time");
    assert_eq!(error.category(), Event3ErrorCategory::Semantic);
    assert_eq!(error.code(), "invalid_time_relationship");
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
        super::Event3TimeSource::Override
    );
    assert_eq!(
        record.common().time_confidence,
        super::Event3TimeConfidence::Low
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

#[cfg(test)]
mod field_inventory;
