use super::super::{append_jsonl_events, serialize_jsonl_events};

use std::collections::BTreeMap;
use std::fs;

use tempfile::tempdir;

use crate::event::{
    ActivityEventInput, ControlledMarker, CorrelationEventInput, CorrelationSessionInput, Evidence,
    HealthEventInput, ProcessChainEventInput, ProcessContext, TELLTALE_VERSION,
    check_serialized_event_markers, correlation_event, evidence_hash, health_event_with_metadata,
    install_inventory_event, process_chain_event, serialize_event_for_emission,
};
use telltale_schema::clients::ClientId;

#[test]
fn canonical_jsonl_sanitizes_source_hash_and_mitre_techniques() {
    let source_hash_marker = "TT_PRIVACY_JSONL_SOURCE_HASH_30";
    let mitre_marker = "TT_PRIVACY_JSONL_MITRE_30";
    let event = process_chain_event(ProcessChainEventInput {
        client: telltale_schema::clients::ClientId::Codex,
        agent: None,
        model: None,
        provider: None,
        session_id: "jsonl-process-session".to_string(),
        source_path_hash: source_hash_marker.to_string(),
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
        detection_reason: "synthetic JSONL privacy fixture".to_string(),
        mitre_attack_techniques: vec![mitre_marker.to_string(), "T1059".to_string()],
        risk_entity_type: "session".to_string(),
        risk_entity_value: Some("jsonl-process-session".to_string()),
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
            dedup_key: "jsonl-process".to_string(),
            suppression_window_seconds: 0,
            rule_severity: "low".to_string(),
            risk_adjustment: None,
        },
    })
    .expect("process-chain event");
    let expected =
        serialize_jsonl_events(std::slice::from_ref(&event)).expect("serialize canonical JSONL");
    let directory = tempdir().expect("temporary directory");
    let path = directory.path().join("events.jsonl");

    append_jsonl_events(&path, std::slice::from_ref(&event)).expect("append canonical JSONL");
    let stored = fs::read(&path).expect("read canonical JSONL");
    assert_eq!(stored, expected);
    assert!(
        check_serialized_event_markers(
            &stored,
            "canonical-jsonl-source-and-mitre",
            &[
                ControlledMarker {
                    id: "source-hash",
                    value: source_hash_marker,
                },
                ControlledMarker {
                    id: "mitre-technique",
                    value: mitre_marker,
                },
            ],
        )
        .is_ok()
    );

    let serialized: serde_json::Value =
        serde_json::from_slice(stored.strip_suffix(b"\n").expect("JSONL newline"))
            .expect("serialized Event JSON");
    assert_eq!(
        serialized["source_path_hash"],
        telltale_schema::event::evidence_hash(source_hash_marker)
    );
    assert_eq!(
        serialized["mitre_attack_techniques"][0],
        format!(
            "mitre:{}",
            telltale_schema::event::evidence_hash(mitre_marker)
        )
    );
    assert_eq!(serialized["mitre_attack_techniques"][1], "T1059");

    let schema: serde_json::Value =
        serde_json::from_str(include_str!("../../../../schemas/event.schema.json"))
            .expect("Event 3.0 schema");
    let validator = jsonschema::validator_for(&schema).expect("schema validator");
    assert!(validator.is_valid(&serialized));
}

mod persisted_bytes;
mod pre_open_validation;
mod url_redaction;
