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
fn text_bearing_event_types_match_canonical_schema_inventory() {
    let schema_path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../schemas/event.schema.json");
    if !schema_path.exists() {
        // Published crate verification intentionally excludes repository-
        // level schemas; the gate runs whenever the canonical schema is
        // present in the repository worktree.
        return;
    }
    let schema_bytes = std::fs::read(schema_path).expect("read canonical event schema");
    let schema: serde_json::Value =
        serde_json::from_slice(&schema_bytes).expect("canonical event schema JSON");
    let mut schema_event_types = BTreeSet::new();
    schema_event_type_consts(&schema, &mut schema_event_types);

    let text_bearing_event_types = super::TEXT_BEARING_EVENT_TYPES
        .iter()
        .map(|event_type| (*event_type).to_string())
        .collect::<BTreeSet<_>>();
    assert_eq!(text_bearing_event_types, schema_event_types);
    let constructor_event_types = NATIVE_EVENT_CONSTRUCTOR_FAMILIES
        .iter()
        .map(|family| family.event_type.to_string())
        .collect::<BTreeSet<_>>();
    assert_eq!(constructor_event_types, schema_event_types);
}

#[test]
fn direct_event_serialization_drops_partial_truncated_credential_prefix() {
    let tail = "sk-abcdefghijklmnopqrstuvwxyz0123456789TT_PRIVACY_DIRECT_TAIL_25";
    let (input, retained_prefix) = truncated_tail_input(tail);
    let event = activity_event(ActivityEventInput {
        client: ClientId::Codex,
        agent: None,
        model: None,
        provider: None,
        session_id: "safe-session".to_string(),
        source_path_hash: "source-hash".to_string(),
        tool_name: Some("shell".to_string()),
        tags: Vec::new(),
        evidence: vec![Evidence {
            field: "evidence".to_string(),
            redacted_value: input,
            hash: None,
            rule_id: None,
        }],
        risk_contributions: Vec::new(),
        event_time: None,
    })
    .expect("activity event");
    let bytes = serde_json::to_vec(&event).expect("direct Event serialization");
    let serialized: serde_json::Value =
        serde_json::from_slice(&bytes).expect("serialized Event JSON");
    let evidence = serialized["evidence"][0]["redacted_value"]
        .as_str()
        .expect("serialized evidence text");

    assert!(!evidence.contains(&retained_prefix));
    assert!(evidence.starts_with("safe-prefix"));
}

#[test]
fn historical_recursion_drops_partial_prefix_in_known_and_unknown_nested_text() {
    let tail = "QWxhZGRpbjpvcGVuIHNlc2FtZQ==TT_PRIVACY_HISTORICAL_TAIL_25";
    let (input, retained_prefix) = truncated_tail_input(tail);
    let mut historical = serde_json::json!({
        "schema_version": "3.0",
        "event_type": "activity",
        "evidence": [{"field": "evidence", "redacted_value": input.clone()}],
        "extensions": {"deep": [{"object": {"array": [input]}}]}
    });

    sanitize_serialized_event(&mut historical);
    let bytes = serde_json::to_vec(&historical).expect("historical Event JSON");
    let serialized = String::from_utf8(bytes).expect("historical UTF-8 JSON");

    assert!(!serialized.contains(&retained_prefix));
    assert!(serialized.contains("safe-prefix"));
    assert!(!serialized.contains(tail));
}

#[test]
fn event_constructor_family_registry_distinguishes_activity_variants() {
    // This checks the current reviewed descriptor inventory. Source review
    // and test maintenance remain necessary for future same-wire families.
    let names = NATIVE_EVENT_CONSTRUCTOR_FAMILIES
        .iter()
        .map(|family| family.name)
        .collect::<BTreeSet<_>>();
    assert_eq!(names.len(), 9);
    assert_eq!(
        NATIVE_EVENT_CONSTRUCTOR_FAMILIES
            .iter()
            .filter(|family| family.event_type == "activity")
            .count(),
        2,
        "standard activity and install inventory must remain separate families"
    );

    let result = std::panic::catch_unwind(|| {
        super::require_constructor_coverage(
            NativeEventConstructorFamily {
                name: "unregistered",
                event_type: "activity",
            },
            "activity",
        )
    });
    assert!(
        result.is_err(),
        "constructor registry gate must remain active in all builds"
    );
}

#[test]
fn historical_source_hash_and_mitre_values_are_terminalized_idempotently() {
    let source_hash_marker = "TT_PRIVACY_HISTORICAL_SOURCE_HASH_30";
    let mitre_marker = "TT_PRIVACY_HISTORICAL_MITRE_30";
    let source_count_marker = "TT_PRIVACY_HISTORICAL_SOURCE_COUNT_KEY_30";
    let mut historical = serde_json::json!({
        "schema_version": "3.0",
        "source_path_hash": source_hash_marker,
        "mitre_attack_techniques": [mitre_marker, "T1059.001"],
        "source_counts": {
            "codex.jsonl": 2
        }
    });
    historical["source_counts"][source_count_marker] = serde_json::json!(4);

    sanitize_serialized_event(&mut historical);
    let first = historical.clone();
    sanitize_serialized_event(&mut historical);

    assert_eq!(historical, first);
    assert_eq!(
        historical["source_path_hash"],
        evidence_hash(source_hash_marker)
    );
    assert_eq!(
        historical["mitre_attack_techniques"][0],
        format!("mitre:{}", evidence_hash(mitre_marker))
    );
    assert_eq!(historical["mitre_attack_techniques"][1], "T1059.001");
    let source_count_key = format!("source_count:{}", evidence_hash(source_count_marker));
    assert_eq!(historical["source_counts"][&source_count_key], 4);
    assert_eq!(historical["source_counts"]["codex.jsonl"], 2);
    let bytes = serde_json::to_vec(&historical).expect("historical Event JSON");
    assert!(
        check_serialized_event_markers(
            &bytes,
            "historical-source-and-mitre",
            &[
                ControlledMarker {
                    id: "source-hash",
                    value: source_hash_marker,
                },
                ControlledMarker {
                    id: "mitre-technique",
                    value: mitre_marker,
                },
                ControlledMarker {
                    id: "source-count-key",
                    value: source_count_marker,
                },
            ],
        )
        .is_ok()
    );
}

#[test]
fn direct_source_count_keys_are_terminalized_without_merging_collisions() {
    let marker = "TT_PRIVACY_SOURCE_COUNTS_KEY_30";
    let canonical_fallback = format!("source_count:{}", evidence_hash(marker));
    let canonical_collision = format!("{canonical_fallback}:2");
    let mut source_counts = BTreeMap::new();
    source_counts.insert(marker.to_string(), 3);
    source_counts.insert(canonical_fallback.clone(), 5);
    source_counts.insert(canonical_collision.clone(), 7);
    source_counts.insert("codex.jsonl".to_string(), 11);

    let mut event = health_event_with_metadata(HealthEventInput {
        sources: &[],
        source_inventory_change: None,
        scan_duration_ms: 0,
        rule_count: 0,
        threshold_config: crate::scoring::load_thresholds(),
        active_policy_name: None,
        emitted_count: 0,
        suppressed_count: 0,
        scanner_error_count: 0,
    });
    event.source_counts = Some(source_counts);
    let direct_bytes = serde_json::to_vec(&event).expect("direct health event serialization");
    let repeated_bytes = serde_json::to_vec(&event).expect("repeated health event serialization");
    assert_eq!(direct_bytes, repeated_bytes);
    assert!(
        check_serialized_event_markers(
            &direct_bytes,
            "source-count-key",
            &[ControlledMarker {
                id: "source-count-key",
                value: marker,
            }],
        )
        .is_ok()
    );

    let emitted: serde_json::Value =
        serde_json::from_slice(&direct_bytes).expect("serialized health event");
    let counts = emitted["source_counts"]
        .as_object()
        .expect("source counts map");
    let mut sanitized = serde_json::json!({ "source_counts": emitted["source_counts"] });
    sanitize_serialized_event(&mut sanitized);
    let first_sanitized = sanitized.clone();
    sanitize_serialized_event(&mut sanitized);
    assert_eq!(sanitized, first_sanitized);
    assert_eq!(counts.len(), 4);
    assert_eq!(counts["codex.jsonl"], 11);
    assert_eq!(counts[&canonical_fallback], 5);
    assert_eq!(counts[&canonical_collision], 7);
    assert_eq!(counts[&format!("{canonical_fallback}:3")], 3);
    assert_eq!(
        counts
            .values()
            .filter_map(serde_json::Value::as_u64)
            .sum::<u64>(),
        26
    );
    assert_eq!(event.source_counts.unwrap().get(marker), Some(&3));
}

#[test]
fn direct_terminal_serialization_replaces_credential_bearing_telltale_version() {
    let credential_version = format!("1.2.3-AKIA{}", "T".repeat(16));
    assert!(super::contains_credential_material(&credential_version));
    let mut event = health_event_with_metadata(HealthEventInput {
        sources: &[],
        source_inventory_change: None,
        scan_duration_ms: 0,
        rule_count: 0,
        threshold_config: crate::scoring::load_thresholds(),
        active_policy_name: None,
        emitted_count: 0,
        suppressed_count: 0,
        scanner_error_count: 0,
    });
    event.telltale_version = credential_version.clone();

    let first = serde_json::to_vec(&event).expect("direct Event serialization");
    let second = serde_json::to_vec(&event).expect("repeated Event serialization");
    assert_eq!(first, second);
    assert!(!String::from_utf8_lossy(&first).contains(&credential_version));
    let emitted: serde_json::Value = serde_json::from_slice(&first).expect("Event JSON");
    assert_eq!(emitted["telltale_version"], TELLTALE_VERSION);
    assert_eq!(event.telltale_version, credential_version);

    let historical_version = "0.4.0-rc.1+build.7";
    let mut historical_event = health_event_with_metadata(HealthEventInput {
        sources: &[],
        source_inventory_change: None,
        scan_duration_ms: 0,
        rule_count: 0,
        threshold_config: crate::scoring::load_thresholds(),
        active_policy_name: None,
        emitted_count: 0,
        suppressed_count: 0,
        scanner_error_count: 0,
    });
    historical_event.telltale_version = historical_version.to_string();
    let historical = serde_json::to_value(historical_event.historical_derived())
        .expect("historical derived Event serialization");
    assert_eq!(historical["telltale_version"], historical_version);
}

#[test]
fn direct_serialization_rejects_invalid_controlled_fields_without_echoing_markers() {
    let marker = |field: &str| format!("TT_PRIVACY_CONTROLLED_{field}_31");
    let mut cases = Vec::new();

    let mut event = controlled_health_event();
    event.time_source = marker("time_source");
    cases.push(("time_source", marker("time_source"), event));

    let mut event = controlled_health_event();
    event.time_confidence = marker("time_confidence");
    cases.push(("time_confidence", marker("time_confidence"), event));

    let mut event = controlled_health_event();
    event.event_type = marker("event_type");
    cases.push(("event_type", marker("event_type"), event));

    let mut event = controlled_health_event();
    event.severity = marker("severity");
    cases.push(("severity", marker("severity"), event));

    let mut event = controlled_process_event();
    event.confidence = Some(marker("confidence"));
    cases.push(("confidence", marker("confidence"), event));

    let mut event = controlled_health_event();
    event.detection_classes = vec![marker("detection_classes")];
    cases.push(("detection_classes", marker("detection_classes"), event));

    let mut event = controlled_health_event();
    event.signal_types = vec![marker("signal_types")];
    cases.push(("signal_types", marker("signal_types"), event));

    let mut event = controlled_health_event();
    event.analytic_intents = vec![marker("analytic_intents")];
    cases.push(("analytic_intents", marker("analytic_intents"), event));

    let mut event = controlled_process_event();
    event.risk_entity_type = Some(marker("risk_entity_type"));
    cases.push(("risk_entity_type", marker("risk_entity_type"), event));

    let mut event = controlled_health_event();
    event.component = Some(marker("component"));
    cases.push(("component", marker("component"), event));

    let mut event = controlled_health_event();
    event.check_name = Some(marker("check_name"));
    cases.push(("check_name", marker("check_name"), event));

    let mut event = controlled_health_event();
    event.status = Some(marker("status"));
    cases.push(("status", marker("status"), event));

    let mut event = controlled_process_event();
    event
        .process
        .as_mut()
        .expect("process context")
        .rule_severity = marker("rule_severity");
    cases.push(("process.rule_severity", marker("rule_severity"), event));

    let mut event = controlled_health_event();
    event.schema_version = marker("schema_version");
    cases.push(("schema_version", marker("schema_version"), event));

    let mut event = controlled_process_event();
    event
        .response
        .as_mut()
        .expect("process response")
        .recommended_action = marker("recommended_action");
    cases.push((
        "response.recommended_action",
        marker("recommended_action"),
        event,
    ));

    let mut event = controlled_process_event();
    event
        .response
        .as_mut()
        .expect("process response")
        .escalation = marker("escalation");
    cases.push(("response.escalation", marker("escalation"), event));

    let mut event = controlled_install_inventory_event();
    event.client = marker("client");
    cases.push(("client", marker("client"), event));

    let mut event = controlled_install_inventory_event();
    event.session_id = marker("session_id");
    cases.push(("session_id", marker("session_id"), event));

    let mut event = controlled_install_inventory_event();
    event.tags[0] = marker("install_tag");
    cases.push(("install.tags", marker("install_tag"), event));

    let mut event = controlled_correlation_event();
    event.categories = vec![marker("correlation_category")];
    cases.push((
        "correlation.categories",
        marker("correlation_category"),
        event,
    ));

    for (field, marker, event) in cases {
        let error = serde_json::to_vec(&event).expect_err(field);
        let message = error.to_string();
        assert!(
            message.contains(INVALID_CONTROLLED_EVENT_ERROR),
            "{field} did not fail with the generic controlled-field error: {message}"
        );
        assert!(
            !message.contains(&marker),
            "{field} echoed its marker: {message}"
        );

        let mut explicit_bytes = Vec::new();
        let mut serializer = serde_json::Serializer::new(&mut explicit_bytes);
        let explicit_error =
            serialize_event_for_emission(&event, &mut serializer).expect_err(field);
        assert_eq!(
            explicit_bytes.len(),
            0,
            "{field} emitted bytes before rejecting its controlled mutation"
        );
        assert_eq!(explicit_error.to_string(), message);
    }
}

#[test]
fn direct_serialization_rejects_unreviewed_response_playbooks_without_echoing_values() {
    let sensitive = "telltale-playbook-credential-access-ghp_AbCdEfGhIjKlMnOpQrStUvWxYz12";
    let cases = [
        (
            "telltale-playbook-unreviewed-operator-escalation",
            "unreviewed",
        ),
        (sensitive, "sensitive"),
    ];

    for (value, case_name) in cases {
        let mut event = controlled_process_event();
        event
            .response
            .as_mut()
            .expect("process response")
            .response_playbook = value.to_string();

        let error = serde_json::to_vec(&event).expect_err(case_name);
        let message = error.to_string();
        assert_eq!(message, INVALID_CONTROLLED_EVENT_ERROR);
        assert!(!message.contains(value));

        let mut bytes = Vec::new();
        let mut serializer = serde_json::Serializer::new(&mut bytes);
        let explicit_error =
            serialize_event_for_emission(&event, &mut serializer).expect_err(case_name);
        assert!(
            bytes.is_empty(),
            "{case_name} emitted bytes before rejection"
        );
        assert_eq!(explicit_error.to_string(), message);
    }
}

#[test]
fn direct_serialization_preserves_reviewed_response_playbooks() {
    for playbook in VALID_RESPONSE_PLAYBOOKS {
        let mut event = controlled_process_event();
        event
            .response
            .as_mut()
            .expect("process response")
            .response_playbook = (*playbook).to_string();

        let emitted: serde_json::Value =
            serde_json::from_slice(&serde_json::to_vec(&event).expect("serialize event"))
                .expect("serialized event JSON");
        assert_eq!(emitted["response"]["response_playbook"], *playbook);
    }
}

#[test]
fn direct_and_historical_serialization_reject_invalid_event_identity_and_timestamps() {
    let marker = |field: &str| format!("TT_PRIVACY_CANONICAL_{field}_32");
    let mut cases = Vec::new();
    for field in ["event_id", "timestamp", "observed_at", "ingested_at"] {
        let mut event = controlled_health_event();
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

    for (field, marker, event) in cases {
        let direct_error = serde_json::to_vec(&event).expect_err(field);
        let direct_message = direct_error.to_string();
        assert_eq!(direct_message, INVALID_CONTROLLED_EVENT_ERROR);
        assert!(!direct_message.contains(&marker));

        let historical_error = serde_json::to_vec(&event.historical_derived()).expect_err(field);
        let historical_message = historical_error.to_string();
        assert_eq!(historical_message, INVALID_CONTROLLED_EVENT_ERROR);
        assert!(!historical_message.contains(&marker));
    }
}

#[test]
fn terminal_event_time_preserves_only_canonical_or_parseable_values() {
    let marker = "TT_PRIVACY_EVENT_TIME_32";
    let mut event = controlled_process_event();
    event.event_time = Some(marker.to_string());

    let first = serde_json::to_vec(&event).expect("serialize terminal event time");
    let second = serde_json::to_vec(&event).expect("repeat terminal event time");
    assert_eq!(first, second);
    assert!(
        !first
            .as_slice()
            .windows(marker.len())
            .any(|window| window == marker.as_bytes())
    );

    let emitted: serde_json::Value = serde_json::from_slice(&first).expect("event JSON");
    let emitted_event_time = emitted["event_time"].as_str().expect("event_time");
    assert!(is_canonical_opaque_identifier_for_kind(
        "invalid-event-time",
        emitted_event_time
    ));

    let historical =
        serde_json::to_vec(&event.historical_derived()).expect("historical terminal event time");
    assert_eq!(historical, first);
}

#[test]
fn historical_unknown_values_default_to_summary_while_controlled_metadata_is_preserved() {
    let triage_marker = "TT_PRIVACY_HISTORICAL_TRIAGE_25";
    let note_marker = "TT_PRIVACY_HISTORICAL_NOTE_25";
    let deep_marker = "TT_PRIVACY_HISTORICAL_DEEP_25";
    let session_marker = "TT_PRIVACY_HISTORICAL_SESSION_25";
    let key_marker = "TT_PRIVACY_HISTORICAL_UNSAFE_KEY_25";
    let nested_metadata_marker = "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz12";
    let playbook = "telltale-playbook-credential-access";
    let mut historical = serde_json::json!({
        "event_type": "activity",
        "session_id": session_marker,
        "rule_ids": ["secret.env.read"],
        "response": { "response_playbook": playbook },
        "triage": { "reason": format!("TOKEN={triage_marker}") },
        "unknown_extension": {
            "note": format!("TOKEN={note_marker}"),
            "deep": { "array": [{ "text": format!("TOKEN={deep_marker}") }] },
            "rule_ids": [nested_metadata_marker],
            "hash": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
        }
    });
    historical
        .as_object_mut()
        .expect("historical event object")
        .insert(key_marker.to_string(), serde_json::json!("safe value"));

    sanitize_serialized_event(&mut historical);
    let bytes = serde_json::to_vec(&historical).expect("sanitized historical JSON");
    let markers = [
        ControlledMarker {
            id: "triage",
            value: triage_marker,
        },
        ControlledMarker {
            id: "note",
            value: note_marker,
        },
        ControlledMarker {
            id: "deep",
            value: deep_marker,
        },
        ControlledMarker {
            id: "session",
            value: session_marker,
        },
        ControlledMarker {
            id: "key",
            value: key_marker,
        },
        ControlledMarker {
            id: "nested-metadata",
            value: nested_metadata_marker,
        },
    ];
    assert!(check_serialized_event_markers(&bytes, "historical-default", &markers).is_ok());
    assert_eq!(
        super::serialized_value_context("unknown_extension", true),
        SanitizationContext::Summary
    );
    assert_eq!(historical["rule_ids"][0], "secret.env.read");
    assert_eq!(historical["response"]["response_playbook"], playbook);
    assert!(
        historical["triage"]["reason"]
            .as_str()
            .is_some_and(|value| value.contains("[redacted-secret]"))
    );
    assert!(
        historical["unknown_extension"]["note"]
            .as_str()
            .is_some_and(|value| value.contains("[redacted-secret]"))
    );
    assert!(
        historical["unknown_extension"]["deep"]["array"][0]["text"]
            .as_str()
            .is_some_and(|value| value.contains("[redacted-secret]"))
    );
    assert!(
        historical["unknown_extension"]["rule_ids"][0]
            .as_str()
            .is_some_and(|value| value.contains("[redacted-secret]"))
    );
    assert_eq!(historical["unknown_extension"]["hash"], "[encoded-blob]");
}

#[test]
fn native_and_historical_events_hide_sensitive_filesystem_url_paths() {
    let native_marker = "TT_PRIVACY_NATIVE_URL_PATH_USER_25";
    let historical_marker = "TT_PRIVACY_HISTORICAL_URL_PATH_USER_25";
    let deep_marker = "TT_PRIVACY_HISTORICAL_URL_PATH_DEEP_25";
    let authority_marker = "TT_PRIVACY_HISTORICAL_URL_AUTHORITY_25";
    let event = activity_event(ActivityEventInput {
        client: ClientId::Codex,
        agent: None,
        model: None,
        provider: None,
        session_id: "safe-session".to_string(),
        source_path_hash: "source-hash".to_string(),
        tool_name: Some("shell".to_string()),
        tags: Vec::new(),
        evidence: vec![Evidence {
            field: "url".to_string(),
            redacted_value: format!("https://example.invalid/home/{native_marker}/.ssh/id_rsa"),
            hash: None,
            rule_id: None,
        }],
        risk_contributions: Vec::new(),
        event_time: None,
    })
    .expect("native activity event");
    let native_bytes = serde_json::to_vec(&event).expect("native event JSON");
    assert!(!String::from_utf8_lossy(&native_bytes).contains(native_marker));
    assert!(
        String::from_utf8_lossy(&native_bytes).contains("https://example.invalid/[sensitive-path]")
    );

    let mut historical = serde_json::json!({
        "schema_version": "1.0",
        "unknown_extension": {
            "note": format!("https://example.invalid/home/{historical_marker}/.ssh/id_rsa"),
            "deep": [{"value": format!("https://example.invalid/home/{deep_marker}/%2Essh/id%5Frsa")}],
            "authority": {"nested": [format!("https://example.invalid%2Fhome%2F{authority_marker}%2F.ssh%2Fid_rsa")]},
        }
    });
    sanitize_serialized_event(&mut historical);
    let historical_bytes = serde_json::to_vec(&historical).expect("historical JSON");
    assert!(!String::from_utf8_lossy(&historical_bytes).contains(historical_marker));
    assert!(!String::from_utf8_lossy(&historical_bytes).contains(deep_marker));
    assert!(!String::from_utf8_lossy(&historical_bytes).contains(authority_marker));
    assert!(
        String::from_utf8_lossy(&historical_bytes)
            .matches("[sensitive-path]")
            .count()
            >= 2
    );
    assert!(String::from_utf8_lossy(&historical_bytes).contains("[redacted-url]"));
}

#[test]
fn direct_and_historical_events_redact_nested_encoded_urls_inside_outer_components() {
    let marker = "TT_PRIVACY_NESTED_EVENT_BOUNDARY_25";
    let query = format!("https://outer.invalid/?next=https%3A%2F%2Finner.invalid%252F{marker}");
    let path = format!("https://outer.invalid/redirect/https%3A%2F%2Finner.invalid%252F{marker}");
    let fragment =
        format!("https://outer.invalid/#next=https%3A%2F%2Finner.invalid%2523token%253D{marker}");
    let event = activity_event(ActivityEventInput {
        client: ClientId::Codex,
        agent: None,
        model: None,
        provider: None,
        session_id: "nested-boundary-session".to_string(),
        source_path_hash: "nested-boundary-source".to_string(),
        tool_name: Some("shell".to_string()),
        tags: Vec::new(),
        evidence: vec![
            Evidence {
                field: "url".to_string(),
                redacted_value: query.clone(),
                hash: None,
                rule_id: None,
            },
            Evidence {
                field: "path".to_string(),
                redacted_value: path.clone(),
                hash: None,
                rule_id: None,
            },
            Evidence {
                field: "fragment".to_string(),
                redacted_value: fragment.clone(),
                hash: None,
                rule_id: None,
            },
        ],
        risk_contributions: Vec::new(),
        event_time: None,
    })
    .expect("nested URL activity event");

    let direct = serde_json::to_vec(&event).expect("direct Event JSON");
    assert!(
        check_serialized_event_markers(
            &direct,
            "direct-nested-url-components",
            &[ControlledMarker {
                id: "nested-url",
                value: marker,
            }],
        )
        .is_ok(),
        "direct Event serialization retained a nested URL marker"
    );
    let direct_text = String::from_utf8_lossy(&direct);
    assert!(
        !direct_text.contains("https%3A%2F%2Finner.invalid"),
        "direct Event serialization retained a nested encoded URL prefix"
    );
    assert!(direct_text.contains("[redacted-url]"));
    assert_eq!(
        serde_json::to_vec(&event).expect("repeat direct Event JSON"),
        direct,
        "direct Event serialization must be idempotent"
    );

    let mut historical = serde_json::json!({
        "schema_version": "1.0",
        "unknown_extension": {
            "diagnostic": query,
            "nested": {
                "path": path,
                "fragment": fragment,
            },
        },
    });
    sanitize_serialized_event(&mut historical);
    let first_historical = historical.clone();
    sanitize_serialized_event(&mut historical);
    assert_eq!(
        historical, first_historical,
        "historical sanitization must be idempotent"
    );
    let historical_bytes = serde_json::to_vec(&historical).expect("historical Event JSON");
    assert!(
        check_serialized_event_markers(
            &historical_bytes,
            "historical-nested-url-components",
            &[ControlledMarker {
                id: "nested-url",
                value: marker,
            }],
        )
        .is_ok(),
        "historical recursive sanitization retained a nested URL marker"
    );
    let historical_text = String::from_utf8_lossy(&historical_bytes);
    assert!(
        !historical_text.contains("https%3A%2F%2Finner.invalid"),
        "historical recursive sanitization retained a nested encoded URL prefix"
    );
    assert!(historical_text.contains("[redacted-url]"));
}

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
fn activity_event_emits_canonical_contribution_order_and_sum() {
    let z = RiskContribution::new(
        "baseline.z",
        RiskContributionType::BaselineDeviation,
        3,
        "z",
    )
    .expect("contribution");
    let a = RiskContribution::new(
        "baseline.a",
        RiskContributionType::BaselineDeviation,
        4,
        "a",
    )
    .expect("contribution");
    let event = activity_event(ActivityEventInput {
        client: ClientId::Codex,
        agent: None,
        model: None,
        provider: None,
        session_id: "session".to_string(),
        source_path_hash: "hash".to_string(),
        tool_name: Some("shell".to_string()),
        tags: Vec::new(),
        evidence: Vec::new(),
        risk_contributions: vec![z.clone(), a.clone(), z],
        event_time: None,
    })
    .expect("build activity event");

    assert_eq!(event.risk_score, 7);
    assert_eq!(event.risk_contributions.len(), 2);
    assert_eq!(event.risk_contributions[0], a);
    assert_eq!(event.risk_contributions[1].id(), "baseline.z");
}

#[test]
fn risk_accounting_scope_rejects_invalid_types_and_rule_links() {
    let deterministic = RiskContribution::new(
        "rule.detected",
        RiskContributionType::DeterministicRule,
        1,
        "detected",
    )
    .expect("contribution");
    let baseline = RiskContribution::new(
        "baseline.deviation",
        RiskContributionType::BaselineDeviation,
        1,
        "baseline",
    )
    .expect("contribution");

    assert!(matches!(
        validate_risk_accounting_scope("activity", &[], std::slice::from_ref(&deterministic)),
        Err(crate::scoring::RiskAccountingError::ContributionTypeNotAllowed { .. })
    ));
    assert!(matches!(
        validate_risk_accounting_scope("detection", &[], std::slice::from_ref(&baseline)),
        Err(crate::scoring::RiskAccountingError::ContributionTypeNotAllowed { .. })
    ));
    assert!(matches!(
        validate_risk_accounting_scope("detection", &[], std::slice::from_ref(&deterministic)),
        Err(crate::scoring::RiskAccountingError::ContributionRuleIdMissing(id))
            if id == "rule.detected"
    ));
    assert!(
        validate_risk_accounting_scope(
            "detection",
            &["rule.detected".to_string()],
            std::slice::from_ref(&deterministic)
        )
        .is_ok()
    );
    assert!(
        validate_risk_accounting_scope(
            "session_risk_summary",
            &["rule.detected".to_string()],
            &[deterministic]
        )
        .is_ok()
    );
}

#[test]
fn event_builders_enforce_contribution_scope() {
    let invalid_activity = activity_event(ActivityEventInput {
        client: ClientId::Codex,
        agent: None,
        model: None,
        provider: None,
        session_id: "session".to_string(),
        source_path_hash: "hash".to_string(),
        tool_name: None,
        tags: Vec::new(),
        evidence: Vec::new(),
        risk_contributions: vec![
            RiskContribution::new(
                "rule.activity",
                RiskContributionType::DeterministicRule,
                1,
                "invalid",
            )
            .expect("contribution"),
        ],
        event_time: None,
    });
    assert!(invalid_activity.is_err());

    let invalid_detection = detection_event(DetectionEventInput {
        client: ClientId::Codex,
        agent: None,
        model: None,
        provider: None,
        session_id: "session".to_string(),
        source_path_hash: "hash".to_string(),
        tool_name: None,
        rule_ids: vec!["rule".to_string()],
        categories: Vec::new(),
        detection_classes: Vec::new(),
        signal_types: Vec::new(),
        analytic_intents: Vec::new(),
        atlas_tags: Vec::new(),
        tags: Vec::new(),
        evidence: Vec::new(),
        risk_contributions: Vec::new(),
        event_time: None,
    });
    assert!(matches!(
        invalid_detection,
        Err(crate::scoring::RiskAccountingError::InvalidRuleId(id)) if id == "rule"
    ));

    let invalid_summary = session_risk_summary_event(SessionRiskSummaryEventInput {
        client: "codex".to_string(),
        agent: None,
        model: None,
        provider: None,
        session_id: "session".to_string(),
        source_path_hash: None,
        rule_ids: vec!["rule".to_string()],
        categories: Vec::new(),
        detection_classes: Vec::new(),
        signal_types: Vec::new(),
        analytic_intents: Vec::new(),
        atlas_tags: Vec::new(),
        tags: Vec::new(),
        evidence: Vec::new(),
        risk_contributions: Vec::new(),
        event_time: None,
    });
    assert!(matches!(
        invalid_summary,
        Err(crate::scoring::RiskAccountingError::InvalidRuleId(id)) if id == "rule"
    ));

    let invalid_correlation = correlation_event(CorrelationEventInput {
        client: "codex".to_string(),
        agent: None,
        model: None,
        provider: None,
        shared_rule_ids: vec!["rule".to_string()],
        sessions: Vec::new(),
        window_start: "2026-05-01T00:00:00Z".to_string(),
        window_end: "2026-05-01T00:00:00Z".to_string(),
        max_risk_score: 0,
    });
    assert!(matches!(
        invalid_correlation,
        Err(crate::scoring::RiskAccountingError::InvalidRuleId(id)) if id == "rule"
    ));

    let valid_session = session_risk_summary_event(SessionRiskSummaryEventInput {
        client: "codex".to_string(),
        agent: None,
        model: None,
        provider: None,
        session_id: "session".to_string(),
        source_path_hash: None,
        rule_ids: vec!["rule.session".to_string()],
        categories: Vec::new(),
        detection_classes: Vec::new(),
        signal_types: Vec::new(),
        analytic_intents: Vec::new(),
        atlas_tags: Vec::new(),
        tags: Vec::new(),
        evidence: Vec::new(),
        risk_contributions: vec![
            RiskContribution::new(
                "rule.session",
                RiskContributionType::DeterministicRule,
                1,
                "valid",
            )
            .expect("contribution"),
        ],
        event_time: None,
    });
    assert!(valid_session.is_ok());
}

#[test]
fn native_detection_process_and_correlation_inputs_require_dimensions() {
    let invalid_detection = detection_event(DetectionEventInput {
        client: ClientId::Codex,
        agent: None,
        model: None,
        provider: None,
        session_id: "session".to_string(),
        source_path_hash: "hash".to_string(),
        tool_name: None,
        rule_ids: vec!["rule.test".to_string()],
        categories: Vec::new(),
        detection_classes: vec!["security_detection".to_string()],
        signal_types: vec!["atomic".to_string()],
        analytic_intents: vec!["alert".to_string()],
        atlas_tags: Vec::new(),
        tags: vec!["test".to_string()],
        evidence: Vec::new(),
        risk_contributions: Vec::new(),
        event_time: None,
    })
    .expect_err("empty detection categories");
    assert!(matches!(
        invalid_detection,
        crate::scoring::RiskAccountingError::EmptyEventField {
            event_type: "detection",
            field: "categories"
        }
    ));

    let invalid_process = process_chain_event(ProcessChainEventInput {
        client: ClientId::Codex,
        agent: None,
        model: None,
        provider: None,
        session_id: "session".to_string(),
        source_path_hash: "hash".to_string(),
        tool_name: None,
        rule_ids: vec!["rule.test".to_string()],
        categories: vec!["process_chain".to_string()],
        detection_classes: Vec::new(),
        signal_types: vec!["chain".to_string()],
        analytic_intents: vec!["alert".to_string()],
        tags: vec!["test".to_string()],
        evidence: Vec::new(),
        risk_contributions: Vec::new(),
        event_time: None,
        confidence: "low".to_string(),
        detection_reason: "test".to_string(),
        mitre_attack_techniques: Vec::new(),
        risk_entity_type: "session".to_string(),
        risk_entity_value: Some("session".to_string()),
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
            rule_name: "test".to_string(),
            secondary_rule_ids: Vec::new(),
            investigation_fields: Vec::new(),
            falsepositives: Vec::new(),
            dedup_key: "test".to_string(),
            suppression_window_seconds: 0,
            rule_severity: "low".to_string(),
            risk_adjustment: None,
        },
    })
    .expect_err("empty process detection classes");
    assert!(matches!(
        invalid_process,
        crate::scoring::RiskAccountingError::EmptyEventField {
            event_type: "process_chain",
            field: "detection_classes"
        }
    ));

    let invalid_correlation = correlation_event(CorrelationEventInput {
        client: "codex".to_string(),
        agent: None,
        model: None,
        provider: None,
        shared_rule_ids: Vec::new(),
        sessions: vec![CorrelationSessionInput {
            session_id: "one".to_string(),
            event_id: "event-one".to_string(),
            timestamp: "2026-05-01T00:00:00Z".to_string(),
            severity: "high".to_string(),
            risk_score: 70,
        }],
        window_start: "2026-05-01T00:00:00Z".to_string(),
        window_end: "2026-05-01T00:00:00Z".to_string(),
        max_risk_score: 70,
    })
    .expect_err("empty correlation shared IDs");
    assert!(matches!(
        invalid_correlation,
        crate::scoring::RiskAccountingError::EmptyEventField {
            event_type: "correlation",
            field: "shared_rule_ids"
        }
    ));

    let invalid_cardinality = correlation_event(CorrelationEventInput {
        client: "codex".to_string(),
        agent: None,
        model: None,
        provider: None,
        shared_rule_ids: vec!["rule.test".to_string()],
        sessions: vec![CorrelationSessionInput {
            session_id: "one".to_string(),
            event_id: "event-one".to_string(),
            timestamp: "2026-05-01T00:00:00Z".to_string(),
            severity: "high".to_string(),
            risk_score: 70,
        }],
        window_start: "2026-05-01T00:00:00Z".to_string(),
        window_end: "2026-05-01T00:00:00Z".to_string(),
        max_risk_score: 70,
    })
    .expect_err("one-session correlation");
    assert!(matches!(
        invalid_cardinality,
        crate::scoring::RiskAccountingError::InvalidCorrelationCardinality { actual: 1 }
    ));
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

#[test]
fn health_event_has_steady_state_check_dimensions() {
    let event = health_event_with_metadata(HealthEventInput {
        sources: &[],
        source_inventory_change: None,
        scan_duration_ms: 7,
        rule_count: 3,
        threshold_config: crate::scoring::load_thresholds(),
        active_policy_name: None,
        emitted_count: 0,
        suppressed_count: 0,
        scanner_error_count: 0,
    });

    assert_eq!(event.event_type, "health");
    assert_eq!(event.component.as_deref(), Some("scanner"));
    assert_eq!(event.check_name.as_deref(), Some("source_discovery"));
    assert_eq!(event.status.as_deref(), Some("ok"));
}

#[test]
fn health_event_can_include_source_inventory_change_marker() {
    let change = crate::source::SourceInventoryChangeSummary {
        baseline: false,
        added: 0,
        removed: 0,
        unchanged: 2,
        hash: "0".repeat(64),
    };
    let event = health_event_with_metadata(HealthEventInput {
        sources: &[],
        source_inventory_change: Some(&change),
        scan_duration_ms: 7,
        rule_count: 3,
        threshold_config: crate::scoring::load_thresholds(),
        active_policy_name: None,
        emitted_count: 0,
        suppressed_count: 0,
        scanner_error_count: 0,
    });

    let evidence = event
        .evidence
        .iter()
        .find(|item| item.field == "source_inventory_change")
        .expect("source inventory change evidence");
    assert_eq!(
        evidence.redacted_value,
        "baseline=false; added=0; removed=0; unchanged=2"
    );
    assert_eq!(
        evidence.hash.as_deref(),
        Some("0000000000000000000000000000000000000000000000000000000000000000")
    );
}

#[test]
fn detection_event_scored_90_is_critical_and_keeps_its_source_time() {
    let event = detection_event(DetectionEventInput {
        client: ClientId::Codex,
        agent: None,
        model: None,
        provider: None,
        session_id: "session".to_string(),
        source_path_hash: "hash".to_string(),
        tool_name: None,
        rule_ids: vec!["rule.test".to_string()],
        categories: vec!["category".to_string()],
        detection_classes: vec!["security_detection".to_string()],
        signal_types: vec!["atomic".to_string()],
        analytic_intents: vec!["alert".to_string()],
        atlas_tags: Vec::new(),
        tags: vec!["tag".to_string()],
        evidence: Vec::new(),
        risk_contributions: test_contribution(90),
        event_time: Some("2026-05-01T00:00:00Z".to_string()),
    })
    .expect("build detection event");

    assert_eq!(event.severity, "critical");
    assert_eq!(event.timestamp, "2026-05-01T00:00:00.000Z");
    assert_eq!(
        event.event_time.as_deref(),
        Some("2026-05-01T00:00:00.000Z")
    );
    assert_eq!(event.time_source, "source");
    assert_eq!(event.time_confidence, "high");
}

#[test]
fn detection_event_without_contributions_is_informational() {
    let event = detection_event(DetectionEventInput {
        client: ClientId::Codex,
        agent: None,
        model: None,
        provider: None,
        session_id: "session".to_string(),
        source_path_hash: "hash".to_string(),
        tool_name: None,
        rule_ids: vec!["rule.test".to_string()],
        categories: vec!["category".to_string()],
        detection_classes: vec!["security_detection".to_string()],
        signal_types: vec!["atomic".to_string()],
        analytic_intents: vec!["alert".to_string()],
        atlas_tags: Vec::new(),
        tags: vec!["tag".to_string()],
        evidence: Vec::new(),
        risk_contributions: Vec::new(),
        event_time: Some("2026-05-01T00:00:00Z".to_string()),
    })
    .expect("build detection event");

    assert_eq!(event.severity, "informational");
}

#[test]
fn detection_event_populates_response_metadata() {
    let event = detection_event(DetectionEventInput {
        client: ClientId::Codex,
        agent: None,
        model: None,
        provider: None,
        session_id: "session".to_string(),
        source_path_hash: "hash".to_string(),
        tool_name: None,
        rule_ids: vec!["mcp.tool_metadata.prompt_injection".to_string()],
        categories: vec!["mcp_prompt_injection".to_string()],
        detection_classes: vec!["security_detection".to_string()],
        signal_types: vec!["atomic".to_string()],
        analytic_intents: vec!["alert".to_string()],
        atlas_tags: vec!["atlas:AML.T0051".to_string()],
        tags: vec!["tag".to_string()],
        evidence: Vec::new(),
        risk_contributions: vec![
            RiskContribution::new(
                "mcp.tool_metadata.prompt_injection",
                RiskContributionType::DeterministicRule,
                90,
                "test rationale",
            )
            .expect("contribution"),
        ],
        event_time: Some("2026-05-01T00:00:00Z".to_string()),
    })
    .expect("build detection event");

    let response = event.response.expect("response metadata");
    assert_eq!(response.recommended_action, "investigate_immediately");
    assert_eq!(
        response.response_playbook,
        "telltale-playbook-mcp-prompt-injection"
    );
    assert_eq!(response.escalation, "security_review_required");
    assert!(response.investigation_summary.contains("critical"));
    assert!(
        response
            .investigation_summary
            .contains("mcp.tool_metadata.prompt_injection")
    );
    assert_eq!(event.detection_classes, vec!["security_detection"]);
    assert_eq!(event.signal_types, vec!["atomic"]);
    assert_eq!(event.analytic_intents, vec!["alert"]);
    assert_eq!(event.atlas_tags, vec!["atlas:AML.T0051"]);
}

#[test]
fn event_builder_sanitizes_null_string_tool_name() {
    let event = detection_event(DetectionEventInput {
        client: ClientId::Codex,
        agent: None,
        model: None,
        provider: None,
        session_id: "session".to_string(),
        source_path_hash: "hash".to_string(),
        tool_name: Some("null".to_string()),
        rule_ids: vec!["rule.test".to_string()],
        categories: vec!["category".to_string()],
        detection_classes: vec!["security_detection".to_string()],
        signal_types: vec!["atomic".to_string()],
        analytic_intents: vec!["alert".to_string()],
        atlas_tags: Vec::new(),
        tags: vec!["tag".to_string()],
        evidence: Vec::new(),
        risk_contributions: Vec::new(),
        event_time: Some("2026-05-01T00:00:00Z".to_string()),
    })
    .expect("build detection event");

    assert_eq!(event.tool_name, None);
}

#[test]
fn detection_event_falls_back_to_observed_time_for_future_source_timestamp() {
    let event = detection_event(DetectionEventInput {
        client: ClientId::Codex,
        agent: None,
        model: None,
        provider: None,
        session_id: "session".to_string(),
        source_path_hash: "hash".to_string(),
        tool_name: None,
        rule_ids: vec!["rule.test".to_string()],
        categories: vec!["category".to_string()],
        detection_classes: vec!["security_detection".to_string()],
        signal_types: vec!["atomic".to_string()],
        analytic_intents: vec!["alert".to_string()],
        atlas_tags: Vec::new(),
        tags: vec!["tag".to_string()],
        evidence: Vec::new(),
        risk_contributions: Vec::new(),
        event_time: Some("2999-01-01T00:00:00Z".to_string()),
    })
    .expect("build detection event");

    assert_eq!(event.time_source, "override");
    assert_eq!(event.time_confidence, "low");
    assert_eq!(
        event.time_override_reason.as_deref(),
        Some("source_timestamp_future_skew")
    );
    assert_eq!(
        event.event_time.as_deref(),
        Some("2999-01-01T00:00:00.000Z")
    );
    assert_eq!(event.timestamp, event.observed_at);
    assert_eq!(event.ingested_at, event.observed_at);
}

#[test]
fn detection_event_falls_back_to_observed_time_for_missing_source_timestamp() {
    let event = detection_event(DetectionEventInput {
        client: ClientId::Codex,
        agent: None,
        model: None,
        provider: None,
        session_id: "session".to_string(),
        source_path_hash: "hash".to_string(),
        tool_name: None,
        rule_ids: vec!["rule.test".to_string()],
        categories: vec!["category".to_string()],
        detection_classes: vec!["security_detection".to_string()],
        signal_types: vec!["atomic".to_string()],
        analytic_intents: vec!["alert".to_string()],
        atlas_tags: Vec::new(),
        tags: vec!["tag".to_string()],
        evidence: Vec::new(),
        risk_contributions: Vec::new(),
        event_time: None,
    })
    .expect("build detection event");

    assert_eq!(event.time_source, "observed");
    assert_eq!(event.time_confidence, "low");
    assert_eq!(
        event.time_override_reason.as_deref(),
        Some("missing_source_timestamp")
    );
    assert_eq!(event.event_time, None);
    assert_eq!(event.timestamp, event.observed_at);
    assert_eq!(event.ingested_at, event.observed_at);
}

#[test]
fn detection_event_normalizes_non_utc_source_timestamp() {
    let event = detection_event(DetectionEventInput {
        client: ClientId::Codex,
        agent: None,
        model: None,
        provider: None,
        session_id: "session".to_string(),
        source_path_hash: "hash".to_string(),
        tool_name: None,
        rule_ids: vec!["rule.test".to_string()],
        categories: vec!["category".to_string()],
        detection_classes: vec!["security_detection".to_string()],
        signal_types: vec!["atomic".to_string()],
        analytic_intents: vec!["alert".to_string()],
        atlas_tags: Vec::new(),
        tags: vec!["tag".to_string()],
        evidence: Vec::new(),
        risk_contributions: Vec::new(),
        event_time: Some("2026-05-01T12:00:00+02:00".to_string()),
    })
    .expect("build detection event");

    assert_eq!(event.time_source, "source");
    assert_eq!(event.time_confidence, "high");
    assert_eq!(event.time_override_reason, None);
    assert_eq!(
        event.event_time.as_deref(),
        Some("2026-05-01T10:00:00.000Z")
    );
    assert_eq!(event.timestamp, "2026-05-01T10:00:00.000Z");
}

#[test]
fn scanner_error_event_has_correct_shape() {
    use crate::clients::SourceKind;
    use crate::source::Source;
    use std::path::PathBuf;

    let source = Source {
        client: ClientId::OpenCode,
        kind: SourceKind::Sqlite,
        source_id: "opencode.sqlite".to_string(),
        path: PathBuf::from("/home/user/.local/share/opencode/opencode.db"),
    };
    let error = "sqlite error: Query is not read-only";

    let event = scanner_error_event(&source, &error);

    assert_eq!(event.event_type, "scanner_error");
    assert_eq!(event.severity, "informational");
    assert_eq!(event.risk_score, 0);
    assert_eq!(event.client, "opencode");
    assert_eq!(event.session_id, "scanner");
    assert_eq!(event.agent, None);
    assert_eq!(event.model, None);
    assert_eq!(event.tool_name, None);
    assert_eq!(event.rule_ids.len(), 0);
    assert!(event.source_path_hash.is_some());
    assert_eq!(event.tags, vec!["scanner", "parse_failure"]);
    assert_eq!(event.evidence.len(), 2);
    assert_eq!(event.evidence[0].field, "error");
    assert_eq!(event.evidence[0].redacted_value, error);
    assert_eq!(event.evidence[1].field, "source_path");
    assert!(event.evidence[1].hash.is_some());
    assert!(event.timeline_anchors.is_empty());
    assert_eq!(event.response, None);
    assert_eq!(event.source_counts, None);
    assert_eq!(event.component.as_deref(), Some("scanner"));
    assert_eq!(event.check_name.as_deref(), Some("source_parse"));
    assert_eq!(event.status.as_deref(), Some("degraded"));
}

#[test]
fn scanner_error_event_preserves_redacted_state_fingerprint_input() {
    use crate::clients::SourceKind;
    use crate::source::Source;
    use std::path::PathBuf;

    let source = Source {
        client: ClientId::OpenCode,
        kind: SourceKind::Sqlite,
        source_id: "opencode.sqlite".to_string(),
        path: PathBuf::from("/synthetic/opencode.db"),
    };
    let raw_error =
        "failed at /home/TT_PRIVACY_SCANNER_25/.config/state TOKEN=TT_PRIVACY_SCANNER_25";
    let event = scanner_error_event(&source, &raw_error);

    assert_eq!(
        event.evidence[0].redacted_value,
        super::PrivacySanitizer::sanitize(super::SanitizationContext::Diagnostic, raw_error)
    );
    assert!(
        !event.evidence[0]
            .redacted_value
            .contains("TT_PRIVACY_SCANNER_25")
    );
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

#[test]
fn operational_alert_event_has_correct_shape() {
    let event = operational_alert_event(OperationalAlertInput {
        alert_type: "scanner_error_threshold_exceeded".to_string(),
        threshold: "max_scanner_errors=3".to_string(),
        actual_value: "scanner_error_count=5".to_string(),
        scan_duration_ms: Some(1500),
        scanner_error_count: Some(5),
    });

    assert_eq!(event.event_type, "operational_alert");
    assert_eq!(event.severity, "warning");
    assert_eq!(event.risk_score, 0);
    assert_eq!(event.client, "scanner");
    assert_eq!(event.session_id, "scanner");
    assert_eq!(event.component.as_deref(), Some("scanner"));
    assert_eq!(event.check_name.as_deref(), Some("scanner_error_threshold"));
    assert_eq!(event.status.as_deref(), Some("degraded"));
    assert_eq!(event.categories, vec!["operational"]);
    assert!(event.tags.contains(&"operational".to_string()));
    assert!(event.tags.contains(&"scanner_health".to_string()));
    assert_eq!(event.scan_duration_ms, Some(1500));
    assert_eq!(event.telltale_version, env!("CARGO_PKG_VERSION"));
    assert!(event.timeline_anchors.is_empty());
    assert_eq!(event.response, None);
    assert!(event.source_path_hash.is_none());

    let alert_type = event
        .evidence
        .iter()
        .find(|e| e.field == "alert_type")
        .expect("alert_type evidence");
    assert_eq!(
        alert_type.redacted_value,
        "scanner_error_threshold_exceeded"
    );

    let threshold = event
        .evidence
        .iter()
        .find(|e| e.field == "threshold")
        .expect("threshold evidence");
    assert_eq!(threshold.redacted_value, "max_scanner_errors=3");

    let actual = event
        .evidence
        .iter()
        .find(|e| e.field == "actual_value")
        .expect("actual_value evidence");
    assert_eq!(actual.redacted_value, "scanner_error_count=5");

    let error_count = event
        .evidence
        .iter()
        .find(|e| e.field == "scanner_error_count")
        .expect("scanner_error_count evidence");
    assert_eq!(error_count.redacted_value, "5");

    let duration = event
        .evidence
        .iter()
        .find(|e| e.field == "scan_duration_ms")
        .expect("scan_duration_ms evidence");
    assert_eq!(duration.redacted_value, "1500");
}

#[test]
fn operational_alert_event_includes_duration_evidence() {
    let event = operational_alert_event(OperationalAlertInput {
        alert_type: "scan_duration_threshold_exceeded".to_string(),
        threshold: "max_scan_duration_ms=300000".to_string(),
        actual_value: "scan_duration_ms=600000".to_string(),
        scan_duration_ms: Some(600_000),
        scanner_error_count: None,
    });

    assert_eq!(event.event_type, "operational_alert");
    assert_eq!(event.severity, "warning");
    assert_eq!(event.check_name.as_deref(), Some("scan_duration_threshold"));
    assert_eq!(event.status.as_deref(), Some("degraded"));
    assert!(event.evidence.iter().any(|e| e.field == "scan_duration_ms"));
    assert!(
        event
            .evidence
            .iter()
            .all(|e| e.field != "scanner_error_count")
    );
}

#[test]
fn operational_alert_config_defaults() {
    let config = super::OperationalAlertConfig::default();
    assert_eq!(config.max_scanner_errors, 3);
    assert_eq!(config.max_scan_duration_ms, 300_000);
}

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
        super::TEXT_BEARING_EVENT_TYPES
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

#[test]
fn direct_event_serialization_replaces_malformed_percent_encoded_url_authorities() {
    let path_marker = "TT_PRIVACY_PATH_25";
    let query_marker = "TT_PRIVACY_QUERY_25";
    let event = activity_event(ActivityEventInput {
            client: ClientId::Codex,
            agent: None,
            model: None,
            provider: None,
            session_id: "opaque-session".to_string(),
            source_path_hash: "source-hash".to_string(),
            tool_name: Some("shell".to_string()),
            tags: Vec::new(),
            evidence: vec![Evidence {
                field: "url".to_string(),
                redacted_value: format!(
                    "https://@/home/{path_marker}/.ssh/id_rsa?token={query_marker} https://example.invalid%2Fhome%2F{path_marker}%2F.ssh%2Fid_rsa"
                ),
                hash: None,
                rule_id: None,
            }],
            risk_contributions: Vec::new(),
            event_time: None,
        })
        .expect("activity event");

    let bytes = serde_json::to_vec(&event).expect("direct event serialization");
    assert!(
        check_serialized_event_markers(
            &bytes,
            "direct-malformed-url-authority",
            &[
                ControlledMarker {
                    id: "path",
                    value: path_marker,
                },
                ControlledMarker {
                    id: "query",
                    value: query_marker,
                },
            ],
        )
        .is_ok(),
        "direct Event serialization retained a malformed URL authority marker"
    );
    let serialized: serde_json::Value =
        serde_json::from_slice(&bytes).expect("serialized Event JSON");
    assert_eq!(
        serialized["evidence"][0]["redacted_value"],
        "[redacted-url] [redacted-url]"
    );
}

#[test]
fn direct_event_serialization_replaces_fully_encoded_url_authority_candidates() {
    let marker = "TT_PRIVACY_DIRECT_ENCODED_AUTHORITY_25";
    let cases = [
        format!("https%3A%2F%2Fexample.invalid%252F{marker}%2Fsafe"),
        format!("https%3A%2F%2Fexample.invalid%255C{marker}%2Fsafe"),
        format!("https%3A%2F%2Fexample.invalid%253Fnext%253D{marker}%2Fsafe"),
        format!("https%3A%2F%2Fexample.invalid%2523safe%253D{marker}%2Fsafe"),
        format!("https%3A%2F%2Fexample.invalid%2540{marker}%2Fsafe"),
        format!("https%3A%2F%2Fexample.invalid%252f{marker}%2Fsafe"),
        format!("https%253A%252F%252Fexample.invalid%25252F{marker}%252Fsafe"),
    ];
    let event = activity_event(ActivityEventInput {
        client: ClientId::Codex,
        agent: None,
        model: None,
        provider: None,
        session_id: "opaque-session".to_string(),
        source_path_hash: "source-hash".to_string(),
        tool_name: Some("shell".to_string()),
        tags: Vec::new(),
        evidence: vec![Evidence {
            field: "url".to_string(),
            redacted_value: cases.join(" "),
            hash: None,
            rule_id: None,
        }],
        risk_contributions: Vec::new(),
        event_time: None,
    })
    .expect("activity event");

    let bytes = serde_json::to_vec(&event).expect("direct event serialization");
    assert!(
        check_serialized_event_markers(
            &bytes,
            "direct-fully-encoded-url-authority",
            &[ControlledMarker {
                id: "authority",
                value: marker,
            }],
        )
        .is_ok(),
        "direct Event serialization retained a fully encoded URL authority marker"
    );
    let serialized: serde_json::Value =
        serde_json::from_slice(&bytes).expect("serialized Event JSON");
    assert_eq!(
        serialized["evidence"][0]["redacted_value"],
        "[redacted-url] [redacted-url] [redacted-url] [redacted-url] [redacted-url] [redacted-url] [redacted-url]"
    );
}

#[test]
fn direct_event_serialization_redacts_encoded_url_candidate_prefix_forms_atomically() {
    let path_marker = "TT_PRIVACY_DIRECT_ENCODED_CANDIDATE_PATH_25";
    let authority_marker = "TT_PRIVACY_DIRECT_ENCODED_CANDIDATE_AUTHORITY_25";
    let evidence = format!(
        "%68%74%74%70%73%3A%2F%2Fexample.invalid%2Fhome%2F{path_marker}%2F.ssh%2Fid_rsa https%3A//example.invalid%252Fhome%252F{authority_marker}%252F.ssh%252Fid_rsa"
    );
    let event = activity_event(ActivityEventInput {
        client: ClientId::Codex,
        agent: None,
        model: None,
        provider: None,
        session_id: "opaque-session".to_string(),
        source_path_hash: "source-hash".to_string(),
        tool_name: Some("shell".to_string()),
        tags: Vec::new(),
        evidence: vec![Evidence {
            field: "url".to_string(),
            redacted_value: evidence,
            hash: None,
            rule_id: None,
        }],
        risk_contributions: Vec::new(),
        event_time: None,
    })
    .expect("activity event");

    let bytes = serde_json::to_vec(&event).expect("direct event serialization");
    assert!(
        check_serialized_event_markers(
            &bytes,
            "direct-encoded-url-candidate-prefix",
            &[
                ControlledMarker {
                    id: "path",
                    value: path_marker,
                },
                ControlledMarker {
                    id: "authority",
                    value: authority_marker,
                },
            ],
        )
        .is_ok(),
        "direct Event serialization retained an encoded URL candidate marker"
    );
    let serialized: serde_json::Value =
        serde_json::from_slice(&bytes).expect("serialized Event JSON");
    assert_eq!(
        serialized["evidence"][0]["redacted_value"],
        "https://example.invalid/[sensitive-path] [redacted-url]"
    );
    assert_eq!(
        serde_json::to_vec(&event).expect("repeat direct Event serialization"),
        bytes,
        "direct Event serialization was not stable"
    );
}

#[test]
fn terminal_session_policy_rejects_assignment_token_and_credential_url_forms() {
    let sessions = [
        "TOKEN=TT_PRIVACY_NATIVE_SESSION_ASSIGNMENT_25",
        "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz12",
        "https://user:TT_PRIVACY_NATIVE_SESSION_URL_25@session.example.invalid",
    ];

    for (index, session) in sessions.into_iter().enumerate() {
        let event = activity_event(ActivityEventInput {
            client: ClientId::Codex,
            agent: Some("codex".to_string()),
            model: Some("gpt-5".to_string()),
            provider: Some("openai".to_string()),
            session_id: session.to_string(),
            source_path_hash: "source-hash".to_string(),
            tool_name: Some("shell".to_string()),
            tags: Vec::new(),
            evidence: Vec::new(),
            risk_contributions: Vec::new(),
            event_time: None,
        })
        .expect("activity event");
        let bytes = serde_json::to_vec(&event).expect("serialize event");
        let emitted: serde_json::Value =
            serde_json::from_slice(&bytes).expect("serialized event JSON");
        assert!(
            check_serialized_event_markers(
                &bytes,
                &format!("native-session-{index}"),
                &[ControlledMarker {
                    id: "session",
                    value: session,
                }],
            )
            .is_ok(),
            "native event retained a credential-shaped session"
        );
        assert_eq!(emitted["session_id"], terminal_session_id(session));
        assert!(
            emitted["session_id"]
                .as_str()
                .is_some_and(|value| value.starts_with("[session:"))
        );
    }
}

#[test]
fn correlation_evidence_applies_the_shared_session_and_identifier_policies() {
    let session = "TOKEN=TT_PRIVACY_CORRELATION_SESSION_25";
    let event_id = "sk-abcdefghijklmnop";
    let event = correlation_event(CorrelationEventInput {
        client: "codex".to_string(),
        agent: None,
        model: None,
        provider: None,
        shared_rule_ids: vec!["rule.privacy".to_string()],
        sessions: vec![
            CorrelationSessionInput {
                session_id: session.to_string(),
                event_id: event_id.to_string(),
                timestamp: "2026-05-01T00:00:00Z".to_string(),
                severity: "high".to_string(),
                risk_score: 80,
            },
            CorrelationSessionInput {
                session_id: "safe-session".to_string(),
                event_id: "safe-event".to_string(),
                timestamp: "2026-05-01T00:01:00Z".to_string(),
                severity: "low".to_string(),
                risk_score: 20,
            },
        ],
        window_start: "2026-05-01T00:00:00Z".to_string(),
        window_end: "2026-05-01T00:01:00Z".to_string(),
        max_risk_score: 80,
    })
    .expect("correlation event");
    assert!(event.evidence[2].redacted_value.contains(session));
    assert!(event.evidence[2].redacted_value.contains(event_id));

    let emitted = serde_json::to_value(&event).expect("serialize correlation");
    let related = emitted["evidence"][2]["redacted_value"]
        .as_str()
        .expect("related detection evidence");
    assert!(!related.contains(session));
    assert!(!related.contains(event_id));
    assert!(related.contains(&terminal_session_id(session)));
    assert!(related.contains(&terminal_identifier("event", event_id)));

    let mut imported = emitted.clone();
    sanitize_serialized_event(&mut imported);
    assert_eq!(
        imported["evidence"][2]["redacted_value"], emitted["evidence"][2]["redacted_value"],
        "canonical correlation identities must survive historical re-export"
    );
}

#[test]
fn historical_correlation_client_identity_is_opaque() {
    let client = "customer_internal_tenant";
    let mut historical = serde_json::json!({
        "schema_version": "2.0",
        "event_type": "correlation",
        "client": client,
    });

    sanitize_serialized_event(&mut historical);

    assert_eq!(historical["client"], opaque_identifier("client", client));
}

#[test]
fn source_values_cannot_spoof_terminal_opaque_session_or_product_markers() {
    let forged_hash = "a".repeat(64);
    let forged_session = format!("[session:{forged_hash}]");
    let forged_model = format!("[model:{forged_hash}]");

    assert_ne!(terminal_session_id(&forged_session), forged_session);
    assert_ne!(
        terminal_product_metadata("model", &forged_model),
        forged_model
    );

    let mut legacy = serde_json::json!({
        "schema_version": "2.0",
        "session_id": forged_session.clone(),
        "extension": forged_model.clone(),
    });
    sanitize_serialized_event(&mut legacy);
    assert_ne!(legacy["session_id"], forged_session);
    assert_ne!(legacy["extension"], forged_model);
}

#[test]
fn historical_canonical_markers_are_idempotent_unauthenticated_labels() {
    let session = format!("[session:{}]", "a".repeat(64));
    let model = format!("[model:{}]", "b".repeat(64));
    let key = format!("[metadata-key:{}]", "c".repeat(64));
    let mut historical = serde_json::json!({
        "schema_version": "3.0",
        "event_type": "activity",
        "session_id": session,
        "model": model,
        key.clone(): "safe",
    });

    for _ in 0..3 {
        sanitize_serialized_event(&mut historical);
    }

    assert_eq!(historical["session_id"], session);
    assert_eq!(historical["model"], model);
    assert_eq!(historical[&key], "safe");
}

#[test]
fn historical_typed_markers_are_exact_kind_scoped_and_idempotent() {
    let marker = |kind| opaque_identifier(kind, &format!("{kind} source value"));
    let agent = marker("agent");
    let model = marker("model");
    let provider = marker("provider");
    let client = marker("client");
    let session = marker("session");
    let tool = marker("tool");
    let category = marker("category");
    let tag = marker("tag");
    let suppression = marker("suppression");
    let evidence_field = marker("evidence-field");
    let invalid_time = marker("invalid-event-time");
    let process = marker("process");
    let host = marker("host");
    let user = marker("user");
    let source_event = marker("source-event");
    let dedup = marker("dedup");
    let process_rule = marker("process-rule");
    let process_config = marker("process-config");
    let process_adjustment = marker("process-adjustment");
    let policy = marker("policy");
    let extension = marker("metadata-key");
    let mut historical = serde_json::json!({
        "schema_version": "3.0",
        "event_type": "detection",
        "event_time": invalid_time,
        "agent": agent,
        "model": model,
        "provider": provider,
        "client": client,
        "session_id": session,
        "tool_name": tool,
        "categories": [category],
        "tags": [tag, format!("allowlist:{suppression}")],
        "active_policy_name": policy,
        "risk_entity_type": "session",
        "risk_entity_value": session,
        "evidence": [{
            "field": evidence_field,
            "redacted_value": "safe",
        }, {
            "field": "allowlist",
            "redacted_value": suppression,
        }],
        "process": {
            "host": host,
            "user": user,
            "source_process_name": process,
            "target_process_name": process,
            "parent_process_name": process,
            "source_event_id": source_event,
            "dedup_key": dedup,
            "rule_name": process_rule,
            "investigation_fields": [process_config],
            "falsepositives": [process_config],
            "risk_adjustment": process_adjustment,
        },
        "timeline_anchors": [{
            "rule_ids": ["rule.test"],
            "categories": [category],
            "evidence_fields": [evidence_field],
        }],
        "extension": extension,
    });
    let expected = historical.clone();

    sanitize_serialized_event(&mut historical);
    assert_eq!(historical, expected);
    sanitize_serialized_event(&mut historical);
    assert_eq!(historical, expected);

    let wrong_kind = marker("session");
    let mut wrong = serde_json::json!({
        "schema_version": "3.0",
        "event_time": wrong_kind,
        "tool_name": wrong_kind,
        "categories": [wrong_kind],
        "tags": [wrong_kind],
        "evidence": [{ "field": wrong_kind, "redacted_value": "safe" }],
        "process": { "source_process_name": wrong_kind },
        "timeline_anchors": [{
            "rule_ids": ["rule.test"],
            "categories": [wrong_kind],
            "evidence_fields": [wrong_kind],
        }],
    });
    sanitize_serialized_event(&mut wrong);
    assert_ne!(wrong["event_time"], wrong_kind);
    assert_ne!(wrong["tool_name"], wrong_kind);
    assert_ne!(wrong["categories"][0], wrong_kind);
    assert_ne!(wrong["tags"][0], wrong_kind);
    assert_ne!(wrong["evidence"][0]["field"], wrong_kind);
    assert_ne!(wrong["process"]["source_process_name"], wrong_kind);
    assert_ne!(wrong["timeline_anchors"][0]["categories"][0], wrong_kind);
    assert_ne!(
        wrong["timeline_anchors"][0]["evidence_fields"][0],
        wrong_kind
    );
}

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

#[test]
fn historical_canonical_hashes_and_terminal_identities_are_preserved() {
    let source_hash = "a".repeat(64);
    let evidence_hash = "b".repeat(64);
    let session = format!("[session:{}]", "c".repeat(64));
    let mut event = serde_json::json!({
        "schema_version": "3.0",
        "event_type": "activity",
        "session_id": session,
        "source_path_hash": source_hash,
        "evidence": [{
            "field": "arguments",
            "redacted_value": "safe",
            "hash": evidence_hash
        }]
    });

    sanitize_serialized_event(&mut event);

    assert_eq!(event["session_id"], session);
    assert_eq!(event["source_path_hash"], source_hash);
    assert_eq!(event["evidence"][0]["hash"], evidence_hash);
}

#[test]
fn terminal_product_metadata_preserves_known_ids_and_rejects_credentials() {
    let credential_model = "gpt-5-ghp_AbCdEfGhIjKlMnOpQrStUvWxYz12";
    assert_eq!(terminal_product_metadata("agent", "codex"), "codex");
    assert_eq!(terminal_product_metadata("model", "gpt-5"), "gpt-5");
    assert_eq!(terminal_product_metadata("provider", "openai"), "openai");
    assert!(terminal_product_metadata("model", credential_model).starts_with("[model:"));
    assert!(terminal_product_metadata("agent", "TOKEN=short").starts_with("[agent:"));
    assert!(
        terminal_product_metadata("provider", "https://user:pass@host.invalid")
            .starts_with("[provider:")
    );

    let event = activity_event(ActivityEventInput {
        client: ClientId::Codex,
        agent: Some("codex".to_string()),
        model: Some(credential_model.to_string()),
        provider: Some("openai".to_string()),
        session_id: "safe-session".to_string(),
        source_path_hash: "source-hash".to_string(),
        tool_name: Some("shell".to_string()),
        tags: Vec::new(),
        evidence: Vec::new(),
        risk_contributions: Vec::new(),
        event_time: None,
    })
    .expect("activity event");
    let bytes = serde_json::to_vec(&event).expect("serialize event");
    assert!(
        check_serialized_event_markers(
            &bytes,
            "credential-model",
            &[ControlledMarker {
                id: "model",
                value: credential_model,
            }],
        )
        .is_ok()
    );
}

#[test]
fn terminal_event_serialization_hashes_unsafe_sessions_but_keeps_safe_product_metadata() {
    let unsafe_session = "TT_PRIVACY_UNSAFE_SESSION_25";
    let event = activity_event(ActivityEventInput {
        client: ClientId::Codex,
        agent: Some("codex".to_string()),
        model: Some("gpt-5".to_string()),
        provider: Some("openai".to_string()),
        session_id: unsafe_session.to_string(),
        source_path_hash: "source-hash".to_string(),
        tool_name: Some("shell".to_string()),
        tags: Vec::new(),
        evidence: Vec::new(),
        risk_contributions: Vec::new(),
        event_time: None,
    })
    .expect("activity event");
    let bytes = serde_json::to_vec(&event).expect("serialize event");
    let emitted: serde_json::Value = serde_json::from_slice(&bytes).expect("event JSON");

    assert!(
        check_serialized_event_markers(
            &bytes,
            "unsafe-session",
            &[ControlledMarker {
                id: "unsafe-session",
                value: unsafe_session,
            }],
        )
        .is_ok(),
        "serialized event retained an unsafe session marker"
    );
    assert_eq!(emitted["agent"], "codex");
    assert_eq!(emitted["model"], "gpt-5");
    assert_eq!(emitted["provider"], "openai");
    assert_eq!(
        emitted["session_id"],
        format!(
            "[session:{}]",
            evidence_hash(&format!("session-id:v1\0{unsafe_session}"))
        )
    );
    assert_eq!(event.session_id, unsafe_session);
}
