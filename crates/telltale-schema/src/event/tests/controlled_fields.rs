use super::*;

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
        super::super::serialized_value_context("unknown_extension", true),
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
