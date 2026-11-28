use super::*;

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
