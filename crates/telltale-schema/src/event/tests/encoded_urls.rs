use super::*;

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
