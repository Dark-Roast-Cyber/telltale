use super::*;

#[test]
fn canonical_jsonl_drops_partial_truncated_url_credential_prefix() {
    const INPUT_CAP: usize = 4096;
    let tail = "https://uTT_PRIVACY_JSONL_TAIL_25";
    let start = INPUT_CAP - 10;
    let input = format!(
        "safe-prefix{}{}",
        " ".repeat(start - "safe-prefix".len()),
        tail
    );
    let retained_prefix = &tail[..INPUT_CAP - start];
    let event = crate::event::activity_event(ActivityEventInput {
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
            redacted_value: input,
            hash: None,
            rule_id: None,
        }],
        risk_contributions: Vec::new(),
        event_time: None,
    })
    .expect("activity event");
    let directory = tempdir().expect("temporary directory");
    let path = directory.path().join("events.jsonl");

    append_jsonl_events(&path, &[event]).expect("append canonical JSONL");
    let persisted = fs::read_to_string(path).expect("read canonical JSONL");

    assert!(!persisted.contains(retained_prefix));
    assert!(persisted.contains("safe-prefix"));
    assert!(!persisted.contains(tail));
}

#[test]
fn canonical_jsonl_hides_sensitive_filesystem_paths_inside_urls() {
    let marker = "TT_PRIVACY_JSONL_URL_PATH_USER_25";
    let directory = tempdir().expect("temporary directory");
    let path = directory.path().join("events.jsonl");
    let event = crate::event::activity_event(ActivityEventInput {
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
            redacted_value: format!("https://example.invalid/home/{marker}/.ssh/id_rsa?mode=view"),
            hash: None,
            rule_id: None,
        }],
        risk_contributions: Vec::new(),
        event_time: None,
    })
    .expect("activity event");

    append_jsonl_events(&path, &[event]).expect("append canonical JSONL");
    let persisted = fs::read(path).expect("read canonical JSONL");
    assert!(!String::from_utf8_lossy(&persisted).contains(marker));
    assert!(String::from_utf8_lossy(&persisted).contains("[sensitive-path]"));
}

#[test]
fn canonical_jsonl_replaces_malformed_percent_encoded_url_authorities() {
    let path_marker = "TT_PRIVACY_PATH_25";
    let query_marker = "TT_PRIVACY_QUERY_25";
    let directory = tempdir().expect("temporary directory");
    let path = directory.path().join("events.jsonl");
    let event = crate::event::activity_event(ActivityEventInput {
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

    append_jsonl_events(&path, &[event]).expect("append canonical JSONL");
    let persisted = fs::read(path).expect("read canonical JSONL");
    assert!(
        check_serialized_event_markers(
            &persisted,
            "canonical-malformed-url-authority",
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
        "canonical JSONL retained a malformed URL authority marker"
    );
    assert!(String::from_utf8_lossy(&persisted).contains("[redacted-url]"));
}

#[test]
fn canonical_jsonl_replaces_fully_encoded_url_authority_candidates() {
    let marker = "TT_PRIVACY_JSONL_ENCODED_AUTHORITY_25";
    let cases = [
        format!("https%3A%2F%2Fexample.invalid%252F{marker}%2Fsafe"),
        format!("https%3A%2F%2Fexample.invalid%255C{marker}%2Fsafe"),
        format!("https%3A%2F%2Fexample.invalid%253Fnext%253D{marker}%2Fsafe"),
        format!("https%3A%2F%2Fexample.invalid%2523safe%253D{marker}%2Fsafe"),
        format!("https%3A%2F%2Fexample.invalid%2540{marker}%2Fsafe"),
        format!("https%3A%2F%2Fexample.invalid%252f{marker}%2Fsafe"),
        format!("https%253A%252F%252Fexample.invalid%25252F{marker}%252Fsafe"),
    ];
    let directory = tempdir().expect("temporary directory");
    let path = directory.path().join("events.jsonl");
    let event = crate::event::activity_event(ActivityEventInput {
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
            redacted_value: cases.join(" "),
            hash: None,
            rule_id: None,
        }],
        risk_contributions: Vec::new(),
        event_time: None,
    })
    .expect("activity event");

    append_jsonl_events(&path, &[event]).expect("append canonical JSONL");
    let persisted = fs::read(path).expect("read canonical JSONL");
    assert!(
        check_serialized_event_markers(
            &persisted,
            "canonical-fully-encoded-url-authority",
            &[ControlledMarker {
                id: "authority",
                value: marker,
            }],
        )
        .is_ok(),
        "canonical JSONL retained a fully encoded URL authority marker"
    );
    let persisted_event: serde_json::Value =
        serde_json::from_slice(&persisted).expect("canonical JSONL event");
    assert_eq!(
        persisted_event["evidence"][0]["redacted_value"],
        "[redacted-url] [redacted-url] [redacted-url] [redacted-url] [redacted-url] [redacted-url] [redacted-url]"
    );
}

#[test]
fn canonical_jsonl_redacts_encoded_url_candidate_prefix_forms_atomically() {
    let path_marker = "TT_PRIVACY_JSONL_ENCODED_CANDIDATE_PATH_25";
    let authority_marker = "TT_PRIVACY_JSONL_ENCODED_CANDIDATE_AUTHORITY_25";
    let directory = tempdir().expect("temporary directory");
    let path = directory.path().join("events.jsonl");
    let event = crate::event::activity_event(ActivityEventInput {
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
            redacted_value: format!(
                "https:%2F%2Fexample.invalid%2Fhome%2F{path_marker}%2F.ssh%2Fid_rsa https%3A//example.invalid%252Fhome%252F{authority_marker}%252F.ssh%252Fid_rsa"
            ),
            hash: None,
            rule_id: None,
        }],
        risk_contributions: Vec::new(),
        event_time: None,
    })
    .expect("activity event");

    append_jsonl_events(&path, std::slice::from_ref(&event)).expect("append canonical JSONL");
    let persisted = fs::read(&path).expect("read canonical JSONL");
    assert!(
        check_serialized_event_markers(
            &persisted,
            "canonical-encoded-url-candidate-prefix",
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
        "canonical JSONL retained an encoded URL candidate marker"
    );
    let persisted_event: serde_json::Value =
        serde_json::from_slice(&persisted).expect("canonical JSONL event");
    assert_eq!(
        persisted_event["evidence"][0]["redacted_value"],
        "https://example.invalid/[sensitive-path] [redacted-url]"
    );
}

#[test]
fn canonical_jsonl_redacts_nested_encoded_urls_inside_outer_components() {
    let marker = "TT_PRIVACY_JSONL_NESTED_BOUNDARY_25";
    let values = [
        format!("https://outer.invalid/?next=https%3A%2F%2Finner.invalid%252F{marker}"),
        format!("https://outer.invalid/redirect/https%3A%2F%2Finner.invalid%252F{marker}"),
        format!("https://outer.invalid/#next=https%3A%2F%2Finner.invalid%2523token%253D{marker}"),
    ];
    let directory = tempdir().expect("temporary directory");
    let path = directory.path().join("events.jsonl");
    let event = crate::event::activity_event(ActivityEventInput {
        client: ClientId::Codex,
        agent: None,
        model: None,
        provider: None,
        session_id: "nested-jsonl-session".to_string(),
        source_path_hash: "nested-jsonl-source".to_string(),
        tool_name: Some("shell".to_string()),
        tags: Vec::new(),
        evidence: vec![Evidence {
            field: "url".to_string(),
            redacted_value: values.join(" "),
            hash: None,
            rule_id: None,
        }],
        risk_contributions: Vec::new(),
        event_time: None,
    })
    .expect("nested URL activity event");

    append_jsonl_events(&path, std::slice::from_ref(&event)).expect("append nested URLs");
    let persisted = fs::read(&path).expect("read nested URL JSONL");
    assert!(
        check_serialized_event_markers(
            &persisted,
            "canonical-jsonl-nested-url-components",
            &[ControlledMarker {
                id: "nested-url",
                value: marker,
            }],
        )
        .is_ok(),
        "canonical JSONL retained a nested URL marker"
    );
    let persisted_text = String::from_utf8_lossy(&persisted);
    assert!(
        !persisted_text.contains("https%3A%2F%2Finner.invalid"),
        "canonical JSONL retained a nested encoded URL prefix"
    );
    assert!(persisted_text.contains("[redacted-url]"));
    assert_eq!(
        persisted,
        serialize_jsonl_events(std::slice::from_ref(&event)).expect("repeat nested URLs"),
        "canonical JSONL serialization must be idempotent"
    );
}
