use super::*;

#[test]
fn canonical_jsonl_persists_only_sanitized_event_bytes() {
    let marker = "TT_PRIVACY_JSONL_25";
    let mut event = crate::event::activity_event(ActivityEventInput {
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
            redacted_value: format!(
                "delivery=https://user:{marker}@example.invalid/?%74%6f%6b%65%6e={marker}"
            ),
            hash: None,
            rule_id: None,
        }],
        risk_contributions: Vec::new(),
        event_time: None,
    })
    .expect("activity event");
    event.tags.push(format!("allowlist:{marker}"));
    event.evidence.push(Evidence {
        field: "allowlist".to_string(),
        redacted_value: marker.to_string(),
        hash: None,
        rule_id: None,
    });
    let expected = serialize_jsonl_events(std::slice::from_ref(&event)).expect("serialize event");
    let directory = tempdir().expect("temporary directory");
    let path = directory.path().join("events.jsonl");

    append_jsonl_events(&path, &[event]).expect("append canonical JSONL");
    let persisted = fs::read(path).expect("read canonical JSONL");

    assert_eq!(persisted, expected);
    assert!(
        check_serialized_event_markers(
            &persisted,
            "canonical-jsonl",
            &[ControlledMarker {
                id: "jsonl-marker",
                value: marker,
            }],
        )
        .is_ok()
    );
}

#[test]
fn canonical_jsonl_stores_the_terminal_emission_bytes() {
    let marker = "TT_PRIVACY_JSONL_STORED_BYTES_26";
    let event = crate::event::activity_event(ActivityEventInput {
        client: ClientId::Codex,
        agent: None,
        model: None,
        provider: None,
        session_id: "synthetic-jsonl-session".to_string(),
        source_path_hash: "synthetic-jsonl-source".to_string(),
        tool_name: Some("shell".to_string()),
        tags: vec![format!("controlled:{marker}")],
        evidence: vec![Evidence {
            field: "tool_result".to_string(),
            redacted_value: format!("SECRET={marker}"),
            hash: None,
            rule_id: None,
        }],
        risk_contributions: Vec::new(),
        event_time: None,
    })
    .expect("activity event");
    let mut canonical = Vec::new();
    let mut serializer = serde_json::Serializer::new(&mut canonical);
    serialize_event_for_emission(&event, &mut serializer).expect("terminal Event 3.0");
    let directory = tempdir().expect("temporary directory");
    let path = directory.path().join("events.jsonl");

    append_jsonl_events(&path, std::slice::from_ref(&event)).expect("append JSONL");
    let stored = fs::read(&path).expect("read stored JSONL bytes");

    assert_eq!(stored, [canonical.as_slice(), b"\n"].concat());
    assert_eq!(stored.strip_suffix(b"\n"), Some(canonical.as_slice()));
    assert!(
        check_serialized_event_markers(
            &stored,
            "canonical-jsonl-stored-bytes",
            &[ControlledMarker {
                id: "stored-bytes-marker",
                value: marker,
            }],
        )
        .is_ok()
    );
}

#[test]
fn canonical_jsonl_preserves_source_count_values_across_key_collisions() {
    let marker = "TT_PRIVACY_JSONL_SOURCE_COUNTS_KEY_30";
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
        threshold_config: telltale_schema::scoring::load_thresholds(),
        active_policy_name: None,
        emitted_count: 0,
        suppressed_count: 0,
        scanner_error_count: 0,
    });
    event.source_counts = Some(source_counts);
    let expected =
        serialize_jsonl_events(std::slice::from_ref(&event)).expect("serialize canonical JSONL");
    let directory = tempdir().expect("temporary directory");
    let path = directory.path().join("health-events.jsonl");

    append_jsonl_events(&path, std::slice::from_ref(&event)).expect("append health JSONL");
    let stored = fs::read(&path).expect("read health JSONL");
    assert_eq!(stored, expected);
    assert_eq!(
        serialize_jsonl_events(std::slice::from_ref(&event)).expect("repeat JSONL serialization"),
        stored
    );
    assert!(
        check_serialized_event_markers(
            &stored,
            "canonical-jsonl-source-count-key",
            &[ControlledMarker {
                id: "source-count-key",
                value: marker,
            }],
        )
        .is_ok()
    );

    let serialized: serde_json::Value =
        serde_json::from_slice(stored.strip_suffix(b"\n").expect("JSONL newline"))
            .expect("serialized health Event");
    let counts = serialized["source_counts"]
        .as_object()
        .expect("serialized source counts");
    assert_eq!(counts[&canonical_fallback], 5);
    assert_eq!(counts[&canonical_collision], 7);
    assert_eq!(counts["codex.jsonl"], 11);
    assert_eq!(counts[&format!("{canonical_fallback}:3")], 3);
    assert_eq!(
        counts
            .values()
            .filter_map(serde_json::Value::as_u64)
            .sum::<u64>(),
        26
    );
}

#[test]
fn canonical_jsonl_persists_the_trusted_telltale_version() {
    let credential_version = format!("1.2.3-AKIA{}", "T".repeat(16));
    let mut event = health_event_with_metadata(HealthEventInput {
        sources: &[],
        source_inventory_change: None,
        scan_duration_ms: 0,
        rule_count: 0,
        threshold_config: telltale_schema::scoring::load_thresholds(),
        active_policy_name: None,
        emitted_count: 0,
        suppressed_count: 0,
        scanner_error_count: 0,
    });
    event.telltale_version = credential_version.clone();
    let expected =
        serialize_jsonl_events(std::slice::from_ref(&event)).expect("serialize canonical JSONL");
    let directory = tempdir().expect("temporary directory");
    let path = directory.path().join("version-events.jsonl");

    append_jsonl_events(&path, std::slice::from_ref(&event)).expect("append canonical JSONL");
    let stored = fs::read(&path).expect("read canonical JSONL");
    assert_eq!(stored, expected);
    assert_eq!(
        serialize_jsonl_events(std::slice::from_ref(&event)).expect("repeat JSONL serialization"),
        stored
    );
    assert!(!String::from_utf8_lossy(&stored).contains(&credential_version));
    let emitted: serde_json::Value =
        serde_json::from_slice(stored.strip_suffix(b"\n").expect("JSONL newline"))
            .expect("serialized health Event");
    assert_eq!(emitted["telltale_version"], TELLTALE_VERSION);
}

#[test]
fn canonical_jsonl_terminalizes_invalid_event_time_without_leaking_it() {
    let marker = "TT_PRIVACY_JSONL_EVENT_TIME_32";
    let event = crate::event::activity_event(ActivityEventInput {
        client: ClientId::Codex,
        agent: None,
        model: None,
        provider: None,
        session_id: "jsonl-event-time-session".to_string(),
        source_path_hash: "jsonl-event-time-source".to_string(),
        tool_name: Some("shell".to_string()),
        tags: Vec::new(),
        evidence: Vec::new(),
        risk_contributions: Vec::new(),
        event_time: Some(marker.to_string()),
    })
    .expect("activity event");
    let directory = tempdir().expect("temporary directory");
    let path = directory.path().join("event-time.jsonl");

    append_jsonl_events(&path, std::slice::from_ref(&event)).expect("append JSONL");
    let stored = fs::read(&path).expect("read JSONL");
    assert!(!String::from_utf8_lossy(&stored).contains(marker));
    let emitted: serde_json::Value =
        serde_json::from_slice(stored.strip_suffix(b"\n").expect("JSONL newline"))
            .expect("event JSON");
    assert!(
        emitted["event_time"]
            .as_str()
            .is_some_and(|value| value.starts_with("[invalid-event-time:"))
    );
}
