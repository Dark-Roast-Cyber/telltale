use super::*;

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

    let text_bearing_event_types = super::super::TEXT_BEARING_EVENT_TYPES
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
        super::super::require_constructor_coverage(
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
    assert!(super::super::contains_credential_material(
        &credential_version
    ));
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
