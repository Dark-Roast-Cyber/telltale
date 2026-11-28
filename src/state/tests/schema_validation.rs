use super::*;

#[test]
fn older_baseline_schema_is_rejected_without_reset_and_current_state_round_trips() {
    let mut state = ScanState::default();
    state
        .seen_source_fingerprints
        .insert("synthetic-source".into());
    state
        .seen_detection_fingerprints
        .insert("synthetic-detection".into());
    let source = Source {
        client: ClientId::OpenCode,
        kind: SourceKind::Sqlite,
        source_id: "opencode.sqlite".into(),
        path: "synthetic.db".into(),
    };
    state.observe_sources(std::slice::from_ref(&source), 12);
    state.observe_sqlite_ingestion_cursor(&source, "part", 42, 12);
    state
        .record_baseline_source_contribution(
            &source,
            "old".into(),
            vec![BaselineSummary::default()],
        )
        .unwrap();
    state
        .rebuild_baseline_snapshots_from_source_contributions()
        .unwrap();
    let current = state.canonical_bytes().unwrap();
    let reloaded = ScanState::validate_native_bytes(&current).unwrap();
    assert_eq!(reloaded.baseline_snapshots.schema_version, 3);
    assert_eq!(reloaded.baseline_source_contributions.len(), 1);
    assert_eq!(reloaded.canonical_bytes().unwrap(), current);

    let mut legacy: Value = serde_json::from_slice(&current).unwrap();
    legacy["baseline_snapshots"]["schema_version"] = 2.into();
    let bytes = serde_json::to_vec(&legacy).unwrap();
    let error = ScanState::validate_native_bytes(&bytes).unwrap_err();
    assert!(error.to_string().contains("older format"));
    assert!(error.to_string().contains("v0.7.0"));
    assert!(error.to_string().contains("was not changed"));
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("schema2.json");
    std::fs::write(&path, &bytes).expect("write older state");
    assert!(ScanState::load(&path).is_err());
    assert_eq!(std::fs::read(&path).expect("unchanged"), bytes);
}

#[test]
fn missing_state_initializes_without_creating_a_file_until_save() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("missing.json");
    let state = ScanState::load_snapshot(&path).expect("missing state initializes");
    assert!(state.seen_source_fingerprints.is_empty());
    assert!(!path.exists());
    state.save(&path).expect("save initialized state");
    let bytes = std::fs::read(&path).expect("saved state");
    assert!(ScanState::validate_native_bytes(&bytes).is_ok());
    assert_eq!(
        std::fs::read(&path).expect("unchanged after validation"),
        bytes
    );
}

#[test]
fn rejects_empty_state_file_without_rewriting_it() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("empty-state.json");
    std::fs::write(&path, "").expect("write empty");

    let error = ScanState::load(&path).expect_err("empty state must fail");
    assert!(error.to_string().contains("invalid"));
    assert!(error.to_string().contains("was not changed"));
    assert!(!error.to_string().contains("v0.7.0"));
    assert_eq!(std::fs::read(&path).expect("unchanged"), b"");
}

#[test]
fn native_state_requires_version_and_rejects_recursive_unknown_fields() {
    let state = ScanState::default();
    let native = state.canonical_bytes().expect("native bytes");
    assert!(ScanState::validate_native_bytes(&native).is_ok());

    let mut observed = ScanState::default();
    observed.source_observations.insert(
        "source".to_string(),
        super::super::SourceObservation {
            client: "codex".to_string(),
            source_id: "source".to_string(),
            source_instance_id: "instance".to_string(),
            last_seen_unix_ms: 1,
        },
    );
    let mut missing_nested = serde_json::to_value(&observed).expect("state value");
    missing_nested["source_observations"]["source"]
        .as_object_mut()
        .expect("observation")
        .remove("source_instance_id");
    missing_nested["state_schema_version"] = Value::String(STATE_SCHEMA_VERSION.to_string());
    assert!(
        ScanState::validate_native_bytes(
            &serde_json::to_vec(&missing_nested).expect("missing nested bytes")
        )
        .is_err()
    );

    let unversioned = serde_json::to_value(&state).expect("state value");
    assert!(
        ScanState::validate_native_bytes(
            &serde_json::to_vec(&unversioned).expect("unversioned bytes")
        )
        .is_err()
    );

    let mut versioned =
        serde_json::from_slice::<Value>(&state.canonical_bytes().unwrap()).expect("native value");
    versioned["baseline_snapshots"]["unexpected"] = Value::Bool(true);
    let unknown =
        ScanState::validate_native_bytes(&serde_json::to_vec(&versioned).expect("unknown bytes"))
            .expect_err("unknown field");
    assert!(unknown.to_string().contains("invalid"));
    assert!(!unknown.to_string().contains("v0.7.0"));

    versioned["not_a_state_family"] = Value::Bool(true);
    let unknown_family = ScanState::validate_native_bytes(
        &serde_json::to_vec(&versioned).expect("unknown family bytes"),
    )
    .expect_err("unknown family");
    assert!(unknown_family.to_string().contains("invalid"));
    assert!(!unknown_family.to_string().contains("v0.7.0"));

    let duplicate = br#"{"seen_source_fingerprints":[],"seen_source_fingerprints":[]}"#;
    let duplicate_error = ScanState::validate_native_bytes(duplicate).expect_err("duplicate");
    assert!(duplicate_error.to_string().contains("invalid"));
    assert!(!duplicate_error.to_string().contains("v0.7.0"));

    let native = String::from_utf8(state.canonical_bytes().expect("native bytes")).unwrap();
    let native_duplicate = native.replacen(
        "\"state_schema_version\"",
        "\"state_schema_version\":\"1.0\",\"state_schema_version\"",
        1,
    );
    let native_duplicate = ScanState::validate_native_bytes(native_duplicate.as_bytes())
        .expect_err("native duplicate");
    assert!(native_duplicate.to_string().contains("invalid"));
    assert!(!native_duplicate.to_string().contains("v0.7.0"));
}

#[test]
fn health_heartbeat_marker_round_trips_and_replaces_without_a_schema_change() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("state.json");
    let mut state = ScanState::default();
    assert_eq!(state.last_health_heartbeat_unix_ms(), None);
    state
        .seen_detection_fingerprints
        .insert("telltale:health_heartbeat_v1@not-a-time".to_string());
    // A damaged marker reads as none, so the heartbeat is due.
    assert_eq!(state.last_health_heartbeat_unix_ms(), None);

    state.record_health_heartbeat(1_000);
    state.record_health_heartbeat(2_000);
    assert_eq!(state.last_health_heartbeat_unix_ms(), Some(2_000));
    assert_eq!(state.seen_detection_fingerprints.len(), 1);

    state.save(&path).expect("save state");
    let bytes = std::fs::read(&path).expect("state bytes");
    let reloaded = ScanState::validate_native_bytes(&bytes).expect("native state");
    assert_eq!(reloaded.last_health_heartbeat_unix_ms(), Some(2_000));
    let value: Value = serde_json::from_slice(&bytes).expect("state json");
    let mut fields = value
        .as_object()
        .expect("state object")
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    fields.sort();
    let mut expected = state_field_names()
        .iter()
        .map(|field| field.to_string())
        .chain(["state_schema_version".to_string()])
        .collect::<Vec<_>>();
    expected.sort();
    assert_eq!(fields, expected, "the heartbeat must not add a state field");
}

#[test]
fn marker_rejection_does_not_claim_malformed_old_input_is_migratable() {
    let secret = "not-an-object";
    let unversioned = format!(
        r#"{{"seen_source_fingerprints":[],"sqlite_ingestion_cursors":{{"k":"{secret}"}}}}"#
    );
    assert_unqualified_marker_rejection(unversioned.as_bytes(), secret);

    for schema in [1, 2] {
        let mut unknown = native_state_value();
        unknown["baseline_snapshots"]["schema_version"] = schema.into();
        unknown["baseline_snapshots"]["not_a_baseline_field"] = Value::Bool(true);
        assert_unqualified_marker_rejection(
            &serde_json::to_vec(&unknown).unwrap(),
            "not_a_baseline_field",
        );

        let mut missing = native_state_value();
        missing["baseline_snapshots"]["schema_version"] = schema.into();
        missing["baseline_snapshots"]
            .as_object_mut()
            .unwrap()
            .remove("snapshots");
        assert_unqualified_marker_rejection(&serde_json::to_vec(&missing).unwrap(), "snapshots");

        let mut cut = native_state_value();
        cut["baseline_snapshots"]["schema_version"] = schema.into();
        cut["sqlite_ingestion_cursors"]["cursor"] = serde_json::json!({
            "client": "opencode",
            "source_id": "opencode.sqlite",
            "source_instance_id": "instance",
            "table": "session_message",
            "last_time_updated": 10,
            "observed_at_unix_ms": 1,
            "draining": true,
            "continue_after_time_updated": 11
        });
        assert_unqualified_marker_rejection(&serde_json::to_vec(&cut).unwrap(), "continue_after");
    }
}

#[test]
fn baseline_schema_2_is_older_state_not_a_host_rejection() {
    let mut value = native_state_value();
    value["baseline_snapshots"]["schema_version"] = 2.into();
    value["baseline_snapshots"]["snapshots"]["id"] =
        host_summary("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    let error = ScanState::validate_native_bytes(&serde_json::to_vec(&value).unwrap())
        .expect_err("schema 2");
    assert!(error.to_string().contains("older format"));
    assert!(error.to_string().contains("v0.7.0"));
}

#[test]
fn current_baseline_rejects_plaintext_and_malformed_hosts_in_both_families() {
    let valid = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let cases = ["internal.example", "sha256:ABC", "sha256:gg"];
    for host in cases {
        for family in ["baseline_snapshots", "baseline_source_contributions"] {
            let mut value = native_state_value();
            assert_eq!(value["baseline_snapshots"]["schema_version"], 3);
            let summary = host_summary(host);
            if family == "baseline_snapshots" {
                value["baseline_snapshots"]["snapshots"]["id"] = summary;
            } else {
                value["baseline_source_contributions"]["source"] = serde_json::json!({
                    "client": "codex",
                    "source_id": "codex.sessions",
                    "source_instance_id": "instance",
                    "source_fingerprint": "fingerprint",
                    "snapshots": {"id": summary}
                });
            }
            let bytes = serde_json::to_vec(&value).unwrap();
            let error = ScanState::validate_native_bytes(&bytes).expect_err(family);
            let message = error.to_string();
            assert!(message.contains("invalid"), "{family} {host}: {message}");
            assert!(!message.contains("v0.7.0"), "{family} {host}: {message}");
            assert!(!message.contains(host), "{family} echoed {host}");
            let temp = tempfile::tempdir().expect("tempdir");
            let path = temp.path().join("state.json");
            std::fs::write(&path, &bytes).expect("write");
            assert!(ScanState::load(&path).is_err());
            assert_eq!(std::fs::read(&path).expect("unchanged"), bytes);
        }
    }
    let mut accepted = native_state_value();
    accepted["baseline_snapshots"]["snapshots"]["id"] = host_summary(valid);
    assert!(
        ScanState::validate_native_bytes(&serde_json::to_vec(&accepted).unwrap()).is_ok(),
        "current hashed hosts remain valid"
    );
    let text = serde_json::to_string(&accepted).unwrap();
    let nested_duplicate = text.replacen(
        &format!("\"{valid}\":1"),
        &format!("\"{valid}\":1,\"{valid}\":1"),
        1,
    );
    let nested = ScanState::validate_native_bytes(nested_duplicate.as_bytes())
        .expect_err("nested duplicate host key");
    assert!(nested.to_string().contains("invalid"));
    assert!(!nested.to_string().contains("v0.7.0"));
}
