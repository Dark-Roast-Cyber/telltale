use std::collections::BTreeSet;
use std::path::Path;

use serde_json::Value;

use crate::baseline::{
    BASELINE_HOST_HASH_PREFIX, BaselineKey, BaselineObservationTotals, BaselineSummary, PathClass,
    baseline_host_identity,
};
use crate::event::{DetectionEventInput, Evidence, detection_event};
use telltale_schema::clients::{ClientId, SourceKind};
use telltale_schema::source::Source;

use super::{
    BASELINE_STATE_VERSION, STATE_SCHEMA_VERSION, ScanState, baseline_snapshot_id,
    detection_fingerprint, source_fingerprint, state_field_names,
};

#[test]
fn legacy_scan_state_fixture_is_rejected_without_rewriting_or_echoing_hosts() {
    let bytes = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/state/legacy-scan-state.json"
    ));
    let fixture: Value = serde_json::from_slice(bytes).expect("legacy state fixture");
    for field in [
        "seen_source_fingerprints",
        "seen_detection_fingerprints",
        "baseline_snapshots",
        "baseline_source_contributions",
        "source_observations",
        "sqlite_ingestion_cursors",
        "install_inventory",
    ] {
        assert!(fixture.get(field).is_some(), "missing state family {field}");
    }
    assert!(fixture.get("state_schema_version").is_none());

    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("legacy-scan-state.json");
    std::fs::write(&path, bytes).expect("write state fixture");
    let error = ScanState::load(&path).expect_err("older fixture must fail");
    let message = error.to_string();
    assert!(message.contains("older format"));
    assert!(message.contains("v0.7.0"));
    assert!(message.contains("was not changed"));
    assert!(!message.contains("internal.example.test"));
    assert_eq!(std::fs::read(&path).expect("unchanged"), bytes);
}

fn assert_unqualified_marker_rejection(bytes: &[u8], echoed: &str) {
    let error = ScanState::validate_native_bytes(bytes).expect_err("marker rejection");
    let message = error.to_string();
    assert!(message.contains("older format"), "{message}");
    assert!(message.contains("was not changed"), "{message}");
    assert!(
        message.contains("or be invalid"),
        "missing qualification: {message}"
    );
    assert!(
        message.contains("eligibility has not been validated"),
        "missing qualification: {message}"
    );
    assert!(message.contains("not invalid data"), "{message}");
    assert!(!message.contains(echoed), "echoed input: {message}");
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("state.json");
    std::fs::write(&path, bytes).expect("write");
    let loaded = ScanState::load(&path).expect_err("load must reject");
    assert_eq!(loaded.to_string(), message);
    assert_eq!(std::fs::read(&path).expect("unchanged"), bytes);
}

fn native_state_value() -> Value {
    serde_json::from_slice(&ScanState::default().canonical_bytes().unwrap()).unwrap()
}

fn host_summary(host: &str) -> Value {
    serde_json::json!({
        "key": {"client": "codex", "agent": null, "model": null, "provider": null},
        "observations": {
            "records": 1,
            "user_messages": 0,
            "assistant_messages": 0,
            "tool_calls": 1,
            "tool_results": 0,
            "session_meta": 0,
            "other": 0
        },
        "tool_call_counts": {},
        "path_class_counts": {},
        "network_host_counts": {host: 1}
    })
}

mod baseline_snapshots;
mod deduplication;
mod schema_validation;
mod sqlite_cursors;
