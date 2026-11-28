use std::fs;

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tempfile::tempdir;

use super::{
    EVENT_3_SCHEMA, HistoricalEventValidationError, compile_validator, read_jsonl_records,
    validate_journal_record,
};

const CURRENT_EVENT_3_SCHEMA: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/schemas/event.schema.json"
));

const EVENT_3_ACTIVITY: &str = r#"{
        "schema_version": "3.0",
        "event_id": "telltale-00000000-0000-4000-8000-000000000001",
        "telltale_version": "0.7.1",
        "timestamp": "2026-05-01T00:00:00.000Z",
        "observed_at": "2026-05-01T00:00:00.000Z",
        "ingested_at": "2026-05-01T00:00:00.000Z",
        "time_source": "observed",
        "time_confidence": "high",
        "event_type": "activity",
        "severity": "informational",
        "risk_score": 0,
        "risk_contributions": [],
        "client": "codex",
        "session_id": "native-session",
        "source_path_hash": "synthetic-source-hash",
        "tags": ["synthetic"],
        "evidence": [{"field": "synthetic", "redacted_value": "fixture"}]
    }"#;

fn fixture(raw: &str) -> Value {
    serde_json::from_str(raw).expect("event fixture JSON")
}

fn sha256_hex(value: &[u8]) -> String {
    hex::encode(Sha256::digest(value))
}

fn assert_no_canary(error: &impl std::fmt::Display, canary: &str) {
    let rendered = error.to_string();
    assert!(!rendered.contains(canary), "{rendered}");
    assert!(!rendered.contains("jsonschema"), "{rendered}");
}

#[test]
fn reader_rejects_event_1_and_2_without_echoing_records() {
    for version in ["1.0", "2.0"] {
        let canary = format!("obsolete-schema-canary-{version}");
        let mut record = fixture(EVENT_3_ACTIVITY);
        record["schema_version"] = json!(version);
        record["session_id"] = json!(canary);
        let error = validate_journal_record(record.clone())
            .expect_err("obsolete schema must not validate as Event 3.0");
        assert_eq!(
            error,
            HistoricalEventValidationError::UnsupportedSchemaVersion
        );
        assert_no_canary(&error, &canary);
        assert_eq!(error.to_string(), "unsupported_schema_version");

        let directory = tempdir().expect("temporary directory");
        let path = directory.path().join("events.jsonl");
        let native = serde_json::to_string(&fixture(EVENT_3_ACTIVITY)).expect("compact event");
        let obsolete = serde_json::to_string(&record).expect("compact obsolete event");
        fs::write(&path, format!("{native}\n{obsolete}\n")).expect("write JSONL");
        let error = read_jsonl_records(&path).expect_err("obsolete record after native prefix");
        let rendered = error.to_string();
        assert!(
            rendered.contains("unsupported_schema_version"),
            "{rendered}"
        );
        assert!(!rendered.contains(&canary), "{rendered}");
        assert!(!rendered.contains("jsonschema"), "{rendered}");
    }
}

#[test]
fn rejects_missing_non_string_and_unknown_versions_without_echoing_values() {
    let mut missing = fixture(EVENT_3_ACTIVITY);
    missing
        .as_object_mut()
        .expect("object fixture")
        .remove("schema_version");
    assert_eq!(
        validate_journal_record(missing),
        Err(HistoricalEventValidationError::MissingSchemaVersion)
    );

    let canary = "version-secret-canary";
    for actual in [Value::Null, json!(7), json!({"nested": canary})] {
        let mut value = fixture(EVENT_3_ACTIVITY);
        value["schema_version"] = actual;
        let error = validate_journal_record(value).expect_err("non-string version");
        assert_eq!(
            error,
            HistoricalEventValidationError::InvalidSchemaVersionType
        );
        assert_no_canary(&error, canary);
    }

    let mut unknown = fixture(EVENT_3_ACTIVITY);
    unknown["schema_version"] = json!(canary);
    let error = validate_journal_record(unknown).expect_err("unknown version");
    assert_eq!(
        error,
        HistoricalEventValidationError::UnknownRequestedSchemaVersion
    );
    assert_no_canary(&error, canary);
    assert_ne!(
        error,
        HistoricalEventValidationError::UnsupportedSchemaVersion
    );
}

#[test]
fn schema_violation_errors_do_not_expose_input_or_validator_instances() {
    let canary = "credential-schema-violation-canary";
    let mut invalid = fixture(EVENT_3_ACTIVITY);
    invalid["event_type"] = json!(canary);
    invalid["unknown_extension"] = json!({"secret": canary});
    let error = validate_journal_record(invalid).expect_err("invalid event type");
    assert_eq!(error, HistoricalEventValidationError::SchemaViolation);
    assert_no_canary(&error, canary);
    assert!(!format!("{error:?}").contains(canary));
}

#[test]
fn historical_schema_hashes_match_tagged_source_blobs() {
    assert_eq!(
        sha256_hex(EVENT_3_SCHEMA.as_bytes()),
        "9014a15c010bc613b4deb7e0195ec56f702e9e950fb13a12c6937a733e38d754"
    );
    assert_eq!(EVENT_3_SCHEMA, CURRENT_EVENT_3_SCHEMA);
}

#[test]
fn schema_compilation_failures_are_bounded() {
    assert!(matches!(
        compile_validator("{not-json"),
        Err(HistoricalEventValidationError::SchemaUnavailable)
    ));
}

#[test]
fn historical_reader_rejects_oversized_frames() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("events.jsonl");
    let mut value = fixture(EVENT_3_ACTIVITY);
    let mut exact = serde_json::to_vec(&value).unwrap();
    exact.resize(8 * 1024 * 1024, b' ');
    fs::write(&path, &exact).unwrap();
    assert_eq!(read_jsonl_records(&path).unwrap().len(), 1);
    exact.push(b' ');
    fs::write(&path, exact).unwrap();
    assert!(read_jsonl_records(&path).is_err());
    value["unknown_extension"] = json!("x".repeat(8 * 1024 * 1024));
    fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
    assert!(read_jsonl_records(&path).is_err());
}

#[test]
fn jsonl_reader_preserves_values_and_exact_duplicates() {
    let directory = tempdir().expect("temporary directory");
    let path = directory.path().join("events.jsonl");
    let line = serde_json::to_string(&fixture(EVENT_3_ACTIVITY)).expect("compact event");
    let raw = format!("{line}\n{line}\n");
    fs::write(&path, raw.as_bytes()).expect("write JSONL");

    let records = read_jsonl_records(&path).expect("read JSONL");
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].value["event_id"], records[1].value["event_id"]);
    assert_eq!(records[0].value, fixture(EVENT_3_ACTIVITY));
    assert_eq!(records[0].value, records[1].value);
    assert_eq!(records[0].value["schema_version"], "3.0");
}

#[test]
fn jsonl_reader_rejects_same_id_with_different_bytes() {
    let directory = tempdir().expect("temporary directory");
    let path = directory.path().join("events.jsonl");
    let first = fixture(EVENT_3_ACTIVITY);
    let mut second = first.clone();
    second["session_id"] = json!("other-session");
    let first = serde_json::to_string(&first).expect("compact event");
    let second = serde_json::to_string(&second).expect("compact event");
    for second in [second, format!(" {first}")] {
        fs::write(&path, format!("{first}\n{second}\n")).expect("write JSONL");

        let error = read_jsonl_records(&path).expect_err("same-id collision");
        assert!(error.to_string().contains("event_id_collision"));
    }
}

#[test]
fn jsonl_reader_ignores_line_framing_when_comparing_same_id_bodies() {
    let directory = tempdir().expect("temporary directory");
    let path = directory.path().join("events.jsonl");
    let line = serde_json::to_string(&fixture(EVENT_3_ACTIVITY)).expect("compact event");
    for ending in [b"\n".as_slice(), b"\r\n".as_slice(), b"".as_slice()] {
        let mut bytes = line.as_bytes().to_vec();
        bytes.extend_from_slice(b"\n");
        bytes.extend_from_slice(line.as_bytes());
        bytes.extend_from_slice(ending);
        fs::write(&path, bytes).expect("write JSONL");
        let records = read_jsonl_records(&path).expect("same object body");
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].value, fixture(EVENT_3_ACTIVITY));
        assert_eq!(records[0].value, records[1].value);
    }
}

#[test]
fn jsonl_reader_rejects_a_malformed_tail_after_a_valid_record() {
    let directory = tempdir().expect("temporary directory");
    let path = directory.path().join("events.jsonl");
    let line = serde_json::to_string(&fixture(EVENT_3_ACTIVITY)).expect("compact event");
    fs::write(&path, format!("{line}\n{{not-json")).expect("write JSONL");
    let error = read_jsonl_records(&path).expect_err("malformed tail");
    assert!(error.to_string().contains("invalid JSONL"));
}
