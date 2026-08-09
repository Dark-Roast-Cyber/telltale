use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::sync::LazyLock;

use jsonschema::{Validator, validator_for};
use serde_json::Value;

const EVENT_1_SCHEMA: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/schemas/historical/event-1.0.schema.json"
));
const EVENT_2_SCHEMA: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/schemas/historical/event-2.0.schema.json"
));
const EVENT_3_SCHEMA: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/schemas/historical/event-3.0.schema.json"
));
const CURRENT_EVENT_3_SCHEMA: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/schemas/event.schema.json"
));

static EVENT_1_VALIDATOR: LazyLock<Result<Validator, HistoricalEventValidationError>> =
    LazyLock::new(|| compile_validator(EVENT_1_SCHEMA));
static EVENT_2_VALIDATOR: LazyLock<Result<Validator, HistoricalEventValidationError>> =
    LazyLock::new(|| compile_validator(EVENT_2_SCHEMA));
static EVENT_3_VALIDATOR: LazyLock<Result<Validator, HistoricalEventValidationError>> =
    LazyLock::new(|| compile_validator(EVENT_3_SCHEMA));

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventRecordKind {
    Historical,
    Native,
}

#[derive(Debug, Clone)]
pub struct JsonlEventRecord {
    pub value: Value,
    pub schema_version: String,
    pub event_id: String,
    pub object_bytes: Vec<u8>,
    pub raw_bytes: Vec<u8>,
    pub line_ending: Vec<u8>,
    pub kind: EventRecordKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HistoricalEventValidationError {
    MissingSchemaVersion,
    InvalidSchemaVersionType,
    UnknownRequestedSchemaVersion,
    UnknownActualSchemaVersion,
    SchemaVersionMismatch,
    SchemaUnavailable,
    SchemaViolation,
}

impl fmt::Display for HistoricalEventValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let code = match self {
            Self::MissingSchemaVersion => "missing_schema_version",
            Self::InvalidSchemaVersionType => "invalid_schema_version_type",
            Self::UnknownRequestedSchemaVersion => "unknown_requested_schema_version",
            Self::UnknownActualSchemaVersion => "unknown_actual_schema_version",
            Self::SchemaVersionMismatch => "schema_version_mismatch",
            Self::SchemaUnavailable => "historical_schema_unavailable",
            Self::SchemaViolation => "historical_schema_violation",
        };
        formatter.write_str(code)
    }
}

impl std::error::Error for HistoricalEventValidationError {}

pub fn validate_historical_event(
    value: Value,
    expected_schema_version: &str,
) -> Result<Value, HistoricalEventValidationError> {
    let validator = match expected_schema_version {
        "1.0" => EVENT_1_VALIDATOR
            .as_ref()
            .map_err(|_| HistoricalEventValidationError::SchemaUnavailable)?,
        "2.0" => EVENT_2_VALIDATOR
            .as_ref()
            .map_err(|_| HistoricalEventValidationError::SchemaUnavailable)?,
        "3.0" => EVENT_3_VALIDATOR
            .as_ref()
            .map_err(|_| HistoricalEventValidationError::SchemaUnavailable)?,
        _ => {
            return Err(HistoricalEventValidationError::UnknownRequestedSchemaVersion);
        }
    };

    let object = value
        .as_object()
        .ok_or(HistoricalEventValidationError::InvalidSchemaVersionType)?;
    let actual_schema_version = match object.get("schema_version") {
        None => return Err(HistoricalEventValidationError::MissingSchemaVersion),
        Some(Value::String(version)) => version,
        Some(_) => return Err(HistoricalEventValidationError::InvalidSchemaVersionType),
    };

    if !matches!(actual_schema_version.as_str(), "1.0" | "2.0" | "3.0") {
        return Err(HistoricalEventValidationError::UnknownActualSchemaVersion);
    }
    if actual_schema_version != expected_schema_version {
        return Err(HistoricalEventValidationError::SchemaVersionMismatch);
    }

    validator
        .validate(&value)
        .map_err(|_| HistoricalEventValidationError::SchemaViolation)?;

    Ok(value)
}

pub fn validate_event_record(
    value: Value,
) -> Result<(Value, EventRecordKind), HistoricalEventValidationError> {
    let object = value
        .as_object()
        .ok_or(HistoricalEventValidationError::InvalidSchemaVersionType)?;
    let version = object
        .get("schema_version")
        .ok_or(HistoricalEventValidationError::MissingSchemaVersion)?
        .as_str()
        .ok_or(HistoricalEventValidationError::InvalidSchemaVersionType)?
        .to_string();
    let kind = if version == "3.0" {
        EventRecordKind::Native
    } else {
        EventRecordKind::Historical
    };
    let validated = validate_historical_event(value, &version)?;
    Ok((validated, kind))
}

/// Read strict event records without converting historical values into `Event`.
/// Raw object bytes and line framing remain available to lossless import code.
pub fn read_jsonl_records(
    path: &std::path::Path,
) -> Result<Vec<JsonlEventRecord>, Box<dyn std::error::Error>> {
    let bytes = fs::read(path)?;
    let mut records = Vec::new();
    let mut seen_ids: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut start = 0;

    while start < bytes.len() {
        let end = bytes[start..]
            .iter()
            .position(|byte| *byte == b'\n')
            .map(|offset| start + offset + 1)
            .unwrap_or(bytes.len());
        let raw_bytes = bytes[start..end].to_vec();
        let (object_end, line_ending) = if raw_bytes.ends_with(b"\r\n") {
            (raw_bytes.len() - 2, b"\r\n".to_vec())
        } else if raw_bytes.ends_with(b"\n") {
            (raw_bytes.len() - 1, b"\n".to_vec())
        } else {
            (raw_bytes.len(), Vec::new())
        };
        let object_bytes = raw_bytes[..object_end].to_vec();
        if !object_bytes.iter().all(u8::is_ascii_whitespace) {
            let value = serde_json::from_slice::<Value>(&object_bytes).map_err(|error| {
                format!(
                    "invalid JSONL at {}:{}: {error}",
                    path.display(),
                    records.len() + 1
                )
            })?;
            let (value, kind) = validate_event_record(value).map_err(|error| {
                format!(
                    "invalid event at {}:{}: {error}",
                    path.display(),
                    records.len() + 1
                )
            })?;
            let object = value
                .as_object()
                .ok_or("validated event is not an object")?;
            let schema_version = object
                .get("schema_version")
                .and_then(Value::as_str)
                .ok_or("validated event is missing schema_version")?
                .to_string();
            let event_id = object
                .get("event_id")
                .and_then(Value::as_str)
                .ok_or("validated event is missing event_id")?
                .to_string();
            if let Some(previous) = seen_ids.get(&event_id)
                && previous != &object_bytes
            {
                return Err("event_id_collision".into());
            }
            seen_ids.insert(event_id.clone(), object_bytes.clone());
            records.push(JsonlEventRecord {
                value,
                schema_version,
                event_id,
                object_bytes,
                raw_bytes,
                line_ending,
                kind,
            });
        }
        start = end;
    }

    Ok(records)
}

fn compile_validator(schema_text: &str) -> Result<Validator, HistoricalEventValidationError> {
    let schema: Value = serde_json::from_str(schema_text)
        .map_err(|_| HistoricalEventValidationError::SchemaUnavailable)?;
    validator_for(&schema).map_err(|_| HistoricalEventValidationError::SchemaUnavailable)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use serde_json::{Value, json};
    use sha2::{Digest, Sha256};
    use tempfile::tempdir;

    use super::{
        CURRENT_EVENT_3_SCHEMA, EVENT_1_SCHEMA, EVENT_2_SCHEMA, EVENT_3_SCHEMA,
        HistoricalEventValidationError, compile_validator, read_jsonl_records,
        validate_historical_event,
    };

    const EVENT_1_DETECTION: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/historical_events/event-1.0.json"
    ));
    const EVENT_1_HEALTH: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/historical_events/health-1.0.json"
    ));
    const EVENT_2_DETECTION: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/historical_events/event-2.0.json"
    ));
    const EVENT_2_HEALTH: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/historical_events/health-2.0.json"
    ));

    fn fixture(raw: &str) -> Value {
        serde_json::from_str(raw).expect("historical fixture JSON")
    }

    fn fixtures() -> [(&'static str, &'static str, Value); 4] {
        [
            ("1.0", "detection", fixture(EVENT_1_DETECTION)),
            ("1.0", "health", fixture(EVENT_1_HEALTH)),
            ("2.0", "detection", fixture(EVENT_2_DETECTION)),
            ("2.0", "health", fixture(EVENT_2_HEALTH)),
        ]
    }

    fn sha256_hex(value: &[u8]) -> String {
        format!("{:x}", Sha256::digest(value))
    }

    fn assert_no_canary(error: HistoricalEventValidationError, canary: &str) {
        assert!(!format!("{error}").contains(canary));
        assert!(!format!("{error:?}").contains(canary));
    }

    #[test]
    fn validates_all_historical_fixtures_and_preserves_exact_values() {
        for (version, _, original) in fixtures() {
            let validated = validate_historical_event(original.clone(), version)
                .expect("historical event should validate");
            assert_eq!(validated, original);
            assert_eq!(
                validated["unknown_extension"],
                json!({"nested": [true, null, 7]})
            );
        }
    }

    #[test]
    fn rejects_missing_unknown_and_mismatched_versions() {
        let mut missing = fixture(EVENT_1_DETECTION);
        missing
            .as_object_mut()
            .expect("object fixture")
            .remove("schema_version");
        assert_eq!(
            validate_historical_event(missing, "1.0"),
            Err(HistoricalEventValidationError::MissingSchemaVersion)
        );

        let actual_canary = "actual-version-secret-canary";
        let mut unknown = fixture(EVENT_1_DETECTION);
        unknown["schema_version"] = json!(actual_canary);
        let error = validate_historical_event(unknown, "1.0").expect_err("unknown actual version");
        assert_eq!(
            error,
            HistoricalEventValidationError::UnknownActualSchemaVersion
        );
        assert_no_canary(error, actual_canary);

        assert_eq!(
            validate_historical_event(fixture(EVENT_1_DETECTION), "2.0"),
            Err(HistoricalEventValidationError::SchemaVersionMismatch)
        );
        assert_eq!(
            validate_historical_event(fixture(EVENT_2_DETECTION), "1.0"),
            Err(HistoricalEventValidationError::SchemaVersionMismatch)
        );
    }

    #[test]
    fn rejects_unknown_requested_and_non_string_actual_versions() {
        let requested_canary = "requested-version-secret-canary";
        let error = validate_historical_event(fixture(EVENT_1_DETECTION), requested_canary)
            .expect_err("unknown requested version");
        assert_eq!(
            error,
            HistoricalEventValidationError::UnknownRequestedSchemaVersion
        );
        assert_no_canary(error, requested_canary);

        for actual in [Value::Null, json!(7), json!({"nested": "version"})] {
            let mut value = fixture(EVENT_1_DETECTION);
            value["schema_version"] = actual;
            assert_eq!(
                validate_historical_event(value, "1.0"),
                Err(HistoricalEventValidationError::InvalidSchemaVersionType)
            );
        }
    }

    #[test]
    fn schema_violation_errors_do_not_expose_input_values() {
        let canary = "credential-schema-violation-canary";
        let mut invalid = fixture(EVENT_2_DETECTION);
        invalid["event_type"] = json!(canary);
        invalid["unknown_extension"] = json!({"secret": canary});
        let error = validate_historical_event(invalid, "2.0").expect_err("invalid event type");
        assert_eq!(error, HistoricalEventValidationError::SchemaViolation);
        assert_no_canary(error, canary);
    }

    #[test]
    fn historical_schema_hashes_match_tagged_source_blobs() {
        assert_eq!(
            sha256_hex(EVENT_1_SCHEMA.as_bytes()),
            "396065acda07468b0d30cd0759fa55b60280b070aa24ccabe89bd6a868509f03"
        );
        assert_eq!(
            sha256_hex(EVENT_2_SCHEMA.as_bytes()),
            "4b41c09e2663ead7049ccdc90737f5536942da6b6247af74f43215f29cfa00a5"
        );
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
    fn jsonl_reader_preserves_order_bytes_and_exact_duplicates() {
        let directory = tempdir().expect("temporary directory");
        let path = directory.path().join("events.jsonl");
        let line = serde_json::to_string(&fixture(EVENT_1_DETECTION)).expect("compact event");
        let raw = format!("{line}\n{line}\n");
        fs::write(&path, raw.as_bytes()).expect("write JSONL");

        let records = read_jsonl_records(&path).expect("read JSONL");
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].event_id, records[1].event_id);
        assert_eq!(records[0].object_bytes, records[1].object_bytes);
        assert_eq!(records[0].raw_bytes, records[1].raw_bytes);
        assert_eq!(records[0].schema_version, "1.0");
        assert_eq!(records[0].kind, super::EventRecordKind::Historical);
    }

    #[test]
    fn jsonl_reader_rejects_same_id_with_different_bytes() {
        let directory = tempdir().expect("temporary directory");
        let path = directory.path().join("events.jsonl");
        let first = fixture(EVENT_1_DETECTION);
        let mut second = first.clone();
        second["risk_score"] = json!(91);
        let first = serde_json::to_string(&first).expect("compact event");
        let second = serde_json::to_string(&second).expect("compact event");
        fs::write(&path, format!("{first}\n{second}\n")).expect("write JSONL");

        let error = read_jsonl_records(&path).expect_err("same-id collision");
        assert!(error.to_string().contains("event_id_collision"));
    }

    #[test]
    fn jsonl_reader_ignores_line_framing_when_comparing_same_id_bodies() {
        let directory = tempdir().expect("temporary directory");
        let path = directory.path().join("events.jsonl");
        let line = serde_json::to_string(&fixture(EVENT_1_DETECTION)).expect("compact event");
        for ending in [b"\n".as_slice(), b"\r\n".as_slice(), b"".as_slice()] {
            let mut bytes = line.as_bytes().to_vec();
            bytes.extend_from_slice(b"\n");
            bytes.extend_from_slice(line.as_bytes());
            bytes.extend_from_slice(ending);
            fs::write(&path, bytes).expect("write JSONL");
            let records = read_jsonl_records(&path).expect("same object body");
            assert_eq!(records.len(), 2);
            assert_eq!(records[0].object_bytes, records[1].object_bytes);
        }
    }
}
