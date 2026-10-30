//! Reading and schema validation of historical Event 1.0, 2.0 and 3.0 JSONL
//! records, shared by export and migration. Historical bytes are validated,
//! not rewritten.

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::sync::LazyLock;

use jsonschema::{Validator, validator_for};
use serde_json::Value;
use sha2::{Digest, Sha256};

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
/// Repeated IDs require identical object bytes, excluding line terminators.
pub fn read_jsonl_records(
    path: &std::path::Path,
) -> Result<Vec<JsonlEventRecord>, Box<dyn std::error::Error>> {
    let mut records = Vec::new();
    let mut retained_bytes = 0usize;
    visit_jsonl_records(path, |record, bytes| {
        retained_bytes = retained_bytes
            .checked_add(bytes)
            .ok_or("historical retention limit exceeded")?;
        if retained_bytes > 128 * 1024 * 1024 || records.len() == 100_000 {
            return Err("historical retention limit exceeded; select a smaller journal".into());
        }
        records.push(record);
        Ok(())
    })?;
    Ok(records)
}

/// Stream all schema generations with the same physical bounds. Duplicate IDs
/// retain file offsets, not another payload copy; compare exact bytes on demand.
pub(crate) fn visit_jsonl_records(
    path: &std::path::Path,
    mut visit: impl FnMut(JsonlEventRecord, usize) -> Result<(), Box<dyn std::error::Error>>,
) -> Result<(), Box<dyn std::error::Error>> {
    const FRAME_BYTES: usize = 8 * 1024 * 1024;
    const JOURNAL_BYTES: u64 = 1024 * 1024 * 1024;
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err("historical input must be a regular file".into());
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes()
            & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
            != 0
        {
            return Err("historical input must not be a reparse point".into());
        }
    }
    if metadata.len() > JOURNAL_BYTES {
        return Err("historical journal byte limit exceeded".into());
    }
    let mut reader = BufReader::new(file);
    let mut seen_ids: BTreeMap<String, (u64, usize, [u8; 32])> = BTreeMap::new();
    let mut identity_bytes = 0usize;
    let mut start = 0u64;
    let mut raw_bytes = Vec::new();
    let mut record_count = 0usize;
    loop {
        raw_bytes.clear();
        let read = reader
            .by_ref()
            .take(FRAME_BYTES as u64 + 1)
            .read_until(b'\n', &mut raw_bytes)?;
        if read == 0 {
            break;
        }
        if read > FRAME_BYTES {
            return Err("historical frame byte limit exceeded".into());
        }
        let end = start
            .checked_add(read as u64)
            .ok_or("historical journal byte limit exceeded")?;
        if end > JOURNAL_BYTES {
            return Err("historical journal byte limit exceeded".into());
        }
        let object_end = if raw_bytes.ends_with(b"\r\n") {
            raw_bytes.len() - 2
        } else if raw_bytes.ends_with(b"\n") {
            raw_bytes.len() - 1
        } else {
            raw_bytes.len()
        };
        let object_bytes = &raw_bytes[..object_end];
        if !object_bytes.iter().all(u8::is_ascii_whitespace) {
            let value = serde_json::from_slice::<Value>(object_bytes).map_err(|error| {
                format!(
                    "invalid JSONL at {}:{}: {error}",
                    path.display(),
                    record_count + 1
                )
            })?;
            let (value, kind) = validate_event_record(value).map_err(|error| {
                format!(
                    "invalid event at {}:{}: {error}",
                    path.display(),
                    record_count + 1
                )
            })?;
            let object = value
                .as_object()
                .ok_or("validated event is not an object")?;
            let event_id = object
                .get("event_id")
                .and_then(Value::as_str)
                .ok_or("validated event is missing event_id")?
                .to_string();
            let digest: [u8; 32] = Sha256::digest(object_bytes).into();
            if let Some(&(offset, length, previous_digest)) = seen_ids.get(&event_id) {
                if length != object_bytes.len() || digest != previous_digest {
                    return Err("event_id_collision".into());
                }
                let position = reader.stream_position()?;
                reader.seek(SeekFrom::Start(offset))?;
                let mut previous = vec![0; length];
                reader.read_exact(&mut previous)?;
                reader.seek(SeekFrom::Start(position))?;
                if previous != object_bytes {
                    return Err("event_id_collision".into());
                }
            } else {
                if seen_ids.len() == 1_000_000 {
                    return Err("historical identity limit exceeded".into());
                }
                identity_bytes += event_id.len();
                if identity_bytes > 64 * 1024 * 1024 {
                    return Err("historical identity byte limit exceeded".into());
                }
                seen_ids.insert(event_id, (start, object_bytes.len(), digest));
            }
            record_count += 1;
            visit(JsonlEventRecord { value, kind }, read)?;
        }
        start = end;
    }

    Ok(())
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
        EVENT_1_SCHEMA, EVENT_2_SCHEMA, EVENT_3_SCHEMA, HistoricalEventValidationError,
        compile_validator, read_jsonl_records, validate_historical_event,
    };

    const CURRENT_EVENT_3_SCHEMA: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/schemas/event.schema.json"
    ));

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

    #[test]
    fn historical_reader_rejects_oversized_frames() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("events.jsonl");
        let mut value = fixture(EVENT_1_HEALTH);
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

    fn fixtures() -> [(&'static str, &'static str, Value); 4] {
        [
            ("1.0", "detection", fixture(EVENT_1_DETECTION)),
            ("1.0", "health", fixture(EVENT_1_HEALTH)),
            ("2.0", "detection", fixture(EVENT_2_DETECTION)),
            ("2.0", "health", fixture(EVENT_2_HEALTH)),
        ]
    }

    fn sha256_hex(value: &[u8]) -> String {
        hex::encode(Sha256::digest(value))
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
    fn jsonl_reader_preserves_values_and_exact_duplicates() {
        let directory = tempdir().expect("temporary directory");
        let path = directory.path().join("events.jsonl");
        let line = serde_json::to_string(&fixture(EVENT_1_DETECTION)).expect("compact event");
        let raw = format!("{line}\n{line}\n");
        fs::write(&path, raw.as_bytes()).expect("write JSONL");

        let records = read_jsonl_records(&path).expect("read JSONL");
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].value["event_id"], records[1].value["event_id"]);
        assert_eq!(records[0].value, fixture(EVENT_1_DETECTION));
        assert_eq!(records[0].value, records[1].value);
        assert_eq!(records[0].value["schema_version"], "1.0");
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
        let line = serde_json::to_string(&fixture(EVENT_1_DETECTION)).expect("compact event");
        for ending in [b"\n".as_slice(), b"\r\n".as_slice(), b"".as_slice()] {
            let mut bytes = line.as_bytes().to_vec();
            bytes.extend_from_slice(b"\n");
            bytes.extend_from_slice(line.as_bytes());
            bytes.extend_from_slice(ending);
            fs::write(&path, bytes).expect("write JSONL");
            let records = read_jsonl_records(&path).expect("same object body");
            assert_eq!(records.len(), 2);
            assert_eq!(records[0].value, fixture(EVENT_1_DETECTION));
            assert_eq!(records[0].value, records[1].value);
        }
    }
}
