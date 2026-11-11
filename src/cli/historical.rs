//! Bounded JSONL journal reading for export and status.
//!
//! Only Event 3.0 records are admitted. Event 1.0 and 2.0 are rejected with a
//! fixed `unsupported_schema_version` error and are never treated as Event 3.0
//! or skipped. Bytes are validated, not rewritten. This reader is not
//! `LocalEventFeed`: retention, framing, and replay contracts differ.

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::sync::LazyLock;

use jsonschema::{Validator, validator_for};
use serde_json::Value;
use sha2::{Digest, Sha256};

const EVENT_3_SCHEMA: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/schemas/historical/event-3.0.schema.json"
));
static EVENT_3_VALIDATOR: LazyLock<Result<Validator, HistoricalEventValidationError>> =
    LazyLock::new(|| compile_validator(EVENT_3_SCHEMA));

#[derive(Debug, Clone)]
pub struct JsonlEventRecord {
    pub value: Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HistoricalEventValidationError {
    MissingSchemaVersion,
    InvalidSchemaVersionType,
    UnknownRequestedSchemaVersion,
    UnsupportedSchemaVersion,
    SchemaUnavailable,
    SchemaViolation,
}

impl fmt::Display for HistoricalEventValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let code = match self {
            Self::MissingSchemaVersion => "missing_schema_version",
            Self::InvalidSchemaVersionType => "invalid_schema_version_type",
            Self::UnknownRequestedSchemaVersion => "unknown_requested_schema_version",
            Self::UnsupportedSchemaVersion => "unsupported_schema_version",
            Self::SchemaUnavailable => "historical_schema_unavailable",
            Self::SchemaViolation => "historical_schema_violation",
        };
        formatter.write_str(code)
    }
}

impl std::error::Error for HistoricalEventValidationError {}

fn validate_journal_record(value: Value) -> Result<Value, HistoricalEventValidationError> {
    let object = value
        .as_object()
        .ok_or(HistoricalEventValidationError::InvalidSchemaVersionType)?;
    let version = match object.get("schema_version") {
        None => return Err(HistoricalEventValidationError::MissingSchemaVersion),
        Some(Value::String(version)) => version.as_str(),
        Some(_) => return Err(HistoricalEventValidationError::InvalidSchemaVersionType),
    };
    match version {
        "1.0" | "2.0" => return Err(HistoricalEventValidationError::UnsupportedSchemaVersion),
        "3.0" => {}
        _ => return Err(HistoricalEventValidationError::UnknownRequestedSchemaVersion),
    }
    let validator = EVENT_3_VALIDATOR
        .as_ref()
        .map_err(|_| HistoricalEventValidationError::SchemaUnavailable)?;
    validator
        .validate(&value)
        .map_err(|_| HistoricalEventValidationError::SchemaViolation)?;
    Ok(value)
}

/// Read strict Event 3.0 records. Repeated IDs require identical object bytes,
/// excluding line terminators.
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

/// Stream Event 3.0 records with the same physical bounds. Duplicate IDs retain
/// file offsets, not another payload copy; compare exact bytes on demand.
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
            let value = validate_journal_record(value).map_err(|error| {
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
            visit(JsonlEventRecord { value }, read)?;
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
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        assert!(
            !root
                .join("schemas/historical/event-1.0.schema.json")
                .exists()
        );
        assert!(
            !root
                .join("schemas/historical/event-2.0.schema.json")
                .exists()
        );
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
}
