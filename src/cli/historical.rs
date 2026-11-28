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
mod tests;
