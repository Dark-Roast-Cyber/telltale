//! Source-native read errors and shared JSONL reading.
//!
//! This module is not a parser, projection, registry, or record model. Adapters
//! own their native structures and map them directly to canonical acquisition.

use serde_json::Value;
use std::fmt;
use std::fs;
use std::io::Read;

use telltale_schema::clients::ClientId;
use telltale_schema::source::Source;

/// Bounded failure while reading a supported source. Display and Debug stay
/// privacy-safe: they do not include the source path or payload.
#[derive(Debug)]
#[non_exhaustive]
pub enum SourceReadError {
    Io(std::io::Error),
    Json(serde_json::Error),
    Sqlite(rusqlite::Error),
    Locked(String),
    SchemaDrift {
        client: ClientId,
        source_id: String,
        detail: &'static str,
    },
}

impl fmt::Display for SourceReadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "io error: {error}"),
            Self::Json(error) => write!(formatter, "json parse error: {error}"),
            Self::Sqlite(error) => write!(formatter, "sqlite error: {error}"),
            Self::Locked(message) => write!(formatter, "locked: {message}"),
            Self::SchemaDrift {
                client,
                source_id,
                detail,
            } => write!(
                formatter,
                "schema drift for ({}, {source_id}): {detail}",
                client.as_str()
            ),
        }
    }
}

impl From<std::io::Error> for SourceReadError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<serde_json::Error> for SourceReadError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

impl From<rusqlite::Error> for SourceReadError {
    fn from(error: rusqlite::Error) -> Self {
        Self::from_sqlite(error)
    }
}

impl SourceReadError {
    pub(crate) fn from_sqlite(error: rusqlite::Error) -> Self {
        match error.sqlite_error_code() {
            Some(rusqlite::ErrorCode::DatabaseBusy) | Some(rusqlite::ErrorCode::DatabaseLocked) => {
                Self::Locked(error.to_string())
            }
            _ => Self::Sqlite(error),
        }
    }
}

pub(crate) fn read_jsonl_values(source: &Source) -> Result<Vec<Value>, SourceReadError> {
    read_jsonl_values_with_limits(source, None)
}

pub(crate) fn read_jsonl_values_with_limits(
    source: &Source,
    limits: Option<crate::acquisition::DirectReadLimits>,
) -> Result<Vec<Value>, SourceReadError> {
    if let Some(limits) = limits {
        let bytes = bounded_file_bytes(&source.path, limits.bytes)
            .map_err(|_| std::io::Error::other("bounded source read failed"))?;
        check_json_depth(&bytes, limits.json_depth)
            .map_err(|_| std::io::Error::other("source JSON depth exceeded"))?;
        let mut values = Vec::new();
        for line in bytes
            .split(|b| *b == b'\n')
            .filter(|line| !line.iter().all(u8::is_ascii_whitespace))
        {
            if values.len() == limits.records {
                return Err(std::io::Error::other("source record limit exceeded").into());
            }
            values.push(serde_json::from_slice(line)?);
        }
        return Ok(values);
    }
    let raw = fs::read_to_string(&source.path)?;
    raw.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str::<Value>(line).map_err(SourceReadError::from))
        .collect()
}

// Validate the opened object, not a pathname precheck. Nonblocking open avoids
// hanging on a replacement FIFO; no-follow rejects symlinks at the final component.
pub(crate) fn bounded_file_bytes(path: &std::path::Path, cap: usize) -> Result<Vec<u8>, ()> {
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
    let file = options.open(path).map_err(|_| ())?;
    let metadata = file.metadata().map_err(|_| ())?;
    if !metadata.is_file() || metadata.len() > cap as u64 {
        return Err(());
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes()
            & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
            != 0
        {
            return Err(());
        }
    }
    let mut bytes = Vec::new();
    file.take(cap as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ())?;
    if bytes.len() > cap {
        return Err(());
    }
    Ok(bytes)
}

pub(crate) fn check_json_depth(bytes: &[u8], cap: usize) -> Result<(), ()> {
    let (mut depth, mut string, mut escape) = (0usize, false, false);
    for &b in bytes {
        if string {
            if escape {
                escape = false;
            } else if b == b'\\' {
                escape = true;
            } else if b == b'"' {
                string = false;
            }
        } else {
            match b {
                b'"' => string = true,
                b'{' | b'[' => {
                    depth += 1;
                    if depth > cap {
                        return Err(());
                    }
                }
                b'}' | b']' => depth = depth.saturating_sub(1),
                _ => {}
            }
        }
    }
    Ok(())
}

/// Nested string lookup used by adapters that store timestamps and labels inside
/// source envelopes. This does not invent a session id or flatten a record.
pub(crate) fn nested_string_field(value: &Value, key: &str) -> Option<String> {
    field_value(value, key)
        .and_then(Value::as_str)
        .map(ToString::to_string)
}

fn field_value<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
    value
        .get(key)
        .or_else(|| value.get("message").and_then(|message| message.get(key)))
        .or_else(|| value.get("payload").and_then(|payload| payload.get(key)))
        .or_else(|| {
            value
                .get("payload")
                .and_then(|payload| payload.get("payload"))
                .and_then(|payload| payload.get(key))
        })
        .or_else(|| {
            value
                .get("session_meta")
                .and_then(|session_meta| session_meta.get(key))
        })
}

/// String values in a source unit, for activity contribution classification.
/// Object keys are not facts. The caller decides which units are tool calls.
pub(crate) fn collect_string_values(value: &Value) -> Vec<String> {
    let mut output = Vec::new();
    collect_string_values_into(value, &mut output);
    output
}

fn collect_string_values_into(value: &Value, output: &mut Vec<String>) {
    match value {
        Value::String(item) => output.push(item.clone()),
        Value::Array(items) => {
            for item in items {
                collect_string_values_into(item, output);
            }
        }
        Value::Object(items) => {
            for item in items.values() {
                collect_string_values_into(item, output);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}
