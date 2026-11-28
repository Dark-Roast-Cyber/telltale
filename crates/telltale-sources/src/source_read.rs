//! Source-native read errors and shared JSONL reading.
//!
//! This module is not a parser, projection, registry, or record model. Adapters
//! own their native structures and map them directly to canonical acquisition.

use serde_json::Value;
use std::fmt;
use std::fs;
use std::io::Read;

use telltale_schema::clients::ClientId;
use telltale_schema::observation::SourceScale;
use telltale_schema::source::Source;

/// Bounded failure while reading a supported source. Display and Debug stay
/// privacy-safe: they do not include the source path or payload.
#[derive(Debug)]
#[non_exhaustive]
pub enum SourceReadError {
    Bounded(BoundedReadError),
    Io(std::io::Error),
    Json(serde_json::Error),
    // Keep the error shape identical when SQLite acquisition is compiled out.
    #[cfg_attr(not(feature = "opencode-sqlite"), allow(dead_code))]
    Sqlite,
    #[cfg_attr(not(feature = "opencode-sqlite"), allow(dead_code))]
    Locked,
    #[cfg_attr(not(feature = "opencode-sqlite"), allow(dead_code))]
    ResumeRegressed,
    /// A store has only part of a supported native schema, or lacks its
    /// required columns. Never falls back to another schema.
    #[cfg_attr(not(feature = "opencode-sqlite"), allow(dead_code))]
    UnsupportedSchema,
    SchemaDrift {
        client: ClientId,
        source_id: String,
        detail: &'static str,
    },
}

impl fmt::Display for SourceReadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bounded(error) => formatter.write_str(error.code()),
            Self::Io(error) => write!(formatter, "io error: {error}"),
            Self::Json(error) => write!(formatter, "json parse error: {error}"),
            Self::Sqlite => formatter.write_str("sqlite error"),
            Self::Locked => formatter.write_str("sqlite locked"),
            Self::ResumeRegressed => formatter.write_str("resume_regressed"),
            Self::UnsupportedSchema => formatter.write_str("unsupported_source_schema"),
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

/// Closed, content-free classifications for direct on-demand reads only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoundedReadError {
    Missing,
    PermissionDenied,
    Unreadable,
    NonRegularSource,
    LimitExceeded,
    MalformedSource,
}

impl BoundedReadError {
    pub fn code(self) -> &'static str {
        match self {
            Self::Missing => "source_missing",
            Self::PermissionDenied => "source_permission_denied",
            Self::Unreadable => "source_unreadable",
            Self::NonRegularSource => "non_regular_source",
            Self::LimitExceeded => "source_limit_exceeded",
            Self::MalformedSource => "malformed_source",
        }
    }

    fn from_io(error: std::io::Error) -> Self {
        match error.kind() {
            std::io::ErrorKind::NotFound => Self::Missing,
            std::io::ErrorKind::PermissionDenied => Self::PermissionDenied,
            _ => Self::Unreadable,
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

#[cfg(feature = "opencode-sqlite")]
impl From<rusqlite::Error> for SourceReadError {
    fn from(error: rusqlite::Error) -> Self {
        Self::from_sqlite(error)
    }
}

#[cfg(feature = "opencode-sqlite")]
impl SourceReadError {
    pub(crate) fn from_sqlite(error: rusqlite::Error) -> Self {
        match error.sqlite_error_code() {
            Some(rusqlite::ErrorCode::DatabaseBusy) | Some(rusqlite::ErrorCode::DatabaseLocked) => {
                Self::Locked
            }
            _ => Self::Sqlite,
        }
    }
}

#[cfg(test)]
pub(crate) fn read_jsonl_values(source: &Source) -> Result<Vec<Value>, SourceReadError> {
    read_jsonl_values_with_limits(source, crate::acquisition::SourceAccess::ByName)
        .map(|(values, _)| values)
}

/// The values and the number of bytes read, which scale the source's bounds.
pub(crate) fn read_jsonl_values_with_limits(
    source: &Source,
    access: crate::acquisition::SourceAccess<'_>,
) -> Result<(Vec<Value>, usize), SourceReadError> {
    use crate::acquisition::{AnchoredRead, DirectRead, SourceAccess};
    match access {
        SourceAccess::Direct(DirectRead { root, limits }) => {
            let bytes = confined_file_bytes(root, &source.path, limits.bytes)
                .map_err(SourceReadError::Bounded)?;
            check_json_depth(&bytes, limits.json_depth)
                .map_err(|_| SourceReadError::Bounded(BoundedReadError::LimitExceeded))?;
            let mut values = Vec::new();
            for line in bytes
                .split(|b| *b == b'\n')
                .filter(|line| !line.iter().all(u8::is_ascii_whitespace))
            {
                if values.len() == limits.records {
                    return Err(SourceReadError::Bounded(BoundedReadError::LimitExceeded));
                }
                values.push(serde_json::from_slice(line)?);
            }
            Ok((values, bytes.len()))
        }
        SourceAccess::Anchored(AnchoredRead { root, max_bytes }) => read_production_jsonl(
            open_anchored(root, &source.path).map_err(SourceReadError::Bounded)?,
            max_bytes,
            || SourceReadError::Bounded(BoundedReadError::LimitExceeded),
        ),
        SourceAccess::Resolved => read_production_jsonl(
            open_resolved(&source.path).map_err(SourceReadError::Bounded)?,
            PRODUCTION_SOURCE_BYTES,
            production_limit_error,
        ),
        SourceAccess::ByName => read_production_jsonl(
            fs::File::open(&source.path)?,
            PRODUCTION_SOURCE_BYTES,
            production_limit_error,
        ),
    }
}

pub(crate) const PRODUCTION_RECORD_BYTES: usize = 8 * 1024 * 1024;
pub(crate) const PRODUCTION_SOURCE_BYTES: usize = 128 * 1024 * 1024;
/// The native unit floor; JSONL session sources scale it by bytes read.
pub(crate) const PRODUCTION_NATIVE_UNITS: usize = 100_000;

fn production_limit_error() -> SourceReadError {
    std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "production JSONL admission limit exceeded",
    )
    .into()
}

// Bound physical bytes before UTF-8/JSON decoding. Limits apply to actual reads,
// including blank records and terminators, not a potentially stale file length.
// The native unit limit scales with the bytes read so far. A transcript read
// may lower the source byte bound; every other bound is the production one.
// Parsed values remain retained; this is not an allocator or process RSS budget.
fn read_production_jsonl(
    mut reader: impl Read,
    source_bytes: usize,
    limit_error: fn() -> SourceReadError,
) -> Result<(Vec<Value>, usize), SourceReadError> {
    let mut chunk = [0u8; 8192];
    let mut record = Vec::new();
    let mut total = 0usize;
    let mut units = PRODUCTION_NATIVE_UNITS;
    let mut values = Vec::new();
    loop {
        let read = match reader.read(&mut chunk) {
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            result => result?,
        };
        if read == 0 {
            if !record.is_empty() {
                decode_production_record(&record, &mut values, units, limit_error)?;
            }
            return Ok((values, total));
        }
        total = total
            .checked_add(read)
            .filter(|bytes| *bytes <= source_bytes)
            .ok_or_else(limit_error)?;
        units = SourceScale::for_source_bytes(total).apply(PRODUCTION_NATIVE_UNITS);
        for part in chunk[..read].split_inclusive(|byte| *byte == b'\n') {
            record
                .len()
                .checked_add(part.len())
                .filter(|bytes| *bytes <= PRODUCTION_RECORD_BYTES)
                .ok_or_else(limit_error)?;
            record.extend_from_slice(part);
            if part.last() == Some(&b'\n') {
                decode_production_record(&record, &mut values, units, limit_error)?;
                record.clear();
            }
        }
    }
}

fn decode_production_record(
    record: &[u8],
    values: &mut Vec<Value>,
    units: usize,
    limit_error: fn() -> SourceReadError,
) -> Result<(), SourceReadError> {
    let line = std::str::from_utf8(record)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid JSONL UTF-8"))?;
    if !line.trim().is_empty() {
        values
            .len()
            .checked_add(1)
            .filter(|count| *count <= units)
            .ok_or_else(limit_error)?;
        values.push(serde_json::from_str(line)?);
    }
    Ok(())
}

// Validate the opened object, not a pathname precheck. Nonblocking open avoids
// hanging on a replacement FIFO; no-follow rejects symlinks at the final component.
// On Windows that open bypasses the filter that owns any other reparse point
// (such as a cloud placeholder), so its raw bytes are not the file's content:
// every reparse point is refused here. The confined and resolved readers reopen
// such a file through its filter instead (see `telltale-discover`'s walk).
pub(crate) fn bounded_file_bytes(
    path: &std::path::Path,
    cap: usize,
) -> Result<Vec<u8>, BoundedReadError> {
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
    let file = options.open(path).map_err(BoundedReadError::from_io)?;
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if file
            .metadata()
            .map_err(BoundedReadError::from_io)?
            .file_attributes()
            & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
            != 0
        {
            return Err(BoundedReadError::NonRegularSource);
        }
    }
    bounded_bytes(file, cap)
}

/// `bounded_file_bytes` for a source coordinate opened under the trust anchors
/// of the discovery `root` it belongs to (`telltale-discover`'s
/// `open_source_file`): the anchor is resolved once, and no link below it is
/// followed, at the file or any ancestor, even if a pathname is replaced during
/// the open. A path under no anchor is walked strictly from the filesystem root.
/// A refused link is not a regular source.
pub(crate) fn confined_file_bytes(
    root: &std::path::Path,
    path: &std::path::Path,
    cap: usize,
) -> Result<Vec<u8>, BoundedReadError> {
    bounded_bytes(open_confined(root, path)?, cap)
}

fn open_confined(
    root: &std::path::Path,
    path: &std::path::Path,
) -> Result<fs::File, BoundedReadError> {
    use telltale_discover::discovery::{BoundedDiscoveryError, open_source_file};
    match open_source_file(root, path) {
        Ok(Some(file)) => Ok(file),
        Ok(None) => Err(BoundedReadError::Missing),
        Err(BoundedDiscoveryError::SymlinkRoot) => Err(BoundedReadError::NonRegularSource),
        Err(BoundedDiscoveryError::PermissionDenied) => Err(BoundedReadError::PermissionDenied),
        Err(_) => Err(BoundedReadError::Unreadable),
    }
}

/// A transcript coordinate opened without following links: under the trust
/// anchors of `root` when given, otherwise as an already-resolved path.
/// The opened object must be a regular file.
fn open_anchored(
    root: Option<&std::path::Path>,
    path: &std::path::Path,
) -> Result<fs::File, BoundedReadError> {
    let Some(root) = root else {
        return open_resolved(path);
    };
    let file = open_confined(root, path)?;
    if !file
        .metadata()
        .map_err(BoundedReadError::from_io)?
        .is_file()
    {
        return Err(BoundedReadError::NonRegularSource);
    }
    Ok(file)
}

/// `bounded_file_bytes` for a transcript coordinate (see `open_anchored`).
pub(crate) fn anchored_file_bytes(
    root: Option<&std::path::Path>,
    path: &std::path::Path,
    cap: usize,
) -> Result<Vec<u8>, BoundedReadError> {
    bounded_bytes(open_anchored(root, path)?, cap)
}

/// An already-resolved (canonical) path opened without following any link or
/// blocking (`telltale-discover`'s `open_resolved_file`), checked to be a
/// regular file. A link anywhere in the path, including one swapped in after
/// resolution, is not a regular source.
fn open_resolved(path: &std::path::Path) -> Result<fs::File, BoundedReadError> {
    use telltale_discover::discovery::{BoundedDiscoveryError, open_resolved_file};
    let file = match open_resolved_file(path) {
        Ok(Some(file)) => file,
        Ok(None) => return Err(BoundedReadError::Missing),
        Err(BoundedDiscoveryError::SymlinkRoot) => return Err(BoundedReadError::NonRegularSource),
        Err(BoundedDiscoveryError::PermissionDenied) => {
            return Err(BoundedReadError::PermissionDenied);
        }
        Err(_) => return Err(BoundedReadError::Unreadable),
    };
    let metadata = file.metadata().map_err(BoundedReadError::from_io)?;
    if !metadata.is_file() {
        return Err(BoundedReadError::NonRegularSource);
    }
    Ok(file)
}

/// `bounded_file_bytes` for an already-resolved path (see `open_resolved`).
pub(crate) fn resolved_file_bytes(
    path: &std::path::Path,
    cap: usize,
) -> Result<Vec<u8>, BoundedReadError> {
    bounded_bytes(open_resolved(path)?, cap)
}

fn bounded_bytes(file: fs::File, cap: usize) -> Result<Vec<u8>, BoundedReadError> {
    let metadata = file.metadata().map_err(BoundedReadError::from_io)?;
    if !metadata.is_file() {
        return Err(BoundedReadError::NonRegularSource);
    }
    if metadata.len() > cap as u64 {
        return Err(BoundedReadError::LimitExceeded);
    }
    let mut bytes = Vec::new();
    file.take(cap as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(BoundedReadError::from_io)?;
    if bytes.len() > cap {
        return Err(BoundedReadError::LimitExceeded);
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

#[cfg(test)]
mod tests;
