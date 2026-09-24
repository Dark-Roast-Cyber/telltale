//! Source-native read errors and shared JSONL reading.
//!
//! This module is not a parser, projection, registry, or record model. Adapters
//! own their native structures and map them directly to canonical acquisition.

use serde_json::Value;
use std::fmt;
use std::fs;

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
    let raw = fs::read_to_string(&source.path)?;
    raw.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str::<Value>(line).map_err(SourceReadError::from))
        .collect()
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
