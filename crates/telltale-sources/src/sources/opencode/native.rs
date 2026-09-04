#![allow(dead_code)]

use rusqlite::Connection;
use serde_json::Value;

use crate::parser::{
    ParseError, ParseOptions, ParsedRecord, arguments_field, model_field, provider_field,
    record_content, record_kind, session_id_with_fallback, string_field, tool_name,
};
use telltale_schema::source::Source;

#[derive(Clone)]
pub(crate) struct OpenCodeMessageContext {
    pub(crate) session_id: Option<String>,
    pub(crate) role: Option<String>,
    pub(crate) agent: Option<String>,
    pub(crate) model: Option<String>,
    pub(crate) provider: Option<String>,
    pub(crate) parent_id: Option<String>,
    pub(crate) occurrence_time: Option<String>,
}

#[derive(Clone)]
pub(crate) struct OpenCodeToolState {
    pub(crate) status: Option<String>,
    pub(crate) status_present: bool,
    pub(crate) input: Option<Value>,
    pub(crate) input_present: bool,
    pub(crate) output: Option<Value>,
    pub(crate) output_present: bool,
    pub(crate) error: Option<Value>,
    pub(crate) error_present: bool,
    pub(crate) is_error: Option<bool>,
    pub(crate) is_error_present: bool,
    pub(crate) start_time: Option<String>,
    pub(crate) end_time: Option<String>,
}

#[derive(Clone)]
pub(crate) struct OpenCodeMessageNativeRecord {
    pub(crate) source_sequence: u64,
    pub(crate) source_id: Option<String>,
    pub(crate) context: OpenCodeMessageContext,
    pub(crate) message_type: Option<String>,
    pub(crate) content: Option<Value>,
    pub(crate) tool_name: Option<String>,
    pub(crate) call_id: Option<String>,
    pub(crate) arguments: Option<Value>,
    pub(crate) arguments_present: bool,
    pub(crate) result: Option<Value>,
    pub(crate) result_present: bool,
    pub(crate) error: Option<Value>,
    pub(crate) error_present: bool,
    pub(crate) tool_state: Option<OpenCodeToolState>,
    pub(crate) tool_state_invalid: bool,
    pub(crate) legacy: ParsedRecord,
}

#[derive(Clone)]
pub(crate) struct OpenCodeTextPartNativeRecord {
    pub(crate) source_rowid: i64,
    pub(crate) source_id: Option<String>,
    pub(crate) message_id: Option<String>,
    pub(crate) context: OpenCodeMessageContext,
    pub(crate) text: Option<String>,
    pub(crate) occurrence_time: Option<String>,
    pub(crate) legacy: ParsedRecord,
}

#[derive(Clone)]
pub(crate) struct OpenCodeToolPartNativeRecord {
    pub(crate) source_rowid: i64,
    pub(crate) source_id: Option<String>,
    pub(crate) message_id: Option<String>,
    pub(crate) context: OpenCodeMessageContext,
    pub(crate) tool_name: Option<String>,
    pub(crate) call_id: Option<String>,
    pub(crate) state: OpenCodeToolState,
    pub(crate) tool_state_invalid: bool,
    pub(crate) legacy: ParsedRecord,
}

#[derive(Clone)]
pub(crate) enum OpenCodeSqliteNativeRecord {
    Message(OpenCodeMessageNativeRecord),
    Text(OpenCodeTextPartNativeRecord),
    Tool(OpenCodeToolPartNativeRecord),
}

impl OpenCodeSqliteNativeRecord {
    pub(crate) fn legacy_record(self) -> ParsedRecord {
        match self {
            Self::Message(record) => record.legacy,
            Self::Text(record) => record.legacy,
            Self::Tool(record) => record.legacy,
        }
    }

    pub(crate) fn message_id(&self) -> Option<&str> {
        match self {
            Self::Message(record) => record.source_id.as_deref(),
            Self::Text(record) => record.message_id.as_deref(),
            Self::Tool(record) => record.message_id.as_deref(),
        }
    }
}

pub(crate) struct OpenCodeSqliteNativeExtraction {
    pub(crate) records: Vec<OpenCodeSqliteNativeRecord>,
    pub(crate) sqlite_part_max_time_updated: Option<i64>,
}

pub(crate) fn extract_sqlite_native_source(
    source: &Source,
    options: ParseOptions,
) -> Result<OpenCodeSqliteNativeExtraction, ParseError> {
    let conn = Connection::open(&source.path)?;
    conn.busy_timeout(std::time::Duration::from_millis(5000))?;
    let mut records = Vec::new();
    let mut sqlite_part_max_time_updated = None;

    let has_message_table = sqlite_table_exists(&conn, "message")?;
    if has_message_table {
        records.extend(extract_sqlite_message_records(&conn)?);
    }
    if sqlite_table_exists(&conn, "part")? {
        let (part_records, max_time_updated) =
            extract_sqlite_part_records(&conn, options, has_message_table)?;
        records.extend(part_records);
        sqlite_part_max_time_updated = max_time_updated;
    }

    Ok(OpenCodeSqliteNativeExtraction {
        records,
        sqlite_part_max_time_updated,
    })
}

fn sqlite_table_exists(conn: &Connection, table_name: &str) -> Result<bool, rusqlite::Error> {
    conn.query_row(
        "select exists(select 1 from sqlite_master where type = 'table' and name = ?1)",
        [table_name],
        |row| row.get::<_, bool>(0),
    )
}

fn extract_sqlite_message_records(
    conn: &Connection,
) -> Result<Vec<OpenCodeSqliteNativeRecord>, ParseError> {
    let mut stmt = conn.prepare("select * from message order by rowid")?;
    let rows = sqlite_rows_as_values(&mut stmt)?;

    Ok(rows
        .into_iter()
        .enumerate()
        .map(|(source_sequence, value)| {
            let normalized = normalize_sqlite_message_value(value.clone());
            let context = message_context(&normalized);
            let content = normalized
                .get("content")
                .cloned()
                .or_else(|| normalized.get("message").cloned());
            let arguments = normalized
                .get("arguments")
                .cloned()
                .or_else(|| normalized.get("input").cloned());
            let result = normalized
                .get("result")
                .cloned()
                .or_else(|| normalized.get("output").cloned())
                .or_else(|| {
                    (string_field(&normalized, "type").as_deref() == Some("tool_result"))
                        .then(|| content.clone())
                        .flatten()
                });
            let error = normalized.get("error").cloned();
            let legacy = sqlite_value_record(&normalized, "unknown");
            OpenCodeSqliteNativeRecord::Message(OpenCodeMessageNativeRecord {
                source_sequence: source_sequence as u64,
                source_id: source_string_field(&value, "id"),
                context,
                message_type: string_field(&normalized, "type"),
                content,
                tool_name: tool_name(&normalized),
                call_id: source_call_id(&normalized),
                arguments_present: arguments.is_some(),
                arguments,
                result_present: result.is_some(),
                result,
                error_present: error.is_some(),
                error,
                tool_state: tool_state(&normalized),
                tool_state_invalid: tool_state_is_invalid(&normalized),
                legacy,
            })
        })
        .collect())
}

fn extract_sqlite_part_records(
    conn: &Connection,
    options: ParseOptions,
    include_message_context: bool,
) -> Result<(Vec<OpenCodeSqliteNativeRecord>, Option<i64>), ParseError> {
    let limit = options.sqlite_part_limit.max(1);
    let rows = if let Some(min_time_updated) = options.sqlite_part_min_time_updated {
        let query = sqlite_part_query(true, include_message_context);
        let mut stmt = conn.prepare(&query)?;
        sqlite_rows_as_values_with_params(&mut stmt, rusqlite::params![min_time_updated, limit])?
    } else {
        let query = sqlite_part_query(false, include_message_context);
        let mut stmt = conn.prepare(&query)?;
        sqlite_rows_as_values_with_params(&mut stmt, rusqlite::params![limit])?
    };

    let max_time_updated = rows.iter().filter_map(sqlite_time_updated).max();
    let records = rows
        .into_iter()
        .map(|value| sqlite_part_native_record(&value))
        .collect();

    Ok((records, max_time_updated))
}

fn sqlite_part_native_record(raw_value: &Value) -> OpenCodeSqliteNativeRecord {
    let value = normalize_sqlite_part_value(raw_value.clone());
    let source_rowid = raw_value
        .get("__telltale_rowid")
        .and_then(Value::as_i64)
        .unwrap_or_default();
    let source_id = source_string_field(raw_value, "id");
    let message_id = source_string_field(raw_value, "message_id");
    let context = merge_message_context(message_context(&value), joined_message_context(raw_value));
    let legacy = sqlite_value_record(&value, "unknown");
    let part_type = string_field(&value, "type");

    if part_type.as_deref() == Some("text") {
        return OpenCodeSqliteNativeRecord::Text(OpenCodeTextPartNativeRecord {
            source_rowid,
            source_id,
            message_id,
            occurrence_time: part_occurrence_time(&value),
            text: value
                .get("text")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
            context,
            legacy,
        });
    }

    OpenCodeSqliteNativeRecord::Tool(OpenCodeToolPartNativeRecord {
        source_rowid,
        source_id,
        message_id,
        tool_name: tool_name(&value),
        call_id: source_call_id(&value),
        state: tool_state(&value).unwrap_or_else(empty_tool_state),
        context,
        tool_state_invalid: tool_state_is_invalid(&value),
        legacy,
    })
}

fn sqlite_part_query(has_min_time_updated: bool, include_message_context: bool) -> String {
    let select = if include_message_context {
        "select part.*, part.rowid as __telltale_rowid, message.data as __telltale_message_data \
         from part left join message on message.id = part.message_id"
    } else {
        "select part.*, part.rowid as __telltale_rowid from part"
    };
    let min_filter = if has_min_time_updated {
        " and part.time_updated >= ?1"
    } else {
        ""
    };
    let limit_param = if has_min_time_updated { "?2" } else { "?1" };
    let order = if has_min_time_updated {
        "part.time_updated, part.rowid"
    } else {
        "part.time_updated desc, part.rowid desc"
    };

    format!(
        "select * from (
            {select}
            where json_extract(part.data, '$.type') in ('tool', 'text')
              {min_filter}
            order by {order}
            limit {limit_param}
         ) order by time_updated, __telltale_rowid"
    )
}

fn sqlite_time_updated(value: &Value) -> Option<i64> {
    value.get("time_updated").and_then(Value::as_i64)
}

fn sqlite_rows_as_values(
    stmt: &mut rusqlite::Statement<'_>,
) -> Result<Vec<Value>, rusqlite::Error> {
    sqlite_rows_as_values_with_params(stmt, [])
}

fn sqlite_rows_as_values_with_params<P: rusqlite::Params>(
    stmt: &mut rusqlite::Statement<'_>,
    params: P,
) -> Result<Vec<Value>, rusqlite::Error> {
    let column_names = stmt
        .column_names()
        .into_iter()
        .map(|name| name.to_string())
        .collect::<Vec<_>>();
    let mut rows = stmt.query(params)?;
    let mut records = Vec::new();
    while let Some(row) = rows.next()? {
        let mut object = serde_json::Map::new();
        for (index, name) in column_names.iter().enumerate() {
            let value = row.get_ref(index)?;
            object.insert(name.clone(), sqlite_value_to_json(value));
        }
        records.push(Value::Object(object));
    }
    Ok(records)
}

fn sqlite_value_record(value: &Value, default_session_id: &str) -> ParsedRecord {
    ParsedRecord {
        session_id: session_id_with_fallback(value, default_session_id),
        agent: string_field(value, "agent"),
        model: model_field(value),
        provider: provider_field(value),
        timestamp: string_field(value, "time").or_else(|| string_field(value, "timestamp")),
        kind: record_kind(value),
        tool_name: tool_name(value),
        arguments: arguments_field(value),
        content: record_content(value),
    }
}

pub(crate) fn opencode_tool_part_is_result(value: &Value) -> bool {
    value
        .get("state")
        .and_then(|state| state.get("status"))
        .and_then(Value::as_str)
        .is_some_and(|status| matches!(status, "completed" | "error"))
        || value
            .get("state")
            .and_then(|state| state.get("output").or_else(|| state.get("error")))
            .is_some()
}

fn normalize_sqlite_message_value(value: Value) -> Value {
    let Value::Object(object) = value else {
        return value;
    };

    let Some(data) = object.get("data").and_then(Value::as_str) else {
        return Value::Object(object);
    };

    let Ok(Value::Object(mut data_object)) = serde_json::from_str::<Value>(data) else {
        return Value::Object(object);
    };

    for (key, value) in object {
        data_object.entry(key).or_insert(value);
    }

    Value::Object(data_object)
}

fn normalize_sqlite_part_value(value: Value) -> Value {
    let Value::Object(object) = value else {
        return value;
    };

    let Some(data) = object.get("data").and_then(Value::as_str) else {
        return Value::Object(object);
    };

    let Ok(Value::Object(mut data_object)) = serde_json::from_str::<Value>(data) else {
        return Value::Object(object);
    };

    if let Some(Value::Object(message_object)) = object
        .get("__telltale_message_data")
        .and_then(Value::as_str)
        .and_then(|message_data| serde_json::from_str::<Value>(message_data).ok())
    {
        for key in [
            "role",
            "agent",
            "modelID",
            "model",
            "providerID",
            "provider",
        ] {
            if let Some(value) = message_object.get(key) {
                data_object.entry(key.to_string()).or_insert(value.clone());
            }
        }
    }

    if let Some(Value::Object(state)) = data_object.get("state") {
        let input = state.get("input").cloned();
        let output = state.get("output").or_else(|| state.get("error")).cloned();
        if let Some(input) = input {
            data_object.entry("input".to_string()).or_insert(input);
        }
        if let Some(output) = output {
            data_object.entry("message".to_string()).or_insert(output);
        }
    }

    for (key, value) in object {
        if key.starts_with("__telltale_") {
            continue;
        }
        data_object.entry(key).or_insert(value);
    }

    Value::Object(data_object)
}

fn sqlite_value_to_json(value: rusqlite::types::ValueRef<'_>) -> Value {
    match value {
        rusqlite::types::ValueRef::Null => Value::Null,
        rusqlite::types::ValueRef::Integer(value) => Value::from(value),
        rusqlite::types::ValueRef::Real(value) => Value::from(value),
        rusqlite::types::ValueRef::Text(value) => {
            Value::String(String::from_utf8_lossy(value).to_string())
        }
        rusqlite::types::ValueRef::Blob(value) => {
            Value::String(format!("<blob:{} bytes>", value.len()))
        }
    }
}

fn source_string_field(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn source_call_id(value: &Value) -> Option<String> {
    source_string_field(value, "callID")
        .or_else(|| source_string_field(value, "call_id"))
        .or_else(|| source_string_field(value, "callId"))
        .or_else(|| {
            value
                .get("state")
                .and_then(|state| source_string_field(state, "callID"))
        })
}

fn message_context(value: &Value) -> OpenCodeMessageContext {
    OpenCodeMessageContext {
        session_id: source_session_id(value),
        role: source_role(value),
        agent: string_field(value, "agent"),
        model: model_field(value),
        provider: provider_field(value),
        parent_id: string_field(value, "parentID").or_else(|| string_field(value, "parent_id")),
        occurrence_time: message_occurrence_time(value),
    }
}

fn source_role(value: &Value) -> Option<String> {
    string_field(value, "role")
        .filter(|value| !value.is_empty())
        .or_else(|| {
            string_field(value, "type").and_then(|kind| match kind.as_str() {
                "user" | "user_message" => Some("user".to_owned()),
                "assistant" | "assistant_message" | "gemini" | "model" => {
                    Some("assistant".to_owned())
                }
                _ => None,
            })
        })
}

fn source_session_id(value: &Value) -> Option<String> {
    ["session_id", "sessionID", "sessionId"]
        .into_iter()
        .find_map(|key| string_field(value, key).filter(|value| !value.is_empty()))
}

fn joined_message_context(value: &Value) -> Option<OpenCodeMessageContext> {
    let data = value
        .get("__telltale_message_data")
        .and_then(Value::as_str)?;
    let message = serde_json::from_str::<Value>(data).ok()?;
    Some(message_context(&message))
}

fn merge_message_context(
    mut part: OpenCodeMessageContext,
    message: Option<OpenCodeMessageContext>,
) -> OpenCodeMessageContext {
    let Some(message) = message else {
        return part;
    };
    part.session_id = part.session_id.or(message.session_id);
    part.role = part.role.or(message.role);
    part.agent = part.agent.or(message.agent);
    part.model = part.model.or(message.model);
    part.provider = part.provider.or(message.provider);
    part.parent_id = part.parent_id.or(message.parent_id);
    part.occurrence_time = part.occurrence_time.or(message.occurrence_time);
    part
}

fn message_occurrence_time(value: &Value) -> Option<String> {
    source_time_field(value.get("time"), "created")
        .or_else(|| source_time_field(value.get("timestamp"), "created"))
        .or_else(|| source_time_field(value.get("time_created"), "created"))
}

fn part_occurrence_time(value: &Value) -> Option<String> {
    source_time_field(value.get("time"), "start")
        .or_else(|| source_time_field(value.get("timestamp"), "start"))
        .or_else(|| source_time_field(value.get("time_created"), "created"))
}

fn source_time_field(value: Option<&Value>, object_key: &str) -> Option<String> {
    let value = value?;
    match value {
        Value::String(value) => Some(value.clone()),
        Value::Number(_) => value.as_i64().and_then(unix_millis_timestamp),
        Value::Object(values) => values
            .get(object_key)
            .or_else(|| values.get("created"))
            .or_else(|| values.get("start"))
            .and_then(|value| source_time_field(Some(value), object_key)),
        _ => None,
    }
}

fn unix_millis_timestamp(value: i64) -> Option<String> {
    let nanos = i128::from(value).checked_mul(1_000_000)?;
    let timestamp = time::OffsetDateTime::from_unix_timestamp_nanos(nanos).ok()?;
    timestamp
        .format(&time::format_description::well_known::Rfc3339)
        .ok()
}

fn tool_state(value: &Value) -> Option<OpenCodeToolState> {
    let state = value.get("state")?.as_object()?;
    let status_present = state.contains_key("status");
    let input_present = state.contains_key("input") || value.get("input").is_some();
    let output_present = state.contains_key("output") || value.get("output").is_some();
    let error_present = state.contains_key("error") || value.get("error").is_some();
    let input = state
        .get("input")
        .cloned()
        .or_else(|| value.get("input").cloned());
    let output = state
        .get("output")
        .cloned()
        .or_else(|| value.get("output").cloned());
    let error = state
        .get("error")
        .cloned()
        .or_else(|| value.get("error").cloned());
    let is_error_present = state.contains_key("is_error") || value.get("is_error").is_some();
    let is_error = state
        .get("is_error")
        .or_else(|| value.get("is_error"))
        .and_then(Value::as_bool);
    let time = state.get("time");
    let start_time = time
        .and_then(|value| source_time_field(Some(value), "start"))
        .or_else(|| {
            state
                .get("input")
                .and_then(|input| input.get("created"))
                .and_then(|value| source_time_field(Some(value), "created"))
        });
    let end_time = time
        .and_then(|value| value.get("end"))
        .and_then(|value| source_time_field(Some(value), "end"))
        .or_else(|| {
            state
                .get("input")
                .and_then(|input| input.get("completed"))
                .and_then(|value| source_time_field(Some(value), "completed"))
        });

    Some(OpenCodeToolState {
        status: state
            .get("status")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        status_present,
        input,
        input_present,
        output,
        output_present,
        error,
        error_present,
        is_error,
        is_error_present,
        start_time,
        end_time,
    })
}

fn tool_state_is_invalid(value: &Value) -> bool {
    value.get("state").is_some_and(|state| !state.is_object())
}

fn empty_tool_state() -> OpenCodeToolState {
    OpenCodeToolState {
        status: None,
        status_present: false,
        input: None,
        input_present: false,
        output: None,
        output_present: false,
        error: None,
        error_present: false,
        is_error: None,
        is_error_present: false,
        start_time: None,
        end_time: None,
    }
}
