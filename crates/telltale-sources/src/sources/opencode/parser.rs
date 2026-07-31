//! OpenCode source parsing: SQLite session store and legacy JSON messages.

use rusqlite::{Connection, ErrorCode};
use serde_json::Value;

use crate::parser::{
    ExtractedSourceRecords, ParseError, ParseOptions, ParsedRecord, arguments_field,
    default_source_parent_name, model_field, provider_field, read_json_document, record_content,
    record_kind, session_id_with_fallback, string_field, tool_name,
};
use telltale_schema::record::RecordKind;
use telltale_schema::source::Source;

pub(crate) const SQLITE_PART_LIMIT: i64 = 5_000;

pub(crate) fn extract_opencode_json_source(
    source: &Source,
    _options: ParseOptions,
) -> Result<ExtractedSourceRecords, ParseError> {
    let value = read_json_document(source)?;
    let default_session_id = default_source_parent_name(source);
    let values = match &value {
        Value::Object(_) => vec![&value],
        Value::Array(items) => {
            if items.iter().any(|item| !item.is_object()) {
                return Err(ParseError::SchemaDrift {
                    client: source.client,
                    source_id: source.source_id.clone(),
                    detail: "JSON document records must be objects",
                });
            }
            items.iter().collect()
        }
        _ => {
            return Err(ParseError::SchemaDrift {
                client: source.client,
                source_id: source.source_id.clone(),
                detail: "JSON document envelope must be an object",
            });
        }
    };

    Ok(ExtractedSourceRecords::records(
        values
            .into_iter()
            .map(|value| opencode_json_record(value, &default_session_id))
            .collect(),
    ))
}

fn opencode_json_record(value: &Value, default_session_id: &str) -> ParsedRecord {
    ParsedRecord {
        session_id: session_id_with_fallback(value, default_session_id),
        agent: string_field(value, "agent"),
        model: model_field(value),
        provider: provider_field(value),
        timestamp: string_field(value, "timestamp").or_else(|| string_field(value, "time")),
        kind: opencode_json_record_kind(value),
        tool_name: opencode_json_tool_name(value),
        arguments: arguments_field(value),
        content: record_content(value),
    }
}

fn opencode_json_record_kind(value: &Value) -> RecordKind {
    let discriminator = opencode_json_discriminator(value);
    if discriminator.is_some_and(|kind| !is_known_opencode_json_discriminator(kind)) {
        return RecordKind::Other;
    }

    if content_blocks(value).is_some_and(|blocks| {
        blocks
            .iter()
            .any(|block| block.get("type").and_then(Value::as_str) == Some("tool_use"))
    }) {
        return RecordKind::ToolCall;
    }
    if content_blocks(value).is_some_and(|blocks| {
        blocks
            .iter()
            .any(|block| block.get("type").and_then(Value::as_str) == Some("tool_result"))
    }) {
        return RecordKind::ToolResult;
    }

    match discriminator {
        Some("user_message" | "user") => RecordKind::UserMessage,
        Some("assistant_message" | "assistant" | "gemini" | "model") => {
            RecordKind::AssistantMessage
        }
        Some("text") if value.get("role").and_then(Value::as_str) == Some("user") => {
            RecordKind::UserMessage
        }
        Some("text")
            if matches!(
                value.get("role").and_then(Value::as_str),
                Some("assistant" | "model")
            ) =>
        {
            RecordKind::AssistantMessage
        }
        Some("tool_call") => RecordKind::ToolCall,
        Some("tool_result") => RecordKind::ToolResult,
        Some("tool") if opencode_tool_part_is_result(value) => RecordKind::ToolResult,
        Some("tool") => RecordKind::ToolCall,
        Some("session_meta") => RecordKind::SessionMeta,
        _ if value.get("session_meta").is_some() => RecordKind::SessionMeta,
        _ => RecordKind::Other,
    }
}

fn opencode_json_discriminator(value: &Value) -> Option<&str> {
    value
        .get("payload")
        .and_then(|payload| payload.get("type"))
        .and_then(Value::as_str)
        .or_else(|| {
            value
                .get("payload")
                .and_then(|payload| payload.get("payload"))
                .and_then(|payload| payload.get("type"))
                .and_then(Value::as_str)
        })
        .or_else(|| value.get("type").and_then(Value::as_str))
        .or_else(|| value.get("role").and_then(Value::as_str))
        .or_else(|| {
            value
                .get("message")
                .and_then(|message| message.get("role"))
                .and_then(Value::as_str)
        })
}

fn is_known_opencode_json_discriminator(kind: &str) -> bool {
    matches!(
        kind,
        "user_message"
            | "user"
            | "assistant_message"
            | "assistant"
            | "gemini"
            | "model"
            | "text"
            | "tool_call"
            | "tool_result"
            | "tool"
            | "session_meta"
    )
}

fn content_blocks(value: &Value) -> Option<&Vec<Value>> {
    value
        .get("message")
        .and_then(|message| message.get("content"))
        .or_else(|| value.get("content"))
        .and_then(Value::as_array)
}

fn opencode_json_tool_name(value: &Value) -> Option<String> {
    string_field(value, "tool_name")
        .or_else(|| string_field(value, "tool"))
        .or_else(|| string_field(value, "name"))
        .or_else(|| {
            content_blocks(value)?
                .iter()
                .find(|block| block.get("type").and_then(Value::as_str) == Some("tool_use"))?
                .get("name")?
                .as_str()
                .map(ToString::to_string)
        })
}

impl From<rusqlite::Error> for ParseError {
    fn from(e: rusqlite::Error) -> Self {
        match e.sqlite_error_code() {
            Some(ErrorCode::DatabaseBusy) | Some(ErrorCode::DatabaseLocked) => {
                ParseError::Locked(e.to_string())
            }
            _ => ParseError::Sqlite(e),
        }
    }
}

pub(crate) fn extract_sqlite_source(
    source: &Source,
    options: ParseOptions,
) -> Result<ExtractedSourceRecords, ParseError> {
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

    Ok(ExtractedSourceRecords {
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

fn extract_sqlite_message_records(conn: &Connection) -> Result<Vec<ParsedRecord>, ParseError> {
    let mut stmt = conn.prepare("select * from message order by rowid")?;
    let rows = sqlite_rows_as_values(&mut stmt)?;

    Ok(rows
        .into_iter()
        .map(normalize_sqlite_message_value)
        .map(|value| sqlite_value_record(&value, "unknown"))
        .collect())
}

fn extract_sqlite_part_records(
    conn: &Connection,
    options: ParseOptions,
    include_message_context: bool,
) -> Result<(Vec<ParsedRecord>, Option<i64>), ParseError> {
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
        .map(normalize_sqlite_part_value)
        .map(|value| sqlite_value_record(&value, "unknown"))
        .collect();

    Ok((records, max_time_updated))
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

    if let Some(message_data) = object
        .get("__telltale_message_data")
        .and_then(Value::as_str)
        && let Ok(Value::Object(message_object)) = serde_json::from_str::<Value>(message_data)
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
