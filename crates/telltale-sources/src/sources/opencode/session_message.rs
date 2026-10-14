//! OpenCode v2 `session_v2`/`session_message` native interpretation.
//!
//! Field meanings follow OpenCode v2.0.27
//! (1f4d07a4a519185955ae8ab2ea3607805509e386): `packages/core/src/database/schema.gen.ts`,
//! `packages/schema/src/session-message.ts`, and `packages/core/src/session/projector.ts`.
//! A message row keeps `id` and `type` in columns and every other field in `data`;
//! `seq` orders a session and `time_updated` changes on every in-place update.

use rusqlite::{Connection, OptionalExtension};
use serde_json::{Map, Value};
use telltale_schema::record::RecordKind;

use super::native::{
    OpenCodeSqliteReadOptions, SqliteAdmission, part_read_error, source_time_field,
    sqlite_table_exists, stream_sqlite_rows,
};
use crate::acquisition::{AcquisitionError, SessionMetadata, session_identity};
use crate::source_read::{SourceReadError, collect_string_values};

const SESSION_MESSAGE_COLUMNS: &[&str] =
    &["id", "session_id", "type", "seq", "time_updated", "data"];
const SESSION_COLUMNS: &[&str] = &["id", "agent", "model"];

/// Only these columns are projected; credential, path, title, permission and
/// other session columns are never selected.
const SELECT: &str = "select m.rowid as __telltale_rowid, m.id as id, m.session_id as session_id, \
     m.type as type, m.seq as seq, m.time_updated as time_updated, m.data as data, \
     s.agent as __telltale_session_agent, s.model as __telltale_session_model \
     from session_message m left join session_v2 s on s.id = m.session_id";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum NativeSchema {
    Legacy,
    SessionMessages,
}

/// Deterministic selection inside the caller's read snapshot. Complete v2
/// tables win, even beside legacy tables, so a migrated store never reads stale
/// legacy rows or both representations. Partial or column-incomplete v2 tables
/// fail without falling back to legacy history.
pub(super) fn select_native_schema(conn: &Connection) -> Result<NativeSchema, SourceReadError> {
    match (
        sqlite_table_exists(conn, "session_message")?,
        sqlite_table_exists(conn, "session_v2")?,
    ) {
        (false, false) => Ok(NativeSchema::Legacy),
        (true, true) => {
            require_columns(conn, "session_message", SESSION_MESSAGE_COLUMNS)?;
            require_columns(conn, "session_v2", SESSION_COLUMNS)?;
            Ok(NativeSchema::SessionMessages)
        }
        _ => Err(SourceReadError::UnsupportedSchema),
    }
}

fn require_columns(
    conn: &Connection,
    table: &str,
    required: &[&str],
) -> Result<(), SourceReadError> {
    let mut stmt = conn.prepare("select lower(name) from pragma_table_info(?1)")?;
    let present = stmt
        .query_map([table], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    if required
        .iter()
        .all(|column| present.iter().any(|name| name == column))
    {
        Ok(())
    } else {
        Err(SourceReadError::UnsupportedSchema)
    }
}

#[derive(Debug)]
pub(crate) struct OpenCodeSessionMessageExtraction {
    /// Ascending by `(time_updated, rowid)`: the order windows are cut in.
    /// Evaluation reorders admitted rows by source session and `seq`.
    pub(crate) records: Vec<OpenCodeSessionMessageRecord>,
    /// More rows matched than the row limit selected.
    pub(crate) truncated: bool,
    /// When truncated, the first unselected row's `time_updated`.
    pub(crate) next_time_updated: Option<i64>,
}

#[derive(Clone, Debug)]
pub(crate) struct OpenCodeSessionMessageRecord {
    pub(crate) source_id: Option<String>,
    pub(crate) session_id: Option<String>,
    pub(crate) seq: u64,
    /// The update coordinate this row was selected by.
    pub(crate) time_updated: i64,
    pub(crate) attestation: Result<SessionMetadata, AcquisitionError>,
    pub(crate) occurrence_time: Option<String>,
    pub(crate) body: OpenCodeSessionMessageBody,
}

#[derive(Clone, Debug)]
pub(crate) enum OpenCodeSessionMessageBody {
    User {
        text: Option<String>,
    },
    Assistant {
        /// `None` when `content` is not an array.
        content: Option<Vec<OpenCodeAssistantContent>>,
    },
    Shell(OpenCodeShell),
    /// A recognized message without canonical meaning in this adapter
    /// (agent/model/location switches, synthetic, system, skill, compaction, idle).
    Auxiliary(RecordKind),
    Unsupported,
}

#[derive(Clone, Debug)]
pub(crate) enum OpenCodeAssistantContent {
    Text(Option<String>),
    /// Recognized; raw reasoning is not retained.
    Reasoning,
    Tool(OpenCodeAssistantTool),
    Unsupported,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OpenCodeToolStatus {
    Streaming,
    Running,
    Completed,
    Error,
    Unsupported,
}

impl OpenCodeToolStatus {
    pub(crate) fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Error)
    }
}

#[derive(Clone, Debug)]
pub(crate) struct OpenCodeAssistantTool {
    pub(crate) id: Option<String>,
    pub(crate) name: Option<String>,
    /// Source-reported `executed`. OpenCode sets it from provider execution, so
    /// `false` does not prove that no local execution happened.
    pub(crate) executed: Option<bool>,
    pub(crate) status: OpenCodeToolStatus,
    /// Streaming input is the raw string; later states carry the input object.
    pub(crate) input: Option<Value>,
    /// Completed: all-text content joined as direct text (upstream joins shell
    /// result messages the same way), otherwise the `content` array with
    /// `data:` URI payloads reduced to their media type. Error: `error.message`
    /// as direct text, or the structured `error` object when it has none.
    pub(crate) result: Option<Value>,
    /// Reported `error.type`, and bytes of `data:` URI payloads not retained.
    pub(crate) result_facts: Option<Box<OpenCodeToolResultFacts>>,
    pub(crate) created: Option<String>,
    pub(crate) ran: Option<String>,
    pub(crate) completed: Option<String>,
    /// Settlement the `shell` tool reported in its completed metadata.
    pub(crate) shell_settlement: Option<Box<OpenCodeShellSettlement>>,
    pub(crate) malformed: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct OpenCodeToolResultFacts {
    pub(crate) error_type: Option<String>,
    pub(crate) omitted_bytes: Option<u64>,
}

/// The `shell` tool writes `{status, truncated, exit?, signal?, timeout?,
/// shellID?}` into its completed state only after the command was authorized,
/// ran and settled (`packages/core/src/tool/plugin/shell.ts`,
/// `packages/core/src/shell/result.ts`). A background command returns with
/// `status: "running"` instead and is not a settlement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OpenCodeShellSettlement {
    pub(crate) exit: Option<i64>,
    pub(crate) signal: Option<String>,
    pub(crate) timeout: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OpenCodeShellStatus {
    Running,
    Exited,
    Timeout,
    Killed,
    Unsupported,
}

#[derive(Clone, Debug)]
pub(crate) struct OpenCodeShell {
    pub(crate) shell_id: Option<String>,
    pub(crate) command: Option<String>,
    pub(crate) status: OpenCodeShellStatus,
    pub(crate) exit: Option<i64>,
    pub(crate) output: Option<String>,
    pub(crate) created: Option<String>,
    pub(crate) completed: Option<String>,
    pub(crate) malformed: bool,
}

/// One source-reported tool call within a native unit, for accounting only.
pub(crate) struct OpenCodeToolAccounting<'a> {
    pub(crate) name: Option<&'a str>,
    pub(crate) timestamp: Option<&'a str>,
    /// Request-side strings only (tool input, user shell command); returned
    /// results, errors and output are not activity.
    pub(crate) contribution_strings: Vec<String>,
}

pub(crate) const SHELL_TOOL_NAME: &str = "shell";

impl OpenCodeSessionMessageRecord {
    /// Classification of this native unit: one row, plus each tool call it holds
    /// and each terminal outcome reported in the same entry.
    pub(crate) fn accounting_kinds(&self) -> Vec<RecordKind> {
        match &self.body {
            OpenCodeSessionMessageBody::User { .. } => vec![RecordKind::UserMessage],
            OpenCodeSessionMessageBody::Assistant { content } => {
                let mut kinds = vec![RecordKind::AssistantMessage];
                for tool in assistant_tools(content.as_deref()) {
                    kinds.push(RecordKind::ToolCall);
                    if tool.status.is_terminal() {
                        kinds.push(RecordKind::ToolResult);
                    }
                }
                kinds
            }
            OpenCodeSessionMessageBody::Shell(shell) => {
                let mut kinds = vec![RecordKind::ToolCall];
                if shell.is_terminal() {
                    kinds.push(RecordKind::ToolResult);
                }
                kinds
            }
            OpenCodeSessionMessageBody::Auxiliary(kind) => vec![*kind],
            OpenCodeSessionMessageBody::Unsupported => vec![RecordKind::Other],
        }
    }

    pub(crate) fn tool_accounting(&self) -> Vec<OpenCodeToolAccounting<'_>> {
        match &self.body {
            OpenCodeSessionMessageBody::Assistant { content } => {
                assistant_tools(content.as_deref())
                    .map(|tool| OpenCodeToolAccounting {
                        name: tool.name.as_deref(),
                        timestamp: tool.created.as_deref(),
                        contribution_strings: tool
                            .input
                            .iter()
                            .flat_map(collect_string_values)
                            .collect(),
                    })
                    .collect()
            }
            OpenCodeSessionMessageBody::Shell(shell) => vec![OpenCodeToolAccounting {
                name: Some(SHELL_TOOL_NAME),
                timestamp: shell.created.as_deref(),
                contribution_strings: shell.command.iter().cloned().collect(),
            }],
            _ => Vec::new(),
        }
    }
}

impl OpenCodeShell {
    pub(crate) fn is_terminal(&self) -> bool {
        matches!(
            self.status,
            OpenCodeShellStatus::Exited
                | OpenCodeShellStatus::Timeout
                | OpenCodeShellStatus::Killed
        )
    }
}

fn assistant_tools(
    content: Option<&[OpenCodeAssistantContent]>,
) -> impl Iterator<Item = &OpenCodeAssistantTool> {
    content
        .unwrap_or_default()
        .iter()
        .filter_map(|entry| match entry {
            OpenCodeAssistantContent::Tool(tool) => Some(tool),
            _ => None,
        })
}

pub(super) fn extract_session_messages(
    conn: &Connection,
    options: OpenCodeSqliteReadOptions,
    admission: &mut SqliteAdmission,
) -> Result<OpenCodeSessionMessageExtraction, SourceReadError> {
    if let Some(high_water) = options.message_resume_high_water {
        // Same snapshot, before selection. Like the part probe, newest rowids are
        // scanned first and non-integer coordinates never count.
        let reaches_high_water = conn
            .query_row(
                "select 1 from session_message where typeof(time_updated) = 'integer' and time_updated >= ?1 order by rowid desc limit 1",
                [high_water],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if !reaches_high_water {
            return Err(SourceReadError::ResumeRegressed);
        }
    }
    let limit = options.message_limit.max(1);
    let (records, truncated, next_time_updated) = match options.message_min_time_updated {
        Some(min_time_updated) => extract_incremental_messages(
            conn,
            min_time_updated,
            limit,
            crate::acquisition::SQLITE_PART_LIMIT,
            admission,
        )?,
        None => extract_bootstrap_messages(conn, limit, admission)?,
    };
    Ok(OpenCodeSessionMessageExtraction {
        records,
        truncated,
        next_time_updated,
    })
}

/// Selected rows in update order, whether the row limit cut the selection,
/// and then the first unselected row's `time_updated`.
type Selected = (Vec<OpenCodeSessionMessageRecord>, bool, Option<i64>);

fn extract_bootstrap_messages(
    conn: &Connection,
    limit: i64,
    admission: &mut SqliteAdmission,
) -> Result<Selected, SourceReadError> {
    let query = format!(
        "select * from ({SELECT} order by m.time_updated desc, m.rowid desc limit ?1) \
         order by time_updated, __telltale_rowid"
    );
    let mut stmt = conn.prepare(&query)?;
    let mut records = Vec::new();
    stream_sqlite_rows(&mut stmt, [limit], admission, None, |value| {
        records.push(decode_row(value)?);
        Ok(())
    })?;
    // Bootstrap samples the newest rows by design; it is not a cut backlog.
    Ok((records, false, None))
}

pub(super) fn extract_incremental_messages(
    conn: &Connection,
    min_time_updated: i64,
    limit: i64,
    page_size: i64,
    admission: &mut SqliteAdmission,
) -> Result<Selected, SourceReadError> {
    limit
        .checked_add(1)
        .ok_or_else(|| part_read_error("message limit overflow"))?;
    let query = format!(
        "{SELECT} where m.time_updated >= ?1 \
           and (?2 is null or (m.time_updated, m.rowid) > (?2, ?3)) \
         order by m.time_updated, m.rowid limit ?4"
    );
    let mut stmt = conn.prepare(&query)?;
    let mut records = Vec::new();
    let mut remaining = limit;
    let mut after: Option<(i64, i64)> = None;
    loop {
        let query_limit = page_size.min(remaining + 1);
        let delivered = stream_sqlite_rows(
            &mut stmt,
            rusqlite::params![
                min_time_updated,
                after.map(|key| key.0),
                after.map(|key| key.1),
                query_limit,
            ],
            admission,
            Some(remaining),
            |value| {
                let key = continuation_key(&value)?;
                if key.0 < min_time_updated || after.is_some_and(|previous| key <= previous) {
                    return Err(part_read_error("invalid message continuation order"));
                }
                records.push(decode_row(value)?);
                remaining -= 1;
                after = Some(key);
                Ok(())
            },
        );
        let delivered = match delivered {
            // The row cap fires before a lookahead row is admitted: more rows
            // exist, and the caller rolls to the next window.
            Err(SourceReadError::Bounded(crate::source_read::BoundedReadError::LimitExceeded))
                if remaining == 0 =>
            {
                // Only the next coordinate, never its payload: it tells the
                // caller whether the cut splits a `time_updated` group.
                let (time, rowid) = after.expect("a full selection has a last row");
                let next = conn.query_row(
                    "select time_updated from session_message \
                     where (time_updated, rowid) > (?1, ?2) \
                     order by time_updated, rowid limit 1",
                    [time, rowid],
                    |row| row.get::<_, i64>(0),
                )?;
                return Ok((records, true, Some(next)));
            }
            other => other?,
        };
        let exhausted = delivered
            < usize::try_from(query_limit)
                .map_err(|_| part_read_error("message page limit overflow"))?;
        if exhausted {
            return Ok((records, false, None));
        }
        #[cfg(test)]
        super::native::run_incremental_page_callback();
    }
}

/// Integer `(time_updated, rowid)`; anything else rejects the whole source.
fn continuation_key(value: &Value) -> Result<(i64, i64), SourceReadError> {
    Ok((
        value
            .get("time_updated")
            .and_then(Value::as_i64)
            .ok_or_else(|| part_read_error("invalid message continuation time"))?,
        value
            .get("__telltale_rowid")
            .and_then(Value::as_i64)
            .ok_or_else(|| part_read_error("invalid message continuation rowid"))?,
    ))
}

fn decode_row(row: Value) -> Result<OpenCodeSessionMessageRecord, SourceReadError> {
    let Value::Object(mut row) = row else {
        return Err(invalid_message());
    };
    let kind = match row.remove("type") {
        Some(Value::String(kind)) => kind,
        _ => return Err(invalid_message()),
    };
    let time_updated = row
        .get("time_updated")
        .and_then(Value::as_i64)
        .ok_or_else(|| part_read_error("invalid message continuation time"))?;
    let seq = row
        .get("seq")
        .and_then(Value::as_i64)
        .and_then(|seq| u64::try_from(seq).ok())
        .ok_or_else(|| part_read_error("invalid session message sequence"))?;
    let data = match row.remove("data") {
        Some(Value::String(data)) => match serde_json::from_str::<Value>(&data) {
            Ok(Value::Object(data)) => data,
            _ => return Err(invalid_message()),
        },
        _ => return Err(invalid_message()),
    };
    // OpenCode strips `id` and `type` before storing `data`; a copy there would
    // make the required identity or variant ambiguous.
    if data.contains_key("id") || data.contains_key("type") {
        return Err(part_read_error("ambiguous session message identity"));
    }
    let source_id = non_empty_string(row.get("id"));
    let session_id = non_empty_string(row.get("session_id"));
    let attestation = attestation(&row, &data);
    let occurrence_time = data
        .get("time")
        .and_then(|time| source_time_field(time.get("created"), "created"));
    let body = match kind.as_str() {
        "user" => OpenCodeSessionMessageBody::User {
            text: data
                .get("text")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
        },
        "assistant" => OpenCodeSessionMessageBody::Assistant {
            content: data
                .get("content")
                .and_then(Value::as_array)
                .map(|content| content.iter().map(decode_content).collect()),
        },
        "shell" => OpenCodeSessionMessageBody::Shell(decode_shell(&data)),
        "agent-switched" | "model-switched" | "location-switched" => {
            OpenCodeSessionMessageBody::Auxiliary(RecordKind::SessionMeta)
        }
        "synthetic" | "system" | "skill" | "compaction" | "idle" => {
            OpenCodeSessionMessageBody::Auxiliary(RecordKind::Other)
        }
        _ => OpenCodeSessionMessageBody::Unsupported,
    };
    Ok(OpenCodeSessionMessageRecord {
        source_id,
        session_id,
        seq,
        time_updated,
        attestation,
        occurrence_time,
        body,
    })
}

fn invalid_message() -> SourceReadError {
    part_read_error("invalid session message data")
}

fn non_empty_string(value: Option<&Value>) -> Option<String> {
    value
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

/// Session ownership comes only from the `session_id` column. Agent, model and
/// provider come from the message and the joined session row; contradictions
/// stay ambiguous instead of being resolved by precedence.
fn attestation(
    row: &Map<String, Value>,
    data: &Map<String, Value>,
) -> Result<SessionMetadata, AcquisitionError> {
    session_identity(row.get("session_id"))?;
    let mut metadata = SessionMetadata::default();
    let agent = serde_json::json!({ "agent": data.get("agent") });
    metadata.merge(&agent_model_metadata(&agent, data.get("model"))?);
    let session_model = match row.get("__telltale_session_model") {
        Some(Value::String(model)) => Some(
            serde_json::from_str::<Value>(model)
                .map_err(|_| AcquisitionError::InvalidAttestation)?,
        ),
        None | Some(Value::Null) => None,
        Some(_) => return Err(AcquisitionError::InvalidAttestation),
    };
    let session = serde_json::json!({ "agent": row.get("__telltale_session_agent") });
    metadata.merge(&agent_model_metadata(&session, session_model.as_ref())?);
    Ok(metadata)
}

fn agent_model_metadata(
    agent: &Value,
    model: Option<&Value>,
) -> Result<SessionMetadata, AcquisitionError> {
    let mut metadata = SessionMetadata::from_fields(agent, &["agent"], &[], &[])?;
    match model {
        None | Some(Value::Null) => {}
        Some(model @ Value::Object(_)) => {
            metadata.merge(&SessionMetadata::from_fields(
                model,
                &[],
                &["id"],
                &["providerID"],
            )?);
        }
        Some(_) => return Err(AcquisitionError::InvalidAttestation),
    }
    Ok(metadata)
}

fn decode_content(entry: &Value) -> OpenCodeAssistantContent {
    match entry.get("type").and_then(Value::as_str) {
        Some("text") => OpenCodeAssistantContent::Text(
            entry
                .get("text")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
        ),
        Some("reasoning") => OpenCodeAssistantContent::Reasoning,
        Some("tool") => OpenCodeAssistantContent::Tool(decode_tool(entry)),
        _ => OpenCodeAssistantContent::Unsupported,
    }
}

fn decode_tool(entry: &Value) -> OpenCodeAssistantTool {
    let mut malformed = false;
    let executed = match entry.get("executed") {
        None => None,
        Some(Value::Bool(executed)) => Some(*executed),
        Some(_) => {
            malformed = true;
            None
        }
    };
    let state = entry.get("state").and_then(Value::as_object);
    malformed |= state.is_none();
    let status = match state.and_then(|state| state.get("status")) {
        Some(Value::String(status)) => match status.as_str() {
            "streaming" => OpenCodeToolStatus::Streaming,
            "running" => OpenCodeToolStatus::Running,
            "completed" => OpenCodeToolStatus::Completed,
            "error" => OpenCodeToolStatus::Error,
            _ => OpenCodeToolStatus::Unsupported,
        },
        _ => {
            malformed = true;
            OpenCodeToolStatus::Unsupported
        }
    };
    let input = state.and_then(|state| state.get("input")).cloned();
    // Streaming input is the raw string; called states carry the input object.
    malformed |= !matches!(
        (status, &input),
        (OpenCodeToolStatus::Streaming, Some(Value::String(_)))
            | (
                OpenCodeToolStatus::Running
                    | OpenCodeToolStatus::Completed
                    | OpenCodeToolStatus::Error,
                Some(Value::Object(_)),
            )
            | (OpenCodeToolStatus::Unsupported, _)
    );
    let mut facts = OpenCodeToolResultFacts::default();
    let result = match status {
        OpenCodeToolStatus::Completed => match state.and_then(|state| state.get("content")) {
            Some(Value::Array(content)) if !content.is_empty() => {
                Some(completed_result(content, &mut facts))
            }
            _ => {
                malformed = true;
                None
            }
        },
        OpenCodeToolStatus::Error => match state.and_then(|state| state.get("error")) {
            Some(Value::Object(error)) => {
                facts.error_type = error
                    .get("type")
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned);
                Some(match error.get("message") {
                    Some(message @ Value::String(_)) => message.clone(),
                    _ => Value::Object(error.clone()),
                })
            }
            _ => {
                malformed = true;
                None
            }
        },
        _ => None,
    };
    let time = entry.get("time");
    malformed |= time.is_some_and(|time| !time.is_object());
    let time_field = |key: &str| time.and_then(|time| source_time_field(time.get(key), key));
    let name = non_empty_string(entry.get("name"));
    let shell_settlement = match (status, name.as_deref()) {
        (OpenCodeToolStatus::Completed, Some(SHELL_TOOL_NAME)) => {
            state.and_then(|state| shell_settlement(state.get("metadata")?))
        }
        _ => None,
    };
    OpenCodeAssistantTool {
        id: non_empty_string(entry.get("id")),
        name,
        executed,
        status,
        input,
        result,
        result_facts: (facts != OpenCodeToolResultFacts::default()).then(|| Box::new(facts)),
        created: time_field("created"),
        ran: time_field("ran"),
        completed: time_field("completed"),
        shell_settlement,
        malformed,
    }
}

fn completed_result(content: &[Value], facts: &mut OpenCodeToolResultFacts) -> Value {
    let texts = content
        .iter()
        .map(
            |part| match (part.get("type").and_then(Value::as_str), part.get("text")) {
                (Some("text"), Some(Value::String(text))) => Some(text.as_str()),
                _ => None,
            },
        )
        .collect::<Option<Vec<_>>>();
    if let Some(texts) = texts {
        return Value::String(texts.join("\n\n"));
    }
    Value::Array(
        content
            .iter()
            .map(|part| {
                let mut part = part.clone();
                if part.get("type").and_then(Value::as_str) == Some("file")
                    && let Some(Value::String(uri)) = part.get_mut("uri")
                    && let Some(rest) = uri.strip_prefix("data:")
                {
                    let media = rest.split([';', ',']).next().unwrap_or_default();
                    let kept = format!("data:{media}");
                    let omitted = (uri.len() - kept.len()) as u64;
                    facts.omitted_bytes =
                        Some(facts.omitted_bytes.unwrap_or(0).saturating_add(omitted));
                    *uri = kept;
                }
                part
            })
            .collect(),
    )
}

/// Tool metadata is an open record, so a shape this adapter does not recognize
/// is not a settlement and not a malformed row: it only withholds the claim.
fn shell_settlement(metadata: &Value) -> Option<Box<OpenCodeShellSettlement>> {
    let metadata = metadata.as_object()?;
    if metadata.get("status").and_then(Value::as_str) != Some("completed") {
        return None;
    }
    let exit = match metadata.get("exit") {
        None => None,
        Some(exit) => Some(exit.as_i64()?),
    };
    let signal = match metadata.get("signal") {
        None => None,
        Some(signal) => Some(
            signal
                .as_str()
                .filter(|signal| !signal.is_empty())?
                .to_owned(),
        ),
    };
    let timeout = match metadata.get("timeout") {
        None => false,
        Some(timeout) => timeout.as_bool()?,
    };
    (exit.is_some() || signal.is_some() || timeout).then(|| {
        Box::new(OpenCodeShellSettlement {
            exit,
            signal,
            timeout,
        })
    })
}

fn decode_shell(data: &Map<String, Value>) -> OpenCodeShell {
    let mut malformed = false;
    let status = match data.get("status").and_then(Value::as_str) {
        Some("running") => OpenCodeShellStatus::Running,
        Some("exited") => OpenCodeShellStatus::Exited,
        Some("timeout") => OpenCodeShellStatus::Timeout,
        Some("killed") => OpenCodeShellStatus::Killed,
        Some(_) => OpenCodeShellStatus::Unsupported,
        None => {
            malformed = true;
            OpenCodeShellStatus::Unsupported
        }
    };
    let command = data
        .get("command")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    malformed |= command.is_none();
    let exit = match data.get("exit") {
        None => None,
        Some(exit) => {
            let code = exit.as_i64();
            malformed |= code.is_none();
            code
        }
    };
    let output = match data.get("output") {
        None => None,
        Some(output) => {
            let text = output
                .get("output")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned);
            malformed |= text.is_none();
            text
        }
    };
    let time = data.get("time");
    malformed |= time.is_some_and(|time| !time.is_object());
    let time_field = |key: &str| time.and_then(|time| source_time_field(time.get(key), key));
    OpenCodeShell {
        shell_id: non_empty_string(data.get("shellID")),
        command,
        status,
        exit,
        output,
        created: time_field("created"),
        completed: time_field("completed"),
        malformed,
    }
}
