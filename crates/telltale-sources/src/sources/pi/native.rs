//! Crate-private Pi JSONL entry structures and their extraction. A known
//! schema failure is terminal; there is no fallback parser.
//!
//! A Pi session file names its session once, in the `session` header; no other
//! entry carries a session ID. Every entry of the file therefore belongs to
//! the header's session, and two headers naming different sessions are a
//! conflicting ownership claim.

use serde_json::Value;

use crate::acquisition::{AcquisitionError, SessionMetadata, session_identity};
use crate::source_read::{SourceReadError, collect_string_values};
use telltale_schema::record::RecordKind;
use telltale_schema::source::Source;

/// Entry types that carry session state, not conversation turns: they are
/// counted and never projected as activity. `custom_message` (extension
/// context) and `context_edit` (a later rewrite of an earlier entry's model
/// context) are kept out as well: the append-only record of what was
/// requested and returned is the evidence, not a later view of it.
pub(crate) const METADATA_ENTRY_TYPES: &[&str] = &[
    "session",
    "thinking_level_change",
    "model_change",
    "usage",
    "compaction",
    "branch_summary",
    "custom",
    "custom_message",
    "context_edit",
    "label",
    "session_info",
];

/// Message roles that are injected context rather than a turn: the system
/// prompt, extension messages and branch and compaction summaries.
pub(crate) const METADATA_MESSAGE_ROLES: &[&str] =
    &["system", "custom", "branchSummary", "compactionSummary"];

#[derive(Debug, Clone)]
pub(crate) enum PiContentBlock {
    Text {
        text: Option<String>,
    },
    ToolCall {
        id: Option<String>,
        name: Option<String>,
        arguments: Option<Value>,
        /// Set for a call to a dynamically loaded or namespaced tool.
        namespace: Option<String>,
    },
    /// Reasoning and image blocks carry no text or tool facts; projection
    /// drops them from the message instead of rejecting the entry.
    Ignored,
    Unknown,
}

/// A `toolResult` message.
#[derive(Debug, Clone)]
pub(crate) struct PiToolResult {
    pub(crate) call_id: Option<String>,
    pub(crate) name: Option<String>,
    pub(crate) content: Option<Value>,
    pub(crate) is_error: Option<bool>,
    pub(crate) is_error_present: bool,
}

/// A `bashExecution` message: a command the user ran with `!` in the session.
#[derive(Debug, Clone)]
pub(crate) struct PiBashExecution {
    pub(crate) command: Option<String>,
    pub(crate) output: Option<Value>,
    pub(crate) exit_code: Option<i64>,
    pub(crate) exit_code_present: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct PiNativeRecord {
    pub(crate) attestation: Result<SessionMetadata, AcquisitionError>,
    pub(crate) source_sequence: u64,
    /// The entry's own `id`; the header's is the session ID.
    pub(crate) native_id: Option<String>,
    pub(crate) session_id: Option<String>,
    pub(crate) timestamp: Option<String>,
    /// The entry `type`.
    pub(crate) discriminator: Option<String>,
    /// `message.role` of a `message` entry.
    pub(crate) role: Option<String>,
    /// String `message.content`.
    pub(crate) message_content: Option<Value>,
    /// Array `message.content`.
    pub(crate) blocks: Option<Vec<PiContentBlock>>,
    pub(crate) tool_result: Option<PiToolResult>,
    pub(crate) bash: Option<PiBashExecution>,
    /// Source strings scanned for tool-call activity contributions. Empty unless
    /// this unit is an accounting tool call.
    pub(crate) contribution_strings: Vec<String>,
}

pub(crate) fn extract_pi_native_records_with_limits(
    source: &Source,
    access: crate::acquisition::SourceAccess<'_>,
) -> Result<(Vec<PiNativeRecord>, usize), SourceReadError> {
    let (values, bytes) = crate::source_read::read_jsonl_values_with_limits(source, access)?;
    if values.iter().any(|value| !value.is_object()) {
        return Err(SourceReadError::SchemaDrift {
            client: source.client,
            source_id: source.source_id.clone(),
            detail: "JSONL record envelope must be an object",
        });
    }

    let ownership = session_identity(
        values
            .iter()
            .filter(|value| value.get("type").and_then(Value::as_str) == Some("session"))
            .filter_map(|header| header.get("id")),
    );
    let session_id = ownership.as_ref().ok().cloned().flatten();

    let mut records = Vec::with_capacity(values.len());
    for (source_sequence, value) in values.into_iter().enumerate() {
        let discriminator = value.get("type").and_then(Value::as_str);
        let message = (discriminator == Some("message"))
            .then(|| value.get("message"))
            .flatten()
            .filter(|message| message.is_object());
        let role = message
            .and_then(|message| message.get("role"))
            .and_then(Value::as_str);
        let conversational = matches!(role, Some("user" | "assistant"));
        let source_blocks = conversational
            .then(|| message.and_then(|message| message.get("content")))
            .flatten()
            .and_then(Value::as_array);
        // Only mapped messages interpret this array as content blocks.
        // Metadata entries and injected-context roles remain opaque.
        if source_blocks.is_some_and(|blocks| {
            blocks
                .iter()
                .any(|block| block.get("type").and_then(Value::as_str).is_none())
        }) {
            return Err(SourceReadError::SchemaDrift {
                client: source.client,
                source_id: source.source_id.clone(),
                detail: "Pi content block must be an object with a string type",
            });
        }
        let blocks =
            source_blocks.map(|blocks| blocks.iter().map(content_block).collect::<Vec<_>>());
        let message_content = conversational
            .then(|| message.and_then(|message| message.get("content")))
            .flatten()
            .filter(|content| content.is_string())
            .cloned();
        let tool_result = message
            .filter(|_| role == Some("toolResult"))
            .map(tool_result);
        let bash = message
            .filter(|_| role == Some("bashExecution"))
            .map(bash_execution);

        let mut contribution_strings = Vec::new();
        for block in blocks.iter().flatten() {
            if let PiContentBlock::ToolCall {
                name, arguments, ..
            } = block
            {
                contribution_strings.extend(name.iter().cloned());
                contribution_strings.extend(arguments.iter().flat_map(collect_string_values));
            }
        }
        if let Some(command) = bash.as_ref().and_then(|bash| bash.command.as_ref()) {
            contribution_strings.push(command.clone());
        }

        let native = PiNativeRecord {
            attestation: ownership
                .clone()
                .and_then(|_| attestation(discriminator, &value, message)),
            source_sequence: source_sequence as u64,
            native_id: value
                .get("id")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
            session_id: session_id.clone(),
            timestamp: value
                .get("timestamp")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
            discriminator: discriminator.map(ToOwned::to_owned),
            role: role.map(ToOwned::to_owned),
            message_content,
            blocks,
            tool_result,
            bash,
            contribution_strings,
        };
        records.push(native);
    }

    Ok((records, bytes))
}

impl PiNativeRecord {
    pub(crate) fn accounting_kind(&self) -> RecordKind {
        match (self.discriminator.as_deref(), self.role.as_deref()) {
            (Some("session"), _) => RecordKind::SessionMeta,
            (Some("message"), Some("user")) => RecordKind::UserMessage,
            (Some("message"), Some("assistant")) if self.has_tool_call() => RecordKind::ToolCall,
            (Some("message"), Some("assistant")) => RecordKind::AssistantMessage,
            (Some("message"), Some("toolResult")) => RecordKind::ToolResult,
            (Some("message"), Some("bashExecution")) => RecordKind::ToolCall,
            _ => RecordKind::Other,
        }
    }

    pub(crate) fn accounting_tool_name(&self) -> Option<&str> {
        if self.bash.is_some() {
            return Some("bashExecution");
        }
        self.tool_call_name()
    }

    pub(crate) fn contribution_strings(&self) -> &[String] {
        &self.contribution_strings
    }

    fn tool_call_name(&self) -> Option<&str> {
        self.blocks.as_ref()?.iter().find_map(|block| match block {
            PiContentBlock::ToolCall { name, .. } => name.as_deref(),
            _ => None,
        })
    }

    fn has_tool_call(&self) -> bool {
        self.blocks.as_ref().is_some_and(|blocks| {
            blocks
                .iter()
                .any(|block| matches!(block, PiContentBlock::ToolCall { .. }))
        })
    }
}

/// Model and provider: an assistant message names the ones that answered it,
/// and a `model_change` entry the ones selected.
fn attestation(
    discriminator: Option<&str>,
    value: &Value,
    message: Option<&Value>,
) -> Result<SessionMetadata, AcquisitionError> {
    match discriminator {
        Some("model_change") => {
            SessionMetadata::from_fields(value, &[], &["modelId"], &["provider"])
        }
        Some("message") => match message {
            Some(message) if message.get("role").and_then(Value::as_str) == Some("assistant") => {
                SessionMetadata::from_fields(message, &[], &["model"], &["provider"])
            }
            _ => Ok(SessionMetadata::default()),
        },
        _ => Ok(SessionMetadata::default()),
    }
}

fn content_block(value: &Value) -> PiContentBlock {
    let Some(object) = value.as_object() else {
        return PiContentBlock::Unknown;
    };
    let string = |key: &str| {
        object
            .get(key)
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
    };
    match object.get("type").and_then(Value::as_str) {
        Some("text") => PiContentBlock::Text {
            text: string("text"),
        },
        Some("toolCall") => PiContentBlock::ToolCall {
            id: string("id"),
            name: string("name"),
            arguments: object.get("arguments").cloned(),
            namespace: string("namespace"),
        },
        Some("thinking" | "image") => PiContentBlock::Ignored,
        _ => PiContentBlock::Unknown,
    }
}

fn tool_result(message: &Value) -> PiToolResult {
    let is_error = message.get("isError");
    PiToolResult {
        call_id: message
            .get("toolCallId")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        name: message
            .get("toolName")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        content: message.get("content").cloned(),
        is_error: is_error.and_then(Value::as_bool),
        is_error_present: is_error.is_some(),
    }
}

fn bash_execution(message: &Value) -> PiBashExecution {
    // `exitCode` is absent or null when the command was cancelled or killed.
    let exit_code = message.get("exitCode").filter(|value| !value.is_null());
    PiBashExecution {
        command: message
            .get("command")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        output: message.get("output").cloned(),
        exit_code: exit_code.and_then(Value::as_i64),
        exit_code_present: exit_code.is_some(),
    }
}
