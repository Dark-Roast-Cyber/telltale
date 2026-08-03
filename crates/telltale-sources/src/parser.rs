use serde_json::Value;
use std::fmt;
use std::fs;

use telltale_schema::clients::{ClientId, SourceKind};
use telltale_schema::record::{NormalizedRecord, RecordKind};
use telltale_schema::source::Source;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct ParseOptions {
    pub sqlite_part_min_time_updated: Option<i64>,
    pub sqlite_part_limit: i64,
}

impl Default for ParseOptions {
    fn default() -> Self {
        Self {
            sqlite_part_min_time_updated: None,
            sqlite_part_limit: crate::sources::opencode::parser::SQLITE_PART_LIMIT,
        }
    }
}

#[derive(Debug)]
#[allow(dead_code)]
#[non_exhaustive]
pub enum ParseError {
    Io(std::io::Error),
    Json(serde_json::Error),
    Sqlite(rusqlite::Error),
    Empty,
    Locked(String),
    UnsupportedSourceKind(SourceKind),
    UnsupportedSourceIdentity {
        client: ClientId,
        source_id: String,
    },
    SourceKindMismatch {
        client: ClientId,
        source_id: String,
        expected: SourceKind,
        actual: SourceKind,
    },
    SchemaDrift {
        client: ClientId,
        source_id: String,
        detail: &'static str,
    },
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::Io(e) => write!(f, "io error: {e}"),
            ParseError::Json(e) => write!(f, "json parse error: {e}"),
            ParseError::Sqlite(e) => write!(f, "sqlite error: {e}"),
            ParseError::Empty => write!(f, "empty source"),
            ParseError::Locked(msg) => write!(f, "locked: {msg}"),
            ParseError::UnsupportedSourceKind(kind) => {
                write!(f, "unsupported source kind: {}", kind.as_str())
            }
            ParseError::UnsupportedSourceIdentity { client, .. } => {
                write!(
                    f,
                    "unsupported source identity for client: {}",
                    client.as_str()
                )
            }
            ParseError::SourceKindMismatch {
                client,
                source_id,
                expected,
                actual,
            } => write!(
                f,
                "source kind mismatch for ({}, {source_id}): expected {}, got {}",
                client.as_str(),
                expected.as_str(),
                actual.as_str()
            ),
            ParseError::SchemaDrift {
                client,
                source_id,
                detail,
            } => write!(
                f,
                "schema drift for ({}, {source_id}): {detail}",
                client.as_str()
            ),
        }
    }
}

impl From<std::io::Error> for ParseError {
    fn from(e: std::io::Error) -> Self {
        ParseError::Io(e)
    }
}

impl From<serde_json::Error> for ParseError {
    fn from(e: serde_json::Error) -> Self {
        ParseError::Json(e)
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ParsedRecord {
    pub(crate) session_id: String,
    pub(crate) agent: Option<String>,
    pub(crate) model: Option<String>,
    pub(crate) provider: Option<String>,
    pub(crate) timestamp: Option<String>,
    pub(crate) kind: RecordKind,
    pub(crate) tool_name: Option<String>,
    pub(crate) arguments: Option<String>,
    pub(crate) content: String,
}

#[derive(Debug, Clone)]
pub struct ParsedSourceRecords {
    pub records: Vec<NormalizedRecord>,
    pub sqlite_part_max_time_updated: Option<i64>,
}

pub fn parse_source_records(source: &Source) -> Result<Vec<NormalizedRecord>, ParseError> {
    Ok(parse_source_records_with_options(source, ParseOptions::default())?.records)
}

pub fn parse_source_records_with_options(
    source: &Source,
    options: ParseOptions,
) -> Result<ParsedSourceRecords, ParseError> {
    let extracted = extract_source_records(source, options)?;
    Ok(ParsedSourceRecords {
        records: normalize_source_records(source, extracted.records),
        sqlite_part_max_time_updated: extracted.sqlite_part_max_time_updated,
    })
}

#[derive(Debug, Clone)]
pub(crate) struct ExtractedSourceRecords {
    pub(crate) records: Vec<ParsedRecord>,
    pub(crate) sqlite_part_max_time_updated: Option<i64>,
}

impl ExtractedSourceRecords {
    pub(crate) fn records(records: Vec<ParsedRecord>) -> Self {
        Self {
            records,
            sqlite_part_max_time_updated: None,
        }
    }
}

fn extract_source_records(
    source: &Source,
    options: ParseOptions,
) -> Result<ExtractedSourceRecords, ParseError> {
    let registration = parser_registration(source)?;
    if source.kind != registration.expected_kind {
        return Err(ParseError::SourceKindMismatch {
            client: source.client,
            source_id: source.source_id.clone(),
            expected: registration.expected_kind,
            actual: source.kind,
        });
    }
    (registration.implementation.parser())(source, options)
}

type SourceParser = fn(&Source, ParseOptions) -> Result<ExtractedSourceRecords, ParseError>;

#[cfg(test)]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum ParserImplementationKind {
    Modeled,
    GenericJsonDocument,
}

#[derive(Clone, Copy)]
enum GenericParser {
    JsonDocument(SourceParser),
}

#[derive(Clone, Copy)]
enum ParserImplementation {
    Modeled(SourceParser),
    GenericFallback(GenericParser),
}

impl GenericParser {
    fn parser(self) -> SourceParser {
        match self {
            Self::JsonDocument(parser) => parser,
        }
    }

    #[cfg(test)]
    fn kind(self) -> ParserImplementationKind {
        match self {
            Self::JsonDocument(_) => ParserImplementationKind::GenericJsonDocument,
        }
    }
}

impl ParserImplementation {
    fn parser(self) -> SourceParser {
        match self {
            Self::Modeled(parser) => parser,
            Self::GenericFallback(parser) => parser.parser(),
        }
    }

    #[cfg(test)]
    fn kind(self) -> ParserImplementationKind {
        match self {
            Self::Modeled(_) => ParserImplementationKind::Modeled,
            Self::GenericFallback(parser) => parser.kind(),
        }
    }
}

#[derive(Clone, Copy)]
struct ParserRegistration {
    client: ClientId,
    source_id: &'static str,
    expected_kind: SourceKind,
    implementation: ParserImplementation,
}

const PARSER_REGISTRATIONS: &[ParserRegistration] = &[
    registration(
        ClientId::Codex,
        "codex.sessions",
        SourceKind::Jsonl,
        ParserImplementation::Modeled(crate::sources::codex::parser::extract_codex_jsonl_source),
    ),
    registration(
        ClientId::Codex,
        "codex.archived_sessions",
        SourceKind::ArchivedJsonl,
        ParserImplementation::Modeled(crate::sources::codex::parser::extract_codex_jsonl_source),
    ),
    registration(
        ClientId::Codex,
        "codex.headless_sessions",
        SourceKind::HeadlessJsonl,
        ParserImplementation::Modeled(crate::sources::codex::parser::extract_codex_jsonl_source),
    ),
    registration(
        ClientId::Codex,
        "codex.project_sessions",
        SourceKind::Jsonl,
        ParserImplementation::Modeled(crate::sources::codex::parser::extract_codex_jsonl_source),
    ),
    registration(
        ClientId::Claude,
        "claude.projects",
        SourceKind::Jsonl,
        ParserImplementation::Modeled(crate::sources::claude::parser::extract_claude_jsonl_source),
    ),
    registration(
        ClientId::Gemini,
        "gemini.tmp",
        SourceKind::Json,
        ParserImplementation::Modeled(crate::sources::gemini::parser::extract_gemini_json_source),
    ),
    registration(
        ClientId::OpenClaw,
        "openclaw.agents",
        SourceKind::Jsonl,
        ParserImplementation::Modeled(
            crate::sources::openclaw::parser::extract_openclaw_jsonl_source,
        ),
    ),
    registration(
        ClientId::Qwen,
        "qwen.projects",
        SourceKind::Jsonl,
        ParserImplementation::Modeled(crate::sources::qwen::parser::extract_qwen_jsonl_source),
    ),
    registration(
        ClientId::RooCode,
        "roocode.tasks",
        SourceKind::UiMessagesJson,
        ParserImplementation::GenericFallback(GenericParser::JsonDocument(
            extract_json_document_registered,
        )),
    ),
    registration(
        ClientId::KiloCode,
        "kilocode.tasks",
        SourceKind::UiMessagesJson,
        ParserImplementation::GenericFallback(GenericParser::JsonDocument(
            extract_json_document_registered,
        )),
    ),
    registration(
        ClientId::OpenCode,
        "opencode.sqlite",
        SourceKind::Sqlite,
        ParserImplementation::Modeled(crate::sources::opencode::parser::extract_sqlite_source),
    ),
    registration(
        ClientId::OpenCode,
        "opencode.legacy_json",
        SourceKind::LegacyJson,
        ParserImplementation::Modeled(
            crate::sources::opencode::parser::extract_opencode_json_source,
        ),
    ),
    registration(
        ClientId::OpenCode,
        "opencode.project_json",
        SourceKind::LegacyJson,
        ParserImplementation::Modeled(
            crate::sources::opencode::parser::extract_opencode_json_source,
        ),
    ),
    registration(
        ClientId::Copilot,
        "copilot.process_log",
        SourceKind::CopilotProcessLog,
        ParserImplementation::Modeled(crate::sources::copilot::parser::extract_copilot_process_log),
    ),
];

const fn registration(
    client: ClientId,
    source_id: &'static str,
    expected_kind: SourceKind,
    implementation: ParserImplementation,
) -> ParserRegistration {
    ParserRegistration {
        client,
        source_id,
        expected_kind,
        implementation,
    }
}

fn parser_registration(source: &Source) -> Result<&'static ParserRegistration, ParseError> {
    PARSER_REGISTRATIONS
        .iter()
        .find(|registration| {
            registration.client == source.client && registration.source_id == source.source_id
        })
        .ok_or_else(|| ParseError::UnsupportedSourceIdentity {
            client: source.client,
            source_id: source.source_id.clone(),
        })
}

fn extract_json_document_registered(
    source: &Source,
    _options: ParseOptions,
) -> Result<ExtractedSourceRecords, ParseError> {
    Ok(ExtractedSourceRecords::records(extract_json_source(
        source,
    )?))
}

fn normalize_source_records(source: &Source, records: Vec<ParsedRecord>) -> Vec<NormalizedRecord> {
    records
        .into_iter()
        .map(|record| normalize_source_record(source, record))
        .collect()
}

fn normalize_source_record(source: &Source, record: ParsedRecord) -> NormalizedRecord {
    NormalizedRecord {
        session_id: record.session_id,
        client: source.client.as_str().to_string(),
        agent: record.agent,
        model: record.model,
        provider: record.provider,
        timestamp: record.timestamp,
        kind: record.kind,
        tool_name: record.tool_name,
        arguments: record.arguments,
        content: record.content,
    }
}

pub(crate) fn read_jsonl_values(source: &Source) -> Result<Vec<Value>, ParseError> {
    let raw = fs::read_to_string(&source.path)?;
    raw.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str::<Value>(line).map_err(ParseError::from))
        .collect()
}

pub(crate) fn read_json_document(source: &Source) -> Result<Value, ParseError> {
    let raw = fs::read_to_string(&source.path)?;
    Ok(serde_json::from_str::<Value>(&raw)?)
}

pub(crate) fn extract_json_source(source: &Source) -> Result<Vec<ParsedRecord>, ParseError> {
    let value = read_json_document(source)?;
    let default_session_id = default_source_parent_name(source);

    match value {
        Value::Array(items) => Ok(items
            .iter()
            .filter(|item| item.is_object())
            .map(|item| json_record(item, &default_session_id))
            .collect()),
        item => Ok(vec![json_record(&item, &default_session_id)]),
    }
}

fn json_record(value: &Value, default_session_id: &str) -> ParsedRecord {
    ParsedRecord {
        session_id: session_id_with_fallback(value, default_session_id),
        agent: string_field(value, "agent"),
        model: model_field(value),
        provider: provider_field(value),
        timestamp: string_field(value, "timestamp").or_else(|| string_field(value, "time")),
        kind: record_kind(value),
        tool_name: tool_name(value),
        arguments: arguments_field(value),
        content: record_content(value),
    }
}

pub(crate) fn record_kind(value: &Value) -> RecordKind {
    let discriminator = record_discriminator(value);
    if discriminator.is_some_and(|kind| !is_known_record_discriminator(kind)) {
        return RecordKind::Other;
    }

    if has_content_block_type(value, "tool_use") {
        return RecordKind::ToolCall;
    }
    if has_content_block_type(value, "tool_result") {
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
        Some("tool") if crate::sources::opencode::parser::opencode_tool_part_is_result(value) => {
            RecordKind::ToolResult
        }
        Some("tool") => RecordKind::ToolCall,
        Some("session_meta") => RecordKind::SessionMeta,
        _ if value.get("session_meta").is_some() => RecordKind::SessionMeta,
        _ => RecordKind::Other,
    }
}

fn record_discriminator(value: &Value) -> Option<&str> {
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

fn is_known_record_discriminator(kind: &str) -> bool {
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

pub(crate) fn record_content(value: &Value) -> String {
    let mut parts = Vec::new();
    collect_strings(value, &mut parts);
    parts.join("\n")
}

fn collect_strings(value: &Value, output: &mut Vec<String>) {
    match value {
        Value::String(item) => output.push(item.clone()),
        Value::Array(items) => {
            for item in items {
                collect_strings(item, output);
            }
        }
        Value::Object(items) => {
            for (key, item) in items {
                output.push(key.clone());
                collect_strings(item, output);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

pub(crate) fn default_source_file_stem(source: &Source) -> String {
    source
        .path
        .file_stem()
        .and_then(|name| name.to_str())
        .unwrap_or("unknown")
        .to_string()
}

pub(crate) fn default_source_parent_name(source: &Source) -> String {
    source
        .path
        .parent()
        .and_then(|path| path.file_name())
        .and_then(|name| name.to_str())
        .unwrap_or("unknown")
        .to_string()
}

fn session_id_field(value: &Value) -> Option<String> {
    string_field(value, "session_id")
        .or_else(|| string_field(value, "sessionID"))
        .or_else(|| string_field(value, "sessionId"))
}

pub(crate) fn session_id_with_fallback(value: &Value, fallback: &str) -> String {
    session_id_field(value).unwrap_or_else(|| fallback.to_string())
}

pub(crate) fn model_field(value: &Value) -> Option<String> {
    string_field(value, "modelID").or_else(|| string_field(value, "model"))
}

pub(crate) fn provider_field(value: &Value) -> Option<String> {
    string_field(value, "providerID").or_else(|| string_field(value, "provider"))
}

pub(crate) fn arguments_field(value: &Value) -> Option<String> {
    field_as_string(value, "arguments").or_else(|| field_as_string(value, "input"))
}

pub(crate) fn string_field(value: &Value, key: &str) -> Option<String> {
    field_value(value, key)
        .and_then(Value::as_str)
        .map(ToString::to_string)
}

fn field_as_string(value: &Value, key: &str) -> Option<String> {
    match field_value(value, key)? {
        Value::String(item) => Some(item.clone()),
        Value::Null => None,
        item => serde_json::to_string(item).ok(),
    }
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
        .or_else(|| {
            value
                .get("session_meta")
                .and_then(|session_meta| session_meta.get("payload"))
                .and_then(|payload| payload.get(key))
        })
}

pub(crate) fn tool_name(value: &Value) -> Option<String> {
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

fn has_content_block_type(value: &Value, block_type: &str) -> bool {
    content_blocks(value).is_some_and(|blocks| {
        blocks
            .iter()
            .any(|block| block.get("type").and_then(Value::as_str) == Some(block_type))
    })
}

fn content_blocks(value: &Value) -> Option<&Vec<Value>> {
    value
        .get("message")
        .and_then(|message| message.get("content"))
        .or_else(|| value.get("content"))
        .and_then(Value::as_array)
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::path::PathBuf;

    use crate::clients::supported_clients;
    use crate::discovery::discover_sources_best_effort;
    use telltale_schema::clients::{ClientId, SourceKind};
    use telltale_schema::source::Source;

    use super::{
        PARSER_REGISTRATIONS, ParsedRecord, ParserImplementationKind, RecordKind,
        normalize_source_record, parse_source_records, parser_registration,
    };

    #[test]
    fn normalizes_parsed_records_with_source_client() {
        let source = Source {
            client: ClientId::Codex,
            kind: SourceKind::Jsonl,
            source_id: "codex.fixture".to_string(),
            path: PathBuf::from("session.jsonl"),
        };
        let parsed = ParsedRecord {
            session_id: "session-1".to_string(),
            agent: Some("fixture-agent".to_string()),
            model: Some("fixture-model".to_string()),
            provider: Some("fixture-provider".to_string()),
            timestamp: Some("2026-05-01T12:00:00Z".to_string()),
            kind: RecordKind::ToolCall,
            tool_name: Some("repo_status".to_string()),
            arguments: Some("{\"format\":\"json\"}".to_string()),
            content: "function_call: repo_status".to_string(),
        };

        let normalized = normalize_source_record(&source, parsed);

        assert_eq!(normalized.session_id, "session-1");
        assert_eq!(normalized.client, "codex");
        assert_eq!(normalized.agent.as_deref(), Some("fixture-agent"));
        assert_eq!(normalized.model.as_deref(), Some("fixture-model"));
        assert_eq!(normalized.provider.as_deref(), Some("fixture-provider"));
        assert_eq!(
            normalized.timestamp.as_deref(),
            Some("2026-05-01T12:00:00Z")
        );
        assert_eq!(normalized.kind, RecordKind::ToolCall);
        assert_eq!(normalized.tool_name.as_deref(), Some("repo_status"));
        assert_eq!(
            normalized.arguments.as_deref(),
            Some("{\"format\":\"json\"}")
        );
        assert_eq!(normalized.content, "function_call: repo_status");
    }

    #[test]
    fn parses_gemini_json_message_array_records() {
        let source = discover_sources_best_effort(&crate::test_fixture_path("session_stores"))
            .into_iter()
            .find(|source| {
                source.client == ClientId::Gemini
                    && source.kind == SourceKind::Json
                    && source.path.file_name().and_then(|name| name.to_str())
                        == Some("session-a.json")
            })
            .expect("fixture source");

        let records = parse_source_records(&source).expect("records");

        assert_eq!(records.len(), 2);
        assert!(records.iter().all(|record| {
            record.session_id == "gemini-session-a" && record.client == "gemini"
        }));
        assert_eq!(records[0].kind, RecordKind::UserMessage);
        assert_eq!(records[0].agent.as_deref(), Some("gemini"));
        assert_eq!(records[0].provider.as_deref(), Some("google"));
        assert_eq!(records[1].kind, RecordKind::AssistantMessage);
        assert_eq!(records[1].model.as_deref(), Some("gemini-fixture-model"));
        assert!(
            records[1]
                .content
                .contains("benign Gemini fixture response")
        );
    }

    #[test]
    fn parses_gemini_json_tool_call_and_result_records() {
        let source = discover_sources_best_effort(&crate::test_fixture_path("session_stores"))
            .into_iter()
            .find(|source| {
                source.client == ClientId::Gemini
                    && source.kind == SourceKind::Json
                    && source.path.file_name().and_then(|name| name.to_str())
                        == Some("uc001-gemini-tool-result.json")
            })
            .expect("fixture source");

        let records = parse_source_records(&source).expect("records");

        assert_eq!(records.len(), 3);
        assert!(records.iter().all(|record| {
            record.session_id == "gemini-uc001-tool-result" && record.client == "gemini"
        }));
        assert_eq!(records[0].kind, RecordKind::UserMessage);
        assert_eq!(records[1].kind, RecordKind::ToolCall);
        assert_eq!(records[1].tool_name.as_deref(), Some("repo_status"));
        assert_eq!(
            records[1].arguments.as_deref(),
            Some("{\"format\":\"json\"}")
        );
        assert_eq!(records[2].kind, RecordKind::ToolResult);
        assert_eq!(records[2].tool_name.as_deref(), Some("repo_status"));
        assert!(records[2].content.contains("darkroastcyber.io/mcp-lab"));
    }

    #[test]
    fn parse_source_records_returns_error_for_malformed_jsonl() {
        let source = Source {
            client: ClientId::Codex,
            kind: SourceKind::Jsonl,
            source_id: "codex.sessions".to_string(),
            path: crate::test_fixture_path("rule_samples/malformed-source.jsonl").to_path_buf(),
        };

        let result = parse_source_records(&source);
        assert!(result.is_err(), "expected parse error for malformed jsonl");
        let err = result.unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("json parse error"),
            "expected json parse error, got: {msg}"
        );
    }

    #[test]
    fn parse_source_records_returns_error_for_missing_file() {
        let temp = tempfile::tempdir().expect("tempdir");
        let source = Source {
            client: ClientId::Codex,
            kind: SourceKind::Jsonl,
            source_id: "codex.sessions".to_string(),
            path: temp.path().join("missing-session.jsonl"),
        };

        let result = parse_source_records(&source);
        assert!(result.is_err(), "expected io error for missing file");
        let err = result.unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("io error"), "expected io error, got: {msg}");
    }

    #[test]
    fn parser_registrations_match_source_definitions_bidirectionally() {
        let definitions = supported_clients()
            .iter()
            .flat_map(|client| {
                client
                    .sources
                    .iter()
                    .map(move |source| ((client.id, source.id), source.kind))
            })
            .collect::<Vec<_>>();
        let definition_keys = definitions
            .iter()
            .map(|(key, _)| *key)
            .collect::<BTreeSet<_>>();
        let registration_keys = PARSER_REGISTRATIONS
            .iter()
            .map(|registration| (registration.client, registration.source_id))
            .collect::<BTreeSet<_>>();

        assert_eq!(definitions.len(), 14);
        assert_eq!(definition_keys.len(), definitions.len());
        assert_eq!(registration_keys.len(), PARSER_REGISTRATIONS.len());
        assert_eq!(definition_keys, registration_keys);

        let expected_kinds = definitions.into_iter().collect::<BTreeMap<_, _>>();
        for registration in PARSER_REGISTRATIONS {
            assert_eq!(
                expected_kinds.get(&(registration.client, registration.source_id)),
                Some(&registration.expected_kind),
                "registration kind must match its source definition"
            );
        }
    }

    #[test]
    fn parser_registration_maturity_snapshot_has_twelve_modeled_and_two_fallbacks() {
        let modeled = PARSER_REGISTRATIONS
            .iter()
            .filter(|registration| {
                registration.implementation.kind() == ParserImplementationKind::Modeled
            })
            .map(|registration| registration.source_id)
            .collect::<BTreeSet<_>>();
        let json_documents = PARSER_REGISTRATIONS
            .iter()
            .filter(|registration| {
                registration.implementation.kind() == ParserImplementationKind::GenericJsonDocument
            })
            .map(|registration| registration.source_id)
            .collect::<BTreeSet<_>>();

        assert_eq!(
            modeled,
            BTreeSet::from_iter([
                "codex.sessions",
                "codex.archived_sessions",
                "codex.headless_sessions",
                "codex.project_sessions",
                "claude.projects",
                "gemini.tmp",
                "opencode.sqlite",
                "opencode.legacy_json",
                "opencode.project_json",
                "openclaw.agents",
                "qwen.projects",
                "copilot.process_log",
            ])
        );
        assert_eq!(PARSER_REGISTRATIONS.len(), 14);
        assert_eq!(modeled.len(), 12);
        assert_eq!(
            json_documents,
            BTreeSet::from_iter(["roocode.tasks", "kilocode.tasks"])
        );
        assert_eq!(json_documents.len(), 2);
    }

    #[test]
    fn parser_registration_requires_case_sensitive_exact_identity_and_kind() {
        let path = PathBuf::from("not-read.jsonl");
        let exact = Source {
            client: ClientId::Claude,
            kind: SourceKind::Jsonl,
            source_id: "claude.projects".to_string(),
            path: path.clone(),
        };
        assert!(parser_registration(&exact).is_ok());

        let wrong_case = Source {
            source_id: "Claude.projects".to_string(),
            ..exact.clone()
        };
        let error = parse_source_records(&wrong_case).expect_err("wrong case must fail");
        let message = error.to_string();
        assert!(matches!(
            error,
            super::ParseError::UnsupportedSourceIdentity { .. }
        ));
        assert!(message.contains("unsupported source identity"));
        assert!(!message.contains("not-read.jsonl"));

        let wrong_client = Source {
            client: ClientId::Codex,
            ..exact.clone()
        };
        assert!(matches!(
            parse_source_records(&wrong_client),
            Err(super::ParseError::UnsupportedSourceIdentity { .. })
        ));

        let wrong_kind = Source {
            kind: SourceKind::Json,
            ..exact
        };
        assert!(matches!(
            parse_source_records(&wrong_kind),
            Err(super::ParseError::SourceKindMismatch { .. })
        ));
    }

    #[test]
    fn registered_fallback_parses_but_unknown_identity_does_not() {
        let path = crate::test_fixture_path(
            "parser_maturity/non_discovered/explicit-generic-fallback.json",
        );
        let registered = Source {
            client: ClientId::OpenCode,
            kind: SourceKind::LegacyJson,
            source_id: "opencode.legacy_json".to_string(),
            path: path.clone(),
        };
        let records = parse_source_records(&registered).expect("registered fallback records");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].kind, RecordKind::AssistantMessage);

        let unknown = Source {
            source_id: "opencode.invented".to_string(),
            path,
            ..registered
        };
        let error = parse_source_records(&unknown).expect_err("unknown identity must fail");
        assert!(matches!(
            error,
            super::ParseError::UnsupportedSourceIdentity { .. }
        ));
    }
}
