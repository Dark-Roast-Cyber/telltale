use crate::parser::{ExtractedSourceRecords, ParseError, ParseOptions, ParsedRecord};
use telltale_schema::record::RecordKind;
use telltale_schema::source::Source;

pub(crate) fn extract_kilocode_source(
    source: &Source,
    _options: ParseOptions,
) -> Result<ExtractedSourceRecords, ParseError> {
    let native_records = super::native::extract_kilocode_native_records(source)?;
    // The pinned legacy writer emits no session companion. This required
    // ParsedRecord field therefore remains the legacy grouping fallback.
    let session_id = super::native::legacy_session_id(source);
    let records = native_records
        .into_iter()
        .map(|record| project_record(record, &session_id))
        .collect();
    Ok(ExtractedSourceRecords::records(records))
}

fn project_record(record: super::native::KiloNativeRecord, session_id: &str) -> ParsedRecord {
    let kind = match &record.semantic {
        super::native::KiloSemantic::UserMessage => RecordKind::UserMessage,
        super::native::KiloSemantic::AssistantMessage => RecordKind::AssistantMessage,
        super::native::KiloSemantic::ToolCall { .. } => RecordKind::ToolCall,
        super::native::KiloSemantic::ToolResult { .. } => RecordKind::ToolResult,
        super::native::KiloSemantic::SessionMeta => RecordKind::SessionMeta,
        super::native::KiloSemantic::Other => RecordKind::Other,
    };
    let (tool_name, arguments, content) = match record.semantic {
        super::native::KiloSemantic::ToolCall {
            tool_name,
            arguments,
        } => (Some(tool_name), arguments, record.text.unwrap_or_default()),
        super::native::KiloSemantic::ToolResult { tool_name, content } => {
            (tool_name, None, content)
        }
        _ => (None, None, record.text.unwrap_or_default()),
    };

    ParsedRecord {
        session_id: session_id.to_string(),
        agent: None,
        model: None,
        provider: None,
        timestamp: Some(record.timestamp),
        kind,
        tool_name,
        arguments,
        content,
    }
}
