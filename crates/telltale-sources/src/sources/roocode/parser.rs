use crate::parser::{ExtractedSourceRecords, ParseError, ParseOptions, ParsedRecord};
use telltale_schema::record::RecordKind;
use telltale_schema::source::Source;

pub(crate) fn extract_roocode_source(
    source: &Source,
    _options: ParseOptions,
) -> Result<ExtractedSourceRecords, ParseError> {
    let (metadata, native_records) = super::native::extract_roocode_native_records(source)?;
    // ParsedRecord.session_id is the required legacy grouping field. Native
    // metadata remains separately optional until a canonical projector can
    // carry source-reported identity and compatibility fallback distinctly.
    let session_id = metadata
        .session_namespace
        .unwrap_or_else(|| super::native::legacy_session_id(source));
    let records = native_records
        .into_iter()
        .map(|record| project_record(record, &session_id))
        .collect();
    Ok(ExtractedSourceRecords::records(records))
}

fn project_record(record: super::native::RooNativeRecord, session_id: &str) -> ParsedRecord {
    let kind = match &record.semantic {
        super::native::RooSemantic::UserMessage => RecordKind::UserMessage,
        super::native::RooSemantic::AssistantMessage => RecordKind::AssistantMessage,
        super::native::RooSemantic::ToolCall { .. } => RecordKind::ToolCall,
        super::native::RooSemantic::ToolResult { .. } => RecordKind::ToolResult,
        super::native::RooSemantic::SessionMeta => RecordKind::SessionMeta,
        super::native::RooSemantic::Other => RecordKind::Other,
    };
    let (tool_name, arguments, content) = match record.semantic {
        super::native::RooSemantic::ToolCall {
            tool_name,
            arguments,
        } => (Some(tool_name), arguments, record.text.unwrap_or_default()),
        super::native::RooSemantic::ToolResult { tool_name, content } => (tool_name, None, content),
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
