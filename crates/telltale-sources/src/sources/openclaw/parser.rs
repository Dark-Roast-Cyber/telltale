use crate::parser::{ExtractedSourceRecords, ParseError, ParseOptions, ParsedRecord};
use telltale_schema::source::Source;

pub(crate) fn extract_openclaw_jsonl_source(
    source: &Source,
    _options: ParseOptions,
) -> Result<ExtractedSourceRecords, ParseError> {
    let records = super::native::extract_openclaw_native_records(source)?
        .into_iter()
        .map(|record| ParsedRecord {
            session_id: record.legacy_session_id,
            agent: record.legacy_effective_agent,
            model: record.legacy_effective_model,
            provider: record.legacy_effective_provider,
            timestamp: record.timestamp,
            kind: record.legacy_kind,
            tool_name: record.legacy_tool_name,
            arguments: record.legacy_arguments,
            content: record.legacy_content,
        })
        .collect();

    Ok(ExtractedSourceRecords::records(records))
}
