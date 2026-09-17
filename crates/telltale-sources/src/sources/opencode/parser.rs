//! OpenCode SQLite source parsing.

use rusqlite::ErrorCode;

use crate::parser::{ExtractedSourceRecords, ParseError, ParseOptions};
use telltale_schema::source::Source;

use super::native::extract_sqlite_native_source;
pub(crate) use super::native::opencode_tool_part_is_result;

pub(crate) const SQLITE_PART_LIMIT: i64 = 5_000;

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
    let extracted = extract_sqlite_native_source(source, options)?;
    Ok(ExtractedSourceRecords {
        records: extracted
            .records
            .into_iter()
            .map(|record| record.legacy_record())
            .collect(),
        sqlite_part_max_time_updated: extracted.sqlite_part_max_time_updated,
    })
}
