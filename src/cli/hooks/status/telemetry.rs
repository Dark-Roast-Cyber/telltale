//! Summarize only the active Hooks record generation.

use std::collections::BTreeMap;
use std::io;
use std::path::Path;

use serde::Serialize;
use telltale_core::hooks::telemetry::visit_active_suffix;
use telltale_schema::hooks_record::HooksRecordKind;
use telltale_sources::journal::{JournalFile, stable_file_identity};
use time::format_description::well_known::Rfc3339;

const MAX_SCAN_BYTES: u64 = 64 * 1024 * 1024;

// Record v1 accepts extension/legacy error codes. Never turn a string from a
// record into an output key; retain built-in codes and count the rest together.
const ERROR_CODES: &[&str] = &[
    "config_invalid",
    "evaluator_answer_too_late",
    "evaluator_no_answer",
    "evaluator_protocol_error",
    telltale_core::hooks::runtime::HOOK_DEADLINE_PASSED,
    "hook_panicked",
    "journal_append_failed",
    "journal_missing_state_present",
    "journal_read_failed",
    "outcome_ambiguous",
    "payload_invalid_json",
    "payload_invalid_protocol",
    "payload_missing_field",
    "payload_oversized",
    "payload_read_failed",
    "pipeline_build_failed",
    "rule_content_unreadable",
    "scan_failed",
    "scan_returned_no_result",
    "semantic_provenance_failed",
    "state_corrupt",
    "state_corrupt_reset",
    "state_dir_create_failed",
    "state_dir_unresolved",
    "state_lock_failed",
    "state_lock_open_failed",
    "state_lock_timeout",
    "state_missing_journal_present",
    "state_read_failed",
    "state_write_failed",
    telltale_schema::hooks_record::TELEMETRY_RECORD_TOO_LARGE,
    "window_write_failed",
];

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum State {
    Active,
    Missing,
    Unavailable,
}

#[derive(Serialize)]
pub(super) struct Summary {
    state: State,
    complete: bool,
    last_decision_at: Option<String>,
    error_counts: BTreeMap<&'static str, u64>,
    rejected_counts: BTreeMap<&'static str, u64>,
}

impl Summary {
    fn new(state: State, complete: bool) -> Self {
        Self {
            state,
            complete,
            last_decision_at: None,
            error_counts: BTreeMap::new(),
            rejected_counts: BTreeMap::new(),
        }
    }
}

pub(super) fn summarize(path: Option<&Path>) -> Summary {
    let unavailable = || Summary::new(State::Unavailable, false);
    let Some(path) = path else {
        return unavailable();
    };
    let mut file = match JournalFile::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Summary::new(State::Missing, true);
        }
        Err(_) => return unavailable(),
    };
    let mut summary = Summary::new(State::Active, false);
    let complete = visit_active_suffix(&mut file, MAX_SCAN_BYTES, |line| match line {
        Ok(record) => {
            if record.kind == HooksRecordKind::Decision {
                summary.last_decision_at =
                    time::OffsetDateTime::parse(&record.recorded_at, &Rfc3339)
                        .ok()
                        .and_then(|at| at.format(&Rfc3339).ok());
            }
            if let Some(code) = record.error_code.as_deref() {
                let code = ERROR_CODES
                    .iter()
                    .copied()
                    .find(|known| *known == code)
                    .unwrap_or("other");
                *summary.error_counts.entry(code).or_default() += 1;
            }
        }
        Err(code) => *summary.rejected_counts.entry(code).or_default() += 1,
    });
    if let Ok(complete) = complete
        && stable_file_identity(path).is_ok_and(|active| active == file.identity())
    {
        summary.complete = complete;
        summary
    } else {
        unavailable()
    }
}

#[cfg(test)]
pub(super) fn error_codes() -> impl Iterator<Item = &'static str> {
    ERROR_CODES.iter().copied().chain(["other"])
}
