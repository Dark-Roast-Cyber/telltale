//! Opt-in operator diagnostics: bounded, content-free records of what a command
//! did and what it cost, written to a local file of their own.
//!
//! Diagnostics are not Event 3.0, scanner health, detections or operational
//! alerts, and never go to the canonical JSONL or a sink. Every category is off
//! by default and selected on its own (`diagnostics.*` in `settings.d`).
//!
//! Records are built only from typed fields: whole numbers, booleans, fixed
//! enum values and a clock-derived timestamp. Nothing read from a session store,
//! path, setting value or error message is formatted into one. Writing a record
//! never changes the outcome of the work it describes: a failure prints one
//! fixed warning naming a [`WriteFailure`] class.
//!
//! - [`phases`]: a monotonic clock splitting elapsed time into named phases.
//! - [`resources`]: process CPU time and peak memory, one module per
//!   operating system.
//! - [`writer`]: the bounded diagnostics file.

pub(crate) mod phases;
pub(crate) mod resources;
mod writer;

use std::path::{Path, PathBuf};

pub(crate) use writer::{WriteFailure, append_record, rotated_path};

/// Where records go when `diagnostics.path` is unset: this directory beside the
/// state file, then this file name. A directory of its own keeps the file out
/// of a non-recursive wildcard over a log directory even when the state file
/// and the event log share one, and the name does not match the event log's.
pub(crate) const DEFAULT_DIRECTORY: &str = "diagnostics";
pub(crate) const DEFAULT_FILE_NAME: &str = "telltale-scan-diagnostics.jsonl";

/// The categories an operator enabled.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Categories {
    pub(crate) scan_phases: bool,
    pub(crate) process_resources: bool,
}

impl Categories {
    pub(crate) fn any(self) -> bool {
        self.scan_phases || self.process_resources
    }
}

/// The diagnostics file for a state path: the configured path, or
/// [`DEFAULT_DIRECTORY`]/[`DEFAULT_FILE_NAME`] beside the state file.
pub(crate) fn resolve_path(configured: Option<&Path>, state_path: &Path) -> PathBuf {
    configured.map_or_else(
        || {
            state_path
                .with_file_name(DEFAULT_DIRECTORY)
                .join(DEFAULT_FILE_NAME)
        },
        Path::to_path_buf,
    )
}

/// Prints the one warning a failed diagnostics write produces. The text is
/// fixed: it names the failure class, never a path or an operating-system
/// error, and a closed stderr is ignored rather than turned into a failure.
pub(crate) fn warn_not_written(failure: WriteFailure) {
    use std::io::Write;
    let _ = writeln!(
        std::io::stderr(),
        "warning: diagnostics not written ({})",
        failure.as_str()
    );
}

/// The current UTC time as an RFC 3339 timestamp with millisecond precision.
pub(crate) fn recorded_at() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::macros::format_description!(
            "[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:3]Z"
        ))
        .unwrap_or_default()
}

/// Microseconds in a duration, saturating at `u64::MAX`.
pub(crate) fn micros(duration: std::time::Duration) -> u64 {
    u64::try_from(duration.as_micros()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_path_sits_beside_the_state_file() {
        let state = Path::new("state-dir").join("telltale-state.json");
        assert_eq!(
            resolve_path(None, &state),
            Path::new("state-dir")
                .join(DEFAULT_DIRECTORY)
                .join(DEFAULT_FILE_NAME)
        );
        let configured = Path::new("elsewhere").join("diag.jsonl");
        assert_eq!(resolve_path(Some(&configured), &state), configured);
    }

    #[test]
    fn recorded_at_is_utc_with_milliseconds() {
        let value = recorded_at();
        assert!(
            time::OffsetDateTime::parse(&value, &time::format_description::well_known::Rfc3339)
                .is_ok(),
            "{value}"
        );
        assert_eq!(value.len(), "2026-11-19T03:00:00.000Z".len(), "{value}");
        assert!(value.ends_with('Z'), "{value}");
    }
}
