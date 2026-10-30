//! `telltale cursor`: lists stored OpenCode ingestion cursors or discards one
//! exactly, guarded by its digest. It never reads session stores or touches
//! history and baseline state.

use std::io::{self, Write};
use std::path::{Path, PathBuf};

use clap::Subcommand;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::file_lock::safe_path_info;
use crate::state::{
    ScanState, SqliteIngestionCursor, StateLock, sqlite_ingestion_cursor_key_for_instance,
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Subcommand)]
pub(super) enum CursorCommand {
    /// Inspect stored OpenCode cursors without reading session stores. Pause scan/watch first.
    List {
        /// Existing native scan state file. No environment or profile default is used.
        #[arg(long)]
        state_path: PathBuf,
    },
    /// Discard one OpenCode cursor, not history or baseline state. Pause scan/watch first.
    Reset {
        /// Existing native scan state file. No environment or profile default is used.
        #[arg(long)]
        state_path: PathBuf,
        /// Exact opaque source instance from cursor list; paths are not accepted.
        #[arg(long)]
        source_instance_id: String,
        /// Exact stored schema: part or session_message. Other schema progress is preserved.
        #[arg(long)]
        table: String,
        /// Cursor digest from a fresh cursor list. Changed progress is never discarded implicitly.
        #[arg(long)]
        expect_cursor: String,
        /// Accept bounded bootstrap, possible repeats and unevaluated/lost history.
        #[arg(long)]
        accept_history_gap: bool,
        /// Also explicitly abandon an unfinished drain, including its raw continuation.
        #[arg(long)]
        abandon_incomplete_drain: bool,
    },
}

#[derive(Serialize)]
struct CursorInspection<'a> {
    source_instance_id: &'a str,
    table: &'a str,
    last_time_updated: i64,
    observed_at_unix_ms: u64,
    draining: bool,
    continue_after_time_updated: Option<i64>,
    cursor_digest: String,
}

pub(super) fn run(command: CursorCommand) -> Result<()> {
    run_with_output(command, &mut io::stdout().lock())
}

fn run_with_output(command: CursorCommand, output: &mut impl Write) -> Result<()> {
    match command {
        CursorCommand::List { state_path } => {
            let (lock, state) = load(&state_path)?;
            let cursors = state
                .sqlite_ingestion_cursors
                .values()
                .filter(|cursor| cursor.client == "opencode")
                .map(|cursor| {
                    Ok(CursorInspection {
                        source_instance_id: &cursor.source_instance_id,
                        table: &cursor.table,
                        last_time_updated: cursor.last_time_updated,
                        observed_at_unix_ms: cursor.observed_at_unix_ms,
                        draining: cursor.draining,
                        continue_after_time_updated: cursor.continue_after_time_updated,
                        cursor_digest: digest(cursor)?,
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            let bytes = result_bytes(serde_json::json!({
                "operation": "cursor_list",
                "client": "opencode",
                "source_id": "opencode.sqlite",
                "cursors": cursors,
            }))?;
            lock.verify().map_err(|_| "cursor_state_changed")?;
            write_result(output, &bytes).map_err(|_| "cursor_list_output_failed".into())
        }
        CursorCommand::Reset {
            state_path,
            source_instance_id,
            table,
            expect_cursor,
            accept_history_gap,
            abandon_incomplete_drain,
        } => {
            if !is_digest(&source_instance_id)
                || !is_digest(&expect_cursor)
                || !matches!(table.as_str(), "part" | "session_message")
            {
                return Err("cursor_selection_invalid".into());
            }
            if !accept_history_gap {
                return Err("cursor_history_gap_acceptance_required".into());
            }
            let (lock, mut state) = load(&state_path)?;
            let key = sqlite_ingestion_cursor_key_for_instance(
                "opencode",
                "opencode.sqlite",
                &source_instance_id,
                &table,
            );
            let cursor = state
                .sqlite_ingestion_cursors
                .get(&key)
                .ok_or("cursor_not_found; inspect state before retrying")?;
            if digest(cursor)? != expect_cursor {
                return Err("cursor_changed; inspect state before retrying".into());
            }
            if cursor.draining && !abandon_incomplete_drain {
                return Err("cursor_drain_abandonment_required".into());
            }
            let bytes = result_bytes(serde_json::json!({
                "operation": "cursor_reset",
                "status": "committed",
                "source_instance_id": source_instance_id,
                "table": table,
                "discarded_cursor_digest": expect_cursor,
                "abandoned_incomplete_drain": cursor.draining,
                "next_selected_schema_read": "bounded_bootstrap",
                "history_recovered": false,
                "whole_store_evaluated": false,
                "exactly_once_replay": false,
                "baseline_changed": false,
                "deduplication_retained": true,
            }))?;
            state.sqlite_ingestion_cursors.remove(&key);
            let prepared = state
                .prepare_atomic_save(&state_path)
                .map_err(|_| "cursor_state_prepare_failed")?;
            lock.verify().map_err(|_| "cursor_state_changed")?;
            prepared.install_replace(&state_path).map_err(
                |_| "cursor_reset_outcome_unknown; stop scanners and inspect state before retrying",
            )?;
            write_result(output, &bytes).map_err(|_| {
                "cursor_reset_committed_ack_failed; stop scanners and inspect state before retrying"
                    .into()
            })
        }
    }
}

fn load(path: &Path) -> Result<(StateLock, ScanState)> {
    let lock = StateLock::acquire(path).map_err(|_| "cursor_state_unavailable")?;
    if safe_path_info(path)
        .map_err(|_| "cursor_state_unavailable")?
        .is_none()
    {
        return Err("cursor_state_missing".into());
    }
    let state = ScanState::load_snapshot(path).map_err(|_| "cursor_state_invalid")?;
    for (key, cursor) in &state.sqlite_ingestion_cursors {
        if cursor.client != "opencode"
            && cursor.source_id != "opencode.sqlite"
            && !key.starts_with("opencode\u{1f}opencode.sqlite\u{1f}")
        {
            continue;
        }
        if cursor.client != "opencode"
            || cursor.source_id != "opencode.sqlite"
            || !is_digest(&cursor.source_instance_id)
            || !matches!(cursor.table.as_str(), "part" | "session_message")
            || key
                != &sqlite_ingestion_cursor_key_for_instance(
                    &cursor.client,
                    &cursor.source_id,
                    &cursor.source_instance_id,
                    &cursor.table,
                )
        {
            return Err("cursor_binding_invalid".into());
        }
    }
    Ok((lock, state))
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn digest(cursor: &SqliteIngestionCursor) -> Result<String> {
    let bytes = serde_json::to_vec(cursor).map_err(|_| "cursor_digest_failed")?;
    let mut hash = Sha256::new();
    hash.update(b"telltale:cursor-reset:v1\0");
    hash.update(bytes);
    Ok(hex::encode(hash.finalize()))
}

fn result_bytes(value: serde_json::Value) -> Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec(&value).map_err(|_| "cursor_result_invalid")?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn write_result(output: &mut impl Write, bytes: &[u8]) -> io::Result<()> {
    output.write_all(bytes)?;
    output.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    use telltale_schema::clients::{ClientId, SourceKind};
    use telltale_schema::source::Source;

    fn fixture(path: &Path) -> SqliteIngestionCursor {
        let source = Source {
            client: ClientId::OpenCode,
            kind: SourceKind::Sqlite,
            source_id: "opencode.sqlite".into(),
            path: "synthetic-not-a-live-store.db".into(),
        };
        let mut state = ScanState::default();
        state.observe_sqlite_ingestion_cursor(&source, "session_message", 100, 1);
        state.observe_sqlite_ingestion_drain(&source, "session_message", 50, 2);
        state.observe_sqlite_ingestion_cursor(&source, "part", 200, 3);
        state.observe_sources(std::slice::from_ref(&source), 4);
        state.seen_detection_fingerprints.insert("retained".into());
        state
            .record_baseline_source_contribution(
                &source,
                "retained".into(),
                vec![crate::baseline::BaselineSummary::default()],
            )
            .unwrap();
        state
            .rebuild_baseline_snapshots_from_source_contributions()
            .unwrap();
        let cursor = state
            .sqlite_ingestion_cursors
            .values()
            .find(|cursor| cursor.table == "session_message")
            .unwrap()
            .clone();
        state.save(path).unwrap();
        cursor
    }

    fn reset(path: &Path, cursor: &SqliteIngestionCursor, abandon: bool) -> CursorCommand {
        CursorCommand::Reset {
            state_path: path.into(),
            source_instance_id: cursor.source_instance_id.clone(),
            table: cursor.table.clone(),
            expect_cursor: digest(cursor).unwrap(),
            accept_history_gap: true,
            abandon_incomplete_drain: abandon,
        }
    }

    #[test]
    fn cursor_reset_preserves_every_other_state_family_and_schema() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("state.json");
        for legacy_drain in [false, true] {
            let mut cursor = fixture(&path);
            if legacy_drain {
                cursor.continue_after_time_updated = None;
                let mut state = ScanState::load(&path).unwrap();
                let key = sqlite_ingestion_cursor_key_for_instance(
                    "opencode",
                    "opencode.sqlite",
                    &cursor.source_instance_id,
                    "session_message",
                );
                state.sqlite_ingestion_cursors.insert(key, cursor.clone());
                state.save(&path).unwrap();
            }
            let before = std::fs::read(&path).unwrap();
            let error = run_with_output(reset(&path, &cursor, false), &mut Vec::new()).unwrap_err();
            assert_eq!(error.to_string(), "cursor_drain_abandonment_required");
            assert_eq!(std::fs::read(&path).unwrap(), before);
            let mut expected: serde_json::Value = serde_json::from_slice(&before).unwrap();
            expected["sqlite_ingestion_cursors"]
                .as_object_mut()
                .unwrap()
                .retain(|_, value| value["table"] != "session_message");
            let mut output = Vec::new();
            run_with_output(reset(&path, &cursor, true), &mut output).unwrap();
            let result: serde_json::Value = serde_json::from_slice(&output).unwrap();
            assert_eq!(result["abandoned_incomplete_drain"], true);
            let actual: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn cursor_reset_ack_failure_is_explicitly_committed() {
        struct BrokenOutput;
        impl Write for BrokenOutput {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(io::ErrorKind::BrokenPipe.into())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("state.json");
        let cursor = fixture(&path);
        let error = run_with_output(reset(&path, &cursor, true), &mut BrokenOutput).unwrap_err();
        assert!(
            error
                .to_string()
                .starts_with("cursor_reset_committed_ack_failed;")
        );
        let state = ScanState::load(&path).unwrap();
        assert_eq!(state.sqlite_ingestion_cursors.len(), 1);
        assert_eq!(
            state
                .sqlite_ingestion_cursors
                .values()
                .next()
                .unwrap()
                .table,
            "part"
        );
        let before = std::fs::read(&path).unwrap();
        let error = run_with_output(reset(&path, &cursor, true), &mut Vec::new()).unwrap_err();
        assert!(error.to_string().starts_with("cursor_not_found;"));
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }

    #[test]
    fn cursor_digest_binds_both_coordinates_and_observation() {
        let temp = tempfile::tempdir().unwrap();
        let cursor = fixture(&temp.path().join("state.json"));
        let mut changed = cursor.clone();
        changed.last_time_updated += 1;
        assert_ne!(digest(&cursor).unwrap(), digest(&changed).unwrap());
        changed = cursor.clone();
        changed.continue_after_time_updated = Some(49);
        assert_ne!(digest(&cursor).unwrap(), digest(&changed).unwrap());
        changed = cursor.clone();
        changed.observed_at_unix_ms += 1;
        assert_ne!(digest(&cursor).unwrap(), digest(&changed).unwrap());
        changed = cursor.clone();
        changed.continue_after_time_updated = None;
        assert_ne!(digest(&cursor).unwrap(), digest(&changed).unwrap());
    }
}
