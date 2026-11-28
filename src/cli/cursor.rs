//! `telltale cursor`: lists stored OpenCode ingestion cursors or discards one
//! exactly, guarded by its digest. It never reads session stores or touches
//! history and baseline state.

use std::io::{self, Write};
use std::path::{Path, PathBuf};

use clap::Subcommand;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::event::is_canonical_sha256_hex;
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
            if !is_canonical_sha256_hex(&source_instance_id)
                || !is_canonical_sha256_hex(&expect_cursor)
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
            || !is_canonical_sha256_hex(&cursor.source_instance_id)
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
mod tests;
