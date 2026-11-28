use std::path::PathBuf;

use rusqlite::Connection;
use telltale_schema::clients::{ClientId, SourceKind};
use telltale_schema::observation::{ObservationBody, ObservedAt};
use telltale_schema::source::Source;
use tempfile::tempdir;

use super::{
    AcquisitionError, AcquisitionOptions, AcquisitionProgress, BoundedReadError,
    OpenCodeSqliteReadOptions, acquire_opencode_sqlite,
};

const OBSERVED_AT: &str = "2026-09-18T12:00:00Z";

fn options() -> AcquisitionOptions {
    AcquisitionOptions::new(ObservedAt::new(OBSERVED_AT).unwrap())
}

const JSONL_IDENTITIES: &[(ClientId, &str, SourceKind)] = &[
    (ClientId::Claude, "claude.projects", SourceKind::Jsonl),
    (ClientId::OpenClaw, "openclaw.agents", SourceKind::Jsonl),
    (ClientId::Qwen, "qwen.projects", SourceKind::Jsonl),
    (ClientId::Pi, "pi.sessions", SourceKind::Jsonl),
    (ClientId::Codex, "codex.sessions", SourceKind::Jsonl),
    (
        ClientId::Codex,
        "codex.archived_sessions",
        SourceKind::ArchivedJsonl,
    ),
    (
        ClientId::Codex,
        "codex.headless_sessions",
        SourceKind::HeadlessJsonl,
    ),
];

#[test]
fn bounded_source_errors_do_not_change_production_classification() {
    for reason in [
        BoundedReadError::Missing,
        BoundedReadError::PermissionDenied,
        BoundedReadError::Unreadable,
        BoundedReadError::NonRegularSource,
        BoundedReadError::LimitExceeded,
        BoundedReadError::MalformedSource,
    ] {
        for production in [super::SourceAccess::ByName, super::SourceAccess::Resolved] {
            assert_eq!(
                super::map_source_read(super::SourceReadError::Bounded(reason), production),
                AcquisitionError::SourceRead
            );
        }
        let root = std::path::Path::new("synthetic-root");
        for bounded in [
            super::SourceAccess::Direct(super::DirectRead {
                root,
                limits: super::DirectReadLimits::default(),
            }),
            super::SourceAccess::Anchored(super::AnchoredRead {
                root: Some(root),
                max_bytes: 1,
            }),
        ] {
            assert_eq!(
                super::map_source_read(super::SourceReadError::Bounded(reason), bounded),
                AcquisitionError::BoundedSourceRead(reason)
            );
        }
    }
}

const JOURNAL_WINDOW: &str = concat!(
    r#"{"type":"user","sessionId":"synthetic-window","uuid":"u1","timestamp":"2026-11-04T00:00:00.001Z","message":{"role":"user","content":"synthetic prompt"}}"#,
    "\n",
    r#"{"type":"assistant","sessionId":"synthetic-window","uuid":"a1","timestamp":"2026-11-04T00:00:00.002Z","message":{"role":"assistant","content":[{"type":"tool_use","id":"call_1","name":"Bash","input":{"command":"ls"}}]}}"#,
    "\n",
);

fn journal_source(client: ClientId, source_id: &str, path: &std::path::Path) -> Source {
    Source {
        client,
        kind: SourceKind::Jsonl,
        source_id: source_id.to_owned(),
        path: path.to_owned(),
    }
}

fn acquisition_error(
    result: Result<super::AcquisitionBatch, AcquisitionError>,
) -> AcquisitionError {
    match result {
        Ok(_) => panic!("expected acquisition error"),
        Err(error) => error,
    }
}

fn source(path: PathBuf) -> Source {
    Source {
        client: ClientId::OpenCode,
        kind: SourceKind::Sqlite,
        source_id: "opencode.sqlite".to_owned(),
        path,
    }
}

fn database() -> (tempfile::TempDir, Connection, Source) {
    let directory = tempdir().unwrap();
    let path = directory.path().join("synthetic-opencode.db");
    let connection = Connection::open(&path).unwrap();
    connection
        .execute_batch(
            "create table message (
                    id text, session_id text, time_created integer,
                    time_updated integer, data text
                 );
                 create table part (
                    id text, message_id text, session_id text,
                    time_created integer, time_updated integer, data text
                 );",
        )
        .unwrap();
    connection
        .execute(
            "insert into message values (?1, ?2, ?3, ?4, ?5)",
            (
                "message-acquisition",
                "session-acquisition",
                1_000_i64,
                1_000_i64,
                r#"{"role":"assistant","modelID":"fixture-model"}"#,
            ),
        )
        .unwrap();
    for (id, updated, text) in [
        ("part-first", 1_000_i64, "first"),
        ("part-second", 2_000_i64, "second"),
        ("part-third", 3_000_i64, "third"),
    ] {
        connection
            .execute(
                "insert into part values (?1, ?2, ?3, ?4, ?5, ?6)",
                (
                    id,
                    "message-acquisition",
                    "session-acquisition",
                    updated,
                    updated,
                    serde_json::json!({"type":"text","text":text}).to_string(),
                ),
            )
            .unwrap();
    }
    let source = source(path);
    (directory, connection, source)
}

#[cfg(test)]
mod accounting;

#[cfg(test)]
mod bound;

mod dispatch;
mod evidence_preservation;
mod hook_journal;
mod jsonl_acquisition;
mod sqlite_acquisition;
