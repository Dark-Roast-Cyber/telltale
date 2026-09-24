use std::fs;

use rusqlite::Connection;
use tempfile::tempdir;

use crate::source_read::SourceReadError;
use telltale_schema::clients::{ClientId, SourceKind};
use telltale_schema::source::Source;

use super::native::{
    OpenCodeSqliteNativeRecord, OpenCodeSqliteReadOptions, extract_sqlite_native_source,
};

fn source(path: std::path::PathBuf) -> Source {
    Source {
        client: ClientId::OpenCode,
        kind: SourceKind::Sqlite,
        source_id: "opencode.sqlite".to_string(),
        path,
    }
}

#[test]
fn sqlite_identity_does_not_accept_json_bytes() {
    let temp = tempdir().expect("tempdir");
    let path = temp.path().join("not-a-database.db");
    fs::write(&path, b"{\"role\":\"assistant\",\"content\":\"synthetic\"}").expect("fixture");
    let error = extract_sqlite_native_source(&source(path), OpenCodeSqliteReadOptions::default())
        .expect_err("json bytes are not sqlite");
    assert!(matches!(error, SourceReadError::Sqlite(_)));
    assert!(!error.to_string().contains("synthetic"));
}

#[test]
fn sqlite_without_supported_tables_is_empty() {
    let temp = tempdir().expect("tempdir");
    let path = temp.path().join("empty.db");
    let conn = Connection::open(&path).expect("open");
    conn.execute("create table unrelated (id text)", [])
        .expect("schema");
    drop(conn);
    let extracted =
        extract_sqlite_native_source(&source(path), OpenCodeSqliteReadOptions::default())
            .expect("empty supported tables");
    assert!(extracted.records.is_empty());
    assert_eq!(extracted.sqlite_part_max_time_updated, None);
}

#[test]
fn part_cursor_is_inclusive_and_reports_selected_high_water() {
    let temp = tempdir().expect("tempdir");
    let path = temp.path().join("opencode.db");
    let conn = Connection::open(&path).expect("open");
    conn.execute_batch(
        "create table part (
            id text primary key,
            message_id text not null,
            session_id text not null,
            time_created integer not null,
            time_updated integer not null,
            data text not null
        );",
    )
    .expect("schema");
    for (id, updated, text) in [
        ("part-a", 1_000_i64, "first"),
        ("part-b", 2_000_i64, "second"),
        ("part-c", 3_000_i64, "third"),
    ] {
        conn.execute(
            "insert into part (id, message_id, session_id, time_created, time_updated, data)
             values (?1, ?2, ?3, ?4, ?5, ?6)",
            (
                id,
                "message-part",
                "session-part-cursor",
                updated,
                updated,
                serde_json::json!({"type": "text", "text": text}).to_string(),
            ),
        )
        .expect("insert");
    }
    drop(conn);

    let extracted = extract_sqlite_native_source(
        &source(path),
        OpenCodeSqliteReadOptions {
            part_min_time_updated: Some(2_000),
            part_limit: 1,
        },
    )
    .expect("bounded read");
    assert_eq!(extracted.records.len(), 1);
    let OpenCodeSqliteNativeRecord::Text(part) = &extracted.records[0] else {
        panic!("expected text part");
    };
    assert_eq!(part.text.as_deref(), Some("second"));
    assert_eq!(extracted.sqlite_part_max_time_updated, Some(2_000));
}

#[test]
fn part_cursor_join_qualifies_time_updated() {
    let temp = tempdir().expect("tempdir");
    let path = temp.path().join("opencode.db");
    let conn = Connection::open(&path).expect("open");
    conn.execute_batch(
        "create table message (
            id text primary key,
            session_id text not null,
            time_created integer not null,
            time_updated integer not null,
            data text not null
        );
        create table part (
            id text primary key,
            message_id text not null,
            session_id text not null,
            time_created integer not null,
            time_updated integer not null,
            data text not null
        );",
    )
    .expect("schema");
    conn.execute(
        "insert into message (id, session_id, time_created, time_updated, data)
         values (?1, ?2, ?3, ?4, ?5)",
        (
            "message-cursor",
            "session-cursor-join",
            1_000_i64,
            1_000_i64,
            serde_json::json!({"role": "assistant"}).to_string(),
        ),
    )
    .expect("message");
    for (id, updated, text) in [
        ("part-old", 1_000_i64, "first"),
        ("part-new", 2_000_i64, "second"),
    ] {
        conn.execute(
            "insert into part (id, message_id, session_id, time_created, time_updated, data)
             values (?1, ?2, ?3, ?4, ?5, ?6)",
            (
                id,
                "message-cursor",
                "session-cursor-join",
                updated,
                updated,
                serde_json::json!({"type": "text", "text": text}).to_string(),
            ),
        )
        .expect("part");
    }
    drop(conn);

    let extracted = extract_sqlite_native_source(
        &source(path),
        OpenCodeSqliteReadOptions {
            part_min_time_updated: Some(1_001),
            part_limit: 100,
        },
    )
    .expect("joined cursor read");
    let texts = extracted
        .records
        .iter()
        .filter_map(|record| match record {
            OpenCodeSqliteNativeRecord::Text(part) => part.text.as_deref(),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(texts, vec!["second"]);
    assert_eq!(extracted.sqlite_part_max_time_updated, Some(2_000));
}

#[test]
fn sqlite_busy_error_maps_to_locked() {
    let temp = tempdir().expect("tempdir");
    let path = temp.path().join("busy.db");
    let writer = Connection::open(&path).expect("writer");
    writer
        .execute("create table t (x integer)", [])
        .expect("schema");
    writer.execute("BEGIN IMMEDIATE", []).expect("lock");
    writer
        .execute("insert into t values (1)", [])
        .expect("insert");
    let reader = Connection::open(&path).expect("reader");
    reader
        .busy_timeout(std::time::Duration::from_millis(0))
        .expect("timeout");
    let error = reader
        .execute("insert into t values (2)", [])
        .expect_err("busy");
    assert!(matches!(
        SourceReadError::from_sqlite(error),
        SourceReadError::Locked(_)
    ));
}
