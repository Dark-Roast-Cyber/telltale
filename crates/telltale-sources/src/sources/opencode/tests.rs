use std::fs;

use rusqlite::Connection;
use tempfile::tempdir;

use crate::source_read::SourceReadError;
use telltale_schema::clients::{ClientId, SourceKind};
use telltale_schema::source::Source;

use super::native::{
    OpenCodeSqliteNativeRecord, OpenCodeSqliteReadOptions, extract_incremental_parts,
    extract_sqlite_native_source, on_next_incremental_page,
};

#[test]
fn sqlite_errors_keep_locked_distinction_without_raw_diagnostics() {
    for (code, locked) in [
        (rusqlite::ffi::SQLITE_BUSY, true),
        (rusqlite::ffi::SQLITE_LOCKED, true),
        (rusqlite::ffi::SQLITE_ERROR, false),
    ] {
        let error = SourceReadError::from_sqlite(rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(code),
            Some("private-path-marker private-SQL-marker".into()),
        ));
        assert_eq!(matches!(error, SourceReadError::Locked), locked);
        assert!(!format!("{error} {error:?}").contains("private-"));
    }
}

fn source(path: std::path::PathBuf) -> Source {
    Source {
        client: ClientId::OpenCode,
        kind: SourceKind::Sqlite,
        source_id: "opencode.sqlite".to_string(),
        path,
    }
}

#[test]
fn sqlite_admission_actual_cell_boundary_unknown_text_and_blob() {
    let temp = tempdir().unwrap();
    let path = temp.path().join("cell.db");
    let conn = Connection::open(&path).unwrap();
    conn.execute_batch(
        "create table message (unknown); insert into message values (zeroblob(8388608));",
    )
    .unwrap();
    let read = || {
        extract_sqlite_native_source(&source(path.clone()), OpenCodeSqliteReadOptions::default())
    };
    assert_eq!(read().unwrap().records.len(), 1);
    conn.execute_batch("update message set unknown=zeroblob(8388609)")
        .unwrap();
    assert!(read().is_err());
    conn.execute_batch("update message set unknown=cast(zeroblob(8388608) as text)")
        .unwrap();
    assert_eq!(read().unwrap().records.len(), 1);
    conn.execute_batch("update message set unknown=cast(zeroblob(8388609) as text)")
        .unwrap();
    let error = read().unwrap_err();
    assert!(!format!("{error} {error:?}").contains("cell.db"));
}

#[test]
fn sqlite_admission_actual_key_boundary_even_empty_schema() {
    let temp = tempdir().unwrap();
    let path = temp.path().join("keys.db");
    let conn = Connection::open(&path).unwrap();
    let read = || {
        extract_sqlite_native_source(&source(path.clone()), OpenCodeSqliteReadOptions::default())
    };
    for size in [8_388_608, 8_388_609] {
        conn.execute_batch(&format!(
            "drop table if exists message; create table message (\"{}\" blob)",
            "k".repeat(size)
        ))
        .unwrap();
        assert_eq!(read().is_ok(), size == 8_388_608);
        conn.execute("insert into message values (null)", [])
            .unwrap();
        assert_eq!(read().is_ok(), size == 8_388_608);
    }
}

#[test]
fn sqlite_admission_actual_aggregate_boundary_unknown_blobs() {
    let temp = tempdir().unwrap();
    let path = temp.path().join("aggregate.db");
    let conn = Connection::open(&path).unwrap();
    conn.execute_batch("create table message (x blob);")
        .unwrap();
    for _ in 0..16 {
        conn.execute("insert into message values (zeroblob(8388607))", [])
            .unwrap();
    }
    let read = || {
        extract_sqlite_native_source(&source(path.clone()), OpenCodeSqliteReadOptions::default())
    };
    assert_eq!(read().unwrap().records.len(), 16);
    conn.execute("insert into message values (null)", [])
        .unwrap();
    assert!(read().is_err(), "one extra key byte exceeds aggregate cap");
}

#[test]
fn sqlite_admission_actual_row_boundary_metadata_only() {
    let temp = tempdir().unwrap();
    let path = temp.path().join("rows.db");
    let conn = Connection::open(&path).unwrap();
    conn.execute_batch("create table message (x); with recursive n(i) as (values(1) union all select i+1 from n where i<100000) insert into message select null from n;").unwrap();
    let read = || {
        extract_sqlite_native_source(&source(path.clone()), OpenCodeSqliteReadOptions::default())
    };
    assert_eq!(read().unwrap().records.len(), 100_000);
    conn.execute("insert into message values (null)", [])
        .unwrap();
    assert!(read().is_err());
}

#[test]
fn sqlite_identity_does_not_accept_json_bytes() {
    let temp = tempdir().expect("tempdir");
    let path = temp.path().join("not-a-database.db");
    fs::write(&path, b"{\"role\":\"assistant\",\"content\":\"synthetic\"}").expect("fixture");
    let error = extract_sqlite_native_source(&source(path), OpenCodeSqliteReadOptions::default())
        .expect_err("json bytes are not sqlite");
    assert!(matches!(error, SourceReadError::Sqlite));
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
fn readonly_acquisition_reads_wal_and_preserves_five_second_busy_timeout() {
    let temp = tempdir().unwrap();
    let wal_path = temp.path().join("wal.db");
    let writer = Connection::open(&wal_path).unwrap();
    writer.execute_batch("pragma journal_mode=WAL; create table message (id text, session_id text, data text); insert into message values ('m', 's', '{}');").unwrap();
    writer
        .execute_batch("begin immediate; insert into message values ('n', 's', '{}');")
        .unwrap();
    let read =
        extract_sqlite_native_source(&source(wal_path), OpenCodeSqliteReadOptions::default())
            .unwrap();
    assert_eq!(read.records.len(), 1);
    writer.execute_batch("rollback").unwrap();

    let locked_path = temp.path().join("locked.db");
    let exclusive = Connection::open(&locked_path).unwrap();
    exclusive
        .execute_batch(
            "create table message (id text, session_id text, data text); begin exclusive;",
        )
        .unwrap();
    let started = std::time::Instant::now();
    let err =
        extract_sqlite_native_source(&source(locked_path), OpenCodeSqliteReadOptions::default())
            .expect_err("locked read must fail");
    assert!(matches!(err, SourceReadError::Locked));
    assert!(started.elapsed() >= std::time::Duration::from_millis(4_800));
    exclusive.execute_batch("rollback").unwrap();
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

    let selected_source = source(path);
    assert!(matches!(
        extract_sqlite_native_source(
            &selected_source,
            OpenCodeSqliteReadOptions {
                part_min_time_updated: Some(2_000),
                part_limit: 1,
            },
        ),
        Err(SourceReadError::Bounded(
            crate::source_read::BoundedReadError::LimitExceeded
        ))
    ));
    let extracted = extract_sqlite_native_source(
        &selected_source,
        OpenCodeSqliteReadOptions {
            part_min_time_updated: Some(2_000),
            part_limit: 2,
        },
    )
    .expect("bounded read");
    assert_eq!(extracted.records.len(), 2);
    let OpenCodeSqliteNativeRecord::Text(part) = &extracted.records[0] else {
        panic!("expected text part");
    };
    assert_eq!(part.text.as_deref(), Some("second"));
    assert_eq!(extracted.sqlite_part_max_time_updated, Some(3_000));
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
        SourceReadError::Locked
    ));
}

#[test]
fn incremental_parts_reject_non_integer_continuation_time() {
    let temp = tempdir().unwrap();
    let path = temp.path().join("invalid-key.db");
    let conn = Connection::open(&path).unwrap();
    conn.execute_batch("create table part (id text, message_id text, session_id text, time_updated, data text);
        insert into part values ('p','m','s','invalid','{\"type\":\"text\",\"text\":\"synthetic\"}');").unwrap();
    assert!(
        extract_sqlite_native_source(
            &source(path),
            OpenCodeSqliteReadOptions {
                part_min_time_updated: Some(0),
                part_limit: 10,
            }
        )
        .is_err()
    );
}

#[test]
fn small_pages_check_exact_cap_overflow_order_and_later_errors() {
    let conn = Connection::open_in_memory().unwrap();
    conn.execute_batch(
        "create table part (id text, message_id text, session_id text, time_updated, data text);
        insert into part values ('a','m','s',10,'{\"type\":\"text\",\"text\":\"a\"}'),
          ('b','m','s',10,'{\"type\":\"text\",\"text\":\"b\"}'),
          ('c','m','s',10,'{\"type\":\"text\",\"text\":\"c\"}'),
          ('d','m','s',11,'{\"type\":\"text\",\"text\":\"d\"}');",
    )
    .unwrap();
    let (records, high_water) = extract_incremental_parts(&conn, 10, 4, false, 2).unwrap();
    assert_eq!(high_water, Some(11));
    let ids = records
        .iter()
        .map(|r| match r {
            OpenCodeSqliteNativeRecord::Text(p) => p.source_id.as_deref().unwrap(),
            _ => panic!("expected text"),
        })
        .collect::<Vec<_>>();
    assert_eq!(ids, ["a", "b", "c", "d"]);
    assert!(extract_incremental_parts(&conn, 10, 3, false, 2).is_err());
    assert!(extract_incremental_parts(&conn, 10, i64::MAX, false, 2).is_err());
    conn.execute(
        "insert into part values ('e','m','s',12,'{\"type\":\"text\"}')",
        [],
    )
    .unwrap();
    assert!(extract_incremental_parts(&conn, 10, 4, false, 2).is_err());
    conn.execute("update part set time_updated='invalid' where id='e'", [])
        .unwrap();
    assert!(extract_incremental_parts(&conn, 10, 6, false, 2).is_err());
    conn.execute(
        "update part set time_updated=12, data='not json' where id='e'",
        [],
    )
    .unwrap();
    assert!(extract_incremental_parts(&conn, 10, 6, false, 2).is_err());
}

#[test]
fn read_snapshot_excludes_concurrent_message_and_part_updates() {
    let temp = tempdir().unwrap();
    let path = temp.path().join("snapshot.db");
    let mut writer = Connection::open(&path).unwrap();
    writer.execute_batch("pragma journal_mode=WAL;
        create table message (id text, session_id text, data text);
        create table part (id text, message_id text, session_id text, time_updated integer, data text);
        insert into message values ('m','s','{\"role\":\"user\"}');").unwrap();
    let tx = writer.transaction().unwrap();
    for i in 0..5001 {
        tx.execute(
            r#"insert into part values (?1,'m','s',10,'{"type":"text","text":"before"}')"#,
            [format!("part-{i}")],
        )
        .unwrap();
    }
    tx.commit().unwrap();
    let mutated = std::rc::Rc::new(std::cell::Cell::new(false));
    let callback_ran = mutated.clone();
    let _callback_guard = on_next_incremental_page(move || {
        writer
            .execute_batch(
                "begin immediate;
        update message set data='{\"role\":\"assistant\"}';
        update part set time_updated=20, data='{\"type\":\"text\",\"text\":\"after\"}';
        insert into part values ('c','m','s',20,'{\"type\":\"text\",\"text\":\"after\"}'); commit;",
            )
            .unwrap();
        callback_ran.set(true);
    });
    let options = OpenCodeSqliteReadOptions {
        part_min_time_updated: Some(10),
        part_limit: 6000,
    };
    let acquired = extract_sqlite_native_source(&source(path.clone()), options).unwrap();
    assert!(mutated.get(), "writer must commit between production pages");
    assert_eq!(acquired.sqlite_part_max_time_updated, Some(10));
    assert_eq!(acquired.records.len(), 5002);
    let mut ids = Vec::new();
    for record in acquired.records {
        match record {
            OpenCodeSqliteNativeRecord::Message(message) => {
                assert_eq!(message.context.role.as_deref(), Some("user"));
            }
            OpenCodeSqliteNativeRecord::Text(part) => {
                assert_eq!(part.text.as_deref(), Some("before"));
                assert_eq!(part.context.role.as_deref(), Some("user"));
                ids.push(part.source_id.unwrap());
            }
            _ => panic!("expected message or text"),
        }
    }
    assert_eq!(
        ids,
        (0..5001).map(|i| format!("part-{i}")).collect::<Vec<_>>()
    );
    let next = extract_sqlite_native_source(&source(path), options).unwrap();
    assert_eq!(next.sqlite_part_max_time_updated, Some(20));
    assert_eq!(next.records.len(), 5003);
    for record in next.records {
        match record {
            OpenCodeSqliteNativeRecord::Message(message) => {
                assert_eq!(message.context.role.as_deref(), Some("assistant"));
            }
            OpenCodeSqliteNativeRecord::Text(part) => {
                assert_eq!(part.text.as_deref(), Some("after"));
                assert_eq!(part.context.role.as_deref(), Some("assistant"));
            }
            _ => panic!("expected message or text"),
        }
    }
}
