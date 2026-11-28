use super::*;
use telltale_schema::clients::{ClientId, SourceKind};

fn budget(bytes: usize, rows: usize) -> SqliteAdmission {
    SqliteAdmission {
        byte_limit: bytes,
        row_limit: rows,
        ..Default::default()
    }
}
fn owned() -> usize {
    OWNED_SQLITE_ROWS.with(std::cell::Cell::get)
}
fn reset_owned() {
    OWNED_SQLITE_ROWS.with(|count| count.set(0));
}
fn stream(
    conn: &Connection,
    sql: &str,
    admission: &mut SqliteAdmission,
) -> Result<Vec<Value>, SourceReadError> {
    let mut values = Vec::new();
    stream_sqlite_rows(&mut conn.prepare(sql)?, [], admission, None, |value| {
        values.push(value);
        Ok(())
    })?;
    Ok(values)
}
fn source(path: std::path::PathBuf) -> Source {
    Source {
        client: ClientId::OpenCode,
        kind: SourceKind::Sqlite,
        source_id: "opencode.sqlite".into(),
        path,
    }
}
#[test]
fn sqlite_admission_occurrences_numeric_null_and_conversion_parity() {
    let conn = Connection::open_in_memory().unwrap();
    // Duplicate keys overwrite only after both occurrences have been charged.
    let sql = "select 1 as x, 2.0 as x, null as n, x'ff00' as b, cast(x'ff0061' as text) as t";
    let mut exact = budget(5 + 16 + 2 + 3, 1);
    let values = stream(&conn, sql, &mut exact).unwrap();
    assert_eq!(exact.bytes, 26);
    assert_eq!(exact.rows, 1);
    assert_eq!(values[0]["x"], 2.0);
    assert_eq!(values[0]["n"], Value::Null);
    assert_eq!(values[0]["b"], "<blob:2 bytes>");
    assert_eq!(values[0]["t"], "\u{fffd}\0a");
    reset_owned();
    let mut insufficient = budget(25, 1);
    assert!(stream(&conn, sql, &mut insufficient).is_err());
    assert_eq!(owned(), 0);
    assert_eq!((insufficient.bytes, insufficient.rows), (0, 0));
    let mut cell = budget(100, 1);
    cell.cell_limit = 2;
    assert!(stream(&conn, "select cast(x'ff0061' as text) as t", &mut cell).is_err());
    assert_eq!(owned(), 0);
    // Name charges use UTF-8 bytes, not characters, and do not charge empty results.
    let mut empty = budget(0, 0);
    assert!(
        stream(&conn, "select null as é where 0", &mut empty)
            .unwrap()
            .is_empty()
    );
    assert_eq!((empty.bytes, empty.rows), (0, 0));
    empty.cell_limit = 1;
    assert!(stream(&conn, "select null as é where 0", &mut empty).is_err());
    assert_eq!(owned(), 0);
}
#[test]
fn sqlite_admission_utf16_uses_exposed_utf8_bytes() {
    let conn = Connection::open_in_memory().unwrap();
    conn.execute_batch("pragma encoding='UTF-16le'; create table sample (t text); insert into sample values ('é😀');").unwrap();
    let encoding: String = conn
        .query_row("pragma encoding", [], |row| row.get(0))
        .unwrap();
    assert_eq!(encoding, "UTF-16le");
    let mut exact = budget(7, 1);
    exact.cell_limit = 6;
    assert_eq!(
        stream(&conn, "select t from sample", &mut exact).unwrap()[0]["t"],
        "é😀"
    );
    assert_eq!(exact.bytes, 7);
    reset_owned();
    let mut short = budget(7, 1);
    short.cell_limit = 5;
    assert!(stream(&conn, "select t from sample", &mut short).is_err());
    assert_eq!(owned(), 0);
}
#[test]
fn sqlite_admission_lookahead_rejects_before_owning_oversized_payload() {
    let conn = Connection::open_in_memory().unwrap();
    conn.execute_batch(
        "create table part(id text,message_id text,time_updated integer,data text,unknown blob);
            insert into part values('a','m',10,'{\"type\":\"text\"}',null);
            insert into part values('b','m',11,'{\"type\":\"text\"}',zeroblob(8388609));",
    )
    .unwrap();
    for page_size in [1, 2] {
        reset_owned();
        let mut admission = SqliteAdmission::default();
        let error =
            extract_incremental_parts_admitted(&conn, 10, 1, false, page_size, &mut admission)
                .unwrap_err();
        assert!(matches!(
            error,
            SourceReadError::Bounded(crate::source_read::BoundedReadError::LimitExceeded)
        ));
        assert_eq!(owned(), 1);
        assert_eq!(admission.rows, 1);
    }
    reset_owned();
    assert!(extract_incremental_parts(&conn, 10, 2, false, 1).is_err());
    assert_eq!(
        owned(),
        1,
        "admission also rejects later-page payload without owning it"
    );
}
#[test]
fn sqlite_admission_shared_messages_pages_context_and_reset() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("combined.db");
    let conn = Connection::open(&path).unwrap();
    conn.execute_batch(
        "create table message(id text, session_id text, data text, unknown blob);
            create table part(id text, message_id text, time_updated integer, data text);
            insert into message values('m','s','{\"role\":\"user\"}',zeroblob(7));
            insert into part values('a','m',10,'{\"type\":\"text\",\"text\":\"one\"}');
            insert into part values('b','m',10,'{\"type\":\"text\",\"text\":\"two\"}');
            insert into part values('unselected','m',10,'{\"type\":\"metadata\"}');",
    )
    .unwrap();
    let options = OpenCodeSqliteReadOptions {
        part_min_time_updated: Some(10),
        part_limit: 3,
        resume_high_water: None,
        ..Default::default()
    };
    let mut exact = budget(usize::MAX, 3);
    let acquired =
        extract_sqlite_native_source_admitted(&source(path.clone()), options, &mut exact).unwrap();
    assert_eq!(acquired.records.len(), 3);
    assert_eq!(exact.rows, 3);
    let message_bytes = ["id", "session_id", "data", "unknown"]
        .iter()
        .map(|name| name.len())
        .sum::<usize>()
        + 1
        + 1
        + r#"{"role":"user"}"#.len()
        + 7;
    let part_bytes = [
        "id",
        "message_id",
        "time_updated",
        "data",
        "__telltale_rowid",
        "__telltale_message_data",
        "__telltale_message_session_id",
    ]
    .iter()
    .map(|name| name.len())
    .sum::<usize>()
        + 1
        + 1
        + 8
        + r#"{"type":"text","text":"one"}"#.len()
        + 8
        + r#"{"role":"user"}"#.len()
        + 1;
    assert_eq!(
        exact.bytes,
        message_bytes + 2 * part_bytes,
        "joined context is charged on each selected occurrence"
    );
    for _ in 0..2 {
        let mut fresh = budget(exact.bytes, 3);
        assert!(
            extract_sqlite_native_source_admitted(&source(path.clone()), options, &mut fresh)
                .is_ok()
        );
        assert_eq!((fresh.bytes, fresh.rows), (exact.bytes, 3));
    }
    reset_owned();
    let mut too_small = budget(exact.bytes - 1, 3);
    assert!(
        extract_sqlite_native_source_admitted(&source(path.clone()), options, &mut too_small)
            .is_err()
    );
    assert_eq!(owned(), 2, "late rejected row was not owned");
    let mut shared = budget(usize::MAX, 2);
    extract_sqlite_message_records(&conn, &mut shared).unwrap();
    reset_owned();
    assert!(extract_incremental_parts_admitted(&conn, 10, 3, true, 1, &mut shared).is_err());
    assert_eq!(
        owned(),
        1,
        "second page shares message and first-page charges"
    );
    assert_eq!(shared.rows, 2);
    reset_owned();
    let mut unlimited = budget(usize::MAX, 100);
    assert!(extract_incremental_parts_admitted(&conn, 10, 1, true, 1, &mut unlimited).is_err());
    assert_eq!(
        owned(),
        1,
        "remaining-zero lookahead must not own its payload"
    );
    assert_eq!(unlimited.rows, 1);
    let mut exact_parts = budget(usize::MAX, 2);
    assert_eq!(
        extract_incremental_parts_admitted(&conn, 10, 2, true, 1, &mut exact_parts)
            .unwrap()
            .0
            .len(),
        2
    );
}
#[test]
fn sqlite_admission_wal_growth_and_shrink_remain_snapshot_local() {
    for grow in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("wal.db");
        let writer = Connection::open(&path).unwrap();
        writer.execute_batch("pragma journal_mode=WAL; create table part(id text,message_id text,time_updated integer,data text,unknown blob);
                insert into part values('a','m',10,'{\"type\":\"text\"}',zeroblob(1));
                insert into part values('b','m',10,'{\"type\":\"text\"}',zeroblob(1));").unwrap();
        if !grow {
            writer
                .execute("update part set unknown=zeroblob(20) where id='b'", [])
                .unwrap();
        }
        let mut reader =
            Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
        let snapshot = reader.transaction().unwrap();
        assert!(sqlite_table_exists(&snapshot, "part").unwrap());
        let mut budget = budget(1000, 2);
        budget.cell_limit = 19;
        let _guard = on_next_incremental_page(move || {
            writer
                .execute(
                    "update part set unknown=zeroblob(?1) where id='b'",
                    [if grow { 20 } else { 1 }],
                )
                .unwrap();
        });
        reset_owned();
        let result = extract_incremental_parts_admitted(&snapshot, 10, 2, false, 1, &mut budget);
        assert_eq!(result.is_ok(), grow, "charges must use pinned values");
        assert_eq!(owned(), if grow { 2 } else { 1 });
        snapshot.commit().unwrap();
        let next = extract_sqlite_native_source_admitted(
            &source(path),
            OpenCodeSqliteReadOptions {
                part_min_time_updated: Some(10),
                part_limit: 2,
                resume_high_water: None,
                ..Default::default()
            },
            &mut SqliteAdmission {
                cell_limit: 19,
                ..Default::default()
            },
        );
        assert_eq!(
            next.is_ok(),
            !grow,
            "next extraction must see writer change"
        );
    }
}
