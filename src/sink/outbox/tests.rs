use std::fs;

use rusqlite::{Connection, TransactionBehavior, params};
use sha2::{Digest, Sha256};
use tempfile::tempdir;

use super::{
    CapacityLimits, DeliveryState, DeliveryUpdate, GenerationLifecycle, JournalSnapshot,
    OUTBOX_OPEN_PROFILE, Outbox, ensure_generation_metadata, ensure_journal_path,
    event3_durable_batch, journal_namespace, journal_path_hash, make_cursor,
    mark_generation_prune_pending, read_generation_metadata, write_ingest_cursor,
};
use crate::event::{
    ActivityEventInput, ControlledMarker, Event, Evidence, check_serialized_event_markers,
    serialize_event_for_emission,
};
use crate::sink::jsonl::{JsonlGeneration, append_jsonl_events, discover_jsonl_generations};
use crate::sink::{DeliveryError, DeliveryErrorClass, EventSink, LocalJsonlSink};
use telltale_schema::clients::ClientId;

fn record_delivery_for_test(
    outbox: &mut Outbox,
    event_id: &str,
    sink_id: &str,
    state: DeliveryState,
    attempts: u32,
    next_attempt_at: Option<i64>,
    last_error_class: Option<DeliveryErrorClass>,
) -> Result<(), Box<dyn std::error::Error>> {
    outbox.record_delivery_at(
        event_id,
        sink_id,
        DeliveryUpdate {
            state,
            attempts,
            next_attempt_at,
            last_error_class,
            updated_at: super::unix_millis(),
        },
    )
}

fn marked_event(marker: &str) -> crate::event::Event {
    crate::event::activity_event(ActivityEventInput {
        client: ClientId::Codex,
        agent: None,
        model: None,
        provider: None,
        session_id: "synthetic-outbox-session".to_string(),
        source_path_hash: "synthetic-outbox-source".to_string(),
        tool_name: Some("shell".to_string()),
        tags: vec![format!("synthetic:{marker}")],
        evidence: vec![Evidence {
            field: "tool_result".to_string(),
            redacted_value: format!("token={marker}"),
            hash: None,
            rule_id: None,
        }],
        risk_contributions: Vec::new(),
        event_time: None,
    })
    .expect("synthetic activity event")
}

fn canonical_bytes(event: &crate::event::Event) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut serializer = serde_json::Serializer::new(&mut bytes);
    serialize_event_for_emission(event, &mut serializer).expect("canonical event bytes");
    bytes
}

fn assert_payload_is_safe(bytes: &[u8], marker: &str, case_id: &str) {
    assert!(
        check_serialized_event_markers(
            bytes,
            case_id,
            &[ControlledMarker {
                id: "outbox-marker",
                value: marker,
            }],
        )
        .is_ok(),
        "outbox payload retained a synthetic marker"
    );
    let value: serde_json::Value = serde_json::from_slice(bytes).expect("Event 3.0 JSON");
    assert_eq!(value["schema_version"], "3.0");
    assert!(value["event_id"].is_string());
    assert!(value["event_type"].is_string());
}

fn private_outbox_path(temp: &tempfile::TempDir) -> std::path::PathBuf {
    let path = temp.path().join("private-outbox").join("outbox.sqlite");
    create_private_parent(path.parent().expect("outbox parent"));
    path
}

#[cfg(test)]
fn create_private_parent(path: &std::path::Path) {
    fs::create_dir_all(path).expect("private parent");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("private parent mode");
    }
}

fn capacity_limits(max_pending_events: u64, max_pending_bytes: u64) -> CapacityLimits {
    CapacityLimits {
        max_pending_events,
        max_pending_bytes,
    }
}

fn named_private_outbox_path(temp: &tempfile::TempDir, name: &str) -> std::path::PathBuf {
    let path = temp.path().join(name).join("outbox.sqlite");
    create_private_parent(path.parent().expect("outbox parent"));
    path
}

fn generation_lifecycle(outbox: &Outbox, generation_id: &str) -> GenerationLifecycle {
    read_generation_metadata(&outbox.connection)
        .expect("generation metadata")
        .into_iter()
        .find(|record| record.generation_id == generation_id)
        .map(|record| record.lifecycle)
        .expect("generation metadata row")
}

fn install_generation_state(
    outbox: &mut Outbox,
    log_path: &std::path::Path,
    generations: &[JsonlGeneration],
    cursor: Option<(&JsonlGeneration, usize)>,
) -> Result<(), Box<dyn std::error::Error>> {
    let namespace = journal_namespace(&outbox.connection)?;
    let path_hash = journal_path_hash(log_path);
    let transaction = outbox
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    ensure_journal_path(&transaction, &path_hash)?;
    ensure_generation_metadata(&transaction, &path_hash, generations, &[])?;
    if let Some((generation, offset)) = cursor {
        let snapshot = JournalSnapshot {
            identity: generation.identity.clone(),
            bytes: fs::read(&generation.path)?,
        };
        let cursor = make_cursor(&namespace, &path_hash, &snapshot, offset)?;
        write_ingest_cursor(&transaction, &cursor)?;
    }
    transaction.commit()?;
    Ok(())
}

fn create_legacy_base(connection: &Connection, version: i64) {
    connection
        .execute_batch(
            "CREATE TABLE meta (
                     key TEXT PRIMARY KEY NOT NULL,
                     value TEXT NOT NULL
                 );
                 CREATE TABLE events (
                     event_id TEXT PRIMARY KEY NOT NULL,
                     payload BLOB NOT NULL,
                     payload_hash BLOB NOT NULL,
                     created_at INTEGER NOT NULL
                 );
                 CREATE TABLE deliveries (
                     event_id TEXT NOT NULL,
                     sink_id TEXT NOT NULL,
                     state TEXT NOT NULL,
                     attempt_count INTEGER NOT NULL,
                     next_attempt_at INTEGER,
                     last_error_class TEXT,
                     last_error_status INTEGER,
                     updated_at INTEGER NOT NULL,
                     PRIMARY KEY(event_id, sink_id)
                 );
                 CREATE TABLE ingest_cursor (
                     id INTEGER PRIMARY KEY CHECK(id = 1),
                     journal_namespace TEXT NOT NULL,
                     journal_path_hash TEXT NOT NULL,
                     generation_id TEXT NOT NULL,
                     byte_offset INTEGER NOT NULL,
                     observed_length INTEGER NOT NULL,
                     window_start INTEGER NOT NULL,
                     prefix_hash BLOB NOT NULL,
                     window_hash BLOB NOT NULL,
                     updated_at INTEGER NOT NULL
                 );",
        )
        .expect("create legacy outbox tables");
    connection
        .execute(
            "INSERT INTO meta (key, value) VALUES
                 ('schema_version', ?1),
                 ('journal_namespace', 'legacy-test-namespace'),
                 ('journal_path_hash', ?2),
                 ('durable_sink_ids', '[\"sink-a\",\"sink-b\"]')",
            params![version.to_string(), "a".repeat(64)],
        )
        .expect("insert legacy metadata");
}

fn insert_legacy_event(connection: &Connection, event: &Event, created_at: i64) {
    let payload = canonical_bytes(event);
    let payload_hash: [u8; 32] = Sha256::digest(&payload).into();
    connection
        .execute(
            "INSERT INTO events (event_id, payload, payload_hash, created_at)
                 VALUES (?1, ?2, ?3, ?4)",
            params![event.event_id, payload, payload_hash.as_slice(), created_at],
        )
        .expect("insert legacy event");
}

fn insert_legacy_cursor(connection: &Connection, generation_id: &str, offset: i64) {
    connection
        .execute(
            "INSERT INTO ingest_cursor
                 (id, journal_namespace, journal_path_hash, generation_id, byte_offset,
                  observed_length, window_start, prefix_hash, window_hash, updated_at)
                 VALUES (1, 'legacy-test-namespace', ?1, ?2, ?3, ?4, 0, ?5, ?6, 900)",
            params![
                "a".repeat(64),
                generation_id,
                offset,
                offset,
                vec![0x11_u8; 32],
                vec![0x22_u8; 32],
            ],
        )
        .expect("insert legacy cursor");
}

fn table_exists(connection: &Connection, table: &str) -> bool {
    connection
        .query_row(
            "SELECT EXISTS(
                     SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1
                 )",
            params![table],
            |row| row.get::<_, i64>(0),
        )
        .expect("query table existence")
        == 1
}

fn prepare_rotated_journal() -> (
    tempfile::TempDir,
    std::path::PathBuf,
    std::path::PathBuf,
    crate::event::Event,
    crate::event::Event,
    std::path::PathBuf,
) {
    let temp = tempdir().expect("tempdir");
    let log_path = temp.path().join("events.jsonl");
    let outbox_path = private_outbox_path(&temp);
    let first = marked_event("TT_ROTATION_FIRST_26");
    let second = marked_event("TT_ROTATION_SECOND_26");
    let rotation = crate::sink::RotationConfig {
        max_size_bytes: 1,
        keep: 0,
    };
    let sink = LocalJsonlSink::with_rotation(&log_path, rotation).with_durable_rotation();
    sink.emit(std::slice::from_ref(&first))
        .expect("first durable JSONL event");
    let mut outbox = Outbox::open(&outbox_path).expect("open outbox");
    outbox
        .reconcile_jsonl(&log_path, &["sink-a"])
        .expect("ingest first event");
    sink.emit(std::slice::from_ref(&second))
        .expect("rotate and append second event");
    let rotated = discover_jsonl_generations(&log_path)
        .expect("discover rotated generation")
        .into_iter()
        .find(|generation| !generation.is_active)
        .expect("rotated generation")
        .path;
    (temp, log_path, outbox_path, first, second, rotated)
}

#[cfg(unix)]
fn make_database_private(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(
        path.parent().expect("database parent"),
        fs::Permissions::from_mode(0o700),
    )
    .expect("database parent mode");
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("database mode");
}

#[cfg(not(unix))]
fn make_database_private(_path: &std::path::Path) {}

mod capacity;
mod event_rows;
mod generation_retention;
mod health;
mod jsonl_reconciliation;
mod pruning_safety;
mod schema_migration;
mod storage_safety;
