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

#[test]
fn unknown_persisted_error_class_fails_closed_without_rewriting_row() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("private/outbox.sqlite");
    let event = marked_event("TT_SYNTHETIC_EVENT");
    let mut outbox = Outbox::open(&path).unwrap();
    outbox.insert_event(&event, &["remote"]).unwrap();
    drop(outbox);
    let connection = Connection::open(&path).unwrap();
    connection.execute(
            "UPDATE deliveries SET last_error_class = 'future_application_class' WHERE sink_id = 'remote'",
            [],
        ).unwrap();
    drop(connection);

    let outbox = Outbox::open(&path).unwrap();
    let error = outbox.get_delivery(&event.event_id, "remote").unwrap_err();
    assert_eq!(
        error.downcast_ref::<DeliveryError>().unwrap().class,
        DeliveryErrorClass::DurableStorage
    );
    assert!(
        error
            .to_string()
            .contains("stored delivery error class is invalid")
    );
    assert!(!error.to_string().contains("future_application_class"));
    drop(outbox);
    let connection = Connection::open(&path).unwrap();
    let (state, class): (String, String) = connection
        .query_row(
            "SELECT state, last_error_class FROM deliveries WHERE sink_id = 'remote'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(state, "pending");
    assert_eq!(class, "future_application_class");
}

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

#[cfg(unix)]
#[test]
fn journal_path_hash_is_stable_across_missing_to_created_symlinked_ancestor() {
    use std::os::unix::fs::symlink;

    let temp = tempdir().expect("tempdir");
    let real_parent = temp.path().join("real");
    let alias_parent = temp.path().join("alias");
    fs::create_dir(&real_parent).expect("real parent");
    symlink(&real_parent, &alias_parent).expect("symlink parent");

    let journal_path = alias_parent.join("events.jsonl");
    let before = journal_path_hash(&journal_path);
    fs::write(&journal_path, b"synthetic journal\n").expect("journal leaf");
    let after = journal_path_hash(&journal_path);

    assert_eq!(before, after);
}

#[cfg(unix)]
#[test]
fn journal_path_hash_distinguishes_symlink_then_parent_alias() {
    use std::os::unix::fs::symlink;

    let temp = tempdir().expect("tempdir");
    let root = temp.path().join("root");
    let target_nested = temp.path().join("target").join("nested");
    fs::create_dir_all(&root).expect("root");
    fs::create_dir_all(&target_nested).expect("target nested");
    symlink(&target_nested, root.join("alias")).expect("alias symlink");

    let root_journal = root.join("events.jsonl");
    let aliased_parent_journal = root.join("alias").join("..").join("events.jsonl");
    fs::write(&root_journal, b"synthetic-root-journal\n").expect("root journal");
    fs::write(&aliased_parent_journal, b"synthetic-target-journal\n")
        .expect("aliased parent journal");

    assert_eq!(
        fs::read(&root_journal).expect("read root journal"),
        b"synthetic-root-journal\n"
    );
    assert_eq!(
        fs::read(&aliased_parent_journal).expect("read aliased parent journal"),
        b"synthetic-target-journal\n"
    );
    assert_ne!(
        journal_path_hash(&root_journal),
        journal_path_hash(&aliased_parent_journal)
    );
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

#[test]
fn stores_canonical_terminal_event_bytes_and_reuses_them_for_retry_and_dead_state() {
    let marker = "TT_PRIVACY_OUTBOX_26";
    let temp = tempdir().expect("temporary directory");
    let path = private_outbox_path(&temp);
    let event = marked_event(marker);
    let expected = canonical_bytes(&event);
    let expected_hash: [u8; 32] = Sha256::digest(&expected).into();

    let mut outbox = Outbox::open(&path).expect("open outbox");
    outbox
        .insert_event(&event, &["sink-a"])
        .expect("insert event");

    let stored = outbox
        .get_event(&event.event_id)
        .expect("get event")
        .expect("stored event");
    assert_eq!(stored.event_id, event.event_id);
    assert_eq!(stored.payload, expected);
    assert_eq!(stored.payload_hash, expected_hash);
    assert_payload_is_safe(&stored.payload, marker, "outbox-event-payload");

    record_delivery_for_test(
        &mut outbox,
        &event.event_id,
        "sink-a",
        DeliveryState::Pending,
        1,
        Some(1_700_000_000),
        Some(DeliveryErrorClass::HttpStatus { status: 503 }),
    )
    .expect("record retry state");
    let retry_payload = outbox
        .get_event(&event.event_id)
        .expect("get retry payload")
        .expect("retry event")
        .payload;
    assert_eq!(retry_payload, expected);
    assert_payload_is_safe(&retry_payload, marker, "outbox-retry-payload");

    record_delivery_for_test(
        &mut outbox,
        &event.event_id,
        "sink-a",
        DeliveryState::Dead,
        2,
        None,
        Some(DeliveryErrorClass::SinkApplicationRejected),
    )
    .expect("record dead state");
    let dead_payload = outbox
        .get_event(&event.event_id)
        .expect("get dead payload")
        .expect("dead event")
        .payload;
    assert_eq!(dead_payload, expected);
    assert_payload_is_safe(&dead_payload, marker, "outbox-dead-payload");
}

#[test]
fn release_blocked_for_sink_releases_matching_rows_without_resetting_history() {
    let temp = tempdir().expect("temporary directory");
    let path = private_outbox_path(&temp);
    let events = [
        marked_event("TT_RELEASE_BLOCKED_FIRST"),
        marked_event("TT_RELEASE_BLOCKED_SECOND"),
        marked_event("TT_RELEASE_PENDING"),
        marked_event("TT_RELEASE_ACKED"),
        marked_event("TT_RELEASE_DEAD"),
    ];
    let mut outbox = Outbox::open(&path).expect("open outbox");
    for event in &events {
        outbox
            .insert_event(event, &["sink-a", "sink-b"])
            .expect("insert event");
    }

    record_delivery_for_test(
        &mut outbox,
        &events[0].event_id,
        "sink-a",
        DeliveryState::Blocked,
        3,
        None,
        Some(DeliveryErrorClass::AuthenticationBlocked { status: 403 }),
    )
    .expect("record first blocked row");
    record_delivery_for_test(
        &mut outbox,
        &events[1].event_id,
        "sink-a",
        DeliveryState::Blocked,
        5,
        None,
        Some(DeliveryErrorClass::AuthenticationBlocked { status: 401 }),
    )
    .expect("record second blocked row");
    record_delivery_for_test(
        &mut outbox,
        &events[2].event_id,
        "sink-a",
        DeliveryState::Pending,
        2,
        Some(100),
        Some(DeliveryErrorClass::HttpStatus { status: 429 }),
    )
    .expect("record pending row");
    record_delivery_for_test(
        &mut outbox,
        &events[3].event_id,
        "sink-a",
        DeliveryState::Acked,
        4,
        None,
        None,
    )
    .expect("record acked row");
    record_delivery_for_test(
        &mut outbox,
        &events[4].event_id,
        "sink-a",
        DeliveryState::Dead,
        6,
        None,
        Some(DeliveryErrorClass::SinkApplicationRejected),
    )
    .expect("record dead row");
    record_delivery_for_test(
        &mut outbox,
        &events[0].event_id,
        "sink-b",
        DeliveryState::Blocked,
        7,
        None,
        Some(DeliveryErrorClass::AuthenticationBlocked { status: 403 }),
    )
    .expect("record other sink blocked row");

    let now = 1_700_000_123_456;
    assert_eq!(
        outbox
            .release_blocked_for_sink("sink-a", now)
            .expect("release blocked rows"),
        2
    );
    for (event, attempts, error_class) in [
        (
            &events[0],
            3,
            Some(DeliveryErrorClass::AuthenticationBlocked { status: 403 }),
        ),
        (
            &events[1],
            5,
            Some(DeliveryErrorClass::AuthenticationBlocked { status: 401 }),
        ),
    ] {
        let row = outbox
            .get_delivery(&event.event_id, "sink-a")
            .expect("released delivery lookup")
            .expect("released delivery row");
        assert_eq!(row.state, DeliveryState::Pending);
        assert_eq!(row.attempts, attempts);
        assert_eq!(row.next_attempt_at, Some(now));
        assert_eq!(row.last_error_class, error_class);
        assert_eq!(row.updated_at, now);
    }

    let pending = outbox
        .get_delivery(&events[2].event_id, "sink-a")
        .expect("pending delivery lookup")
        .expect("pending delivery row");
    assert_eq!(pending.state, DeliveryState::Pending);
    assert_eq!(pending.attempts, 2);
    assert_eq!(pending.next_attempt_at, Some(100));
    assert_eq!(
        pending.last_error_class,
        Some(DeliveryErrorClass::HttpStatus { status: 429 })
    );
    assert_eq!(
        outbox
            .get_delivery(&events[3].event_id, "sink-a")
            .expect("acked delivery lookup")
            .expect("acked delivery row")
            .state,
        DeliveryState::Acked
    );
    assert_eq!(
        outbox
            .get_delivery(&events[4].event_id, "sink-a")
            .expect("dead delivery lookup")
            .expect("dead delivery row")
            .state,
        DeliveryState::Dead
    );
    assert_eq!(
        outbox
            .get_delivery(&events[0].event_id, "sink-b")
            .expect("other sink delivery lookup")
            .expect("other sink delivery row")
            .state,
        DeliveryState::Blocked
    );
    assert_eq!(
        outbox
            .release_blocked_for_sink("sink-a", now)
            .expect("repeat release"),
        0
    );
    drop(outbox);

    let reopened = Outbox::open(&path).expect("reopen outbox");
    let row = reopened
        .get_delivery(&events[0].event_id, "sink-a")
        .expect("reopened delivery lookup")
        .expect("reopened delivery row");
    assert_eq!(row.state, DeliveryState::Pending);
    assert_eq!(row.attempts, 3);
    assert_eq!(row.next_attempt_at, Some(now));
    assert_eq!(
        row.last_error_class,
        Some(DeliveryErrorClass::AuthenticationBlocked { status: 403 })
    );
}

#[test]
fn duplicate_event_is_harmless_and_missing_sink_rows_are_added_without_resetting_state() {
    let temp = tempdir().expect("temporary directory");
    let path = private_outbox_path(&temp);
    let event = marked_event("TT_OUTBOX_DUPLICATE_26");
    let mut outbox = Outbox::open(&path).expect("open outbox");

    outbox
        .insert_event(&event, &["sink-a", "sink-b"])
        .expect("first insert");
    record_delivery_for_test(
        &mut outbox,
        &event.event_id,
        "sink-a",
        DeliveryState::Acked,
        1,
        None,
        None,
    )
    .expect("ack first sink");

    outbox
        .insert_event(&event, &["sink-a", "sink-b", "sink-c"])
        .expect("duplicate insert");

    assert_eq!(
        outbox
            .get_delivery(&event.event_id, "sink-a")
            .expect("get sink a")
            .expect("sink a row")
            .state,
        DeliveryState::Acked
    );
    assert_eq!(
        outbox
            .get_delivery(&event.event_id, "sink-b")
            .expect("get sink b")
            .expect("sink b row")
            .state,
        DeliveryState::Pending
    );
    assert_eq!(
        outbox
            .get_delivery(&event.event_id, "sink-c")
            .expect("get sink c")
            .expect("sink c row")
            .state,
        DeliveryState::Pending
    );
}

#[test]
fn same_event_id_with_different_canonical_bytes_fails_closed_as_payload_collision() {
    let temp = tempdir().expect("temporary directory");
    let path = private_outbox_path(&temp);
    let event = marked_event("TT_OUTBOX_COLLISION_A_26");
    let mut different = event.clone();
    different.evidence[0].redacted_value = "synthetic second payload".to_string();

    let mut outbox = Outbox::open(&path).expect("open outbox");
    outbox
        .insert_event(&event, &["sink-a"])
        .expect("first insert");
    let error = outbox
        .insert_event(&different, &["sink-b"])
        .expect_err("different bytes for one event ID must fail");
    let delivery = error
        .downcast_ref::<DeliveryError>()
        .expect("structured delivery error");
    assert_eq!(delivery.class, DeliveryErrorClass::PayloadCollision);
    assert!(
        outbox
            .get_delivery(&event.event_id, "sink-b")
            .expect("collision lookup")
            .is_none(),
        "collision must not create a delivery row"
    );
}

#[test]
fn sqlite_open_profile_is_explicit_and_schema_migrates_forward_only() {
    let temp = tempdir().expect("temporary directory");
    let path = private_outbox_path(&temp);
    let outbox = Outbox::open(&path).expect("open outbox");

    let foreign_keys: i64 = outbox
        .connection
        .pragma_query_value(None, "foreign_keys", |row| row.get(0))
        .expect("foreign_keys pragma");
    let busy_timeout: i64 = outbox
        .connection
        .pragma_query_value(None, "busy_timeout", |row| row.get(0))
        .expect("busy_timeout pragma");
    let journal_mode: String = outbox
        .connection
        .pragma_query_value(None, "journal_mode", |row| row.get(0))
        .expect("journal_mode pragma");
    let synchronous: i64 = outbox
        .connection
        .pragma_query_value(None, "synchronous", |row| row.get(0))
        .expect("synchronous pragma");
    assert_eq!(foreign_keys, 1);
    assert_eq!(
        busy_timeout,
        OUTBOX_OPEN_PROFILE.busy_timeout.as_millis() as i64
    );
    assert_eq!(
        journal_mode.to_ascii_lowercase(),
        OUTBOX_OPEN_PROFILE.journal_mode
    );
    assert_eq!(synchronous, 2, "SQLite FULL synchronous mode is 2");

    let namespace = outbox
        .meta_value("journal_namespace")
        .expect("journal namespace")
        .expect("namespace value");
    assert!(!namespace.is_empty());
    drop(outbox);

    let reopened = Outbox::open(&path).expect("reopen outbox");
    assert_eq!(
        reopened
            .meta_value("journal_namespace")
            .expect("namespace after reopen"),
        Some(namespace)
    );
    drop(reopened);

    let connection = Connection::open(&path).expect("raw connection");
    connection
        .execute(
            "UPDATE meta SET value = '999' WHERE key = 'schema_version'",
            [],
        )
        .expect("make newer schema");
    drop(connection);
    let error = Outbox::open(&path).expect_err("newer schema must not be downgraded");
    let delivery = error
        .downcast_ref::<DeliveryError>()
        .expect("structured schema error");
    assert_eq!(delivery.class, DeliveryErrorClass::DurableStorage);
    assert!(delivery.message.contains("newer"));
}

#[test]
fn migrates_v4_to_current_without_losing_replay_or_generation_state() {
    let temp = tempdir().expect("temporary directory");
    let path = temp.path().join("migration-v4").join("outbox.sqlite");
    create_private_parent(path.parent().expect("outbox parent"));
    let connection = Connection::open(&path).expect("legacy v4 database");
    create_legacy_base(&connection, 4);
    connection
        .execute_batch(
            "CREATE TABLE event_origins (
                     event_id TEXT NOT NULL,
                     generation_id TEXT NOT NULL,
                     byte_offset INTEGER NOT NULL,
                     PRIMARY KEY(event_id, generation_id, byte_offset)
                 );
                 CREATE TABLE journal_generations (
                     generation_id TEXT PRIMARY KEY NOT NULL,
                     journal_path_hash TEXT NOT NULL,
                     observed_at INTEGER NOT NULL
                 );",
        )
        .expect("create v4 generation tables");

    let pending = marked_event("TT_MIGRATE_V4_PENDING");
    let blocked = marked_event("TT_MIGRATE_V4_BLOCKED");
    let acked = marked_event("TT_MIGRATE_V4_ACKED");
    let dead = marked_event("TT_MIGRATE_V4_DEAD");
    for (event, created_at) in [
        (&pending, 101_i64),
        (&blocked, 102),
        (&acked, 103),
        (&dead, 104),
    ] {
        insert_legacy_event(&connection, event, created_at);
    }
    connection
        .execute(
            "INSERT INTO deliveries
                 (event_id, sink_id, state, attempt_count, next_attempt_at,
                  last_error_class, last_error_status, updated_at)
                 VALUES (?1, 'sink-a', 'pending', 2, 1_234,
                         'transport_no_response', NULL, 201),
                        (?2, 'sink-a', 'blocked', 3, NULL,
                         'authentication_blocked', 403, 202),
                        (?3, 'sink-a', 'acked', 4, NULL, NULL, NULL, 203),
                        (?4, 'sink-a', 'dead', 5, NULL,
                         'sink_application_rejected', NULL, 204)",
            params![
                pending.event_id,
                blocked.event_id,
                acked.event_id,
                dead.event_id
            ],
        )
        .expect("insert v4 delivery states");
    connection
        .execute(
            "INSERT INTO event_origins (event_id, generation_id, byte_offset)
                 VALUES (?1, 'legacy-generation-1', 0),
                        (?2, 'legacy-generation-2', 27)",
            params![pending.event_id, blocked.event_id],
        )
        .expect("insert v4 event origins");
    connection
        .execute(
            "INSERT INTO journal_generations
                 (generation_id, journal_path_hash, observed_at)
                 VALUES ('legacy-generation-1', ?1, 301),
                        ('legacy-generation-2', ?1, 302)",
            params!["a".repeat(64)],
        )
        .expect("insert v4 generation metadata");
    insert_legacy_cursor(&connection, "legacy-generation-2", 27);
    drop(connection);
    make_database_private(&path);

    let outbox = Outbox::open(&path).expect("migrate v4 outbox");
    assert_eq!(
        outbox.meta_value("schema_version").expect("schema version"),
        Some("6".to_string())
    );
    for (event, expected_state, expected_attempts, expected_next, expected_error) in [
        (
            &pending,
            DeliveryState::Pending,
            2,
            Some(1_234),
            Some(DeliveryErrorClass::TransportNoResponse),
        ),
        (
            &blocked,
            DeliveryState::Blocked,
            3,
            None,
            Some(DeliveryErrorClass::AuthenticationBlocked { status: 403 }),
        ),
        (&acked, DeliveryState::Acked, 4, None, None),
        (
            &dead,
            DeliveryState::Dead,
            5,
            None,
            Some(DeliveryErrorClass::SinkApplicationRejected),
        ),
    ] {
        let stored = outbox
            .get_event(&event.event_id)
            .expect("migrated event")
            .expect("event row");
        assert_eq!(stored.payload, canonical_bytes(event));
        let delivery = outbox
            .get_delivery(&event.event_id, "sink-a")
            .expect("migrated delivery")
            .expect("delivery row");
        assert_eq!(delivery.state, expected_state);
        assert_eq!(delivery.attempts, expected_attempts);
        assert_eq!(delivery.next_attempt_at, expected_next);
        assert_eq!(delivery.last_error_class, expected_error);
    }

    let cursor = outbox
        .ingest_cursor()
        .expect("migrated cursor")
        .expect("cursor row");
    assert_eq!(cursor.journal_namespace, "legacy-test-namespace");
    assert_eq!(cursor.journal_path_hash, "a".repeat(64));
    assert_eq!(cursor.generation_id, "legacy-generation-2");
    assert_eq!(cursor.byte_offset, 27);
    assert_eq!(cursor.observed_length, 27);
    assert_eq!(cursor.prefix_hash, [0x11_u8; 32]);
    assert_eq!(cursor.window_hash, [0x22_u8; 32]);

    let origins: Vec<(String, String, i64)> = outbox
        .connection
        .prepare(
            "SELECT event_id, generation_id, byte_offset
                 FROM event_origins ORDER BY generation_id, byte_offset",
        )
        .expect("origins query")
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .expect("origins rows")
        .collect::<Result<_, _>>()
        .expect("origins values");
    assert_eq!(origins.len(), 2);
    assert!(origins.iter().any(|(event_id, generation, offset)| {
        event_id == &pending.event_id && generation == "legacy-generation-1" && *offset == 0
    }));
    assert!(origins.iter().any(|(event_id, generation, offset)| {
        event_id == &blocked.event_id && generation == "legacy-generation-2" && *offset == 27
    }));

    let generations = read_generation_metadata(&outbox.connection).expect("generations");
    assert_eq!(generations.len(), 2);
    assert!(generations.iter().all(|generation| {
        generation.lifecycle == GenerationLifecycle::Present
            && generation.pruned_at.is_none()
            && generation.journal_path_hash == "a".repeat(64)
    }));
    assert!(table_exists(&outbox.connection, "sink_health"));
}

#[test]
fn migrates_v3_to_current_without_fabricating_origins() {
    let temp = tempdir().expect("temporary directory");
    let path = temp.path().join("migration-v3").join("outbox.sqlite");
    create_private_parent(path.parent().expect("outbox parent"));
    let connection = Connection::open(&path).expect("legacy v3 database");
    create_legacy_base(&connection, 3);
    let event = marked_event("TT_MIGRATE_V3_EVENT");
    insert_legacy_event(&connection, &event, 401);
    connection
        .execute(
            "INSERT INTO deliveries
                 (event_id, sink_id, state, attempt_count, next_attempt_at,
                  last_error_class, last_error_status, updated_at)
                 VALUES (?1, 'sink-a', 'pending', 7, 4_321,
                         'http_status', 429, 402)",
            params![event.event_id],
        )
        .expect("insert v3 delivery");
    insert_legacy_cursor(&connection, "legacy-generation-v3", 19);
    drop(connection);
    make_database_private(&path);

    let outbox = Outbox::open(&path).expect("migrate v3 outbox");
    assert_eq!(
        outbox.meta_value("schema_version").expect("schema version"),
        Some("6".to_string())
    );
    assert_eq!(
        outbox
            .get_event(&event.event_id)
            .expect("event lookup")
            .expect("event row")
            .payload,
        canonical_bytes(&event)
    );
    let delivery = outbox
        .get_delivery(&event.event_id, "sink-a")
        .expect("delivery lookup")
        .expect("delivery row");
    assert_eq!(delivery.state, DeliveryState::Pending);
    assert_eq!(delivery.attempts, 7);
    assert_eq!(delivery.next_attempt_at, Some(4_321));
    assert_eq!(
        delivery.last_error_class,
        Some(DeliveryErrorClass::HttpStatus { status: 429 })
    );
    let cursor = outbox
        .ingest_cursor()
        .expect("cursor lookup")
        .expect("cursor row");
    assert_eq!(cursor.generation_id, "legacy-generation-v3");
    assert_eq!(cursor.byte_offset, 19);
    assert!(table_exists(&outbox.connection, "event_origins"));
    assert!(table_exists(&outbox.connection, "journal_generations"));
    assert!(table_exists(&outbox.connection, "sink_health"));
    assert!(
        read_generation_metadata(&outbox.connection)
            .expect("generation metadata")
            .is_empty()
    );
    let origin_count: i64 = outbox
        .connection
        .query_row("SELECT COUNT(*) FROM event_origins", [], |row| row.get(0))
        .expect("origin count");
    assert_eq!(
        origin_count, 0,
        "v3 migration must not invent event origins"
    );
}

#[cfg(unix)]
#[test]
fn outbox_parent_and_database_are_private() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let temp = tempdir().expect("temporary directory");
    let path = private_outbox_path(&temp);
    let _outbox = Outbox::open(&path).expect("open outbox");
    let parent_mode = fs::metadata(path.parent().expect("outbox parent"))
        .expect("parent metadata")
        .permissions()
        .mode()
        & 0o777;
    let database = fs::metadata(&path).expect("database metadata");
    assert_eq!(parent_mode, 0o700);
    assert_eq!(database.permissions().mode() & 0o777, 0o600);
    assert_eq!(database.nlink(), 1);
}

#[cfg(unix)]
#[test]
fn unsafe_outbox_database_is_rejected_without_changing_target() {
    use std::os::unix::fs::{PermissionsExt, symlink};

    for case in ["symlink", "hardlink", "broad-mode"] {
        let temp = tempdir().expect("temporary directory");
        let path = private_outbox_path(&temp);
        let target = path.with_file_name("synthetic-target");
        fs::write(&target, b"synthetic database bytes").expect("target");
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).expect("private target");
        let expected = match case {
            "symlink" => {
                symlink(&target, &path).expect("symlink");
                "outbox database is not a regular file"
            }
            "hardlink" => {
                fs::hard_link(&target, &path).expect("hardlink");
                "outbox database hard links are not allowed"
            }
            _ => {
                fs::rename(&target, &path).expect("database");
                fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).expect("broad mode");
                "outbox database permissions are too broad"
            }
        };

        let error = Outbox::open(&path).expect_err("unsafe database");
        let delivery = error
            .downcast_ref::<DeliveryError>()
            .expect("storage error");
        assert_eq!(delivery.class, DeliveryErrorClass::DurableStorage, "{case}");
        assert!(delivery.message.contains(expected), "{case}: {delivery:?}");
        assert_eq!(
            fs::read(&path).unwrap(),
            b"synthetic database bytes",
            "{case}"
        );
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o7777,
            if case == "broad-mode" { 0o640 } else { 0o600 },
            "{case}"
        );
    }
}

#[cfg(unix)]
#[test]
fn broad_outbox_parent_permissions_are_rejected() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempdir().expect("temporary directory");
    let parent = temp.path().join("broad-outbox");
    fs::create_dir(&parent).expect("parent");
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o755)).expect("permissions");
    let error =
        Outbox::open(parent.join("outbox.sqlite")).expect_err("broad parent must be rejected");
    let delivery = error
        .downcast_ref::<DeliveryError>()
        .expect("structured permissions error");
    assert_eq!(delivery.class, DeliveryErrorClass::DurableStorage);
    assert!(!delivery.message.contains("TT_PRIVACY"));
}

#[test]
fn corrupt_outbox_is_a_bounded_durable_storage_error() {
    let temp = tempdir().expect("temporary directory");
    let path = private_outbox_path(&temp);
    fs::write(&path, b"synthetic-not-a-sqlite-database").expect("corrupt database");
    make_database_private(&path);

    let error = Outbox::open(&path).expect_err("corrupt database must fail closed");
    let delivery = error
        .downcast_ref::<DeliveryError>()
        .expect("structured corrupt database error");
    assert_eq!(delivery.class, DeliveryErrorClass::DurableStorage);
    assert!(delivery.message.len() <= 200);
    assert!(!delivery.message.contains("TT_PRIVACY"));
}

#[test]
fn locked_outbox_fails_closed_without_losing_an_accepted_event() {
    use std::time::{Duration, Instant};

    let temp = tempdir().expect("temporary directory");
    let path = private_outbox_path(&temp);
    let accepted = marked_event("TT_OUTBOX_LOCK_ACCEPTED_26");
    let blocked = marked_event("TT_OUTBOX_LOCK_BLOCKED_26");
    let mut holder = Outbox::open(&path).expect("open holding outbox");
    holder
        .insert_event(&accepted, &["sink-a"])
        .expect("accepted event");
    let mut contender = Outbox::open(&path).expect("open second outbox");
    contender
        .connection
        .busy_timeout(Duration::from_millis(25))
        .expect("bounded contender busy timeout");

    holder
        .connection
        .execute_batch("BEGIN EXCLUSIVE")
        .expect("hold an exclusive lock");
    let started = Instant::now();
    let error = contender
        .insert_event(&blocked, &["sink-a"])
        .expect_err("locked outbox must reject the new event");
    let elapsed = started.elapsed();
    holder
        .connection
        .execute_batch("ROLLBACK")
        .expect("release exclusive lock");

    let delivery = error
        .downcast_ref::<DeliveryError>()
        .expect("structured lock error");
    assert_eq!(delivery.class, DeliveryErrorClass::DurableStorage);
    assert!(
        elapsed < Duration::from_secs(1),
        "lock failure was not bounded"
    );
    assert!(delivery.message.len() <= 200);
    assert!(!delivery.message.contains("TT_OUTBOX_LOCK"));
    assert!(
        holder
            .get_event(&accepted.event_id)
            .expect("accepted event lookup")
            .is_some()
    );
    assert!(
        contender
            .get_event(&blocked.event_id)
            .expect("blocked event lookup")
            .is_none()
    );
}

#[test]
fn full_outbox_fails_closed_without_deleting_accepted_rows() {
    let temp = tempdir().expect("temporary directory");
    let path = private_outbox_path(&temp);
    let accepted = marked_event("TT_OUTBOX_FULL_ACCEPTED_26");
    let mut blocked = marked_event("TT_OUTBOX_FULL_BLOCKED_26");
    blocked.evidence = (0..1_200)
        .map(|index| Evidence {
            field: "tool_result".to_string(),
            redacted_value: format!(
                "synthetic-full-storage-payload-{index:04}-{}",
                "x".repeat(480)
            ),
            hash: None,
            rule_id: None,
        })
        .collect();

    let mut outbox = Outbox::open(&path).expect("open outbox");
    outbox
        .insert_event(&accepted, &["sink-a"])
        .expect("accepted event");
    let page_count: i64 = outbox
        .connection
        .pragma_query_value(None, "page_count", |row| row.get(0))
        .expect("page count");
    let configured_max: i64 = outbox
        .connection
        .pragma_query_value(None, "max_page_count", |row| row.get(0))
        .expect("maximum page count");
    assert!(configured_max > page_count);
    outbox
        .connection
        .pragma_update(None, "max_page_count", page_count)
        .expect("set deterministic storage limit");

    let error = outbox
        .insert_event(&blocked, &["sink-a"])
        .expect_err("storage limit must reject the new event");
    let delivery = error
        .downcast_ref::<DeliveryError>()
        .expect("structured full-storage error");
    assert_eq!(delivery.class, DeliveryErrorClass::DurableStorage);
    assert!(
        delivery.message.contains("full"),
        "storage limit must report SQLite full, not a renamed error: {}",
        delivery.message
    );
    assert!(delivery.message.len() <= 200);
    assert!(!delivery.message.contains("TT_OUTBOX_FULL"));
    assert!(
        outbox
            .get_event(&accepted.event_id)
            .expect("accepted event lookup")
            .is_some()
    );
    assert_eq!(
        outbox
            .get_delivery(&accepted.event_id, "sink-a")
            .expect("accepted delivery lookup")
            .expect("accepted delivery row")
            .state,
        DeliveryState::Pending
    );
    assert!(
        outbox
            .get_event(&blocked.event_id)
            .expect("blocked event lookup")
            .is_none()
    );
}

#[test]
fn capacity_accepts_exact_event_limit_but_rejects_the_next_event() {
    let temp = tempdir().expect("temporary directory");
    let log_path = temp.path().join("events.jsonl");
    let outbox_path = private_outbox_path(&temp);
    let first = marked_event("TT_CAPACITY_EVENT_FIRST_26");
    let second = marked_event("TT_CAPACITY_EVENT_SECOND_26");
    let first_batch =
        event3_durable_batch(std::slice::from_ref(&first)).expect("first canonical batch");
    let both_batch = event3_durable_batch(&[first, second]).expect("two canonical events");
    let outbox = Outbox::open(&outbox_path).expect("open outbox");

    outbox
        .check_capacity_for_payloads(
            &log_path,
            &first_batch.payloads,
            capacity_limits(1, first_batch.payloads[0].bytes.len() as u64),
        )
        .expect("exact event capacity is accepted");
    let error = outbox
        .check_capacity_for_payloads(
            &log_path,
            &both_batch.payloads,
            capacity_limits(1, u64::MAX),
        )
        .expect_err("the next unique event exceeds event capacity");
    assert!(error.to_string().contains("limit_kind=pending_events"));
}

#[test]
fn capacity_accepts_exact_canonical_byte_boundary_but_rejects_the_next_byte() {
    let temp = tempdir().expect("temporary directory");
    let log_path = temp.path().join("events.jsonl");
    let outbox_path = private_outbox_path(&temp);
    let first = marked_event("TT_CAPACITY_BYTES_FIRST_26");
    let second = marked_event("TT_CAPACITY_BYTES_SECOND_26");
    let batch = event3_durable_batch(&[first, second]).expect("canonical batch");
    let bytes = batch
        .payloads
        .iter()
        .map(|payload| payload.bytes.len() as u64)
        .sum::<u64>();
    let outbox = Outbox::open(&outbox_path).expect("open outbox");

    outbox
        .check_capacity_for_payloads(&log_path, &batch.payloads, capacity_limits(2, bytes))
        .expect("exact canonical byte boundary is accepted");
    let error = outbox
        .check_capacity_for_payloads(&log_path, &batch.payloads, capacity_limits(2, bytes - 1))
        .expect_err("one byte below the canonical boundary is rejected");
    assert!(error.to_string().contains("limit_kind=pending_bytes"));
}

#[test]
fn pending_and_blocked_count_but_acked_and_dead_release_capacity() {
    let temp = tempdir().expect("temporary directory");
    let log_path = temp.path().join("events.jsonl");
    let outbox_path = private_outbox_path(&temp);
    let first = marked_event("TT_CAPACITY_PENDING_26");
    let second = marked_event("TT_CAPACITY_BLOCKED_26");
    let third = marked_event("TT_CAPACITY_ACKED_26");
    let fourth = marked_event("TT_CAPACITY_DEAD_26");
    let fifth = marked_event("TT_CAPACITY_RELEASED_26");
    append_jsonl_events(
        &log_path,
        &[first.clone(), second.clone(), third.clone(), fourth.clone()],
    )
    .expect("canonical JSONL");
    let mut outbox = Outbox::open(&outbox_path).expect("open outbox");
    outbox
        .reconcile_jsonl(&log_path, &["sink-a"])
        .expect("ingest events");
    record_delivery_for_test(
        &mut outbox,
        &second.event_id,
        "sink-a",
        DeliveryState::Blocked,
        1,
        None,
        None,
    )
    .expect("blocked state");
    record_delivery_for_test(
        &mut outbox,
        &third.event_id,
        "sink-a",
        DeliveryState::Acked,
        1,
        None,
        None,
    )
    .expect("acked state");
    record_delivery_for_test(
        &mut outbox,
        &fourth.event_id,
        "sink-a",
        DeliveryState::Dead,
        1,
        None,
        None,
    )
    .expect("dead state");
    let batch = event3_durable_batch(std::slice::from_ref(&fifth)).expect("prospective event");
    outbox
        .check_capacity_for_payloads(&log_path, &batch.payloads, capacity_limits(3, u64::MAX))
        .expect("pending and blocked plus one prospective event fit");
}

#[test]
fn multi_sink_event_counts_once_for_capacity() {
    let temp = tempdir().expect("temporary directory");
    let log_path = temp.path().join("events.jsonl");
    let outbox_path = private_outbox_path(&temp);
    let existing = marked_event("TT_CAPACITY_MULTI_EXISTING_26");
    let prospective = marked_event("TT_CAPACITY_MULTI_PROSPECTIVE_26");
    append_jsonl_events(&log_path, std::slice::from_ref(&existing)).expect("canonical JSONL");
    let mut outbox = Outbox::open(&outbox_path).expect("open outbox");
    outbox
        .reconcile_jsonl(&log_path, &["sink-a", "sink-b"])
        .expect("ingest multi-sink event");
    let batch =
        event3_durable_batch(std::slice::from_ref(&prospective)).expect("prospective event");
    outbox
        .check_capacity_for_payloads(&log_path, &batch.payloads, capacity_limits(2, u64::MAX))
        .expect("one event per sink is counted once");
}

#[test]
fn unread_jsonl_counts_with_empty_sqlite_and_after_reopen() {
    let temp = tempdir().expect("temporary directory");
    let log_path = temp.path().join("events.jsonl");
    let outbox_path = private_outbox_path(&temp);
    let first = marked_event("TT_CAPACITY_UNREAD_FIRST_26");
    let second = marked_event("TT_CAPACITY_UNREAD_SECOND_26");
    append_jsonl_events(&log_path, &[first, second]).expect("committed JSONL");
    let batch = event3_durable_batch(&[marked_event("TT_CAPACITY_UNREAD_NEXT_26")])
        .expect("prospective event");
    let bytes = fs::read_to_string(&log_path)
        .expect("JSONL")
        .lines()
        .map(|line| line.len() as u64)
        .sum::<u64>();

    let outbox = Outbox::open(&outbox_path).expect("open empty outbox");
    let error = outbox
        .check_capacity_for_payloads(
            &log_path,
            &batch.payloads,
            capacity_limits(2, bytes + 1_000),
        )
        .expect_err("unread events plus prospective event exceed count");
    assert!(error.to_string().contains("limit_kind=pending_events"));
    drop(outbox);

    let reopened = Outbox::open(&outbox_path).expect("reopen empty outbox");
    reopened
        .check_capacity_for_payloads(
            &log_path,
            &batch.payloads,
            capacity_limits(3, bytes + batch.payloads[0].bytes.len() as u64),
        )
        .expect("unread capacity is counted after reopen");
}

#[test]
fn already_represented_unread_event_is_not_counted_twice() {
    let temp = tempdir().expect("temporary directory");
    let log_path = temp.path().join("events.jsonl");
    let outbox_path = private_outbox_path(&temp);
    let existing = marked_event("TT_CAPACITY_REPRESENTED_26");
    let next = marked_event("TT_CAPACITY_REPRESENTED_NEXT_26");
    append_jsonl_events(&log_path, std::slice::from_ref(&existing)).expect("first JSONL");
    let mut outbox = Outbox::open(&outbox_path).expect("open outbox");
    outbox
        .reconcile_jsonl(&log_path, &["sink-a"])
        .expect("represent first event");
    append_jsonl_events(&log_path, std::slice::from_ref(&existing)).expect("duplicate JSONL");
    let duplicate =
        event3_durable_batch(std::slice::from_ref(&existing)).expect("duplicate payload");
    outbox
        .check_capacity_for_payloads(
            &log_path,
            &duplicate.payloads,
            capacity_limits(1, duplicate.payloads[0].bytes.len() as u64),
        )
        .expect("represented duplicate does not consume capacity");
    let next_batch = event3_durable_batch(std::slice::from_ref(&next)).expect("next payload");
    let error = outbox
        .check_capacity_for_payloads(
            &log_path,
            &next_batch.payloads,
            capacity_limits(1, u64::MAX),
        )
        .expect_err("the next unique event exceeds the one-event limit");
    assert!(error.to_string().contains("limit_kind=pending_events"));
}

#[test]
fn unread_same_id_with_different_bytes_fails_closed() {
    let temp = tempdir().expect("temporary directory");
    let log_path = temp.path().join("events.jsonl");
    let outbox_path = private_outbox_path(&temp);
    let first = marked_event("TT_CAPACITY_COLLISION_FIRST_26");
    let mut different = first.clone();
    different.evidence[0].redacted_value = "safe-different-canonical-payload".to_string();
    append_jsonl_events(&log_path, &[first, different]).expect("collision JSONL");
    let outbox = Outbox::open(&outbox_path).expect("open outbox");
    let error = outbox
        .check_capacity_for_payloads(&log_path, &[], capacity_limits(10, u64::MAX))
        .expect_err("same ID with different bytes must fail closed");
    let delivery = error
        .downcast_ref::<DeliveryError>()
        .expect("structured collision error");
    assert_eq!(delivery.class, DeliveryErrorClass::PayloadCollision);
    assert!(!delivery.message.contains("TT_CAPACITY_COLLISION"));
}

#[test]
fn recovery_reconcile_is_not_gated_by_current_capacity_limits() {
    let temp = tempdir().expect("temporary directory");
    let log_path = temp.path().join("events.jsonl");
    let outbox_path = private_outbox_path(&temp);
    let first = marked_event("TT_CAPACITY_RECOVERY_FIRST_26");
    let second = marked_event("TT_CAPACITY_RECOVERY_SECOND_26");
    append_jsonl_events(&log_path, &[first, second]).expect("committed JSONL");
    let mut outbox = Outbox::open(&outbox_path).expect("open outbox");
    let prospective = marked_event("TT_CAPACITY_RECOVERY_PROSPECTIVE_26");
    let batch = event3_durable_batch(std::slice::from_ref(&prospective))
        .expect("prospective recovery event");
    let error = outbox
        .check_capacity_for_payloads(&log_path, &batch.payloads, capacity_limits(1, u64::MAX))
        .expect_err("existing unread queue is above the current limit");
    assert!(error.to_string().contains("pending_events"));
    outbox
        .reconcile_jsonl(&log_path, &["sink-a"])
        .expect("recovery reconciliation remains available");
}

#[test]
fn restart_reconciles_jsonl_after_the_fsync_before_ingest_gap() {
    let temp = tempdir().expect("temporary directory");
    let log_path = temp.path().join("events.jsonl");
    let outbox_path = private_outbox_path(&temp);
    let event = marked_event("TT_OUTBOX_CRASH_GAP_FSYNC_26");

    LocalJsonlSink::with_rotation(&log_path, crate::sink::RotationConfig::disabled())
        .emit(std::slice::from_ref(&event))
        .expect("canonical JSONL fsync");
    let outbox = Outbox::open(&outbox_path).expect("open before crash");
    assert!(
        outbox
            .get_event(&event.event_id)
            .expect("before crash")
            .is_none()
    );
    drop(outbox);

    let mut restarted = Outbox::open(&outbox_path).expect("restart outbox");
    restarted
        .reconcile_jsonl(&log_path, &["sink-a"])
        .expect("reconcile after restart");

    let stored = restarted
        .get_event(&event.event_id)
        .expect("stored event")
        .expect("event recovered from JSONL");
    assert_payload_is_safe(
        &stored.payload,
        "TT_OUTBOX_CRASH_GAP_FSYNC_26",
        "outbox-restart-recovery",
    );
    assert_eq!(
        restarted
            .get_delivery(&event.event_id, "sink-a")
            .expect("delivery row")
            .expect("pending delivery")
            .state,
        DeliveryState::Pending
    );
}

#[test]
fn restart_replays_ingested_pending_rows_before_any_send_attempt() {
    let temp = tempdir().expect("temporary directory");
    let log_path = temp.path().join("events.jsonl");
    let outbox_path = private_outbox_path(&temp);
    let event = marked_event("TT_OUTBOX_CRASH_GAP_INGEST_26");
    append_jsonl_events(&log_path, std::slice::from_ref(&event)).expect("canonical JSONL");

    let mut outbox = Outbox::open(&outbox_path).expect("open outbox");
    outbox
        .reconcile_jsonl(&log_path, &["sink-a"])
        .expect("ingest transaction");
    drop(outbox);

    let restarted = Outbox::open(&outbox_path).expect("restart outbox");
    let delivery = restarted
        .get_delivery(&event.event_id, "sink-a")
        .expect("delivery lookup")
        .expect("pending delivery survives restart");
    assert_eq!(delivery.state, DeliveryState::Pending);
    assert_eq!(delivery.attempts, 0);
    assert_eq!(delivery.next_attempt_at, None);
}

#[test]
fn reconcile_leaves_partial_trailing_record_until_the_line_is_complete() {
    let temp = tempdir().expect("temporary directory");
    let log_path = temp.path().join("events.jsonl");
    let outbox_path = private_outbox_path(&temp);
    let first = marked_event("TT_OUTBOX_PARTIAL_FIRST_26");
    let second = marked_event("TT_OUTBOX_PARTIAL_SECOND_26");
    append_jsonl_events(&log_path, std::slice::from_ref(&first)).expect("first JSONL event");

    let mut outbox = Outbox::open(&outbox_path).expect("open outbox");
    outbox
        .reconcile_jsonl(&log_path, &["sink-a"])
        .expect("initial ingest");
    let cursor_before = outbox.ingest_cursor().expect("cursor").expect("cursor row");

    let second_bytes = canonical_bytes(&second);
    let split = second_bytes.len() / 2;
    let mut log = fs::OpenOptions::new()
        .append(true)
        .open(&log_path)
        .expect("open JSONL for partial append");
    std::io::Write::write_all(&mut log, &second_bytes[..split]).expect("append partial line");
    drop(log);

    let partial = outbox
        .reconcile_jsonl(&log_path, &["sink-a"])
        .expect("partial tail is deferred");
    assert_eq!(partial.ingested_events, 0);
    assert_eq!(
        outbox.ingest_cursor().expect("cursor after partial"),
        Some(cursor_before)
    );
    assert!(
        outbox
            .get_event(&second.event_id)
            .expect("partial event lookup")
            .is_none()
    );

    let mut log = fs::OpenOptions::new()
        .append(true)
        .open(&log_path)
        .expect("reopen JSONL");
    std::io::Write::write_all(&mut log, &second_bytes[split..]).expect("complete partial line");
    std::io::Write::write_all(&mut log, b"\n").expect("terminate JSONL line");
    drop(log);

    let completed = outbox
        .reconcile_jsonl(&log_path, &["sink-a"])
        .expect("completed tail ingest");
    assert_eq!(completed.ingested_events, 1);
    assert!(
        outbox
            .get_event(&second.event_id)
            .expect("completed event lookup")
            .is_some()
    );
    assert_eq!(
        outbox
            .get_delivery(&second.event_id, "sink-a")
            .expect("completed delivery lookup")
            .expect("completed pending delivery")
            .state,
        DeliveryState::Pending
    );
}

#[test]
fn malformed_non_tail_jsonl_does_not_commit_prior_events_or_cursor() {
    let temp = tempdir().expect("temporary directory");
    let log_path = temp.path().join("events.jsonl");
    let outbox_path = private_outbox_path(&temp);
    let event = marked_event("TT_OUTBOX_MALFORMED_NON_TAIL_26");
    let mut bytes = canonical_bytes(&event);
    bytes.extend_from_slice(b"\n{\"not_an_event\":true}\n");
    fs::write(&log_path, bytes).expect("malformed JSONL fixture");

    let mut outbox = Outbox::open(&outbox_path).expect("open outbox");
    let error = outbox
        .reconcile_jsonl(&log_path, &["sink-a"])
        .expect_err("malformed non-tail record must fail closed");
    let delivery = error
        .downcast_ref::<DeliveryError>()
        .expect("structured ingest error");
    assert_eq!(delivery.class, DeliveryErrorClass::DurableStorage);
    assert!(
        outbox
            .get_event(&event.event_id)
            .expect("event lookup")
            .is_none()
    );
    assert!(outbox.ingest_cursor().expect("cursor lookup").is_none());
}

#[test]
fn cursor_rejects_replacement_truncation_and_unsafe_advancement() {
    let temp = tempdir().expect("temporary directory");
    let log_path = temp.path().join("events.jsonl");
    let outbox_path = private_outbox_path(&temp);
    let event = marked_event("TT_OUTBOX_CURSOR_INTEGRITY_26");
    append_jsonl_events(&log_path, std::slice::from_ref(&event)).expect("canonical JSONL");

    let mut outbox = Outbox::open(&outbox_path).expect("open outbox");
    outbox
        .reconcile_jsonl(&log_path, &["sink-a"])
        .expect("initial ingest");
    let cursor = outbox.ingest_cursor().expect("cursor").expect("cursor row");
    assert_eq!(
        cursor.byte_offset as usize,
        fs::read(&log_path).expect("log").len()
    );

    let replacement = temp.path().join("replacement.jsonl");
    fs::write(&replacement, fs::read(&log_path).expect("original log")).expect("replacement");
    fs::remove_file(&log_path).expect("remove active log");
    fs::rename(&replacement, &log_path).expect("replace active log");
    let error = outbox
        .reconcile_jsonl(&log_path, &["sink-a"])
        .expect_err("replacement must fail closed");
    assert!(error.to_string().contains("generation"));

    // Restore the original bytes through a new outbox so the truncation
    // and cursor-boundary checks each exercise the persisted cursor.
    let second_path = named_private_outbox_path(&temp, "second-outbox");
    let original = canonical_bytes(&event);
    fs::write(
        &log_path,
        format!("{}\n", String::from_utf8(original).expect("UTF-8")),
    )
    .expect("restore log");
    let mut second = Outbox::open(&second_path).expect("second outbox");
    second
        .reconcile_jsonl(&log_path, &["sink-a"])
        .expect("second initial ingest");
    let mut truncated = fs::read(&log_path).expect("read restored log");
    truncated.truncate(truncated.len().saturating_sub(1));
    fs::write(&log_path, truncated).expect("truncate log");
    let error = second
        .reconcile_jsonl(&log_path, &["sink-a"])
        .expect_err("truncation must fail closed");
    assert!(error.to_string().contains("truncat"));

    let unsafe_path = named_private_outbox_path(&temp, "unsafe-cursor");
    let log_path = temp.path().join("unsafe-events.jsonl");
    append_jsonl_events(&log_path, std::slice::from_ref(&event)).expect("unsafe log");
    let mut unsafe_outbox = Outbox::open(&unsafe_path).expect("unsafe outbox");
    unsafe_outbox
        .reconcile_jsonl(&log_path, &["sink-a"])
        .expect("unsafe cursor initial ingest");
    let cursor = unsafe_outbox
        .ingest_cursor()
        .expect("unsafe cursor lookup")
        .expect("unsafe cursor row");
    assert!(cursor.byte_offset > 1);
    unsafe_outbox
        .connection
        .execute("UPDATE ingest_cursor SET byte_offset = 1 WHERE id = 1", [])
        .expect("unsafe cursor fixture");
    let error = unsafe_outbox
        .reconcile_jsonl(&log_path, &["sink-a"])
        .expect_err("cursor in the middle of a line must fail closed");
    assert!(error.to_string().contains("line boundary"));
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

#[test]
fn unread_rotated_generation_is_retained_before_reconciliation() {
    let (_temp, log_path, outbox_path, _first, _second, rotated) = prepare_rotated_journal();
    let mut outbox = Outbox::open(&outbox_path).expect("reopen outbox");
    let report = outbox.prune_eligible_rotations(&log_path, 0);
    assert!(rotated.exists(), "unread rotated bytes must be retained");
    assert!(report.pruned == 0);
    assert!(
        !report.warnings.is_empty(),
        "unregistered identity is fail-safe"
    );
}

#[test]
fn current_cursor_generation_is_protected_even_when_fully_consumed() {
    // The first event is reconciled while it is still active. The second
    // write then renames that file to A and creates active B without
    // reconciling B. The persisted cursor must follow A by filesystem
    // identity, not by the discovery filename.
    let (_temp, log_path, outbox_path, first, _second, rotated) = prepare_rotated_journal();
    let mut outbox = Outbox::open(&outbox_path).expect("reopen outbox");
    let generations = discover_jsonl_generations(&log_path).expect("discover generations");
    let rotated_generation = generations
        .iter()
        .find(|generation| generation.path == rotated)
        .expect("rotated generation");
    let active = generations
        .iter()
        .find(|generation| generation.is_active)
        .expect("active generation");
    let cursor = outbox
        .ingest_cursor()
        .expect("cursor after rotation")
        .expect("cursor established while A was active");
    let rotated_length = fs::metadata(&rotated).expect("rotated metadata").len();
    assert_eq!(cursor.generation_id, rotated_generation.identity);
    assert_eq!(cursor.byte_offset, rotated_length);
    assert_eq!(cursor.observed_length, rotated_length);
    assert_eq!(cursor.byte_offset, canonical_bytes(&first).len() as u64 + 1);

    // Register the newly discovered active generation without reconciling
    // its bytes. This is the metadata state a rotation restart must be
    // able to validate before deciding whether A is still protected.
    install_generation_state(&mut outbox, &log_path, &generations, None)
        .expect("register rotated and active generations");
    let report = outbox.prune_eligible_rotations(&log_path, 0);
    assert_eq!(report.pruned, 0);
    assert!(rotated.exists(), "the cursor generation remains protected");
    assert_eq!(
        generation_lifecycle(&outbox, &rotated_generation.identity),
        GenerationLifecycle::Present
    );
    assert!(active.path.exists(), "active generation remains present");
}

#[test]
fn older_unread_generation_is_protected_when_cursor_points_to_a_newer_generation() {
    let temp = tempdir().expect("tempdir");
    let log_path = temp.path().join("events.jsonl");
    let outbox_path = private_outbox_path(&temp);
    let older = marked_event("TT_ROTATION_OLDER_UNREAD");
    let active = marked_event("TT_ROTATION_NEWER_ACTIVE");
    let older_path = temp.path().join("events-2020-01-01.jsonl");
    fs::write(
        &older_path,
        [canonical_bytes(&older).as_slice(), b"\n{\"partial\""].concat(),
    )
    .expect("write partial older generation");
    let active_bytes = [canonical_bytes(&active).as_slice(), b"\n"].concat();
    fs::write(&log_path, &active_bytes).expect("write active generation");

    let generations = discover_jsonl_generations(&log_path).expect("discover generations");
    let active_generation = generations
        .iter()
        .find(|generation| generation.is_active)
        .expect("active generation");
    let mut outbox = Outbox::open(&outbox_path).expect("open outbox");
    install_generation_state(
        &mut outbox,
        &log_path,
        &generations,
        Some((active_generation, active_bytes.len())),
    )
    .expect("install generation metadata and newer cursor");

    let report = outbox.prune_eligible_rotations(&log_path, 0);
    assert_eq!(report.pruned, 0);
    assert_eq!(report.protected, 1);
    assert!(older_path.exists(), "unread older bytes must remain");
    assert_eq!(
        generation_lifecycle(
            &outbox,
            &generations
                .iter()
                .find(|generation| !generation.is_active)
                .expect("older generation")
                .identity,
        ),
        GenerationLifecycle::Present
    );
}

#[test]
fn newest_rotated_keep_window_is_retained_after_older_consumed_generation_is_pruned() {
    let temp = tempdir().expect("tempdir");
    let log_path = temp.path().join("events.jsonl");
    let outbox_path = private_outbox_path(&temp);
    let first = marked_event("TT_ROTATION_KEEP_OLDEST");
    let second = marked_event("TT_ROTATION_KEEP_NEWEST");
    let third = marked_event("TT_ROTATION_KEEP_ACTIVE");
    let first_path = temp.path().join("events-2020-01-01.jsonl");
    let second_path = temp.path().join("events-2020-01-02.jsonl");
    fs::write(
        &first_path,
        [canonical_bytes(&first).as_slice(), b"\n"].concat(),
    )
    .expect("oldest generation");
    fs::write(
        &second_path,
        [canonical_bytes(&second).as_slice(), b"\n"].concat(),
    )
    .expect("newest rotated generation");
    let active_bytes = [canonical_bytes(&third).as_slice(), b"\n"].concat();
    fs::write(&log_path, &active_bytes).expect("active generation");

    let generations = discover_jsonl_generations(&log_path).expect("discover generations");
    let mut outbox = Outbox::open(&outbox_path).expect("open outbox");
    outbox
        .reconcile_jsonl(&log_path, &["sink-a"])
        .expect("consume every generation");
    let report = outbox.prune_eligible_rotations(&log_path, 1);
    assert_eq!(report.pruned, 1);
    assert!(!first_path.exists(), "oldest consumed generation is pruned");
    assert!(
        second_path.exists(),
        "newest rotated keep window is retained"
    );
    assert!(log_path.exists(), "active generation is retained");
    assert_eq!(
        generation_lifecycle(
            &outbox,
            &generations
                .iter()
                .find(|generation| generation.path == first_path)
                .expect("oldest generation")
                .identity,
        ),
        GenerationLifecycle::Pruned
    );
}

#[test]
fn fully_ingested_generation_prunes_without_downstream_ack_and_keeps_active() {
    let (_temp, log_path, outbox_path, first, second, rotated) = prepare_rotated_journal();
    let mut outbox = Outbox::open(&outbox_path).expect("reopen outbox");
    outbox
        .reconcile_jsonl(&log_path, &["sink-a"])
        .expect("ingest rotated and active generations");
    record_delivery_for_test(
        &mut outbox,
        &first.event_id,
        "sink-a",
        DeliveryState::Blocked,
        1,
        None,
        Some(DeliveryErrorClass::AuthenticationBlocked { status: 403 }),
    )
    .expect("block first delivery");
    let report = outbox.prune_eligible_rotations(&log_path, 0);
    assert_eq!(report.pruned, 1);
    assert!(
        !rotated.exists(),
        "fully ingested generation should be pruned"
    );
    assert!(log_path.exists(), "active generation must be retained");
    assert_eq!(
        outbox
            .get_delivery(&first.event_id, "sink-a")
            .expect("first delivery")
            .expect("first row")
            .state,
        DeliveryState::Blocked
    );
    assert_eq!(
        outbox
            .get_delivery(&first.event_id, "sink-a")
            .expect("first delivery")
            .expect("first row")
            .last_error_class,
        Some(DeliveryErrorClass::AuthenticationBlocked { status: 403 })
    );
    assert_eq!(
        outbox
            .get_event(&first.event_id)
            .expect("first event after prune")
            .expect("first event remains replayable")
            .payload,
        canonical_bytes(&first)
    );
    assert_eq!(
        outbox
            .get_delivery(&second.event_id, "sink-a")
            .expect("second delivery")
            .expect("second row")
            .state,
        DeliveryState::Pending
    );
}

#[test]
fn pending_consumed_generation_prunes_and_remains_replayable() {
    let (_temp, log_path, outbox_path, first, _second, rotated) = prepare_rotated_journal();
    let mut outbox = Outbox::open(&outbox_path).expect("reopen outbox");
    outbox
        .reconcile_jsonl(&log_path, &["sink-a"])
        .expect("ingest rotated and active generations");
    record_delivery_for_test(
        &mut outbox,
        &first.event_id,
        "sink-a",
        DeliveryState::Pending,
        2,
        Some(1_700_000_100_000),
        Some(DeliveryErrorClass::TransportNoResponse),
    )
    .expect("retain pending delivery");
    record_delivery_for_test(
        &mut outbox,
        &_second.event_id,
        "sink-a",
        DeliveryState::Acked,
        1,
        None,
        None,
    )
    .expect("complete active delivery");

    let report = outbox.prune_eligible_rotations(&log_path, 0);
    assert_eq!(report.pruned, 1);
    assert!(!rotated.exists(), "consumed source generation is pruned");

    let delivery = outbox
        .get_delivery(&first.event_id, "sink-a")
        .expect("pending delivery")
        .expect("pending row remains after source prune");
    assert_eq!(delivery.state, DeliveryState::Pending);
    assert_eq!(delivery.attempts, 2);
    assert_eq!(
        delivery.last_error_class,
        Some(DeliveryErrorClass::TransportNoResponse)
    );
    let event = outbox
        .get_event(&first.event_id)
        .expect("replay event")
        .expect("event remains after source prune");
    assert_eq!(event.payload, canonical_bytes(&first));
    let ready = outbox
        .next_ready_delivery("sink-a", 1_700_000_100_001)
        .expect("ready pending delivery")
        .expect("pending delivery remains replayable");
    assert_eq!(ready.row.state, DeliveryState::Pending);
    assert_eq!(ready.payload, event.payload);
}

#[test]
fn prune_pending_generation_is_recovered_after_restart() {
    let (_temp, log_path, outbox_path, _first, _second, rotated) = prepare_rotated_journal();
    let mut outbox = Outbox::open(&outbox_path).expect("reopen outbox");
    outbox
        .reconcile_jsonl(&log_path, &["sink-a"])
        .expect("ingest rotated generation");
    let generation = discover_jsonl_generations(&log_path)
        .expect("discover generations")
        .into_iter()
        .find(|generation| generation.path == rotated)
        .expect("rotated generation");
    assert!(
        mark_generation_prune_pending(&mut outbox.connection, &generation.identity)
            .expect("mark prune pending")
    );
    drop(outbox);

    let mut restarted = Outbox::open(&outbox_path).expect("restart outbox");
    let report = restarted.prune_eligible_rotations(&log_path, 0);
    assert_eq!(report.pruned, 1);
    assert_eq!(report.finalized_pending, 1);
    assert!(
        !rotated.exists(),
        "pending deletion should complete after restart"
    );
}

#[test]
fn missing_prune_pending_file_is_finalized_and_cleanup_is_idempotent() {
    let (_temp, log_path, outbox_path, _first, _second, rotated) = prepare_rotated_journal();
    let mut outbox = Outbox::open(&outbox_path).expect("reopen outbox");
    outbox
        .reconcile_jsonl(&log_path, &["sink-a"])
        .expect("ingest rotated generation");
    let generation = discover_jsonl_generations(&log_path)
        .expect("discover generations")
        .into_iter()
        .find(|generation| generation.path == rotated)
        .expect("rotated generation");
    assert!(
        mark_generation_prune_pending(&mut outbox.connection, &generation.identity)
            .expect("mark prune pending")
    );
    std::fs::remove_file(&rotated).expect("simulate missing rotated file");

    let first = outbox.prune_eligible_rotations(&log_path, 0);
    assert_eq!(first.finalized_pending, 1);
    assert!(first.warnings.is_empty());
    let second = outbox.prune_eligible_rotations(&log_path, 0);
    assert_eq!(second, super::PruneReport::default());
}

#[test]
fn invalid_generation_lifecycle_fails_safe_without_pruning_source_bytes() {
    let (_temp, log_path, outbox_path, _first, _second, rotated) = prepare_rotated_journal();
    let mut outbox = Outbox::open(&outbox_path).expect("reopen outbox");
    outbox
        .reconcile_jsonl(&log_path, &["sink-a"])
        .expect("ingest rotated generation");
    let rotated_identity = discover_jsonl_generations(&log_path)
        .expect("discover generations")
        .into_iter()
        .find(|generation| generation.path == rotated)
        .expect("rotated generation")
        .identity;
    drop(outbox);

    let connection = Connection::open(&outbox_path).expect("raw lifecycle fixture");
    if connection
        .pragma_update(None, "ignore_check_constraints", "ON")
        .is_err()
    {
        drop(connection);
        fs::write(&outbox_path, b"synthetic-corrupt-lifecycle-database")
            .expect("corrupt database fallback");
        let error = Outbox::open(&outbox_path).expect_err("corrupt fallback must fail closed");
        let delivery = error
            .downcast_ref::<DeliveryError>()
            .expect("structured corrupt lifecycle fallback error");
        assert_eq!(delivery.class, DeliveryErrorClass::DurableStorage);
        assert!(outbox_path.exists());
        assert!(rotated.exists(), "corrupt storage must retain JSONL bytes");
        return;
    }
    connection
        .execute(
            "UPDATE journal_generations
                 SET lifecycle = 'synthetic-invalid-lifecycle'
                 WHERE generation_id = ?1",
            [&rotated_identity],
        )
        .expect("insert invalid lifecycle fixture");
    drop(connection);

    let mut reopened = Outbox::open(&outbox_path).expect("reopen normal outbox");
    let report = reopened.prune_eligible_rotations(&log_path, 0);
    assert_eq!(report.pruned, 0);
    assert!(!report.warnings.is_empty());
    assert!(
        rotated.exists(),
        "invalid lifecycle must retain JSONL bytes"
    );
}

#[test]
fn unknown_or_mismatched_cursor_state_never_authorizes_pruning() {
    let (_temp, log_path, outbox_path, _first, _second, rotated) = prepare_rotated_journal();
    let mut outbox = Outbox::open(&outbox_path).expect("reopen outbox");
    outbox
        .reconcile_jsonl(&log_path, &["sink-a"])
        .expect("ingest rotated generation");
    outbox
        .connection
        .execute(
            "UPDATE ingest_cursor SET generation_id = 'unknown-generation' WHERE id = 1",
            [],
        )
        .expect("corrupt cursor identity");
    let report = outbox.prune_eligible_rotations(&log_path, 0);
    assert!(rotated.exists(), "unknown cursor must retain bytes");
    assert_eq!(report.pruned, 0);
    assert!(!report.warnings.is_empty());

    outbox
            .connection
            .execute(
                "UPDATE ingest_cursor SET generation_id = (SELECT generation_id FROM journal_generations WHERE lifecycle = 'present' ORDER BY observed_at LIMIT 1), journal_path_hash = ?1 WHERE id = 1",
                ["f".repeat(64)],
            )
            .expect("corrupt cursor journal binding");
    let report = outbox.prune_eligible_rotations(&log_path, 0);
    assert!(rotated.exists(), "mismatched cursor must retain bytes");
    assert_eq!(report.pruned, 0);
}

#[test]
fn rename_restart_keeps_unregistered_generation_until_reconciliation() {
    let (_temp, log_path, outbox_path, _first, _second, rotated) = prepare_rotated_journal();
    let mut restarted = Outbox::open(&outbox_path).expect("restart outbox");
    let cursor_before = restarted
        .ingest_cursor()
        .expect("cursor before restart")
        .expect("cursor row");
    let rotated_identity = discover_jsonl_generations(&log_path)
        .expect("discover generations")
        .into_iter()
        .find(|generation| generation.path == rotated)
        .expect("rotated generation")
        .identity;
    assert_eq!(cursor_before.generation_id, rotated_identity);

    // The rename and new active-file write happened before the process
    // stopped. The old cursor and generation metadata are still the only
    // committed state, so cleanup must wait for restart reconciliation.
    let before_reconcile = restarted.prune_eligible_rotations(&log_path, 0);
    assert_eq!(before_reconcile.pruned, 0);
    assert!(!before_reconcile.warnings.is_empty());
    assert!(rotated.exists());

    restarted
        .reconcile_jsonl(&log_path, &["sink-a"])
        .expect("reconcile renamed generation after restart");
    let after_reconcile = restarted.prune_eligible_rotations(&log_path, 0);
    assert_eq!(after_reconcile.pruned, 1);
    assert!(!rotated.exists());
}

#[test]
fn rotation_pruning_is_serialized_by_the_jsonl_sidecar_lock() {
    let (_temp, log_path, outbox_path, _first, _second, rotated) = prepare_rotated_journal();
    let mut outbox = Outbox::open(&outbox_path).expect("reopen outbox");
    outbox
        .reconcile_jsonl(&log_path, &["sink-a"])
        .expect("ingest rotated generation");

    let lock =
        crate::file_lock::SidecarLock::acquire_lock_only(&log_path).expect("hold rotation lock");
    let blocked = outbox.prune_eligible_rotations(&log_path, 0);
    assert_eq!(blocked.pruned, 0);
    assert!(!blocked.warnings.is_empty());
    assert!(rotated.exists(), "a locked lifecycle cannot prune bytes");
    drop(lock);

    let after_release = outbox.prune_eligible_rotations(&log_path, 0);
    assert_eq!(after_release.pruned, 1);
    assert!(!rotated.exists());
}

#[test]
fn corrupt_generation_metadata_disables_pruning() {
    let (_temp, log_path, outbox_path, _first, _second, rotated) = prepare_rotated_journal();
    let mut outbox = Outbox::open(&outbox_path).expect("reopen outbox");
    outbox
        .reconcile_jsonl(&log_path, &["sink-a"])
        .expect("ingest rotated generation");
    let rotated_identity = discover_jsonl_generations(&log_path)
        .expect("discover generations")
        .into_iter()
        .find(|generation| generation.path == rotated)
        .expect("rotated generation")
        .identity;
    outbox
        .connection
        .execute(
            "UPDATE journal_generations SET journal_path_hash = 'corrupt' WHERE generation_id = ?1",
            [&rotated_identity],
        )
        .expect("corrupt generation metadata fixture");

    let report = outbox.prune_eligible_rotations(&log_path, 0);
    assert_eq!(report.pruned, 0);
    assert!(!report.warnings.is_empty());
    assert!(rotated.exists(), "corrupt metadata must retain JSONL");
}

#[test]
fn deletion_failure_leaves_prune_pending_until_restart_recovery() {
    let (_temp, log_path, outbox_path, _first, _second, rotated) = prepare_rotated_journal();
    let mut outbox = Outbox::open(&outbox_path).expect("reopen outbox");
    outbox
        .reconcile_jsonl(&log_path, &["sink-a"])
        .expect("ingest rotated generation");
    let rotated_identity = discover_jsonl_generations(&log_path)
        .expect("discover generations")
        .into_iter()
        .find(|generation| generation.path == rotated)
        .expect("rotated generation")
        .identity;
    outbox.fail_next_prune_deletion();

    let failed = outbox.prune_eligible_rotations(&log_path, 0);
    assert_eq!(failed.pruned, 0);
    assert!(!failed.warnings.is_empty());
    assert!(rotated.exists(), "failed deletion must retain JSONL");
    let lifecycle: String = outbox
        .connection
        .query_row(
            "SELECT lifecycle FROM journal_generations WHERE generation_id = ?1",
            [&rotated_identity],
            |row| row.get(0),
        )
        .expect("pending lifecycle");
    assert_eq!(lifecycle, "prune_pending");
    drop(outbox);

    let mut restarted = Outbox::open(&outbox_path).expect("restart after deletion failure");
    let recovered = restarted.prune_eligible_rotations(&log_path, 0);
    assert_eq!(recovered.pruned, 1);
    assert_eq!(recovered.finalized_pending, 1);
    assert!(!rotated.exists());
}

#[test]
fn replaced_rotated_generation_is_retained_by_identity_mismatch() {
    let (temp, log_path, outbox_path, _first, _second, rotated) = prepare_rotated_journal();
    let mut outbox = Outbox::open(&outbox_path).expect("reopen outbox");
    outbox
        .reconcile_jsonl(&log_path, &["sink-a"])
        .expect("ingest rotated generation");
    let replacement = temp.path().join("replacement.jsonl");
    fs::copy(&rotated, &replacement).expect("copy replacement");
    fs::remove_file(&rotated).expect("remove original generation");
    fs::rename(&replacement, &rotated).expect("replace generation");

    let report = outbox.prune_eligible_rotations(&log_path, 0);
    assert_eq!(report.pruned, 0);
    assert!(!report.warnings.is_empty());
    assert!(rotated.exists(), "identity replacement must be retained");
}

#[test]
fn changed_bytes_with_the_same_generation_identity_are_retained() {
    use std::io::Write;

    let (_temp, log_path, outbox_path, _first, _second, rotated) = prepare_rotated_journal();
    let mut outbox = Outbox::open(&outbox_path).expect("reopen outbox");
    outbox
        .reconcile_jsonl(&log_path, &["sink-a"])
        .expect("ingest rotated generation");
    let extra = marked_event("TT_ROTATION_APPENDED_AFTER_CURSOR_26");
    let mut file = fs::OpenOptions::new()
        .append(true)
        .open(&rotated)
        .expect("open rotated generation");
    file.write_all(&canonical_bytes(&extra))
        .expect("append changed bytes");
    file.write_all(b"\n").expect("terminate changed bytes");
    file.sync_all().expect("sync changed bytes");

    let report = outbox.prune_eligible_rotations(&log_path, 0);
    assert_eq!(report.pruned, 0);
    assert!(rotated.exists(), "unproven appended bytes must be retained");
}

#[test]
fn missing_active_generation_disables_pruning() {
    let (_temp, log_path, outbox_path, _first, _second, rotated) = prepare_rotated_journal();
    let mut outbox = Outbox::open(&outbox_path).expect("reopen outbox");
    outbox
        .reconcile_jsonl(&log_path, &["sink-a"])
        .expect("ingest rotated generation");
    fs::remove_file(&log_path).expect("remove active generation");

    let report = outbox.prune_eligible_rotations(&log_path, 0);
    assert_eq!(report.pruned, 0);
    assert!(!report.warnings.is_empty());
    assert!(rotated.exists(), "missing active state must retain bytes");
}

#[test]
fn health_is_metadata_only_and_separates_sink_states() {
    let temp = tempdir().expect("temporary directory");
    let path = private_outbox_path(&temp);
    let first = marked_event("TT_HEALTH_FIRST");
    let second = marked_event("TT_HEALTH_SECOND");
    let third = marked_event("TT_HEALTH_THIRD");
    let first_bytes = canonical_bytes(&first);
    let second_bytes = canonical_bytes(&second);
    let mut outbox = Outbox::open(&path).expect("open outbox");
    for event in [&first, &second, &third] {
        outbox
            .insert_event(event, &["sink-a", "sink-b"])
            .expect("insert event");
    }
    outbox
        .connection
        .execute(
            "UPDATE events SET created_at = CASE event_id
                     WHEN ?1 THEN 100 WHEN ?2 THEN 200 WHEN ?3 THEN 300 END",
            params![first.event_id, second.event_id, third.event_id],
        )
        .expect("set deterministic event times");
    outbox
        .record_delivery_at(
            &first.event_id,
            "sink-a",
            super::DeliveryUpdate {
                state: DeliveryState::Pending,
                attempts: 1,
                next_attempt_at: Some(9_999),
                last_error_class: Some(DeliveryErrorClass::HttpStatus { status: 429 }),
                updated_at: 1_000,
            },
        )
        .expect("record retry-delayed row");
    outbox
        .record_delivery_at(
            &second.event_id,
            "sink-a",
            super::DeliveryUpdate {
                state: DeliveryState::Blocked,
                attempts: 1,
                next_attempt_at: None,
                last_error_class: Some(DeliveryErrorClass::AuthenticationBlocked { status: 403 }),
                updated_at: 1_100,
            },
        )
        .expect("record blocked row");
    outbox
        .record_delivery_at(
            &third.event_id,
            "sink-a",
            super::DeliveryUpdate {
                state: DeliveryState::Dead,
                attempts: 1,
                next_attempt_at: None,
                last_error_class: Some(DeliveryErrorClass::SinkApplicationRejected),
                updated_at: 1_200,
            },
        )
        .expect("record dead row");
    outbox
        .record_delivery_at(
            &first.event_id,
            "sink-b",
            super::DeliveryUpdate {
                state: DeliveryState::Acked,
                attempts: 1,
                next_attempt_at: None,
                last_error_class: None,
                updated_at: 1_300,
            },
        )
        .expect("record acknowledged row");

    let health = outbox.health(&["sink-a", "sink-b"], 1_000).expect("health");
    assert_eq!(health.sinks.len(), 2);
    let sink_a = &health.sinks[0];
    assert_eq!(sink_a.sink_id, "sink-a");
    assert_eq!(sink_a.pending_depth, 2);
    assert_eq!(
        sink_a.pending_bytes,
        (first_bytes.len() + second_bytes.len()) as u64
    );
    assert_eq!(sink_a.oldest_pending_age_seconds, Some(900));
    assert_eq!(sink_a.dead_count, 1);
    assert_eq!(sink_a.last_error_at, Some(1_200));
    assert_eq!(
        sink_a.last_error_class,
        Some(DeliveryErrorClass::SinkApplicationRejected)
    );
    let sink_b = &health.sinks[1];
    assert_eq!(sink_b.pending_depth, 2);
    assert_eq!(sink_b.dead_count, 0);
    assert_eq!(sink_b.last_success_at, Some(1_300));
    assert!(sink_b.last_error_at.is_none());

    let rendered = crate::sink::durable_health_json_from_path(&path, &["sink-a", "sink-b"]);
    let rendered = serde_json::to_string(&rendered).expect("health JSON");
    assert!(!rendered.contains("TT_HEALTH_FIRST"));
    assert!(!rendered.contains("TT_HEALTH_SECOND"));
    assert!(!rendered.contains("TT_HEALTH_THIRD"));
}

#[test]
fn health_history_survives_restart_and_read_only_lookup_is_bounded() {
    let temp = tempdir().expect("temporary directory");
    let path = private_outbox_path(&temp);
    let event = marked_event("TT_HEALTH_RESTART");
    let mut outbox = Outbox::open(&path).expect("open outbox");
    outbox
        .insert_event(&event, &["sink"])
        .expect("insert event");
    outbox
        .record_delivery_at(
            &event.event_id,
            "sink",
            super::DeliveryUpdate {
                state: DeliveryState::Acked,
                attempts: 1,
                next_attempt_at: None,
                last_error_class: None,
                updated_at: 2_000,
            },
        )
        .expect("record success");
    let failed = marked_event("TT_HEALTH_FAILURE");
    outbox
        .insert_event(&failed, &["sink"])
        .expect("insert failed event");
    outbox
        .record_delivery_at(
            &failed.event_id,
            "sink",
            super::DeliveryUpdate {
                state: DeliveryState::Dead,
                attempts: 1,
                next_attempt_at: None,
                last_error_class: Some(DeliveryErrorClass::HttpStatus { status: 500 }),
                updated_at: 3_000,
            },
        )
        .expect("record failure");
    drop(outbox);

    let restarted = Outbox::open_read_only(&path).expect("read-only restart lookup");
    let health = restarted.health(&[], 4_000).expect("restart health");
    assert_eq!(health.sinks[0].last_success_at, Some(2_000));
    assert_eq!(health.sinks[0].last_error_at, Some(3_000));
    assert_eq!(
        health.sinks[0].last_error_class,
        Some(DeliveryErrorClass::HttpStatus { status: 500 })
    );

    let corrupt = temp.path().join("corrupt.sqlite");
    fs::write(&corrupt, b"TT_HEALTH_CORRUPT_SECRET").expect("write corrupt outbox");
    let rendered = crate::sink::durable_health_json_from_path(&corrupt, &[]);
    let rendered = serde_json::to_string(&rendered).expect("unavailable health JSON");
    assert!(rendered.len() < 512);
    assert!(!rendered.contains("TT_HEALTH_CORRUPT_SECRET"));
    assert!(rendered.contains("unavailable"));
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
