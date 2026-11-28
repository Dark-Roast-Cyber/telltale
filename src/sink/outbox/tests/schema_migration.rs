use super::*;

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
