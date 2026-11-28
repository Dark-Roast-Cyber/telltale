use super::*;

#[test]
fn bootstrap_sampling_incremental_limits_and_regression() {
    let store = Store::v2();
    for seq in 1..=3 {
        store.message(&format!("msg_{seq}"), seq, T0 + seq, user("text", T0));
    }
    let sampled = store
        .acquire(OpenCodeSqliteReadOptions {
            message_limit: 2,
            ..Default::default()
        })
        .unwrap();
    assert_eq!(
        shape(&sampled)
            .into_iter()
            .map(|(id, ..)| id)
            .collect::<Vec<_>>(),
        ["msg_2", "msg_3"]
    );
    assert_eq!(
        sampled.progress,
        AcquisitionProgress::OpenCodeSessionMessages {
            message_max_time_updated: Some(T0 + 3),
            window_complete: true,
        }
    );
    let incremental = |limit| {
        store.acquire(OpenCodeSqliteReadOptions {
            message_min_time_updated: Some(T0 + 2),
            message_limit: limit,
            ..Default::default()
        })
    };
    // Without a resume point a cut window is progress, not saturation.
    assert_eq!(
        incremental(1).unwrap().progress,
        AcquisitionProgress::OpenCodeSessionMessages {
            message_max_time_updated: Some(T0 + 2),
            window_complete: false,
        }
    );
    assert_eq!(incremental(2).unwrap().observations.len(), 2);

    let regressed = OpenCodeSqliteReadOptions::default().resume_session_messages_after(T0 + 4);
    assert_eq!(
        store.acquire(regressed).err(),
        Some(AcquisitionError::ResumeRegressed)
    );
    let at_high_water = OpenCodeSqliteReadOptions::default().resume_session_messages_after(T0 + 3);
    assert_eq!(store.acquire(at_high_water).unwrap().observations.len(), 3);

    // A legacy part watermark far beyond every v2 row neither regresses nor
    // skips v2 history: the v2 store reads its own bootstrap selection.
    let legacy_cursor = OpenCodeSqliteReadOptions::resume_after(T0 + 100 * HOUR);
    let batch = store.acquire(legacy_cursor).unwrap();
    assert_eq!(batch.observations.len(), 3);
    assert_eq!(
        batch.progress,
        AcquisitionProgress::OpenCodeSessionMessages {
            message_max_time_updated: Some(T0 + 3),
            window_complete: true,
        }
    );
    // And a v2 cursor does not apply to a legacy store.
    let legacy = Store::new(LEGACY_SCHEMA);
    assert!(
        legacy
            .acquire(OpenCodeSqliteReadOptions::default().resume_session_messages_after(T0))
            .unwrap()
            .observations
            .is_empty()
    );
}

#[test]
fn in_place_updates_are_reselected_by_update_coordinate_not_seq() {
    let store = Store::v2();
    store.message("msg_1", 1, T0, user("first", T0));
    store.message("msg_2", 2, T0 + HOUR, user("second", T0));
    store.message(
        "msg_3",
        3,
        T0 + 2 * HOUR,
        assistant(
            json!([tool_entry(
                "call",
                Some(false),
                json!({"status": "running", "input": {"command": "make"}, "metadata": {}}),
                json!({"created": T0})
            )]),
            T0,
        ),
    );
    let high_water = T0 + 2 * HOUR;
    let resume = OpenCodeSqliteReadOptions::default().resume_session_messages_after(high_water);
    let ids = |batch: AcquisitionBatch| {
        let mut ids = shape(&batch)
            .into_iter()
            .map(|(id, ..)| id)
            .collect::<Vec<_>>();
        ids.dedup();
        ids
    };
    assert_eq!(ids(store.acquire(resume).unwrap()), ["msg_3"]);

    // msg_1 keeps seq 1, below every seq already read, but its in-place update
    // moves its update coordinate past the cursor.
    store.update("msg_1", T0 + 3 * HOUR, user("first, edited", T0));
    // msg_3 completes inside the overlap window with the same timestamp tie.
    store.update(
        "msg_3",
        high_water,
        assistant(
            json!([tool_entry("call", Some(false), json!({"status": "completed", "input": {"command": "make"}, "content": [{"type": "text", "text": "built"}]}), json!({"created": T0, "ran": T0, "completed": T0}))]),
            T0,
        ),
    );
    let batch = store.acquire(resume).unwrap();
    assert_eq!(
        batch.progress,
        AcquisitionProgress::OpenCodeSessionMessages {
            message_max_time_updated: Some(T0 + 3 * HOUR),
            window_complete: true,
        }
    );
    assert!(
        batch
            .observations
            .iter()
            .any(|item| item.stage() == ObservationStage::ToolResultReturned)
    );
    assert_eq!(
        ids(batch),
        ["msg_1", "msg_3"],
        "source order is session seq order"
    );
}

#[test]
fn equal_timestamps_cross_pages_and_late_failures_reject_the_source() {
    let store = Store::v2();
    for seq in 1..=5 {
        store.message(&format!("msg_{seq}"), seq, T0, user("tie", T0));
    }
    let read = |limit, page| {
        extract_incremental_messages(
            &store.connection,
            T0,
            limit,
            page,
            &mut SqliteAdmission::default(),
            usize::MAX,
        )
    };
    for page in [1, 2, 5, 6] {
        let (records, truncated, next) = read(5, page).unwrap();
        assert!(!truncated);
        assert_eq!(next, None);
        assert_eq!(
            records.iter().map(|record| record.seq).collect::<Vec<_>>(),
            [1, 2, 3, 4, 5],
            "page {page}"
        );
        // Over the limit, the selection is cut at the limit, not rejected.
        let (records, truncated, next) = read(4, page).unwrap();
        assert!(truncated, "page {page}");
        assert_eq!(records.len(), 4);
        assert_eq!(next, Some(T0), "the cut splits a timestamp group");
    }

    store
        .connection
        .execute(
            "insert into session_message values ('msg_late','ses_synthetic','user',6,1,?1,'not json')",
            [T0 + 1],
        )
        .unwrap();
    assert!(read(10, 2).is_err());
    store
        .connection
        .execute("update session_message set data = '{\"text\":\"t\"}', time_updated = 'late' where id = 'msg_late'", [])
        .unwrap();
    assert!(read(10, 2).is_err());
    assert!(store.acquire(OpenCodeSqliteReadOptions::default()).is_err());
}

#[test]
fn read_snapshot_pins_every_page_including_committed_wal_contents() {
    let store = Store::v2();
    store
        .connection
        .execute_batch("pragma journal_mode=WAL; pragma wal_autocheckpoint=0;")
        .unwrap();
    for seq in 1..=3 {
        store.message(&format!("msg_{seq}"), seq, T0, user("committed in wal", T0));
    }
    assert!(store.source.path.with_extension("db-wal").is_file());

    let mut reader =
        Connection::open_with_flags(&store.source.path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    let snapshot = reader.transaction().unwrap();
    let writer = Connection::open(&store.source.path).unwrap();
    let _guard = on_next_incremental_page(move || {
        writer
            .execute(
                "insert into session_message values ('msg_4','ses_synthetic','user',4,1,?1,'not json')",
                [T0],
            )
            .unwrap();
        writer
            .execute(
                "update session_message set data = 'not json' where id = 'msg_3'",
                [],
            )
            .unwrap();
    });
    let (records, ..) = extract_incremental_messages(
        &snapshot,
        T0,
        10,
        1,
        &mut SqliteAdmission::default(),
        usize::MAX,
    )
    .unwrap();
    assert_eq!(records.len(), 3, "later pages read the pinned snapshot");
    snapshot.commit().unwrap();
    assert_eq!(
        store.acquire(OpenCodeSqliteReadOptions::default()).err(),
        Some(AcquisitionError::SourceRead),
        "the next extraction sees the committed writer change"
    );
}

#[test]
fn repeated_acquisition_is_deterministic_in_session_seq_order() {
    let store = Store::v2();
    store.session("ses_other");
    store.message("msg_b", 2, T0 + 10, user("second by seq", T0));
    store.message("msg_a", 1, T0 + 50, user("first by seq", T0));
    store.message_in("ses_other", "msg_c", 1, T0 + 5, user("other session", T0));
    let first = store.acquire_default();
    let second = store.acquire_default();
    assert_eq!(
        first
            .observations
            .iter()
            .map(|item| item.source().native_id().unwrap())
            .collect::<Vec<_>>(),
        ["msg_c", "msg_a", "msg_b"]
    );
    assert_eq!(identities(&first), identities(&second));
    assert_eq!(
        first
            .observations
            .iter()
            .map(|item| item.sequence())
            .collect::<Vec<_>>(),
        [Some(1), Some(1), Some(2)]
    );
}
