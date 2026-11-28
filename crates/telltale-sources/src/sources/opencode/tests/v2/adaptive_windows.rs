use super::*;

/// An incremental read stops before the row that would exceed its stored-byte
/// budget, reporting that row's `time_updated` as the next coordinate, so a
/// large backlog is read a window at a time. The first row is always taken.
#[test]
fn incremental_reads_stop_at_their_stored_byte_budget() {
    let store = Store::v2();
    for seq in 1..=5 {
        store.message(
            &format!("msg_{seq}"),
            seq,
            T0 + seq,
            user(&"x".repeat(1_000), T0),
        );
    }
    let read = |bytes| {
        extract_incremental_messages(
            &store.connection,
            T0,
            10,
            2,
            &mut SqliteAdmission::default(),
            bytes,
        )
        .unwrap()
    };
    let (records, truncated, next) = read(2_500);
    assert_eq!(records.len(), 2);
    assert!(truncated);
    assert_eq!(next, Some(T0 + 3));
    let (records, truncated, next) = read(1);
    assert_eq!(records.len(), 1);
    assert!(truncated);
    assert_eq!(next, Some(T0 + 2));
    let (records, truncated, next) = read(usize::MAX);
    assert_eq!(records.len(), 5);
    assert!(!truncated);
    assert_eq!(next, None);
}

/// Adaptive budgets may not split the first timestamp group. It is the
/// smallest cursor-safe unit, but the production retained limit still applies.
#[test]
fn adaptive_windows_keep_the_first_timestamp_group_within_hard_limits() {
    let store = Store::v2();
    for seq in 1..=3 {
        store.message(&format!("msg_{seq}"), seq, T0, user(&"x".repeat(1_000), T0));
    }
    store.message("later", 4, T0 + 1, user("later", T0));
    let bounds = OpenCodeSqliteReadOptions {
        message_min_time_updated: Some(T0),
        message_window_bytes: Some(1),
        ..Default::default()
    };
    for read in [
        bounds,
        OpenCodeSqliteReadOptions {
            message_min_time_updated: None,
            ..bounds
        },
    ] {
        let batch = store.acquire(read).unwrap();
        assert_eq!(batch.observations.len(), 3);
        assert!(batch.quarantined.is_empty());
        assert_eq!(
            batch.progress,
            AcquisitionProgress::OpenCodeSessionMessages {
                message_max_time_updated: Some(T0),
                window_complete: false,
            }
        );
        let later = store
            .acquire(read.continue_session_messages_after(T0))
            .unwrap();
        assert_eq!(later.observations.len(), 1);
        assert_eq!(
            later.progress,
            AcquisitionProgress::OpenCodeSessionMessages {
                message_max_time_updated: Some(T0 + 1),
                window_complete: true,
            }
        );
    }
    store.connection.execute(
        "UPDATE session_message SET data = '{\"content\":\"not an array\"}', type = 'assistant' WHERE id = 'msg_2'", [],
    ).unwrap();
    assert_eq!(
        mapping_code(store.acquire(bounds).err().unwrap()),
        "invalid_assistant_content"
    );
    let large = Store::v2();
    for seq in 1..=140 {
        large.message(
            &format!("msg_{seq}"),
            seq,
            T0,
            user(&"x".repeat(64_000), T0),
        );
    }
    assert_eq!(
        large.acquire(bounds).err(),
        Some(AcquisitionError::BoundedSourceRead(
            BoundedReadError::LimitExceeded
        ))
    );
}

#[test]
fn adaptive_timestamp_groups_do_not_exceed_the_production_stored_byte_budget() {
    let store = Store::v2();
    for seq in 1..=3 {
        store.message(
            &format!("msg_{seq}"),
            seq,
            T0,
            user(&"x".repeat(6 * 1024 * 1024), T0),
        );
    }
    let (records, truncated, next) = extract_incremental_messages(
        &store.connection,
        T0,
        10,
        2,
        &mut SqliteAdmission::default(),
        1,
    )
    .unwrap();
    assert_eq!(records.len(), 2);
    assert!(truncated);
    assert_eq!(next, Some(T0));
}

/// A selection larger than one window's retained budget or row limit is
/// evaluated in successive windows instead of failing. Each window ends on a
/// row boundary, reports itself incomplete, and moves progress to its last
/// admitted row; the next read resumes from there minus the overlap until
/// the backlog is drained. A window that cannot advance past its resume
/// point still fails as saturated.
#[test]
fn oversized_selections_roll_through_windows_until_drained() {
    let store = Store::v2();
    // Each row retains roughly 100 KB (arguments on request and result), so
    // 100 rows need more than one 8 MiB window.
    let patch = format!("*** Begin Patch\n{}", "+line\n".repeat(7_000));
    let rows = 100;
    for seq in 1..=rows {
        store.message(
            &format!("msg_{seq:03}"),
            seq,
            T0 + seq * HOUR,
            assistant(
                json!([completed_tool(
                    &format!("call_{seq}"),
                    "patch",
                    json!({"patchText": patch}),
                    "ok",
                    T0
                )]),
                T0,
            ),
        );
    }
    let mut seen = std::collections::BTreeSet::new();
    let mut read = OpenCodeSqliteReadOptions {
        message_limit: 1_000,
        ..Default::default()
    };
    let mut windows = 0;
    loop {
        windows += 1;
        assert!(windows <= 10, "backlog must drain");
        let batch = store.acquire(read).unwrap();
        assert!(batch.quarantined.is_empty());
        seen.extend(shape(&batch).into_iter().map(|(id, ..)| id));
        let AcquisitionProgress::OpenCodeSessionMessages {
            message_max_time_updated: Some(high_water),
            window_complete,
        } = batch.progress
        else {
            panic!("{:?}", batch.progress)
        };
        if window_complete {
            assert_eq!(high_water, T0 + rows * HOUR);
            break;
        }
        assert!(high_water < T0 + rows * HOUR);
        read = OpenCodeSqliteReadOptions::default().resume_session_messages_after(high_water);
    }
    assert!(windows >= 2, "one window cannot hold {rows} rows");
    assert_eq!(
        seen.len(),
        usize::try_from(rows).unwrap(),
        "every row evaluated"
    );

    // The row limit rolls the same way.
    let small = Store::v2();
    for seq in 1..=3 {
        small.message(
            &format!("msg_{seq}"),
            seq,
            T0 + seq * HOUR,
            user("text", T0),
        );
    }
    let first = small
        .acquire(OpenCodeSqliteReadOptions {
            message_min_time_updated: Some(T0),
            message_limit: 2,
            ..Default::default()
        })
        .unwrap();
    assert_eq!(
        first.progress,
        AcquisitionProgress::OpenCodeSessionMessages {
            message_max_time_updated: Some(T0 + 2 * HOUR),
            window_complete: false,
        }
    );

    // More rows inside the overlap than one window holds: the cut window may
    // end before the resume point, and continuing strictly after it (without
    // the overlap) still drains the rest.
    let packed = Store::v2();
    for seq in 1..=3 {
        packed.message(&format!("msg_{seq}"), seq, T0 + seq, user("text", T0));
    }
    let resume = OpenCodeSqliteReadOptions {
        message_limit: 2,
        ..OpenCodeSqliteReadOptions::default().resume_session_messages_after(T0 + 3)
    };
    let cut = packed.acquire(resume).unwrap();
    assert_eq!(
        cut.progress,
        AcquisitionProgress::OpenCodeSessionMessages {
            message_max_time_updated: Some(T0 + 2),
            window_complete: false,
        }
    );
    let continuation = resume.continue_session_messages_after(T0 + 2);
    assert_eq!(continuation.message_resume_high_water, Some(T0 + 3));
    let rest = packed.acquire(continuation).unwrap();
    assert_eq!(
        shape(&rest)
            .into_iter()
            .map(|(id, ..)| id)
            .collect::<Vec<_>>(),
        ["msg_3"]
    );
    assert_eq!(
        rest.progress,
        AcquisitionProgress::OpenCodeSessionMessages {
            message_max_time_updated: Some(T0 + 3),
            window_complete: true,
        }
    );

    // The raw continuation is not the regression floor: rows can still exist
    // after the cut while the previously evaluated checkpoint has disappeared.
    packed
        .connection
        .execute("DELETE FROM session_message WHERE id = 'msg_3'", [])
        .unwrap();
    assert_eq!(
        packed.acquire(continuation).err(),
        Some(AcquisitionError::ResumeRegressed)
    );

    // A cut never splits rows sharing one `time_updated`: it backs off to the
    // previous timestamp, and fails only when one timestamp fills a window.
    let ties = Store::v2();
    ties.message("msg_a", 1, T0, user("text", T0));
    for seq in 2..=4 {
        ties.message(&format!("msg_{seq}"), seq, T0 + 1, user("text", T0));
    }
    let limited = |limit| OpenCodeSqliteReadOptions {
        message_min_time_updated: Some(T0),
        message_limit: limit,
        ..Default::default()
    };
    let backed_off = ties.acquire(limited(3)).unwrap();
    assert_eq!(
        backed_off.progress,
        AcquisitionProgress::OpenCodeSessionMessages {
            message_max_time_updated: Some(T0),
            window_complete: false,
        }
    );
    assert_eq!(backed_off.observations.len(), 1);
    let saturated = Store::v2();
    for seq in 1..=3 {
        saturated.message(&format!("msg_{seq}"), seq, T0, user("text", T0));
    }
    assert_eq!(
        saturated.acquire(limited(2)).err(),
        Some(AcquisitionError::BoundedSourceRead(
            BoundedReadError::LimitExceeded
        ))
    );
}
