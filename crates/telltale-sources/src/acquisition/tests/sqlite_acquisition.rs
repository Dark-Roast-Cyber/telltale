use super::*;

#[test]
#[cfg(feature = "opencode-sqlite")]
fn empty_opencode_progress_is_not_no_progress() {
    let (_directory, connection, source) = database();
    connection.execute("delete from part", []).unwrap();
    drop(connection);
    let batch = super::super::acquire_source(&source, options()).unwrap();
    assert_eq!(
        batch.progress,
        AcquisitionProgress::OpenCodeSqlite {
            part_max_time_updated: None
        }
    );
    assert_ne!(batch.progress, AcquisitionProgress::None);
}

#[test]
#[cfg(feature = "opencode-sqlite")]
fn long_message_sqlite_acquisition_keeps_full_suffix_and_rejects_atomically() {
    use telltale_schema::observation::{JsonValue, ObservationBody};
    let (_directory, connection, source) = database();
    for (bytes, accepted) in [(9_000, true), (65_537, false)] {
        let text = format!("{}suffix", "x".repeat(bytes - 6));
        connection
            .execute(
                "update part set data = ?1 where id = 'part-third'",
                [serde_json::json!({"type":"text", "text":text}).to_string()],
            )
            .unwrap();
        let result = super::super::acquire_source(&source, options());
        if accepted {
            let batch = result.unwrap();
            assert!(batch.observations.iter().any(|observation| matches!(observation.body(), ObservationBody::Message(message) if message.content() == Some(&JsonValue::string(&text)))));
        } else {
            assert_eq!(acquisition_error(result).code(), "unbounded_value");
        }
    }
}

#[test]
fn validates_exact_identity_and_kind_before_source_io() {
    let directory = tempdir().unwrap();
    let missing = directory.path().join("must-not-be-created.db");
    for invalid in [
        Source {
            client: ClientId::Claude,
            kind: SourceKind::Sqlite,
            source_id: "opencode.sqlite".to_owned(),
            path: missing.clone(),
        },
        Source {
            client: ClientId::OpenCode,
            kind: SourceKind::Sqlite,
            source_id: "OpenCode.sqlite".to_owned(),
            path: missing.clone(),
        },
    ] {
        assert_eq!(
            acquisition_error(acquire_opencode_sqlite(
                &invalid,
                options(),
                OpenCodeSqliteReadOptions::default()
            )),
            AcquisitionError::UnsupportedSourceIdentity
        );
        assert!(!missing.exists());
    }

    let wrong_kind = Source {
        client: ClientId::OpenCode,
        kind: SourceKind::Json,
        source_id: "opencode.sqlite".to_owned(),
        path: missing.clone(),
    };
    assert_eq!(
        acquisition_error(acquire_opencode_sqlite(
            &wrong_kind,
            options(),
            OpenCodeSqliteReadOptions::default()
        )),
        AcquisitionError::SourceKindMismatch
    );
    assert!(!missing.exists());
}

#[test]
fn missing_opencode_database_is_not_created_by_either_acquisition_entry() {
    let directory = tempdir().unwrap();
    let source = source(directory.path().join("missing.db"));
    for error in [
        acquisition_error(super::super::acquire_source(&source, options())),
        acquisition_error(acquire_opencode_sqlite(
            &source,
            options(),
            OpenCodeSqliteReadOptions::default(),
        )),
    ] {
        let expected = if cfg!(feature = "opencode-sqlite") {
            AcquisitionError::SourceRead
        } else {
            AcquisitionError::CapabilityNotCompiled
        };
        assert_eq!(error, expected);
        assert!(!source.path.exists());
    }
}

#[cfg(not(feature = "opencode-sqlite"))]
#[test]
fn disabled_opencode_acquisition_does_not_touch_present_database() {
    let (directory, connection, source) = database();
    drop(connection);
    let bytes = std::fs::read(&source.path).unwrap();
    let modified = std::fs::metadata(&source.path).unwrap().modified().unwrap();
    for result in [
        super::super::acquire_source(&source, options()),
        acquire_opencode_sqlite(&source, options(), OpenCodeSqliteReadOptions::default()),
    ] {
        assert_eq!(
            acquisition_error(result),
            AcquisitionError::CapabilityNotCompiled
        );
    }
    assert_eq!(std::fs::read(&source.path).unwrap(), bytes);
    assert_eq!(
        std::fs::metadata(&source.path).unwrap().modified().unwrap(),
        modified
    );
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
}

#[test]
#[cfg(feature = "opencode-sqlite")]
fn malformed_serialized_message_data_fails_atomically_but_metadata_only_succeeds() {
    let (_directory, connection, source) = database();
    connection.execute("delete from part", []).unwrap();
    connection.execute("delete from message", []).unwrap();
    connection
        .execute(
            "insert into message values ('metadata', 'session', 1, 1, '{}')",
            [],
        )
        .unwrap();
    let valid = super::super::acquire_source(&source, options()).unwrap();
    assert_eq!(valid.accounting.sessions[0].counts.native_units, 1);
    for invalid in ["not-json", "null", "[]", "42", "\"text\""] {
        connection
            .execute(
                "insert into message values ('malformed', 'session', 2, 2, ?1)",
                [invalid],
            )
            .unwrap();
        assert_eq!(
            acquisition_error(super::super::acquire_source(&source, options())),
            AcquisitionError::SourceRead,
        );
        connection
            .execute("delete from message where id = 'malformed'", [])
            .unwrap();
    }
    connection
        .execute(
            "insert into message values ('malformed', 'session', 2, 2, NULL)",
            [],
        )
        .unwrap();
    assert_eq!(
        acquisition_error(super::super::acquire_source(&source, options())),
        AcquisitionError::SourceRead,
    );
}

#[test]
#[cfg(feature = "opencode-sqlite")]
fn sqlite_admission_failure_is_source_read_without_partial_acquisition() {
    let (_directory, connection, source) = database();
    let before = super::super::acquire_source(&source, options()).unwrap();
    connection.execute_batch("alter table message add column unknown blob; alter table part add column unknown blob;").unwrap();
    let under = super::super::acquire_source(&source, options()).unwrap();
    assert_eq!(
        format!("{:?}", under.observations),
        format!("{:?}", before.observations)
    );
    assert_eq!(under.accounting, before.accounting);
    assert_eq!(under.progress, before.progress);
    connection.execute_batch("insert into part values('unselected','message-acquisition','session-acquisition',4,4,'{\"type\":\"metadata\"}',zeroblob(8388609));").unwrap();
    let unselected = super::super::acquire_source(&source, options()).unwrap();
    assert_eq!(
        format!("{:?}", unselected.observations),
        format!("{:?}", before.observations)
    );
    assert_eq!(unselected.accounting, before.accounting);
    assert_eq!(unselected.progress, before.progress);
    connection
        .execute("delete from part where id='unselected'", [])
        .unwrap();
    for table in ["message", "part"] {
        connection
            .execute_batch(&format!("update {table} set unknown=zeroblob(8388609)"))
            .unwrap();
        let error = acquisition_error(super::super::acquire_source(&source, options()));
        assert_eq!(error, AcquisitionError::SourceRead);
        assert!(!format!("{error:?} {error}").contains("unknown"));
        connection
            .execute_batch(&format!("update {table} set unknown=null"))
            .unwrap();
        let repaired = super::super::acquire_source(&source, options()).unwrap();
        assert_eq!(
            format!("{:?}", repaired.observations),
            format!("{:?}", before.observations)
        );
        assert_eq!(repaired.accounting, before.accounting);
        assert_eq!(repaired.progress, before.progress);
    }
    connection.execute_batch("insert into message values('metadata-only','another-session',4,4,'{}',zeroblob(8388609));").unwrap();
    assert_eq!(
        acquisition_error(super::super::acquire_source(&source, options())),
        AcquisitionError::SourceRead
    );
}

#[test]
#[cfg(feature = "opencode-sqlite")]
fn incremental_parts_must_fit_the_effective_limit_or_fail_atomically() {
    let (_directory, connection, source) = database();
    connection.execute("delete from part", []).unwrap();
    for i in 0..7 {
        connection.execute(
                "insert into part values (?1, 'message-acquisition', 'session-acquisition', 1, ?2, '{\"type\":\"text\",\"text\":\"synthetic\"}')",
                (format!("part-{i}"), if i < 5 { 100 } else { 100 + i }),
            ).unwrap();
    }
    let read = |min, limit| {
        acquire_opencode_sqlite(
            &source,
            options(),
            OpenCodeSqliteReadOptions {
                part_min_time_updated: min,
                part_limit: limit,
                resume_high_water: None,
                ..Default::default()
            },
        )
    };
    for (limit, expected) in [(8, 7), (7, 7), (6, 6)] {
        let batch = read(Some(i64::MIN), limit);
        if limit == 6 {
            assert_eq!(
                acquisition_error(batch),
                AcquisitionError::BoundedSourceRead(BoundedReadError::LimitExceeded)
            );
        } else {
            assert_eq!(batch.unwrap().observations.len(), expected);
        }
    }
    // Selecting more parts than the (at least one) limit is a typed overflow.
    for limit in [0, -1, 1, 2, 3, 4, 5] {
        assert_eq!(
            acquisition_error(read(Some(100), limit)),
            AcquisitionError::BoundedSourceRead(BoundedReadError::LimitExceeded),
        );
    }
    // An unrepresentable page limit is rejected before reading.
    assert_eq!(
        acquisition_error(read(Some(100), i64::MAX)),
        AcquisitionError::SourceRead,
    );
    for limit in [0, -1, 1] {
        let one = read(Some(106), limit).unwrap();
        assert_eq!(one.observations.len(), 1);
        assert_eq!(
            one.progress,
            AcquisitionProgress::OpenCodeSqlite {
                part_max_time_updated: Some(106)
            }
        );
    }
    assert_eq!(read(Some(105), 2).unwrap().observations.len(), 2);
    // Bootstrap still selects the newest bounded rows without overflow.
    assert_eq!(read(None, 2).unwrap().observations.len(), 2);
    let empty = read(Some(i64::MAX), 1).unwrap();
    assert!(empty.observations.is_empty());
    assert_eq!(
        empty.progress,
        AcquisitionProgress::OpenCodeSqlite {
            part_max_time_updated: None
        }
    );
    connection.execute("delete from part", []).unwrap();
    assert!(read(Some(i64::MIN), 1).unwrap().observations.is_empty());
}

#[test]
#[cfg(feature = "opencode-sqlite")]
fn dense_distinct_incremental_timestamps_fail_instead_of_truncating() {
    let (_directory, connection, source) = database();
    connection.execute("delete from part", []).unwrap();
    for i in 0..7_i64 {
        connection.execute(
                "insert into part values (?1, 'message-acquisition', 'session-acquisition', 1, ?2, '{\"type\":\"text\",\"text\":\"synthetic\"}')",
                (format!("part-{i}"), 1_000 + i),
            ).unwrap();
    }
    assert_eq!(
        acquisition_error(acquire_opencode_sqlite(
            &source,
            options(),
            OpenCodeSqliteReadOptions {
                part_min_time_updated: Some(1_000),
                part_limit: 5,
                resume_high_water: None,
                ..Default::default()
            },
        )),
        AcquisitionError::BoundedSourceRead(BoundedReadError::LimitExceeded),
    );
}

#[test]
#[cfg(feature = "opencode-sqlite")]
fn default_acquisition_preserves_canonical_semantics_and_observed_time() {
    let (_directory, connection, source) = database();
    drop(connection);

    let acquired = super::super::acquire_source(&source, options()).unwrap();
    assert_eq!(acquired.observations.len(), 3);
    for (observation, (id, text)) in acquired.observations.iter().zip([
        ("part-first", "first"),
        ("part-second", "second"),
        ("part-third", "third"),
    ]) {
        assert_eq!(observation.source().native_id(), Some(id));
        assert_eq!(observation.observed_at().as_str(), OBSERVED_AT);
        let ObservationBody::Message(message) = observation.body() else {
            panic!("expected text part message")
        };
        assert_eq!(
            message.content(),
            Some(&telltale_schema::observation::JsonValue::string(text))
        );
    }
    assert_eq!(
        acquired.progress,
        AcquisitionProgress::OpenCodeSqlite {
            part_max_time_updated: Some(3_000)
        }
    );
}

#[test]
#[cfg(feature = "opencode-sqlite")]
fn bounded_read_options_return_selected_progress() {
    let (_directory, connection, source) = database();
    drop(connection);
    let read = OpenCodeSqliteReadOptions {
        part_min_time_updated: Some(3_000),
        part_limit: 1,
        resume_high_water: None,
        ..Default::default()
    };

    let acquired = acquire_opencode_sqlite(&source, options(), read).unwrap();
    assert_eq!(acquired.observations.len(), 1);
    let ObservationBody::Message(message) = acquired.observations[0].body() else {
        panic!("expected selected message part")
    };
    assert_eq!(
        message.content(),
        Some(&telltale_schema::observation::JsonValue::string("third"))
    );
    assert_eq!(
        acquired.progress,
        AcquisitionProgress::OpenCodeSqlite {
            part_max_time_updated: Some(3_000)
        }
    );
}

#[test]
#[cfg(feature = "opencode-sqlite")]
fn repeated_equivalent_acquisition_is_identity_stable() {
    let (_directory, connection, source) = database();
    drop(connection);
    let first = super::super::acquire_source(&source, options()).unwrap();
    let second = super::super::acquire_source(&source, options()).unwrap();

    assert_eq!(first.progress, second.progress);
    assert_eq!(
        first
            .observations
            .iter()
            .map(|observation| observation.observation_id())
            .collect::<Vec<_>>(),
        second
            .observations
            .iter()
            .map(|observation| observation.observation_id())
            .collect::<Vec<_>>()
    );
}

#[test]
#[cfg(feature = "opencode-sqlite")]
fn acquisition_errors_do_not_expose_source_details() {
    let private_directory = tempdir().unwrap();
    let private_path = private_directory
        .path()
        .join("private-source-path-marker.db");
    std::fs::create_dir(&private_path).unwrap();
    let unreadable = source(private_path.clone());
    let error = acquisition_error(super::super::acquire_source(&unreadable, options()));
    assert_eq!(error, AcquisitionError::SourceRead);
    assert_eq!(error.to_string(), "source_read");
    assert!(!format!("{error:?}").contains(private_path.to_string_lossy().as_ref()));

    let (directory, connection, source) = database();
    connection
            .execute(
                "insert into part values (?1, ?2, ?3, ?4, ?5, ?6)",
                (
                    "private-part-id-marker",
                    "private-message-id-marker",
                    "private-session-id-marker",
                    4_000_i64,
                    4_000_i64,
                    r#"{"type":"tool","tool":"private-tool-marker","callID":"private-call-marker","state":{"status":"private-status-marker","input":{"command":"private-argument-marker"},"output":"private-result-marker"}}"#,
                ),
            )
            .unwrap();
    drop(connection);
    let error = acquisition_error(super::super::acquire_source(&source, options()));
    assert_eq!(error.code(), "unknown_tool_status");
    let rendered = format!("{error:?} {error}");
    let directory_marker = directory.path().to_string_lossy().into_owned();
    for marker in [
        directory_marker.as_str(),
        "private-part-id-marker",
        "private-message-id-marker",
        "private-session-id-marker",
        "private-tool-marker",
        "private-call-marker",
        "private-status-marker",
        "private-argument-marker",
        "private-result-marker",
    ] {
        assert!(!rendered.contains(marker));
    }
}
