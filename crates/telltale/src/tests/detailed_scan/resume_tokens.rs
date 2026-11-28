use super::*;

#[cfg(feature = "opencode-sqlite")]
#[test]
fn opencode_resume_token_reads_from_the_overlap_window_and_binds_to_its_source() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("resume.db");
    let conn = rusqlite::Connection::open(&path).unwrap();
    let tool = |id: &str, call: &str, updated: i64| {
        format!(
            r#"INSERT INTO part VALUES ('{id}','a','s',{updated},'{{"type":"tool","tool":"shell","callID":"{call}","state":{{"status":"running","input":{{"command":"cat .env"}},"time":{{"start":{start}}}}}}}');"#,
            start = 1_789_603_200_000_i64 + updated
        )
    };
    conn.execute_batch(&format!(
        r#"CREATE TABLE message (id TEXT, session_id TEXT, data TEXT);
        CREATE TABLE part (id TEXT, message_id TEXT, session_id TEXT, time_updated INTEGER, data TEXT);
        INSERT INTO message VALUES ('a','s','{{"role":"assistant","time":{{"created":1789603200000}}}}');
        {old}
        {mid}"#,
        old = tool("old", "call-old", 1_000),
        mid = tool("mid", "call-mid", 2_000_000),
    ))
    .unwrap();
    let source = Source {
        client: ClientId::OpenCode,
        source_id: "opencode.sqlite".into(),
        kind: SourceKind::Sqlite,
        path: path.clone(),
    };
    let pipeline = Pipeline::builder().build().unwrap();
    let options = DetailedEvaluationOptions::default();

    // Bootstrap reads the bounded recent window and issues a token.
    let bootstrap = pipeline
        .scan_source_detailed_resuming(&source, None, &options)
        .unwrap();
    assert!(bootstrap.failure().is_none());
    assert_eq!(bootstrap.coverage(), Some(SourceCoverage::Partial));
    assert_eq!(bootstrap.action_findings.len(), 2);
    let token = bootstrap.resume_token().cloned().expect("bootstrap token");
    assert!(
        token
            .as_str()
            .starts_with("resume:v1:opencode.sqlite:2000000:")
    );
    assert_eq!(ResumeToken::parse(token.as_str()).unwrap(), token);
    let mid = bootstrap
        .action_findings
        .iter()
        .map(|a| a.coordinate().clone())
        .collect::<Vec<_>>();

    // Resuming reads parts updated since the high-water minus the overlap:
    // the overlap part again (same coordinate), the new part, not the old one.
    conn.execute_batch(&tool("new", "call-new", 9_000_000))
        .unwrap();
    let resumed = pipeline
        .scan_source_detailed_resuming(&source, Some(&token), &options)
        .unwrap();
    assert!(resumed.failure().is_none());
    assert_eq!(resumed.action_findings.len(), 2);
    assert!(
        resumed
            .action_findings
            .iter()
            .any(|a| mid.contains(a.coordinate()))
    );
    let next = resumed.resume_token().cloned().expect("resumed token");
    assert!(
        next.as_str()
            .starts_with("resume:v1:opencode.sqlite:9000000:")
    );

    // No newer parts: an idle resumed scan keeps its token.
    let idle_token = pipeline
        .scan_source_detailed_resuming(&source, Some(&next), &options)
        .unwrap()
        .resume_token()
        .cloned();
    assert_eq!(idle_token.as_ref(), Some(&next));

    // A token is bound to its source and is rejected before any I/O.
    let other_path = root.path().join("other-missing.db");
    let other = Source {
        path: other_path.clone(),
        ..source.clone()
    };
    assert!(matches!(
        pipeline.scan_source_detailed_resuming(&other, Some(&next), &options),
        Err(PipelineError::InvalidResumeToken)
    ));
    assert!(!other_path.exists());
    let jsonl = write_source(
        root.path(),
        "plain.jsonl",
        "session",
        &[call("call", "2026-09-17T00:00:00Z", "cat .env")],
    );
    assert!(matches!(
        pipeline.scan_source_detailed_resuming(&jsonl, Some(&next), &options),
        Err(PipelineError::InvalidResumeToken)
    ));
    let plain = pipeline
        .scan_source_detailed_resuming(&jsonl, None, &options)
        .unwrap();
    assert!(plain.resume_token().is_none());
    for bad in ["", "resume:v1:opencode.sqlite:-1:00", "resume:v2:x:1:y"] {
        assert!(ResumeToken::parse(bad).is_err(), "{bad}");
    }
}

#[cfg(feature = "opencode-sqlite")]
#[test]
fn opencode_v2_resume_tokens_name_their_coordinate_and_never_cross_schemas() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("v2.db");
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute_batch(
        r#"CREATE TABLE session_v2 (id TEXT PRIMARY KEY, agent TEXT, model TEXT);
        CREATE TABLE session_message (id TEXT PRIMARY KEY, session_id TEXT, type TEXT, seq INTEGER,
            time_created INTEGER, time_updated INTEGER, data TEXT);
        INSERT INTO session_v2 VALUES ('ses', 'build', '{"id":"m","providerID":"p"}');"#,
    )
    .unwrap();
    let message = |id: &str, seq: i64, updated: i64| {
        let data = serde_json::json!({
            "agent": "build", "model": {"id": "m", "providerID": "p"}, "time": {"created": 1_789_603_200_000_i64},
            "content": [{"type": "tool", "id": format!("call-{id}"), "name": "bash", "executed": false,
                "state": {"status": "running", "input": {"command": "cat .env"}, "metadata": {}},
                "time": {"created": 1_789_603_200_000_i64 + updated}}]
        });
        conn.execute(
            "INSERT INTO session_message VALUES (?1, 'ses', 'assistant', ?2, 0, ?3, ?4)",
            rusqlite::params![id, seq, updated, data.to_string()],
        )
        .unwrap();
    };
    message("old", 1, 1_000);
    message("mid", 2, 2_000_000);
    let source = Source {
        client: ClientId::OpenCode,
        source_id: "opencode.sqlite".into(),
        kind: SourceKind::Sqlite,
        path: path.clone(),
    };
    let pipeline = Pipeline::builder().build().unwrap();
    let options = DetailedEvaluationOptions::default();
    let scan = |token: Option<&ResumeToken>| {
        pipeline
            .scan_source_detailed_resuming(&source, token, &options)
            .unwrap()
    };

    let bootstrap = scan(None);
    assert!(bootstrap.failure().is_none());
    assert_eq!(bootstrap.coverage(), Some(SourceCoverage::Partial));
    assert_eq!(bootstrap.action_findings.len(), 2);
    let token = bootstrap.resume_token().cloned().expect("bootstrap token");
    assert!(
        token
            .as_str()
            .starts_with("resume:v1:opencode.sqlite:session_message:2000000:")
    );
    assert_eq!(ResumeToken::parse(token.as_str()).unwrap(), token);

    // Resume reads the overlap and newer rows, not the old message.
    message("new", 3, 9_000_000);
    let resumed = scan(Some(&token));
    assert!(resumed.failure().is_none());
    assert_eq!(resumed.action_findings.len(), 2);
    let next = resumed.resume_token().cloned().unwrap();
    assert!(
        next.as_str()
            .starts_with("resume:v1:opencode.sqlite:session_message:9000000:")
    );
    assert_eq!(scan(Some(&next)).resume_token(), Some(&next));

    // A legacy part token far ahead of every message neither skips v2 history
    // nor bounds the new token: the v2 store reads its bootstrap selection.
    let legacy = ResumeToken::new(resume_binding(&source), ResumeCoordinate::Part, 99_000_000);
    let crossed = scan(Some(&legacy));
    assert!(crossed.failure().is_none());
    assert_eq!(crossed.action_findings.len(), 3);
    assert_eq!(crossed.resume_token(), Some(&next));

    // Deleting the newest messages regresses the store below the token.
    conn.execute("DELETE FROM session_message WHERE id = 'new'", [])
        .unwrap();
    let regressed = scan(Some(&next));
    assert_eq!(
        regressed
            .failure()
            .and_then(|failure| failure.acquisition_error()),
        Some(telltale_sources::acquisition::AcquisitionError::ResumeRegressed)
    );
    assert!(regressed.resume_token().is_none());
    assert!(regressed.coverage().is_none());

    // A session_message token does not apply to a legacy store.
    let legacy_path = root.path().join("legacy.db");
    rusqlite::Connection::open(&legacy_path)
        .unwrap()
        .execute_batch(
            r#"CREATE TABLE part (id TEXT, message_id TEXT, session_id TEXT, time_updated INTEGER, data TEXT);
            INSERT INTO part VALUES ('p','a','s',5000,'{"type":"tool","tool":"bash","callID":"c","state":{"status":"running","input":{"command":"cat .env"}}}');"#,
        )
        .unwrap();
    let legacy_source = Source {
        path: legacy_path,
        ..source.clone()
    };
    let v2_token = ResumeToken::new(
        resume_binding(&legacy_source),
        ResumeCoordinate::SessionMessage,
        99_000_000,
    );
    let legacy_scan = pipeline
        .scan_source_detailed_resuming(&legacy_source, Some(&v2_token), &options)
        .unwrap();
    assert!(legacy_scan.failure().is_none());
    assert!(
        legacy_scan
            .resume_token()
            .unwrap()
            .as_str()
            .starts_with("resume:v1:opencode.sqlite:5000:")
    );

    for bad in [
        "resume:v1:opencode.sqlite:session_message:-1:00",
        "resume:v1:opencode.sqlite:session_message:",
        "resume:v1:opencode.sqlite:session_message:1",
        "resume:v1:opencode.sqlite:part:1:00",
    ] {
        assert!(ResumeToken::parse(bad).is_err(), "{bad}");
    }
}

#[cfg(feature = "opencode-sqlite")]
#[test]
fn opencode_resume_overflow_is_typed_and_recoverable_by_bootstrap() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("overflow.db");
    let mut conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute_batch(r#"CREATE TABLE message (id TEXT, session_id TEXT, data TEXT);
        CREATE TABLE part (id TEXT, message_id TEXT, session_id TEXT, time_updated INTEGER, data TEXT);
        INSERT INTO message VALUES ('a','s','{"role":"assistant","time":{"created":1789603200000}}');
        INSERT INTO part VALUES ('first','a','s',1000,'{"type":"text","text":"synthetic"}');"#)
        .unwrap();
    let source = Source {
        client: ClientId::OpenCode,
        source_id: "opencode.sqlite".into(),
        kind: SourceKind::Sqlite,
        path,
    };
    let pipeline = Pipeline::builder().build().unwrap();
    let options = DetailedEvaluationOptions::default();
    let token = pipeline
        .scan_source_detailed_resuming(&source, None, &options)
        .unwrap()
        .resume_token()
        .cloned()
        .expect("bootstrap token");
    let transaction = conn.transaction().unwrap();
    for i in 0..=telltale_sources::acquisition::OPENCODE_SQLITE_RESUME_PART_LIMIT {
        transaction
            .execute(
                "INSERT INTO part VALUES (?1, 'a', 's', 2000, '{\"type\":\"text\",\"text\":\"synthetic\"}')",
                [format!("bulk-{i}")],
            )
            .unwrap();
    }
    transaction.commit().unwrap();
    let overflow = pipeline
        .scan_source_detailed_resuming(&source, Some(&token), &options)
        .unwrap();
    let failure = overflow.failure().expect("resumed overflow fails");
    assert_eq!(
        failure.acquisition_error(),
        Some(AcquisitionError::BoundedSourceRead(
            BoundedReadError::LimitExceeded
        ))
    );
    assert!(overflow.resume_token().is_none());
    // Recovery: a bootstrap read of the bounded recent window succeeds.
    let recovered = pipeline
        .scan_source_detailed_resuming(&source, None, &options)
        .unwrap();
    assert!(recovered.failure().is_none());
    assert!(recovered.resume_token().is_some());
}

#[cfg(feature = "opencode-sqlite")]
#[test]
fn opencode_resume_against_an_older_store_fails_typed_and_recovers_by_bootstrap() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("regressed.db");
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute_batch(r#"CREATE TABLE message (id TEXT, session_id TEXT, data TEXT);
        CREATE TABLE part (id TEXT, message_id TEXT, session_id TEXT, time_updated INTEGER, data TEXT);
        INSERT INTO message VALUES ('a','s','{"role":"assistant","time":{"created":1789603200000}}');
        INSERT INTO part VALUES ('old','a','s',1000,'{"type":"text","text":"synthetic"}');
        INSERT INTO part VALUES ('newest','a','s',5000000,'{"type":"text","text":"synthetic"}');"#)
        .unwrap();
    let source = Source {
        client: ClientId::OpenCode,
        source_id: "opencode.sqlite".into(),
        kind: SourceKind::Sqlite,
        path,
    };
    let pipeline = Pipeline::builder().build().unwrap();
    let options = DetailedEvaluationOptions::default();
    let token = pipeline
        .scan_source_detailed_resuming(&source, None, &options)
        .unwrap()
        .resume_token()
        .cloned()
        .expect("bootstrap token");

    // The store no longer reaches the token's high-water (restored, replaced,
    // or newest parts deleted). Older parts written later
    // would never be selected, so this is a typed failure, not an idle scan.
    for regress in [
        "DELETE FROM part WHERE id = 'newest';",
        // SQLite orders TEXT above INTEGER; a non-integer timestamp never counts.
        r#"INSERT INTO part VALUES ('textual','a','s','not-a-time','{"type":"step-finish"}');"#,
        "DELETE FROM part;",
        "DROP TABLE part;",
    ] {
        conn.execute_batch(regress).unwrap();
        let regressed = pipeline
            .scan_source_detailed_resuming(&source, Some(&token), &options)
            .unwrap();
        let failure = regressed.failure().expect("regressed store fails");
        assert_eq!(
            failure.acquisition_error(),
            Some(AcquisitionError::ResumeRegressed),
            "{regress}"
        );
        assert_eq!(regressed.coverage(), None);
        assert!(regressed.resume_token().is_none());
        assert!(regressed.action_findings.is_empty());
    }

    // Recovery: a tokenless bootstrap read succeeds and rebaselines.
    conn.execute_batch(r#"CREATE TABLE part (id TEXT, message_id TEXT, session_id TEXT, time_updated INTEGER, data TEXT);
        INSERT INTO part VALUES ('restored','a','s',2000,'{"type":"text","text":"synthetic"}');"#)
        .unwrap();
    let recovered = pipeline
        .scan_source_detailed_resuming(&source, None, &options)
        .unwrap();
    assert!(recovered.failure().is_none());
    let rebaselined = recovered.resume_token().cloned().expect("new token");
    assert!(
        rebaselined
            .as_str()
            .starts_with("resume:v1:opencode.sqlite:2000:")
    );
}

#[cfg(feature = "opencode-sqlite")]
#[test]
fn opencode_resume_survives_wal_commits_and_fails_closed_when_the_store_disappears() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("wal.db");
    let create = |path: &std::path::Path, parts: &[(&str, i64)]| {
        let conn = rusqlite::Connection::open(path).unwrap();
        conn.pragma_update(None, "journal_mode", "WAL").unwrap();
        conn.execute_batch(r#"CREATE TABLE message (id TEXT, session_id TEXT, data TEXT);
            CREATE TABLE part (id TEXT, message_id TEXT, session_id TEXT, time_updated INTEGER, data TEXT);
            INSERT INTO message VALUES ('a','s','{"role":"assistant","time":{"created":1789603200000}}');"#)
            .unwrap();
        for (id, updated) in parts {
            conn.execute(
                "INSERT INTO part VALUES (?1,'a','s',?2,'{\"type\":\"text\",\"text\":\"synthetic\"}')",
                (id, updated),
            )
            .unwrap();
        }
        conn
    };
    let writer = create(&path, &[("first", 1_000_000)]);
    // Keep the WAL from being checkpointed into the main file.
    writer.pragma_update(None, "wal_autocheckpoint", 0).unwrap();
    let source = Source {
        client: ClientId::OpenCode,
        source_id: "opencode.sqlite".into(),
        kind: SourceKind::Sqlite,
        path: path.clone(),
    };
    let pipeline = Pipeline::builder().build().unwrap();
    let options = DetailedEvaluationOptions::default();
    let token = pipeline
        .scan_source_detailed_resuming(&source, None, &options)
        .unwrap()
        .resume_token()
        .cloned()
        .expect("bootstrap token");

    // A part committed only to the WAL is visible to the resumed read.
    writer
        .execute(
            "INSERT INTO part VALUES ('wal','a','s',9000000,'{\"type\":\"text\",\"text\":\"synthetic\"}')",
            [],
        )
        .unwrap();
    assert!(root.path().join("wal.db-wal").metadata().unwrap().len() > 0);
    let resumed = pipeline
        .scan_source_detailed_resuming(&source, Some(&token), &options)
        .unwrap();
    assert!(resumed.failure().is_none());
    let token = resumed.resume_token().cloned().expect("advanced token");
    assert!(
        token
            .as_str()
            .starts_with("resume:v1:opencode.sqlite:9000000:")
    );

    // The store disappears: a typed failure, no token, nothing created.
    drop(writer);
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(root.path().join(format!("wal.db{suffix}")));
    }
    let missing = pipeline
        .scan_source_detailed_resuming(&source, Some(&token), &options)
        .unwrap();
    assert!(missing.failure().is_some());
    assert!(missing.resume_token().is_none());
    assert!(!path.exists());

    // Recreated at the same path with older content: the same binding, but a
    // regressed store. A tokenless scan rebaselines.
    let _recreated = create(&path, &[("recreated", 2_000_000)]);
    let regressed = pipeline
        .scan_source_detailed_resuming(&source, Some(&token), &options)
        .unwrap();
    assert_eq!(
        regressed.failure().and_then(|f| f.acquisition_error()),
        Some(AcquisitionError::ResumeRegressed)
    );
    let rebaselined = pipeline
        .scan_source_detailed_resuming(&source, None, &options)
        .unwrap();
    assert!(rebaselined.failure().is_none());
    assert!(
        rebaselined
            .resume_token()
            .unwrap()
            .as_str()
            .starts_with("resume:v1:opencode.sqlite:2000000:")
    );
}

#[cfg(unix)]
#[test]
fn resume_binding_uses_exact_path_bytes() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;
    let source = |bytes: &[u8]| Source {
        client: ClientId::OpenCode,
        source_id: "opencode.sqlite".into(),
        kind: SourceKind::Sqlite,
        path: std::path::PathBuf::from(OsStr::from_bytes(bytes)),
    };
    // Distinct invalid-UTF-8 paths that are equal under `to_string_lossy`.
    let first = source(b"/stores/\xff/opencode.db");
    let second = source(b"/stores/\xfe/opencode.db");
    assert_eq!(first.path.to_string_lossy(), second.path.to_string_lossy());
    assert_ne!(resume_binding(&first), resume_binding(&second));

    let token = ResumeToken::new(resume_binding(&first), ResumeCoordinate::Part, 10);
    let pipeline = Pipeline::builder().build().unwrap();
    assert!(matches!(
        pipeline.scan_source_detailed_resuming(
            &second,
            Some(&token),
            &DetailedEvaluationOptions::default()
        ),
        Err(PipelineError::InvalidResumeToken)
    ));
}
