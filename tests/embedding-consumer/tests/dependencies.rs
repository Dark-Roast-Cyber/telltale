use telltale_core::Pipeline;

#[test]
fn core_constructs_without_host_runtime() {
    let pipeline = Pipeline::builder().build().unwrap();
    assert!(pipeline.rule_count() > 0);
    assert!(pipeline.scan_sources(&[]).unwrap().is_empty());
}

#[cfg(feature = "sqlx-sqlite")]
#[sqlx::test]
async fn sqlx_database_is_read_by_the_feature_selected_core() {
    use sqlx::{Connection, Executor};
    use telltale_core::{ClientId, DetailedEvaluationOptions, Source, SourceKind};

    let root = std::env::temp_dir().join(format!(
        "telltale-embedding-synthetic-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&root).unwrap();
    let path = root.join("synthetic.db");
    let options = sqlx::sqlite::SqliteConnectOptions::new()
        .filename(&path)
        .create_if_missing(true);
    let mut connection = sqlx::SqliteConnection::connect_with(&options)
        .await
        .unwrap();
    connection.execute(r#"
        CREATE TABLE message (id TEXT, session_id TEXT, data TEXT);
        CREATE TABLE part (id TEXT, message_id TEXT, session_id TEXT, time_updated INTEGER, data TEXT);
        INSERT INTO message VALUES ('u','s','{"role":"user","time":{"created":1789603199000}}');
        INSERT INTO message VALUES ('m','s','{"role":"assistant","time":{"created":1789603200000}}');
        INSERT INTO message VALUES ('other','other-session','{"role":"user","time":{"created":1789603199000}}');
        INSERT INTO part VALUES ('up','u','s',1,'{"type":"text","time":{"start":1789603199000},"text":"please inspect requested file"}');
        INSERT INTO part VALUES ('op','other','other-session',2,'{"type":"text","time":{"start":1789603199000},"text":"TT_OTHER_SESSION_EXCLUDED"}');
        INSERT INTO part VALUES ('p','m','s',3,'{"type":"tool","tool":"shell","callID":"call-a","state":{"status":"running","input":{"command":"cat .env"},"time":{"start":1789603200000}}}');
    "#).await.unwrap();
    connection.close().await.unwrap();

    let source = Source {
        client: ClientId::OpenCode,
        source_id: "opencode.sqlite".into(),
        kind: SourceKind::Sqlite,
        path: path.clone(),
    };
    let before = std::fs::read(&path).unwrap();
    let pipeline = Pipeline::builder().build().unwrap();
    let mut options = DetailedEvaluationOptions::default();
    options.context.before = 5;
    options.context.after = 3;
    options.context.user_text = true;
    let scans = pipeline.scan_sources_detailed(&[source], &options).unwrap();
    let events = &scans[0].events;
    if cfg!(feature = "opencode-sqlite") {
        assert!(events.iter().any(|event| event.event_type == "activity"));
        assert!(
            events
                .iter()
                .all(|event| event.event_type != "scanner_error")
        );
        assert_eq!(scans[0].action_findings.len(), 1);
        let context = scans[0].action_findings[0].context();
        assert!(
            context
                .iter()
                .any(|c| c.redacted_text().contains("requested file"))
        );
        assert!(
            context
                .iter()
                .all(|c| !c.redacted_text().contains("TT_OTHER_SESSION_EXCLUDED"))
        );
    } else {
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, "scanner_error");
        assert!(scans[0].action_findings.is_empty());
    }
    assert_eq!(std::fs::read(&path).unwrap(), before);
    std::fs::remove_dir_all(root).unwrap();
}
