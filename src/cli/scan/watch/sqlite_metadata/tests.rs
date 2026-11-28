use super::*;
use std::fs;
use telltale_schema::clients::{ClientId, SourceKind};

fn index(path: PathBuf) -> BTreeMap<PathBuf, Source> {
    let source = Source {
        path: path.clone(),
        client: ClientId::OpenCode,
        source_id: "opencode.sqlite".into(),
        kind: SourceKind::Sqlite,
    };
    BTreeMap::from([(path, source)])
}

#[test]
fn observes_open_writer_wal_without_notifications_or_reader_sidecars() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let database = root.join("custom.sqlite");
    let writer = rusqlite::Connection::open(&database).unwrap();
    writer.execute_batch("PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0; CREATE TABLE synthetic (value INTEGER);").unwrap();
    let now = Instant::now();
    let mut watch = SqliteMetadataWatch::new(&index(database.clone()), now);
    writer
        .execute("INSERT INTO synthetic VALUES (1)", [])
        .unwrap();
    assert!(watch.poll(now).is_empty(), "cadence must bound idle work");
    assert_eq!(watch.poll(now + INTERVAL), std::slice::from_ref(&database));
    let shm = super::super::sqlite_sidecar_path(&database, "-shm");
    fs::OpenOptions::new()
        .write(true)
        .open(shm)
        .unwrap()
        .set_times(fs::FileTimes::new().set_modified(std::time::SystemTime::now()))
        .unwrap();
    fs::write(root.join("unrelated.db"), b"synthetic").unwrap();
    assert!(watch.poll(now + INTERVAL * 2).is_empty());
    writer
        .execute_batch("PRAGMA wal_checkpoint(RESTART);")
        .unwrap();
    let wal = super::super::sqlite_sidecar_path(&database, "-wal");
    let length_before = fs::metadata(&wal).unwrap().len();
    watch.before_scan(&ScanTargets::Full);
    let wal_before = stamp(&wal);
    writer
        .execute("INSERT INTO synthetic VALUES (2)", [])
        .unwrap();
    assert_eq!(
        fs::metadata(&wal).unwrap().len(),
        length_before,
        "WAL reuse must not require growth"
    );
    assert_ne!(
        stamp(&wal),
        wal_before,
        "same-size WAL commits must change metadata"
    );
    assert_eq!(watch.poll(now + INTERVAL * 3), [database]);
}

#[test]
fn pre_scan_baseline_keeps_same_length_late_writes_and_replacements_visible() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let database = root.join("synthetic.db");
    fs::write(&database, b"first").unwrap();
    let now = Instant::now();
    let mut watch = SqliteMetadataWatch::new(&index(database.clone()), now);
    // A notification is about to run a scan. A subsequent write must not be
    // absorbed into a post-scan baseline, even if the file length is unchanged.
    watch.before_scan(&ScanTargets::Full);
    fs::write(&database, b"later").unwrap();
    fs::OpenOptions::new()
        .write(true)
        .open(&database)
        .unwrap()
        .set_times(
            fs::FileTimes::new().set_modified(std::time::UNIX_EPOCH + Duration::from_secs(2)),
        )
        .unwrap();
    assert_eq!(watch.poll(now + INTERVAL), std::slice::from_ref(&database));
    assert!(watch.poll(now + INTERVAL * 2).is_empty());
    let replacement = root.join("replacement");
    fs::write(&replacement, b"later").unwrap();
    fs::OpenOptions::new()
        .write(true)
        .open(&replacement)
        .unwrap()
        .set_times(
            fs::FileTimes::new().set_modified(std::time::UNIX_EPOCH + Duration::from_secs(2)),
        )
        .unwrap();
    fs::rename(replacement, &database).unwrap();
    assert_eq!(watch.poll(now + INTERVAL * 3), [database]);
}

#[test]
fn sampling_is_round_robin_work_bounded_and_exactly_owned() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let mut sources = BTreeMap::new();
    for i in 0..BATCH + 1 {
        let path = root.join(format!("db-{i:03}"));
        fs::write(&path, b"a").unwrap();
        sources.extend(index(path));
    }
    for (name, client, source_id, kind) in [
        (
            "wrong-client",
            ClientId::Codex,
            "opencode.sqlite",
            SourceKind::Sqlite,
        ),
        (
            "wrong-id",
            ClientId::OpenCode,
            "opencode.other",
            SourceKind::Sqlite,
        ),
        (
            "wrong-kind",
            ClientId::OpenCode,
            "opencode.sqlite",
            SourceKind::Jsonl,
        ),
    ] {
        let path = root.join(name);
        fs::write(&path, b"a").unwrap();
        sources.insert(
            path.clone(),
            Source {
                path,
                client,
                source_id: source_id.into(),
                kind,
            },
        );
    }
    let now = Instant::now();
    let mut watch = SqliteMetadataWatch::new(&sources, now);
    assert_eq!(watch.targets.len(), BATCH + 1);
    for path in sources.keys() {
        fs::write(path, b"changed").unwrap();
    }
    assert_eq!(watch.poll(now + INTERVAL).len(), BATCH);
    assert!(watch.poll(now + INTERVAL).is_empty());
    assert_eq!(watch.poll(now + INTERVAL * 2).len(), 1);
    assert!(watch.poll(now + INTERVAL * 3).is_empty());
    let new_path = root.join("new-db");
    fs::write(&new_path, b"synthetic").unwrap();
    let new_index = index(new_path.clone());
    watch.reconcile(&new_index);
    assert_eq!(watch.poll(now + INTERVAL * 4), [new_path]);
    watch.reconcile(&BTreeMap::new());
    assert!(watch.poll(now + INTERVAL * 5).is_empty());
}

#[test]
fn linked_files_and_ancestors_are_unsafe_not_sampled_through() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let real = root.join("real");
    fs::create_dir(&real).unwrap();
    let file = real.join("source.db");
    fs::write(&file, b"synthetic").unwrap();
    let linked_file = root.join("file-link");
    let linked_dir = root.join("dir-link");
    std::os::unix::fs::symlink(&file, &linked_file).unwrap();
    std::os::unix::fs::symlink(&real, &linked_dir).unwrap();
    assert_eq!(stamp(&linked_file), Stamp::Unsafe);
    assert_eq!(stamp(&linked_dir.join("source.db")), Stamp::Unsafe);
    let now = Instant::now();
    let mut watch = SqliteMetadataWatch::new(&index(file.clone()), now);
    fs::remove_file(&file).unwrap();
    assert_eq!(watch.poll(now + INTERVAL), [file]);
}
