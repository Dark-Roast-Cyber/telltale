//! Polls metadata of admitted OpenCode databases and their WAL for watch,
//! because filesystem notifications (notably macOS FSEvents) can miss commits
//! to an open WAL.

use std::collections::BTreeMap;
use std::fs;
use std::ops::Bound::{Excluded, Unbounded};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use telltale_schema::clients::{ClientId, SourceKind};
use telltale_schema::source::Source;

use super::{ScanTargets, sqlite_sidecar_path};

const INTERVAL: Duration = Duration::from_secs(1);
const BATCH: usize = 64;

#[derive(Debug, PartialEq, Eq)]
enum Stamp {
    Unavailable(std::io::ErrorKind),
    Unsafe,
    File {
        device: u64,
        inode: u64,
        length: u64,
        seconds: i64,
        nanoseconds: i64,
    },
}

fn stamp(path: &Path) -> Stamp {
    // Discovery rejected linked ancestors; recheck them before sampling a leaf.
    // Like discovery, these metadata guards are not an atomic filesystem snapshot.
    let mut ancestor = PathBuf::new();
    for component in path.components() {
        ancestor.push(component.as_os_str());
        let metadata = match fs::symlink_metadata(&ancestor) {
            Ok(metadata) => metadata,
            Err(error) => return Stamp::Unavailable(error.kind()),
        };
        if metadata.file_type().is_symlink() {
            return Stamp::Unsafe;
        }
        if ancestor == path {
            if !metadata.is_file() {
                return Stamp::Unsafe;
            }
            return Stamp::File {
                device: metadata.dev(),
                inode: metadata.ino(),
                length: metadata.len(),
                seconds: metadata.mtime(),
                nanoseconds: metadata.mtime_nsec(),
            };
        }
        if !metadata.is_dir() {
            return Stamp::Unsafe;
        }
    }
    Stamp::Unsafe
}

fn snapshot(path: &Path) -> (Stamp, Stamp) {
    (stamp(path), stamp(&sqlite_sidecar_path(path, "-wal")))
}

/// FSEvents can omit commits to an open WAL. Sample only admitted OpenCode files,
/// at most 64 database/WAL pairs per second, round-robin. Never enumerate parents.
pub(super) struct SqliteMetadataWatch {
    targets: BTreeMap<PathBuf, Option<(Stamp, Stamp)>>,
    cursor: Option<PathBuf>,
    last_sample: Instant,
}

impl SqliteMetadataWatch {
    pub(super) fn new(sources: &BTreeMap<PathBuf, Source>, now: Instant) -> Self {
        let mut watch = Self {
            targets: BTreeMap::new(),
            cursor: None,
            last_sample: now,
        };
        watch.reconcile(sources);
        watch.before_scan(&ScanTargets::Full);
        watch
    }

    pub(super) fn reconcile(&mut self, sources: &BTreeMap<PathBuf, Source>) {
        let mut previous = std::mem::take(&mut self.targets);
        self.targets = sources
            .values()
            .filter(|source| {
                source.client == ClientId::OpenCode
                    && source.source_id == "opencode.sqlite"
                    && source.kind == SourceKind::Sqlite
            })
            .map(|source| {
                let path = source.path.clone();
                // A new source gets a conservative wakeup: sampling after its scan
                // could otherwise swallow a write arriving after that scan's snapshot.
                let old = previous.remove(&path).unwrap_or(None);
                (path, old)
            })
            .collect();
    }

    pub(super) fn before_scan(&mut self, targets: &ScanTargets) {
        match targets {
            ScanTargets::Full => {
                for (path, stamp) in &mut self.targets {
                    *stamp = Some(snapshot(path));
                }
            }
            ScanTargets::Targeted { sources, .. } => {
                for source in sources {
                    if let Some(stamp) = self.targets.get_mut(&source.path) {
                        *stamp = Some(snapshot(&source.path));
                    }
                }
            }
        }
    }

    pub(super) fn poll(&mut self, now: Instant) -> Vec<PathBuf> {
        if now.duration_since(self.last_sample) < INTERVAL {
            return Vec::new();
        }
        self.last_sample = now;
        let mut paths = match self.cursor.as_ref() {
            Some(cursor) => self
                .targets
                .range::<PathBuf, _>((Excluded(cursor), Unbounded))
                .map(|(path, _)| path.clone())
                .take(BATCH)
                .collect::<Vec<_>>(),
            None => Vec::new(),
        };
        if paths.is_empty() {
            paths = self.targets.keys().take(BATCH).cloned().collect();
        }
        self.cursor = paths.last().cloned();
        paths
            .into_iter()
            .filter(|path| {
                let current = snapshot(path);
                let previous = self.targets.get_mut(path).expect("indexed metadata target");
                let changed = previous.as_ref() != Some(&current);
                *previous = Some(current);
                changed
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
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
}
