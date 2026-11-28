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
mod tests;
