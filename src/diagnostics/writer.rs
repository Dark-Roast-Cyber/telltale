//! The diagnostics file: one JSON object per line, bounded in size.
//!
//! A record is appended with one write and is not synced, because diagnostics
//! are not a durable record. Before an append would take the file past
//! [`MAX_FILE_BYTES`], the file is renamed to `<path>.1`, replacing the previous
//! generation, so the two files stay below about twice that. Writers are not
//! serialized: when two scans write at once, such as a `--history` scan beside
//! a routine scanner, each can pass the size check before the other appends,
//! which takes the file past the bound by one record per writer, and racing
//! rotations can discard a whole generation. The bound on both files stays
//! within a few records.
//! The target is opened like the event log: symbolic links, hard links and
//! non-regular files are refused.

use std::ffi::OsString;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::file_lock::{open_append, safe_path_info};

/// The largest record written. Records hold only fixed fields, so a larger
/// one means a bug, not a large scan.
pub(crate) const MAX_RECORD_BYTES: usize = 4 * 1024;
/// The size at which the file is rotated.
pub(crate) const MAX_FILE_BYTES: u64 = 1024 * 1024;

/// Why a record was not written. The class is the whole diagnostic: no path or
/// operating-system text accompanies it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WriteFailure {
    /// The path names, or rotates onto, one of the scanner's own state, log or
    /// queue files, or lies in a log directory.
    Overlap,
    /// The target is a link or not a regular file.
    UnsafeTarget,
    /// The serialized record exceeds [`MAX_RECORD_BYTES`].
    TooLarge,
    /// The full file could not be renamed to its rotated generation, for
    /// example because a directory has that name or, on Windows, another
    /// process holds the file open without sharing deletion.
    Rotate,
    /// The file or its directory could not be created or opened.
    Open,
    /// The record could not be serialized or appended.
    Write,
}

impl WriteFailure {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Overlap => "overlap",
            Self::UnsafeTarget => "unsafe_target",
            Self::TooLarge => "too_large",
            Self::Rotate => "rotate",
            Self::Open => "open",
            Self::Write => "write",
        }
    }
}

/// The one rotated generation of a diagnostics file: `<path>.1`.
pub(crate) fn rotated_path(path: &Path) -> PathBuf {
    let mut name = OsString::from(path.as_os_str());
    name.push(".1");
    PathBuf::from(name)
}

/// Appends `record` as one line, rotating first when the file is full.
pub(crate) fn append_record(
    path: &Path,
    record: &impl serde::Serialize,
) -> Result<(), WriteFailure> {
    let mut line = serde_json::to_vec(record).map_err(|_| WriteFailure::Write)?;
    line.push(b'\n');
    if line.len() > MAX_RECORD_BYTES {
        return Err(WriteFailure::TooLarge);
    }
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent).map_err(|_| WriteFailure::Open)?;
    }
    let existing = safe_path_info(path).map_err(|_| WriteFailure::UnsafeTarget)?;
    if let Some(info) = existing
        && info.length.saturating_add(line.len() as u64) > MAX_FILE_BYTES
    {
        // A rename replaces the name `<path>.1`, never what a link there points
        // to, and fails on a directory.
        std::fs::rename(path, rotated_path(path)).map_err(|_| WriteFailure::Rotate)?;
    }
    let (mut file, _, _) = open_append(path).map_err(|_| WriteFailure::Open)?;
    file.write_all(&line).map_err(|_| WriteFailure::Write)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(serde::Serialize)]
    struct Sample {
        value: u64,
    }

    fn lines(path: &Path) -> Vec<String> {
        std::fs::read_to_string(path)
            .unwrap_or_default()
            .lines()
            .map(str::to_string)
            .collect()
    }

    #[test]
    fn appends_one_line_per_record_and_creates_the_directory() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("nested").join("diagnostics.jsonl");
        append_record(&path, &Sample { value: 1 }).expect("first");
        append_record(&path, &Sample { value: 2 }).expect("second");
        assert_eq!(lines(&path), [r#"{"value":1}"#, r#"{"value":2}"#]);
    }

    #[test]
    fn rotates_to_one_generation_before_exceeding_the_bound() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("diagnostics.jsonl");
        let rotated = rotated_path(&path);
        std::fs::write(&rotated, "old generation\n").expect("old generation");
        let full = "x".repeat(MAX_FILE_BYTES as usize - 4) + "\n";
        std::fs::write(&path, &full).expect("full file");

        append_record(&path, &Sample { value: 3 }).expect("rotating append");

        assert_eq!(lines(&path), [r#"{"value":3}"#]);
        assert_eq!(std::fs::read_to_string(&rotated).expect("rotated"), full);
    }

    #[test]
    fn refuses_an_oversized_record_without_touching_the_file() {
        #[derive(serde::Serialize)]
        struct Large {
            text: String,
        }
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("diagnostics.jsonl");
        let record = Large {
            text: "x".repeat(MAX_RECORD_BYTES),
        };
        assert_eq!(append_record(&path, &record), Err(WriteFailure::TooLarge));
        assert!(!path.exists());
    }

    #[test]
    fn a_directory_in_place_of_the_file_is_an_unsafe_target() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("diagnostics.jsonl");
        std::fs::create_dir(&path).expect("directory");
        assert_eq!(
            append_record(&path, &Sample { value: 1 }),
            Err(WriteFailure::UnsafeTarget)
        );
    }

    #[test]
    fn a_file_in_place_of_the_directory_cannot_be_opened() {
        let dir = tempfile::tempdir().expect("tempdir");
        let parent = dir.path().join("not-a-directory");
        std::fs::write(&parent, "").expect("file");
        assert_eq!(
            append_record(&parent.join("diagnostics.jsonl"), &Sample { value: 1 }),
            Err(WriteFailure::Open)
        );
    }

    #[cfg(unix)]
    #[test]
    fn symbolic_links_are_refused_for_the_file_and_its_generation() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("elsewhere.jsonl");
        std::fs::write(&target, "").expect("target");
        let path = dir.path().join("diagnostics.jsonl");
        std::os::unix::fs::symlink(&target, &path).expect("link");
        assert_eq!(
            append_record(&path, &Sample { value: 1 }),
            Err(WriteFailure::UnsafeTarget)
        );
        assert_eq!(std::fs::read_to_string(&target).expect("target"), "");

        std::fs::remove_file(&path).expect("unlink");
        std::fs::write(&path, "x".repeat(MAX_FILE_BYTES as usize)).expect("full");
        std::os::unix::fs::symlink(&target, rotated_path(&path)).expect("generation link");
        // A link in place of the generation is replaced, never written through.
        append_record(&path, &Sample { value: 1 }).expect("rotating append");
        assert_eq!(std::fs::read_to_string(&target).expect("target"), "");
        assert!(
            std::fs::symlink_metadata(rotated_path(&path))
                .expect("generation")
                .is_file()
        );
    }

    #[test]
    fn failure_classes_are_fixed_words() {
        for failure in [
            WriteFailure::Overlap,
            WriteFailure::UnsafeTarget,
            WriteFailure::TooLarge,
            WriteFailure::Rotate,
            WriteFailure::Open,
            WriteFailure::Write,
        ] {
            let word = failure.as_str();
            assert!(
                word.bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
            );
        }
    }
}
