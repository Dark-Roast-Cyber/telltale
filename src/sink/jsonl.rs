use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::event::{Event, append_jsonl_bytes, ensure_jsonl_tail, serialize_jsonl_events};
use crate::file_lock::{RotationNamespace, SidecarLock, atomic_rename_no_replace, sync_parent};
use crate::sink::EventSink;

/// Built-in size-based log rotation configuration.
///
/// When the active JSONL file exceeds `max_size_bytes`, it is renamed to a
/// date-stamped rotated file and a fresh active file is started. Rotated files
/// beyond `keep` are deleted oldest-first. This provides cross-platform
/// rotation without OS-specific tooling (logrotate, newsyslog, Scheduled Tasks).
#[derive(Debug, Clone)]
pub struct RotationConfig {
    /// Maximum size in bytes before the active file is rotated. 0 disables rotation.
    pub max_size_bytes: u64,
    /// Number of rotated files to keep. 0 keeps none (rotated files are deleted immediately).
    pub keep: usize,
}

impl Default for RotationConfig {
    fn default() -> Self {
        Self {
            max_size_bytes: 100 * 1024 * 1024, // 100 MB
            keep: 5,
        }
    }
}

impl RotationConfig {
    pub fn disabled() -> Self {
        Self {
            max_size_bytes: 0,
            keep: 0,
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.max_size_bytes > 0
    }
}

pub struct LocalJsonlSink {
    name: String,
    path: PathBuf,
    rotation: RotationConfig,
}

impl LocalJsonlSink {
    #[cfg(test)]
    fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            name: "local".to_string(),
            path: path.into(),
            rotation: RotationConfig::default(),
        }
    }

    pub fn with_rotation(path: impl Into<PathBuf>, rotation: RotationConfig) -> Self {
        Self {
            name: "local".to_string(),
            path: path.into(),
            rotation,
        }
    }

    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }

    pub(crate) fn rotation_namespace(
        &self,
    ) -> Result<Option<RotationNamespace>, Box<dyn std::error::Error>> {
        if !self.rotation.is_enabled() {
            return Ok(None);
        }
        let (stem, extension) = rotation_components(&self.path)?;
        Ok(Some(RotationNamespace::from_active_path(
            &self.path, &stem, &extension,
        )))
    }
}

impl EventSink for LocalJsonlSink {
    fn name(&self) -> &str {
        &self.name
    }

    fn emit(&self, events: &[Event]) -> Result<(), Box<dyn std::error::Error>> {
        let bytes = serialize_jsonl_events(events)?;
        if bytes.is_empty() {
            return Ok(());
        }
        if self.rotation.is_enabled() {
            rotation_components(&self.path)?;
        }
        let lock = SidecarLock::acquire(&self.path)?;
        ensure_jsonl_tail(&self.path)?;
        let rotated = if self.rotation.is_enabled() {
            maybe_rotate(&self.path, &self.rotation)?
        } else {
            false
        };
        let created = append_jsonl_bytes(&self.path, &bytes)?;
        if rotated || created {
            sync_parent(&self.path)?;
        }
        lock.verify_lock()?;
        Ok(())
    }
}

/// Check if the active file exceeds the rotation threshold and rotate if so.
fn maybe_rotate(path: &Path, config: &RotationConfig) -> Result<bool, Box<dyn std::error::Error>> {
    let size = match fs::metadata(path) {
        Ok(meta) => meta.len(),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(err) => return Err(err.into()),
    };

    if size < config.max_size_bytes {
        return Ok(false);
    }

    rotate_file(path, config)
}

/// Rename the active file to a date-stamped rotated file and clean up old rotations.
fn rotate_file(path: &Path, config: &RotationConfig) -> Result<bool, Box<dyn std::error::Error>> {
    let date = current_date_utc();
    let rotated = rotated_path(path, &date)?;

    // If the date-stamped file already exists (same-day rotation), append a counter.
    let mut final_path = rotated.clone();
    let mut counter = 1;
    while final_path.exists() {
        final_path = rotated_with_counter(path, &date, counter)?;
        counter += 1;
    }

    atomic_rename_no_replace(path, &final_path)?;

    cleanup_rotated_files(path, config.keep)?;
    sync_parent(path)?;
    Ok(true)
}

/// Generate the rotated file path: `telltale-events-2026-06-21.jsonl`
fn rotated_path(active: &Path, date: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let (stem, ext) = rotation_components(active)?;
    let parent = active.parent().unwrap_or_else(|| Path::new("."));
    Ok(parent.join(format!("{stem}-{date}.{ext}")))
}

/// Generate a counter-suffixed rotated path: `telltale-events-2026-06-21.1.jsonl`
fn rotated_with_counter(
    active: &Path,
    date: &str,
    counter: usize,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let (stem, ext) = rotation_components(active)?;
    let parent = active.parent().unwrap_or_else(|| Path::new("."));
    Ok(parent.join(format!("{stem}-{date}.{counter}.{ext}")))
}

fn rotation_components(active: &Path) -> Result<(String, String), Box<dyn std::error::Error>> {
    let stem = active
        .file_stem()
        .and_then(OsStr::to_str)
        .ok_or("built-in rotation requires a UTF-8 active filename")?;
    let ext = active
        .extension()
        .and_then(OsStr::to_str)
        .ok_or("built-in rotation requires a UTF-8 active filename")?;
    Ok((stem.to_string(), ext.to_string()))
}

/// A parsed rotated file name, e.g. `telltale-events-2026-06-21.3.jsonl` → (date, counter).
/// The base date-stamped file (`telltale-events-2026-06-21.jsonl`) has counter 0.
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
struct RotatedFileEntry {
    date: String,
    counter: usize,
    path: PathBuf,
}

/// Parse a rotated file name into its date and counter components.
/// Returns None if the name does not match the exact built-in rotation pattern:
/// `<stem>-YYYY-MM-DD.<ext>` or `<stem>-YYYY-MM-DD.<counter>.<ext>`
fn parse_rotated_name(name: &str, stem: &str, ext: &str) -> Option<(String, usize)> {
    let suffix = format!(".{ext}");
    let prefix = format!("{stem}-");
    let name = name.strip_prefix(&prefix)?;
    let name = name.strip_suffix(&suffix)?;
    // name is now "YYYY-MM-DD" or "YYYY-MM-DD.N"
    if let Some((date, counter_str)) = name.rsplit_once('.') {
        if is_valid_date(date) {
            let counter = counter_str.parse::<usize>().ok()?;
            return Some((date.to_string(), counter));
        }
        None
    } else if is_valid_date(name) {
        // Base date-stamped file, no counter → counter 0.
        Some((name.to_string(), 0))
    } else {
        None
    }
}

/// Check if a string is a valid `YYYY-MM-DD` date with plausible month/day values.
fn is_valid_date(s: &str) -> bool {
    if s.len() != 10 {
        return false;
    }
    let bytes = s.as_bytes();
    if bytes[4] != b'-' || bytes[7] != b'-' {
        return false;
    }
    let year = &s[..4];
    let month = &s[5..7];
    let day = &s[8..10];
    if !year.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }
    if !month.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }
    if !day.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }
    let month: u32 = month.parse().unwrap_or(0);
    let day: u32 = day.parse().unwrap_or(0);
    (1..=12).contains(&month) && (1..=31).contains(&day)
}

/// Delete rotated files beyond `keep`, oldest-first.
/// Only matches the exact built-in rotation pattern to avoid deleting
/// externally-managed files (e.g., logrotate's `telltale-events-20260621.jsonl`).
fn cleanup_rotated_files(active: &Path, keep: usize) -> Result<(), Box<dyn std::error::Error>> {
    let parent = active.parent().unwrap_or_else(|| Path::new("."));
    let (stem, ext) = rotation_components(active)?;

    let entries: Vec<_> = fs::read_dir(parent)?.collect::<Result<_, _>>()?;
    let mut rotated: Vec<RotatedFileEntry> = entries
        .into_iter()
        .filter_map(|entry| {
            let name = entry.file_name();
            let name = name.to_str()?;
            // Skip directories and symlinks — only manage regular files.
            let file_type = entry.file_type().ok()?;
            if !file_type.is_file() {
                return None;
            }
            let (date, counter) = parse_rotated_name(name, &stem, &ext)?;
            Some(RotatedFileEntry {
                date,
                counter,
                path: entry.path(),
            })
        })
        .collect();

    // Sort by (date, counter) so same-day files order correctly numerically.
    rotated.sort();

    let to_delete = if keep == 0 {
        &rotated[..]
    } else if rotated.len() > keep {
        &rotated[..rotated.len() - keep]
    } else {
        &[][..]
    };

    for file in to_delete {
        // Best-effort cleanup: don't abort the scan if one file can't be deleted.
        if let Err(err) = fs::remove_file(&file.path) {
            eprintln!(
                "warning: could not delete rotated log {}: {err}",
                file.path.display()
            );
        }
    }

    Ok(())
}

/// Current UTC date as `YYYY-MM-DD`.
fn current_date_utc() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = secs / 86_400;
    // Days since 1970-01-01 → convert to Y-M-D using a simple algorithm.
    date_from_days_since_epoch(days as i64)
}

/// Convert days since Unix epoch (1970-01-01) to `YYYY-MM-DD`.
fn date_from_days_since_epoch(days: i64) -> String {
    // Civil date algorithm from Howard Hinnant (https://howardhinnant.github.io/date_algorithms.html)
    let z = days + 719_468; // days since 0000-03-01
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}")
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use tempfile::tempdir;

    use super::{
        LocalJsonlSink, RotationConfig, cleanup_rotated_files, date_from_days_since_epoch,
        maybe_rotate, parse_rotated_name, rotated_path,
    };
    use crate::event::health_event_with_metadata;
    use crate::sink::{EventSink, emit_events};

    fn make_health_event() -> crate::event::Event {
        health_event_with_metadata(crate::event::HealthEventInput {
            sources: &[],
            source_inventory_change: None,
            scan_duration_ms: 7,
            rule_count: 3,
            threshold_config: crate::scoring::load_thresholds(),
            active_policy_name: None,
            emitted_count: 0,
            suppressed_count: 0,
            scanner_error_count: 0,
        })
    }

    #[test]
    fn local_jsonl_sink_appends_canonical_events() {
        let temp = tempdir().expect("tempdir");
        let log_path = temp.path().join("logs/telltale-events.jsonl");
        let sink = LocalJsonlSink::new(&log_path);
        let event = make_health_event();

        emit_events(&sink, &[event]).expect("emit events");

        let output = std::fs::read_to_string(log_path).expect("jsonl output");
        assert_eq!(output.lines().count(), 1);
        assert!(output.contains("\"event_type\":\"health\""));
    }

    #[test]
    fn rotation_rotates_when_file_exceeds_max_size() {
        let temp = tempdir().expect("tempdir");
        let log_path = temp.path().join("logs/telltale-events.jsonl");

        // Write enough data to exceed 100 bytes.
        let big_event = make_health_event();
        let sink = LocalJsonlSink::with_rotation(
            &log_path,
            RotationConfig {
                max_size_bytes: 100,
                keep: 5,
            },
        );
        emit_events(&sink, std::slice::from_ref(&big_event)).expect("first emit");
        // First emit should not rotate (file is new, under threshold).
        assert!(log_path.exists());
        assert!(!log_path.with_file_name("telltale-events-").exists());

        // Write more events to exceed 100 bytes.
        emit_events(&sink, std::slice::from_ref(&big_event)).expect("second emit");
        emit_events(&sink, std::slice::from_ref(&big_event)).expect("third emit");

        // By now the file should have been rotated at least once.
        // The active file should still exist with fresh content.
        assert!(log_path.exists());

        // At least one rotated file should exist.
        let parent = log_path.parent().expect("parent");
        let rotated: Vec<_> = std::fs::read_dir(parent)
            .expect("read dir")
            .filter_map(Result::ok)
            .filter(|e| {
                let name = e.file_name();
                let name = name.to_string_lossy();
                name.starts_with("telltale-events-") && name.ends_with(".jsonl")
            })
            .collect();
        assert!(
            !rotated.is_empty(),
            "expected at least one rotated file after exceeding max size"
        );
    }

    #[test]
    fn rotation_disabled_does_not_rotate() {
        let temp = tempdir().expect("tempdir");
        let log_path = temp.path().join("logs/telltale-events.jsonl");
        let sink = LocalJsonlSink::with_rotation(&log_path, RotationConfig::disabled());

        let event = make_health_event();
        for _ in 0..10 {
            emit_events(&sink, std::slice::from_ref(&event)).expect("emit");
        }

        // Active file should exist and be large (no rotation).
        let size = std::fs::metadata(&log_path).expect("metadata").len();
        assert!(size > 1000, "file should be large without rotation");

        // No rotated files should exist.
        let parent = log_path.parent().expect("parent");
        let rotated: Vec<_> = std::fs::read_dir(parent)
            .expect("read dir")
            .filter_map(Result::ok)
            .filter(|e| {
                let name = e.file_name();
                let name = name.to_string_lossy();
                name.starts_with("telltale-events-") && name.ends_with(".jsonl")
            })
            .collect();
        assert!(rotated.is_empty(), "no rotated files when disabled");
    }

    #[test]
    fn trailing_partial_jsonl_record_is_refused() {
        let temp = tempdir().expect("tempdir");
        let log_path = temp.path().join("logs/telltale-events.jsonl");
        std::fs::create_dir_all(log_path.parent().expect("parent")).expect("parent");
        std::fs::write(&log_path, b"{\"event_type\":\"partial\"").expect("partial log");

        let error = LocalJsonlSink::new(&log_path)
            .emit(&[make_health_event()])
            .expect_err("partial record must fail closed");
        assert!(error.to_string().contains("partial record"));
    }

    #[test]
    fn empty_batch_does_not_create_or_rotate_jsonl() {
        let temp = tempdir().expect("tempdir");
        let log_path = temp.path().join("logs/telltale-events.jsonl");
        LocalJsonlSink::with_rotation(
            &log_path,
            RotationConfig {
                max_size_bytes: 1,
                keep: 1,
            },
        )
        .emit(&[])
        .expect("empty batch");
        assert!(!log_path.exists());
        assert!(
            !log_path
                .with_file_name("telltale-events-2026-01-01.jsonl")
                .exists()
        );
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_active_name_fails_before_rotation() {
        use std::fs;
        use std::os::unix::ffi::OsStringExt;

        let temp = tempdir().expect("tempdir");
        let name = std::ffi::OsString::from_vec(b"events-\xff.jsonl".to_vec());
        let path = temp.path().join(name);
        fs::write(&path, b"{}\n").expect("active log");
        let error = LocalJsonlSink::with_rotation(
            &path,
            RotationConfig {
                max_size_bytes: 1,
                keep: 1,
            },
        )
        .emit(&[make_health_event()])
        .expect_err("non-UTF-8 rotation must fail closed");
        assert!(error.to_string().contains("UTF-8"));
        assert_eq!(fs::read(&path).expect("active log"), b"{}\n");
        assert_eq!(fs::read_dir(temp.path()).expect("directory").count(), 1);

        let valid = temp.path().join("events.jsonl");
        fs::write(&valid, b"{}\n").expect("valid active log");
        let unrelated = temp
            .path()
            .join(std::ffi::OsString::from_vec(b"unrelated-\xff".to_vec()));
        fs::write(&unrelated, b"unrelated").expect("unrelated file");
        LocalJsonlSink::with_rotation(
            &valid,
            RotationConfig {
                max_size_bytes: 1,
                keep: 1,
            },
        )
        .emit(&[make_health_event()])
        .expect("unrelated non-UTF-8 name must be ignored");
        assert!(fs::read(&valid).expect("valid active log").ends_with(b"\n"));
        assert!(unrelated.exists(), "unrelated non-UTF-8 file must remain");
    }

    #[test]
    fn rotated_path_uses_date_and_extension() {
        let active = Path::new("/tmp/logs/telltale-events.jsonl");
        let rotated = rotated_path(active, "2026-06-21").expect("rotated path");
        assert_eq!(
            rotated,
            Path::new("/tmp/logs/telltale-events-2026-06-21.jsonl")
        );
    }

    #[test]
    fn cleanup_deletes_oldest_beyond_keep() {
        let temp = tempdir().expect("tempdir");
        let active = temp.path().join("telltale-events.jsonl");
        // Create 5 rotated files with different dates.
        for date in [
            "2026-06-17",
            "2026-06-18",
            "2026-06-19",
            "2026-06-20",
            "2026-06-21",
        ] {
            let path = temp.path().join(format!("telltale-events-{date}.jsonl"));
            std::fs::write(&path, b"old").expect("write");
        }

        cleanup_rotated_files(&active, 3).expect("cleanup");

        // Should keep the 3 newest (by name sort): 19, 20, 21.
        let remaining: Vec<String> = std::fs::read_dir(temp.path())
            .expect("read dir")
            .filter_map(Result::ok)
            .filter(|e| {
                let name = e.file_name();
                let name = name.to_string_lossy();
                name.starts_with("telltale-events-") && name.ends_with(".jsonl")
            })
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();

        assert_eq!(remaining.len(), 3);
        assert!(remaining.iter().any(|n| n.contains("2026-06-19")));
        assert!(remaining.iter().any(|n| n.contains("2026-06-20")));
        assert!(remaining.iter().any(|n| n.contains("2026-06-21")));
        assert!(!remaining.iter().any(|n| n.contains("2026-06-17")));
        assert!(!remaining.iter().any(|n| n.contains("2026-06-18")));
    }

    #[test]
    fn cleanup_ignores_externally_managed_files() {
        let temp = tempdir().expect("tempdir");
        let active = temp.path().join("telltale-events.jsonl");

        // Built-in rotated file (should be managed).
        std::fs::write(
            temp.path().join("telltale-events-2026-06-21.jsonl"),
            b"builtin",
        )
        .expect("write");

        // External logrotate file with different date format (should be ignored).
        std::fs::write(
            temp.path().join("telltale-events-20260621.jsonl"),
            b"external",
        )
        .expect("write");

        // Manual backup file (should be ignored).
        std::fs::write(
            temp.path().join("telltale-events-manual-backup.jsonl"),
            b"manual",
        )
        .expect("write");

        // Non-matching extension (should be ignored).
        std::fs::write(temp.path().join("telltale-events-2026-06-21.log"), b"log").expect("write");

        cleanup_rotated_files(&active, 0).expect("cleanup with keep=0");

        // Built-in file should be deleted.
        assert!(
            !temp
                .path()
                .join("telltale-events-2026-06-21.jsonl")
                .exists()
        );

        // External/manual files should be untouched.
        assert!(temp.path().join("telltale-events-20260621.jsonl").exists());
        assert!(
            temp.path()
                .join("telltale-events-manual-backup.jsonl")
                .exists()
        );
        assert!(temp.path().join("telltale-events-2026-06-21.log").exists());
    }

    #[test]
    fn cleanup_orders_same_day_rotations_numerically() {
        let temp = tempdir().expect("tempdir");
        let active = temp.path().join("telltale-events.jsonl");

        // Create same-day files with counters that would sort wrong lexicographically.
        for counter in [1, 2, 10, 3] {
            let path = temp
                .path()
                .join(format!("telltale-events-2026-06-21.{counter}.jsonl"));
            std::fs::write(&path, b"old").expect("write");
        }
        // Also the base file (counter 0).
        std::fs::write(
            temp.path().join("telltale-events-2026-06-21.jsonl"),
            b"base",
        )
        .expect("write");

        // Keep 3: should keep the 3 newest by (date, counter).
        // Order: (2026-06-21, 0), (2026-06-21, 1), (2026-06-21, 2), (2026-06-21, 3), (2026-06-21, 10)
        // Keep: counter 2, 3, 10. Delete: 0, 1.
        cleanup_rotated_files(&active, 3).expect("cleanup");

        let remaining: Vec<String> = std::fs::read_dir(temp.path())
            .expect("read dir")
            .filter_map(Result::ok)
            .filter(|e| {
                let name = e.file_name();
                let name = name.to_string_lossy();
                name.starts_with("telltale-events-") && name.ends_with(".jsonl")
            })
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();

        assert_eq!(remaining.len(), 3);
        // Should keep .2, .3, .10 (the 3 highest counters).
        assert!(remaining.iter().any(|n| n.contains(".2.")));
        assert!(remaining.iter().any(|n| n.contains(".3.")));
        assert!(remaining.iter().any(|n| n.contains(".10.")));
        // Should delete base (counter 0) and .1.
        assert!(
            !remaining
                .iter()
                .any(|n| n == "telltale-events-2026-06-21.jsonl")
        );
        assert!(!remaining.iter().any(|n| n.contains(".1.")));
    }

    #[test]
    fn parse_rotated_name_matches_builtin_patterns() {
        // Base date-stamped file.
        assert_eq!(
            parse_rotated_name(
                "telltale-events-2026-06-21.jsonl",
                "telltale-events",
                "jsonl"
            ),
            Some(("2026-06-21".to_string(), 0))
        );

        // Counter file.
        assert_eq!(
            parse_rotated_name(
                "telltale-events-2026-06-21.3.jsonl",
                "telltale-events",
                "jsonl"
            ),
            Some(("2026-06-21".to_string(), 3))
        );

        // External logrotate format (YYYYMMDD, no hyphens) should NOT match.
        assert_eq!(
            parse_rotated_name("telltale-events-20260621.jsonl", "telltale-events", "jsonl"),
            None
        );

        // Manual backup should NOT match.
        assert_eq!(
            parse_rotated_name("telltale-events-manual.jsonl", "telltale-events", "jsonl"),
            None
        );

        // Non-matching extension should NOT match.
        assert_eq!(
            parse_rotated_name("telltale-events-2026-06-21.log", "telltale-events", "jsonl"),
            None
        );

        // Invalid date should NOT match.
        assert_eq!(
            parse_rotated_name(
                "telltale-events-2026-13-45.jsonl",
                "telltale-events",
                "jsonl"
            ),
            None
        );
    }

    #[test]
    fn maybe_rotate_does_nothing_when_file_under_threshold() {
        let temp = tempdir().expect("tempdir");
        let log_path = temp.path().join("telltale-events.jsonl");
        std::fs::write(&log_path, b"small").expect("write");

        let config = RotationConfig {
            max_size_bytes: 10_000,
            keep: 5,
        };
        maybe_rotate(&log_path, &config).expect("rotate check");

        // File should still be the active file, unchanged.
        let content = std::fs::read_to_string(&log_path).expect("read");
        assert_eq!(content, "small");
    }

    #[test]
    fn maybe_rotate_does_nothing_when_file_missing() {
        let temp = tempdir().expect("tempdir");
        let log_path = temp.path().join("nonexistent.jsonl");

        let config = RotationConfig {
            max_size_bytes: 100,
            keep: 5,
        };
        maybe_rotate(&log_path, &config).expect("rotate check on missing file");
    }

    #[test]
    fn date_from_days_since_epoch_matches_known_dates() {
        // 1970-01-01 = day 0
        assert_eq!(date_from_days_since_epoch(0), "1970-01-01");
        // 2026-06-21: days from 1970-01-01
        // 56 years * ~365.25 ≈ 20454 days. Let's verify with a known value.
        // 2026-01-01 = 20454 days since epoch (verified externally).
        // 2026-06-21 = 20454 + 31(jan) + 28(feb) + 31(mar) + 30(apr) + 31(may) + 21(jun) - 1
        //            = 20454 + 171 = 20625
        assert_eq!(date_from_days_since_epoch(20_625), "2026-06-21");
        // 2000-02-29 (leap day)
        // 2000-01-01 = 10957 days since epoch
        // 2000-02-29 = 10957 + 31 + 29 - 1 = 11016
        assert_eq!(date_from_days_since_epoch(11_016), "2000-02-29");
    }
}
