//! The local JSONL sink: the canonical first write, with append, tail repair
//! and date-based rotation.

use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::event::{Event, PrivacySanitizer, SanitizationContext, serialize_event_for_emission};
use crate::file_lock::{
    RotationNamespace, SidecarLock, atomic_rename_no_replace, open_append, safe_path_info,
    sync_parent,
};
use crate::sink::EventSink;
use telltale_sources::journal;

pub(crate) fn serialize_jsonl_events(
    events: &[Event],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut bytes = Vec::new();
    for event in events {
        let mut serializer = serde_json::Serializer::new(&mut bytes);
        serialize_event_for_emission(event, &mut serializer)?;
        bytes.push(b'\n');
    }
    Ok(bytes)
}

fn append_jsonl_bytes(path: &Path, bytes: &[u8]) -> Result<bool, Box<dyn std::error::Error>> {
    ensure_jsonl_tail(path)?;
    let (mut file, created, info) = open_append(path)?;
    file.write_all(bytes)?;
    file.flush()?;
    file.sync_all()?;
    let current = safe_path_info(path)?.ok_or("log target disappeared during append")?;
    if current.identity != info.identity || current.links != info.links {
        return Err("log target changed during append".into());
    }
    Ok(created)
}

fn ensure_jsonl_tail(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = match OpenOptions::new().read(true).open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    let length = file.metadata()?.len();
    if length == 0 {
        return Ok(());
    }
    file.seek(SeekFrom::End(-1))?;
    let mut last = [0u8; 1];
    file.read_exact(&mut last)?;
    if last[0] != b'\n' {
        return Err(
            "local JSONL ends with a partial record; repair or replace it before retrying".into(),
        );
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn append_jsonl_events(
    path: &Path,
    events: &[Event],
) -> Result<(), Box<dyn std::error::Error>> {
    let bytes = serialize_jsonl_events(events)?;
    if bytes.is_empty() {
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let _lock = SidecarLock::acquire_lock_only(path)?;
    let created = append_jsonl_bytes(path, &bytes)?;
    if created {
        sync_parent(path)?;
    }
    Ok(())
}

pub use journal::RotationConfig;

pub struct LocalJsonlSink {
    name: String,
    path: PathBuf,
    rotation: RotationConfig,
    preserve_rotated: bool,
}

impl LocalJsonlSink {
    #[cfg(test)]
    fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            name: "local".to_string(),
            path: path.into(),
            rotation: RotationConfig::default(),
            preserve_rotated: false,
        }
    }

    pub fn with_rotation(path: impl Into<PathBuf>, rotation: RotationConfig) -> Self {
        Self {
            name: "local".to_string(),
            path: path.into(),
            rotation,
            preserve_rotated: false,
        }
    }

    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }

    /// Keep rotated generations for durable cursor coordination. Ordinary
    /// rotation keeps its existing keep-based cleanup behavior.
    pub(crate) fn with_durable_rotation(mut self) -> Self {
        self.preserve_rotated = true;
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
        self.emit_jsonl_bytes(&bytes)
    }

    fn emit_canonical_jsonl_bytes(&self, bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        self.emit_jsonl_bytes(bytes)
    }
}

impl LocalJsonlSink {
    fn emit_jsonl_bytes(&self, bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        if bytes.is_empty() {
            return Ok(());
        }
        if self.rotation.is_enabled() {
            rotation_components(&self.path)?;
        }
        let lock = SidecarLock::acquire_lock_only(&self.path)?;
        ensure_jsonl_tail(&self.path)?;
        let rotated = if self.rotation.is_enabled() {
            maybe_rotate_with_mode(&self.path, &self.rotation, self.preserve_rotated)?
        } else {
            false
        };
        let created = append_jsonl_bytes(&self.path, bytes)?;
        if rotated || created {
            sync_parent(&self.path)?;
        }
        lock.verify_lock()?;
        Ok(())
    }
}

/// A JSONL generation in oldest-to-newest journal order. The identity is
/// derived from the platform file identity and therefore survives a rename.
#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct JsonlGeneration {
    pub(crate) path: PathBuf,
    pub(crate) identity: String,
    pub(crate) is_active: bool,
}

/// Discover the active file and exact built-in rotated generations. Matching
/// names that are not regular files fail closed rather than being ignored, so
/// a symlink cannot hide a replay source from durable ingest.
pub(crate) fn discover_jsonl_generations(
    active: &Path,
) -> Result<Vec<JsonlGeneration>, Box<dyn std::error::Error>> {
    Ok(journal::discover_generations(active, usize::MAX)?
        .generations
        .into_iter()
        .map(|generation| JsonlGeneration {
            path: generation.path,
            identity: generation.identity,
            is_active: generation.is_active,
        })
        .collect())
}

/// Check if the active file exceeds the rotation threshold and rotate if so.
fn maybe_rotate_with_mode(
    path: &Path,
    config: &RotationConfig,
    preserve_rotated: bool,
) -> Result<bool, Box<dyn std::error::Error>> {
    let size = match fs::metadata(path) {
        Ok(meta) => meta.len(),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(err) => return Err(err.into()),
    };

    if size < config.max_size_bytes {
        return Ok(false);
    }

    rotate_file(path, config, preserve_rotated)
}

/// Rename the active file to a date-stamped rotated file and clean up old rotations.
fn rotate_file(
    path: &Path,
    config: &RotationConfig,
    preserve_rotated: bool,
) -> Result<bool, Box<dyn std::error::Error>> {
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

    if !preserve_rotated {
        cleanup_rotated_files(path, config.keep)?;
    }
    sync_parent(path)?;
    Ok(true)
}

/// Generate the rotated file path: `telltale-events-2026-06-21.jsonl`
fn rotated_path(active: &Path, date: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    Ok(journal::rotated_path(active, date, 0)?)
}

/// Generate a counter-suffixed rotated path: `telltale-events-2026-06-21.1.jsonl`
fn rotated_with_counter(
    active: &Path,
    date: &str,
    counter: usize,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    Ok(journal::rotated_path(active, date, counter)?)
}

fn rotation_components(active: &Path) -> Result<(String, String), Box<dyn std::error::Error>> {
    Ok(journal::rotation_components(active)?)
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
    journal::parse_rotated_name(name, stem, ext)
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
            let rendered = format!(
                "warning: could not delete rotated log {}: {err}",
                file.path.display()
            );
            eprintln!(
                "{}",
                PrivacySanitizer::sanitize(SanitizationContext::Diagnostic, &rendered)
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
mod tests;
