use std::ffi::OsStr;
use std::fs;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Serialize;

use crate::event::{Event, append_jsonl_events, parse_event_timestamp};

pub trait EventSink {
    fn emit(&self, events: &[Event]) -> Result<(), Box<dyn std::error::Error>>;
}

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

pub struct LocalJsonlSink<'a> {
    path: &'a Path,
    rotation: RotationConfig,
}

impl<'a> LocalJsonlSink<'a> {
    pub fn new(path: &'a Path) -> Self {
        Self {
            path,
            rotation: RotationConfig::default(),
        }
    }

    pub fn with_rotation(path: &'a Path, rotation: RotationConfig) -> Self {
        Self { path, rotation }
    }
}

impl EventSink for LocalJsonlSink<'_> {
    fn emit(&self, events: &[Event]) -> Result<(), Box<dyn std::error::Error>> {
        if self.rotation.is_enabled() {
            maybe_rotate(self.path, &self.rotation)?;
        }
        append_jsonl_events(self.path, events)
    }
}

/// Check if the active file exceeds the rotation threshold and rotate if so.
fn maybe_rotate(path: &Path, config: &RotationConfig) -> Result<(), Box<dyn std::error::Error>> {
    let size = match fs::metadata(path) {
        Ok(meta) => meta.len(),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err.into()),
    };

    if size < config.max_size_bytes {
        return Ok(());
    }

    rotate_file(path, config)
}

/// Rename the active file to a date-stamped rotated file and clean up old rotations.
fn rotate_file(path: &Path, config: &RotationConfig) -> Result<(), Box<dyn std::error::Error>> {
    let date = current_date_utc();
    let rotated = rotated_path(path, &date);

    // If the date-stamped file already exists (same-day rotation), append a counter.
    let mut final_path = rotated.clone();
    let mut counter = 1;
    while final_path.exists() {
        final_path = rotated_with_counter(path, &date, counter);
        counter += 1;
    }

    fs::rename(path, &final_path)?;

    cleanup_rotated_files(path, config.keep)?;

    Ok(())
}

/// Generate the rotated file path: `adr-events-2026-06-21.jsonl`
fn rotated_path(active: &Path, date: &str) -> PathBuf {
    let stem = active
        .file_stem()
        .and_then(OsStr::to_str)
        .unwrap_or("adr-events");
    let ext = active
        .extension()
        .and_then(OsStr::to_str)
        .unwrap_or("jsonl");
    let parent = active.parent().unwrap_or_else(|| Path::new("."));
    parent.join(format!("{stem}-{date}.{ext}"))
}

/// Generate a counter-suffixed rotated path: `adr-events-2026-06-21.1.jsonl`
fn rotated_with_counter(active: &Path, date: &str, counter: usize) -> PathBuf {
    let stem = active
        .file_stem()
        .and_then(OsStr::to_str)
        .unwrap_or("adr-events");
    let ext = active
        .extension()
        .and_then(OsStr::to_str)
        .unwrap_or("jsonl");
    let parent = active.parent().unwrap_or_else(|| Path::new("."));
    parent.join(format!("{stem}-{date}.{counter}.{ext}"))
}

/// A parsed rotated file name, e.g. `adr-events-2026-06-21.3.jsonl` → (date, counter).
/// The base date-stamped file (`adr-events-2026-06-21.jsonl`) has counter 0.
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
/// externally-managed files (e.g., logrotate's `adr-events-20260621.jsonl`).
fn cleanup_rotated_files(active: &Path, keep: usize) -> Result<(), Box<dyn std::error::Error>> {
    let parent = active.parent().unwrap_or_else(|| Path::new("."));
    let stem = active
        .file_stem()
        .and_then(OsStr::to_str)
        .unwrap_or("adr-events");
    let ext = active
        .extension()
        .and_then(OsStr::to_str)
        .unwrap_or("jsonl");

    let mut rotated: Vec<RotatedFileEntry> = fs::read_dir(parent)?
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            // Skip directories and symlinks — only manage regular files.
            let file_type = entry.file_type().ok()?;
            if !file_type.is_file() {
                return None;
            }
            let (date, counter) = parse_rotated_name(&name, stem, ext)?;
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

pub struct SplunkHecHttpSink {
    endpoint: String,
    token: String,
    config: SplunkHecConfig,
    timeout: Duration,
}

impl SplunkHecHttpSink {
    pub fn new(endpoint: String, token: String, config: SplunkHecConfig) -> Self {
        Self {
            endpoint,
            token,
            config,
            timeout: Duration::from_secs(10),
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

impl EventSink for SplunkHecHttpSink {
    fn emit(&self, events: &[Event]) -> Result<(), Box<dyn std::error::Error>> {
        for envelope in splunk_hec_envelopes(events, &self.config) {
            send_splunk_hec_envelope(&self.endpoint, &self.token, &envelope, self.timeout)?;
        }
        Ok(())
    }
}

pub fn emit_events(
    sink: &dyn EventSink,
    events: &[Event],
) -> Result<(), Box<dyn std::error::Error>> {
    sink.emit(events)
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SplunkHecConfig {
    pub index: Option<String>,
    pub sourcetype: String,
    pub source: Option<String>,
    pub host: Option<String>,
}

impl Default for SplunkHecConfig {
    fn default() -> Self {
        Self {
            index: Some("adr".to_string()),
            sourcetype: "adr:json".to_string(),
            source: Some("telltale:adr".to_string()),
            host: None,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct SplunkHecEnvelope<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub index: Option<&'a str>,
    pub sourcetype: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<&'a str>,
    pub event: &'a Event,
}

impl<'a> SplunkHecEnvelope<'a> {
    fn new(event: &'a Event, config: &'a SplunkHecConfig) -> Self {
        Self {
            time: splunk_hec_time(&event.timestamp),
            host: config.host.as_deref(),
            index: config.index.as_deref(),
            sourcetype: &config.sourcetype,
            source: config.source.as_deref(),
            event,
        }
    }
}

pub fn splunk_hec_envelopes<'a>(
    events: &'a [Event],
    config: &'a SplunkHecConfig,
) -> Vec<SplunkHecEnvelope<'a>> {
    events
        .iter()
        .map(|event| SplunkHecEnvelope::new(event, config))
        .collect()
}

fn splunk_hec_time(timestamp: &str) -> Option<f64> {
    let parsed = parse_event_timestamp(timestamp)?;
    Some(parsed.unix_timestamp() as f64 + f64::from(parsed.nanosecond()) / 1_000_000_000.0)
}

fn send_splunk_hec_envelope(
    endpoint: &str,
    token: &str,
    envelope: &SplunkHecEnvelope<'_>,
    timeout: Duration,
) -> Result<(), Box<dyn std::error::Error>> {
    let (host, port, path) = parse_http_endpoint(endpoint)?;
    let address = (host.as_str(), port)
        .to_socket_addrs()?
        .next()
        .ok_or("could not resolve Splunk HEC host")?;
    let mut stream = TcpStream::connect_timeout(&address, timeout)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    let payload = serde_json::to_vec(envelope)?;
    let request = format!(
        "POST {} HTTP/1.1\r\nHost: {}:{}\r\nAuthorization: Splunk {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        path,
        host,
        port,
        token,
        payload.len()
    );
    stream.write_all(request.as_bytes())?;
    stream.write_all(&payload)?;
    stream.shutdown(Shutdown::Write)?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    let status_line = response
        .lines()
        .next()
        .ok_or("invalid Splunk HEC response")?;
    let status = status_line
        .split_whitespace()
        .nth(1)
        .ok_or("missing Splunk HEC response status")?
        .parse::<u16>()?;
    if (200..300).contains(&status) {
        Ok(())
    } else {
        Err(format!("Splunk HEC request failed with HTTP {status}").into())
    }
}

fn parse_http_endpoint(
    endpoint: &str,
) -> Result<(String, u16, String), Box<dyn std::error::Error>> {
    let endpoint = endpoint
        .strip_prefix("http://")
        .ok_or("only http:// Splunk HEC endpoints are supported")?;
    let (host_port, path) = match endpoint.split_once('/') {
        Some((host_port, "")) => (host_port, "/services/collector".to_string()),
        Some((host_port, rest)) => (host_port, format!("/{}", rest)),
        None => (endpoint, "/services/collector".to_string()),
    };
    let (host, port) = match host_port.split_once(':') {
        Some((host, port)) => (host.to_string(), port.parse()?),
        None => (host_port.to_string(), 8088),
    };
    Ok((host, port, path))
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::path::Path;
    use std::sync::mpsc;
    use std::thread;
    use std::time::{Duration, Instant};

    use tempfile::tempdir;

    use crate::event::health_event_with_metadata;
    use crate::sink::{
        LocalJsonlSink, RotationConfig, SplunkHecConfig, SplunkHecHttpSink, cleanup_rotated_files,
        date_from_days_since_epoch, emit_events, maybe_rotate, parse_http_endpoint,
        parse_rotated_name, rotated_path, splunk_hec_envelopes,
    };

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
        let log_path = temp.path().join("logs/adr-events.jsonl");
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
        let log_path = temp.path().join("logs/adr-events.jsonl");

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
        assert!(!log_path.with_file_name("adr-events-").exists());

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
                name.starts_with("adr-events-") && name.ends_with(".jsonl")
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
        let log_path = temp.path().join("logs/adr-events.jsonl");
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
                name.starts_with("adr-events-") && name.ends_with(".jsonl")
            })
            .collect();
        assert!(rotated.is_empty(), "no rotated files when disabled");
    }

    #[test]
    fn rotated_path_uses_date_and_extension() {
        let active = Path::new("/tmp/logs/adr-events.jsonl");
        let rotated = rotated_path(active, "2026-06-21");
        assert_eq!(rotated, Path::new("/tmp/logs/adr-events-2026-06-21.jsonl"));
    }

    #[test]
    fn cleanup_deletes_oldest_beyond_keep() {
        let temp = tempdir().expect("tempdir");
        let active = temp.path().join("adr-events.jsonl");
        // Create 5 rotated files with different dates.
        for date in [
            "2026-06-17",
            "2026-06-18",
            "2026-06-19",
            "2026-06-20",
            "2026-06-21",
        ] {
            let path = temp.path().join(format!("adr-events-{date}.jsonl"));
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
                name.starts_with("adr-events-") && name.ends_with(".jsonl")
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
        let active = temp.path().join("adr-events.jsonl");

        // Built-in rotated file (should be managed).
        std::fs::write(temp.path().join("adr-events-2026-06-21.jsonl"), b"builtin").expect("write");

        // External logrotate file with different date format (should be ignored).
        std::fs::write(temp.path().join("adr-events-20260621.jsonl"), b"external").expect("write");

        // Manual backup file (should be ignored).
        std::fs::write(
            temp.path().join("adr-events-manual-backup.jsonl"),
            b"manual",
        )
        .expect("write");

        // Non-matching extension (should be ignored).
        std::fs::write(temp.path().join("adr-events-2026-06-21.log"), b"log").expect("write");

        cleanup_rotated_files(&active, 0).expect("cleanup with keep=0");

        // Built-in file should be deleted.
        assert!(!temp.path().join("adr-events-2026-06-21.jsonl").exists());

        // External/manual files should be untouched.
        assert!(temp.path().join("adr-events-20260621.jsonl").exists());
        assert!(temp.path().join("adr-events-manual-backup.jsonl").exists());
        assert!(temp.path().join("adr-events-2026-06-21.log").exists());
    }

    #[test]
    fn cleanup_orders_same_day_rotations_numerically() {
        let temp = tempdir().expect("tempdir");
        let active = temp.path().join("adr-events.jsonl");

        // Create same-day files with counters that would sort wrong lexicographically.
        for counter in [1, 2, 10, 3] {
            let path = temp
                .path()
                .join(format!("adr-events-2026-06-21.{counter}.jsonl"));
            std::fs::write(&path, b"old").expect("write");
        }
        // Also the base file (counter 0).
        std::fs::write(temp.path().join("adr-events-2026-06-21.jsonl"), b"base").expect("write");

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
                name.starts_with("adr-events-") && name.ends_with(".jsonl")
            })
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();

        assert_eq!(remaining.len(), 3);
        // Should keep .2, .3, .10 (the 3 highest counters).
        assert!(remaining.iter().any(|n| n.contains(".2.")));
        assert!(remaining.iter().any(|n| n.contains(".3.")));
        assert!(remaining.iter().any(|n| n.contains(".10.")));
        // Should delete base (counter 0) and .1.
        assert!(!remaining.iter().any(|n| n == "adr-events-2026-06-21.jsonl"));
        assert!(!remaining.iter().any(|n| n.contains(".1.")));
    }

    #[test]
    fn parse_rotated_name_matches_builtin_patterns() {
        // Base date-stamped file.
        assert_eq!(
            parse_rotated_name("adr-events-2026-06-21.jsonl", "adr-events", "jsonl"),
            Some(("2026-06-21".to_string(), 0))
        );

        // Counter file.
        assert_eq!(
            parse_rotated_name("adr-events-2026-06-21.3.jsonl", "adr-events", "jsonl"),
            Some(("2026-06-21".to_string(), 3))
        );

        // External logrotate format (YYYYMMDD, no hyphens) should NOT match.
        assert_eq!(
            parse_rotated_name("adr-events-20260621.jsonl", "adr-events", "jsonl"),
            None
        );

        // Manual backup should NOT match.
        assert_eq!(
            parse_rotated_name("adr-events-manual.jsonl", "adr-events", "jsonl"),
            None
        );

        // Non-matching extension should NOT match.
        assert_eq!(
            parse_rotated_name("adr-events-2026-06-21.log", "adr-events", "jsonl"),
            None
        );

        // Invalid date should NOT match.
        assert_eq!(
            parse_rotated_name("adr-events-2026-13-45.jsonl", "adr-events", "jsonl"),
            None
        );
    }

    #[test]
    fn maybe_rotate_does_nothing_when_file_under_threshold() {
        let temp = tempdir().expect("tempdir");
        let log_path = temp.path().join("adr-events.jsonl");
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

    #[test]
    fn splunk_hec_envelope_wraps_canonical_event_with_transport_metadata() {
        let mut event = health_event_with_metadata(crate::event::HealthEventInput {
            sources: &[],
            source_inventory_change: None,
            scan_duration_ms: 7,
            rule_count: 3,
            threshold_config: crate::scoring::load_thresholds(),
            active_policy_name: None,
            emitted_count: 0,
            suppressed_count: 0,
            scanner_error_count: 0,
        });
        event.timestamp = "2026-05-18T02:00:00.000Z".to_string();
        let config = SplunkHecConfig {
            index: Some("adr".to_string()),
            sourcetype: "adr:json".to_string(),
            source: Some("telltale:adr-events".to_string()),
            host: Some("developer-workstation".to_string()),
        };

        let events = vec![event];
        let envelopes = splunk_hec_envelopes(&events, &config);
        let envelope = serde_json::to_value(&envelopes[0]).expect("serialize hec envelope");

        assert_eq!(envelope["index"], "adr");
        assert_eq!(envelope["sourcetype"], "adr:json");
        assert_eq!(envelope["source"], "telltale:adr-events");
        assert_eq!(envelope["host"], "developer-workstation");
        assert_eq!(envelope["time"], 1_779_069_600.0);
        assert_eq!(envelope["event"]["event_type"], "health");
        assert_eq!(envelope["event"]["schema_version"], "1.0");
        assert!(envelope["event"].get("index").is_none());
        assert!(envelope["event"].get("sourcetype").is_none());
    }

    #[test]
    fn splunk_hec_http_sink_posts_envelope_to_collector() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("mock hec listener");
        listener
            .set_nonblocking(true)
            .expect("nonblocking listener");
        let addr = listener.local_addr().expect("listener addr");
        let (tx, rx) = mpsc::channel();
        let handle = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(5);
            while Instant::now() < deadline {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream
                            .set_read_timeout(Some(Duration::from_secs(2)))
                            .expect("read timeout");
                        let mut request = Vec::new();
                        let mut buf = [0_u8; 1024];
                        while let Ok(read) = stream.read(&mut buf) {
                            if read == 0 {
                                break;
                            }
                            request.extend_from_slice(&buf[..read]);
                            let text = String::from_utf8_lossy(&request);
                            if let Some((headers, body)) = text.split_once("\r\n\r\n") {
                                let content_length = headers
                                    .lines()
                                    .find_map(|line| line.strip_prefix("Content-Length: "))
                                    .and_then(|value| value.parse::<usize>().ok())
                                    .unwrap_or(0);
                                if body.len() >= content_length {
                                    break;
                                }
                            }
                        }
                        tx.send(String::from_utf8_lossy(&request).to_string())
                            .expect("request capture");
                        stream
                            .write_all(
                                b"HTTP/1.1 200 OK\r\nContent-Length: 17\r\nConnection: close\r\n\r\n{\"text\":\"ok\"}\n",
                            )
                            .expect("mock hec response");
                        return;
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(20));
                    }
                    Err(err) => panic!("mock hec accept failed: {err}"),
                }
            }
            panic!("mock hec listener timed out");
        });

        let mut event = health_event_with_metadata(crate::event::HealthEventInput {
            sources: &[],
            source_inventory_change: None,
            scan_duration_ms: 7,
            rule_count: 3,
            threshold_config: crate::scoring::load_thresholds(),
            active_policy_name: None,
            emitted_count: 0,
            suppressed_count: 0,
            scanner_error_count: 0,
        });
        event.timestamp = "2026-05-18T02:00:00.000Z".to_string();
        let sink = SplunkHecHttpSink::new(
            format!("http://{addr}/services/collector"),
            "test-token".to_string(),
            SplunkHecConfig::default(),
        )
        .with_timeout(Duration::from_secs(2));

        emit_events(&sink, &[event]).expect("emit hec event");
        let request = rx.recv_timeout(Duration::from_secs(2)).expect("request");
        handle.join().expect("mock hec join");

        assert!(request.starts_with("POST /services/collector HTTP/1.1"));
        assert!(request.contains("Authorization: Splunk test-token"));
        assert!(request.contains("Content-Type: application/json"));
        let body = request.split_once("\r\n\r\n").expect("body split").1;
        let envelope: serde_json::Value = serde_json::from_str(body).expect("hec body");
        assert_eq!(envelope["index"], "adr");
        assert_eq!(envelope["sourcetype"], "adr:json");
        assert_eq!(envelope["event"]["event_type"], "health");
    }

    #[test]
    fn parse_http_endpoint_maps_trailing_slash_to_default_collector_path() {
        let (host, port, path) =
            parse_http_endpoint("http://127.0.0.1:8088/").expect("parse endpoint");

        assert_eq!(host, "127.0.0.1");
        assert_eq!(port, 8088);
        assert_eq!(path, "/services/collector");
    }
}
