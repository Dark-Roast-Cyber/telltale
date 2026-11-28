use std::path::Path;

use tempfile::tempdir;

use super::{
    LocalJsonlSink, RotationConfig, cleanup_rotated_files, date_from_days_since_epoch,
    maybe_rotate_with_mode, parse_rotated_name, rotated_path,
};
use crate::sink::test_support::make_health_event;
use crate::sink::{EventSink, emit_events};

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
    let rotated = || -> Vec<_> {
        std::fs::read_dir(log_path.parent().expect("parent"))
            .expect("read dir")
            .filter_map(Result::ok)
            .filter(|e| {
                let name = e.file_name();
                let name = name.to_string_lossy();
                name.starts_with("telltale-events-") && name.ends_with(".jsonl")
            })
            .collect()
    };
    emit_events(&sink, std::slice::from_ref(&big_event)).expect("first emit");
    // First emit should not rotate (file is new, under threshold).
    assert!(log_path.exists());
    assert!(rotated().is_empty(), "the first emit rotated a new file");

    // Write more events to exceed 100 bytes.
    emit_events(&sink, std::slice::from_ref(&big_event)).expect("second emit");
    emit_events(&sink, std::slice::from_ref(&big_event)).expect("third emit");

    // By now the file should have been rotated at least once.
    // The active file should still exist with fresh content.
    assert!(log_path.exists());
    assert!(
        !rotated().is_empty(),
        "expected at least one rotated file after exceeding max size"
    );
}

#[test]
fn non_durable_rotation_keeps_only_the_configured_number_of_generations() {
    let temp = tempdir().expect("tempdir");
    let log_path = temp.path().join("logs/telltale-events.jsonl");
    let sink = LocalJsonlSink::with_rotation(
        &log_path,
        RotationConfig {
            max_size_bytes: 1,
            keep: 1,
        },
    );
    let event = make_health_event();

    for _ in 0..4 {
        sink.emit(std::slice::from_ref(&event)).expect("emit event");
    }

    let generations = super::discover_jsonl_generations(&log_path).expect("discover files");
    assert!(generations.iter().any(|generation| generation.is_active));
    assert_eq!(
        generations
            .iter()
            .filter(|generation| !generation.is_active)
            .count(),
        1,
        "non-durable rotation must retain its existing keep policy"
    );
}

#[test]
fn reopening_non_durable_sink_appends_without_changing_rotation_policy() {
    let temp = tempdir().expect("tempdir");
    let log_path = temp.path().join("logs/telltale-events.jsonl");
    let event = make_health_event();
    let rotation = RotationConfig {
        max_size_bytes: 10_000,
        keep: 2,
    };
    LocalJsonlSink::with_rotation(&log_path, rotation.clone())
        .emit(std::slice::from_ref(&event))
        .expect("first process emit");
    drop(LocalJsonlSink::with_rotation(&log_path, rotation).emit(&[event]));

    let contents = std::fs::read_to_string(&log_path).expect("reopened JSONL");
    assert_eq!(contents.lines().count(), 2);
    assert_eq!(
        super::discover_jsonl_generations(&log_path)
            .expect("discover reopened files")
            .iter()
            .filter(|generation| !generation.is_active)
            .count(),
        0
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
    // Nothing is written, not even the log directory or a lock file.
    assert!(!log_path.parent().expect("parent").exists());
}

#[cfg(target_os = "linux")]
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
    maybe_rotate_with_mode(&log_path, &config, false).expect("rotate check");

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
    maybe_rotate_with_mode(&log_path, &config, false).expect("rotate check on missing file");
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

#[cfg(test)]
mod privacy;
