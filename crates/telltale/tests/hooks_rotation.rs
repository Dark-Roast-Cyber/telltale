#![cfg(feature = "hooks")]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Barrier;

use telltale_core::HooksRecordV1;
use telltale_core::hooks::telemetry::{
    Harness, Kind, Producer, Record, RotationConfig, Session, Sink,
};
use telltale_sources::journal::discover_generations;

fn record(id: usize) -> Record {
    Record {
        schema: "telltale_hooks.record.v1",
        record_id: format!("tth:{id:032x}"),
        recorded_at: "2026-11-26T00:00:00Z".into(),
        kind: Kind::Lifecycle,
        producer: Producer {
            name: "telltale-hooks",
            version: "0.8.0",
            telltale_rev: "0123456789012345678901234567890123456789",
            semantic_identity: None,
        },
        harness: Harness {
            name: "claude-code",
            hook_event: "SessionStart".into(),
            permission_mode: None,
        },
        session: Session {
            session_id: "synthetic-session".into(),
            agent_id: None,
            agent_type: None,
            prompt_id: None,
            cwd_sha256: None,
        },
        action: None,
        evaluation: None,
        decision: None,
        outcome: None,
        lifecycle: Some(serde_json::json!({"event": "session_start", "source": null})),
        error_code: None,
        lock_wait_ms: None,
        telltale: Vec::new(),
    }
}

fn ids(path: &Path) -> Vec<Vec<String>> {
    discover_generations(path, 4096)
        .unwrap()
        .generations
        .iter()
        .map(|generation| {
            std::fs::read_to_string(&generation.path)
                .unwrap()
                .split_inclusive('\n')
                .map(|line| {
                    assert!(line.ends_with('\n'));
                    HooksRecordV1::from_json(line.as_bytes()).unwrap().record_id
                })
                .collect()
        })
        .collect()
}

fn limit() -> u64 {
    (serde_json::to_vec(&record(0)).unwrap().len() + 1) as u64
}

fn sink(path: &Path, max_size_bytes: u64, keep: usize) -> Sink {
    Sink::with_rotation(
        path.to_owned(),
        RotationConfig {
            max_size_bytes,
            keep,
        },
    )
}

#[test]
fn rotation_keeps_only_the_newest_archives() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("records.jsonl");
    let sink = sink(&path, limit() * 2, 1);
    sink.write(&record(1)).unwrap();
    sink.write(&record(2)).unwrap();
    assert_eq!(ids(&path), [vec![record(1).record_id, record(2).record_id]]);
    sink.write(&record(3)).unwrap();
    assert_eq!(ids(&path)[0], [record(1).record_id, record(2).record_id]);
    sink.write(&record(4)).unwrap();
    sink.write(&record(5)).unwrap();
    assert_eq!(
        ids(&path),
        [
            vec![record(3).record_id, record(4).record_id],
            vec![record(5).record_id],
        ]
    );
}

#[test]
fn disabled_rotation_and_records_larger_than_the_threshold() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("records.jsonl");
    let disabled = sink(&path, 0, 0);
    disabled.write(&record(1)).unwrap();
    disabled.write(&record(2)).unwrap();
    assert_eq!(ids(&path), [vec![record(1).record_id, record(2).record_id]]);

    let path = dir.path().join("small.jsonl");
    let enabled = sink(&path, 1, 2);
    enabled.write(&record(3)).unwrap();
    enabled.write(&record(4)).unwrap();
    assert_eq!(
        ids(&path),
        [vec![record(3).record_id], vec![record(4).record_id]]
    );

    let path = dir.path().join("no-archives.jsonl");
    let enabled = sink(&path, 1, 0);
    enabled.write(&record(5)).unwrap();
    enabled.write(&record(6)).unwrap();
    assert_eq!(ids(&path), [vec![record(6).record_id]]);
}

#[test]
fn failed_rotation_appends_and_reports() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("records.jsonl");
    let sink = sink(&path, limit(), 4);
    sink.write(&record(1)).unwrap();
    // A matching unsafe generation makes discovery fail before rename.
    std::fs::create_dir(dir.path().join("records-2026-11-26.jsonl")).unwrap();
    sink.write(&record(2)).unwrap();
    let wire = std::fs::read_to_string(path).unwrap();
    assert_eq!(wire.lines().count(), 2);
    assert_eq!(
        HooksRecordV1::from_json(wire.lines().last().unwrap().as_bytes())
            .unwrap()
            .record_id,
        record(2).record_id
    );
}

#[cfg(unix)]
#[test]
fn unwritable_directory_does_not_drop_the_append() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("records.jsonl");
    let sink = sink(&path, limit(), 4);
    sink.write(&record(1)).unwrap();
    let permissions = |mode| std::fs::Permissions::from_mode(mode);
    std::fs::set_permissions(dir.path(), permissions(0o500)).unwrap();
    let result = sink.write(&record(2));
    std::fs::set_permissions(dir.path(), permissions(0o700)).unwrap();
    let rows = ids(&path);
    assert_eq!(
        rows.into_iter().flatten().collect::<Vec<_>>(),
        [record(1).record_id, record(2).record_id]
    );
    result.unwrap();
}

#[test]
fn held_sidecar_lock_does_not_delay_or_drop_the_append() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("records.jsonl");
    let sink = sink(&path, limit(), 0);
    sink.write(&record(1)).unwrap();
    let held = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(dir.path().join("records.jsonl.lock"))
        .unwrap();
    // Wait for the lock: another test in this binary may be between fork and
    // exec, where its child still holds a copy of the first write's handle.
    held.lock().unwrap();
    let started = std::time::Instant::now();
    let result = sink.write(&record(2));
    assert!(started.elapsed() < std::time::Duration::from_secs(2));
    result.unwrap();
    assert_eq!(ids(&path), [vec![record(1).record_id, record(2).record_id]]);
    drop(held);
}

#[test]
fn unusable_sidecar_still_allows_an_append_without_rotation() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("records.jsonl");
    std::fs::create_dir(dir.path().join("records.jsonl.lock")).unwrap();
    let sink = sink(&path, 1, 0);
    sink.write(&record(1)).unwrap();
    sink.write(&record(2)).unwrap();
    assert_eq!(ids(&path), [vec![record(1).record_id, record(2).record_id]]);
}

#[test]
fn a_directory_over_the_discovery_bound_is_neither_rotated_nor_pruned() {
    use telltale_sources::journal::DEFAULT_MAX_DIRECTORY_ENTRIES;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("records.jsonl");
    let archive = dir.path().join("records-2026-11-26.jsonl");
    let sink = sink(&path, limit(), 0);
    sink.write(&record(1)).unwrap();
    std::fs::write(&archive, b"synthetic archive").unwrap();
    // Active, sidecar and archive already occupy three entries.
    for index in 0..DEFAULT_MAX_DIRECTORY_ENTRIES - 2 {
        std::fs::write(dir.path().join(format!("synthetic-{index}")), b"").unwrap();
    }
    sink.write(&record(2)).unwrap();
    let wire = std::fs::read_to_string(path).unwrap();
    assert_eq!(
        wire.lines()
            .map(|line| HooksRecordV1::from_json(line.as_bytes()).unwrap().record_id)
            .collect::<Vec<_>>(),
        [record(1).record_id, record(2).record_id]
    );
    assert_eq!(std::fs::read(archive).unwrap(), b"synthetic archive");
}

const WRITERS: usize = 4;
const RECORDS: usize = 8;

fn assert_every_record(path: &Path) {
    let rows: Vec<_> = ids(path).into_iter().flatten().collect();
    assert_eq!(rows.len(), WRITERS * RECORDS);
    assert_eq!(
        rows.into_iter().collect::<BTreeSet<_>>(),
        (0..WRITERS * RECORDS)
            .map(|id| record(id).record_id)
            .collect(),
    );
}

fn append(path: &Path, writer: usize) {
    let sink = sink(path, limit() * 3, WRITERS * RECORDS);
    for id in writer * RECORDS..(writer + 1) * RECORDS {
        sink.write(&record(id)).unwrap();
    }
}

#[test]
fn concurrent_rotation_threads() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("records.jsonl");
    let start = Barrier::new(WRITERS);
    std::thread::scope(|scope| {
        for writer in 0..WRITERS {
            let (start, path) = (&start, &path);
            scope.spawn(move || {
                start.wait();
                append(path, writer);
            });
        }
    });
    assert_every_record(&path);
}

#[test]
fn rotation_child() {
    let Some(path) = std::env::var_os("TELLTALE_SYNTHETIC_ROTATION_FILE") else {
        return;
    };
    let writer = std::env::var("TELLTALE_SYNTHETIC_ROTATION_WRITER")
        .unwrap()
        .parse()
        .unwrap();
    std::io::Read::read_exact(&mut std::io::stdin(), &mut [0]).unwrap();
    append(&PathBuf::from(path), writer);
}

#[test]
fn concurrent_rotation_processes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("records.jsonl");
    let mut children: Vec<_> = (0..WRITERS)
        .map(|writer| {
            Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "rotation_child"])
                .env("TELLTALE_SYNTHETIC_ROTATION_FILE", &path)
                .env("TELLTALE_SYNTHETIC_ROTATION_WRITER", writer.to_string())
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap()
        })
        .collect();
    for child in &mut children {
        std::io::Write::write_all(&mut child.stdin.take().unwrap(), b"1").unwrap();
    }
    for child in children {
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    assert_every_record(&path);
}

#[test]
fn custom_rotated_record_names_have_the_same_self_protection() {
    use telltale_core::hooks::config::{Config, Mode};
    use telltale_core::hooks::runtime::{Context, Event, Response, Runtime, ToolCall};
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("elsewhere/records.jsonl");
    let mut runtime = Runtime::new(Config {
        mode: Mode::Enforce,
        state_dir: Some(dir.path().join("state")),
        telemetry_path: Some(path.clone()),
        ..Config::default()
    });
    let ctx = Context {
        harness: "claude-code",
        hook_event: "PreToolUse".into(),
        session_id: "synthetic-session".into(),
        agent_id: None,
        agent_type: None,
        prompt_id: None,
        permission_mode: None,
        cwd: None,
        can_ask: true,
        can_grant: false,
    };
    let verdict = |runtime: &mut Runtime, id: &str, path: &Path| {
        let response = runtime.handle(
            &ctx,
            Event::ToolRequested(ToolCall {
                tool_name: "Bash".into(),
                tool_use_id: Some(id.into()),
                input: serde_json::json!({"command": format!("rm -f '{}'", path.display())}),
            }),
        );
        match response {
            Response::Decision(decision) => Some(decision.verdict()),
            _ => None,
        }
    };
    let active = verdict(&mut runtime, "active", &path);
    assert!(active.is_some());
    assert_eq!(
        verdict(
            &mut runtime,
            "rotated",
            &path.with_file_name("records-2026-11-26.9.jsonl")
        ),
        active
    );
}

#[test]
#[ignore = "local append cost measurement"]
fn measure_append_overhead() {
    use std::io::Write;
    use std::time::Instant;
    use telltale_core::hooks::state::{create_private_dir, open_regular};
    const COUNT: usize = 3000;
    let samples = |mode| {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("records.jsonl");
        let record = record(1);
        let sink = sink(&path, if mode == "enabled" { u64::MAX } else { 0 }, 5);
        let start = Instant::now();
        for _ in 0..COUNT {
            if mode == "previous" {
                let mut line = serde_json::to_vec(&record).unwrap();
                line.push(b'\n');
                create_private_dir(dir.path()).unwrap();
                let mut file =
                    open_regular(std::fs::OpenOptions::new().create(true).append(true), &path)
                        .unwrap();
                file.write_all(&line).unwrap();
            } else {
                sink.write(&record).unwrap();
            }
        }
        start.elapsed().as_secs_f64() * 1_000_000.0 / COUNT as f64
    };
    for _ in 0..5 {
        for mode in ["previous", "disabled", "enabled"] {
            println!("{mode}: {:.2} us/append", samples(mode));
        }
    }
}
