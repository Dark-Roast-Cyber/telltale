use super::{JournalFile, discover_generations, parse_rotated_name};
use std::fs;
use tempfile::tempdir;

#[test]
fn exact_rotation_names_are_orderable_and_external_names_are_ignored() {
    assert_eq!(
        parse_rotated_name("events-2026-01-02.3.jsonl", "events", "jsonl"),
        Some(("2026-01-02".to_string(), 3))
    );
    assert!(parse_rotated_name("events-20260102.jsonl", "events", "jsonl").is_none());
}

#[test]
fn discovery_and_open_are_read_only_and_identity_survives_rename() {
    let directory = tempdir().expect("tempdir");
    let active = directory.path().join("events.jsonl");
    fs::write(&active, b"one\n").expect("active");
    let mut file = JournalFile::open(&active).expect("open");
    let identity = file.identity().to_owned();
    assert_eq!(file.read_at(0, 4).expect("read"), b"one\n");
    let rotated = directory.path().join("events-2026-01-02.jsonl");
    fs::rename(&active, &rotated).expect("rename");
    assert_eq!(file.read_at(0, 4).expect("renamed handle"), b"one\n");
    assert_eq!(file.identity(), identity);
    let discovery =
        discover_generations(&directory.path().join("events.jsonl"), 8).expect("discover");
    assert_eq!(discovery.generations.len(), 1);
    assert!(!discovery.generations[0].is_active);
}

#[test]
fn bounded_directory_discovery_reports_when_the_entry_cap_is_reached() {
    let directory = tempdir().expect("tempdir");
    let active = directory.path().join("events.jsonl");
    fs::write(&active, b"active\n").expect("active");
    for index in 0..4 {
        fs::write(
            directory.path().join(format!("unrelated-{index}")),
            b"fixture",
        )
        .expect("unrelated entry");
    }

    let discovery = discover_generations(&active, 2).expect("bounded discovery");

    assert!(discovery.directory_bound_reached);
}

#[test]
fn extensionless_active_file_is_discovered_without_rotations() {
    let directory = tempdir().expect("tempdir");
    let active = directory.path().join("events");
    fs::write(&active, b"active\n").expect("active");

    let discovery = discover_generations(&active, 8).expect("discover");

    assert_eq!(discovery.generations.len(), 1);
    assert_eq!(discovery.generations[0].path, active);
    assert!(discovery.generations[0].is_active);
    assert!(!discovery.directory_bound_reached);
}

#[test]
fn discover_open_and_read_at_do_not_create_files() {
    let directory = tempdir().expect("tempdir");
    let missing = directory.path().join("missing/events.jsonl");
    let before_missing = fs::read_dir(directory.path())
        .expect("fixture directory")
        .count();
    let discovery = discover_generations(&missing, 8).expect("missing discovery");
    assert!(discovery.generations.is_empty());
    assert!(JournalFile::open(&missing).is_err());
    assert_eq!(
        fs::read_dir(directory.path())
            .expect("fixture directory")
            .count(),
        before_missing
    );
    assert!(!missing.exists());
    assert!(!missing.parent().expect("missing parent").exists());

    let active = directory.path().join("events.jsonl");
    fs::write(&active, b"one\n").expect("active fixture");
    let mut before_read = fs::read_dir(directory.path())
        .expect("fixture directory")
        .map(|entry| entry.expect("entry").file_name())
        .collect::<Vec<_>>();
    before_read.sort();
    let mut file = JournalFile::open(&active).expect("open active");
    assert_eq!(file.read_at(0, 4).expect("read active"), b"one\n");
    let mut after_read = fs::read_dir(directory.path())
        .expect("fixture directory")
        .map(|entry| entry.expect("entry").file_name())
        .collect::<Vec<_>>();
    after_read.sort();
    assert_eq!(after_read, before_read);
}

#[cfg(unix)]
#[test]
fn metadata_open_refuses_a_swapped_fifo_without_waiting_for_a_writer() {
    use std::os::unix::ffi::OsStrExt;
    use std::sync::mpsc;
    use std::time::Duration;

    let directory = tempdir().expect("tempdir");
    let fifo = directory.path().join("events.jsonl");
    let name = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
    let (send, receive) = mpsc::channel();
    // Exercise the open after the path precheck, where a replacement can
    // occur. A pre-planted FIFO is already refused before that open.
    std::thread::spawn(move || {
        let result = JournalFile::open_metadata(&fifo).and_then(|file| super::file_metadata(&file));
        let _ = send.send(result);
    });
    let result = receive
        .recv_timeout(Duration::from_secs(1))
        .expect("journal open blocked on a FIFO");
    assert_eq!(result.unwrap_err().to_string(), "unsafe journal file");
}

#[cfg(unix)]
#[test]
fn symlink_and_hardlink_journals_are_rejected_by_open_and_discovery() {
    use std::os::unix::fs::symlink;

    let directory = tempdir().expect("tempdir");
    let real = directory.path().join("real.jsonl");
    fs::write(&real, b"one\n").expect("real journal");

    let symlink_path = directory.path().join("symlink.jsonl");
    symlink(&real, &symlink_path).expect("symlink journal");
    assert!(JournalFile::open(&symlink_path).is_err());
    assert!(discover_generations(&symlink_path, 8).is_err());

    let hardlink_path = directory.path().join("hardlink.jsonl");
    fs::hard_link(&real, &hardlink_path).expect("hardlink journal");
    assert!(JournalFile::open(&hardlink_path).is_err());
    assert!(discover_generations(&hardlink_path, 8).is_err());
}
