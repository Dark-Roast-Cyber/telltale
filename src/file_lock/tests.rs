use std::fs;

use tempfile::tempdir;

#[cfg(windows)]
use super::{sync_directory, windows_file_time};

use super::{
    RotationNamespace, SidecarLock, TempFile, atomic_rename_no_replace, atomic_replace,
    conflicts_with_runtime_paths, manifest_path, safe_path_info, sidecar_path,
    stable_file_identity, validate_pinned_observation, validate_runtime_paths,
    verify_target_observation,
};

#[test]
fn side_files_may_not_land_on_scanner_files_or_in_a_log_directory() {
    let dir = tempdir().expect("tempdir");
    let state = dir.path().join("state").join("state.json");
    let log = dir.path().join("logs").join("events.jsonl");
    let queue = dir.path().join("queue");
    let outbox = crate::sink::outbox::reserved_outbox_paths(&queue.join("outbox.sqlite"));
    let namespace = RotationNamespace::from_active_path(&log, "events", "jsonl");
    let conflicts = |candidate: &std::path::Path| {
        conflicts_with_runtime_paths(
            candidate,
            &state,
            std::slice::from_ref(&log),
            &outbox,
            std::slice::from_ref(&namespace),
        )
        .expect("conflict check")
    };
    for protected in [
        state.clone(),
        sidecar_path(&state),
        manifest_path(&state),
        log.clone(),
        sidecar_path(&log),
        queue.join("outbox.sqlite"),
        queue.join("outbox.sqlite.lock"),
        queue.join("outbox.sqlite-journal"),
        queue.join("outbox.sqlite-wal"),
        queue.join("outbox.sqlite-shm"),
        dir.path().join("logs").join("diagnostics.jsonl"),
        dir.path().join("logs").join("events-2026-11-19.jsonl"),
    ] {
        assert!(conflicts(&protected), "{}", protected.display());
    }
    for allowed in [
        dir.path()
            .join("state")
            .join("diagnostics")
            .join("scan.jsonl"),
        queue.join("diagnostics.jsonl"),
        dir.path()
            .join("logs")
            .join("nested")
            .join("diagnostics.jsonl"),
    ] {
        assert!(!conflicts(&allowed), "{}", allowed.display());
    }

    // A hard link to the state file is refused, not written through.
    fs::create_dir_all(state.parent().unwrap()).expect("state dir");
    fs::write(&state, "{}").expect("state");
    let alias = dir.path().join("alias.json");
    fs::hard_link(&state, &alias).expect("hard link");
    assert!(
        conflicts_with_runtime_paths(&alias, &state, std::slice::from_ref(&log), &[], &[]).is_err()
    );
}

#[test]
fn sidecar_lock_is_permanent_and_fail_fast() {
    let temp = tempdir().expect("tempdir");
    let target = temp.path().join("state.json");
    let first = SidecarLock::acquire(&target).expect("first lock");
    assert!(target.with_file_name("state.json.lock").exists());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        assert_eq!(
            fs::metadata(target.with_file_name("state.json.lock"))
                .expect("sidecar metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
    let error = match SidecarLock::acquire(&target) {
        Ok(_) => panic!("second lock must be busy"),
        Err(error) => error,
    };
    assert_eq!(error.to_string(), "resource busy; retry later");
    drop(first);
    let _second = SidecarLock::acquire(&target).expect("released lock");
}

#[test]
fn stable_identity_survives_atomic_rotation_rename_and_restart_lookup() {
    let temp = tempdir().expect("tempdir");
    let source = temp.path().join("events.jsonl");
    let rotated = temp.path().join("events-2026-06-21.jsonl");
    fs::write(&source, b"one\n").expect("source");
    let identity = stable_file_identity(&source).expect("source identity");
    let lock = SidecarLock::acquire_lock_only(&source).expect("rotation lock");

    atomic_rename_no_replace(&source, &rotated).expect("atomic rotation rename");
    lock.verify_lock().expect("sidecar remains stable");
    drop(lock);

    assert!(!source.exists());
    assert_eq!(
        stable_file_identity(&rotated).expect("rotated identity after restart"),
        identity
    );
}

#[test]
fn failed_atomic_replace_cleans_temp_and_leaves_changed_destination() {
    let temp = tempdir().expect("tempdir");
    let destination = temp.path().join("state.json");
    fs::write(&destination, b"old").expect("destination");
    let expected = safe_path_info(&destination).expect("expected info");
    let temporary = TempFile::write_and_sync(&destination, b"new", 0o600).expect("temp");
    let temporary_path = temporary.path.clone();
    assert!(temporary_path.exists());
    // Length differs from the captured identity, so rejection does not depend
    // on timestamp granularity.
    fs::write(&destination, b"concurrently-changed").expect("length-changing mutation");
    let error = atomic_replace(temporary, &destination, expected).expect_err("stale identity");
    assert!(
        error
            .to_string()
            .contains("persistence destination changed during commit"),
        "{error}"
    );
    assert_eq!(
        fs::read(&destination).expect("destination"),
        b"concurrently-changed"
    );
    assert!(
        !temporary_path.exists(),
        "failed replace must remove the temporary"
    );
    assert!(
        !fs::read_dir(temp.path())
            .expect("directory")
            .filter_map(Result::ok)
            .any(|entry| entry
                .file_name()
                .to_string_lossy()
                .contains(".telltale-tmp-"))
    );
}

#[test]
fn lock_verification_detects_same_length_target_changes() {
    let temp = tempdir().expect("tempdir");
    let target = temp.path().join("state.json");
    fs::write(&target, b"one").expect("target");
    let lock = SidecarLock::acquire(&target).expect("lock");
    fs::write(&target, b"two").expect("same-length mutation");
    assert!(lock.verify().is_err());
}

#[test]
fn unchanged_strict_target_verifies_successfully() {
    let temp = tempdir().expect("tempdir");
    let target = temp.path().join("state.json");
    fs::write(&target, b"one").expect("target");
    let lock = SidecarLock::acquire(&target).expect("lock");
    lock.verify().expect("unchanged target");
}

#[test]
fn strict_verification_detects_different_length_target_changes() {
    let temp = tempdir().expect("tempdir");
    let target = temp.path().join("state.json");
    fs::write(&target, b"one").expect("target");
    let lock = SidecarLock::acquire(&target).expect("lock");
    fs::write(&target, b"ones").expect("different-length mutation");
    assert!(lock.verify().is_err());
}

#[test]
fn strict_verification_detects_replacement_identity_change() {
    let temp = tempdir().expect("tempdir");
    let target = temp.path().join("state.json");
    let replacement = temp.path().join("replacement.json");
    fs::write(&target, b"one").expect("target");
    fs::write(&replacement, b"one").expect("replacement");
    let lock = SidecarLock::acquire(&target).expect("lock");
    fs::remove_file(&target).expect("remove target");
    fs::rename(&replacement, &target).expect("replace target");
    assert!(lock.verify().is_err());
}

#[test]
fn strict_verification_detects_deletion_and_recreation() {
    let temp = tempdir().expect("tempdir");
    let target = temp.path().join("state.json");
    fs::write(&target, b"one").expect("target");
    let lock = SidecarLock::acquire(&target).expect("lock");
    fs::remove_file(&target).expect("delete target");
    fs::write(&target, b"one").expect("recreate target");
    assert!(lock.verify().is_err());
}

#[test]
fn strict_verification_rejects_absent_to_created_transition() {
    let temp = tempdir().expect("tempdir");
    let target = temp.path().join("state.json");
    let lock = SidecarLock::acquire(&target).expect("lock");
    fs::write(&target, b"created").expect("created target");
    assert!(lock.verify().is_err());
}

#[test]
fn sidecar_replacement_is_detected_by_verify_lock() {
    let temp = tempdir().expect("tempdir");
    let target = temp.path().join("state.json");
    let replacement = temp.path().join("replacement.lock");
    let sidecar = sidecar_path(&target);
    let lock = SidecarLock::acquire(&target).expect("lock");
    fs::write(&replacement, b"replacement").expect("replacement sidecar");
    fs::remove_file(&sidecar).expect("remove sidecar");
    fs::rename(&replacement, &sidecar).expect("replace sidecar");
    assert!(lock.verify_lock().is_err());
}

#[test]
fn lock_only_allows_protected_target_mutation() {
    let temp = tempdir().expect("tempdir");
    let target = temp.path().join("events.jsonl");
    fs::write(&target, b"one\n").expect("target");
    let lock = SidecarLock::acquire_lock_only(&target).expect("lock");
    fs::write(&target, b"two\n").expect("mutable target");
    lock.verify_lock().expect("sidecar unchanged");
    assert!(lock.verify().is_err());
}

#[test]
fn equal_metadata_with_different_digest_fails_closed() {
    let temp = tempdir().expect("tempdir");
    let target = temp.path().join("state.json");
    fs::write(&target, b"one").expect("target");
    let info = safe_path_info(&target)
        .expect("target info")
        .expect("existing target");
    assert!(
        verify_target_observation(Some(info), Some(info), Some([0; 32]), Some([1; 32]),).is_err()
    );
    verify_target_observation(Some(info), Some(info), Some([0; 32]), Some([0; 32]))
        .expect("equal metadata and digest");
}

#[cfg(windows)]
#[test]
fn windows_strict_verification_rejects_same_length_mutation_with_restored_timestamp() {
    let temp = tempdir().expect("tempdir");
    let target = temp.path().join("state.json");
    fs::write(&target, b"one").expect("target");
    let lock = SidecarLock::acquire(&target).expect("lock");
    let captured_time = lock.target_info.expect("target info").modified;

    fs::write(&target, b"two").expect("same-length mutation");
    restore_windows_last_write_time(&target, captured_time);

    assert_eq!(
        safe_path_info(&target).expect("target info"),
        lock.target_info
    );
    assert!(lock.verify().is_err());
}

#[test]
fn pinned_read_rejects_acquisition_instability() {
    let temp = tempdir().expect("tempdir");
    let target = temp.path().join("state.json");
    fs::write(&target, b"one").expect("target");
    let info = safe_path_info(&target)
        .expect("target info")
        .expect("existing target");
    let mut after = info;
    after.length += 1;
    assert!(
        validate_pinned_observation(info, info, after, Some(info), "unstable pinned read",)
            .is_err()
    );
}

#[test]
fn pinned_read_rejects_verification_instability() {
    let temp = tempdir().expect("tempdir");
    let target = temp.path().join("state.json");
    fs::write(&target, b"one").expect("target");
    let info = safe_path_info(&target)
        .expect("target info")
        .expect("existing target");
    assert!(validate_pinned_observation(info, info, info, None, "unstable pinned read",).is_err());
}

#[cfg(unix)]
#[test]
fn namespace_validation_resolves_symlinked_missing_ancestors() {
    use std::os::unix::fs::symlink;

    let temp = tempdir().expect("tempdir");
    let real = temp.path().join("real");
    fs::create_dir(&real).expect("real directory");
    let alias = temp.path().join("alias");
    symlink(&real, &alias).expect("alias");
    let state = alias.join("nested/state.json");
    let log = real.join("nested/state.json");
    assert!(validate_runtime_paths(&state, std::slice::from_ref(&log), &[]).is_err());
}

#[cfg(unix)]
#[test]
fn normalized_path_preserves_filesystem_order_for_symlink_parent() {
    let temp = tempdir().unwrap();
    let sessions = temp.path().join("stores/codex/sessions");
    fs::create_dir_all(&sessions).unwrap();
    let alias = temp.path().join("sessions-alias");
    std::os::unix::fs::symlink(&sessions, &alias).unwrap();
    let target = alias.join("../sessions/private/outbox.sqlite");
    let expected = fs::canonicalize(&sessions)
        .unwrap()
        .join("private/outbox.sqlite");
    assert_eq!(super::normalized_path(&target).unwrap(), expected);
    assert!(super::paths_identity_equivalent(&target, &expected).unwrap());
    fs::create_dir_all(sessions.join("private")).unwrap();
    fs::write(sessions.join("private/outbox.sqlite"), b"synthetic").unwrap();
    assert_eq!(
        super::normalized_path(&target).unwrap(),
        fs::canonicalize(&target).unwrap()
    );
}

#[cfg(unix)]
#[test]
fn normalized_path_rejects_missing_intermediate_before_parent() {
    let temp = tempdir().unwrap();
    let target = temp.path().join("missing/../outbox.sqlite");
    assert!(super::normalized_path(&target).is_err());
    assert!(!temp.path().join("missing").exists());
}

#[cfg(unix)]
#[test]
fn normalized_path_propagates_invalid_ancestor_errors() {
    let temp = tempdir().unwrap();
    let file = temp.path().join("file");
    fs::write(&file, b"synthetic").unwrap();
    assert!(super::normalized_path(&file.join("child")).is_err());
    let alias = temp.path().join("loop");
    std::os::unix::fs::symlink(&alias, &alias).unwrap();
    assert!(super::normalized_path(&alias.join("child")).is_err());
}

#[test]
fn rotation_namespace_rejects_each_protected_category_without_path_overlap() {
    let temp = tempdir().expect("tempdir");
    let cases = vec![
        (
            "state path",
            validate_runtime_paths(
                &temp.path().join("events-2026-06-21.jsonl"),
                &[temp.path().join("events.jsonl")],
                &[RotationNamespace::from_active_path(
                    &temp.path().join("events.jsonl"),
                    "events",
                    "jsonl",
                )],
            ),
        ),
        (
            "migration companion",
            validate_runtime_paths(
                &temp.path().join("events-2026"),
                &[temp.path().join("events.json")],
                &[RotationNamespace::from_active_path(
                    &temp.path().join("events.json"),
                    "events",
                    "json",
                )],
            ),
        ),
        (
            "state sidecar",
            validate_runtime_paths(
                &temp.path().join("events-x.2026"),
                &[temp.path().join("events.lock")],
                &[RotationNamespace::from_active_path(
                    &temp.path().join("events.lock"),
                    "events",
                    "2026.lock",
                )],
            ),
        ),
        (
            "manifest sidecar",
            validate_runtime_paths(
                &temp.path().join("events-2026"),
                &[temp.path().join("events.json")],
                &[RotationNamespace::from_active_path(
                    &temp.path().join("events.json"),
                    "events",
                    "json.lock",
                )],
            ),
        ),
        (
            "another active local JSONL sink",
            validate_runtime_paths(
                &temp.path().join("state.json"),
                &[
                    temp.path().join("events.jsonl"),
                    temp.path().join("events-2026-06-21.jsonl"),
                ],
                &[RotationNamespace::from_active_path(
                    &temp.path().join("events.jsonl"),
                    "events",
                    "jsonl",
                )],
            ),
        ),
        (
            "overlapping local sinks",
            validate_runtime_paths(
                &temp.path().join("state.json"),
                &[
                    temp.path().join("events.jsonl"),
                    temp.path().join("events-2026.jsonl"),
                ],
                &[
                    RotationNamespace::from_active_path(
                        &temp.path().join("events.jsonl"),
                        "events",
                        "jsonl",
                    ),
                    RotationNamespace::from_active_path(
                        &temp.path().join("events-2026.jsonl"),
                        "events-2026",
                        "jsonl",
                    ),
                ],
            ),
        ),
    ];
    let failures = cases
        .into_iter()
        .filter_map(|(name, result)| match result {
            Err(error) if error.to_string().contains("rotation namespace") => None,
            Ok(()) => Some(format!("{name}: collision was accepted")),
            Err(error) => Some(format!("{name}: unexpected error: {error}")),
        })
        .collect::<Vec<_>>();
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[cfg(any(windows, target_os = "macos"))]
#[test]
fn case_only_aliases_are_rejected_for_state_manifest_sidecar_and_rotation() {
    let temp = tempdir().expect("tempdir");
    let cases = vec![
        (
            "state path",
            validate_runtime_paths(
                &temp.path().join("State.json"),
                &[temp.path().join("state.JSON")],
                &[],
            ),
        ),
        (
            "reserved migration companion",
            validate_runtime_paths(
                &temp.path().join("native"),
                &[temp.path().join("native.migration.JSON")],
                &[],
            ),
        ),
        (
            "sidecar",
            validate_runtime_paths(
                &temp.path().join("sidecar-state.json"),
                &[temp.path().join("SIDECAR-STATE.JSON.LOCK")],
                &[],
            ),
        ),
        (
            "rotation path",
            validate_runtime_paths(
                &temp.path().join("ROTATION-2026-06-21.JSONL"),
                &[],
                &[RotationNamespace::from_active_path(
                    &temp.path().join("rotation.jsonl"),
                    "rotation",
                    "jsonl",
                )],
            ),
        ),
    ];
    let failures = cases
        .into_iter()
        .filter_map(|(name, result)| match result {
            Err(_) => None,
            Ok(()) => Some(format!("{name}: case-only alias was accepted")),
        })
        .collect::<Vec<_>>();
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[cfg(windows)]
#[test]
fn windows_filesystem_bindings_compile() {
    use std::path::Path;
    use windows_sys::Win32::Foundation::FILETIME;

    let time = windows_file_time(FILETIME {
        dwHighDateTime: 0,
        dwLowDateTime: 0,
    });
    assert_eq!(time.seconds, 0);
    assert_eq!(time.nanos, 0);
    sync_directory(Path::new("."))
        .expect("Windows parent durability is intentionally not asserted");
}

#[cfg(windows)]
fn restore_windows_last_write_time(path: &std::path::Path, time: super::FileTime) {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::FILETIME;
    use windows_sys::Win32::Storage::FileSystem::SetFileTime;

    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .expect("open target for timestamp restoration");
    let value = time.seconds as u64 * 10_000_000 + u64::from(time.nanos) / 100;
    let write_time = FILETIME {
        dwHighDateTime: (value >> 32) as u32,
        dwLowDateTime: value as u32,
    };
    assert_ne!(
        unsafe {
            SetFileTime(
                file.as_raw_handle(),
                std::ptr::null(),
                std::ptr::null(),
                &write_time,
            )
        },
        0
    );
}
