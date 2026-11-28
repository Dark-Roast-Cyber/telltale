use super::super::*;

#[test]
fn bounded_read_io_classification_discards_diagnostics() {
    for (kind, expected) in [
        (std::io::ErrorKind::NotFound, BoundedReadError::Missing),
        (
            std::io::ErrorKind::PermissionDenied,
            BoundedReadError::PermissionDenied,
        ),
        (std::io::ErrorKind::WouldBlock, BoundedReadError::Unreadable),
        (std::io::ErrorKind::Other, BoundedReadError::Unreadable),
    ] {
        let reason = BoundedReadError::from_io(std::io::Error::new(
            kind,
            "/synthetic/private/DIAGNOSTIC_CANARY token=SECRET_CANARY",
        ));
        assert_eq!(reason, expected);
        let public = format!("{reason:?} {}", reason.code());
        assert!(!public.contains("CANARY"));
        assert!(!public.contains("/synthetic"));
    }
}

#[cfg(unix)]
#[test]
fn confined_read_refuses_every_link_below_the_root_and_keeps_bounds() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("root");
    fs::create_dir_all(root.join("store")).unwrap();
    let source = root.join("store/source.jsonl");
    fs::write(&source, b"1234").unwrap();
    // Even a link that stays inside the root is not followed.
    std::os::unix::fs::symlink(root.join("store"), root.join("linked")).unwrap();
    let linked = root.join("linked/source.jsonl");
    assert_eq!(confined_file_bytes(&root, &source, 4).unwrap(), b"1234");
    assert_eq!(
        confined_file_bytes(&root, &source, 3),
        Err(BoundedReadError::LimitExceeded)
    );
    assert_eq!(
        confined_file_bytes(&root, &linked, 4),
        Err(BoundedReadError::NonRegularSource)
    );
    assert_eq!(
        confined_file_bytes(&root, &root.join("store/missing.jsonl"), 4),
        Err(BoundedReadError::Missing)
    );
    assert_eq!(
        confined_file_bytes(&root, &root.join("store"), 4),
        Err(BoundedReadError::NonRegularSource)
    );
    // The unconfined reader (MCP configuration, Copilot) is unchanged: it
    // refuses only a link in the last component.
    assert_eq!(bounded_file_bytes(&linked, 4).unwrap(), b"1234");
}

#[test]
fn bounded_read_observes_missing_regular_and_limits() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("PRIVATE_PATH_CANARY");
    assert_eq!(bounded_file_bytes(&path, 4), Err(BoundedReadError::Missing));
    fs::write(&path, b"1234").unwrap();
    assert_eq!(bounded_file_bytes(&path, 4).unwrap(), b"1234");
    assert_eq!(
        bounded_file_bytes(&path, 3),
        Err(BoundedReadError::LimitExceeded)
    );
    #[cfg(unix)]
    assert_eq!(
        bounded_file_bytes(dir.path(), 4),
        Err(BoundedReadError::NonRegularSource)
    );
}
