use super::*;

#[test]
fn bounded_discovery_classifies_only_observed_permission() {
    for (kind, expected) in [
        (
            std::io::ErrorKind::PermissionDenied,
            super::super::BoundedDiscoveryError::PermissionDenied,
        ),
        (
            std::io::ErrorKind::NotFound,
            super::super::BoundedDiscoveryError::Traversal,
        ),
        (
            std::io::ErrorKind::WouldBlock,
            super::super::BoundedDiscoveryError::Traversal,
        ),
    ] {
        let error = super::super::BoundedDiscoveryError::from_io(std::io::Error::new(
            kind,
            "/synthetic/private/DIAGNOSTIC_CANARY",
        ));
        assert_eq!(error, expected);
        assert!(!format!("{error:?}").contains("CANARY"));
    }
}

#[test]
fn checked_discovery_reports_invalid_roots_and_best_effort_preserves_empty_behavior() {
    let temp = tempdir().expect("tempdir");
    let missing = temp.path().join("missing");

    let error =
        discover_sources(&missing, supported_clients()).expect_err("missing root should fail");
    assert_eq!(
        error,
        DiscoveryError::InvalidRoot {
            root: missing.clone()
        }
    );
    assert!(discover_sources_best_effort(&missing, supported_clients()).is_empty());
    assert!(
        error
            .to_string()
            .contains(missing.to_string_lossy().as_ref())
    );
}

#[test]
fn best_effort_walk_retains_valid_entries_around_failure() {
    let traversal_error = DiscoveryError::Traversal {
        root: PathBuf::from("synthetic-root"),
        source_id: "synthetic.source".to_string(),
    };
    let entries = [Ok("direct"), Err("failed"), Ok("sibling")];

    let retained = collect_walk_entries(entries, DiscoveryMode::BestEffort, || {
        traversal_error.clone()
    })
    .expect("best effort keeps valid entries");
    assert_eq!(retained, ["direct", "sibling"]);

    let entries = [Ok("direct"), Err("failed"), Ok("sibling")];
    let error = collect_walk_entries(entries, DiscoveryMode::Checked, || traversal_error.clone())
        .expect_err("checked discovery reports the first failure");
    assert_eq!(error, traversal_error);
}

#[test]
fn best_effort_discovery_matches_checked_success_ordering() {
    let fixture_root = crate::test_fixture_path("session_stores");
    let checked = discover_sources(&fixture_root, supported_clients()).expect("checked discovery");
    let best_effort = discover_sources_best_effort(&fixture_root, supported_clients());

    assert_eq!(checked, best_effort);
}

#[cfg(unix)]
#[test]
fn checked_discovery_reports_unreadable_source_traversal() {
    use std::os::unix::fs::PermissionsExt;

    // Root bypasses DAC. Require an unprivileged runner rather than passing
    // without exercising the boundary.
    // SAFETY: geteuid has no arguments or memory ownership preconditions.
    assert_ne!(
        unsafe { libc::geteuid() },
        0,
        "run permission tests as an unprivileged user"
    );
    let temp = tempdir().expect("tempdir");
    let restricted = temp.path().join(".codex/sessions");
    fs::create_dir_all(&restricted).expect("sessions directory");
    fs::set_permissions(&restricted, fs::Permissions::from_mode(0o000))
        .expect("restrict sessions directory");
    let result = discover_sources(temp.path(), supported_clients());
    fs::set_permissions(&restricted, fs::Permissions::from_mode(0o755))
        .expect("restore sessions directory");

    let error = result.expect_err("an unreadable source directory is an error");
    assert!(matches!(
        error,
        DiscoveryError::Traversal { ref source_id, .. } if source_id == "codex.sessions"
    ));
}
