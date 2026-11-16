//! Synthetic no-follow discovery boundaries. Returned paths are not pinned reads.
#![cfg(any(unix, windows))]

use std::fs;
use std::path::Path;
use telltale_discover::clients::{ClientDef, ClientSourceDef, PathRoot, SourcePattern};
use telltale_discover::discovery::{BoundedDiscoveryError, discover_sources_bounded};
use telltale_schema::clients::{ClientId, SourceKind};

const SOURCES: &[ClientSourceDef] = &[ClientSourceDef {
    id: "codex.sessions",
    kind: SourceKind::Jsonl,
    root: PathRoot::Home,
    relative_path: ".codex/sessions",
    fixture_relative_path: "codex/sessions",
    pattern: SourcePattern::Extension("jsonl"),
    recursive: true,
    project_relative_path: None,
}];

fn registry() -> Vec<ClientDef> {
    vec![ClientDef {
        id: ClientId::Codex,
        display_name: "Synthetic Codex",
        sources: SOURCES,
    }]
}

fn link(target: &Path, path: &Path) {
    #[cfg(unix)]
    std::os::unix::fs::symlink(target, path).unwrap();
    #[cfg(windows)]
    {
        let result = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(path)
            .arg(target)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "synthetic junction creation failed: {}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
}

#[test]
fn ancestor_links_are_rejected_without_returning_external_sources() {
    let temp = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    let home = temp.path().join("home");
    let outside = temp.path().join("outside");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(outside.join("sessions")).unwrap();
    fs::write(outside.join("sessions/synthetic.jsonl"), b"synthetic").unwrap();
    link(&outside, &home.join(".codex"));
    assert_eq!(
        discover_sources_bounded(&home, ClientId::Codex, 1024, &registry()),
        Err(BoundedDiscoveryError::SymlinkRoot)
    );
}

#[test]
fn explicit_root_links_are_rejected() {
    let temp = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    let outside = temp.path().join("outside");
    fs::create_dir_all(outside.join(".codex/sessions")).unwrap();
    link(&outside, &temp.path().join("home"));
    assert_eq!(
        discover_sources_bounded(
            &temp.path().join("home"),
            ClientId::Codex,
            1024,
            &registry()
        ),
        Err(BoundedDiscoveryError::SymlinkRoot)
    );
}

#[test]
fn parent_components_are_checked_before_returning_to_the_parent() {
    // Windows canonicalization yields a `\\?\` verbatim path, and pushing onto
    // one resolves `..` lexically before discovery sees it. Keep it ordinary.
    #[cfg(windows)]
    let temp = tempfile::tempdir().unwrap();
    #[cfg(not(windows))]
    let temp = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    assert!(
        temp.path().join("x/../y").components().count() > temp.path().components().count() + 1,
        "test path must retain its parent component"
    );
    let home = temp.path().join("home");
    // Native separators: `mklink /J` rejects a target written with `/`.
    let outside = temp.path().join("outside").join("deeper");
    fs::create_dir_all(home.join(".codex/sessions")).unwrap();
    fs::write(home.join(".codex/sessions/synthetic.jsonl"), b"synthetic").unwrap();
    fs::create_dir_all(&outside).unwrap();
    fs::create_dir(temp.path().join("ordinary")).unwrap();
    link(&outside, &temp.path().join("linked"));
    assert_eq!(
        discover_sources_bounded(
            &temp.path().join("linked/../home"),
            ClientId::Codex,
            1024,
            &registry()
        ),
        Err(BoundedDiscoveryError::SymlinkRoot)
    );
    assert!(
        discover_sources_bounded(
            &temp.path().join("missing/../home"),
            ClientId::Codex,
            1024,
            &registry()
        )
        .unwrap()
        .is_empty()
    );
    let alias = temp.path().join("ordinary/../home");
    let sources = discover_sources_bounded(&alias, ClientId::Codex, 1024, &registry()).unwrap();
    assert_eq!(sources.len(), 1);
    assert_eq!(
        sources[0].path,
        alias.join(".codex/sessions/synthetic.jsonl")
    );
    assert!(fs::metadata(&sources[0].path).unwrap().is_file());
    let mut excessive = temp.path().to_path_buf();
    for _ in 0..140 {
        excessive.push("ordinary/..");
    }
    excessive.push("home");
    assert_eq!(
        discover_sources_bounded(&excessive, ClientId::Codex, 1024, &registry()),
        Err(BoundedDiscoveryError::LimitExceeded)
    );
}

#[test]
#[cfg(unix)]
fn nonrecursive_discovery_does_not_open_unrelated_unreadable_directories() {
    use std::os::unix::fs::PermissionsExt;
    // DAC tests require an unprivileged process, including in the local sandbox.
    // SAFETY: geteuid takes no pointers and has no memory preconditions.
    assert_ne!(unsafe { libc::geteuid() }, 0);
    let temp = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    let home = temp.path().join("search/home");
    let sessions = home.join(".codex/sessions");
    let denied = sessions.join("denied");
    fs::create_dir_all(&denied).unwrap();
    fs::write(sessions.join("synthetic.jsonl"), b"synthetic").unwrap();
    fs::set_permissions(&denied, fs::Permissions::from_mode(0o0)).unwrap();
    fs::set_permissions(
        temp.path().join("search"),
        fs::Permissions::from_mode(0o111),
    )
    .unwrap();
    const FLAT: &[ClientSourceDef] = &[ClientSourceDef {
        recursive: false,
        ..SOURCES[0]
    }];
    let flat = [ClientDef {
        sources: FLAT,
        ..registry()[0]
    }];
    let result = discover_sources_bounded(&home, ClientId::Codex, 3, &flat);
    let recursive = discover_sources_bounded(&home, ClientId::Codex, 1024, &registry());
    fs::set_permissions(&denied, fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(
        temp.path().join("search"),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    assert_eq!(result.unwrap().len(), 1);
    assert_eq!(recursive, Err(BoundedDiscoveryError::PermissionDenied));
}
