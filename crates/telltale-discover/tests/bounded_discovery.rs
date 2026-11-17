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
fn explicit_root_and_its_ancestors_are_trusted_but_nothing_below_it() {
    // A plain temporary parent may itself be an alias (macOS `/var`); that is
    // exactly the administrator-controlled case an explicit root must accept.
    let temp = tempfile::tempdir().unwrap();
    let real = temp.path().join("real");
    let alias = temp.path().join("alias");
    fs::create_dir_all(real.join("home").join(".codex").join("sessions")).unwrap();
    fs::write(
        real.join("home/.codex/sessions/synthetic.jsonl"),
        b"synthetic",
    )
    .unwrap();
    link(&real, &alias);

    // Linked ancestor of the root: accepted, and coordinates keep the caller's
    // spelling rather than the resolved location.
    let root = alias.join("home");
    let sources = discover_sources_bounded(&root, ClientId::Codex, 1024, &registry()).unwrap();
    assert_eq!(sources.len(), 1);
    assert_eq!(
        sources[0].path,
        root.join(".codex/sessions/synthetic.jsonl")
    );
    assert!(fs::metadata(&sources[0].path).unwrap().is_file());

    // The root itself is a link: the caller named it, so it is resolved too.
    link(&real.join("home"), &temp.path().join("linked-home"));
    let linked = temp.path().join("linked-home");
    let sources = discover_sources_bounded(&linked, ClientId::Codex, 1024, &registry()).unwrap();
    assert_eq!(
        sources[0].path,
        linked.join(".codex/sessions/synthetic.jsonl")
    );

    // A tool store linked below the trusted root is still refused.
    let planted = real.join("planted");
    fs::create_dir_all(&planted).unwrap();
    link(&real.join("home").join(".codex"), &planted.join(".codex"));
    assert_eq!(
        discover_sources_bounded(&alias.join("planted"), ClientId::Codex, 1024, &registry()),
        Err(BoundedDiscoveryError::SymlinkRoot)
    );
}

/// Environment mode: HOME is the only anchor. Relocation variables get none,
/// so a link at or above a relocated store is refused inside or outside home.
#[test]
fn environment_home_is_the_only_trust_anchor() {
    const CHILD: &str = "TELLTALE_BOUNDED_ANCHOR_CHILD";
    const CODEX_HOME_SOURCES: &[ClientSourceDef] = &[ClientSourceDef {
        root: PathRoot::CodexHome,
        relative_path: "sessions",
        ..SOURCES[0]
    }];
    let codex_home_registry = [ClientDef {
        sources: CODEX_HOME_SOURCES,
        ..registry()[0]
    }];
    if let Some(mode) = std::env::var_os(CHILD) {
        let var = |name| std::path::PathBuf::from(std::env::var_os(name).unwrap());
        let result =
            discover_sources_bounded(Path::new("."), ClientId::Codex, 1024, &codex_home_registry);
        let expected = match mode.to_str().unwrap() {
            "home" => var("HOME").join(".codex/sessions/home.jsonl"),
            "relocated" => var("CODEX_HOME").join("sessions/relocated.jsonl"),
            _ => {
                assert_eq!(result, Err(BoundedDiscoveryError::SymlinkRoot));
                return;
            }
        };
        let paths = result
            .unwrap()
            .into_iter()
            .map(|source| source.path)
            .collect::<Vec<_>>();
        assert_eq!(paths, vec![expected]);
        return;
    }
    let temp = tempfile::tempdir().unwrap();
    let real = temp.path().join("real");
    let alias = temp.path().join("alias");
    let work = temp.path().join("work");
    for directory in [
        real.join("home").join(".codex").join("sessions"),
        real.join("codex").join("sessions"),
        real.join("planted-home"),
        work.clone(),
    ] {
        fs::create_dir_all(directory).unwrap();
    }
    fs::write(real.join("home/.codex/sessions/home.jsonl"), b"synthetic").unwrap();
    fs::write(real.join("codex/sessions/relocated.jsonl"), b"synthetic").unwrap();
    link(&real, &alias);
    link(
        &real.join("codex"),
        &real.join("planted-home").join(".codex"),
    );
    let run = |mode: &str, home: &Path, codex_home: Option<&Path>| {
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command
            .env_clear()
            .current_dir(&work)
            .env("HOME", home)
            .env("USERPROFILE", home)
            .env(CHILD, mode)
            .args([
                "--exact",
                "environment_home_is_the_only_trust_anchor",
                "--nocapture",
            ]);
        if let Some(codex_home) = codex_home {
            command.env("CODEX_HOME", codex_home);
        }
        for key in ["PATH", "SystemRoot", "windir"] {
            if let Some(value) = std::env::var_os(key) {
                command.env(key, value);
            }
        }
        let output = command.output().unwrap();
        assert!(output.status.success(), "{mode}: {output:?}");
    };
    run("home", &alias.join("home"), None);
    // A relocation outside home is walked strictly: fine on a physical path,
    // refused through the linked ancestor.
    let physical = temp
        .path()
        .canonicalize()
        .unwrap()
        .join("real")
        .join("codex");
    run("relocated", &alias.join("home"), Some(&physical));
    run(
        "relocated-alias",
        &alias.join("home"),
        Some(&alias.join("codex")),
    );
    // Naming the linked store explicitly does not make it an anchor.
    let planted = alias.join("planted-home");
    run("inside", &planted, Some(&planted.join(".codex")));
    run("inside", &planted, None);
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
    // An explicit root is trusted, so it resolves as the OS resolves it: on
    // Unix `linked/..` is `outside`, which has no `home`; Windows collapses
    // `..` first. Either way every coordinate names what was inspected, never
    // the lexical `home` sibling on Unix.
    let through_link = temp.path().join("linked/../home");
    let sources =
        discover_sources_bounded(&through_link, ClientId::Codex, 1024, &registry()).unwrap();
    assert_eq!(sources.len(), usize::from(cfg!(windows)));
    for source in &sources {
        assert!(fs::metadata(&source.path).unwrap().is_file());
    }
    // Likewise `missing/..` fails on Unix but collapses to `home` on Windows.
    let through_missing = temp.path().join("missing/../home");
    let sources =
        discover_sources_bounded(&through_missing, ClientId::Codex, 1024, &registry()).unwrap();
    assert_eq!(sources.len(), usize::from(cfg!(windows)));
    assert!(
        sources
            .iter()
            .all(|source| fs::metadata(&source.path).unwrap().is_file())
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
