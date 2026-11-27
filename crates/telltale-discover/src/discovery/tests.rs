use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use telltale_schema::clients::{ClientId, SourceKind};
fn tempdir() -> std::io::Result<tempfile::TempDir> {
    tempfile::tempdir_in(std::env::temp_dir().canonicalize()?)
}

use crate::clients::{ClientSourceDef, PathRoot};

use super::{
    DiscoveryError, DiscoveryMode, HostPlatform, RootResolutionContext, collect_walk_entries,
    current_host_platform, default_data_home, discover_source_from_context, discover_sources,
    discover_sources_best_effort, discover_sources_with_projects, discover_watch_roots,
    discover_watch_roots_for_clients, discover_watch_roots_with_projects,
    resolve_path_root_from_context, source_search_root_from_context,
};
use crate::test_registry::supported_clients;

fn lookup_source(id: &str) -> (ClientId, ClientSourceDef) {
    supported_clients()
        .iter()
        .flat_map(|client| {
            client
                .sources
                .iter()
                .map(move |source| (client.id, *source))
        })
        .find(|(_, source)| source.id == id)
        .expect("source definition")
}

#[test]
fn bounded_discovery_classifies_only_observed_permission() {
    for (kind, expected) in [
        (
            std::io::ErrorKind::PermissionDenied,
            super::BoundedDiscoveryError::PermissionDenied,
        ),
        (
            std::io::ErrorKind::NotFound,
            super::BoundedDiscoveryError::Traversal,
        ),
        (
            std::io::ErrorKind::WouldBlock,
            super::BoundedDiscoveryError::Traversal,
        ),
    ] {
        let error = super::BoundedDiscoveryError::from_io(std::io::Error::new(
            kind,
            "/synthetic/private/DIAGNOSTIC_CANARY",
        ));
        assert_eq!(error, expected);
        assert!(!format!("{error:?}").contains("CANARY"));
    }
}

#[test]
fn discovers_codex_and_opencode_fixture_sources() {
    let sources = discover_sources(
        &crate::test_fixture_path("session_stores"),
        supported_clients(),
    )
    .expect("discovery");

    let keys: HashSet<_> = sources
        .iter()
        .map(|source| {
            (
                source.client,
                source.kind,
                source.path.file_name().and_then(|name| name.to_str()),
            )
        })
        .collect();

    assert!(keys.contains(&(ClientId::Codex, SourceKind::Jsonl, Some("session-a.jsonl"))));
    assert!(keys.contains(&(ClientId::Claude, SourceKind::Jsonl, Some("session-a.jsonl"))));
    assert!(keys.contains(&(
        ClientId::OpenClaw,
        SourceKind::Jsonl,
        Some("session-a.jsonl.deleted")
    )));
    assert!(keys.contains(&(ClientId::Qwen, SourceKind::Jsonl, Some("session-a.jsonl"))));
    assert!(keys.contains(&(
        ClientId::Codex,
        SourceKind::ArchivedJsonl,
        Some("session-b.jsonl")
    )));
    assert!(keys.contains(&(
        ClientId::Codex,
        SourceKind::HeadlessJsonl,
        Some("headless-a.jsonl")
    )));
    assert!(keys.contains(&(ClientId::OpenCode, SourceKind::Sqlite, Some("opencode.db"))));
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

#[test]
fn repeated_and_overlapping_projects_return_exact_sources_once() {
    let temp = tempdir().expect("tempdir");
    let home = temp.path().join("home");
    let workspace = temp.path().join("workspace");
    let project = workspace.join("repo");
    fs::create_dir_all(&home).expect("home");
    fs::create_dir_all(project.join("logs/copilot")).expect("logs");
    let path = project.join("logs/copilot/process.log");
    fs::write(&path, b"synthetic log\n").expect("log");
    let projects = [workspace, project.clone(), project].map(|path| crate::projects::ProjectDef {
        name: "synthetic".to_string(),
        path,
    });
    let expected = vec![telltale_schema::source::Source {
        client: ClientId::Copilot,
        kind: SourceKind::CopilotProcessLog,
        source_id: "copilot.process_log".to_string(),
        path,
    }];
    assert_eq!(
        discover_sources_with_projects(&home, &projects, supported_clients()).expect("checked"),
        expected
    );
    assert_eq!(
        super::discover_sources_with_projects_best_effort(&home, &projects, supported_clients()),
        expected
    );
    let roots = discover_watch_roots_with_projects(
        &home,
        &[ClientId::Copilot],
        &projects,
        supported_clients(),
    );
    assert_eq!(
        roots,
        vec![expected[0].path.parent().expect("parent").to_path_buf()]
    );
}

#[test]
fn overlapping_fixture_and_project_discovery_preserves_source_ownership() {
    let root = crate::test_fixture_path("session_stores");
    let expected = discover_sources(&root, supported_clients()).expect("fixture sources");
    let projects = [crate::projects::ProjectDef {
        name: "fixture".to_string(),
        path: root.clone(),
    }];
    assert_eq!(
        discover_sources_with_projects(&root, &projects, supported_clients()).expect("overlap"),
        expected
    );
    assert_eq!(
        super::discover_sources_with_projects_best_effort(&root, &projects, supported_clients()),
        expected
    );
    for id in [
        "codex.sessions",
        "codex.archived_sessions",
        "codex.headless_sessions",
    ] {
        assert!(
            expected
                .iter()
                .any(|source| source.client == ClientId::Codex && source.source_id == id)
        );
    }
}

#[cfg(unix)]
#[test]
fn exact_dedup_preserves_paths_with_identical_lossy_display() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    // APFS rejects these filenames; exact path identity needs no filesystem.
    let paths = [0xfe, 0xff].map(|byte| {
        let mut name = b"process-".to_vec();
        name.push(byte);
        name.extend_from_slice(b".log");
        std::path::PathBuf::from(OsString::from_vec(name))
    });
    assert_ne!(paths[0], paths[1]);
    assert_eq!(paths[0].to_string_lossy(), paths[1].to_string_lossy());
    let expected = paths.map(|path| telltale_schema::source::Source {
        client: ClientId::Copilot,
        kind: SourceKind::CopilotProcessLog,
        source_id: "copilot.process_log".to_string(),
        path,
    });
    let mut sources = vec![
        expected[1].clone(),
        expected[0].clone(),
        expected[1].clone(),
        expected[0].clone(),
    ];
    super::sort_and_dedup_sources(&mut sources);
    assert_eq!(sources, expected);
}

#[cfg(target_os = "linux")]
#[test]
fn discovery_preserves_paths_with_identical_lossy_display() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    let temp = tempdir().expect("tempdir");
    let logs = temp.path().join("logs/copilot");
    fs::create_dir_all(&logs).expect("logs");
    for byte in [0xfe, 0xff] {
        let mut name = b"process-".to_vec();
        name.push(byte);
        name.extend_from_slice(b".log");
        fs::write(logs.join(OsString::from_vec(name)), b"synthetic log\n").expect("log");
    }
    let project = crate::projects::ProjectDef {
        name: "synthetic".to_string(),
        path: temp.path().to_path_buf(),
    };
    let sources = discover_sources_with_projects(
        temp.path(),
        &[project.clone(), project],
        supported_clients(),
    )
    .expect("discovery");
    assert_eq!(sources.len(), 2);
    assert_ne!(sources[0].path, sources[1].path);
    assert_eq!(
        sources[0].path.to_string_lossy(),
        sources[1].path.to_string_lossy()
    );
    assert!(
        sources[0].path.as_os_str().as_encoded_bytes()
            < sources[1].path.as_os_str().as_encoded_bytes()
    );
}

#[test]
fn discovers_all_nested_project_local_watch_roots() {
    let temp = tempdir().expect("tempdir");
    let workspace = temp.path().join("workspace");
    let first = workspace.join("org-a/repo-a/logs/copilot");
    let second = workspace.join("org-b/repo-b/logs/copilot");
    fs::create_dir_all(&first).expect("first copilot dir");
    fs::create_dir_all(&second).expect("second copilot dir");

    let projects = vec![crate::projects::ProjectDef {
        name: "workspace".to_string(),
        path: workspace,
    }];
    let roots = discover_watch_roots_with_projects(
        std::path::Path::new("."),
        &[ClientId::Copilot],
        &projects,
        supported_clients(),
    );

    assert!(roots.contains(&first));
    assert!(roots.contains(&second));
}

#[test]
fn discovers_host_style_opencode_sources_from_home_root() {
    let temp = tempdir().expect("tempdir");
    let home = temp.path();
    let data_home = default_data_home(current_host_platform(), home).join("opencode");
    let data_home_relative = data_home
        .strip_prefix(home)
        .expect("data home relative path")
        .to_path_buf();
    fs::create_dir_all(&data_home).expect("data home");
    fs::write(data_home.join("opencode.db"), b"sqlite fixture").expect("sqlite fixture");

    let sources = discover_sources(home, supported_clients()).expect("discovery");
    let keys: HashSet<_> = sources
        .iter()
        .map(|source| {
            (
                source.client,
                source.kind,
                source
                    .path
                    .strip_prefix(home)
                    .expect("relative path")
                    .to_path_buf(),
            )
        })
        .collect();

    assert!(keys.contains(&(
        ClientId::OpenCode,
        SourceKind::Sqlite,
        data_home_relative.join("opencode.db")
    )));
}

#[test]
fn discovers_existing_fixture_watch_roots() {
    let roots = discover_watch_roots(
        &crate::test_fixture_path("session_stores"),
        supported_clients(),
    );
    let fixture_root = Path::new("tests").join("fixtures").join("session_stores");

    assert!(
        roots
            .iter()
            .any(|path| path.ends_with(fixture_root.join("codex").join("sessions")))
    );
    assert!(
        roots
            .iter()
            .any(|path| path.ends_with(fixture_root.join("opencode")))
    );
}

#[test]
fn opencode_data_home_is_not_a_fixture_and_supports_bounded_discovery_and_watch() {
    let temp = tempdir().unwrap();
    let data_home = temp.path().join(".local/share");
    let db = data_home.join("opencode/opencode.db");
    fs::create_dir_all(db.parent().unwrap()).unwrap();
    fs::write(&db, b"synthetic metadata only").unwrap();
    assert!(!super::is_fixture_root(&data_home, supported_clients()));
    let sources = discover_sources(&data_home, supported_clients()).unwrap();
    assert_eq!(sources.len(), 1);
    assert_eq!(sources[0].path, db);
    assert_eq!(
        super::discover_sources_bounded(&data_home, ClientId::OpenCode, 1, supported_clients())
            .unwrap(),
        sources
    );
    assert_eq!(
        discover_watch_roots_for_clients(&data_home, &[ClientId::OpenCode], supported_clients()),
        vec![db.parent().unwrap().to_path_buf()]
    );
    fs::write(data_home.join(".telltale-fixtures"), b"").unwrap();
    assert!(super::is_fixture_root(&data_home, supported_clients()));
    assert_eq!(
        discover_sources(&data_home, supported_clients()).unwrap(),
        sources
    );
    assert!(super::is_fixture_root(
        &crate::test_fixture_path("session_stores"),
        supported_clients()
    ));
}

#[test]
fn windows_opencode_candidates_include_appdata_xdg_and_home_fallback() {
    let temp = tempdir().unwrap();
    let context = RootResolutionContext {
        home: temp.path().join("home"),
        codex_home: None,
        data_home: Some(temp.path().join("local-app-data")),
    };
    let xdg = temp.path().join("xdg-data");
    let source_def = lookup_source("opencode.sqlite").1;
    let roots =
        super::opencode_search_roots(&context, HostPlatform::Windows, source_def, Some(&xdg));
    assert_eq!(roots.len(), 3);
    for data_home in [
        context.data_home.clone().unwrap(),
        xdg,
        context.home.join(".local/share"),
    ] {
        assert!(roots.contains(&data_home.join("opencode/opencode.db")));
    }
    let roots = super::opencode_search_roots(
        &context,
        HostPlatform::Windows,
        source_def,
        context.data_home.as_deref(),
    );
    assert_eq!(
        roots.len(),
        2,
        "duplicate candidates must not consume bounded discovery budget"
    );
}

#[cfg(windows)]
#[test]
fn windows_opencode_home_discovery_keeps_both_stores_and_watch_roots() {
    let temp = tempdir().unwrap();
    let stores = ["AppData/Local/opencode", ".local/share/opencode"]
        .map(|subpath| temp.path().join(subpath));
    for store in &stores {
        fs::create_dir_all(store).unwrap();
        fs::write(store.join("opencode.db"), b"synthetic metadata only").unwrap();
    }
    let sources = discover_sources(temp.path(), supported_clients()).unwrap();
    assert_eq!(sources.len(), 2);
    assert_eq!(
        super::discover_sources_bounded(temp.path(), ClientId::OpenCode, 2, supported_clients())
            .unwrap(),
        sources
    );
    assert_eq!(
        super::discover_sources_bounded(temp.path(), ClientId::OpenCode, 1, supported_clients()),
        Err(super::BoundedDiscoveryError::LimitExceeded)
    );
    let mut expected = stores.to_vec();
    expected.sort_unstable();
    assert_eq!(
        discover_watch_roots_for_clients(temp.path(), &[ClientId::OpenCode], supported_clients()),
        expected
    );
}

#[test]
fn filters_fixture_watch_roots_by_client() {
    let roots = discover_watch_roots_for_clients(
        &crate::test_fixture_path("session_stores"),
        &[ClientId::Claude],
        supported_clients(),
    );
    let fixture_root = Path::new("tests").join("fixtures").join("session_stores");

    assert!(!roots.is_empty());
    assert!(
        roots
            .iter()
            .all(|path| path.ends_with(fixture_root.join("claude").join("projects")))
    );
}

#[test]
fn resolves_linux_roots_from_context() {
    let context = RootResolutionContext {
        home: PathBuf::from("/home/tester"),
        codex_home: Some(PathBuf::from("/srv/codex")),
        data_home: Some(PathBuf::from("/xdg/data")),
    };

    assert_eq!(
        resolve_path_root_from_context(&context, PathRoot::Home),
        PathBuf::from("/home/tester")
    );
    assert_eq!(
        resolve_path_root_from_context(&context, PathRoot::CodexHome),
        PathBuf::from("/srv/codex")
    );
    assert_eq!(
        resolve_path_root_from_context(&context, PathRoot::DataHome),
        PathBuf::from("/xdg/data")
    );
}

#[test]
fn resolves_macos_default_roots_from_context() {
    let home = PathBuf::from("/Users/tester");
    let context = RootResolutionContext {
        home: home.clone(),
        codex_home: None,
        data_home: Some(default_data_home(HostPlatform::MacOs, &home)),
    };

    assert_eq!(
        resolve_path_root_from_context(&context, PathRoot::CodexHome),
        PathBuf::from("/Users/tester/.codex")
    );
    assert_eq!(
        resolve_path_root_from_context(&context, PathRoot::DataHome),
        PathBuf::from("/Users/tester/Library/Application Support")
    );
}

#[test]
fn resolves_windows_default_roots_from_context() {
    let home = PathBuf::from(r#"C:\Users\tester"#);
    let context = RootResolutionContext {
        home: home.clone(),
        codex_home: None,
        data_home: Some(default_data_home(HostPlatform::Windows, &home)),
    };

    assert_eq!(
        resolve_path_root_from_context(&context, PathRoot::CodexHome),
        PathBuf::from(r#"C:\Users\tester/.codex"#)
    );
    assert_eq!(
        resolve_path_root_from_context(&context, PathRoot::DataHome),
        PathBuf::from(r#"C:\Users\tester/AppData/Local"#)
    );
}

#[test]
fn discovers_windows_codex_source_candidates() {
    let temp = tempdir().expect("tempdir");
    let home = temp.path().join("Users/tester");
    let codex_home = home.join(".codex");
    let context = RootResolutionContext {
        home: home.clone(),
        codex_home: None,
        data_home: Some(home.join("AppData/Local")),
    };

    fs::create_dir_all(codex_home.join("sessions/2026/05")).expect("codex sessions dir");
    fs::create_dir_all(codex_home.join("archived_sessions")).expect("codex archived dir");
    fs::create_dir_all(codex_home.join("headless")).expect("codex headless dir");
    fs::write(codex_home.join("sessions/2026/05/session-a.jsonl"), b"{}\n")
        .expect("codex session fixture");
    fs::write(
        codex_home.join("archived_sessions/session-b.jsonl"),
        b"{}\n",
    )
    .expect("codex archived fixture");
    fs::write(codex_home.join("headless/headless-a.jsonl"), b"{}\n")
        .expect("codex headless fixture");

    let source_ids = [
        "codex.sessions",
        "codex.archived_sessions",
        "codex.headless_sessions",
    ];
    let sources = source_ids
        .into_iter()
        .flat_map(|source_id| {
            let (client, source_def) = lookup_source(source_id);
            discover_source_from_context(&context, client, source_def)
        })
        .collect::<Vec<_>>();
    let keys: HashSet<_> = sources
        .iter()
        .map(|source| {
            (
                source.client,
                source.kind,
                source
                    .path
                    .strip_prefix(&home)
                    .expect("relative path")
                    .to_path_buf(),
            )
        })
        .collect();

    assert!(keys.contains(&(
        ClientId::Codex,
        SourceKind::Jsonl,
        PathBuf::from(".codex/sessions/2026/05/session-a.jsonl")
    )));
    assert!(keys.contains(&(
        ClientId::Codex,
        SourceKind::ArchivedJsonl,
        PathBuf::from(".codex/archived_sessions/session-b.jsonl")
    )));
    assert!(keys.contains(&(
        ClientId::Codex,
        SourceKind::HeadlessJsonl,
        PathBuf::from(".codex/headless/headless-a.jsonl")
    )));
}

#[test]
fn resolves_confirmed_macos_source_candidates() {
    let home = PathBuf::from("/Users/tester");
    let context = RootResolutionContext {
        home: home.clone(),
        codex_home: None,
        data_home: Some(default_data_home(HostPlatform::MacOs, &home)),
    };

    let lookup = |id: &str| lookup_source(id).1;

    assert_eq!(
        source_search_root_from_context(&context, lookup("codex.sessions")),
        PathBuf::from("/Users/tester/.codex/sessions")
    );
    assert_eq!(
        source_search_root_from_context(&context, lookup("claude.projects")),
        PathBuf::from("/Users/tester/.claude/projects")
    );
    assert_eq!(
        source_search_root_from_context(&context, lookup("qwen.projects")),
        PathBuf::from("/Users/tester/.qwen/projects")
    );
    assert_eq!(
        source_search_root_from_context(&context, lookup("openclaw.agents")),
        PathBuf::from("/Users/tester/.openclaw/agents")
    );
    assert_eq!(
        source_search_root_from_context(&context, lookup("opencode.sqlite")),
        PathBuf::from("/Users/tester/Library/Application Support/opencode/opencode.db")
    );
}

#[test]
fn claude_config_dir_adds_a_relocated_projects_root() {
    use super::claude_projects_search_roots;
    let temp = tempdir().unwrap();
    let default = temp.path().join("home/.claude/projects");
    let relocated = temp.path().join("relocated");

    assert_eq!(
        claude_projects_search_roots(default.clone(), None),
        vec![default.clone()]
    );
    assert_eq!(
        claude_projects_search_roots(default.clone(), Some("".into())),
        vec![default.clone()]
    );
    assert_eq!(
        claude_projects_search_roots(default.clone(), Some(relocated.clone().into())),
        vec![default.clone(), relocated.join("projects")]
    );
    // A relocation naming the default directory, spelled differently, is one root.
    fs::create_dir_all(&default).unwrap();
    let alias = temp.path().join("home/.claude/../.claude");
    assert_eq!(
        claude_projects_search_roots(default.clone(), Some(alias.into())),
        vec![default]
    );
}

#[test]
fn explicit_root_ignores_claude_config_dir() {
    let (_, def) = lookup_source("claude.projects");
    let temp = tempdir().unwrap();
    // Environment-independent: an explicit root never consults the variable.
    assert_eq!(
        super::source_search_roots(temp.path(), def, supported_clients()),
        vec![temp.path().join(".claude/projects")]
    );
}

#[test]
fn opencode_channel_names_and_xdg_controls_are_exact() {
    for name in [
        "opencode.db",
        "opencode-stable.db",
        "opencode-Latest.db",
        "opencode-test_branch.1.db",
    ] {
        assert!(super::opencode_database_name(Path::new(name)), "{name}");
    }
    for name in [
        "Opencode.db",
        "Opencode-stable.db",
        "opencode-.db",
        "opencode-a b.db",
        "opencode-stable.db-wal",
        "opencode-stable.db-shm",
        "opencode-stable.db.bak",
        "unrelated.db",
    ] {
        assert!(!super::opencode_database_name(Path::new(name)), "{name}");
    }
    let home = Path::new("/synthetic/home");
    assert_eq!(
        super::opencode_data_directory(home, None),
        home.join(".local/share/opencode")
    );
    assert_eq!(
        super::opencode_data_directory(home, Some(Path::new(""))),
        home.join(".local/share/opencode")
    );
    assert_eq!(
        super::opencode_data_directory(home, Some(Path::new("/synthetic/xdg"))),
        Path::new("/synthetic/xdg/opencode")
    );
}

#[test]
fn opencode_channel_budget_counts_unmatched_directory_entries() {
    let temp = tempdir().unwrap();
    for index in 0..20 {
        fs::write(
            temp.path().join(format!("unrelated-{index}")),
            b"synthetic metadata only",
        )
        .unwrap();
    }
    let mut remaining = 10;
    assert_eq!(
        super::bounded_paths(
            temp.path(),
            &[],
            ClientId::OpenCode,
            lookup_source("opencode.sqlite").1,
            &mut remaining,
            1,
            true,
            &mut Vec::new()
        ),
        Err(super::BoundedDiscoveryError::LimitExceeded)
    );
    assert_eq!(remaining, 0);
}

#[test]
fn opencode_bounded_environment_discovery_preserves_scope_and_failures() {
    const CHILD: &str = "TELLTALE_RELOCATION_DISCOVERY_CHILD";
    if let Some(mode) = std::env::var_os(CHILD) {
        let bounded = super::discover_sources_bounded(
            Path::new("."),
            ClientId::OpenCode,
            16384,
            supported_clients(),
        );
        if mode == "symlink" || mode == "directory" {
            let expected = if mode == "symlink" {
                super::BoundedDiscoveryError::SymlinkRoot
            } else {
                super::BoundedDiscoveryError::Traversal
            };
            assert_eq!(bounded, Err(expected));
            assert_eq!(
                super::opencode_database_override(Path::new("."), supported_clients()),
                Err(expected)
            );
            assert!(discover_sources(Path::new("."), supported_clients()).is_err());
            assert_eq!(
                discover_sources_best_effort(Path::new("."), supported_clients()).len(),
                2
            );
        } else {
            let checked = discover_sources(Path::new("."), supported_clients()).unwrap();
            assert_eq!(checked.len(), if mode == "duplicate" { 2 } else { 3 });
            assert_eq!(bounded.unwrap(), checked);
            assert_eq!(
                discover_sources_best_effort(Path::new("."), supported_clients()),
                checked
            );
            assert!(
                checked
                    .iter()
                    .all(|source| source.client == ClientId::OpenCode
                        && source.source_id == "opencode.sqlite")
            );
            assert_eq!(
                super::discover_sources_bounded(
                    Path::new("."),
                    ClientId::OpenCode,
                    1,
                    supported_clients()
                ),
                Err(super::BoundedDiscoveryError::LimitExceeded)
            );
            let override_path =
                super::opencode_database_override(Path::new("."), supported_clients())
                    .unwrap()
                    .unwrap();
            assert_eq!(
                super::inspect_opencode_path(&override_path, &[], &mut 1, false),
                Err(super::BoundedDiscoveryError::LimitExceeded)
            );
            assert!(
                super::discover_sources_bounded(
                    Path::new("."),
                    ClientId::Qwen,
                    16384,
                    supported_clients()
                )
                .unwrap()
                .is_empty()
            );
        }
        return;
    }
    let temp = tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let home = root.join("home");
    let work = root.join("work");
    let data = home.join("data/opencode");
    let outside = root.join("PRIVATE-OVERRIDE");
    fs::create_dir_all(data.join("nested")).unwrap();
    fs::create_dir_all(&work).unwrap();
    fs::create_dir_all(&outside).unwrap();
    for name in [
        "opencode.db",
        "opencode-stable.db",
        "unrelated.db",
        "opencode-stable.db-wal",
        "nested/opencode-other.db",
    ] {
        fs::write(data.join(name), b"synthetic metadata only").unwrap();
    }
    let database = outside.join("custom.sqlite");
    fs::write(&database, b"synthetic metadata only").unwrap();
    fs::write(
        outside.join("opencode-neighbor.db"),
        b"synthetic metadata only",
    )
    .unwrap();
    let run = |mode: &str, path: &Path| {
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command.env_clear().current_dir(&work)
                .env("HOME", &home).env("USERPROFILE", &home).env("XDG_DATA_HOME", home.join("data"))
                .env("OPENCODE_DB", path).env(CHILD, mode)
                .args(["--exact", "discovery::tests::opencode_bounded_environment_discovery_preserves_scope_and_failures", "--nocapture"]);
        if mode == "duplicate" {
            command.env("XDG_DATA_HOME", home.join("data/../data"));
        }
        for key in ["PATH", "SystemRoot", "windir"] {
            if let Some(value) = std::env::var_os(key) {
                command.env(key, value);
            }
        }
        let output = command.output().unwrap();
        assert!(output.status.success(), "{output:?}");
    };
    run("normal", &database);
    run(
        "normal",
        Path::new("../../../PRIVATE-OVERRIDE/custom.sqlite"),
    );
    run("duplicate", Path::new("opencode.db"));
    fs::create_dir_all(data.join("~")).unwrap();
    fs::write(data.join("~/custom.sqlite"), b"synthetic metadata only").unwrap();
    run("normal", Path::new("~/custom.sqlite"));
    #[cfg(windows)]
    {
        fs::rename(data.join("opencode.db"), data.join("Opencode.db")).unwrap();
        run("normal", &database);
    }
    run("directory", &outside);
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&database, outside.join("leaf-link")).unwrap();
        run("symlink", &outside.join("leaf-link"));
        std::os::unix::fs::symlink(&outside, root.join("directory-link")).unwrap();
        run("symlink", &root.join("directory-link/custom.sqlite"));
    }
}

#[cfg(unix)]
#[test]
fn opencode_explicit_root_retains_legacy_default_link_coordinates() {
    let temp = tempdir().unwrap();
    let home = temp.path().join("home");
    let data = home.join("opencode");
    fs::create_dir_all(&data).unwrap();
    let target = temp.path().join("synthetic.sqlite");
    fs::write(&target, b"synthetic metadata only").unwrap();
    let path = data.join("opencode.db");
    std::os::unix::fs::symlink(target, &path).unwrap();
    let sources = discover_sources(&home, supported_clients()).unwrap();
    assert_eq!(sources.len(), 1);
    assert_eq!(sources[0].path, path);
    assert_eq!(
        discover_sources_best_effort(&home, supported_clients()),
        sources
    );
    assert_eq!(
        discover_watch_roots_for_clients(&home, &[ClientId::OpenCode], supported_clients()),
        vec![data]
    );
    assert_eq!(
        super::discover_sources_bounded(&home, ClientId::OpenCode, 16384, supported_clients()),
        Err(super::BoundedDiscoveryError::SymlinkRoot)
    );
}

#[cfg(unix)]
#[test]
fn opencode_environment_default_links_preserve_discovery_boundaries() {
    const CHILD: &str = "TELLTALE_OPENCODE_DEFAULT_LINK_CHILD";
    if let Some(mode) = std::env::var_os(CHILD) {
        let home = PathBuf::from(std::env::var_os("HOME").unwrap());
        let root = home.parent().unwrap();
        let data = home.join("data/opencode");
        let bounded = super::discover_sources_bounded(
            Path::new("."),
            ClientId::OpenCode,
            16384,
            supported_clients(),
        );
        let checked = discover_sources(Path::new("."), supported_clients());
        assert_eq!(bounded, Err(super::BoundedDiscoveryError::SymlinkRoot));
        assert!(
            matches!(&checked, Err(DiscoveryError::Traversal { source_id, .. }) if source_id == "opencode.sqlite"),
            "bounded={bounded:?}; checked={checked:?}"
        );
        let mut expected = vec![root.join("allowed.sqlite")];
        let mut expected_roots = vec![root.to_path_buf()];
        // A linked HOME is a trust anchor resolved once, so "home" behaves
        // like "file". A linked XDG_DATA_HOME inside HOME ("ancestor")
        // gets no anchor of its own and stays refused.
        if mode != "directory" && mode != "ancestor" {
            expected.push(data.join("opencode-preview.db"));
            expected_roots.push(data);
        }
        expected.sort();
        expected_roots.sort();
        let sources = discover_sources_best_effort(Path::new("."), supported_clients());
        let mut actual = sources
            .iter()
            .map(|source| source.path.clone())
            .collect::<Vec<_>>();
        actual.sort();
        assert_eq!(actual, expected);
        assert_eq!(
            discover_watch_roots_for_clients(
                Path::new("."),
                &[ClientId::OpenCode],
                supported_clients()
            ),
            expected_roots
        );
        return;
    }
    let mut failures = Vec::new();
    for mode in [
        "file",
        "dangling",
        "leaf-directory",
        "directory",
        "ancestor",
        "home",
    ] {
        let temp = tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let home = root.join("home");
        let work = root.join("work");
        let outside = root.join("PRIVATE-DEFAULT/opencode");
        if mode == "home" {
            let real_home = root.join("real-home");
            fs::create_dir_all(&real_home).unwrap();
            std::os::unix::fs::symlink(real_home, &home).unwrap();
        } else {
            fs::create_dir_all(&home).unwrap();
        }
        fs::create_dir_all(&work).unwrap();
        fs::create_dir_all(&outside).unwrap();
        fs::write(root.join("allowed.sqlite"), b"synthetic metadata only").unwrap();
        fs::write(outside.join("opencode.db"), b"synthetic metadata only").unwrap();
        let data = home.join("data/opencode");
        match mode {
            "ancestor" => {
                std::os::unix::fs::symlink(outside.parent().unwrap(), home.join("data")).unwrap()
            }
            "directory" => {
                fs::create_dir_all(home.join("data")).unwrap();
                std::os::unix::fs::symlink(&outside, &data).unwrap();
            }
            _ => {
                fs::create_dir_all(&data).unwrap();
                fs::write(data.join("opencode-preview.db"), b"synthetic metadata only").unwrap();
                let target = match mode {
                    "dangling" => outside.join("missing.sqlite"),
                    "leaf-directory" => outside.clone(),
                    _ => outside.join("opencode.db"),
                };
                std::os::unix::fs::symlink(target, data.join("opencode.db")).unwrap();
            }
        }
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command.env_clear().current_dir(&work)
                .env("HOME", &home).env("USERPROFILE", &home)
                .env("XDG_DATA_HOME", home.join("data"))
                .env("OPENCODE_DB", root.join("allowed.sqlite")).env(CHILD, mode)
                .args(["--exact", "discovery::tests::opencode_environment_default_links_preserve_discovery_boundaries", "--nocapture"]);
        for key in ["PATH", "SystemRoot", "windir"] {
            if let Some(value) = std::env::var_os(key) {
                command.env(key, value);
            }
        }
        let output = command.output().unwrap();
        if !output.status.success() {
            failures.push(format!("{mode}: {output:?}"));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
