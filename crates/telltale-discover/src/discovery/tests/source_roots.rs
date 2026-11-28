use super::*;

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
    use super::super::claude_projects_search_roots;
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
        super::super::source_search_roots(temp.path(), def, supported_clients()),
        vec![temp.path().join(".claude/projects")]
    );
}
