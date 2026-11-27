use super::*;
use tempfile::tempdir;

#[test]
fn windows_opencode_desktop_is_confirmed_without_path_or_node() {
    for executable in [
        "AppData/Local/Programs/ai.opencode.desktop/OpenCode.exe",
        "AppData/Local/Programs/@opencode-aidesktop/OpenCode.exe",
        "AppData/Roaming/ai.opencode.desktop/cli/2.0.24/opencode-cli.exe",
    ] {
        let temp = tempdir().unwrap();
        let context = InstallInventoryContext {
            home: temp.path().into(),
            path_dirs: vec![],
            extension_roots: vec![],
            global_storage_roots: vec![],
            node_roots: vec![],
        };
        let observe = |platform| {
            collect_install_inventory_for_platform(&context, 1, platform)
                .agents
                .into_iter()
                .find(|agent| agent.agent == "opencode")
                .unwrap()
        };
        let path = temp.path().join(executable);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        assert_eq!(
            observe(InstallPlatform::Windows).confidence,
            InstallConfidence::Absent
        );
        std::fs::write(&path, b"metadata-only-probe-must-not-execute").unwrap();
        let agent = observe(InstallPlatform::Windows);
        assert!(agent.installed);
        assert_eq!(agent.confidence, InstallConfidence::Confirmed);
        assert!(
            !serde_json::to_string(&agent)
                .unwrap()
                .contains(temp.path().to_str().unwrap())
        );
        assert!(agent.signals.iter().any(|signal| signal.present
            && signal.kind == "executable"
            && signal.path_hash.is_some()));
        assert_eq!(
            observe(InstallPlatform::Unix).confidence,
            InstallConfidence::Absent
        );
    }
}

#[test]
fn windows_claude_desktop_bundle_is_confirmed_without_path_or_node() {
    for (root, signal_name) in [
        ("AppData/Roaming/Claude/claude-code", "claude-desktop"),
        (
            "AppData/Local/Packages/Claude_pzs8sxrjxfjjc/LocalCache/Roaming/Claude/claude-code",
            "claude-desktop-packaged",
        ),
        (
            "AppData/Local/Claude-Data/claude_pzs8sxrjxfjjc/claude-code",
            "claude-desktop-packaged",
        ),
    ] {
        let temp = tempdir().unwrap();
        let context = InstallInventoryContext {
            home: temp.path().into(),
            path_dirs: vec![],
            extension_roots: vec![],
            global_storage_roots: vec![],
            node_roots: vec![],
        };
        let observe = |platform| {
            collect_install_inventory_for_platform(&context, 1, platform)
                .agents
                .into_iter()
                .find(|agent| agent.agent == "claude")
                .unwrap()
        };
        let root = temp.path().join(root);
        // Wrong depths and a directory named like the binary are not evidence.
        std::fs::create_dir_all(root.join("2.1.295/d2e29494ec83/claude.exe")).unwrap();
        std::fs::write(root.join("claude.exe"), b"synthetic").unwrap();
        std::fs::write(root.join("2.1.295/claude.exe"), b"synthetic").unwrap();
        assert_eq!(
            observe(InstallPlatform::Windows).confidence,
            InstallConfidence::Absent
        );
        // Joined per component, as the directory walk builds it, so the
        // path hash compares equal on Windows.
        let path = root.join("2.1.266").join("b6be4b20d80c").join("claude.exe");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, b"metadata-only-probe-must-not-execute").unwrap();
        let agent = observe(InstallPlatform::Windows);
        assert!(agent.installed);
        assert_eq!(agent.confidence, InstallConfidence::Confirmed);
        assert!(
            !serde_json::to_string(&agent)
                .unwrap()
                .contains(temp.path().to_str().unwrap())
        );
        let present = agent
            .signals
            .iter()
            .filter(|signal| signal.present)
            .collect::<Vec<_>>();
        assert_eq!(present.len(), 1);
        assert_eq!(present[0].kind, "executable");
        assert_eq!(present[0].name, signal_name);
        assert_eq!(present[0].path_hash, Some(path_hash(&path)));
        assert_eq!(
            observe(InstallPlatform::Unix).confidence,
            InstallConfidence::Absent
        );
    }
}

#[test]
fn unbalanced_windows_path_quote_keeps_later_entries() {
    assert_eq!(
        split_unbalanced_windows_path(
            r#"C:\Windows;C:\Program Files\dotnet";C:\Users\u\.local\bin;;C:\Links"#
        ),
        Some(
            [
                r"C:\Windows",
                r"C:\Program Files\dotnet",
                r"C:\Users\u\.local\bin",
                r"C:\Links",
            ]
            .map(PathBuf::from)
            .to_vec()
        )
    );
    // Balanced quoting keeps the platform splitter's behavior.
    assert_eq!(
        split_unbalanced_windows_path(r#"C:\Windows;"C:\a;b";C:\Links"#),
        None
    );
}

#[test]
fn windows_codex_desktop_bundle_is_confirmed_without_path_or_node() {
    let temp = tempdir().unwrap();
    let context = InstallInventoryContext {
        home: temp.path().into(),
        path_dirs: vec![],
        extension_roots: vec![],
        global_storage_roots: vec![],
        node_roots: vec![],
    };
    let observe = |platform| {
        collect_install_inventory_for_platform(&context, 1, platform)
            .agents
            .into_iter()
            .find(|agent| agent.agent == "codex")
            .unwrap()
    };
    let root = temp.path().join("AppData/Local/OpenAI/Codex/bin");
    // Wrong depths, a sibling tool and a directory named like the binary
    // are not evidence.
    std::fs::create_dir_all(root.join("8dbccda2214d0643/codex.exe")).unwrap();
    std::fs::write(root.join("codex.exe"), b"synthetic").unwrap();
    std::fs::create_dir_all(root.join("1111111111111111/nested")).unwrap();
    std::fs::write(root.join("1111111111111111/nested/codex.exe"), b"synthetic").unwrap();
    std::fs::write(root.join("1111111111111111/rg.exe"), b"synthetic").unwrap();
    assert_eq!(
        observe(InstallPlatform::Windows).confidence,
        InstallConfidence::Absent
    );
    let path = root.join("f71a721e0e6193a9").join("codex.exe");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, b"metadata-only-probe-must-not-execute").unwrap();
    let agent = observe(InstallPlatform::Windows);
    assert!(agent.installed);
    assert_eq!(agent.confidence, InstallConfidence::Confirmed);
    assert!(
        !serde_json::to_string(&agent)
            .unwrap()
            .contains(temp.path().to_str().unwrap())
    );
    let present = agent
        .signals
        .iter()
        .filter(|signal| signal.present)
        .collect::<Vec<_>>();
    assert_eq!(present.len(), 1);
    assert_eq!(present[0].kind, "executable");
    assert_eq!(present[0].name, "codex-desktop");
    assert_eq!(present[0].path_hash, Some(path_hash(&path)));
    assert_eq!(
        observe(InstallPlatform::Unix).confidence,
        InstallConfidence::Absent
    );
}

#[test]
fn pi_managed_launcher_is_confirmed_without_path_or_node() {
    let temp = tempdir().unwrap();
    let context = InstallInventoryContext {
        home: temp.path().into(),
        path_dirs: vec![],
        extension_roots: vec![],
        global_storage_roots: vec![],
        node_roots: vec![],
    };
    let observe = |platform| {
        collect_install_inventory_for_platform(&context, 1, platform)
            .agents
            .into_iter()
            .find(|agent| agent.agent == "pi")
            .unwrap()
    };
    let bin = temp.path().join(".pi/agent/bin");
    // A directory named like the launcher and the bundled helpers are not
    // evidence.
    std::fs::create_dir_all(bin.join("pi.cmd")).unwrap();
    std::fs::write(bin.join("pi-launcher.js"), b"synthetic").unwrap();
    for platform in [InstallPlatform::Windows, InstallPlatform::Unix] {
        assert_eq!(observe(platform).confidence, InstallConfidence::Absent);
    }
    std::fs::remove_dir(bin.join("pi.cmd")).unwrap();
    for (platform, name) in [
        (InstallPlatform::Windows, "pi.cmd"),
        (InstallPlatform::Unix, "pi"),
    ] {
        let path = bin.join(name);
        std::fs::write(&path, b"metadata-only-probe-must-not-execute").unwrap();
        let agent = observe(platform);
        assert!(agent.installed);
        assert_eq!(agent.confidence, InstallConfidence::Confirmed);
        let present = agent
            .signals
            .iter()
            .filter(|signal| signal.present)
            .collect::<Vec<_>>();
        assert_eq!(present.len(), 1);
        assert_eq!(present[0].name, "pi-managed");
        assert_eq!(present[0].path_hash, Some(path_hash(&path)));
        std::fs::remove_file(&path).unwrap();
    }
}

#[cfg(windows)]
#[test]
fn detects_windows_executable_and_script_suffixes() {
    let temp = tempdir().expect("tempdir");
    for suffix in ["EXE", "com", "cmd", "bat", "ps1"] {
        let bin = temp.path().join(suffix);
        std::fs::create_dir(&bin).expect("bin");
        std::fs::write(bin.join(format!("codex.{suffix}")), b"").expect("Windows command metadata");
        let snapshot = collect_install_inventory_with_context(
            &InstallInventoryContext {
                home: temp.path().to_path_buf(),
                path_dirs: vec![bin],
                extension_roots: Vec::new(),
                global_storage_roots: Vec::new(),
                node_roots: Vec::new(),
            },
            1_000,
        );
        let codex = snapshot
            .agents
            .iter()
            .find(|agent| agent.agent == "codex")
            .expect("Codex observation");
        assert!(codex.installed, "suffix {suffix}");
        assert_eq!(codex.confidence, InstallConfidence::Confirmed);
        assert!(
            codex
                .signals
                .iter()
                .any(|signal| signal.kind == "executable"
                    && signal.present
                    && signal.path_hash.is_some())
        );
    }
    assert!(
        !executable_signal_for_platform(
            "codex",
            &[temp.path().join("absent")],
            InstallPlatform::Windows
        )
        .present
    );
}

#[test]
fn launcher_suffixes_follow_selected_platform() {
    let temp = tempdir().unwrap();
    for suffix in ["exe", "com", "cmd", "bat", "ps1"] {
        let dir = temp.path().join(suffix);
        std::fs::create_dir(&dir).unwrap();
        std::fs::write(dir.join(format!("claude.{suffix}")), b"synthetic").unwrap();
        assert!(
            executable_signal_for_platform(
                "claude",
                std::slice::from_ref(&dir),
                InstallPlatform::Windows
            )
            .present
        );
        assert!(!executable_signal_for_platform("claude", &[dir], InstallPlatform::Unix).present);
    }
    std::fs::write(temp.path().join("claude.exe.cmd"), b"synthetic").unwrap();
    assert!(
        !executable_signal_for_platform(
            "claude.exe",
            &[temp.path().into()],
            InstallPlatform::Windows
        )
        .present
    );
    std::fs::write(temp.path().join("claude.exe"), b"synthetic").unwrap();
    assert!(
        executable_signal_for_platform(
            "claude.exe",
            &[temp.path().into()],
            InstallPlatform::Windows
        )
        .present
    );
}

#[test]
fn session_evidence_is_partial_exact_and_content_free() {
    use telltale_schema::{
        clients::{ClientId, SourceKind},
        source::Source,
    };
    let temp = tempdir().unwrap();
    let context = InstallInventoryContext {
        home: temp.path().into(),
        path_dirs: vec![],
        extension_roots: vec![],
        global_storage_roots: vec![],
        node_roots: vec![],
    };
    let source = Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "codex.sessions".into(),
        path: temp.path().join("TT_SESSION_PATH_MARKER"),
    };
    let snapshot =
        collect_install_inventory_with_sources(&context, 1, std::slice::from_ref(&source));
    let codex = snapshot.agents.iter().find(|a| a.agent == "codex").unwrap();
    assert!(codex.installed);
    assert_eq!(codex.confidence, InstallConfidence::Partial);
    assert!(
        !serde_json::to_string(&snapshot)
            .unwrap()
            .contains("TT_SESSION_PATH_MARKER")
    );
    assert!(
        !serde_json::to_string(&snapshot_to_event(&snapshot).unwrap())
            .unwrap()
            .contains("TT_SESSION_PATH_MARKER")
    );
    let mut wrong = source;
    wrong.client = ClientId::Claude;
    let snapshot = collect_install_inventory_with_sources(&context, 1, &[wrong]);
    assert!(
        snapshot
            .agents
            .iter()
            .all(|a| a.confidence == InstallConfidence::Absent)
    );
}

#[test]
fn detects_cli_and_extension_install_evidence_without_contents() {
    let temp = tempdir().expect("tempdir");
    let bin = temp.path().join("bin");
    let npm_root = temp.path().join("node_modules");
    let extensions = temp.path().join("extensions");
    std::fs::create_dir_all(&bin).expect("bin");
    std::fs::create_dir_all(npm_root.join("@openai/codex")).expect("npm package");
    std::fs::create_dir_all(extensions.join("github.copilot-1.2.3")).expect("extension");
    std::fs::write(bin.join("codex"), b"").expect("codex executable");
    std::fs::write(npm_root.join("@openai/codex/package.json"), b"{}").expect("package");

    let snapshot = collect_install_inventory_with_context(
        &InstallInventoryContext {
            home: temp.path().to_path_buf(),
            path_dirs: vec![bin],
            extension_roots: vec![extensions],
            global_storage_roots: Vec::new(),
            node_roots: vec![npm_root],
        },
        1_000,
    );

    let codex = snapshot
        .agents
        .iter()
        .find(|agent| agent.agent == "codex")
        .expect("codex observation");
    assert!(codex.installed);
    assert_eq!(codex.confidence, InstallConfidence::Confirmed);
    let copilot = snapshot
        .agents
        .iter()
        .find(|agent| agent.agent == "copilot")
        .expect("copilot observation");
    assert!(copilot.installed);
    assert_eq!(copilot.confidence, InstallConfidence::Confirmed);
}

#[test]
fn marks_global_storage_only_as_partial() {
    let temp = tempdir().expect("tempdir");
    let storage = temp.path().join("globalStorage");
    std::fs::create_dir_all(storage.join("github.copilot")).expect("storage");

    let snapshot = collect_install_inventory_with_context(
        &InstallInventoryContext {
            home: temp.path().to_path_buf(),
            path_dirs: Vec::new(),
            extension_roots: Vec::new(),
            global_storage_roots: vec![storage],
            node_roots: Vec::new(),
        },
        1_000,
    );

    let copilot = snapshot
        .agents
        .iter()
        .find(|agent| agent.agent == "copilot")
        .expect("copilot observation");
    assert!(!copilot.installed);
    assert_eq!(copilot.confidence, InstallConfidence::Partial);
}

#[test]
fn inventory_due_honors_interval() {
    let snapshot = InstallInventorySnapshot {
        observed_at_unix_ms: 1_000,
        hash: "abc".to_string(),
        agents: Vec::new(),
    };

    assert!(!install_inventory_due(
        Some(&snapshot),
        1_000 + 86_399_000,
        86_400
    ));
    assert!(install_inventory_due(
        Some(&snapshot),
        1_000 + 86_400_000,
        86_400
    ));
    assert!(install_inventory_due(Some(&snapshot), 1_001, 0));
    assert!(install_inventory_due(None, 1_001, 86_400));
}
