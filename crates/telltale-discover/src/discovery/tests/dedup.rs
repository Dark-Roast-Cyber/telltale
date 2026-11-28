use super::*;

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
        super::super::discover_sources_with_projects_best_effort(
            &home,
            &projects,
            supported_clients()
        ),
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
        super::super::discover_sources_with_projects_best_effort(
            &root,
            &projects,
            supported_clients()
        ),
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
    super::super::sort_and_dedup_sources(&mut sources);
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
