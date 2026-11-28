use super::*;

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
fn opencode_data_home_is_not_a_fixture_and_supports_bounded_discovery_and_watch() {
    let temp = tempdir().unwrap();
    let data_home = temp.path().join(".local/share");
    let db = data_home.join("opencode/opencode.db");
    fs::create_dir_all(db.parent().unwrap()).unwrap();
    fs::write(&db, b"synthetic metadata only").unwrap();
    assert!(!super::super::is_fixture_root(
        &data_home,
        supported_clients()
    ));
    let sources = discover_sources(&data_home, supported_clients()).unwrap();
    assert_eq!(sources.len(), 1);
    assert_eq!(sources[0].path, db);
    assert_eq!(
        super::super::discover_sources_bounded(
            &data_home,
            ClientId::OpenCode,
            1,
            supported_clients()
        )
        .unwrap(),
        sources
    );
    assert_eq!(
        discover_watch_roots_for_clients(&data_home, &[ClientId::OpenCode], supported_clients()),
        vec![db.parent().unwrap().to_path_buf()]
    );
    fs::write(data_home.join(".telltale-fixtures"), b"").unwrap();
    assert!(super::super::is_fixture_root(
        &data_home,
        supported_clients()
    ));
    assert_eq!(
        discover_sources(&data_home, supported_clients()).unwrap(),
        sources
    );
    assert!(super::super::is_fixture_root(
        &crate::test_fixture_path("session_stores"),
        supported_clients()
    ));
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
        super::super::discover_sources_bounded(
            temp.path(),
            ClientId::OpenCode,
            2,
            supported_clients()
        )
        .unwrap(),
        sources
    );
    assert_eq!(
        super::super::discover_sources_bounded(
            temp.path(),
            ClientId::OpenCode,
            1,
            supported_clients()
        ),
        Err(super::super::BoundedDiscoveryError::LimitExceeded)
    );
    let mut expected = stores.to_vec();
    expected.sort_unstable();
    assert_eq!(
        discover_watch_roots_for_clients(temp.path(), &[ClientId::OpenCode], supported_clients()),
        expected
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
        assert!(
            super::super::opencode_database_name(Path::new(name)),
            "{name}"
        );
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
        assert!(
            !super::super::opencode_database_name(Path::new(name)),
            "{name}"
        );
    }
    let home = Path::new("/synthetic/home");
    assert_eq!(
        super::super::opencode_data_directory(home, None),
        home.join(".local/share/opencode")
    );
    assert_eq!(
        super::super::opencode_data_directory(home, Some(Path::new(""))),
        home.join(".local/share/opencode")
    );
    assert_eq!(
        super::super::opencode_data_directory(home, Some(Path::new("/synthetic/xdg"))),
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
        super::super::bounded_paths(
            temp.path(),
            &[],
            ClientId::OpenCode,
            lookup_source("opencode.sqlite").1,
            &mut remaining,
            1,
            true,
            &mut Vec::new()
        ),
        Err(super::super::BoundedDiscoveryError::LimitExceeded)
    );
    assert_eq!(remaining, 0);
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
        super::super::discover_sources_bounded(
            &home,
            ClientId::OpenCode,
            16384,
            supported_clients()
        ),
        Err(super::super::BoundedDiscoveryError::SymlinkRoot)
    );
}
