use std::fs;
use std::io;
use std::path::Path;

use tempfile::tempdir;

use super::{
    LocalConfigDiscoveryKind, discover_local_config_files, effective_rule_paths,
    resolve_allowlist_path, resolve_policy_path,
};

fn write(path: &Path) {
    fs::create_dir_all(path.parent().expect("parent dir")).expect("create parent");
    fs::write(path, "---\n").expect("write file");
}

#[test]
fn user_config_root_prefers_xdg_then_home_then_windows_profile() {
    use std::ffi::OsString;
    use std::path::PathBuf;
    let root = |xdg: Option<&str>, home: Option<&str>, profile: Option<&str>| {
        super::user_config_root_from(
            xdg.map(OsString::from),
            home.map(OsString::from),
            profile.map(OsString::from),
        )
    };
    let dot_config = |base: &str| PathBuf::from(base).join(".config").join("telltale");
    assert_eq!(
        root(Some("xdg"), Some("home"), Some("profile")),
        Some(PathBuf::from("xdg").join("telltale"))
    );
    assert_eq!(
        root(Some(""), Some("home"), Some("profile")),
        Some(dot_config("home"))
    );
    assert_eq!(
        root(None, Some(""), Some("profile")),
        Some(dot_config("profile"))
    );
    assert_eq!(
        root(None, None, Some("profile")),
        Some(dot_config("profile"))
    );
    assert_eq!(root(None, None, Some("")), None);
    assert_eq!(root(None, None, None), None);
}

#[test]
fn optional_metadata_skips_only_genuinely_absent_paths() {
    let temp = tempdir().expect("tempdir");
    let missing = temp.path().join("missing");
    assert!(
        super::config_metadata(&missing, true)
            .expect("optional absent path")
            .is_none()
    );
    assert!(super::config_metadata(&missing, false).is_err());
    assert!(
        super::config_metadata(temp.path(), true)
            .expect("present optional root")
            .is_some()
    );
}

#[test]
fn metadata_errors_are_not_optional_and_have_bounded_diagnostics() {
    let temp = tempdir().expect("tempdir");
    for optional in [false, true] {
        for kind in [io::ErrorKind::PermissionDenied, io::ErrorKind::Other] {
            let error = super::config_metadata_result(
                temp.path(),
                optional,
                Err(io::Error::new(kind, "CONTROLLED_METADATA_SECRET")),
            )
            .expect_err("metadata failure is not absence");
            assert_eq!(error.kind(), kind);
            assert_eq!(
                error.to_string(),
                format!("local config metadata failed: {kind:?}")
            );
            assert!(!format!("{error:?}").contains("CONTROLLED_METADATA_SECRET"));
        }
    }
}

#[cfg(unix)]
#[test]
fn optional_broken_root_symlink_is_not_absent() {
    let temp = tempdir().expect("tempdir");
    let root = temp.path().join("root");
    std::os::unix::fs::symlink("missing-target", &root).expect("broken root link");
    super::config_metadata(&root, true).expect_err("broken optional root must fail");
}

#[test]
fn discovers_yaml_files_in_root_order_then_path_order() {
    let temp = tempdir().expect("tempdir");
    let root_a = temp.path().join("a");
    let root_b = temp.path().join("b");
    write(&root_a.join("rules.d/z.yml"));
    write(&root_a.join("rules.d/a.yaml"));
    write(&root_a.join("organization-rules.d/org.yaml"));
    write(&root_a.join("ui-rules.d/ui.yaml"));
    write(&root_a.join("rules.d/ignored.txt"));
    write(&root_a.join("overrides.d/z.yml"));
    write(&root_a.join("overrides.d/a.yaml"));
    write(&root_b.join("rules.d/b.yaml"));
    write(&root_b.join("organization-rules.d/org-b.yaml"));
    write(&root_b.join("ui-rules.d/ui-b.yaml"));
    write(&root_b.join("overrides.d/b.yaml"));

    let discovered = discover_local_config_files(
        &[root_a.clone(), root_b.clone()],
        false,
        LocalConfigDiscoveryKind::Scan,
    )
    .expect("discover config");

    assert_eq!(
        discovered.rule_paths,
        vec![
            root_a.join("organization-rules.d/org.yaml"),
            root_b.join("organization-rules.d/org-b.yaml"),
            root_a.join("rules.d/a.yaml"),
            root_a.join("rules.d/z.yml"),
            root_b.join("rules.d/b.yaml"),
            root_a.join("ui-rules.d/ui.yaml"),
            root_b.join("ui-rules.d/ui-b.yaml"),
        ]
    );
    assert_eq!(
        discovered.organization_rule_paths,
        vec![
            root_a.join("organization-rules.d/org.yaml"),
            root_b.join("organization-rules.d/org-b.yaml"),
        ]
    );
    assert_eq!(
        discovered.deployment_rule_paths,
        vec![
            root_a.join("rules.d/a.yaml"),
            root_a.join("rules.d/z.yml"),
            root_b.join("rules.d/b.yaml"),
        ]
    );
    assert_eq!(
        discovered.local_rule_paths,
        vec![
            root_a.join("ui-rules.d/ui.yaml"),
            root_b.join("ui-rules.d/ui-b.yaml")
        ]
    );
    assert_eq!(
        discovered.override_paths,
        vec![
            root_a.join("overrides.d/a.yaml"),
            root_a.join("overrides.d/z.yml"),
            root_b.join("overrides.d/b.yaml"),
        ]
    );
}

#[test]
fn ignores_existing_roots_with_missing_config_subdirs() {
    let temp = tempdir().expect("tempdir");
    let existing = temp.path().join("existing");
    fs::create_dir_all(&existing).expect("create root");

    let discovered =
        discover_local_config_files(&[existing], false, LocalConfigDiscoveryKind::Scan)
            .expect("discover config");

    assert!(discovered.rule_paths.is_empty());
    assert!(discovered.organization_rule_paths.is_empty());
    assert!(discovered.deployment_rule_paths.is_empty());
    assert!(discovered.local_rule_paths.is_empty());
    assert!(discovered.override_paths.is_empty());
    assert!(discovered.policy_paths.is_empty());
    assert!(discovered.allowlist_paths.is_empty());
    assert!(discovered.output_paths.is_empty());
}

#[test]
fn present_config_subdirs_must_be_directories() {
    for subdir in ["rules.d", "policies.d", "outputs.d"] {
        let temp = tempdir().expect("tempdir");
        write(&temp.path().join(subdir));
        let error = discover_local_config_files(
            &[temp.path().to_path_buf()],
            false,
            LocalConfigDiscoveryKind::Scan,
        )
        .expect_err("present config subdir with wrong type must fail");
        assert!(error.to_string().contains("not a directory"));
    }
}

#[test]
fn yaml_entries_must_be_regular_files() {
    for subdir in ["rules.d", "outputs.d"] {
        let temp = tempdir().expect("tempdir");
        fs::create_dir_all(temp.path().join(subdir).join("invalid.yaml")).expect("YAML directory");
        let error = discover_local_config_files(
            &[temp.path().to_path_buf()],
            false,
            LocalConfigDiscoveryKind::Scan,
        )
        .expect_err("YAML entry with wrong type must fail");
        assert!(error.to_string().contains("not a regular file"));
    }
}

#[cfg(unix)]
#[test]
fn broken_yaml_symlinks_are_errors_not_absent_configuration() {
    for subdir in ["rules.d", "outputs.d"] {
        let temp = tempdir().expect("tempdir");
        let dir = temp.path().join(subdir);
        fs::create_dir_all(&dir).expect("config subdir");
        std::os::unix::fs::symlink("missing-target", dir.join("broken.yaml"))
            .expect("broken YAML symlink");
        discover_local_config_files(
            &[temp.path().to_path_buf()],
            false,
            LocalConfigDiscoveryKind::Scan,
        )
        .expect_err("broken YAML symlink must fail");
    }
}

#[cfg(unix)]
#[test]
fn broken_config_subdir_symlinks_are_errors() {
    let temp = tempdir().expect("tempdir");
    std::os::unix::fs::symlink("missing-target", temp.path().join("rules.d"))
        .expect("broken subdir symlink");
    discover_local_config_files(
        &[temp.path().to_path_buf()],
        false,
        LocalConfigDiscoveryKind::Scan,
    )
    .expect_err("broken subdir symlink must fail");
}

#[cfg(unix)]
#[test]
fn valid_config_symlinks_are_followed_and_non_yaml_entries_ignored() {
    use std::os::unix::fs::symlink;

    let temp = tempdir().expect("tempdir");
    let target_root = temp.path().join("target");
    let rule = target_root.join("rule.yaml");
    write(&rule);
    let target_dir = temp.path().join("rule-files");
    fs::create_dir_all(&target_dir).expect("target directory");
    symlink(&rule, target_dir.join("linked.yml")).expect("valid YAML symlink");
    symlink("missing-target", target_dir.join("ignored.txt")).expect("non-YAML symlink");
    fs::create_dir(target_dir.join("nested")).expect("ignored directory");
    symlink(&target_dir, target_root.join("rules.d")).expect("valid directory symlink");
    let root = temp.path().join("linked-root");
    symlink(&target_root, &root).expect("valid root symlink");

    let discovered = discover_local_config_files(
        std::slice::from_ref(&root),
        false,
        LocalConfigDiscoveryKind::Scan,
    )
    .expect("discover symlink configuration");
    assert_eq!(discovered.rule_paths, vec![root.join("rules.d/linked.yml")]);
}

#[test]
fn explicit_missing_config_root_is_an_error() {
    let temp = tempdir().expect("tempdir");
    let missing = temp.path().join("missing");

    let error = discover_local_config_files(
        std::slice::from_ref(&missing),
        false,
        LocalConfigDiscoveryKind::Scan,
    )
    .expect_err("explicit missing config root should fail")
    .to_string();

    assert!(error.contains("local config metadata failed: NotFound"));
    assert!(!error.contains(&missing.display().to_string()));
}

#[test]
fn explicit_config_root_must_be_a_directory() {
    let temp = tempdir().expect("tempdir");
    let root = temp.path().join("root");
    write(&root);
    let error = discover_local_config_files(&[root], false, LocalConfigDiscoveryKind::Scan)
        .expect_err("wrong-type root must fail");
    assert_eq!(error.to_string(), "local config root is not a directory");
}

#[test]
fn no_local_config_ignores_explicit_roots() {
    let temp = tempdir().expect("tempdir");
    let root = temp.path().join("config");
    write(&root.join("rules.d/local.yaml"));
    write(&root.join("overrides.d/local.yaml"));
    write(&root.join("outputs.d"));

    let discovered = discover_local_config_files(&[root], true, LocalConfigDiscoveryKind::Scan)
        .expect("discover config");

    assert!(discovered.rule_paths.is_empty());
    assert!(discovered.organization_rule_paths.is_empty());
    assert!(discovered.override_paths.is_empty());
}

#[test]
fn rule_discovery_scans_overrides_but_not_allowlists() {
    let temp = tempdir().expect("tempdir");
    let root = temp.path().join("config");
    write(&root.join("rules.d/local.yaml"));
    write(&root.join("overrides.d/local.yaml"));
    write(&root.join("policies.d/local.yaml"));
    write(&root.join("allowlists.d/one.yaml"));
    write(&root.join("allowlists.d/two.yml"));
    write(&root.join("outputs.d"));

    let discovered = discover_local_config_files(
        std::slice::from_ref(&root),
        false,
        LocalConfigDiscoveryKind::Rules,
    )
    .expect("discover config");

    assert_eq!(discovered.rule_paths, vec![root.join("rules.d/local.yaml")]);
    assert_eq!(
        discovered.override_paths,
        vec![root.join("overrides.d/local.yaml")]
    );
    assert_eq!(
        discovered.policy_paths,
        vec![root.join("policies.d/local.yaml")]
    );
    assert!(discovered.allowlist_paths.is_empty());
    assert!(discovered.output_paths.is_empty());
}

#[test]
fn combines_discovered_rules_before_explicit_rules() {
    let discovered = vec![Path::new("local-a.yaml").to_path_buf()];
    let explicit = vec![Path::new("cli-b.yaml").to_path_buf()];

    assert_eq!(
        effective_rule_paths(&discovered, &explicit),
        vec![
            Path::new("local-a.yaml").to_path_buf(),
            Path::new("cli-b.yaml").to_path_buf(),
        ]
    );
}

#[test]
fn policy_and_allowlist_discovery_require_a_single_file() {
    let paths = vec![
        Path::new("one.yaml").to_path_buf(),
        Path::new("two.yml").to_path_buf(),
    ];

    let policy_error = resolve_policy_path(None, &paths)
        .expect_err("multiple discovered policies should be ambiguous")
        .to_string();
    assert!(policy_error.contains("multiple local policy files discovered"));
    assert!(policy_error.contains("pass --policy explicitly"));

    let allowlist_error = resolve_allowlist_path(None, &paths)
        .expect_err("multiple discovered allowlists should be ambiguous")
        .to_string();
    assert!(allowlist_error.contains("multiple local allowlist files discovered"));
    assert!(allowlist_error.contains("pass --allowlist explicitly"));
}

#[test]
fn explicit_policy_or_allowlist_wins_over_discovered_ambiguity() {
    let discovered = vec![
        Path::new("one.yaml").to_path_buf(),
        Path::new("two.yml").to_path_buf(),
    ];

    assert_eq!(
        resolve_policy_path(Some(Path::new("explicit-policy.yaml")), &discovered)
            .expect("resolve policy"),
        Some(Path::new("explicit-policy.yaml").to_path_buf())
    );
    assert_eq!(
        resolve_allowlist_path(Some(Path::new("explicit-allowlist.yaml")), &discovered)
            .expect("resolve allowlist"),
        Some(Path::new("explicit-allowlist.yaml").to_path_buf())
    );
}

/// Only paths read from the system root are checked, however that root
/// is named; a user-created folder there fails the load.
#[cfg(windows)]
#[test]
fn only_the_system_root_must_be_administrator_only() {
    let system = super::system_config_root().expect("ProgramData resolves");
    assert!(system.ends_with(r"ProgramData\telltale"));
    let temp = tempdir().expect("tempdir");
    super::trust_system_path(temp.path(), temp.path()).expect("not the system root");
    let error = super::trust_system_path(&system, temp.path())
        .expect_err("a user-owned folder is not trusted");
    let message = error.to_string();
    assert!(
        message.contains("Administrators, SYSTEM and TrustedInstaller"),
        "{message}"
    );
    let missing = super::trust_system_path(&system, &temp.path().join("missing"))
        .expect_err("an unreadable path is not trusted");
    assert!(missing.to_string().contains("NotFound"), "{missing}");
}
