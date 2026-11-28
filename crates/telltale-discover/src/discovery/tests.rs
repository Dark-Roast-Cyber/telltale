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

mod dedup;
mod failure_reporting;
mod opencode_roots;
mod source_roots;
