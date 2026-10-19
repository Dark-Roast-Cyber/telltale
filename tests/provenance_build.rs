#[allow(dead_code)]
mod root_build {
    include!("../build.rs");
}

#[allow(dead_code)]
mod schema_build {
    include!("../crates/telltale-schema/build.rs");
}

fn assert_public_sha_contract(valid_sha: fn(&str) -> bool, public_sha: fn(&str) -> Option<String>) {
    let full_sha = "0123456789abcdef0123456789abcdef01234567";
    assert!(valid_sha(full_sha));
    assert_eq!(public_sha(full_sha).as_deref(), Some("0123456789ab"));
    assert_eq!(public_sha("unknown"), None);
    assert_eq!(public_sha("0123456789ABCDEF0123456789abcdef01234567"), None);
    assert_eq!(public_sha("0123456789abcdef"), None);
}

#[test]
fn build_scripts_share_exact_twelve_character_provenance_contract() {
    assert_public_sha_contract(root_build::valid_sha, root_build::public_sha);
    assert_public_sha_contract(schema_build::valid_sha, schema_build::public_sha);
}

fn git(root: &std::path::Path, args: &[&str]) -> String {
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .expect("Git available for provenance tests");
    assert!(output.status.success(), "Git fixture operation failed");
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

fn commit(root: &std::path::Path) -> String {
    git(
        root,
        &[
            "-c",
            "user.name=Synthetic",
            "-c",
            "user.email=synthetic@example.invalid",
            "commit",
            "--allow-empty",
            "-m",
            "synthetic provenance",
        ],
    );
    git(root, &["rev-parse", "HEAD"])
}

#[test]
fn checkout_provenance_tracks_commits_packed_refs_detached_heads_and_linked_worktrees() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("checkout");
    std::fs::create_dir_all(root.join("crates/telltale-schema")).unwrap();
    std::fs::write(root.join("Cargo.toml"), "").unwrap();
    std::fs::write(root.join("crates/telltale-schema/Cargo.toml"), "").unwrap();
    git(&root, &["init", "-b", "main"]);
    let first = commit(&root);
    let canonical = std::fs::canonicalize(&root).unwrap();
    for paths in [
        root_build::git_metadata_paths(&canonical).unwrap(),
        schema_build::git_metadata_paths(&canonical).unwrap(),
    ] {
        assert!(paths.contains(&canonical.join(".git/HEAD")));
        assert!(paths.contains(&canonical.join(".git/refs/heads/main")));
        assert!(paths.iter().all(|path| path.exists()));
    }
    let second = commit(&root);
    assert_ne!(first, second);
    assert_eq!(root_build::resolve_provenance(&root).unwrap(), second[..12]);
    assert_eq!(
        schema_build::resolve_provenance(&root.join("crates/telltale-schema")).unwrap(),
        second[..12]
    );
    git(&root, &["pack-refs", "--all", "--prune"]);
    assert!(
        root_build::git_metadata_paths(&canonical)
            .unwrap()
            .contains(&canonical.join(".git/packed-refs"))
    );
    git(&root, &["checkout", "--detach", "HEAD"]);
    assert_eq!(root_build::resolve_provenance(&root).unwrap(), second[..12]);

    // Materialize the expected checkout markers in the linked tree via a commit.
    git(
        &root,
        &["add", "Cargo.toml", "crates/telltale-schema/Cargo.toml"],
    );
    let linked_sha = commit(&root);
    let linked = temp.path().join("linked");
    git(
        &root,
        &[
            "worktree",
            "add",
            "--detach",
            linked.to_str().unwrap(),
            "HEAD",
        ],
    );
    let linked = std::fs::canonicalize(linked).unwrap();
    assert!(linked.join(".git").is_file());
    for paths in [
        root_build::git_metadata_paths(&linked).unwrap(),
        schema_build::git_metadata_paths(&linked).unwrap(),
    ] {
        assert!(paths.iter().all(|path| path.exists()));
        assert!(!paths.contains(&linked.join(".git/HEAD")));
        assert!(
            paths
                .iter()
                .any(|path| path.file_name().is_some_and(|name| name == "HEAD"))
        );
    }
    assert_eq!(
        root_build::resolve_provenance(&linked).unwrap(),
        linked_sha[..12]
    );
    assert_eq!(
        schema_build::resolve_provenance(&linked.join("crates/telltale-schema")).unwrap(),
        linked_sha[..12]
    );
}

#[test]
fn packaged_metadata_precedes_checkout_and_invalid_identity_is_bounded() {
    let temp = tempfile::tempdir().unwrap();
    let package = temp.path();
    let metadata = package.join(".cargo_vcs_info.json");
    std::fs::write(
        &metadata,
        r#"{"git":{"sha1": "0123456789abcdef0123456789abcdef01234567"}}"#,
    )
    .unwrap();
    assert_eq!(
        root_build::resolve_provenance(package).unwrap(),
        "0123456789ab"
    );
    assert_eq!(
        schema_build::resolve_provenance(package).unwrap(),
        "0123456789ab"
    );
    std::fs::write(metadata, r#"{"git":{"sha1": "invalid"}}"#).unwrap();
    assert_eq!(
        root_build::resolve_provenance(package),
        Err("invalid_revision")
    );
    assert_eq!(
        schema_build::resolve_provenance(package),
        Err("invalid_revision")
    );
}

#[test]
fn nested_checkout_markers_cannot_claim_the_parent_revision() {
    let temp = tempfile::tempdir().unwrap();
    git(temp.path(), &["init"]);
    commit(temp.path());
    let nested = temp.path().join("nested");
    std::fs::create_dir_all(nested.join("crates/telltale-schema")).unwrap();
    std::fs::write(nested.join("Cargo.toml"), "").unwrap();
    std::fs::write(nested.join("crates/telltale-schema/Cargo.toml"), "").unwrap();
    assert_eq!(
        root_build::resolve_provenance(&nested),
        Err("checkout_root_mismatch")
    );
    assert_eq!(
        schema_build::resolve_provenance(&nested.join("crates/telltale-schema")),
        Err("checkout_root_mismatch")
    );
}

#[test]
fn standalone_build_scripts_categorize_missing_git_and_emit_matching_real_revision() {
    let temp = tempfile::tempdir().unwrap();
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let revision = git(root, &["rev-parse", "HEAD"]);
    let decoy = temp.path().join("decoy");
    std::fs::create_dir_all(&decoy).unwrap();
    git(&decoy, &["init"]);
    let decoy_revision = commit(&decoy);
    for (index, (source, manifest)) in [
        ("build.rs", root.to_path_buf()),
        (
            "crates/telltale-schema/build.rs",
            root.join("crates/telltale-schema"),
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let binary = temp.path().join(format!(
            "provenance-{index}{}",
            std::env::consts::EXE_SUFFIX
        ));
        let status = std::process::Command::new("rustc")
            .args(["--edition=2024", "--crate-type=bin"])
            .arg(root.join(source))
            .arg("-o")
            .arg(&binary)
            .status()
            .expect("compile standalone build script");
        assert!(status.success());
        let missing = std::process::Command::new(&binary)
            .current_dir(temp.path())
            .env("CARGO_MANIFEST_DIR", &manifest)
            .env("PATH", "")
            .output()
            .unwrap();
        let missing = String::from_utf8(missing.stdout).unwrap();
        assert!(missing.contains("cargo:warning=telltale_provenance:git_unavailable"));
        assert!(missing.contains("cargo:rustc-env=TELLTALE_GIT_HASH=unknown"));
        let output = std::process::Command::new(&binary)
            .current_dir(temp.path())
            .env("CARGO_MANIFEST_DIR", &manifest)
            .output()
            .unwrap();
        let output = String::from_utf8(output.stdout).unwrap();
        assert!(output.contains(&format!(
            "cargo:rustc-env=TELLTALE_GIT_HASH={}",
            &revision[..12]
        )));
        assert!(output.contains("cargo:rerun-if-env-changed=PATH"));
        if cfg!(windows) {
            assert!(output.contains("cargo:rerun-if-env-changed=PATHEXT"));
        }
        assert!(!output.contains("cargo:warning="));
        // Repository-selection overrides cannot substitute another revision.
        let overridden = std::process::Command::new(&binary)
            .current_dir(temp.path())
            .env("CARGO_MANIFEST_DIR", &manifest)
            .env("GIT_DIR", decoy.join(".git"))
            .env("GIT_WORK_TREE", root)
            .env("GIT_COMMON_DIR", decoy.join(".git"))
            .output()
            .unwrap();
        let overridden = String::from_utf8(overridden.stdout).unwrap();
        assert!(overridden.contains(&format!(
            "cargo:rustc-env=TELLTALE_GIT_HASH={}",
            &revision[..12]
        )));
        assert!(!overridden.contains(&decoy_revision[..12]));
    }
}
