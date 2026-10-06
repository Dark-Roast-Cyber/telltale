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

#[cfg(windows)]
#[test]
fn native_git_head_dependency_paths_exist_on_windows() {
    let temp = tempfile::tempdir().expect("tempdir");
    let git = temp.path().join(".git");
    std::fs::create_dir(&git).expect("Git directory");
    std::fs::write(git.join("HEAD"), b"ref: refs/heads/main\n").expect("HEAD");
    let root = std::fs::canonicalize(temp.path()).expect("canonical Windows root");
    for path in [
        root_build::git_head_path(&root),
        schema_build::git_head_path(&root),
    ] {
        assert_eq!(
            std::fs::read(path).expect("native HEAD path"),
            b"ref: refs/heads/main\n"
        );
    }
}
