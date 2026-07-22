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
