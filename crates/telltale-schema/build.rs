use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const CHECKOUT_RELATIVE: &str = "../..";
const FULL_SHA_LENGTH: usize = 40;
const PUBLIC_SHA_LENGTH: usize = 12;

pub(crate) fn valid_sha(value: &str) -> bool {
    value.len() == FULL_SHA_LENGTH
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

pub(crate) fn public_sha(value: &str) -> Option<String> {
    valid_sha(value).then(|| value[..PUBLIC_SHA_LENGTH].to_string())
}

fn packaged_sha(manifest_dir: &Path) -> Option<Option<String>> {
    let path = manifest_dir.join(".cargo_vcs_info.json");
    let contents = fs::read_to_string(path).ok()?;
    let sha = contents
        .split_once("\"sha1\": \"")
        .and_then(|(_, rest)| rest.split_once('"').map(|(sha, _)| sha.to_string()));
    Some(sha.and_then(|sha| public_sha(&sha)))
}

fn checkout_root(manifest_dir: &Path) -> Option<PathBuf> {
    let root = fs::canonicalize(manifest_dir.join(CHECKOUT_RELATIVE)).ok()?;
    (root.join("Cargo.toml").is_file() && root.join("crates/telltale-schema/Cargo.toml").is_file())
        .then_some(root)
}

fn git_sha(root: &Path) -> Option<String> {
    let top = Command::new("git")
        .args(["-C", root.to_str()?, "rev-parse", "--show-toplevel"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|value| value.trim().to_string())
        .and_then(|value| fs::canonicalize(value).ok())?;
    if top != root {
        return None;
    }

    let output = Command::new("git")
        .args(["-C", root.to_str()?, "rev-parse", "HEAD"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|value| value.trim().to_string())?;
    public_sha(&output)
}

fn main() {
    let manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("manifest dir"));
    println!("cargo:rerun-if-changed=.cargo_vcs_info.json");

    let sha = match packaged_sha(&manifest_dir) {
        Some(Some(sha)) => sha,
        Some(None) => "unknown".to_string(),
        None => checkout_root(&manifest_dir)
            .and_then(|root| {
                println!("cargo:rerun-if-changed={}/.git/HEAD", root.display());
                git_sha(&root)
            })
            .unwrap_or_else(|| "unknown".to_string()),
    };

    println!("cargo:rustc-env=ADR_GIT_HASH={sha}");
}
