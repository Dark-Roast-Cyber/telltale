use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const CHECKOUT_RELATIVE: &str = ".";
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
    let contents = fs::read_to_string(manifest_dir.join(".cargo_vcs_info.json")).ok()?;
    let sha = contents
        .split_once("\"sha1\": \"")
        .and_then(|(_, rest)| rest.split_once('"').map(|(sha, _)| sha));
    Some(sha.and_then(public_sha))
}

fn checkout_root(manifest_dir: &Path) -> Option<PathBuf> {
    let root = fs::canonicalize(manifest_dir.join(CHECKOUT_RELATIVE)).ok()?;
    (root.join("Cargo.toml").is_file() && root.join("crates/telltale-schema/Cargo.toml").is_file())
        .then_some(root)
}

// Never expose Git stderr, environments or private paths in warnings.
// Repository-selection overrides are removed so the checkout root alone decides
// which metadata is reported and watched.
fn git_output(root: &Path, args: &[&str]) -> Result<String, &'static str> {
    let output = Command::new("git")
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_COMMON_DIR")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                "git_unavailable"
            } else {
                "git_failed"
            }
        })?;
    if !output.status.success() {
        return Err("git_failed");
    }
    String::from_utf8(output.stdout)
        .map(|value| value.trim().to_string())
        .map_err(|_| "git_failed")
}

fn verify_checkout(root: &Path) -> Result<(), &'static str> {
    let top = git_output(root, &["rev-parse", "--show-toplevel"])?;
    let top = fs::canonicalize(top).map_err(|_| "git_failed")?;
    if top != root {
        return Err("checkout_root_mismatch");
    }
    Ok(())
}

pub(crate) fn git_metadata_paths(root: &Path) -> Result<Vec<PathBuf>, &'static str> {
    verify_checkout(root)?;
    // `--git-path` (Git 2.5+) prints a path relative to `root` unless it is
    // already absolute, as in linked worktrees; `--path-format` needs 2.31.
    let git_path = |name: &str| -> Result<PathBuf, &'static str> {
        git_output(root, &["rev-parse", "--git-path", name]).map(|path| root.join(path))
    };
    let head = git_path("HEAD")?;
    let mut paths = vec![head.clone()];
    let head_contents = fs::read_to_string(head).map_err(|_| "git_failed")?;
    if let Some(reference) = head_contents.trim().strip_prefix("ref: ") {
        paths.push(git_path(reference)?);
    }
    paths.push(git_path("packed-refs")?);
    // Watching an existing ancestor also detects newly created refs without
    // making Cargo perpetually dirty because a dependency does not yet exist.
    for path in &mut paths {
        while !path.exists() {
            *path = path.parent().ok_or("git_failed")?.to_path_buf();
        }
        *path = fs::canonicalize(&*path).map_err(|_| "git_failed")?;
    }
    paths.sort();
    paths.dedup();
    Ok(paths)
}

pub(crate) fn resolve_provenance(manifest_dir: &Path) -> Result<String, &'static str> {
    if let Some(sha) = packaged_sha(manifest_dir) {
        return sha.ok_or("invalid_revision");
    }
    let root = checkout_root(manifest_dir).ok_or("checkout_root_mismatch")?;
    verify_checkout(&root)?;
    public_sha(&git_output(&root, &["rev-parse", "HEAD"])?).ok_or("invalid_revision")
}

fn main() {
    let manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("manifest dir"));
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=.cargo_vcs_info.json");
    println!("cargo:rerun-if-env-changed=PATH");
    if cfg!(windows) {
        println!("cargo:rerun-if-env-changed=PATHEXT");
    }
    if packaged_sha(&manifest_dir).is_none()
        && let Some(root) = checkout_root(&manifest_dir)
        && let Ok(paths) = git_metadata_paths(&root)
    {
        for path in paths {
            println!("cargo:rerun-if-changed={}", path.display());
        }
    }
    let sha = resolve_provenance(&manifest_dir).unwrap_or_else(|category| {
        println!("cargo:warning=telltale_provenance:{category}");
        "unknown".to_string()
    });
    println!("cargo:rustc-env=TELLTALE_GIT_HASH={sha}");
}
