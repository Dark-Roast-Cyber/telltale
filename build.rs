use std::fs;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=.git/HEAD");
    if let Ok(head) = fs::read_to_string(".git/HEAD")
        && let Some(ref_path) = head.trim().strip_prefix("ref: ")
    {
        println!("cargo:rerun-if-changed=.git/{ref_path}");
    }

    let git_hash = Command::new("git")
        .args(["rev-parse", "--short=12", "HEAD"])
        .output()
        .ok()
        .and_then(|output| {
            output
                .status
                .success()
                .then(|| String::from_utf8_lossy(&output.stdout).trim().to_string())
        })
        .filter(|hash| !hash.is_empty())
        .unwrap_or_else(|| "unknown".to_string());

    println!("cargo:rustc-env=ADR_GIT_HASH={git_hash}");
}
