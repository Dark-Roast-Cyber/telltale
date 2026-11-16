//! Real-process inventory checks use synthetic locations, never host sessions.

use std::process::{Command, Output};

fn synthetic_root() -> tempfile::TempDir {
    let parent = std::env::temp_dir().canonicalize().unwrap();
    let mut builder = tempfile::Builder::new();
    builder.prefix("PRIVATE_ROOT_");
    // Linux accepts arbitrary filename bytes; APFS and NTFS reject this one.
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::ffi::OsStrExt;
        builder.prefix(std::ffi::OsStr::from_bytes(b"PRIVATE_ROOT_\xff"));
    }
    builder.tempdir_in(parent).unwrap()
}

fn discover(args: &[&std::ffi::OsStr]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_telltale"));
    command.env_clear().arg("discover").args(args);
    for name in ["SystemRoot", "windir"] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    command.output().unwrap()
}

#[test]
#[cfg(unix)]
fn inventory_is_one_content_free_record_without_token_collection() {
    let root = synthetic_root();
    let sessions = root.path().join(".gemini/tmp");
    std::fs::create_dir_all(&sessions).unwrap();
    std::fs::write(
        sessions.join("PRIVATE_SESSION_NAME.json"),
        b"PRIVATE_SESSION_CONTENT",
    )
    .unwrap();
    let output = discover(&["--root".as_ref(), root.path().as_os_str()]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_eq!(stdout.lines().count(), 1);
    let record: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(record["schema"], "telltale.inventory/v1");
    assert!(!stdout.contains("PRIVATE_SESSION"));
    assert!(!stdout.contains(root.path().to_string_lossy().as_ref()));
    assert!(!stdout.contains("input_tokens"));
    assert!(!stdout.contains("output_tokens"));
    assert!(output.stderr.is_empty());
}

#[test]
fn license_notice_needs_no_host_roots_and_includes_upstream_mit_terms() {
    let output = discover(&["--licenses".as_ref()]);
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("Copyright (c) 2025 Junho Yeo"));
    assert!(stdout.contains("Permission is hereby granted, free of charge"));
    assert!(stdout.contains("THE SOFTWARE IS PROVIDED \"AS IS\""));
    assert!(output.stderr.is_empty());
}

#[test]
fn invalid_root_reports_no_partial_snapshot_or_private_path() {
    let root = synthetic_root();
    let missing = root.path().join("PRIVATE_INVENTORY_ROOT");
    let output = discover(&["--root".as_ref(), missing.as_os_str()]);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(!stderr.contains("PRIVATE_INVENTORY_ROOT"));
    assert!(!stderr.contains(root.path().to_string_lossy().as_ref()));
}

#[test]
fn zero_budget_is_rejected_before_inventory_output() {
    let root = tempfile::tempdir().unwrap();
    let output = discover(&[
        "--root".as_ref(),
        root.path().as_os_str(),
        "--max-checks".as_ref(),
        "0".as_ref(),
    ]);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
}

#[test]
#[cfg(not(unix))]
fn unsupported_platform_precedes_home_and_root_resolution() {
    for args in [
        vec![],
        vec!["--root".as_ref(), "PRIVATE_MISSING_ROOT".as_ref()],
    ] {
        let output = discover(&args);
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert_eq!(
            String::from_utf8(output.stderr).unwrap().trim(),
            "inventory execution platform unsupported"
        );
    }
}
