use super::*;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(unix)]
use std::os::unix::fs::symlink;

const HOST_ONLY_REPO_PATHS: &[&str] = &[
    "AGENTS.md",
    "PLAN.md",
    "VISION.md",
    "IDEAS.md",
    "docs/internal/",
    "docs/CHANGELOG.md",
    "docs/research-urls.md",
    "docs/siem-logging.md",
    "docs/splunk-content.md",
    "skills/",
    ".ai/",
    "tasks/",
    ".opencode/",
    "logs/",
    "state/",
    "artifacts/",
    "scripts/ralph",
    "scripts/inspiration/",
    "runtime/ralph/",
    "config/examples/splunk-",
    "openspec/changes/",
    "openspec/config.yaml",
];

const PUBLIC_OPENSPEC_CONTENT_MARKERS: &[&str] = &[
    "local-only evidence",
    "private evidence",
    "redacted local-only evidence",
];

#[cfg(unix)]
fn configure_git_user(repo: &Path) {
    git_expect(repo, &["config", "user.email", "adr-test@example.invalid"]);
    git_expect(repo, &["config", "user.name", "ADR Test"]);
}

#[cfg(unix)]
fn git_expect(repo: &Path, args: &[&str]) {
    let output = Command::new("git")
        .args(args)
        .current_dir(repo)
        .output()
        .expect("git command");
    assert!(
        output.status.success(),
        "git {args:?} failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

// These release-tooling tests invoke the Unix-only Makefile and shell tools.
#[cfg(unix)]
#[test]
fn release_context_check_rejects_empty_public_config() {
    let temp = tempdir().expect("tempdir");
    let repo = temp.path();

    let init = Command::new("git")
        .args(["init", "--quiet", "--initial-branch=main"])
        .current_dir(repo)
        .output()
        .expect("git init");
    assert!(
        init.status.success(),
        "git init failed: {}",
        String::from_utf8_lossy(&init.stderr)
    );

    let remote = "git@github.com:Dark-Roast-Cyber/telltale.git";
    let remote_add = Command::new("git")
        .args(["remote", "add", "origin", remote])
        .current_dir(repo)
        .output()
        .expect("git remote add");
    assert!(
        remote_add.status.success(),
        "git remote add failed: {}",
        String::from_utf8_lossy(&init.stderr)
    );

    let makefile = Path::new(env!("CARGO_MANIFEST_DIR")).join("Makefile");
    let output = Command::new("make")
        .arg("--silent")
        .arg("-f")
        .arg(makefile)
        .args([
            "release-context-check",
            "PUBLIC_RELEASE_BRANCH=",
            "PUBLIC_RELEASE_REMOTE=git@github.com:Dark-Roast-Cyber/telltale.git",
        ])
        .current_dir(repo)
        .env("MAKEFLAGS", "")
        .output()
        .expect("make release-context-check");

    assert!(
        !output.status.success(),
        "release-context-check should fail when PUBLIC_RELEASE_BRANCH is empty"
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("PUBLIC_RELEASE_BRANCH must be set."),
        "unexpected output: {combined}"
    );

    let output = Command::new("make")
        .arg("--silent")
        .arg("-f")
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("Makefile"))
        .args([
            "release-context-check",
            "PUBLIC_RELEASE_BRANCH=main",
            "PUBLIC_RELEASE_REMOTE=",
        ])
        .current_dir(repo)
        .env("MAKEFLAGS", "")
        .output()
        .expect("make release-context-check");

    assert!(
        !output.status.success(),
        "release-context-check should fail when PUBLIC_RELEASE_REMOTE is empty"
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("PUBLIC_RELEASE_REMOTE must be set."),
        "unexpected output: {combined}"
    );
}

#[cfg(unix)]
#[test]
fn public_push_review_summarizes_repo_and_staged_context() {
    let temp = tempdir().expect("tempdir");
    let repo = temp.path();

    let init = Command::new("git")
        .args(["init", "--quiet", "--initial-branch=main"])
        .current_dir(repo)
        .output()
        .expect("git init");
    assert!(
        init.status.success(),
        "git init failed: {}",
        String::from_utf8_lossy(&init.stderr)
    );
    configure_git_user(repo);
    git_expect(
        repo,
        &[
            "remote",
            "add",
            "origin",
            "git@github.com:Dark-Roast-Cyber/telltale.git",
        ],
    );

    fs::write(repo.join("tracked.txt"), "initial\n").expect("write tracked file");
    git_expect(repo, &["add", "tracked.txt"]);
    git_expect(repo, &["commit", "--quiet", "-m", "Initial commit"]);

    fs::write(repo.join("tracked.txt"), "modified\n").expect("modify tracked file");
    fs::write(repo.join("staged.txt"), "public\n").expect("write staged file");
    git_expect(repo, &["add", "staged.txt"]);

    let makefile = Path::new(env!("CARGO_MANIFEST_DIR")).join("Makefile");
    let output = Command::new("make")
        .arg("--silent")
        .arg("-f")
        .arg(makefile)
        .arg("public-push-review")
        .current_dir(repo)
        .env("MAKEFLAGS", "")
        .output()
        .expect("make public-push-review");

    assert!(
        output.status.success(),
        "public-push-review failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("stdout must be UTF-8");
    assert!(
        stdout.contains("Public branch: main"),
        "missing branch summary: {stdout}"
    );
    assert!(
        stdout.contains("Origin fetch: git@github.com:Dark-Roast-Cyber/telltale.git"),
        "missing fetch remote: {stdout}"
    );
    assert!(
        stdout.contains("Origin push: git@github.com:Dark-Roast-Cyber/telltale.git"),
        "missing push remote: {stdout}"
    );
    assert!(
        stdout.contains("Working tree status:") && stdout.contains(" M tracked.txt"),
        "missing dirty status: {stdout}"
    );
    assert!(
        stdout.contains("Staged paths:") && stdout.contains("staged.txt"),
        "missing staged path summary: {stdout}"
    );
    assert!(
        stdout.contains("docs/release-readiness.md") && stdout.contains("make release-preflight"),
        "missing public push reminder: {stdout}"
    );
}

#[cfg(unix)]
#[test]
fn release_context_check_reports_sync_and_rejects_behind_head() {
    let temp = tempdir().expect("tempdir");
    let bare = temp.path().join("origin.git");
    let repo = temp.path().join("work");
    let peer = temp.path().join("peer");

    let init_bare = Command::new("git")
        .args(["init", "--bare", "--quiet", "--initial-branch=main"])
        .arg(&bare)
        .output()
        .expect("git init bare");
    assert!(
        init_bare.status.success(),
        "git init bare failed: {}",
        String::from_utf8_lossy(&init_bare.stderr)
    );

    let clone = Command::new("git")
        .args(["clone", "--quiet"])
        .arg(&bare)
        .arg(&repo)
        .output()
        .expect("git clone");
    assert!(
        clone.status.success(),
        "git clone failed: {}",
        String::from_utf8_lossy(&clone.stderr)
    );
    configure_git_user(&repo);
    fs::write(repo.join("public.txt"), "initial public content\n").expect("write initial");
    git_expect(&repo, &["add", "public.txt"]);
    git_expect(
        &repo,
        &["commit", "--quiet", "-m", "Initial public content"],
    );
    git_expect(&repo, &["push", "--quiet", "-u", "origin", "main"]);

    let makefile = Path::new(env!("CARGO_MANIFEST_DIR")).join("Makefile");
    let output = Command::new("make")
        .arg("--silent")
        .arg("-f")
        .arg(&makefile)
        .arg("release-context-check")
        .arg(format!("PUBLIC_RELEASE_REMOTE={}", bare.to_string_lossy()))
        .current_dir(&repo)
        .env("MAKEFLAGS", "")
        .output()
        .expect("make release-context-check");
    assert!(
        output.status.success(),
        "release-context-check failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("origin/main matches HEAD"),
        "unexpected output: {}",
        String::from_utf8_lossy(&output.stdout)
    );

    let clone_peer = Command::new("git")
        .args(["clone", "--quiet"])
        .arg(&bare)
        .arg(&peer)
        .output()
        .expect("git clone peer");
    assert!(
        clone_peer.status.success(),
        "git clone peer failed: {}",
        String::from_utf8_lossy(&clone_peer.stderr)
    );
    configure_git_user(&peer);
    fs::write(peer.join("public.txt"), "remote public content\n").expect("write peer");
    git_expect(&peer, &["commit", "--quiet", "-am", "Remote public update"]);
    git_expect(&peer, &["push", "--quiet"]);
    git_expect(&repo, &["fetch", "--quiet", "origin", "main"]);

    let output = Command::new("make")
        .arg("--silent")
        .arg("-f")
        .arg(&makefile)
        .arg("release-context-check")
        .arg(format!("PUBLIC_RELEASE_REMOTE={}", bare.to_string_lossy()))
        .current_dir(&repo)
        .env("MAKEFLAGS", "")
        .output()
        .expect("make release-context-check");
    assert!(
        !output.status.success(),
        "release-context-check should fail when HEAD is behind"
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("HEAD is behind origin/main by 1 commit(s)"),
        "unexpected output: {combined}"
    );
}

#[cfg(unix)]
#[test]
fn release_tag_review_matches_package_version_and_rejects_mismatch() {
    let temp = tempdir().expect("tempdir");
    let repo = temp.path();
    fs::create_dir(repo.join("src")).expect("create src");
    fs::write(
        repo.join("Cargo.toml"),
        r#"[package]
name = "tag-review-fixture"
version = "1.2.3"
edition = "2021"
"#,
    )
    .expect("write Cargo.toml");
    fs::write(repo.join("src").join("lib.rs"), "pub fn fixture() {}\n").expect("write lib.rs");

    let init = Command::new("git")
        .args(["init", "--quiet", "--initial-branch=main"])
        .current_dir(repo)
        .output()
        .expect("git init");
    assert!(
        init.status.success(),
        "git init failed: {}",
        String::from_utf8_lossy(&init.stderr)
    );
    configure_git_user(repo);
    git_expect(repo, &["add", "Cargo.toml", "src/lib.rs"]);
    git_expect(repo, &["commit", "--quiet", "-m", "Initial fixture"]);

    let makefile = Path::new(env!("CARGO_MANIFEST_DIR")).join("Makefile");
    let output = Command::new("make")
        .arg("--silent")
        .arg("-f")
        .arg(&makefile)
        .arg("release-tag-review")
        .current_dir(repo)
        .env("MAKEFLAGS", "")
        .output()
        .expect("make release-tag-review");
    assert!(
        output.status.success(),
        "release-tag-review failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("Public release tag: v1.2.3"),
        "unexpected output: {}",
        String::from_utf8_lossy(&output.stdout)
    );

    let output = Command::new("make")
        .arg("--silent")
        .arg("-f")
        .arg(&makefile)
        .arg("release-tag-review")
        .arg("PUBLIC_RELEASE_TAG=v1.2.4")
        .current_dir(repo)
        .env("MAKEFLAGS", "")
        .output()
        .expect("make release-tag-review mismatch");
    assert!(
        !output.status.success(),
        "release-tag-review should fail when PUBLIC_RELEASE_TAG mismatches package version"
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("Expected public release tag v1.2.3"),
        "unexpected output: {combined}"
    );

    git_expect(repo, &["tag", "-m", "v1.2.3", "v1.2.3"]);
    let output = Command::new("make")
        .arg("--silent")
        .arg("-f")
        .arg(&makefile)
        .arg("release-tag-review")
        .current_dir(repo)
        .env("MAKEFLAGS", "")
        .output()
        .expect("make release-tag-review existing tag");
    assert!(
        !output.status.success(),
        "release-tag-review should fail when the release tag already exists"
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("Public release tag v1.2.3 already exists locally."),
        "unexpected output: {combined}"
    );
}

#[cfg(unix)]
#[test]
fn release_context_check_reports_empty_and_staged_paths() {
    let temp = tempdir().expect("tempdir");
    let bare = temp.path().join("origin.git");
    let repo = temp.path().join("work");

    let init_bare = Command::new("git")
        .args(["init", "--bare", "--quiet", "--initial-branch=main"])
        .arg(&bare)
        .output()
        .expect("git init bare");
    assert!(
        init_bare.status.success(),
        "git init bare failed: {}",
        String::from_utf8_lossy(&init_bare.stderr)
    );

    let clone = Command::new("git")
        .args(["clone", "--quiet"])
        .arg(&bare)
        .arg(&repo)
        .output()
        .expect("git clone");
    assert!(
        clone.status.success(),
        "git clone failed: {}",
        String::from_utf8_lossy(&clone.stderr)
    );
    configure_git_user(&repo);
    fs::write(repo.join("public.txt"), "initial public content\n").expect("write initial");
    git_expect(&repo, &["add", "public.txt"]);
    git_expect(
        &repo,
        &["commit", "--quiet", "-m", "Initial public content"],
    );
    git_expect(&repo, &["push", "--quiet", "-u", "origin", "main"]);

    let makefile = Path::new(env!("CARGO_MANIFEST_DIR")).join("Makefile");
    let output = Command::new("make")
        .arg("--silent")
        .arg("-f")
        .arg(&makefile)
        .arg("release-context-check")
        .arg(format!("PUBLIC_RELEASE_REMOTE={}", bare.to_string_lossy()))
        .current_dir(&repo)
        .env("MAKEFLAGS", "")
        .output()
        .expect("make release-context-check");

    assert!(
        output.status.success(),
        "release-context-check failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Staged paths: none"),
        "missing staged paths summary: {stdout}"
    );

    fs::write(repo.join("staged.txt"), "public release note\n").expect("write staged fixture");
    let add = Command::new("git")
        .args(["add", "staged.txt"])
        .current_dir(&repo)
        .output()
        .expect("git add");
    assert!(
        add.status.success(),
        "git add failed: {}",
        String::from_utf8_lossy(&add.stderr)
    );

    let output = Command::new("make")
        .arg("--silent")
        .arg("-f")
        .arg(&makefile)
        .arg("release-context-check")
        .arg(format!("PUBLIC_RELEASE_REMOTE={}", bare.to_string_lossy()))
        .current_dir(&repo)
        .env("MAKEFLAGS", "")
        .output()
        .expect("make release-context-check");

    assert!(
        !output.status.success(),
        "release-context-check should fail when working tree has staged files"
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("staged.txt"),
        "missing staged path in output: {combined}"
    );
}

#[cfg(unix)]
#[test]
fn release_crate_manifest_excludes_host_only_release_material() {
    let makefile = Path::new(env!("CARGO_MANIFEST_DIR")).join("Makefile");
    let output = Command::new("make")
        .arg("--silent")
        .arg("-f")
        .arg(&makefile)
        .arg("CARGO_LOCKED=--locked")
        .arg("release-crate-manifest")
        .env("MAKEFLAGS", "")
        .output()
        .expect("make release-crate-manifest");

    assert!(
        output.status.success(),
        "release-crate-manifest failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let package_paths = stdout.lines().collect::<Vec<_>>();
    assert!(
        package_paths.contains(&"README.md"),
        "package manifest should list public source content"
    );

    let host_only = package_paths
        .iter()
        .filter(|path| is_host_only_repo_path(Path::new(path)))
        .collect::<Vec<_>>();
    assert!(
        host_only.is_empty(),
        "Cargo package must not include host-only release material: {host_only:?}"
    );

    let preflight = Command::new("make")
        .arg("--dry-run")
        .arg("--no-print-directory")
        .arg("-f")
        .arg(&makefile)
        .arg("CARGO_LOCKED=--locked")
        .arg("release-preflight")
        .env("MAKEFLAGS", "")
        .output()
        .expect("make release-preflight dry run");
    assert!(
        preflight.status.success(),
        "release-preflight dry run failed: {}",
        String::from_utf8_lossy(&preflight.stderr)
    );
    let preflight_stdout = String::from_utf8_lossy(&preflight.stdout);
    let manifest_pos = preflight_stdout
        .find("cargo package --locked --list --allow-dirty")
        .expect("release-preflight should review Cargo package contents");
    let tag_pos = preflight_stdout
        .find("cargo metadata --no-deps --locked --format-version 1")
        .expect("release-preflight should review the public release tag");
    let fmt_pos = preflight_stdout
        .find("cargo fmt --check")
        .expect("release-preflight should still run format checks");
    let public_docs_pos = preflight_stdout
        .find("cargo test --locked --quiet public_docs_")
        .expect("release-preflight should run focused public boundary checks");
    let package_verify_pos = preflight_stdout
        .find("scripts/package-verify")
        .expect("release-preflight should run normalized package verification");
    let artifact_manifest_pos = preflight_stdout
        .find("python3 scripts/release-artifact-manifest")
        .expect("release-preflight should include optional downloaded artifact validation");
    assert!(
        tag_pos < manifest_pos,
        "release-preflight should review the public release tag before package contents: {preflight_stdout}"
    );
    assert!(
        manifest_pos < fmt_pos,
        "release-preflight should review Cargo package contents before expensive checks: {preflight_stdout}"
    );
    assert!(
        manifest_pos < package_verify_pos,
        "release-preflight should run package verification after the manifest check: {preflight_stdout}"
    );
    assert!(
        package_verify_pos < artifact_manifest_pos,
        "release-preflight should validate downloaded artifacts after package verification: {preflight_stdout}"
    );
    assert!(
        public_docs_pos < fmt_pos,
        "release-preflight should run focused public boundary checks before expensive checks: {preflight_stdout}"
    );
}

#[cfg(unix)]
#[test]
fn release_artifact_manifest_accepts_workflow_shaped_bundles_and_rejects_extra_entries() {
    let temp = tempdir().expect("tempdir");
    let artifacts = temp.path().join("artifacts");
    let good_payload = temp.path().join("good-payload");
    let bad_payload = temp.path().join("bad-payload");
    fs::create_dir_all(&artifacts).expect("create artifacts");
    fs::create_dir_all(good_payload.join("config/examples")).expect("create good payload");
    fs::create_dir_all(bad_payload.join("logs")).expect("create bad payload logs");
    fs::write(good_payload.join("telltale"), "binary\n").expect("write telltale");
    fs::write(good_payload.join("LICENSE"), "Apache-2.0\n").expect("write LICENSE");
    fs::write(good_payload.join("README.md"), "# quick start\n").expect("write README");
    fs::write(
        good_payload.join("config/examples/telltale-outputs.yaml"),
        "outputs: {}\n",
    )
    .expect("write outputs example");
    fs::write(
        good_payload.join("config/examples/telltale-scan.service"),
        "[Service]\n",
    )
    .expect("write service example");
    fs::write(
        good_payload.join("config/examples/telltale-scan.timer"),
        "[Timer]\n",
    )
    .expect("write timer example");
    fs::write(
        good_payload.join("config/examples/telltale-scan-task.xml"),
        "<Task/>\n",
    )
    .expect("write task example");
    fs::write(
        good_payload.join("config/examples/elastic-telltale-index-template.json"),
        "{}\n",
    )
    .expect("write Elastic mapping example");
    fs::write(
        good_payload.join("config/examples/elastic-telltale-role.json"),
        "{}\n",
    )
    .expect("write Elastic role example");
    fs::write(bad_payload.join("telltale.exe"), "binary\n").expect("write bad telltale.exe");
    fs::write(bad_payload.join("adr.exe"), "binary\n").expect("write bad adr.exe");
    fs::write(
        bad_payload.join("logs").join("adr-events.jsonl"),
        "{\"event_type\":\"activity\"}\n",
    )
    .expect("write bad log");

    // The old recursive bundle glob shape creates directory entries. Keep a
    // regression for that rejected shape beside the explicit-file ZIP below.
    fs::write(good_payload.join("telltale.exe"), "binary\n").expect("write Windows binary");
    let directory_artifacts = temp.path().join("directory-artifacts");
    fs::create_dir_all(&directory_artifacts).expect("create directory-entry artifacts");
    let directory_zip = directory_artifacts.join("telltale-v0.1.0-x86_64-pc-windows-msvc.zip");
    let recursive_zip = Command::new("zip")
        .args(["-q", "-r"])
        .arg(&directory_zip)
        .args(["telltale.exe", "LICENSE", "README.md", "config"])
        .current_dir(&good_payload)
        .output()
        .expect("recursive workflow-shaped zip");
    assert!(recursive_zip.status.success());
    let directory_sums = Command::new("sha256sum")
        .arg(directory_zip.file_name().unwrap())
        .current_dir(&directory_artifacts)
        .output()
        .expect("directory-entry checksum");
    assert!(directory_sums.status.success());
    fs::write(
        directory_artifacts.join("SHA256SUMS"),
        directory_sums.stdout,
    )
    .expect("directory-entry sums");
    let rejected = Command::new("python3")
        .arg("scripts/release-artifact-manifest")
        .env("RELEASE_ARTIFACT_DIR", &directory_artifacts)
        .output()
        .expect("directory-entry manifest check");
    assert!(!rejected.status.success());
    assert!(
        format!(
            "{}{}",
            String::from_utf8_lossy(&rejected.stdout),
            String::from_utf8_lossy(&rejected.stderr)
        )
        .contains("non-regular or link member")
    );

    let good_archive = artifacts.join("telltale-v0.1.0-x86_64-unknown-linux-gnu.tar.gz");
    let tar = Command::new("tar")
        .arg("-czf")
        .arg(&good_archive)
        .arg("-C")
        .arg(&good_payload)
        .arg("telltale")
        .arg("LICENSE")
        .arg("README.md")
        .arg("config/examples/telltale-outputs.yaml")
        .arg("config/examples/telltale-scan.service")
        .arg("config/examples/telltale-scan.timer")
        .arg("config/examples/telltale-scan-task.xml")
        .arg("config/examples/elastic-telltale-index-template.json")
        .arg("config/examples/elastic-telltale-role.json")
        .output()
        .expect("tar good archive");
    assert!(
        tar.status.success(),
        "tar good archive failed: {}",
        String::from_utf8_lossy(&tar.stderr)
    );
    let initial_checksums = Command::new("sha256sum")
        .arg(good_archive.file_name().unwrap())
        .current_dir(&artifacts)
        .output()
        .expect("initial checksum");
    assert!(initial_checksums.status.success());
    fs::write(artifacts.join("SHA256SUMS"), initial_checksums.stdout).expect("initial sums");
    let makefile = Path::new(env!("CARGO_MANIFEST_DIR")).join("Makefile");
    let output = Command::new("make")
        .arg("--silent")
        .arg("-f")
        .arg(&makefile)
        .arg("release-artifact-manifest")
        .arg(format!(
            "RELEASE_ARTIFACT_DIR={}",
            artifacts.to_string_lossy()
        ))
        .env("MAKEFLAGS", "")
        .output()
        .expect("make release-artifact-manifest");
    assert!(
        output.status.success(),
        "release-artifact-manifest failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Archive:"),
        "missing archive header: {stdout}"
    );
    assert!(
        stdout.contains("  telltale"),
        "missing primary binary entry: {stdout}"
    );
    fs::write(good_payload.join("telltale.exe"), "binary\n").expect("write telltale.exe");
    let good_zip = artifacts.join("telltale-v0.1.0-x86_64-pc-windows-msvc.zip");
    let zip = Command::new("zip")
        .arg("-q")
        .arg(&good_zip)
        .arg("telltale.exe")
        .arg("LICENSE")
        .arg("README.md")
        .arg("config/examples/telltale-outputs.yaml")
        .arg("config/examples/telltale-scan.service")
        .arg("config/examples/telltale-scan.timer")
        .arg("config/examples/telltale-scan-task.xml")
        .arg("config/examples/elastic-telltale-index-template.json")
        .arg("config/examples/elastic-telltale-role.json")
        .current_dir(&good_payload)
        .output()
        .expect("zip good archive");
    assert!(
        zip.status.success(),
        "zip good archive failed: {}",
        String::from_utf8_lossy(&zip.stderr)
    );
    let checksums = Command::new("sha256sum")
        .arg(good_archive.file_name().expect("tar archive file name"))
        .arg(good_zip.file_name().expect("zip archive file name"))
        .current_dir(&artifacts)
        .output()
        .expect("sha256sum release archives");
    assert!(
        checksums.status.success(),
        "sha256sum failed: {}",
        String::from_utf8_lossy(&checksums.stderr)
    );
    fs::write(artifacts.join("SHA256SUMS"), &checksums.stdout).expect("write SHA256SUMS");

    let output = Command::new("make")
        .arg("--silent")
        .arg("-f")
        .arg(&makefile)
        .arg("release-artifact-manifest")
        .arg(format!(
            "RELEASE_ARTIFACT_DIR={}",
            artifacts.to_string_lossy()
        ))
        .env("MAKEFLAGS", "")
        .output()
        .expect("make release-artifact-manifest");
    assert!(
        output.status.success(),
        "release-artifact-manifest failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(good_archive.to_string_lossy().as_ref()),
        "missing tar archive header: {stdout}"
    );
    assert!(
        stdout.contains(good_zip.to_string_lossy().as_ref()),
        "missing zip archive header: {stdout}"
    );
    assert!(
        stdout.contains("  telltale.exe"),
        "missing primary Windows binary entry: {stdout}"
    );
    assert!(
        stdout.contains("telltale-v0.1.0-x86_64-unknown-linux-gnu.tar.gz: OK"),
        "missing tar checksum verification: {stdout}"
    );
    assert!(
        stdout.contains("telltale-v0.1.0-x86_64-pc-windows-msvc.zip: OK"),
        "missing zip checksum verification: {stdout}"
    );

    fs::write(
        artifacts.join("SHA256SUMS"),
        "0000000000000000000000000000000000000000000000000000000000000000  stale.zip\n",
    )
    .expect("write stale SHA256SUMS");
    let output = Command::new("make")
        .arg("--silent")
        .arg("-f")
        .arg(&makefile)
        .arg("release-artifact-manifest")
        .arg(format!(
            "RELEASE_ARTIFACT_DIR={}",
            artifacts.to_string_lossy()
        ))
        .env("MAKEFLAGS", "")
        .output()
        .expect("make release-artifact-manifest");
    assert!(
        !output.status.success(),
        "release-artifact-manifest should reject stale checksum manifests"
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("SHA256SUMS entries must match release archives"),
        "unexpected output: {combined}"
    );

    fs::remove_file(&good_archive).expect("remove good archive");
    fs::remove_file(&good_zip).expect("remove good zip");
    fs::remove_file(artifacts.join("SHA256SUMS")).expect("remove stale SHA256SUMS");
    let bad_archive = artifacts.join("telltale-v0.1.0-with-log.zip");
    let zip = Command::new("zip")
        .arg("-q")
        .arg(&bad_archive)
        .arg("telltale.exe")
        .arg("adr.exe")
        .arg("logs/adr-events.jsonl")
        .current_dir(&bad_payload)
        .output()
        .expect("zip bad archive");
    assert!(
        zip.status.success(),
        "zip bad archive failed: {}",
        String::from_utf8_lossy(&zip.stderr)
    );
    let bad_checksum = Command::new("sha256sum")
        .arg(bad_archive.file_name().unwrap())
        .current_dir(&artifacts)
        .output()
        .expect("bad archive checksum");
    assert!(bad_checksum.status.success());
    fs::write(artifacts.join("SHA256SUMS"), bad_checksum.stdout).expect("bad sums");
    let output = Command::new("make")
        .arg("--silent")
        .arg("-f")
        .arg(&makefile)
        .arg("release-artifact-manifest")
        .arg(format!(
            "RELEASE_ARTIFACT_DIR={}",
            artifacts.to_string_lossy()
        ))
        .env("MAKEFLAGS", "")
        .output()
        .expect("make release-artifact-manifest");
    assert!(
        !output.status.success(),
        "release-artifact-manifest should reject archives with extra entries"
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("does not match the exact canonical bundle"),
        "unexpected output: {combined}"
    );
}

#[cfg(unix)]
#[test]
fn release_artifact_manifest_accepts_only_canonical_bundle() {
    let temp = tempdir().expect("tempdir");
    let artifacts = temp.path().join("artifacts");
    let payload = temp.path().join("payload");
    fs::create_dir_all(payload.join("config/examples")).expect("payload");
    fs::create_dir_all(&artifacts).expect("artifacts");
    for (path, body) in [
        ("telltale", "binary\n"),
        ("LICENSE", "Apache-2.0\n"),
        ("README.md", "# release\n"),
        ("config/examples/telltale-outputs.yaml", "outputs: {}\n"),
        ("config/examples/telltale-scan.service", "[Service]\n"),
        ("config/examples/telltale-scan.timer", "[Timer]\n"),
        ("config/examples/telltale-scan-task.xml", "<Task/>\n"),
        (
            "config/examples/elastic-telltale-index-template.json",
            "{}\n",
        ),
        ("config/examples/elastic-telltale-role.json", "{}\n"),
    ] {
        fs::write(payload.join(path), body).expect("payload member");
    }
    let archive = artifacts.join("telltale-v0.5.0-x86_64-unknown-linux-gnu.tar.gz");
    let output = Command::new("tar")
        .args(["-czf"])
        .arg(&archive)
        .args([
            "-C",
            payload.to_str().unwrap(),
            "telltale",
            "LICENSE",
            "README.md",
            "config/examples/telltale-outputs.yaml",
            "config/examples/telltale-scan.service",
            "config/examples/telltale-scan.timer",
            "config/examples/telltale-scan-task.xml",
            "config/examples/elastic-telltale-index-template.json",
            "config/examples/elastic-telltale-role.json",
        ])
        .output()
        .expect("archive");
    assert!(output.status.success());
    let sums = Command::new("sha256sum")
        .arg(archive.file_name().unwrap())
        .current_dir(&artifacts)
        .output()
        .expect("checksum");
    fs::write(artifacts.join("SHA256SUMS"), sums.stdout).expect("sums");
    let makefile = Path::new(env!("CARGO_MANIFEST_DIR")).join("Makefile");
    let output = Command::new("make")
        .args(["--silent", "-f"])
        .arg(&makefile)
        .arg("release-artifact-manifest")
        .arg(format!("RELEASE_ARTIFACT_DIR={}", artifacts.display()))
        .env("MAKEFLAGS", "")
        .output()
        .expect("manifest check");
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("telltale"));

    fs::copy(
        &archive,
        artifacts.join("adr-v0.5.0-x86_64-unknown-linux-gnu.tar.gz"),
    )
    .expect("legacy archive");
    let output = Command::new("make")
        .args(["--silent", "-f"])
        .arg(&makefile)
        .arg("release-artifact-manifest")
        .arg(format!("RELEASE_ARTIFACT_DIR={}", artifacts.display()))
        .env("MAKEFLAGS", "")
        .output()
        .expect("legacy manifest check");
    assert!(!output.status.success());
    assert!(
        format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
        .contains("telltale-* filename")
    );
}

#[cfg(unix)]
#[test]
fn release_artifact_manifest_rejects_link_and_traversal_members() {
    let temp = tempdir().expect("tempdir");
    let artifacts = temp.path().join("artifacts");
    let payload = temp.path().join("payload");
    let link_payload = temp.path().join("link-payload");
    let traversal_payload = temp.path().join("traversal-payload");
    fs::create_dir_all(payload.join("config/examples")).expect("payload");
    fs::create_dir_all(&artifacts).expect("artifacts");
    for (path, body) in [
        ("telltale", "binary\n"),
        ("LICENSE", "Apache-2.0\n"),
        ("README.md", "# release\n"),
        ("config/examples/telltale-outputs.yaml", "outputs: {}\n"),
        ("config/examples/telltale-scan.service", "[Service]\n"),
        ("config/examples/telltale-scan.timer", "[Timer]\n"),
        ("config/examples/telltale-scan-task.xml", "<Task/>\n"),
        (
            "config/examples/elastic-telltale-index-template.json",
            "{}\n",
        ),
        ("config/examples/elastic-telltale-role.json", "{}\n"),
    ] {
        fs::write(payload.join(path), body).expect("payload member");
    }
    fs::create_dir_all(link_payload.join("config/examples")).expect("link payload");
    fs::create_dir_all(traversal_payload.join("config/examples")).expect("traversal payload");
    for path in [
        "LICENSE",
        "README.md",
        "config/examples/telltale-outputs.yaml",
        "config/examples/telltale-scan.service",
        "config/examples/telltale-scan.timer",
        "config/examples/telltale-scan-task.xml",
        "config/examples/elastic-telltale-index-template.json",
        "config/examples/elastic-telltale-role.json",
    ] {
        fs::copy(payload.join(path), link_payload.join(path)).expect("copy link member");
        fs::copy(payload.join(path), traversal_payload.join(path)).expect("copy traversal member");
    }
    symlink("LICENSE", link_payload.join("telltale.exe")).expect("canonical link");
    fs::write(traversal_payload.join("telltale.exe"), "binary\n").expect("canonical binary");
    fs::write(temp.path().join("escape.txt"), "outside\n").expect("escape member");

    let link_archive = artifacts.join("telltale-v0.5.0-x86_64-pc-windows-msvc.zip");
    let zip = Command::new("zip")
        .args(["-q", "-y"])
        .arg(&link_archive)
        .args([
            "telltale.exe",
            "LICENSE",
            "README.md",
            "config/examples/telltale-outputs.yaml",
            "config/examples/telltale-scan.service",
            "config/examples/telltale-scan.timer",
            "config/examples/telltale-scan-task.xml",
            "config/examples/elastic-telltale-index-template.json",
            "config/examples/elastic-telltale-role.json",
        ])
        .current_dir(&link_payload)
        .output()
        .expect("link archive");
    assert!(zip.status.success());
    let sums = Command::new("sha256sum")
        .arg(link_archive.file_name().unwrap())
        .current_dir(&artifacts)
        .output()
        .expect("link checksum");
    fs::write(artifacts.join("SHA256SUMS"), sums.stdout).expect("link sums");
    let makefile = Path::new(env!("CARGO_MANIFEST_DIR")).join("Makefile");
    let output = Command::new("make")
        .args(["--silent", "-f"])
        .arg(&makefile)
        .arg("release-artifact-manifest")
        .arg(format!("RELEASE_ARTIFACT_DIR={}", artifacts.display()))
        .env("MAKEFLAGS", "")
        .output()
        .expect("link manifest check");
    assert!(!output.status.success());
    assert!(
        format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
        .contains("non-regular or link")
    );

    fs::remove_file(&link_archive).expect("remove link archive");
    fs::remove_file(artifacts.join("SHA256SUMS")).expect("remove link sums");
    let traversal_archive = artifacts.join("telltale-v0.5.0-x86_64-pc-windows-msvc.zip");
    let zip = Command::new("zip")
        .arg("-q")
        .arg(&traversal_archive)
        .args([
            "telltale.exe",
            "LICENSE",
            "README.md",
            "config/examples/telltale-outputs.yaml",
            "config/examples/telltale-scan.service",
            "config/examples/telltale-scan.timer",
            "config/examples/telltale-scan-task.xml",
            "config/examples/elastic-telltale-index-template.json",
            "config/examples/elastic-telltale-role.json",
            "../escape.txt",
        ])
        .current_dir(&traversal_payload)
        .output()
        .expect("traversal archive");
    assert!(zip.status.success());
    let sums = Command::new("sha256sum")
        .arg(traversal_archive.file_name().unwrap())
        .current_dir(&artifacts)
        .output()
        .expect("traversal checksum");
    fs::write(artifacts.join("SHA256SUMS"), sums.stdout).expect("traversal sums");
    let output = Command::new("make")
        .args(["--silent", "-f"])
        .arg(&makefile)
        .arg("release-artifact-manifest")
        .arg(format!("RELEASE_ARTIFACT_DIR={}", artifacts.display()))
        .env("MAKEFLAGS", "")
        .output()
        .expect("traversal manifest check");
    assert!(!output.status.success());
    assert!(
        format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
        .contains("absolute or traversal")
    );

    fs::remove_file(&traversal_archive).expect("remove traversal archive");
    fs::remove_file(artifacts.join("SHA256SUMS")).expect("remove traversal sums");
    let dos_directory_archive = artifacts.join("telltale-v0.5.0-dos-directory-attribute.zip");
    let dos_zip = Command::new("python3")
        .args([
            "-c",
            r#"
import sys
import zipfile

members = [
    "telltale.exe",
    "LICENSE",
    "README.md",
    "config/examples/telltale-outputs.yaml",
    "config/examples/telltale-scan.service",
    "config/examples/telltale-scan.timer",
    "config/examples/telltale-scan-task.xml",
    "config/examples/elastic-telltale-index-template.json",
    "config/examples/elastic-telltale-role.json",
]
with zipfile.ZipFile(sys.argv[1], "w") as bundle:
    for name in members:
        info = zipfile.ZipInfo(name)
        info.create_system = 0
        if name == "LICENSE":
            info.external_attr = 0x10
        bundle.writestr(info, b"fixture\n")
"#,
            dos_directory_archive.to_str().unwrap(),
        ])
        .output()
        .expect("DOS-directory-attribute ZIP");
    assert!(
        dos_zip.status.success(),
        "DOS-directory-attribute ZIP failed: {}",
        String::from_utf8_lossy(&dos_zip.stderr)
    );
    let dos_checksum = Command::new("sha256sum")
        .arg(dos_directory_archive.file_name().unwrap())
        .current_dir(&artifacts)
        .output()
        .expect("DOS-directory-attribute checksum");
    assert!(dos_checksum.status.success());
    fs::write(artifacts.join("SHA256SUMS"), dos_checksum.stdout)
        .expect("write DOS-directory-attribute sums");
    let output = Command::new("make")
        .args(["--silent", "-f"])
        .arg(&makefile)
        .arg("release-artifact-manifest")
        .arg(format!(
            "RELEASE_ARTIFACT_DIR={}",
            artifacts.to_string_lossy()
        ))
        .env("MAKEFLAGS", "")
        .output()
        .expect("DOS-directory-attribute manifest check");
    assert!(!output.status.success());
    assert!(
        format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
        .contains("non-regular or link")
    );
}

#[cfg(unix)]
#[test]
fn release_fixture_smoke_uses_fixture_safe_commands() {
    let makefile = Path::new(env!("CARGO_MANIFEST_DIR")).join("Makefile");
    let output = Command::new("make")
        .arg("--dry-run")
        .arg("--no-print-directory")
        .arg("-f")
        .arg(&makefile)
        .arg("CARGO_LOCKED=--locked")
        .arg("release-fixture-smoke")
        .env("MAKEFLAGS", "")
        .output()
        .expect("make release-fixture-smoke dry run");

    assert!(
        output.status.success(),
        "release-fixture-smoke dry run failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(
            "cargo run --locked --bin telltale -- scan --once --dry-run --no-local-config --emit-activity --emit-session-risk-summary --root tests/fixtures/session_stores --state-path \"$smoke_dir/state.json\" --log-path \"$smoke_dir/events.jsonl\""
        ),
        "fixture scan must stay dry-run, fixture-rooted, summary-enabled, and isolated: {stdout}"
    );
    assert!(
        stdout.contains("cargo run --locked --bin telltale -- rules validate --no-local-config"),
        "bundled rule validation missing from fixture smoke target: {stdout}"
    );
}

#[cfg(unix)]
#[test]
fn makefile_build_install_and_scan_targets_use_primary_binary() {
    let makefile = Path::new(env!("CARGO_MANIFEST_DIR")).join("Makefile");
    let output = Command::new("make")
        .args(["--dry-run", "--no-print-directory", "-f"])
        .arg(&makefile)
        .args(["build", "install", "scan-dry", "scan"])
        .env("MAKEFLAGS", "")
        .output()
        .expect("make primary binary targets");

    assert!(
        output.status.success(),
        "primary binary targets failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("target/release/telltale"));
    assert!(stdout.contains("install -m 0755 target/release/telltale"));
    assert!(stdout.contains("does not install or activate a user schedule"));
    assert!(!stdout.contains("systemctl --user enable telltale-scan.timer"));
    assert!(!stdout.contains("target/release/adr"));
    assert!(stdout.contains("/telltale scan --once"));
    assert!(!stdout.contains("/adr scan --once"));
}

#[cfg(unix)]
#[test]
fn release_artifact_manifest_skips_absent_download_directory() {
    let temp = tempdir().expect("tempdir");
    let absent = temp.path().join("no-downloaded-artifacts");
    let makefile = Path::new(env!("CARGO_MANIFEST_DIR")).join("Makefile");
    let output = Command::new("make")
        .args(["--silent", "-f"])
        .arg(&makefile)
        .arg("release-artifact-manifest")
        .arg(format!("RELEASE_ARTIFACT_DIR={}", absent.display()))
        .env("MAKEFLAGS", "")
        .output()
        .expect("manifest skip check");
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("Skipping release artifact manifest"));
}

#[test]
fn release_workflow_packages_only_canonical_identity() {
    let workflow = read_release_workflow();
    assert!(workflow.contains("telltale-${{ github.ref_name }}-${{ matrix.target }}"));
    assert!(!workflow.contains("adr-${{ github.ref_name }}-${{ matrix.target }}"));
    assert!(workflow.contains("telltale LICENSE README.md"));
    assert!(workflow.contains("config/examples/elastic-telltale-index-template.json"));
    assert!(workflow.contains("config/examples/elastic-telltale-role.json"));
    assert!(!workflow.contains("Compress-Archive"));
    assert!(workflow.contains("& .\\scripts\\release-windows-zip.ps1"));
    assert!(workflow.contains("-BundleDirectory $bundleDir -OutputArchive $archivePath"));
    for member in [
        "telltale.exe",
        "LICENSE",
        "README.md",
        "config/examples/telltale-outputs.yaml",
        "config/examples/telltale-scan.service",
        "config/examples/telltale-scan.timer",
        "config/examples/telltale-scan-task.xml",
        "config/examples/elastic-telltale-index-template.json",
        "config/examples/elastic-telltale-role.json",
    ] {
        assert!(
            workflow.contains(member),
            "workflow ZIP is missing {member}"
        );
    }
    assert!(workflow.contains(
        "subject-path: telltale-${{ github.ref_name }}-${{ matrix.target }}.${{ matrix.archive }}"
    ));
    assert!(!workflow.contains(
        "subject-path: adr-${{ github.ref_name }}-${{ matrix.target }}.${{ matrix.archive }}"
    ));
    assert!(!workflow.contains("cmp -s \"$canonical\" \"$legacy\""));
    assert!(workflow.contains("prerelease: ${{ contains(github.ref_name, '-') }}"));
    assert!(workflow.contains("overwrite_files: false"));
    assert!(workflow.contains("Fail closed if the tag already has a Release"));
    assert!(workflow.contains("releases?per_page=100"));
    assert!(
        workflow.contains(
            "concurrency:\n  group: release-${{ github.ref }}\n  cancel-in-progress: false"
        )
    );
    assert!(workflow.contains("on:\n  push:\n    tags:"));
    assert!(!workflow.contains("workflow_dispatch:"));
    assert!(!workflow.contains("branches:"));
    assert!(!workflow.contains("refs/heads/"));
    assert!(!workflow.contains("branch-artifact"));
    assert!(!workflow.contains("artifact-reference"));
    assert!(!workflow.contains("adr-${{ github.ref_name }}"));
}

#[test]
fn release_windows_zip_helper_is_the_fail_closed_gate_before_evidence() {
    let workflow = read_release_workflow();
    let package = workflow
        .find("- name: Stage and package release bundle (windows)")
        .expect("Windows package step");
    let smoke = workflow
        .find("- name: Mandatory Windows staged binary --version smoke")
        .expect("Windows smoke step");
    let attestation = workflow
        .find("- name: Attest release archive")
        .expect("archive attestation step");
    let upload = workflow
        .find("- name: Upload artifact")
        .expect("artifact upload step");
    assert!(package < smoke && smoke < attestation && attestation < upload);

    let package_block = &workflow[package..smoke];
    assert!(package_block.contains("$archivePath = Join-Path (Get-Location) $archive"));
    assert!(package_block.contains("& .\\scripts\\release-windows-zip.ps1"));
    for forbidden in [
        "[System.IO.Compression.ZipFile]::Open",
        "[System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile",
        "continue-on-error",
        "catch",
        "always()",
    ] {
        assert!(
            !package_block.contains(forbidden),
            "Windows package block must not bypass helper failure: {forbidden}"
        );
    }
    assert!(workflow.contains(
        "subject-path: telltale-${{ github.ref_name }}-${{ matrix.target }}.${{ matrix.archive }}"
    ));
}

#[test]
fn windows_ci_runs_release_zip_helper_before_rust_suite() {
    let workflow = fs::read_to_string(".github/workflows/ci.yml")
        .expect("CI workflow")
        .replace("\r\n", "\n");
    let windows = workflow.find("  windows:\n").expect("Windows CI job");
    let macos = workflow[windows..]
        .find("  macos:")
        .map(|offset| windows + offset)
        .expect("macOS CI job");
    let job = &workflow[windows..macos];
    let helper = job
        .find("- name: Validate Windows release ZIP helper")
        .expect("Windows helper test step");
    let rust = job
        .find("- run: cargo fmt --all --check")
        .expect("Rust suite");
    assert!(helper < rust);
    assert!(job.contains("shell: pwsh\n        run: .\\tests\\release_windows_zip.ps1"));
}

#[cfg(unix)]
#[test]
fn release_workflow_requires_exact_current_tag_target_archive_set() {
    let workflow = read_release_workflow();
    let start = workflow
        .find("- name: Validate exact current-tag target archive set")
        .expect("exact target archive validation step");
    let checksum = workflow[start..]
        .find("- name: Generate checksums")
        .map(|offset| start + offset)
        .expect("checksum step");
    let manifests = workflow
        .find("- name: Validate assembled release artifact manifests")
        .expect("assembled manifest validation step");
    let release = workflow
        .find("- name: Create GitHub Release")
        .expect("GitHub Release step");
    let step = &workflow[start..checksum];
    let run_start = step.find("run: |\n").expect("archive validation run block") + "run: |\n".len();
    let indentation = step[run_start..]
        .lines()
        .find(|line| !line.trim().is_empty())
        .map(|line| &line[..line.len() - line.trim_start().len()])
        .expect("archive validation indentation");
    let script = step[run_start..]
        .lines()
        .map(|line| {
            if line.trim().is_empty() {
                ""
            } else {
                line.strip_prefix(indentation)
                    .expect("archive validation indentation")
            }
        })
        .collect::<Vec<_>>()
        .join("\n");

    let targets = [
        "x86_64-unknown-linux-gnu.tar.gz",
        "aarch64-unknown-linux-gnu.tar.gz",
        "x86_64-apple-darwin.tar.gz",
        "aarch64-apple-darwin.tar.gz",
        "x86_64-pc-windows-msvc.zip",
    ];
    for target in targets {
        assert!(
            step.contains(&format!("telltale-${{GITHUB_REF_NAME}}-{target}")),
            "workflow is missing canonical target {target}"
        );
    }
    for (name, offset) in [
        ("checksum generation", checksum),
        ("assembled manifest validation", manifests),
        ("GitHub Release creation", release),
    ] {
        assert!(start < offset, "archive validation must precede {name}");
    }

    let temp = tempdir().expect("tempdir");
    let downloads = temp.path().join("release-downloads");
    fs::create_dir(&downloads).expect("release downloads");
    for target in targets {
        fs::write(
            downloads.join(format!("telltale-v0.5.0-rc.1-{target}")),
            b"synthetic archive",
        )
        .expect("synthetic archive");
    }

    let run = |expected_success: bool| {
        let output = Command::new("bash")
            .args(["-euo", "pipefail", "-c", &script])
            .env("GITHUB_REF_NAME", "v0.5.0-rc.1")
            .current_dir(temp.path())
            .output()
            .expect("run archive validation");
        assert_eq!(
            output.status.success(),
            expected_success,
            "archive validation output: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    };

    let windows_target = downloads.join("telltale-v0.5.0-rc.1-x86_64-pc-windows-msvc.zip");
    let restore_windows_target = || {
        fs::write(&windows_target, b"synthetic archive").expect("restore canonical archive");
    };

    run(true);
    fs::remove_file(&windows_target).expect("remove canonical archive");
    run(false);
    restore_windows_target();

    fs::remove_file(&windows_target).expect("remove canonical archive");
    fs::create_dir(&windows_target).expect("same-count directory archive");
    run(false);
    fs::remove_dir(&windows_target).expect("remove same-count directory archive");
    restore_windows_target();

    fs::remove_file(&windows_target).expect("remove canonical archive");
    fs::write(
        downloads.join("telltale-v0.5.0-rc.1-x86_64-pc-windows-msvc.tar.gz"),
        b"wrong extension",
    )
    .expect("wrong-extension archive");
    run(false);
    fs::remove_file(downloads.join("telltale-v0.5.0-rc.1-x86_64-pc-windows-msvc.tar.gz"))
        .expect("remove wrong-extension archive");
    restore_windows_target();

    fs::remove_file(&windows_target).expect("remove canonical archive");
    fs::write(
        downloads.join("telltale-v0.5.0-x86_64-pc-windows-msvc.zip"),
        b"wrong tag",
    )
    .expect("wrong-tag archive");
    run(false);
    fs::remove_file(downloads.join("telltale-v0.5.0-x86_64-pc-windows-msvc.zip"))
        .expect("remove wrong-tag archive");
    restore_windows_target();

    fs::remove_file(&windows_target).expect("remove canonical archive");
    fs::write(
        downloads.join("telltale-v0.5.0-rc.1-x86_64-pc-windows-msvc-copy.zip"),
        b"alternate target",
    )
    .expect("alternate target archive");
    run(false);

    fs::remove_file(downloads.join("telltale-v0.5.0-rc.1-x86_64-pc-windows-msvc-copy.zip"))
        .expect("remove alternate target archive");
    restore_windows_target();

    fs::remove_file(&windows_target).expect("remove canonical archive");
    let symlink_target = temp.path().join("symlink-target");
    fs::write(&symlink_target, b"symlink target").expect("symlink target");
    symlink(&symlink_target, &windows_target).expect("canonical archive symlink");
    run(false);
    fs::remove_file(&windows_target).expect("remove canonical archive symlink");
    restore_windows_target();

    fs::write(
        downloads.join("telltale-v0.5.0-rc.1-x86_64-pc-windows-msvc-copy.zip"),
        b"extra target",
    )
    .expect("extra target archive");
    run(false);
}

#[test]
fn release_workflow_has_ci_safe_preflight_and_native_smoke_gates() {
    let workflow = read_release_workflow();
    serde_yaml::from_str::<serde_yaml::Value>(&workflow).expect("release workflow YAML");
    let installer = fs::read_to_string("scripts/install-telltale").expect("installer script");
    assert!(installer.contains("INSTALLER_PROVENANCE=\"git-blob\""));
    assert!(!installer.contains("INSTALLER_COMMIT="));

    for required in [
        "preflight:",
        "needs: preflight",
        "needs: [preflight, build]",
        "fetch-depth: 0",
        "git fetch --no-tags --force origin main:refs/remotes/origin/main",
        "git merge-base --is-ancestor",
        "expected_tag=\"v${package_version}\"",
        "cargo fmt --all --check",
        "cargo metadata --no-deps --locked --format-version 1",
        "cargo clippy --locked --all-targets -- -D warnings",
        "cargo test --locked --quiet",
        "make --silent CARGO_LOCKED=--locked release-public-docs-check",
        "make --silent CARGO_LOCKED=--locked release-canonical-identity-check",
        "make --silent CARGO_LOCKED=--locked release-crate-manifest",
        "make --silent CARGO_LOCKED=--locked package-verify",
        "make --silent CARGO_LOCKED=--locked release-fixture-smoke",
        "cargo build --locked --release --target",
        "Release gate: verify installer content provenance",
        "installer_path=scripts/install-telltale",
        "git hash-object \"${installer_path}\"",
        "git rev-parse \"${GITHUB_SHA}:${installer_path}\"",
        "git ls-tree \"${GITHUB_SHA}\" -- \"${installer_path}\"",
        "Installer content blob",
        "Validate assembled release artifact manifests",
        "make --silent RELEASE_ARTIFACT_DIR=release-downloads release-artifact-manifest",
        "Native staged binary --version smoke (unix)",
        "Mandatory Windows staged binary --version smoke",
    ] {
        assert!(
            workflow.contains(required),
            "release workflow is missing {required:?}"
        );
    }

    for forbidden in [
        "release-preflight",
        "release-context-check",
        "release-tag-review",
        "git branch --show-current",
        "git status --short",
    ] {
        assert!(
            !workflow.contains(forbidden),
            "CI release workflow must not invoke local-only check {forbidden:?}"
        );
    }

    let prerelease_line = workflow
        .lines()
        .find(|line| line.trim_start().starts_with("prerelease:"))
        .expect("release action must set prerelease explicitly")
        .trim();
    assert_eq!(
        prerelease_line,
        "prerelease: ${{ contains(github.ref_name, '-') }}"
    );
    let rendered_rc = prerelease_line.replace("github.ref_name", "'v0.5.0-rc.1'");
    let rendered_stable = prerelease_line.replace("github.ref_name", "'v0.5.0'");
    assert_eq!(
        rendered_rc,
        "prerelease: ${{ contains('v0.5.0-rc.1', '-') }}"
    );
    assert_eq!(
        rendered_stable,
        "prerelease: ${{ contains('v0.5.0', '-') }}"
    );
    let evaluate_contains_dash = |rendered: &str| {
        let tag = rendered
            .split("contains('")
            .nth(1)
            .and_then(|value| value.split("', '-'").next())
            .expect("rendered contains expression");
        tag.contains('-')
    };
    assert!(evaluate_contains_dash(&rendered_rc));
    assert!(!evaluate_contains_dash(&rendered_stable));
}

#[test]
fn release_workflow_existing_release_guard_is_fail_closed_without_live_calls() {
    let workflow = read_release_workflow();
    let start = workflow
        .find("- name: Fail closed if the tag already has a Release")
        .expect("existing-release guard");
    let end = workflow
        .find("- name: Reserve GitHub Release")
        .expect("release reservation");
    assert!(
        start < end,
        "existing-release guard must precede release creation"
    );
    let guard = &workflow[start..end];
    for required in [
        "gh api --paginate --slurp",
        "releases?per_page=100",
        "match_state=",
        "Could not validate the GitHub Releases response.",
        "published assets are immutable",
        "release.get(\"tag_name\")",
    ] {
        assert!(guard.contains(required), "guard is missing {required:?}");
    }
    assert!(guard.contains("exit 1"));
    assert!(!guard.contains("releases/tags/"));
}

#[test]
fn release_workflow_reserves_release_before_action_creation() {
    let workflow = read_release_workflow();
    let guard = workflow
        .find("- name: Fail closed if the tag already has a Release")
        .expect("existing-release guard");
    let reservation = workflow
        .find("- name: Reserve GitHub Release")
        .expect("release reservation");
    let action = workflow
        .find("- name: Create GitHub Release")
        .expect("release action");
    assert!(guard < reservation && reservation < action);
    let reservation_block = &workflow[reservation..action];
    for required in [
        "gh api --method POST --include --input -",
        "repos/${GITHUB_REPOSITORY}/releases",
        "\"draft\": True",
        "prerelease",
        "HTTP 201",
        "reservation response was malformed or uncertain",
    ] {
        assert!(
            reservation_block.contains(required),
            "reservation is missing {required:?}"
        );
    }
    assert!(workflow.contains("tag_name: ${{ github.ref_name }}"));
    assert!(workflow.contains("prerelease: ${{ contains(github.ref_name, '-') }}"));
    assert!(workflow.contains("overwrite_files: false"));
}

#[cfg(unix)]
#[test]
fn release_workflow_existing_release_guard_handles_representative_gh_responses() {
    let workflow = read_release_workflow();
    let guard_start = workflow
        .find("- name: Fail closed if the tag already has a Release")
        .expect("existing-release guard");
    let run_start = workflow[guard_start..]
        .find("run: |\n")
        .map(|offset| guard_start + offset + "run: |\n".len())
        .expect("guard run block");
    let release_action_start = workflow[run_start..]
        .find("- name: Reserve GitHub Release")
        .map(|offset| run_start + offset)
        .expect("guard run block terminator");
    let run_end = workflow[..release_action_start]
        .rfind('\n')
        .expect("guard run block line boundary");
    let indentation = workflow[run_start..run_end]
        .lines()
        .find(|line| !line.trim().is_empty())
        .map(|line| &line[..line.len() - line.trim_start().len()])
        .expect("guard indentation");
    let guard_script = workflow[run_start..run_end]
        .lines()
        .map(|line| {
            if line.trim().is_empty() {
                ""
            } else {
                line.strip_prefix(indentation).expect("guard indentation")
            }
        })
        .collect::<Vec<_>>()
        .join("\n");

    let temp = tempdir().expect("tempdir");
    let fake_bin = temp.path().join("bin");
    fs::create_dir(&fake_bin).expect("fake bin");
    let fake_gh = fake_bin.join("gh");
    fs::write(
        &fake_gh,
        r####"#!/bin/sh
set -eu
case "${FAKE_GH_RESPONSE:?}" in
  published) printf '%s\n' '[[{"tag_name":"v0.5.0","draft":false,"prerelease":false}]]'; exit 0;;
  draft) printf '%s\n' '[[{"tag_name":"v0.5.0","draft":true,"prerelease":false}]]'; exit 0;;
  empty) printf '%s\n' '[]'; exit 0;;
  api-error) printf '%s\n' 'API failure'; exit 1;;
  malformed) printf '%s\n' '{"unexpected":[]}' ; exit 0;;
  match-then-malformed) printf '%s\n' '[[{"tag_name":"v0.5.0"},{"draft":false}]]'; exit 0;;
  missing-tag) printf '%s\n' '[[{"draft":false,"prerelease":false}]]'; exit 0;;
  empty-tag) printf '%s\n' '[[{"tag_name":"","draft":false,"prerelease":false}]]'; exit 0;;
  non-string-tag) printf '%s\n' '[[{"tag_name":123,"draft":false,"prerelease":false}]]'; exit 0;;
  *) exit 2;;
esac
"####,
    )
    .expect("fake gh");
    fs::set_permissions(&fake_gh, fs::Permissions::from_mode(0o755)).expect("executable fake gh");
    let path = format!(
        "{}:{}",
        fake_bin.display(),
        std::env::var("PATH").expect("PATH")
    );

    for (response, expected_success, expected_output) in [
        ("published", false, "already exists"),
        ("draft", false, "already exists"),
        ("empty", true, ""),
        ("api-error", false, "Could not query"),
        ("malformed", false, "Could not validate"),
        ("match-then-malformed", false, "Could not validate"),
        ("missing-tag", false, "Could not validate"),
        ("empty-tag", false, "Could not validate"),
        ("non-string-tag", false, "Could not validate"),
    ] {
        let output = Command::new("bash")
            .args(["-euo", "pipefail", "-c", &guard_script])
            .env("PATH", &path)
            .env("FAKE_GH_RESPONSE", response)
            .env("GH_TOKEN", "synthetic-token")
            .env("GITHUB_REPOSITORY", "example/telltale")
            .env("GITHUB_REF_NAME", "v0.5.0")
            .output()
            .expect("run release guard");
        assert_eq!(
            output.status.success(),
            expected_success,
            "response {response}"
        );
        let output_text = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        if !expected_output.is_empty() {
            assert!(
                output_text.contains(expected_output),
                "response {response} output: {output_text}"
            );
        }
    }
}

#[cfg(unix)]
#[test]
fn release_workflow_reservation_uses_exact_draft_rc_inputs_without_live_calls() {
    let workflow = read_release_workflow();
    let reservation_start = workflow
        .find("- name: Reserve GitHub Release")
        .expect("release reservation");
    let run_start = workflow[reservation_start..]
        .find("run: |\n")
        .map(|offset| reservation_start + offset + "run: |\n".len())
        .expect("reservation run block");
    let action_start = workflow[run_start..]
        .find("- name: Create GitHub Release")
        .map(|offset| run_start + offset)
        .expect("release action");
    let run_end = workflow[..action_start]
        .rfind('\n')
        .expect("reservation block line boundary");
    let indentation = workflow[run_start..run_end]
        .lines()
        .find(|line| !line.trim().is_empty())
        .map(|line| &line[..line.len() - line.trim_start().len()])
        .expect("reservation indentation");
    let reservation_script = workflow[run_start..run_end]
        .lines()
        .map(|line| {
            if line.trim().is_empty() {
                ""
            } else {
                line.strip_prefix(indentation)
                    .expect("reservation indentation")
            }
        })
        .collect::<Vec<_>>()
        .join("\n");

    let temp = tempdir().expect("tempdir");
    let fake_bin = temp.path().join("bin");
    fs::create_dir(&fake_bin).expect("fake bin");
    let fake_gh = fake_bin.join("gh");
    fs::write(
        &fake_gh,
        r####"#!/bin/sh
set -eu
printf '%s\n' "$*" > "${FAKE_GH_ARGS:?}"
cat > "${FAKE_GH_PAYLOAD:?}"
printf '%s\n\n' 'HTTP/2 201 Created'
printf '%s\n' '{"id":123,"tag_name":"v0.5.0-rc.1","draft":true,"prerelease":true}'
"####,
    )
    .expect("fake gh");
    fs::set_permissions(&fake_gh, fs::Permissions::from_mode(0o755)).expect("executable fake gh");
    let args_path = temp.path().join("gh.args");
    let payload_path = temp.path().join("gh.payload");
    let path = format!(
        "{}:{}",
        fake_bin.display(),
        std::env::var("PATH").expect("PATH")
    );
    let output = Command::new("bash")
        .args(["-euo", "pipefail", "-c", &reservation_script])
        .env("PATH", &path)
        .env("FAKE_GH_ARGS", &args_path)
        .env("FAKE_GH_PAYLOAD", &payload_path)
        .env("GH_TOKEN", "synthetic-token")
        .env("GITHUB_REPOSITORY", "example/telltale")
        .env("GITHUB_REF_NAME", "v0.5.0-rc.1")
        .output()
        .expect("run release reservation");
    assert!(
        output.status.success(),
        "reservation failed: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let args = fs::read_to_string(args_path).unwrap();
    assert!(args.contains("--method POST --include --input - repos/example/telltale/releases"));
    let payload = fs::read_to_string(payload_path).unwrap();
    assert!(payload.contains("\"tag_name\":\"v0.5.0-rc.1\""));
    assert!(payload.contains("\"draft\":true"));
    assert!(payload.contains("\"prerelease\":true"));
}

#[cfg(unix)]
#[test]
fn release_public_docs_check_runs_focused_boundary_tests() {
    let stdout = release_public_docs_check_dry_run_stdout();
    assert!(
        stdout.contains("cargo test --locked --quiet public_docs_"),
        "release-public-docs-check must run consolidated public-docs tests with a prefix filter: {stdout}"
    );
}

#[test]
fn release_readiness_documents_public_docs_check_commands() {
    let docs =
        fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/release-readiness.md"))
            .expect("read release readiness docs");

    assert!(
        docs.contains("make release-public-docs-check"),
        "release readiness guidance must name the focused public docs target"
    );
    assert!(
        docs.contains("cargo test --quiet public_docs_"),
        "release readiness guidance must document the consolidated public-docs test command"
    );
}

#[test]
fn public_docs_runtime_identity_guidance_is_canonical() {
    let readme = fs::read_to_string("README.md").expect("read README");
    assert!(readme.contains("./scripts/install-telltale"));
    assert!(!readme.contains("https://agentarchaeology.ai/telltale_install.sh"));
    let windows = text_between(&readme, "### Windows", "Before pushing public history");
    let source_build = text_between(windows, "Or build from source:", "For periodic scans");
    assert!(source_build.contains("target\\release\\telltale.exe"));
    assert!(source_build.contains("telltale-events.jsonl"));
    assert!(source_build.contains("telltale-state.json"));
    assert!(!source_build.contains("adr.exe"));
    let archive_download = text_between(
        windows,
        "Download the canonical release archive",
        "Or build from source:",
    );
    assert!(archive_download.contains("telltale.exe"));
    assert!(!archive_download.contains("adr.exe"));

    let readiness =
        fs::read_to_string("docs/release-readiness.md").expect("read release readiness docs");
    let package_verify = text_between(
        &readiness,
        "`make package-verify` performs",
        "For the actual publication pass",
    );
    assert!(package_verify.contains("the `telltale` install"));
    assert!(package_verify.contains("telltale --version"));
    assert!(package_verify.contains("rejects the retired `adr`"));
    assert!(package_verify.contains("executable if it is installed"));
    assert!(!package_verify.contains("adr --version"));
    let readiness_baseline =
        text_between(&readiness, "# Release Readiness", "## Artifact Boundary");
    assert!(readiness_baseline.contains("telltale --version"));
    assert!(!readiness_baseline.contains("adr-events.jsonl"));
    for retired in [
        "ADR_LOG_PATH",
        "ADR_STATE_PATH",
        "ADR_SCAN_ROOT",
        "adr-events.jsonl",
        "adr-state.json",
    ] {
        assert!(!source_build.contains(retired));
        assert!(!readiness_baseline.contains(retired));
    }
}

fn text_between<'a>(text: &'a str, start: &str, end: &str) -> &'a str {
    let start = text
        .find(start)
        .unwrap_or_else(|| panic!("missing section marker {start:?}"))
        + start.len();
    let end = text[start..]
        .find(end)
        .unwrap_or_else(|| panic!("missing section marker {end:?}"))
        + start;
    &text[start..end]
}

#[cfg(unix)]
fn release_public_docs_check_dry_run_stdout() -> String {
    let makefile = Path::new(env!("CARGO_MANIFEST_DIR")).join("Makefile");
    let output = Command::new("make")
        .arg("--dry-run")
        .arg("--no-print-directory")
        .arg("-f")
        .arg(&makefile)
        .arg("CARGO_LOCKED=--locked")
        .arg("release-public-docs-check")
        .env("MAKEFLAGS", "")
        .output()
        .expect("make release-public-docs-check dry run");

    assert!(
        output.status.success(),
        "release-public-docs-check dry run failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    String::from_utf8(output.stdout).expect("release-public-docs-check stdout must be UTF-8")
}

#[test]
fn public_docs_links_and_paths_are_safe() {
    // README local links resolve
    let readme_links = repo_local_markdown_links(Path::new("README.md"));
    assert!(!readme_links.is_empty(), "expected README local links");
    let missing = readme_links
        .iter()
        .filter(|(_, target)| !target.exists())
        .map(|(link, _)| link.clone())
        .collect::<Vec<_>>();
    assert!(
        missing.is_empty(),
        "README local links must point at tracked files or directories: {missing:?}"
    );

    // Public docs local links resolve
    let docs = fs::read_dir("docs")
        .expect("docs directory")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|extension| extension == "md"))
        .collect::<Vec<_>>();
    assert!(!docs.is_empty(), "expected public docs");
    let missing = docs
        .iter()
        .flat_map(|path| {
            repo_local_markdown_links(path)
                .into_iter()
                .filter(|(_, target)| !target.exists())
                .map(|(link, target)| {
                    format!("{} -> {} ({})", path.display(), link, target.display())
                })
        })
        .collect::<Vec<_>>();
    assert!(
        missing.is_empty(),
        "public docs local links must point at existing files or directories: {missing:?}"
    );

    // Public docs local links target tracked content
    let mut tracked_docs = vec![Path::new("README.md").to_path_buf()];
    tracked_docs.extend(
        public_markdown_docs()
            .into_iter()
            .filter(|path| !is_host_only_repo_path(path)),
    );
    let untracked = tracked_docs
        .iter()
        .flat_map(|path| {
            repo_local_markdown_links(path)
                .into_iter()
                .filter(|(_, target)| !is_host_only_repo_path(target))
                .filter(|(_, target)| !git_tracks_path(target))
                .map(|(link, target)| {
                    format!("{} -> {} ({})", path.display(), link, target.display())
                })
        })
        .collect::<Vec<_>>();
    assert!(
        untracked.is_empty(),
        "public docs local links must target tracked repository content: {untracked:?}"
    );

    // Public docs do not contain host-absolute home paths
    let mut home_path_docs = vec![Path::new("README.md").to_path_buf()];
    home_path_docs.extend(
        public_markdown_docs()
            .into_iter()
            .filter(|path| !is_host_only_repo_path(path)),
    );
    let home_path_matches = home_path_docs
        .iter()
        .flat_map(|path| host_absolute_home_path_matches(path))
        .collect::<Vec<_>>();
    assert!(
        home_path_matches.is_empty(),
        "public docs must not contain host-absolute home paths: {home_path_matches:?}"
    );

    // Public docs do not link to host-only paths
    let mut link_docs = vec![Path::new("README.md").to_path_buf()];
    link_docs.extend(
        public_markdown_docs()
            .into_iter()
            .filter(|path| !is_host_only_repo_path(path)),
    );
    let host_only_links = link_docs
        .iter()
        .flat_map(|path| {
            repo_local_markdown_links(path)
                .into_iter()
                .filter(|(_, target)| is_host_only_repo_path(target))
                .map(|(link, target)| {
                    format!("{} -> {} ({})", path.display(), link, target.display())
                })
        })
        .collect::<Vec<_>>();
    assert!(
        host_only_links.is_empty(),
        "public docs must not link to ignored host-only release paths: {host_only_links:?}"
    );

    // Public docs linked example configs are public-safe
    let mut config_docs = vec![Path::new("README.md").to_path_buf()];
    config_docs.extend(
        public_markdown_docs()
            .into_iter()
            .filter(|path| !is_host_only_repo_path(path)),
    );
    let unclassified = config_docs
        .iter()
        .flat_map(|path| {
            repo_local_markdown_links(path)
                .into_iter()
                .map(|(_, target)| normalize_repo_path(&target))
                .filter(|target| target.starts_with("config/examples/"))
                .filter(|target| !git_tracks_repo_path(target))
                .map(|target| format!("{} -> {target}", path.display()))
        })
        .collect::<Vec<_>>();
    assert!(
        unclassified.is_empty(),
        "public docs must link only to tracked example configs: {unclassified:?}"
    );

    // Host-only release material is never tracked in the public repository.
    // Some paths are excluded by the tracked `.gitignore`; the internal
    // planning and workflow ones may be excluded per-clone via
    // `.git/info/exclude`. The invariant that matters either way is that git
    // does not track them.
    let tracked_host_only = public_tip_tracked_repo_paths()
        .into_iter()
        .filter(|path| is_host_only_repo_path(Path::new(path)))
        .collect::<Vec<_>>();
    assert!(
        tracked_host_only.is_empty(),
        "host-only release material must not be tracked: {tracked_host_only:?}"
    );

    let tracked_public_specs = public_tip_tracked_repo_paths()
        .into_iter()
        .filter(|path| path.starts_with("openspec/specs/"))
        .collect::<Vec<_>>();
    assert!(
        !tracked_public_specs.is_empty(),
        "public OpenSpec product specifications must remain tracked"
    );
    let marker_matches = tracked_public_specs
        .iter()
        .flat_map(|path| {
            let contents = fs::read_to_string(path)
                .unwrap_or_else(|error| panic!("{path}: {error}"))
                .to_lowercase();
            PUBLIC_OPENSPEC_CONTENT_MARKERS
                .iter()
                .filter(move |marker| contents.contains(**marker))
                .map(move |marker| format!("{path} contains {marker:?}"))
        })
        .collect::<Vec<_>>();
    assert!(
        marker_matches.is_empty(),
        "public OpenSpec specifications must not contain private evidence declarations: {marker_matches:?}"
    );
}

#[test]
fn public_docs_classify_openspec_planning_and_product_specs() {
    for path in [
        "openspec/changes/active/proposal.md",
        "openspec/changes/archive/evidence.md",
        "openspec/config.yaml",
    ] {
        assert!(
            is_host_only_repo_path(Path::new(path)),
            "OpenSpec planning path must be host-only: {path}"
        );
    }

    for path in [
        "openspec/specs/installer-service-archive/spec.md",
        "openspec/specs/release-rc-provenance/spec.md",
    ] {
        assert!(
            !is_host_only_repo_path(Path::new(path)),
            "synced OpenSpec product specification must be public-safe: {path}"
        );
        assert!(
            public_tip_tracked_repo_paths()
                .iter()
                .any(|tracked| tracked == path),
            "public specification must be tracked: {path}"
        );
    }
}

#[test]
fn public_docs_wording_and_config_are_safe() {
    // Public surfaces do not reintroduce split-checkout guidance
    let stale_terms = stale_split_checkout_terms();
    let surfaces = public_text_surfaces();
    assert!(!surfaces.is_empty(), "expected public text surfaces");
    let matches = surfaces
        .iter()
        .flat_map(|path| stale_public_guidance_matches(path, &stale_terms))
        .collect::<Vec<_>>();
    assert!(
        matches.is_empty(),
        "public surfaces must not reintroduce retired split-checkout guidance: {matches:?}"
    );

    // Public release workflows do not reference host-only paths
    let release_workflows = [".github/workflows/ci.yml", ".github/workflows/release.yml"];
    let workflow_matches = release_workflows
        .iter()
        .flat_map(|path| {
            let workflow =
                fs::read_to_string(path).unwrap_or_else(|error| panic!("{path}: {error}"));
            HOST_ONLY_REPO_PATHS
                .iter()
                .filter(move |host_only_path| workflow.contains(**host_only_path))
                .map(move |host_only_path| format!("{path} references {host_only_path:?}"))
        })
        .collect::<Vec<_>>();
    assert!(
        workflow_matches.is_empty(),
        "public release workflow YAML must not reference host-only paths: {workflow_matches:?}"
    );
}
fn public_markdown_docs() -> Vec<std::path::PathBuf> {
    top_level_markdown_docs()
        .into_iter()
        .filter(|path| path.file_name().is_none_or(|name| name != "CHANGELOG.md"))
        .collect()
}

fn read_release_workflow() -> String {
    fs::read_to_string(".github/workflows/release.yml")
        .expect("release workflow")
        .replace("\r\n", "\n")
}

fn public_text_surfaces() -> Vec<std::path::PathBuf> {
    let mut surfaces = vec![Path::new("README.md").to_path_buf()];
    surfaces.extend(public_markdown_docs());
    surfaces.extend(
        [".github/workflows/ci.yml", ".github/workflows/release.yml"]
            .into_iter()
            .map(Path::new)
            .filter(|path| path.exists() && git_tracks_path(path))
            .map(Path::to_path_buf),
    );

    surfaces
}

fn top_level_markdown_docs() -> Vec<std::path::PathBuf> {
    fs::read_dir("docs")
        .expect("docs directory")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|extension| extension == "md"))
        .collect()
}

fn git_tracked_repo_paths() -> Vec<String> {
    let output = Command::new("git")
        .arg("ls-files")
        .output()
        .expect("git ls-files");

    assert!(
        output.status.success(),
        "git ls-files failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::to_string)
        .collect()
}

fn public_tip_tracked_repo_paths() -> Vec<String> {
    let deleted = Command::new("git")
        .args(["diff", "--name-only", "--diff-filter=D", "HEAD", "--"])
        .output()
        .expect("git diff");
    assert!(
        deleted.status.success(),
        "git diff failed: {}",
        String::from_utf8_lossy(&deleted.stderr)
    );
    let deleted_output = String::from_utf8_lossy(&deleted.stdout);
    let deleted = deleted_output
        .lines()
        .map(str::to_string)
        .collect::<std::collections::HashSet<_>>();

    git_tracked_repo_paths()
        .into_iter()
        .filter(|path| !deleted.contains(path.as_str()))
        .collect()
}

fn git_tracks_repo_path(path: &str) -> bool {
    let output = Command::new("git")
        .args(["ls-files", "--", path])
        .output()
        .expect("git ls-files");

    assert!(
        output.status.success(),
        "git ls-files failed for {path}: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    !output.stdout.is_empty()
}

fn git_tracks_path(path: &Path) -> bool {
    let path = normalize_repo_path(path);
    if path.is_empty() {
        return false;
    }

    git_tracks_repo_path(&path)
}

fn stale_split_checkout_terms() -> [&'static str; 9] {
    [
        "runewatch-public",
        "split-checkout",
        "split checkout",
        "second local checkout",
        "separate checkout",
        "export tree",
        "exported tree",
        "export-tree",
        "paired private/public",
    ]
}

fn is_host_only_repo_path(path: &Path) -> bool {
    let path = normalize_repo_path(path);

    HOST_ONLY_REPO_PATHS.iter().any(|host_only_path| {
        if host_only_path.ends_with('/') || host_only_path.ends_with('-') {
            path.starts_with(host_only_path)
        } else {
            path == *host_only_path
        }
    })
}

fn normalize_repo_path(path: &Path) -> String {
    let mut components = Vec::new();

    for component in path.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                components.pop();
            }
            std::path::Component::Normal(value) => {
                components.push(value.to_string_lossy().to_string());
            }
            _ => {}
        }
    }

    components.join("/")
}

fn stale_public_guidance_matches(path: &Path, stale_terms: &[&str]) -> Vec<String> {
    let markdown =
        fs::read_to_string(path).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    let lowercase = markdown.to_lowercase();

    stale_terms
        .iter()
        .filter(|term| lowercase.contains(**term))
        .map(|term| format!("{} contains {term:?}", path.display()))
        .collect()
}

fn host_absolute_home_path_matches(path: &Path) -> Vec<String> {
    let markdown =
        fs::read_to_string(path).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    let host_home_path_markers = [
        "/home/christian/",
        "/Users/christian/",
        "C:/Users/christian/",
        "C:\\Users\\christian\\",
    ];

    markdown
        .lines()
        .enumerate()
        .flat_map(|(index, line)| {
            host_home_path_markers
                .iter()
                .filter(move |marker| line.contains(**marker))
                .map(move |marker| format!("{}:{} contains {marker:?}", path.display(), index + 1))
        })
        .collect()
}

fn repo_local_markdown_links(markdown_path: &Path) -> Vec<(String, std::path::PathBuf)> {
    let markdown = fs::read_to_string(markdown_path)
        .unwrap_or_else(|error| panic!("{}: {error}", markdown_path.display()));
    let base = markdown_path.parent().unwrap_or_else(|| Path::new(""));

    extract_markdown_links(&markdown)
        .into_iter()
        .filter(|link| is_repo_local_link(link))
        .map(|link| {
            let target = link.split_once('#').map_or(link, |(path, _)| path);
            (link.to_string(), base.join(target))
        })
        .collect()
}

fn extract_markdown_links(markdown: &str) -> Vec<&str> {
    let mut links = Vec::new();
    let mut rest = markdown;

    while let Some(start) = rest.find("](") {
        rest = &rest[start + 2..];
        let Some(end) = rest.find(')') else {
            break;
        };
        links.push(&rest[..end]);
        rest = &rest[end + 1..];
    }

    links
}

fn is_repo_local_link(link: &str) -> bool {
    !link.is_empty()
        && !link.starts_with('#')
        && !link.starts_with("http://")
        && !link.starts_with("https://")
        && !link.starts_with("mailto:")
}
