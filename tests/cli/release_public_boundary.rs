use super::*;

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
    "scripts/ralph",
    "scripts/inspiration/",
    "tasks/",
    ".opencode/",
    "logs/",
    "state/",
    "artifacts/",
    "runtime/ralph/",
    "config/examples/splunk-",
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
        public_docs_pos < fmt_pos,
        "release-preflight should run focused public boundary checks before expensive checks: {preflight_stdout}"
    );
}

#[cfg(unix)]
#[test]
fn release_artifact_manifest_accepts_curated_bundles_and_rejects_extra_entries() {
    let temp = tempdir().expect("tempdir");
    let artifacts = temp.path().join("artifacts");
    let good_payload = temp.path().join("good-payload");
    let bad_payload = temp.path().join("bad-payload");
    fs::create_dir_all(&artifacts).expect("create artifacts");
    fs::create_dir_all(good_payload.join("config/examples")).expect("create good payload");
    fs::create_dir_all(bad_payload.join("logs")).expect("create bad payload logs");
    fs::write(good_payload.join("telltale"), "binary\n").expect("write telltale");
    fs::write(good_payload.join("adr"), "binary\n").expect("write adr");
    fs::write(good_payload.join("LICENSE"), "Apache-2.0\n").expect("write LICENSE");
    fs::write(good_payload.join("README.md"), "# quick start\n").expect("write README");
    fs::write(
        good_payload.join("config/examples/telltale-outputs.yaml"),
        "outputs: {}\n",
    )
    .expect("write outputs example");
    fs::write(
        good_payload.join("config/examples/adr-scan.service"),
        "[Service]\n",
    )
    .expect("write service example");
    fs::write(
        good_payload.join("config/examples/adr-scan.timer"),
        "[Timer]\n",
    )
    .expect("write timer example");
    fs::write(
        good_payload.join("config/examples/adr-scan-task.xml"),
        "<Task/>\n",
    )
    .expect("write task example");
    fs::write(bad_payload.join("telltale.exe"), "binary\n").expect("write bad telltale.exe");
    fs::write(bad_payload.join("adr.exe"), "binary\n").expect("write bad adr.exe");
    fs::write(
        bad_payload.join("logs").join("adr-events.jsonl"),
        "{\"event_type\":\"activity\"}\n",
    )
    .expect("write bad log");

    let good_archive = artifacts.join("telltale-v0.1.0-x86_64-unknown-linux-gnu.tar.gz");
    let tar = Command::new("tar")
        .arg("-czf")
        .arg(&good_archive)
        .arg("-C")
        .arg(&good_payload)
        .arg("telltale")
        .arg("adr")
        .arg("LICENSE")
        .arg("README.md")
        .arg("config/examples/telltale-outputs.yaml")
        .arg("config/examples/adr-scan.service")
        .arg("config/examples/adr-scan.timer")
        .arg("config/examples/adr-scan-task.xml")
        .output()
        .expect("tar good archive");
    assert!(
        tar.status.success(),
        "tar good archive failed: {}",
        String::from_utf8_lossy(&tar.stderr)
    );
    let legacy_archive = artifacts.join("adr-v0.1.0-x86_64-unknown-linux-gnu.tar.gz");
    fs::copy(&good_archive, &legacy_archive).expect("copy legacy tar archive");

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
    assert!(
        stdout.contains("  adr"),
        "missing compatibility binary entry: {stdout}"
    );

    fs::write(good_payload.join("adr.exe"), "binary\n").expect("write adr.exe");
    fs::write(good_payload.join("telltale.exe"), "binary\n").expect("write telltale.exe");
    let good_zip = artifacts.join("telltale-v0.1.0-x86_64-pc-windows-msvc.zip");
    let zip = Command::new("zip")
        .arg("-q")
        .arg(&good_zip)
        .arg("telltale.exe")
        .arg("adr.exe")
        .arg("LICENSE")
        .arg("README.md")
        .arg("config/examples/telltale-outputs.yaml")
        .arg("config/examples/adr-scan.service")
        .arg("config/examples/adr-scan.timer")
        .arg("config/examples/adr-scan-task.xml")
        .current_dir(&good_payload)
        .output()
        .expect("zip good archive");
    assert!(
        zip.status.success(),
        "zip good archive failed: {}",
        String::from_utf8_lossy(&zip.stderr)
    );
    let legacy_zip = artifacts.join("adr-v0.1.0-x86_64-pc-windows-msvc.zip");
    fs::copy(&good_zip, &legacy_zip).expect("copy legacy zip archive");

    let checksums = Command::new("sha256sum")
        .arg(good_archive.file_name().expect("tar archive file name"))
        .arg(
            legacy_archive
                .file_name()
                .expect("legacy tar archive file name"),
        )
        .arg(good_zip.file_name().expect("zip archive file name"))
        .arg(
            legacy_zip
                .file_name()
                .expect("legacy zip archive file name"),
        )
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
        stdout.contains(legacy_archive.to_string_lossy().as_ref()),
        "missing legacy tar archive header: {stdout}"
    );
    assert!(
        stdout.contains(legacy_zip.to_string_lossy().as_ref()),
        "missing legacy zip archive header: {stdout}"
    );
    assert!(
        stdout.contains("  adr.exe"),
        "missing Windows binary entry: {stdout}"
    );
    assert!(
        stdout.contains("  telltale.exe"),
        "missing primary Windows binary entry: {stdout}"
    );
    assert!(
        stdout.contains("adr-v0.1.0-x86_64-unknown-linux-gnu.tar.gz: OK"),
        "missing tar checksum verification: {stdout}"
    );
    assert!(
        stdout.contains("adr-v0.1.0-x86_64-pc-windows-msvc.zip: OK"),
        "missing zip checksum verification: {stdout}"
    );

    fs::remove_file(&legacy_archive).expect("remove legacy archive");
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
        .expect("make release-artifact-manifest for missing pair");
    assert!(
        !output.status.success(),
        "release-artifact-manifest should reject a missing canonical/legacy pair"
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("missing matching legacy archive"),
        "unexpected missing pair output: {combined}"
    );
    fs::copy(&good_archive, &legacy_archive).expect("restore missing legacy archive");

    fs::write(&legacy_archive, "different archive bytes\n").expect("mutate legacy archive");
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
        .expect("make release-artifact-manifest for mismatched pair");
    assert!(
        !output.status.success(),
        "release-artifact-manifest should reject mismatched canonical/legacy archives"
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("different digests"),
        "unexpected mismatched pair output: {combined}"
    );
    fs::copy(&good_archive, &legacy_archive).expect("restore legacy archive");

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
    fs::remove_file(&legacy_archive).expect("remove legacy archive");
    fs::remove_file(&good_zip).expect("remove good zip");
    fs::remove_file(&legacy_zip).expect("remove legacy zip");
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
    let bad_legacy_archive = artifacts.join("adr-v0.1.0-with-log.zip");
    fs::copy(&bad_archive, &bad_legacy_archive).expect("copy bad legacy archive");

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
        combined.contains("does not match the expected bundle manifest"),
        "unexpected output: {combined}"
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
            "cargo run --locked --bin telltale -- scan --once --dry-run --emit-activity --emit-session-risk-summary --root tests/fixtures/session_stores"
        ),
        "fixture scan must stay dry-run, fixture-rooted, and summary-enabled: {stdout}"
    );
    assert!(
        stdout.contains("cargo run --locked --bin telltale -- rules validate"),
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
    assert!(stdout.contains("target/release/adr"));
    assert!(stdout.contains("install -m 0755 target/release/telltale"));
    assert!(stdout.contains("install -m 0755 target/release/adr"));
    assert!(stdout.contains("/telltale scan --once"));
    assert!(!stdout.contains("/adr scan --once"));
}

#[test]
fn release_workflow_packages_and_verifies_canonical_legacy_pairs() {
    let workflow = fs::read_to_string(".github/workflows/release.yml").expect("release workflow");
    assert!(workflow.contains("telltale-${{ github.ref_name }}-${{ matrix.target }}"));
    assert!(workflow.contains("adr-${{ github.ref_name }}-${{ matrix.target }}"));
    assert!(workflow.contains("telltale adr LICENSE README.md"));
    assert!(workflow.contains("cp \"$archive\" \"$legacy_archive\""));
    assert!(workflow.contains(
        "subject-path: telltale-${{ github.ref_name }}-${{ matrix.target }}.${{ matrix.archive }}"
    ));
    assert!(workflow.contains(
        "subject-path: adr-${{ github.ref_name }}-${{ matrix.target }}.${{ matrix.archive }}"
    ));
    assert!(workflow.contains("cmp -s \"$canonical\" \"$legacy\""));
}

#[test]
fn release_workflow_has_ci_safe_preflight_and_native_smoke_gates() {
    let workflow = fs::read_to_string(".github/workflows/release.yml").expect("release workflow");
    serde_yaml::from_str::<serde_yaml::Value>(&workflow).expect("release workflow YAML");

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
        "make --silent CARGO_LOCKED=--locked release-crate-manifest",
        "make --silent CARGO_LOCKED=--locked package-verify",
        "make --silent CARGO_LOCKED=--locked release-fixture-smoke",
        "cargo build --locked --release --target",
        "Release gate: verify installer provenance",
        "INSTALLER_COMMIT=\"",
        "uncommitted|unknown|placeholder|local|dirty|none|todo",
        "^[0-9a-f]{7,40}$",
        "git cat-file -e \"${installer_commit}^{commit}\"",
        "git merge-base --is-ancestor \"${installer_commit}\" \"${GITHUB_SHA}\"",
        "is not present in the checkout",
        "is not an ancestor of tagged commit",
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
    // planning and workflow ones are excluded per-clone via `.git/info/exclude`
    // so the public `.gitignore` does not enumerate host-only material. The
    // invariant that matters either way is that git does not track them.
    let tracked_host_only = git_tracked_repo_paths()
        .into_iter()
        .filter(|path| is_host_only_repo_path(Path::new(path)))
        .collect::<Vec<_>>();
    assert!(
        tracked_host_only.is_empty(),
        "host-only release material must not be tracked: {tracked_host_only:?}"
    );
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
