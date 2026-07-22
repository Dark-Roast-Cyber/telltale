#![cfg(target_os = "linux")]

use std::fs;
use std::io::Write;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use tempfile::tempdir;

const SCRIPT: &str = "scripts/install-telltale";

fn target() -> String {
    match std::env::consts::ARCH {
        "x86_64" => "x86_64-unknown-linux-gnu",
        "aarch64" => "aarch64-unknown-linux-gnu",
        arch => panic!("unsupported Linux test architecture: {arch}"),
    }
    .to_owned()
}

fn executable(path: &Path, contents: &str) {
    fs::write(path, contents).expect("write executable");
    let mut permissions = fs::metadata(path)
        .expect("executable metadata")
        .permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions).expect("make executable");
}

fn binary(path: &Path, version: &str) {
    let name = path.file_name().unwrap().to_string_lossy();
    executable(
        path,
        &format!(
            "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then printf '%s\\n' '{name} {version} (synthetic)'; else exit 0; fi\n"
        ),
    );
}

fn archive(
    root: &Path,
    name: &str,
    version: &str,
    include_telltale: bool,
    include_adr: bool,
) -> PathBuf {
    let payload = root.join(format!(
        "payload-{name}-{version}-{include_telltale}-{include_adr}"
    ));
    fs::create_dir(&payload).expect("create archive payload");
    if include_telltale {
        binary(&payload.join("telltale"), version);
    }
    if include_adr {
        binary(&payload.join("adr"), version);
    }
    let archive = root.join(name);
    let mut command = Command::new("tar");
    command
        .args(["-czf"])
        .arg(&archive)
        .args(["-C", payload.to_str().unwrap()]);
    if include_telltale {
        command.arg("telltale");
    }
    if include_adr {
        command.arg("adr");
    }
    let output = command.output().expect("create archive");
    assert!(
        output.status.success(),
        "tar failed: {}",
        output_text(&output)
    );
    archive
}

fn identity_binary(path: &Path, reported_name: &str, version: &str) {
    executable(
        path,
        &format!(
            "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then printf '%s\\n' '{reported_name} {version} (synthetic)'; else exit 0; fi\n"
        ),
    );
}

fn curated_archive(root: &Path, name: &str, version: &str) -> PathBuf {
    let payload = root.join(format!("payload-curated-{name}"));
    fs::create_dir_all(payload.join("config/examples")).expect("create curated payload");
    binary(&payload.join("telltale"), version);
    binary(&payload.join("adr"), version);
    fs::write(payload.join("LICENSE"), b"Apache-2.0\n").expect("license");
    fs::write(payload.join("README.md"), b"synthetic release\n").expect("readme");
    fs::write(
        payload.join("config/examples/adr-scan.service"),
        b"[Service]\n",
    )
    .expect("service example");
    fs::write(
        payload.join("config/examples/adr-scan.timer"),
        b"[Timer]\nUnit=adr-scan.service\n",
    )
    .expect("timer example");
    fs::write(
        payload.join("config/examples/adr-scan-task.xml"),
        b"<Task>synthetic</Task>\n",
    )
    .expect("task example");
    fs::write(
        payload.join("config/examples/telltale-outputs.yaml"),
        b"version: 1\n",
    )
    .expect("outputs example");
    let archive = root.join(name);
    let output = Command::new("tar")
        .args(["-czf"])
        .arg(&archive)
        .args([
            "-C",
            payload.to_str().unwrap(),
            "telltale",
            "adr",
            "LICENSE",
            "README.md",
            "config/examples/adr-scan.service",
            "config/examples/adr-scan.timer",
            "config/examples/adr-scan-task.xml",
            "config/examples/telltale-outputs.yaml",
        ])
        .output()
        .expect("create curated archive");
    assert!(
        output.status.success(),
        "tar failed: {}",
        output_text(&output)
    );
    archive
}

fn identity_archive(
    root: &Path,
    name: &str,
    version: &str,
    telltale_reports: &str,
    adr_reports: &str,
) -> PathBuf {
    let payload = root.join(format!(
        "payload-identity-{name}-{telltale_reports}-{adr_reports}"
    ));
    fs::create_dir(&payload).expect("create identity payload");
    identity_binary(&payload.join("telltale"), telltale_reports, version);
    identity_binary(&payload.join("adr"), adr_reports, version);
    let archive = root.join(name);
    let output = Command::new("tar")
        .args(["-czf"])
        .arg(&archive)
        .args(["-C", payload.to_str().unwrap(), "telltale", "adr"])
        .output()
        .expect("create identity archive");
    assert!(
        output.status.success(),
        "tar failed: {}",
        output_text(&output)
    );
    archive
}

fn symlink_archive(root: &Path, name: &str, version: &str) -> PathBuf {
    let payload = root.join(format!("payload-link-{name}"));
    fs::create_dir(&payload).expect("create link payload");
    binary(&payload.join("adr"), version);
    symlink("adr", payload.join("telltale")).expect("create archive link");
    let archive = root.join(name);
    let output = Command::new("tar")
        .args(["-czf"])
        .arg(&archive)
        .args(["-C", payload.to_str().unwrap(), "telltale", "adr"])
        .output()
        .expect("create link archive");
    assert!(
        output.status.success(),
        "tar failed: {}",
        output_text(&output)
    );
    archive
}

fn traversal_archive(root: &Path, name: &str, version: &str) -> PathBuf {
    let payload = root.join(format!("payload-traversal-{name}"));
    fs::create_dir(&payload).expect("create traversal payload");
    fs::write(payload.join("evil"), b"unsafe").expect("write traversal member");
    binary(&payload.join("telltale"), version);
    binary(&payload.join("adr"), version);
    let archive = root.join(name);
    let output = Command::new("tar")
        .args(["-czf"])
        .arg(&archive)
        .args([
            "-C",
            payload.to_str().unwrap(),
            "--transform=s,^evil$,../evil,",
            "evil",
            "telltale",
            "adr",
        ])
        .output()
        .expect("create traversal archive");
    assert!(
        output.status.success(),
        "tar failed: {}",
        output_text(&output)
    );
    archive
}

fn checksum(archive: &Path, sums: &Path) {
    let output = Command::new("sha256sum")
        .arg(archive)
        .output()
        .expect("calculate checksum");
    assert!(
        output.status.success(),
        "sha256sum failed: {}",
        output_text(&output)
    );
    let digest = String::from_utf8_lossy(&output.stdout)
        .split_whitespace()
        .next()
        .expect("checksum digest")
        .to_owned();
    fs::write(
        sums,
        format!(
            "{digest}  {}\n",
            archive.file_name().unwrap().to_string_lossy()
        ),
    )
    .expect("write checksums");
}

fn release_metadata(root: &Path, tag: &str) -> PathBuf {
    let metadata = root.join("release.json");
    fs::write(
        &metadata,
        format!(
            "{{\"tag_name\":\"{tag}\",\"assets\":[{{\"browser_download_url\":\"https://invalid.example/decoy.tar.gz\"}}]}}\n"
        ),
    )
    .expect("write release metadata");
    metadata
}

fn fake_curl(tools: &Path) {
    executable(
        &tools.join("curl"),
        r####"#!/bin/sh
set -eu
output=''
url=''
while [ "$#" -gt 0 ]; do
    case "$1" in
        -o) output=$2; shift 2 ;;
        -*) shift ;;
        *) url=$1; shift ;;
    esac
done
printf '%s\n' "$url" >> "${FAKE_CURL_LOG:?}"
case "$url" in
    */releases/latest)
        cat "${FAKE_CURL_METADATA:?}"
        ;;
    */SHA256SUMS)
        [ -n "${FAKE_CURL_CHECKSUMS:-}" ] && [ -f "$FAKE_CURL_CHECKSUMS" ] || exit 22
        cp "$FAKE_CURL_CHECKSUMS" "$output"
        ;;
    */*.tar.gz)
        asset=${url##*/}
        [ -f "${FAKE_CURL_ASSET_DIR:?}/$asset" ] || exit 22
        cp "$FAKE_CURL_ASSET_DIR/$asset" "$output"
        ;;
    *) exit 22 ;;
esac
"####,
    );
}

fn fake_tools(root: &Path) -> PathBuf {
    let tools = root.join("tools");
    fs::create_dir_all(&tools).expect("create tools");
    fake_curl(&tools);
    tools
}

fn installer_command(
    root: &Path,
    metadata: &Path,
    asset_dir: &Path,
    checksum_file: Option<&Path>,
    tools: &Path,
) -> Command {
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join(SCRIPT);
    let mut command = Command::new("bash");
    let path = format!("{}:{}", tools.display(), std::env::var("PATH").unwrap());
    command
        .arg(script)
        .env("HOME", root.join("home"))
        .env("PATH", path)
        .env("FAKE_CURL_METADATA", metadata)
        .env("FAKE_CURL_ASSET_DIR", asset_dir)
        .env("FAKE_CURL_LOG", root.join("curl.log"));
    if let Some(checksum_file) = checksum_file {
        command.env("FAKE_CURL_CHECKSUMS", checksum_file);
    } else {
        command.env_remove("FAKE_CURL_CHECKSUMS");
    }
    command
}

fn output_text(output: &Output) -> String {
    format!(
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "installer failed: {}",
        output_text(output)
    );
}

fn assert_failure(output: &Output) {
    assert!(
        !output.status.success(),
        "installer unexpectedly succeeded: {}",
        output_text(output)
    );
}

fn run_release(
    root: &Path,
    metadata: &Path,
    asset_dir: &Path,
    checksum_file: Option<&Path>,
    install_dir: &Path,
    args: &[&str],
) -> Output {
    let tools = fake_tools(root);
    let mut command = installer_command(root, metadata, asset_dir, checksum_file, &tools);
    command
        .args(args)
        .args(["--install-dir", install_dir.to_str().unwrap()]);
    command.output().expect("run installer")
}

#[test]
fn canonical_asset_is_preferred_and_browser_urls_are_ignored() {
    let temp = tempdir().expect("tempdir");
    let target = target();
    let canonical_name = format!("telltale-v0.2.0-{target}.tar.gz");
    let legacy_name = format!("adr-v0.2.0-{target}.tar.gz");
    let canonical = archive(temp.path(), &canonical_name, "0.2.0", true, true);
    let _legacy = archive(temp.path(), &legacy_name, "0.2.0", false, true);
    let metadata = release_metadata(temp.path(), "v0.2.0");
    let sums = temp.path().join("SHA256SUMS");
    checksum(&canonical, &sums);
    let install_dir = temp.path().join("bin");

    let output = run_release(
        temp.path(),
        &metadata,
        temp.path(),
        Some(&sums),
        &install_dir,
        &[],
    );
    assert_success(&output);
    assert!(install_dir.join("telltale").is_file());
    assert!(install_dir.join("adr").is_file());
    let log = fs::read_to_string(temp.path().join("curl.log")).expect("curl log");
    assert!(log.contains(&format!("/telltale-v0.2.0-{target}.tar.gz")));
    assert!(!log.contains(&format!("/adr-v0.2.0-{target}.tar.gz")));
}

#[test]
fn legacy_exact_asset_fallback_is_only_one_binary_bootstrap_for_v0_1_0() {
    let temp = tempdir().expect("tempdir");
    let target = target();
    let name = format!("adr-v0.1.0-{target}.tar.gz");
    let selected = archive(temp.path(), &name, "0.1.0", false, true);
    let metadata = release_metadata(temp.path(), "v0.1.0");
    let sums = temp.path().join("SHA256SUMS");
    checksum(&selected, &sums);
    let install_dir = temp.path().join("bin");

    let output = run_release(
        temp.path(),
        &metadata,
        temp.path(),
        Some(&sums),
        &install_dir,
        &[],
    );
    assert_success(&output);
    assert!(install_dir.join("telltale").is_file());
    assert!(install_dir.join("adr").is_file());
}

#[test]
fn dual_binary_v0_2_legacy_asset_fallback_uses_exact_adr_checksum() {
    let temp = tempdir().expect("tempdir");
    let target = target();
    let name = format!("adr-v0.2.0-{target}.tar.gz");
    let selected = archive(temp.path(), &name, "0.2.0", true, true);
    let metadata = release_metadata(temp.path(), "v0.2.0");
    let sums = temp.path().join("SHA256SUMS");
    checksum(&selected, &sums);
    let install_dir = temp.path().join("bin");

    let output = run_release(
        temp.path(),
        &metadata,
        temp.path(),
        Some(&sums),
        &install_dir,
        &[],
    );
    assert_success(&output);
    let log = fs::read_to_string(temp.path().join("curl.log")).expect("curl log");
    assert!(log.contains(&format!("/telltale-v0.2.0-{target}.tar.gz")));
    assert!(log.contains(&format!("/adr-v0.2.0-{target}.tar.gz")));
    assert!(output_text(&output).contains(&format!("Checksum verified: {name}")));
}

#[test]
fn one_binary_v0_2_legacy_archive_is_rejected() {
    let temp = tempdir().expect("tempdir");
    let target = target();
    let name = format!("adr-v0.2.0-{target}.tar.gz");
    let selected = archive(temp.path(), &name, "0.2.0", false, true);
    let metadata = release_metadata(temp.path(), "v0.2.0");
    let sums = temp.path().join("SHA256SUMS");
    checksum(&selected, &sums);

    let output = run_release(
        temp.path(),
        &metadata,
        temp.path(),
        Some(&sums),
        &temp.path().join("bin"),
        &[],
    );
    assert_failure(&output);
    assert!(output_text(&output).contains("supported only for v0.1.0"));
}

#[test]
fn missing_asset_does_not_fall_back_to_source() {
    let temp = tempdir().expect("tempdir");
    let metadata = release_metadata(temp.path(), "v0.2.0");
    let output = run_release(
        temp.path(),
        &metadata,
        temp.path(),
        None,
        &temp.path().join("bin"),
        &[],
    );
    assert_failure(&output);
    assert!(output_text(&output).contains("No exact release asset"));
}

#[test]
fn checksum_failures_preserve_existing_installation() {
    let temp = tempdir().expect("tempdir");
    let target = target();
    let name = format!("telltale-v0.2.0-{target}.tar.gz");
    let _selected = archive(temp.path(), &name, "0.2.0", true, true);
    let metadata = release_metadata(temp.path(), "v0.2.0");
    let install_dir = temp.path().join("bin");
    fs::create_dir(&install_dir).expect("create install dir");
    fs::write(install_dir.join("telltale"), "old telltale").expect("old telltale");
    fs::write(install_dir.join("adr"), "old adr").expect("old adr");

    let output = run_release(
        temp.path(),
        &metadata,
        temp.path(),
        Some(&temp.path().join("missing-SHA256SUMS")),
        &install_dir,
        &[],
    );
    assert_failure(&output);
    assert_eq!(
        fs::read_to_string(install_dir.join("telltale")).unwrap(),
        "old telltale"
    );
    assert_eq!(
        fs::read_to_string(install_dir.join("adr")).unwrap(),
        "old adr"
    );
    assert!(output_text(&output).contains("Could not fetch SHA256SUMS"));

    let sums = temp.path().join("SHA256SUMS");
    fs::write(&sums, "deadbeef  other.tar.gz\n").expect("write nonmatching checksums");
    let output = run_release(
        temp.path(),
        &metadata,
        temp.path(),
        Some(&sums),
        &install_dir,
        &[],
    );
    assert_failure(&output);
    assert!(output_text(&output).contains("No exact SHA256SUMS entry"));

    fs::write(&sums, format!("{}  {name}\n", "0".repeat(64))).expect("write bad checksum");
    let output = run_release(
        temp.path(),
        &metadata,
        temp.path(),
        Some(&sums),
        &install_dir,
        &[],
    );
    assert_failure(&output);
    assert!(output_text(&output).contains("Checksum mismatch"));
}

#[test]
fn curated_release_archive_installs_only_required_binaries() {
    let temp = tempdir().expect("tempdir");
    let target = target();
    let name = format!("telltale-v0.2.0-{target}.tar.gz");
    let selected = curated_archive(temp.path(), &name, "0.2.0");
    let metadata = release_metadata(temp.path(), "v0.2.0");
    let sums = temp.path().join("SHA256SUMS");
    checksum(&selected, &sums);
    let install_dir = temp.path().join("bin");

    let output = run_release(
        temp.path(),
        &metadata,
        temp.path(),
        Some(&sums),
        &install_dir,
        &[],
    );
    assert_success(&output);
    assert!(install_dir.join("telltale").is_file());
    assert!(install_dir.join("adr").is_file());
    assert!(!install_dir.join("LICENSE").exists());
    assert!(!install_dir.join("config").exists());
}

#[test]
fn unsafe_archive_and_version_forms_fail_before_install() {
    let temp = tempdir().expect("tempdir");
    let target = target();
    let name = format!("telltale-v0.2.0-{target}.tar.gz");
    let unsafe_archive = traversal_archive(temp.path(), &name, "0.2.0");
    let metadata = release_metadata(temp.path(), "v0.2.0");
    let sums = temp.path().join("SHA256SUMS");
    checksum(&unsafe_archive, &sums);
    let output = run_release(
        temp.path(),
        &metadata,
        temp.path(),
        Some(&sums),
        &temp.path().join("unsafe-bin"),
        &[],
    );
    assert_failure(&output);
    assert!(output_text(&output).contains("path traversal"));

    let unsafe_archive = symlink_archive(temp.path(), &name, "0.2.0");
    checksum(&unsafe_archive, &sums);
    let output = run_release(
        temp.path(),
        &metadata,
        temp.path(),
        Some(&sums),
        &temp.path().join("link-bin"),
        &[],
    );
    assert_failure(&output);
    assert!(output_text(&output).contains("contains a link"));

    let wrong = archive(temp.path(), &name, "0.2.0-rc.1", true, true);
    checksum(&wrong, &sums);
    let output = run_release(
        temp.path(),
        &metadata,
        temp.path(),
        Some(&sums),
        &temp.path().join("version-bin"),
        &[],
    );
    assert_failure(&output);
    assert!(output_text(&output).contains("does not match"));
}

#[test]
fn strict_binary_identity_rejects_cross_named_versions() {
    let temp = tempdir().expect("tempdir");
    let target = target();
    let name = format!("telltale-v0.2.0-{target}.tar.gz");
    let selected = identity_archive(temp.path(), &name, "0.2.0", "adr", "telltale");
    let metadata = release_metadata(temp.path(), "v0.2.0");
    let sums = temp.path().join("SHA256SUMS");
    checksum(&selected, &sums);
    let output = run_release(
        temp.path(),
        &metadata,
        temp.path(),
        Some(&sums),
        &temp.path().join("identity-bin"),
        &[],
    );
    assert_failure(&output);
    assert!(output_text(&output).contains("does not match"));
}

#[test]
fn v0_1_adr_only_install_upgrades_to_both_v0_2_binaries() {
    let temp = tempdir().expect("tempdir");
    let target = target();
    let name = format!("telltale-v0.2.0-{target}.tar.gz");
    let selected = archive(temp.path(), &name, "0.2.0", true, true);
    let metadata = release_metadata(temp.path(), "v0.2.0");
    let sums = temp.path().join("SHA256SUMS");
    checksum(&selected, &sums);
    let install_dir = temp.path().join("bin");
    fs::create_dir(&install_dir).expect("create install dir");
    binary(&install_dir.join("adr"), "0.1.0");

    let output = run_release(
        temp.path(),
        &metadata,
        temp.path(),
        Some(&sums),
        &install_dir,
        &[],
    );
    assert_success(&output);
    assert!(install_dir.join("telltale").is_file());
    assert!(install_dir.join("adr").is_file());
    let telltale_version = Command::new(install_dir.join("telltale"))
        .arg("--version")
        .output()
        .expect("run upgraded telltale");
    let adr_version = Command::new(install_dir.join("adr"))
        .arg("--version")
        .output()
        .expect("run upgraded adr");
    assert!(String::from_utf8_lossy(&telltale_version.stdout).starts_with("telltale 0.2.0"));
    assert!(String::from_utf8_lossy(&adr_version.stdout).starts_with("adr 0.2.0"));
}

#[test]
fn binary_replacement_rolls_back_both_files_and_modes_after_mid_failure() {
    let temp = tempdir().expect("tempdir");
    let target = target();
    let name = format!("telltale-v0.2.0-{target}.tar.gz");
    let selected = archive(temp.path(), &name, "0.2.0", true, true);
    let metadata = release_metadata(temp.path(), "v0.2.0");
    let sums = temp.path().join("SHA256SUMS");
    checksum(&selected, &sums);
    let install_dir = temp.path().join("bin");
    fs::create_dir(&install_dir).expect("create install dir");
    fs::write(install_dir.join("telltale"), "old telltale bytes").expect("old telltale");
    fs::write(install_dir.join("adr"), "old adr bytes").expect("old adr");
    fs::set_permissions(
        install_dir.join("telltale"),
        fs::Permissions::from_mode(0o711),
    )
    .expect("old telltale mode");
    fs::set_permissions(install_dir.join("adr"), fs::Permissions::from_mode(0o744))
        .expect("old adr mode");
    let tools = fake_tools(temp.path());
    executable(
        &tools.join("mv"),
        r####"#!/bin/sh
set -eu
src=$2
dst=$3
/usr/bin/mv "$src" "$dst"
case "${src##*/}" in
    telltale.new) exit 1 ;;
esac
"####,
    );
    let mut command = installer_command(temp.path(), &metadata, temp.path(), Some(&sums), &tools);
    command.args(["--install-dir", install_dir.to_str().unwrap()]);
    let output = command.output().expect("run failing replacement");
    assert_failure(&output);
    assert_eq!(
        fs::read(install_dir.join("telltale")).unwrap(),
        b"old telltale bytes"
    );
    assert_eq!(fs::read(install_dir.join("adr")).unwrap(), b"old adr bytes");
    assert_eq!(
        fs::metadata(install_dir.join("telltale"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o711
    );
    assert_eq!(
        fs::metadata(install_dir.join("adr"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o744
    );
}

#[test]
fn explicit_source_install_is_pinned_to_latest_tag() {
    let temp = tempdir().expect("tempdir");
    let metadata = release_metadata(temp.path(), "v0.3.0");
    let tools = fake_tools(temp.path());
    let cargo_log = temp.path().join("cargo-args");
    executable(
        &tools.join("cargo"),
        &format!(
            "#!/bin/sh\nprintf '%s\\n' \"$*\" > '{}'\nroot=''\nwhile [ $# -gt 0 ]; do if [ \"$1\" = \"--root\" ]; then root=$2; shift 2; else shift; fi; done\nmkdir -p \"$root/bin\"\ncat > \"$root/bin/telltale\" <<'EOF'\n#!/bin/sh\nprintf '%s\\n' 'telltale 0.3.0 (synthetic)'\nEOF\ncat > \"$root/bin/adr\" <<'EOF'\n#!/bin/sh\nprintf '%s\\n' 'adr 0.3.0 (synthetic)'\nEOF\nchmod 755 \"$root/bin/telltale\" \"$root/bin/adr\"\n",
            cargo_log.display()
        ),
    );
    let install_dir = temp.path().join("bin");
    let mut command = installer_command(temp.path(), &metadata, temp.path(), None, &tools);
    command
        .args(["--from-source", "--install-dir"])
        .arg(&install_dir);
    let output = command.output().expect("run source installer");
    assert_success(&output);
    let cargo_args = fs::read_to_string(cargo_log).expect("cargo log");
    assert!(cargo_args.contains("--tag v0.3.0"));
    assert!(cargo_args.contains("--locked"));
    assert!(cargo_args.contains("--bins"));
    assert!(!cargo_args.contains("--branch main"));
}

#[test]
fn v0_1_source_adr_only_uses_scoped_bootstrap() {
    let temp = tempdir().expect("tempdir");
    let metadata = release_metadata(temp.path(), "v0.1.0");
    let tools = fake_tools(temp.path());
    let cargo_log = temp.path().join("cargo-args");
    executable(
        &tools.join("cargo"),
        &format!(
            "#!/bin/sh\nprintf '%s\\n' \"$*\" > '{}'\nroot=''\nwhile [ $# -gt 0 ]; do if [ \"$1\" = \"--root\" ]; then root=$2; shift 2; else shift; fi; done\nmkdir -p \"$root/bin\"\ncat > \"$root/bin/adr\" <<'EOF'\n#!/bin/sh\nprintf '%s\\n' 'adr 0.1.0 (synthetic)'\nEOF\nchmod 755 \"$root/bin/adr\"\n",
            cargo_log.display()
        ),
    );
    let install_dir = temp.path().join("bin");
    let mut command = installer_command(temp.path(), &metadata, temp.path(), None, &tools);
    command
        .args(["--from-source", "--install-dir"])
        .arg(&install_dir);
    let output = command.output().expect("run v0.1 source installer");
    assert_success(&output);
    assert!(install_dir.join("telltale").is_file());
    assert!(install_dir.join("adr").is_file());
    let cargo_args = fs::read_to_string(cargo_log).expect("cargo log");
    assert!(cargo_args.contains("--tag v0.1.0"));
    assert!(cargo_args.contains("--locked"));
    assert!(cargo_args.contains("--bins"));
    let telltale_version = Command::new(install_dir.join("telltale"))
        .arg("--version")
        .output()
        .expect("run bootstrapped telltale");
    assert!(String::from_utf8_lossy(&telltale_version.stdout).starts_with("adr 0.1.0"));
}

fn systemctl_ok_script(log: &Path) -> String {
    format!(
        "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\ncase \"$*\" in\n  '--user is-enabled adr-scan.timer') printf 'enabled\\n'; exit 0;;\n  '--user is-active adr-scan.timer') printf 'active\\n'; exit 0;;\nesac\n",
        log.display()
    )
}

#[test]
fn timer_is_single_identity_with_escaped_exec_path() {
    let temp = tempdir().expect("tempdir");
    let target = target();
    let name = format!("telltale-v0.2.0-{target}.tar.gz");
    archive(temp.path(), &name, "0.2.0", true, true);
    let metadata = release_metadata(temp.path(), "v0.2.0");
    let tools = fake_tools(temp.path());
    let log = temp.path().join("systemctl.log");
    executable(&tools.join("systemctl"), &systemctl_ok_script(&log));
    let install_dir = temp
        .path()
        .join("bin space ${HOME} %h \"quote\" \\slash café");
    let mut command = installer_command(temp.path(), &metadata, temp.path(), None, &tools);
    command
        .args(["--skip-checksum", "--with-timer", "--install-dir"])
        .arg(&install_dir);
    let output = command.output().expect("run timer installer");
    assert_success(&output);
    let service = fs::read_to_string(
        temp.path()
            .join("home/.config/systemd/user/adr-scan.service"),
    )
    .expect("service unit");
    let escaped_install_dir = install_dir
        .display()
        .to_string()
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('%', "%%");
    assert!(
        service.contains(&format!(
            "ExecStart=:/usr/bin/env -- \"{escaped_install_dir}/telltale\" scan --once"
        )),
        "service unit: {service}"
    );
    assert!(service.contains("${HOME}"));
    assert!(service.contains("%%h"));
    assert!(service.contains("café"));
    assert!(!service.contains("/adr scan --once"));
    let timer = fs::read_to_string(temp.path().join("home/.config/systemd/user/adr-scan.timer"))
        .expect("timer unit");
    assert!(timer.contains("Unit=adr-scan.service"));
    assert!(!timer.contains("telltale.timer"));
    let analyzer_available = Command::new("systemd-analyze")
        .arg("--version")
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false);
    if analyzer_available {
        let verify = Command::new("systemd-analyze")
            .args([
                "verify",
                temp.path()
                    .join("home/.config/systemd/user/adr-scan.service")
                    .to_str()
                    .unwrap(),
                temp.path()
                    .join("home/.config/systemd/user/adr-scan.timer")
                    .to_str()
                    .unwrap(),
            ])
            .output()
            .expect("verify generated units");
        assert!(
            verify.status.success(),
            "systemd-analyze verify failed: {}",
            output_text(&verify)
        );
    }
}

#[test]
fn timer_failure_restores_existing_units_and_state() {
    let temp = tempdir().expect("tempdir");
    let target = target();
    let name = format!("telltale-v0.2.0-{target}.tar.gz");
    archive(temp.path(), &name, "0.2.0", true, true);
    let metadata = release_metadata(temp.path(), "v0.2.0");
    let unit_dir = temp.path().join("home/.config/systemd/user");
    fs::create_dir_all(&unit_dir).expect("create unit dir");
    let service = unit_dir.join("adr-scan.service");
    let timer = unit_dir.join("adr-scan.timer");
    fs::write(&service, b"old service\n").expect("old service");
    fs::write(&timer, b"old timer\n").expect("old timer");
    fs::set_permissions(&service, fs::Permissions::from_mode(0o601)).expect("service mode");
    fs::set_permissions(&timer, fs::Permissions::from_mode(0o642)).expect("timer mode");
    let tools = fake_tools(temp.path());
    let systemctl_log = temp.path().join("systemctl.log");
    executable(
        &tools.join("systemctl"),
        &format!(
            r#"#!/bin/sh
printf '%s\n' "$*" >> '{}'
case "$*" in
  '--user is-enabled adr-scan.timer') exit 0;;
  '--user is-active adr-scan.timer') exit 0;;
  '--user enable --now adr-scan.timer') exit 1;;
esac
"#,
            systemctl_log.display()
        ),
    );
    let install_dir = temp.path().join("bin");
    let mut command = installer_command(temp.path(), &metadata, temp.path(), None, &tools);
    command
        .args(["--skip-checksum", "--with-timer", "--install-dir"])
        .arg(&install_dir);
    let output = command.output().expect("run failing timer installer");
    assert_failure(&output);
    assert_eq!(fs::read(&service).unwrap(), b"old service\n");
    assert_eq!(fs::read(&timer).unwrap(), b"old timer\n");
    assert_eq!(
        fs::metadata(&service).unwrap().permissions().mode() & 0o777,
        0o601
    );
    assert_eq!(
        fs::metadata(&timer).unwrap().permissions().mode() & 0o777,
        0o642
    );
    assert!(install_dir.join("telltale").is_file());
    assert!(output_text(&output).contains("previous state restoration was attempted"));
    let calls = fs::read_to_string(systemctl_log).expect("systemctl log");
    assert!(calls.contains("--user enable adr-scan.timer"));
    assert!(calls.contains("--user start adr-scan.timer"));
}

#[test]
fn install_without_timer_leaves_existing_units_unchanged() {
    let temp = tempdir().expect("tempdir");
    let target = target();
    let name = format!("telltale-v0.2.0-{target}.tar.gz");
    archive(temp.path(), &name, "0.2.0", true, true);
    let metadata = release_metadata(temp.path(), "v0.2.0");
    let unit_dir = temp.path().join("home/.config/systemd/user");
    fs::create_dir_all(&unit_dir).expect("create unit dir");
    let service = unit_dir.join("adr-scan.service");
    let timer = unit_dir.join("adr-scan.timer");
    fs::write(&service, b"unchanged service\n").expect("service");
    fs::write(&timer, b"unchanged timer\n").expect("timer");
    let before_service = fs::read(&service).unwrap();
    let before_timer = fs::read(&timer).unwrap();
    let output = run_release(
        temp.path(),
        &metadata,
        temp.path(),
        None,
        &temp.path().join("bin"),
        &["--skip-checksum"],
    );
    assert_success(&output);
    assert_eq!(fs::read(service).unwrap(), before_service);
    assert_eq!(fs::read(timer).unwrap(), before_timer);
}

#[test]
fn checksum_verification_fails_when_no_hash_tool_is_available() {
    let temp = tempdir().expect("tempdir");
    let target = target();
    let name = format!("telltale-v0.2.0-{target}.tar.gz");
    let selected = archive(temp.path(), &name, "0.2.0", true, true);
    let metadata = release_metadata(temp.path(), "v0.2.0");
    let sums = temp.path().join("SHA256SUMS");
    checksum(&selected, &sums);
    let tools = fake_tools(temp.path());
    for name in [
        "awk", "bash", "cat", "cp", "grep", "install", "mkdir", "mktemp", "rm", "sed", "tar", "tr",
        "uname",
    ] {
        let source = [
            Path::new("/usr/bin").join(name),
            Path::new("/bin").join(name),
        ]
        .into_iter()
        .find(|path| path.is_file())
        .unwrap_or_else(|| panic!("missing test tool {name}"));
        symlink(source, tools.join(name)).expect("link test tool");
    }
    let mut command = installer_command(temp.path(), &metadata, temp.path(), Some(&sums), &tools);
    command
        .env("PATH", tools)
        .args(["--install-dir"])
        .arg(temp.path().join("bin"));
    let output = command.output().expect("run installer without hash tool");
    assert_failure(&output);
    assert!(output_text(&output).contains("Neither sha256sum nor shasum is available"));
}

#[test]
fn timer_requires_an_absolute_install_directory() {
    let temp = tempdir().expect("tempdir");
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join(SCRIPT);
    let output = Command::new("bash")
        .arg(script)
        .args(["--with-timer", "--install-dir", "relative-bin"])
        .env("HOME", temp.path().join("home"))
        .output()
        .expect("run relative timer installer");
    assert!(!output.status.success());
    assert!(output_text(&output).contains("requires an absolute --install-dir"));
}

#[test]
fn piped_bash_help_does_not_read_script_from_bash_zero() {
    let script = fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(SCRIPT))
        .expect("read installer script");
    let mut child = Command::new("bash")
        .args(["-s", "--", "--help"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn piped installer");
    child
        .stdin
        .as_mut()
        .expect("installer stdin")
        .write_all(script.as_bytes())
        .expect("pipe installer script");
    let output = child.wait_with_output().expect("wait for piped installer");
    assert_success(&output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Usage:"));
    assert!(stdout.contains("--from-source"));
    assert!(output.stderr.is_empty());
}
