#![cfg(target_os = "linux")]

use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::thread;
use std::time::Duration;

use tempfile::tempdir;

const SCRIPT: &str = "scripts/install-telltale";
const CANONICAL_ARCHIVE_MEMBERS: [&str; 9] = [
    "telltale",
    "LICENSE",
    "README.md",
    "config/examples/telltale-outputs.yaml",
    "config/examples/telltale-scan.service",
    "config/examples/telltale-scan.timer",
    "config/examples/telltale-scan-task.xml",
    "config/examples/elastic-telltale-index-template.json",
    "config/examples/elastic-telltale-role.json",
];

fn executable(path: &Path, contents: &str) {
    fs::write(path, contents).expect("write executable");
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).expect("make executable");
}

fn regular_file(path: &Path, contents: &[u8], mode: u32) {
    fs::write(path, contents).expect("write regular file");
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("set file mode");
}

fn telltale_binary(path: &Path, version: &str, report_adr_identity: bool) {
    let identity = if report_adr_identity {
        "adr"
    } else {
        "telltale"
    };
    executable(
        path,
        &format!(
            "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then printf '%s\\n' '{identity} {version} (synthetic)'; fi\nif [ -n \"${{FAKE_EVENT_LOG:-}}\" ]; then printf 'binary:%s:%s\\n' \"$0\" \"$*\" >> \"$FAKE_EVENT_LOG\"; fi\nif [ \"${{FAKE_REQUIRE_SMOKE_FIXTURE:-0}}\" = 1 ] && [ \"$1\" = \"scan\" ]; then smoke_root=''; previous=''; for arg in \"$@\"; do if [ \"$previous\" = --root ]; then smoke_root=$arg; fi; previous=$arg; done; [ -f \"$smoke_root/codex/sessions/2026/04/telltale-installer-smoke.jsonl\" ] || exit 77; fi\nif [ \"${{FAKE_REENABLE_DURING_SMOKE:-0}}\" = 1 ] && [ \"$1\" = \"scan\" ] && [ -n \"${{FAKE_SYSTEMCTL_STATE:-}}\" ]; then awk '$1 == \"telltale-scan.timer\" {{ $3=1; $4=1 }} {{ print }}' \"$FAKE_SYSTEMCTL_STATE\" > \"$FAKE_SYSTEMCTL_STATE.tmp\"; mv \"$FAKE_SYSTEMCTL_STATE.tmp\" \"$FAKE_SYSTEMCTL_STATE\"; fi\nif [ \"$1\" = \"migrate\" ] && [ -n \"${{FAKE_MIGRATION_LOG:-}}\" ]; then printf '%s|%s\\n' \"$0\" \"$*\" >> \"$FAKE_MIGRATION_LOG\"; fi\nexit 0\n"
        ),
    );
}

fn archive_with_members(
    root: &Path,
    name: &str,
    version: &str,
    members: &[&str],
    extra_member: Option<&str>,
) -> PathBuf {
    let payload = root.join(format!("payload-{name}"));
    fs::create_dir_all(&payload).expect("create archive payload");
    for member in members {
        let path = payload.join(member);
        fs::create_dir_all(path.parent().expect("archive member parent"))
            .expect("create archive member directory");
        if *member == "telltale" {
            telltale_binary(&path, version, false);
        } else {
            fs::write(path, b"canonical support member\n").expect("write archive member");
        }
    }
    if let Some(member) = extra_member {
        fs::create_dir_all(payload.join(Path::new(member).parent().unwrap_or(Path::new("."))))
            .expect("create extra archive directory");
        fs::write(payload.join(member), b"active legacy identity\n").expect("write extra member");
    }
    let archive = root.join(name);
    let mut command = Command::new("tar");
    command
        .args(["-czf"])
        .arg(&archive)
        .args(["-C", payload.to_str().unwrap()]);
    for member in members {
        command.arg(member);
    }
    if let Some(member) = extra_member {
        command.arg(member);
    }
    let output = command.output().expect("create archive");
    assert!(
        output.status.success(),
        "tar failed: {}",
        output_text(&output)
    );
    archive
}

fn archive(root: &Path, name: &str, version: &str, extra_member: Option<&str>) -> PathBuf {
    archive_with_members(
        root,
        name,
        version,
        &CANONICAL_ARCHIVE_MEMBERS,
        extra_member,
    )
}

fn archive_with_link_member(root: &Path, name: &str, version: &str, link_member: &str) -> PathBuf {
    let archive = archive(root, name, version, None);
    let payload = root.join(format!("payload-{name}"));
    fs::remove_file(payload.join(link_member)).expect("remove linked archive member");
    symlink("telltale", payload.join(link_member)).expect("create linked archive member");
    fs::remove_file(&archive).expect("replace linked archive");
    let mut command = Command::new("tar");
    command
        .args(["-czf"])
        .arg(&archive)
        .args(["-C", payload.to_str().unwrap()]);
    for member in CANONICAL_ARCHIVE_MEMBERS {
        command.arg(member);
    }
    let output = command.output().expect("create linked archive");
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
        .expect("checksum");
    assert!(output.status.success());
    let digest = String::from_utf8_lossy(&output.stdout)
        .split_whitespace()
        .next()
        .expect("digest")
        .to_owned();
    fs::write(
        sums,
        format!(
            "{digest}  {}\n",
            archive.file_name().unwrap().to_string_lossy()
        ),
    )
    .expect("write sums");
}

fn assert_archive_rejected(root: &Path, archive: &Path, message: &str) {
    let sums = root.join("SHA256SUMS");
    checksum(archive, &sums);
    let metadata = release_metadata(root, "v0.5.0");
    let output = run_release(root, &metadata, root, Some(&sums), &[]);
    assert!(!output.status.success(), "archive should be rejected");
    assert!(
        output_text(&output).contains(message),
        "expected {message:?}: {}",
        output_text(&output)
    );
    assert!(!root.join("home/bin/telltale").exists());
}

fn release_metadata(root: &Path, tag: &str) -> PathBuf {
    let path = root.join("release.json");
    fs::write(&path, format!("{{\"tag_name\":\"{tag}\"}}\n")).expect("metadata");
    path
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
        -o) output=$2; shift 2;;
        -*) shift;;
        *) url=$1; shift;;
    esac
done
printf '%s\n' "$url" >> "${FAKE_CURL_LOG:?}"
if [ -n "${FAKE_CURL_DELAY:-}" ]; then sleep "$FAKE_CURL_DELAY"; fi
case "$url" in
    */releases/latest) cat "$FAKE_CURL_METADATA";;
    */SHA256SUMS) cp "$FAKE_CURL_CHECKSUMS" "$output";;
    */*.tar.gz) cp "$FAKE_CURL_ASSET_DIR/${url##*/}" "$output";;
    *) exit 22;;
esac
"####,
    );
}

fn fail_partial_binary_copy(tools: &Path) {
    executable(
        &tools.join("install"),
        r####"#!/bin/sh
set -eu
real_install=/usr/bin/install
[ -x "$real_install" ] || real_install=/bin/install
source=''
destination=''
skip_next=0
for arg in "$@"; do
  if [ "$skip_next" = 1 ]; then skip_next=0; continue; fi
  case "$arg" in
    -m) skip_next=1;;
    -*) ;;
    *) source=$destination; destination=$arg;;
  esac
done
case "${FAKE_FAIL_INSTALL_COPY:-0}:$destination" in
  1:*/telltale.installing|unit-service:*/telltale-scan.service.installing|unit-timer:*/telltale-scan.timer.installing)
    dd if="$source" of="$destination" bs=1 count=1 2>/dev/null || true
    chmod 0755 "$destination"
    exit 1
    ;;
esac
exec "$real_install" "$@"
"####,
    );
}

fn reject_no_copy_mv(tools: &Path) {
    executable(
        &tools.join("mv"),
        r####"#!/bin/sh
case " $* " in
  *" --no-copy "*) exit 1;;
  *) exit 1;;
esac
"####,
    );
}

fn fake_systemctl(tools: &Path) {
    executable(
        &tools.join("systemctl"),
        r####"#!/bin/sh
set -eu
printf '%s\n' "$*" >> "${FAKE_SYSTEMCTL_LOG:?}"
if [ -n "${FAKE_EVENT_LOG:-}" ]; then printf 'systemctl:%s\n' "$*" >> "$FAKE_EVENT_LOG"; fi
config_root=${XDG_CONFIG_HOME:-$HOME/.config}
unit_dir=$config_root/systemd/user
state=${FAKE_SYSTEMCTL_STATE:?}
generated=${FAKE_GENERATED_UNIT:-}

init_state() {
  : > "$state"
  for unit in adr-scan.service adr-scan.timer telltale-scan.service telltale-scan.timer; do
    present=0
    [ -f "$unit_dir/$unit" ] && present=1
    [ "$unit" = "$generated" ] && present=1
    enabled=0
    active=0
    case "$unit" in
      adr-scan.timer)
        [ "${FAKE_OLD_ENABLED:-0}" = 1 ] && enabled=1
        [ "${FAKE_OLD_ACTIVE:-0}" = 1 ] && active=1
        [ "$enabled" = 1 ] || [ "$active" = 1 ] && present=1
        ;;
      telltale-scan.timer)
        [ "${FAKE_NEW_ENABLED:-0}" = 1 ] && enabled=1
        [ "${FAKE_NEW_ACTIVE:-0}" = 1 ] && active=1
        [ "$enabled" = 1 ] || [ "$active" = 1 ] && present=1
        ;;
    esac
    printf '%s %s %s %s\n' "$unit" "$present" "$enabled" "$active" >> "$state"
  done
}

refresh_present() {
  tmp="$state.tmp"
  while read -r unit present enabled active; do
    new_present=0
    [ -f "$unit_dir/$unit" ] && new_present=1
    [ "$unit" = "$generated" ] && new_present=1
    if [ "$new_present" = 0 ]; then enabled=0; active=0; fi
    printf '%s %s %s %s\n' "$unit" "$new_present" "$enabled" "$active"
  done < "$state" > "$tmp"
  mv "$tmp" "$state"
}

[ -f "$state" ] || init_state
command=${2:-}
case "$command" in
  show)
    unit=${3:?unit}
    property=''
    value_mode=0
    for arg in "$@"; do
      case "$arg" in
        --property=*) property=${arg#--property=};;
        --value) value_mode=1;;
      esac
    done
    if [ "${FAKE_SYSTEMCTL_FAIL_QUERY:-}" = "$property:$unit" ]; then exit 42; fi
    line=$(awk -v unit="$unit" '$1 == unit { print; exit }' "$state")
    present=$(printf '%s\n' "$line" | awk '{print $2}')
    enabled=$(printf '%s\n' "$line" | awk '{print $3}')
    active=$(printf '%s\n' "$line" | awk '{print $4}')
    if [ "$present" = 1 ]; then
      case "$property" in
        LoadState) printf 'loaded\n';;
        FragmentPath)
          if [ "$unit" = "$generated" ]; then
            printf '/run/systemd/generator/%s\n' "$unit"
          else
            printf '%s/%s\n' "$unit_dir" "$unit"
          fi
          ;;
        DropInPaths)
          dropin_paths=''
          if [ "${FAKE_DROP_IN_UNIT:-}" = "$unit" ]; then
            dropin_paths=${FAKE_DROP_IN_PATHS:-/run/user/1000/systemd/user/$unit.d/override.conf}
          fi
          if [ "$value_mode" = 1 ]; then
            printf '%s\n' "$dropin_paths"
          else
            printf 'DropInPaths=%s\n' "$dropin_paths"
          fi
          ;;
        UnitFileState) [ "$enabled" = 1 ] && printf 'enabled\n' || printf 'disabled\n';;
        ActiveState) [ "$active" = 1 ] && printf 'active\n' || printf 'inactive\n';;
        *) exit 1;;
      esac
    else
        case "$property" in
        LoadState) printf 'not-found\n';;
        FragmentPath) printf '\n';;
        DropInPaths)
          dropin_paths=''
          if [ "${FAKE_DROP_IN_UNIT:-}" = "$unit" ]; then
            dropin_paths=${FAKE_DROP_IN_PATHS:-/run/user/1000/systemd/user/$unit.d/override.conf}
          fi
          if [ "$value_mode" = 1 ]; then
            printf '%s\n' "$dropin_paths"
          else
            printf 'DropInPaths=%s\n' "$dropin_paths"
          fi
          ;;
        UnitFileState) printf 'bad\n';;
        ActiveState) printf 'inactive\n';;
        *) exit 1;;
      esac
    fi
    ;;
  daemon-reload)
    refresh_present
    ;;
  disable)
    unit=${3:?unit}
    if [ -n "${FAKE_REQUIRE_STAGE_DURING_QUIESCE:-}" ] && [ ! -d "$FAKE_REQUIRE_STAGE_DURING_QUIESCE" ]; then
      exit 43
    fi
    awk -v unit="$unit" '$1 == unit { $3=0 } { print }' "$state" > "$state.tmp"
    mv "$state.tmp" "$state"
    ;;
  stop)
    unit=${3:?unit}
    if [ -n "${FAKE_REQUIRE_STAGE_DURING_QUIESCE:-}" ] && [ ! -d "$FAKE_REQUIRE_STAGE_DURING_QUIESCE" ]; then
      exit 43
    fi
    awk -v unit="$unit" '$1 == unit { $4=0 } { print }' "$state" > "$state.tmp"
    mv "$state.tmp" "$state"
    ;;
  enable)
    if [ "${3:-}" = --now ]; then unit=${4:?unit}; else unit=${3:?unit}; fi
    awk -v unit="$unit" '$1 == unit { $3=1; $4=1 } { print }' "$state" > "$state.tmp"
    mv "$state.tmp" "$state"
    ;;
  *) exit 0;;
esac
"####,
    );
}

fn tools(root: &Path, with_systemctl: bool) -> PathBuf {
    let tools = root.join("tools");
    fs::create_dir_all(&tools).expect("tools");
    fake_curl(&tools);
    if with_systemctl {
        fake_systemctl(&tools);
    }
    tools
}

fn target() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "x86_64-unknown-linux-gnu",
        "aarch64" => "aarch64-unknown-linux-gnu",
        arch => panic!("unsupported Linux test architecture: {arch}"),
    }
}

fn installer_command(
    root: &Path,
    metadata: &Path,
    asset_dir: &Path,
    sums: Option<&Path>,
    tools: &Path,
) -> Command {
    fs::create_dir_all(root.join("home")).expect("test HOME");
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join(SCRIPT);
    let mut command = Command::new("bash");
    let path = format!("{}:{}", tools.display(), std::env::var("PATH").unwrap());
    command
        .arg(script)
        .env("HOME", root.join("home"))
        .env("PATH", path)
        .env("FAKE_CURL_METADATA", metadata)
        .env("FAKE_CURL_ASSET_DIR", asset_dir)
        .env("FAKE_CURL_LOG", root.join("curl.log"))
        .env("FAKE_SYSTEMCTL_LOG", root.join("systemctl.log"))
        .env("FAKE_SYSTEMCTL_STATE", root.join("systemctl.state"))
        .env("FAKE_EVENT_LOG", root.join("events.log"));
    if let Some(sums) = sums {
        command.env("FAKE_CURL_CHECKSUMS", sums);
    } else {
        command.env_remove("FAKE_CURL_CHECKSUMS");
    }
    command
}

fn piped_installer_command(
    root: &Path,
    metadata: &Path,
    asset_dir: &Path,
    sums: Option<&Path>,
    tools: &Path,
) -> Command {
    fs::create_dir_all(root.join("home")).expect("test HOME");
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join(SCRIPT);
    let mut command = Command::new("bash");
    let path = format!("{}:{}", tools.display(), std::env::var("PATH").unwrap());
    command
        .args([
            "-c",
            "cat \"$1\" | bash -s -- \"${@:2}\"",
            "piped-installer",
        ])
        .arg(script)
        .env("HOME", root.join("home"))
        .env("PATH", path)
        .env("FAKE_CURL_METADATA", metadata)
        .env("FAKE_CURL_ASSET_DIR", asset_dir)
        .env("FAKE_CURL_LOG", root.join("curl.log"))
        .env("FAKE_SYSTEMCTL_LOG", root.join("systemctl.log"))
        .env("FAKE_SYSTEMCTL_STATE", root.join("systemctl.state"))
        .env("FAKE_EVENT_LOG", root.join("events.log"));
    if let Some(sums) = sums {
        command.env("FAKE_CURL_CHECKSUMS", sums);
    } else {
        command.env_remove("FAKE_CURL_CHECKSUMS");
    }
    command
}

fn run_release(
    root: &Path,
    metadata: &Path,
    asset_dir: &Path,
    sums: Option<&Path>,
    args: &[&str],
) -> Output {
    let tools = tools(root, true);
    let install_dir = root.join("home/bin");
    let mut command = installer_command(root, metadata, asset_dir, sums, &tools);
    command
        .args(args)
        .args(["--install-dir", install_dir.to_str().unwrap()]);
    command.output().expect("run installer")
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

#[test]
fn installer_script_is_executable() {
    let mode = fs::metadata(Path::new(env!("CARGO_MANIFEST_DIR")).join(SCRIPT))
        .expect("installer metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o755);
}

#[test]
fn installer_requires_no_copy_no_replace_capability_before_installation() {
    let temp = tempdir().unwrap();
    let metadata = release_metadata(temp.path(), "v0.5.0");
    let tools = tools(temp.path(), false);
    reject_no_copy_mv(&tools);
    let home = temp.path().join("home");
    let mut command = installer_command(temp.path(), &metadata, temp.path(), None, &tools);
    command.args([
        "--no-timer",
        "--install-dir",
        home.join("bin").to_str().unwrap(),
    ]);
    let output = command.output().unwrap();
    assert!(!output.status.success());
    assert!(output_text(&output).contains("--no-copy"));
    assert!(home.join(".telltale-installer.lock").is_dir());
    assert!(!home.join(".local").exists());
    assert!(!home.join("bin").exists());
}

#[test]
fn fresh_install_is_canonical_and_journaled() {
    let temp = tempdir().unwrap();
    let name = format!("telltale-v0.5.0-{}.tar.gz", target());
    let selected = archive(temp.path(), &name, "0.5.0", None);
    let metadata = release_metadata(temp.path(), "v0.5.0");
    let sums = temp.path().join("SHA256SUMS");
    checksum(&selected, &sums);

    let tools = tools(temp.path(), true);
    let mut command = installer_command(temp.path(), &metadata, temp.path(), Some(&sums), &tools);
    command.env("ADR_THIRD_PARTY_EXTENSION", "allowed").args([
        "--no-timer",
        "--install-dir",
        temp.path().join("home/bin").to_str().unwrap(),
    ]);
    let output = command.output().unwrap();
    assert_success(&output);
    let install = temp.path().join("home/bin");
    assert!(install.join("telltale").is_file());
    assert_eq!(
        fs::metadata(install.join("telltale"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o755
    );
    assert!(!install.join("adr").exists());
    let units = temp.path().join("home/.config/systemd/user");
    assert!(units.join("telltale-scan.service").is_file());
    assert!(units.join("telltale-scan.timer").is_file());
    let systemctl_state = fs::read_to_string(temp.path().join("systemctl.state")).unwrap();
    assert!(systemctl_state.contains("telltale-scan.service 1 0 0"));
    assert!(systemctl_state.contains("telltale-scan.timer 1 0 0"));
    assert!(
        fs::read_to_string(
            temp.path()
                .join("home/.local/state/telltale/installer-transaction.json")
        )
        .unwrap()
        .contains("committed")
    );
}

#[test]
fn piped_install_uses_deterministic_synthetic_smoke_fixture() {
    let temp = tempdir().unwrap();
    let name = format!("telltale-v0.5.0-{}.tar.gz", target());
    let selected = archive(temp.path(), &name, "0.5.0", None);
    let metadata = release_metadata(temp.path(), "v0.5.0");
    let sums = temp.path().join("SHA256SUMS");
    checksum(&selected, &sums);
    let tools = tools(temp.path(), true);
    let install = temp.path().join("home/bin");
    let mut command =
        piped_installer_command(temp.path(), &metadata, temp.path(), Some(&sums), &tools);
    command.env("FAKE_REQUIRE_SMOKE_FIXTURE", "1").args([
        "--no-timer",
        "--install-dir",
        install.to_str().unwrap(),
    ]);
    let output = command.output().unwrap();
    assert_success(&output);
    assert!(output_text(&output).contains("deterministic synthetic fixture"));
    assert!(install.join("telltale").is_file());
}

#[test]
fn inherited_retired_runtime_environment_blocks_install_without_reading_value() {
    let temp = tempdir().unwrap();
    let metadata = release_metadata(temp.path(), "v0.5.0");
    let tools = tools(temp.path(), true);
    let install = temp.path().join("home/bin");
    let mut command = installer_command(temp.path(), &metadata, temp.path(), None, &tools);
    command
        .env("ADR_LOG_PATH", "retired-secret-canary")
        .env("ADR_THIRD_PARTY_EXTENSION", "allowed")
        .args(["--no-timer", "--install-dir", install.to_str().unwrap()]);
    let output = command.output().unwrap();
    assert!(!output.status.success());
    let text = output_text(&output);
    assert!(text.contains("retired runtime environment variables are inherited"));
    assert!(text.contains("ADR_LOG_PATH"));
    assert!(!text.contains("retired-secret-canary"));
    assert!(!install.exists());
    assert!(!temp.path().join("home/.local").exists());
    assert!(!temp.path().join("events.log").exists());
}

#[test]
fn checksum_failure_and_active_adr_archive_are_fail_closed() {
    let temp = tempdir().unwrap();
    let name = format!("telltale-v0.5.0-{}.tar.gz", target());
    let _selected = archive(temp.path(), &name, "0.5.0", None);
    let metadata = release_metadata(temp.path(), "v0.5.0");
    let output = run_release(temp.path(), &metadata, temp.path(), None, &[]);
    assert!(!output.status.success());
    assert!(output_text(&output).contains("SHA256SUMS"));
    assert!(!temp.path().join("home/bin/telltale").exists());

    let bad = archive(
        temp.path(),
        &name,
        "0.5.0",
        Some("config/examples/adr-scan.service"),
    );
    let bad_sums = temp.path().join("bad-SHA256SUMS");
    checksum(&bad, &bad_sums);
    let bad_metadata = release_metadata(temp.path(), "v0.5.0");
    let output = run_release(
        temp.path(),
        &bad_metadata,
        temp.path(),
        Some(&bad_sums),
        &[],
    );
    assert!(!output.status.success());
    assert!(output_text(&output).contains("active ADR technical identity"));
}

#[test]
fn installer_requires_exact_canonical_archive_bundle() {
    let missing = tempdir().unwrap();
    let name = format!("telltale-v0.5.0-{}.tar.gz", target());
    let missing_archive = archive_with_members(
        missing.path(),
        &name,
        "0.5.0",
        &CANONICAL_ARCHIVE_MEMBERS[..8],
        None,
    );
    assert_archive_rejected(
        missing.path(),
        &missing_archive,
        "exact canonical nine-member bundle",
    );

    let extra = tempdir().unwrap();
    let extra_archive = archive(
        extra.path(),
        &name,
        "0.5.0",
        Some("config/examples/unexpected.txt"),
    );
    assert_archive_rejected(
        extra.path(),
        &extra_archive,
        "exact canonical nine-member bundle",
    );

    let duplicate = tempdir().unwrap();
    let mut duplicate_members = CANONICAL_ARCHIVE_MEMBERS.to_vec();
    duplicate_members.push("telltale");
    let duplicate_archive =
        archive_with_members(duplicate.path(), &name, "0.5.0", &duplicate_members, None);
    assert_archive_rejected(duplicate.path(), &duplicate_archive, "duplicate member");

    let traversal = tempdir().unwrap();
    let traversal_archive = archive(traversal.path(), &name, "0.5.0", Some("../escape.txt"));
    let sums = traversal.path().join("SHA256SUMS");
    checksum(&traversal_archive, &sums);
    let metadata = release_metadata(traversal.path(), "v0.5.0");
    let output = run_release(
        traversal.path(),
        &metadata,
        traversal.path(),
        Some(&sums),
        &[],
    );
    assert!(!output.status.success());
    let text = output_text(&output);
    assert!(
        text.contains("path traversal") || text.contains("exact canonical nine-member bundle"),
        "unexpected traversal rejection: {text}"
    );
    assert!(!traversal.path().join("home/bin/telltale").exists());

    let link = tempdir().unwrap();
    let archive = archive_with_link_member(
        link.path(),
        &name,
        "0.5.0",
        "config/examples/telltale-scan.timer",
    );
    assert_archive_rejected(link.path(), &archive, "non-regular member");

    let wrong_binary = tempdir().unwrap();
    let mut wrong_binary_members = CANONICAL_ARCHIVE_MEMBERS[1..].to_vec();
    wrong_binary_members.insert(0, "telltale.exe");
    let archive = archive_with_members(
        wrong_binary.path(),
        &name,
        "0.5.0",
        &wrong_binary_members,
        None,
    );
    assert_archive_rejected(
        wrong_binary.path(),
        &archive,
        "exact canonical nine-member bundle",
    );
}

#[test]
fn source_build_is_pinned_and_does_not_produce_retired_binary() {
    let temp = tempdir().unwrap();
    let metadata = release_metadata(temp.path(), "v0.5.0");
    let tools = tools(temp.path(), true);
    let cargo_log = temp.path().join("cargo.log");
    executable(
        &tools.join("cargo"),
        &format!(
            "#!/bin/sh\nprintf '%s\\n' \"$*\" > '{}'\nroot=''\nwhile [ $# -gt 0 ]; do if [ \"$1\" = \"--root\" ]; then root=$2; shift 2; else shift; fi; done\nmkdir -p \"$root/bin\"\nprintf '#!/bin/sh\\nprintf \\\"telltale 0.5.0 (synthetic)\\\\n\\\"\\n' > \"$root/bin/telltale\"\nchmod 755 \"$root/bin/telltale\"\n",
            cargo_log.display()
        ),
    );
    let mut command = installer_command(temp.path(), &metadata, temp.path(), None, &tools);
    command.args([
        "--from-source",
        "--install-dir",
        temp.path().join("home/bin").to_str().unwrap(),
    ]);
    let output = command.output().unwrap();
    assert_success(&output);
    let args = fs::read_to_string(cargo_log).unwrap();
    assert!(
        args.contains("--tag v0.5.0")
            && args.contains("--locked")
            && args.contains("--bin telltale")
    );
    assert!(!temp.path().join("home/bin/adr").exists());
}

#[test]
fn upgrade_migrates_before_activation_and_installs_one_canonical_schedule() {
    let temp = tempdir().unwrap();
    let name = format!("telltale-v0.5.0-{}.tar.gz", target());
    let selected = archive(temp.path(), &name, "0.5.0", None);
    let metadata = release_metadata(temp.path(), "v0.5.0");
    let sums = temp.path().join("SHA256SUMS");
    checksum(&selected, &sums);
    let state = temp.path().join("home/.local/state/telltale");
    let config = temp.path().join("home/.config/telltale");
    let units = temp.path().join("home/.config/systemd/user");
    fs::create_dir_all(state.join("logs")).unwrap();
    fs::create_dir_all(&config).unwrap();
    fs::create_dir_all(&units).unwrap();
    regular_file(&state.join("adr-state.json"), b"legacy state", 0o600);
    regular_file(
        &state.join("logs/adr-events.jsonl"),
        b"legacy events\n",
        0o640,
    );
    regular_file(&config.join("adr.env"), b"ADR_LOG_PATH=/old\n", 0o600);
    fs::create_dir_all(temp.path().join("home/bin")).unwrap();
    telltale_binary(&temp.path().join("home/bin/adr"), "0.3.0", true);
    regular_file(&units.join("adr-scan.service"), b"old service\n", 0o644);
    regular_file(&units.join("adr-scan.timer"), b"old timer\n", 0o644);
    let tools = tools(temp.path(), true);
    let migration_log = temp.path().join("migrations.log");
    let mut command = installer_command(temp.path(), &metadata, temp.path(), Some(&sums), &tools);
    command
        .env("FAKE_MIGRATION_LOG", &migration_log)
        .env("FAKE_OLD_ENABLED", "1")
        .env("FAKE_OLD_ACTIVE", "1")
        .args([
            "--with-timer",
            "--install-dir",
            temp.path().join("home/bin").to_str().unwrap(),
        ]);
    let output = command.output().unwrap();
    assert_success(&output);
    let migrations = fs::read_to_string(&migration_log).unwrap();
    assert!(migrations.contains("migrate state --from"));
    assert!(migrations.contains("migrate events --pair"));
    assert!(migrations.contains("migrate env --from"));
    let service = fs::read_to_string(units.join("telltale-scan.service")).unwrap();
    assert!(service.contains("TELLTALE_LOG_PATH") && service.contains("telltale-events.jsonl"));
    assert!(service.contains("TELLTALE_STATE_PATH") && service.contains("telltale-state.json"));
    assert!(service.contains("telltale/telltale.env"));
    assert!(service.contains("--root \"${TELLTALE_SCAN_ROOT}\""));
    assert!(!service.contains("ExecStart=:"));
    let timer = fs::read_to_string(units.join("telltale-scan.timer")).unwrap();
    assert!(timer.contains("OnActiveSec=1min"));
    assert!(!timer.contains("OnBootSec="));
    assert!(timer.contains("OnUnitActiveSec=5min"));
    assert!(timer.contains("Unit=telltale-scan.service"));
    assert!(!units.join("adr-scan.timer").exists());
    assert!(!temp.path().join("home/bin/adr").exists());
    let calls = fs::read_to_string(temp.path().join("systemctl.log")).unwrap();
    assert!(
        calls.contains("disable adr-scan.timer")
            && calls.contains("enable --now telltale-scan.timer")
    );
    let events = fs::read_to_string(temp.path().join("events.log")).unwrap();
    let quiesce = events
        .find("systemctl:--user disable adr-scan.timer")
        .expect("old timer disable event");
    let candidate_version = events
        .find("telltale.new:--version")
        .expect("staged candidate version probe");
    let migration = events
        .find("migrate state")
        .expect("staged migration event");
    let reload_after_migration = events[migration..]
        .find("systemctl:--user daemon-reload")
        .map(|offset| migration + offset)
        .expect("post-install daemon reload event");
    let enable = events
        .find("systemctl:--user enable --now telltale-scan.timer")
        .expect("canonical timer enable event");
    assert!(
        quiesce < migration
            && quiesce < candidate_version
            && candidate_version < migration
            && migration < reload_after_migration
            && reload_after_migration < enable
    );
    let migration_line = fs::read_to_string(migration_log).unwrap();
    assert!(
        migration_line.contains(".telltale-install.") && migration_line.contains("telltale.new")
    );
}

#[test]
fn duplicate_schedule_conflict_leaves_both_disabled_and_rolls_back_binary() {
    let temp = tempdir().unwrap();
    let name = format!("telltale-v0.5.0-{}.tar.gz", target());
    let selected = archive(temp.path(), &name, "0.5.0", None);
    let metadata = release_metadata(temp.path(), "v0.5.0");
    let sums = temp.path().join("SHA256SUMS");
    checksum(&selected, &sums);
    let install = temp.path().join("home/bin");
    let units = temp.path().join("home/.config/systemd/user");
    fs::create_dir_all(&install).unwrap();
    fs::create_dir_all(&units).unwrap();
    regular_file(&install.join("telltale"), b"old bytes", 0o755);
    regular_file(&units.join("adr-scan.service"), b"old service\n", 0o644);
    regular_file(&units.join("adr-scan.timer"), b"old timer\n", 0o644);
    regular_file(
        &units.join("telltale-scan.service"),
        b"new service\n",
        0o644,
    );
    regular_file(&units.join("telltale-scan.timer"), b"new timer\n", 0o644);
    let mut command = installer_command(
        temp.path(),
        &metadata,
        temp.path(),
        Some(&sums),
        &tools(temp.path(), true),
    );
    command
        .env("FAKE_OLD_ENABLED", "1")
        .env("FAKE_NEW_ENABLED", "1")
        .args(["--with-timer", "--install-dir", install.to_str().unwrap()]);
    let output = command.output().unwrap();
    assert!(!output.status.success());
    assert!(output_text(&output).contains("duplicate old/new schedules"));
    assert_eq!(fs::read(install.join("telltale")).unwrap(), b"old bytes");
    let calls = fs::read_to_string(temp.path().join("systemctl.log")).unwrap();
    assert!(!calls.contains("enable --now telltale-scan.timer"));
}

#[test]
fn scope_symlink_and_unidentified_binary_checks_fail_closed() {
    let temp = tempdir().unwrap();
    let metadata = release_metadata(temp.path(), "v0.5.0");
    let outside = temp.path().join("outside");
    fs::create_dir_all(&outside).unwrap();
    let output = {
        let tools = tools(temp.path(), false);
        let mut command = installer_command(temp.path(), &metadata, temp.path(), None, &tools);
        command.args(["--install-dir", outside.to_str().unwrap()]);
        command.output().unwrap()
    };
    assert!(!output.status.success());
    assert!(output_text(&output).contains("unmanaged or system install scope"));

    let install = temp.path().join("home/bin");
    fs::create_dir_all(&install).unwrap();
    symlink("/tmp", install.join("telltale")).unwrap();
    let name = format!("telltale-v0.5.0-{}.tar.gz", target());
    let selected = archive(temp.path(), &name, "0.5.0", None);
    let sums = temp.path().join("SHA256SUMS");
    checksum(&selected, &sums);
    let output = run_release(temp.path(), &metadata, temp.path(), Some(&sums), &[]);
    assert!(!output.status.success());
    assert!(output_text(&output).contains("refusing symlink path"));

    let mode_temp = tempdir().unwrap();
    let mode_metadata = release_metadata(mode_temp.path(), "v0.5.0");
    let mode_tools = tools(mode_temp.path(), false);
    let mut mode_command = installer_command(
        mode_temp.path(),
        &mode_metadata,
        mode_temp.path(),
        None,
        &mode_tools,
    );
    fs::set_permissions(
        mode_temp.path().join("home"),
        fs::Permissions::from_mode(0o777),
    )
    .unwrap();
    mode_command.args([
        "--install-dir",
        mode_temp.path().join("home/bin").to_str().unwrap(),
    ]);
    let output = mode_command.output().unwrap();
    assert!(!output.status.success());
    assert!(output_text(&output).contains("HOME has unsafe type, mode, or link count"));
}

#[test]
fn installer_lock_has_bounded_busy_failure() {
    let temp = tempdir().unwrap();
    let home = temp.path().join("home");
    fs::create_dir_all(&home).unwrap();
    let lock = home.join(".telltale-installer.lock");
    fs::create_dir(&lock).unwrap();
    fs::set_permissions(&lock, fs::Permissions::from_mode(0o700)).unwrap();
    let holder = Command::new("flock")
        .args(["-x", lock.to_str().unwrap(), "-c", "sleep 2"])
        .spawn()
        .unwrap();
    thread::sleep(Duration::from_millis(100));
    let metadata = release_metadata(temp.path(), "v0.5.0");
    let output = {
        let tools = tools(temp.path(), false);
        let mut command = installer_command(temp.path(), &metadata, temp.path(), None, &tools);
        command.args(["--install-dir", home.join("bin").to_str().unwrap()]);
        command.output().unwrap()
    };
    assert!(!output.status.success());
    assert!(output_text(&output).contains("installer busy"));
    let _ = holder.wait_with_output();
}

#[test]
fn installer_lock_is_shared_across_different_xdg_state_roots() {
    let temp = tempdir().unwrap();
    let name = format!("telltale-v0.5.0-{}.tar.gz", target());
    let selected = archive(temp.path(), &name, "0.5.0", None);
    let metadata = release_metadata(temp.path(), "v0.5.0");
    let sums = temp.path().join("SHA256SUMS");
    checksum(&selected, &sums);
    let tools = tools(temp.path(), true);
    let state_a = temp.path().join("home/state-a");
    let state_b = temp.path().join("home/state-b");
    let install_a = temp.path().join("home/bin-a");
    let install_b = temp.path().join("home/bin-b");

    let mut holder = installer_command(temp.path(), &metadata, temp.path(), Some(&sums), &tools);
    holder
        .env("XDG_STATE_HOME", &state_a)
        .env("FAKE_CURL_DELAY", "1")
        .args(["--no-timer", "--install-dir", install_a.to_str().unwrap()]);
    let mut holder = holder.spawn().expect("spawn installer lock holder");

    let curl_log = temp.path().join("curl.log");
    let mut holder_ready = false;
    for _ in 0..250 {
        if fs::read_to_string(&curl_log).is_ok_and(|log| !log.trim().is_empty()) {
            holder_ready = true;
            break;
        }
        if holder.try_wait().unwrap().is_some() {
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }
    assert!(
        holder_ready,
        "first installer did not reach its locked network phase"
    );

    let mut second = installer_command(temp.path(), &metadata, temp.path(), Some(&sums), &tools);
    second.env("XDG_STATE_HOME", &state_b).args([
        "--no-timer",
        "--install-dir",
        install_b.to_str().unwrap(),
    ]);
    let output = second.output().expect("run second installer");
    assert!(!output.status.success());
    assert!(output_text(&output).contains("installer busy"));
    assert!(
        !state_b.exists(),
        "contended install must not create its XDG state root"
    );
    assert!(
        !install_b.exists(),
        "contended install must not create its install directory"
    );

    let holder_output = holder.wait_with_output().expect("wait for lock holder");
    assert_success(&holder_output);
}

#[test]
fn unsafe_preexisting_installer_lock_fails_closed_before_directory_creation() {
    let temp = tempdir().unwrap();
    let home = temp.path().join("home");
    fs::create_dir_all(&home).unwrap();
    let lock = home.join(".telltale-installer.lock");
    regular_file(&lock, b"regular file, not a lock directory\n", 0o700);
    let metadata = release_metadata(temp.path(), "v0.5.0");
    let mut command = installer_command(
        temp.path(),
        &metadata,
        temp.path(),
        None,
        &tools(temp.path(), false),
    );
    command.args([
        "--no-timer",
        "--install-dir",
        temp.path().join("home/bin").to_str().unwrap(),
    ]);
    let output = command.output().expect("run unsafe-lock installer");
    assert!(!output.status.success());
    assert!(output_text(&output).contains("unsafe installer lock path"));
    assert!(!home.join(".local").exists());
    assert!(!home.join("bin").exists());
}

#[test]
fn installer_lock_reuses_safe_directory_and_rejects_symlink_or_unsafe_directory() {
    let preserved = tempdir().unwrap();
    let name = format!("telltale-v0.5.0-{}.tar.gz", target());
    let selected = archive(preserved.path(), &name, "0.5.0", None);
    let metadata = release_metadata(preserved.path(), "v0.5.0");
    let sums = preserved.path().join("SHA256SUMS");
    checksum(&selected, &sums);
    let home = preserved.path().join("home");
    fs::create_dir_all(&home).unwrap();
    let lock = home.join(".telltale-installer.lock");
    fs::create_dir(&lock).unwrap();
    fs::set_permissions(&lock, fs::Permissions::from_mode(0o700)).unwrap();
    let output = run_release(
        preserved.path(),
        &metadata,
        preserved.path(),
        Some(&sums),
        &[],
    );
    assert_success(&output);
    assert!(
        lock.is_dir(),
        "the permanent lock sidecar must remain a directory"
    );
    assert_eq!(
        fs::metadata(lock).unwrap().permissions().mode() & 0o777,
        0o700
    );

    let symlinked = tempdir().unwrap();
    let symlink_home = symlinked.path().join("home");
    fs::create_dir_all(&symlink_home).unwrap();
    regular_file(&symlink_home.join("lock-target"), b"lock target\n", 0o600);
    symlink("lock-target", symlink_home.join(".telltale-installer.lock")).unwrap();
    let symlink_metadata = release_metadata(symlinked.path(), "v0.5.0");
    let mut symlink_command = installer_command(
        symlinked.path(),
        &symlink_metadata,
        symlinked.path(),
        None,
        &tools(symlinked.path(), false),
    );
    symlink_command.args([
        "--no-timer",
        "--install-dir",
        symlink_home.join("bin").to_str().unwrap(),
    ]);
    let output = symlink_command.output().unwrap();
    assert!(!output.status.success());
    assert!(output_text(&output).contains("unsafe installer lock path"));
    assert!(!symlink_home.join("bin").exists());

    let unsafe_directory = tempdir().unwrap();
    let unsafe_home = unsafe_directory.path().join("home");
    fs::create_dir_all(&unsafe_home).unwrap();
    fs::create_dir(unsafe_home.join(".telltale-installer.lock")).unwrap();
    fs::set_permissions(
        unsafe_home.join(".telltale-installer.lock"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    let unsafe_metadata = release_metadata(unsafe_directory.path(), "v0.5.0");
    let mut unsafe_command = installer_command(
        unsafe_directory.path(),
        &unsafe_metadata,
        unsafe_directory.path(),
        None,
        &tools(unsafe_directory.path(), false),
    );
    unsafe_command.args([
        "--no-timer",
        "--install-dir",
        unsafe_home.join("bin").to_str().unwrap(),
    ]);
    let output = unsafe_command.output().unwrap();
    assert!(!output.status.success());
    assert!(output_text(&output).contains("unsafe installer lock path"));
    assert!(!unsafe_home.join("bin").exists());
}

#[test]
fn no_timer_quiesces_legacy_schedule_before_removing_adr() {
    let temp = tempdir().unwrap();
    let name = format!("telltale-v0.5.0-{}.tar.gz", target());
    let selected = archive(temp.path(), &name, "0.5.0", None);
    let metadata = release_metadata(temp.path(), "v0.5.0");
    let sums = temp.path().join("SHA256SUMS");
    checksum(&selected, &sums);
    let install = temp.path().join("home/bin");
    let units = temp.path().join("home/.config/systemd/user");
    fs::create_dir_all(&install).unwrap();
    fs::create_dir_all(&units).unwrap();
    telltale_binary(&install.join("adr"), "0.3.0", true);
    regular_file(&units.join("adr-scan.service"), b"old service\n", 0o644);
    regular_file(&units.join("adr-scan.timer"), b"old timer\n", 0o644);

    let mut command = installer_command(
        temp.path(),
        &metadata,
        temp.path(),
        Some(&sums),
        &tools(temp.path(), true),
    );
    command
        .env("FAKE_OLD_ENABLED", "1")
        .env("FAKE_OLD_ACTIVE", "1")
        .args(["--no-timer", "--install-dir", install.to_str().unwrap()]);
    let output = command.output().unwrap();
    assert_success(&output);
    assert!(!install.join("adr").exists());
    assert!(!units.join("adr-scan.service").exists());
    assert!(!units.join("adr-scan.timer").exists());
    assert!(units.join("telltale-scan.service").is_file());
    assert!(units.join("telltale-scan.timer").is_file());
    let systemctl_state = fs::read_to_string(temp.path().join("systemctl.state")).unwrap();
    assert!(systemctl_state.contains("telltale-scan.service 1 0 0"));
    assert!(systemctl_state.contains("telltale-scan.timer 1 0 0"));

    let events = fs::read_to_string(temp.path().join("events.log")).unwrap();
    let disable = events
        .find("systemctl:--user disable adr-scan.timer")
        .expect("legacy timer disable event");
    let probe = events
        .find(&format!(
            "binary:{}:--version",
            install.join("adr").display()
        ))
        .expect("bounded legacy binary probe");
    assert!(
        disable < probe,
        "legacy binary was probed before schedule quiescing: {events}"
    );
    assert!(!events.contains("enable --now telltale-scan.timer"));
}

#[test]
fn no_timer_query_failure_does_not_assume_schedules_are_absent() {
    let temp = tempdir().unwrap();
    let name = format!("telltale-v0.5.0-{}.tar.gz", target());
    let selected = archive(temp.path(), &name, "0.5.0", None);
    let metadata = release_metadata(temp.path(), "v0.5.0");
    let sums = temp.path().join("SHA256SUMS");
    checksum(&selected, &sums);
    let install = temp.path().join("home/bin");
    let tools = tools(temp.path(), true);
    let mut command = installer_command(temp.path(), &metadata, temp.path(), Some(&sums), &tools);
    command
        .env("FAKE_SYSTEMCTL_FAIL_QUERY", "LoadState:telltale-scan.timer")
        .args(["--no-timer", "--install-dir", install.to_str().unwrap()]);
    let output = command.output().unwrap();
    assert!(!output.status.success());
    assert!(output_text(&output).contains("could not safely query systemd state"));
    assert!(!install.join("telltale").exists());
}

#[test]
fn no_timer_final_schedule_proof_rejects_candidate_reenable() {
    let temp = tempdir().unwrap();
    let name = format!("telltale-v0.5.0-{}.tar.gz", target());
    let selected = archive(temp.path(), &name, "0.5.0", None);
    let metadata = release_metadata(temp.path(), "v0.5.0");
    let sums = temp.path().join("SHA256SUMS");
    checksum(&selected, &sums);
    let install = temp.path().join("home/bin");
    let mut command = installer_command(
        temp.path(),
        &metadata,
        temp.path(),
        Some(&sums),
        &tools(temp.path(), true),
    );
    command.env("FAKE_REENABLE_DURING_SMOKE", "1").args([
        "--no-timer",
        "--install-dir",
        install.to_str().unwrap(),
    ]);
    let output = command.output().unwrap();
    assert!(!output.status.success());
    assert!(output_text(&output).contains("final all-schedules-disabled postcondition"));
    assert!(!install.join("telltale").exists());
    assert!(
        fs::read_to_string(
            temp.path()
                .join("home/.local/state/telltale/installer-transaction.json")
        )
        .unwrap()
        .contains("\"phase\": \"failed\"")
    );
}

#[test]
fn loaded_generated_unit_without_owned_local_file_fails_closed() {
    let temp = tempdir().unwrap();
    let name = format!("telltale-v0.5.0-{}.tar.gz", target());
    let selected = archive(temp.path(), &name, "0.5.0", None);
    let metadata = release_metadata(temp.path(), "v0.5.0");
    let sums = temp.path().join("SHA256SUMS");
    checksum(&selected, &sums);
    let install = temp.path().join("home/bin");
    let tools = tools(temp.path(), true);
    let mut command = installer_command(temp.path(), &metadata, temp.path(), Some(&sums), &tools);
    command
        .env("FAKE_GENERATED_UNIT", "telltale-scan.timer")
        .args(["--no-timer", "--install-dir", install.to_str().unwrap()]);
    let output = command.output().unwrap();
    assert!(!output.status.success());
    assert!(output_text(&output).contains("could not safely query systemd state"));
    assert!(!install.join("telltale").exists());
}

#[test]
fn all_known_unit_dropins_are_rejected_without_staging_legacy_units() {
    for unit in [
        "adr-scan.service",
        "adr-scan.timer",
        "telltale-scan.service",
        "telltale-scan.timer",
    ] {
        let temp = tempdir().unwrap();
        let name = format!("telltale-v0.5.0-{}.tar.gz", target());
        let selected = archive(temp.path(), &name, "0.5.0", None);
        let metadata = release_metadata(temp.path(), "v0.5.0");
        let sums = temp.path().join("SHA256SUMS");
        checksum(&selected, &sums);
        let units = temp.path().join("home/.config/systemd/user");
        fs::create_dir_all(&units).unwrap();
        regular_file(&units.join(unit), b"existing canonical unit\n", 0o644);
        let tools = tools(temp.path(), true);
        let mut command =
            installer_command(temp.path(), &metadata, temp.path(), Some(&sums), &tools);
        command.env("FAKE_DROP_IN_UNIT", unit).args([
            "--no-timer",
            "--install-dir",
            temp.path().join("home/bin").to_str().unwrap(),
        ]);
        let output = command.output().unwrap();
        assert!(
            !output.status.success(),
            "drop-in metadata must be rejected for {unit}"
        );
        assert!(output_text(&output).contains("could not safely query systemd state"));
        assert!(units.join(unit).is_file());
        assert!(!temp.path().join("home/bin/telltale").exists());
    }

    for unit in [
        "adr-scan.service",
        "adr-scan.timer",
        "telltale-scan.service",
        "telltale-scan.timer",
    ] {
        let temp = tempdir().unwrap();
        let name = format!("telltale-v0.5.0-{}.tar.gz", target());
        let selected = archive(temp.path(), &name, "0.5.0", None);
        let metadata = release_metadata(temp.path(), "v0.5.0");
        let sums = temp.path().join("SHA256SUMS");
        checksum(&selected, &sums);
        let units = temp.path().join("home/.config/systemd/user");
        fs::create_dir_all(&units).unwrap();
        regular_file(&units.join(unit), b"legacy unit\n", 0o644);
        let dropin = units.join(format!("{unit}.d/override.conf"));
        fs::create_dir_all(dropin.parent().unwrap()).unwrap();
        regular_file(&dropin, b"[Unit]\nDescription=legacy drop-in\n", 0o644);
        let output = run_release(
            temp.path(),
            &metadata,
            temp.path(),
            Some(&sums),
            &[
                "--no-timer",
                "--install-dir",
                temp.path().join("home/bin").to_str().unwrap(),
            ],
        );
        assert!(
            !output.status.success(),
            "local drop-in must be rejected for {unit}"
        );
        assert!(output_text(&output).contains("could not safely query systemd state"));
        assert_eq!(fs::read(units.join(unit)).unwrap(), b"legacy unit\n");
        assert_eq!(
            fs::read(dropin).unwrap(),
            b"[Unit]\nDescription=legacy drop-in\n"
        );
        assert!(!temp.path().join("home/bin/telltale").exists());
    }
}

#[test]
fn not_found_unit_system_dropins_are_checked_for_all_known_units() {
    for unit in [
        "adr-scan.service",
        "adr-scan.timer",
        "telltale-scan.service",
        "telltale-scan.timer",
    ] {
        let temp = tempdir().unwrap();
        let name = format!("telltale-v0.5.0-{}.tar.gz", target());
        let selected = archive(temp.path(), &name, "0.5.0", None);
        let metadata = release_metadata(temp.path(), "v0.5.0");
        let sums = temp.path().join("SHA256SUMS");
        checksum(&selected, &sums);
        let tools = tools(temp.path(), true);
        let install = temp.path().join("home/bin");
        let mut command =
            installer_command(temp.path(), &metadata, temp.path(), Some(&sums), &tools);
        command.env("FAKE_DROP_IN_UNIT", unit).args([
            "--no-timer",
            "--install-dir",
            install.to_str().unwrap(),
        ]);
        let output = command.output().unwrap();
        assert!(
            !output.status.success(),
            "not-found system drop-in must be rejected for {unit}"
        );
        assert!(output_text(&output).contains("could not safely query systemd state"));
        assert!(
            !install.join("telltale").exists(),
            "drop-in rejection must precede canonical installation for {unit}"
        );
        if install.exists() {
            let staging_exists =
                fs::read_dir(&install)
                    .unwrap()
                    .filter_map(Result::ok)
                    .any(|entry| {
                        entry
                            .file_name()
                            .to_string_lossy()
                            .starts_with(".telltale-install.")
                    });
            assert!(
                !staging_exists,
                "drop-in rejection must precede staging for {unit}"
            );
        }
    }
}

#[test]
fn schedule_query_failure_happens_before_candidate_staging() {
    let temp = tempdir().unwrap();
    let name = format!("telltale-v0.5.0-{}.tar.gz", target());
    let selected = archive(temp.path(), &name, "0.5.0", None);
    let metadata = release_metadata(temp.path(), "v0.5.0");
    let sums = temp.path().join("SHA256SUMS");
    checksum(&selected, &sums);
    let install = temp.path().join("home/bin");
    let units = temp.path().join("home/.config/systemd/user");
    fs::create_dir_all(&install).unwrap();
    fs::create_dir_all(&units).unwrap();
    regular_file(&install.join("telltale"), b"old canonical bytes\n", 0o755);
    regular_file(&install.join("adr"), b"old compatibility bytes\n", 0o755);
    regular_file(&units.join("adr-scan.service"), b"old service\n", 0o644);
    regular_file(&units.join("adr-scan.timer"), b"old timer\n", 0o644);

    let mut command = installer_command(
        temp.path(),
        &metadata,
        temp.path(),
        Some(&sums),
        &tools(temp.path(), true),
    );
    command
        .env("FAKE_OLD_ENABLED", "1")
        .env("FAKE_SYSTEMCTL_FAIL_QUERY", "LoadState:adr-scan.timer")
        .args(["--no-timer", "--install-dir", install.to_str().unwrap()]);
    let output = command.output().unwrap();
    assert!(!output.status.success());
    assert!(output_text(&output).contains("could not safely query systemd state"));
    assert_eq!(
        fs::read(install.join("telltale")).unwrap(),
        b"old canonical bytes\n"
    );
    assert_eq!(
        fs::read(install.join("adr")).unwrap(),
        b"old compatibility bytes\n"
    );
    let stages = fs::read_dir(&install)
        .unwrap()
        .filter_map(Result::ok)
        .any(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with(".telltale-install.")
        });
    assert!(!stages, "schedule failure must precede candidate staging");
    let journal = temp
        .path()
        .join("home/.local/state/telltale/installer-transaction.json");
    assert!(
        fs::read_to_string(journal)
            .unwrap()
            .contains("\"phase\": \"failed\"")
    );
    assert!(
        !fs::read_to_string(temp.path().join("events.log"))
            .unwrap()
            .contains("enable --now")
    );
}

#[test]
fn committed_journal_survives_schedule_failure_before_recovery() {
    let temp = tempdir().unwrap();
    let metadata = release_metadata(temp.path(), "v0.5.0");
    let install = temp.path().join("home/bin");
    let journal_dir = temp.path().join("home/.local/state/telltale");
    let units = temp.path().join("home/.config/systemd/user");
    fs::create_dir_all(&install).unwrap();
    fs::create_dir_all(&journal_dir).unwrap();
    fs::create_dir_all(&units).unwrap();

    let stage = install.join(".telltale-install.committed");
    fs::create_dir_all(&stage).unwrap();
    regular_file(
        &stage.join("transaction.marker"),
        b"telltale-installer-transaction-v1\n",
        0o600,
    );
    telltale_binary(&stage.join("telltale.old"), "0.4.0", false);
    telltale_binary(&stage.join("telltale.new"), "0.5.0", false);
    let new_bytes = fs::read(stage.join("telltale.new")).unwrap();
    regular_file(&install.join("telltale"), &new_bytes, 0o755);
    regular_file(&units.join("telltale-scan.timer"), b"new timer\n", 0o644);
    regular_file(
        &journal_dir.join("installer-transaction.json"),
        br#"{
  "version": "1.0",
  "phase": "committed",
  "identity": "telltale",
  "schedule": "telltale-scan.timer"
}
"#,
        0o600,
    );

    let mut command = installer_command(
        temp.path(),
        &metadata,
        temp.path(),
        None,
        &tools(temp.path(), true),
    );
    command
        .env("FAKE_SYSTEMCTL_FAIL_QUERY", "LoadState:telltale-scan.timer")
        .args(["--no-timer", "--install-dir", install.to_str().unwrap()]);
    let output = command.output().unwrap();
    assert!(!output.status.success());
    assert!(output_text(&output).contains("could not safely query systemd state"));
    assert_eq!(fs::read(install.join("telltale")).unwrap(), new_bytes);
    assert!(stage.exists(), "committed staging must remain for retry");
    assert!(
        fs::read_to_string(journal_dir.join("installer-transaction.json"))
            .unwrap()
            .contains("\"phase\": \"committed\"")
    );
}

#[test]
fn stale_stage_recovery_waits_for_active_schedule_quiescing() {
    let temp = tempdir().unwrap();
    let name = format!("telltale-v0.5.0-{}.tar.gz", target());
    let selected = archive(temp.path(), &name, "0.5.0", None);
    let metadata = release_metadata(temp.path(), "v0.5.0");
    let sums = temp.path().join("SHA256SUMS");
    checksum(&selected, &sums);

    let install = temp.path().join("home/bin");
    let units = temp.path().join("home/.config/systemd/user");
    fs::create_dir_all(&install).unwrap();
    fs::create_dir_all(&units).unwrap();
    regular_file(&units.join("adr-scan.service"), b"old service\n", 0o644);
    regular_file(&units.join("adr-scan.timer"), b"old timer\n", 0o644);

    let stage = install.join(".telltale-install.stale");
    fs::create_dir_all(&stage).unwrap();
    regular_file(
        &stage.join("transaction.marker"),
        b"telltale-installer-transaction-v1\n",
        0o600,
    );
    telltale_binary(&stage.join("telltale.old"), "0.4.0", false);

    let mut command = installer_command(
        temp.path(),
        &metadata,
        temp.path(),
        Some(&sums),
        &tools(temp.path(), true),
    );
    command
        .env("FAKE_OLD_ENABLED", "1")
        .env("FAKE_OLD_ACTIVE", "1")
        .env("FAKE_REQUIRE_STAGE_DURING_QUIESCE", &stage)
        .args(["--no-timer", "--install-dir", install.to_str().unwrap()]);
    let output = command.output().unwrap();
    assert_success(&output);
    assert!(install.join("telltale").is_file());
    assert!(
        !stage.exists(),
        "stale staging should be recovered and cleaned"
    );

    let events = fs::read_to_string(temp.path().join("events.log")).unwrap();
    let quiesce = events
        .find("systemctl:--user disable adr-scan.timer")
        .expect("active legacy timer disable event");
    let candidate = events
        .find("telltale.new:--version")
        .expect("candidate version probe");
    assert!(
        quiesce < candidate,
        "candidate execution preceded quiescing: {events}"
    );
}

#[test]
fn interrupted_binary_replacement_restores_old_before_later_failure() {
    let temp = tempdir().unwrap();
    let install = temp.path().join("home/bin");
    fs::create_dir_all(&install).unwrap();
    let stage = install.join(".telltale-install.binary-crash");
    fs::create_dir_all(&stage).unwrap();
    regular_file(
        &stage.join("transaction.marker"),
        b"telltale-installer-transaction-v1\n",
        0o600,
    );
    telltale_binary(&stage.join("telltale.old"), "0.4.0", false);
    telltale_binary(&stage.join("telltale.new"), "0.5.0", false);
    let old_bytes = fs::read(stage.join("telltale.old")).unwrap();
    fs::copy(stage.join("telltale.new"), install.join("telltale")).unwrap();

    let name = format!("telltale-v0.5.0-{}.tar.gz", target());
    let _selected = archive(temp.path(), &name, "0.5.0", None);
    let metadata = release_metadata(temp.path(), "v0.5.0");
    let output = run_release(temp.path(), &metadata, temp.path(), None, &[]);
    assert!(!output.status.success());
    assert!(output_text(&output).contains("SHA256SUMS"));
    assert_eq!(fs::read(install.join("telltale")).unwrap(), old_bytes);
    assert!(
        !stage.exists(),
        "verified interrupted recovery should clean staging"
    );
}

#[test]
fn failed_fresh_binary_copy_retains_partial_stage_without_partial_destination() {
    let temp = tempdir().unwrap();
    let name = format!("telltale-v0.5.0-{}.tar.gz", target());
    let selected = archive(temp.path(), &name, "0.5.0", None);
    let metadata = release_metadata(temp.path(), "v0.5.0");
    let sums = temp.path().join("SHA256SUMS");
    checksum(&selected, &sums);
    let install = temp.path().join("home/bin");
    let tools = tools(temp.path(), true);
    fail_partial_binary_copy(&tools);

    let mut command = installer_command(temp.path(), &metadata, temp.path(), Some(&sums), &tools);
    command.env("FAKE_FAIL_INSTALL_COPY", "1").args([
        "--no-timer",
        "--install-dir",
        install.to_str().unwrap(),
    ]);
    let output = command.output().expect("run failing fresh installer");
    assert!(!output.status.success());
    assert!(
        output_text(&output).contains("could not stage canonical telltale binary"),
        "unexpected failed-copy output: {}",
        output_text(&output)
    );
    assert!(
        !install.join("telltale").exists(),
        "failed staged copy must not leave a canonical partial destination"
    );

    let stage = fs::read_dir(&install)
        .expect("install directory after failed copy")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| {
            path.file_name()
                .is_some_and(|name| name.to_string_lossy().starts_with(".telltale-install."))
        })
        .expect("marker-owned staging after failed copy");
    let candidate = fs::read(stage.join("telltale.new")).expect("complete recovery candidate");
    let partial = fs::read(stage.join("telltale.installing")).expect("partial recovery copy");
    assert!(!candidate.is_empty());
    assert!(!partial.is_empty() && partial.len() < candidate.len());
    assert_eq!(partial, candidate[..partial.len()]);

    let journal = temp
        .path()
        .join("home/.local/state/telltale/installer-transaction.json");
    assert!(
        fs::read_to_string(journal)
            .expect("failed transaction journal")
            .contains("\"phase\": \"failed\"")
    );

    fs::remove_file(tools.join("install")).expect("remove failing install wrapper");
    let mut retry = installer_command(temp.path(), &metadata, temp.path(), Some(&sums), &tools);
    let retry_output = retry
        .args(["--no-timer", "--install-dir", install.to_str().unwrap()])
        .output()
        .expect("rerun installer after staged-copy failure");
    assert_success(&retry_output);
    assert!(install.join("telltale").is_file());
    assert!(
        !stage.exists(),
        "validated temporary staging should recover on retry"
    );
}

#[test]
fn failed_unit_copy_restores_preexisting_units_after_partial_stage() {
    let temp = tempdir().unwrap();
    let name = format!("telltale-v0.5.0-{}.tar.gz", target());
    let selected = archive(temp.path(), &name, "0.5.0", None);
    let metadata = release_metadata(temp.path(), "v0.5.0");
    let sums = temp.path().join("SHA256SUMS");
    checksum(&selected, &sums);
    let tools = tools(temp.path(), true);
    fail_partial_binary_copy(&tools);
    let install = temp.path().join("home/bin");
    let units = temp.path().join("home/.config/systemd/user");
    fs::create_dir_all(&units).unwrap();
    let old_service = b"preexisting service bytes\n";
    let old_timer = b"preexisting timer bytes\n";
    regular_file(&units.join("telltale-scan.service"), old_service, 0o644);
    regular_file(&units.join("telltale-scan.timer"), old_timer, 0o644);

    let mut command = installer_command(temp.path(), &metadata, temp.path(), Some(&sums), &tools);
    command.env("FAKE_FAIL_INSTALL_COPY", "unit-service").args([
        "--no-timer",
        "--install-dir",
        install.to_str().unwrap(),
    ]);
    let output = command.output().expect("run failing unit installer");
    assert!(!output.status.success());
    assert!(
        output_text(&output).contains("could not stage canonical user unit telltale-scan.service"),
        "unexpected failed unit-copy output: {}",
        output_text(&output)
    );
    assert!(!install.join("telltale").exists());
    assert_eq!(
        fs::read(units.join("telltale-scan.service")).unwrap(),
        old_service
    );
    assert_eq!(
        fs::read(units.join("telltale-scan.timer")).unwrap(),
        old_timer
    );
    let staging_exists = fs::read_dir(&units)
        .expect("unit directory after failed copy")
        .filter_map(Result::ok)
        .any(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with(".telltale-units.")
        });
    assert!(
        !staging_exists,
        "validated rollback should clean unit staging"
    );

    let journal = temp
        .path()
        .join("home/.local/state/telltale/installer-transaction.json");
    assert!(
        fs::read_to_string(journal)
            .expect("failed unit transaction journal")
            .contains("\"phase\": \"failed\"")
    );

    fs::remove_file(tools.join("install")).expect("remove failing install wrapper");
    let mut retry = installer_command(temp.path(), &metadata, temp.path(), Some(&sums), &tools);
    let retry_output = retry
        .args(["--no-timer", "--install-dir", install.to_str().unwrap()])
        .output()
        .expect("rerun installer after staged-unit failure");
    assert_success(&retry_output);
    assert!(units.join("telltale-scan.service").is_file());
    assert!(units.join("telltale-scan.timer").is_file());
    assert_ne!(
        fs::read(units.join("telltale-scan.service")).unwrap(),
        old_service
    );
    assert_ne!(
        fs::read(units.join("telltale-scan.timer")).unwrap(),
        old_timer
    );
    let staging_exists = fs::read_dir(&units)
        .unwrap()
        .filter_map(Result::ok)
        .any(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with(".telltale-units.")
        });
    assert!(!staging_exists, "retry must leave no unit staging");
}

#[test]
fn committed_recovery_keeps_new_install_and_cleans_staging() {
    let temp = tempdir().unwrap();
    let install = temp.path().join("home/bin");
    let journal_dir = temp.path().join("home/.local/state/telltale");
    fs::create_dir_all(&install).unwrap();
    fs::create_dir_all(&journal_dir).unwrap();
    let stage = install.join(".telltale-install.committed");
    fs::create_dir_all(&stage).unwrap();
    regular_file(
        &stage.join("transaction.marker"),
        b"telltale-installer-transaction-v1\n",
        0o600,
    );
    telltale_binary(&stage.join("telltale.old"), "0.4.0", false);
    telltale_binary(&stage.join("telltale.new"), "0.5.0", false);
    let new_bytes = fs::read(stage.join("telltale.new")).unwrap();
    fs::write(install.join("telltale"), &new_bytes).unwrap();
    fs::set_permissions(install.join("telltale"), fs::Permissions::from_mode(0o755)).unwrap();
    regular_file(
        &journal_dir.join("installer-transaction.json"),
        br#"{
  "version": "1.0",
  "phase": "committed",
  "identity": "telltale",
  "schedule": "telltale-scan.timer"
}
"#,
        0o600,
    );

    let name = format!("telltale-v0.5.0-{}.tar.gz", target());
    let _selected = archive(temp.path(), &name, "0.5.0", None);
    let metadata = release_metadata(temp.path(), "v0.5.0");
    let output = run_release(temp.path(), &metadata, temp.path(), None, &[]);
    assert!(!output.status.success());
    assert!(output_text(&output).contains("SHA256SUMS"));
    assert_eq!(fs::read(install.join("telltale")).unwrap(), new_bytes);
    assert!(!stage.exists(), "committed recovery should clean staging");
}

#[test]
fn duplicate_conflicting_initial_journal_phase_and_staging_are_retained() {
    let temp = tempdir().unwrap();
    let metadata = release_metadata(temp.path(), "v0.5.0");
    let install = temp.path().join("home/bin");
    let journal_dir = temp.path().join("home/.local/state/telltale");
    fs::create_dir_all(&install).unwrap();
    fs::create_dir_all(&journal_dir).unwrap();

    let stage = install.join(".telltale-install.malformed");
    fs::create_dir_all(&stage).unwrap();
    regular_file(
        &stage.join("transaction.marker"),
        b"telltale-installer-transaction-v1\n",
        0o600,
    );
    regular_file(&stage.join(".unknown"), b"retain this\n", 0o600);
    let journal = journal_dir.join("installer-transaction.json");
    let original_journal = br#"{
  "version": "1.0",
  "phase": "committed",
  "phase": "failed",
  "identity": "telltale",
  "schedule": "telltale-scan.timer"
}
"#;
    regular_file(&journal, original_journal, 0o600);

    let output = run_release(temp.path(), &metadata, temp.path(), None, &[]);
    assert!(!output.status.success());
    assert!(output_text(&output).contains("could not safely read the installer journal"));
    assert_eq!(fs::read(&journal).unwrap(), original_journal);
    assert!(stage.exists(), "malformed journal must retain staging");
    assert_eq!(fs::read(stage.join(".unknown")).unwrap(), b"retain this\n");
}

#[test]
fn unknown_hidden_stage_entry_is_retained_before_recursive_recovery_cleanup() {
    let temp = tempdir().unwrap();
    let metadata = release_metadata(temp.path(), "v0.5.0");
    let install = temp.path().join("home/bin");
    fs::create_dir_all(&install).unwrap();

    let stage = install.join(".telltale-install.hidden-entry");
    fs::create_dir_all(&stage).unwrap();
    regular_file(
        &stage.join("transaction.marker"),
        b"telltale-installer-transaction-v1\n",
        0o600,
    );
    regular_file(&stage.join(".unknown"), b"retain this\n", 0o600);
    telltale_binary(&stage.join("telltale.old"), "0.4.0", false);

    let output = run_release(temp.path(), &metadata, temp.path(), None, &[]);
    assert!(!output.status.success());
    assert!(output_text(&output).contains("marker-owned installer staging"));
    assert!(stage.exists());
    assert_eq!(fs::read(stage.join(".unknown")).unwrap(), b"retain this\n");
    assert!(stage.join("telltale.old").exists());
}

#[test]
fn interrupted_recovery_restores_backup_without_clobber_then_reruns() {
    let temp = tempdir().unwrap();
    let install = temp.path().join("home/bin");
    fs::create_dir_all(&install).unwrap();
    let stage = install.join(".telltale-install.interrupted");
    fs::create_dir_all(&stage).unwrap();
    regular_file(
        &stage.join("transaction.marker"),
        b"telltale-installer-transaction-v1\n",
        0o600,
    );
    telltale_binary(&stage.join("telltale.old"), "0.4.0", false);

    let name = format!("telltale-v0.5.0-{}.tar.gz", target());
    let selected = archive(temp.path(), &name, "0.5.0", None);
    let metadata = release_metadata(temp.path(), "v0.5.0");
    let sums = temp.path().join("SHA256SUMS");
    checksum(&selected, &sums);
    let output = run_release(temp.path(), &metadata, temp.path(), Some(&sums), &[]);
    assert_success(&output);
    assert!(install.join("telltale").is_file());
    assert!(
        !stage.exists(),
        "verified recovery staging should be cleaned"
    );
    assert!(
        fs::read_to_string(
            temp.path()
                .join("home/.local/state/telltale/installer-transaction.json")
        )
        .unwrap()
        .contains("committed")
    );
}

#[test]
fn recovery_conflict_preserves_both_byte_sets_and_records_failure() {
    let temp = tempdir().unwrap();
    let install = temp.path().join("home/bin");
    fs::create_dir_all(&install).unwrap();
    let stage = install.join(".telltale-install.conflict");
    fs::create_dir_all(&stage).unwrap();
    regular_file(
        &stage.join("transaction.marker"),
        b"telltale-installer-transaction-v1\n",
        0o600,
    );
    regular_file(&stage.join("telltale.old"), b"backup bytes\n", 0o755);
    regular_file(&stage.join("telltale.new"), b"expected new bytes\n", 0o755);
    regular_file(&install.join("telltale"), b"destination bytes\n", 0o755);

    let metadata = release_metadata(temp.path(), "v0.5.0");
    let output = run_release(temp.path(), &metadata, temp.path(), None, &[]);
    assert!(!output.status.success());
    assert_eq!(
        fs::read(stage.join("telltale.old")).unwrap(),
        b"backup bytes\n"
    );
    assert_eq!(
        fs::read(stage.join("telltale.new")).unwrap(),
        b"expected new bytes\n"
    );
    assert_eq!(
        fs::read(install.join("telltale")).unwrap(),
        b"destination bytes\n"
    );
    assert!(
        stage.exists(),
        "recovery conflict must retain marker-owned staging"
    );
    let journal = temp
        .path()
        .join("home/.local/state/telltale/installer-transaction.json");
    assert!(
        fs::read_to_string(journal)
            .unwrap()
            .contains("\"phase\": \"failed\"")
    );
}

#[test]
fn xdg_override_and_space_path_generate_safe_canonical_unit() {
    let temp = tempdir().unwrap();
    let name = format!("telltale-v0.5.0-{}.tar.gz", target());
    let selected = archive(temp.path(), &name, "0.5.0", None);
    let metadata = release_metadata(temp.path(), "v0.5.0");
    let sums = temp.path().join("SHA256SUMS");
    checksum(&selected, &sums);
    let install = temp.path().join("home/bin with spaces 50%");
    let config = temp.path().join("home/custom config 50%");
    let state = temp.path().join("home/custom state 50%");
    let units = config.join("systemd/user");
    let mut command = installer_command(
        temp.path(),
        &metadata,
        temp.path(),
        Some(&sums),
        &tools(temp.path(), true),
    );
    command
        .env("XDG_CONFIG_HOME", &config)
        .env("XDG_STATE_HOME", &state)
        .args(["--with-timer", "--install-dir", install.to_str().unwrap()]);
    let output = command.output().unwrap();
    assert_success(&output);
    let service = fs::read_to_string(units.join("telltale-scan.service")).unwrap();
    let escaped_install = install.to_string_lossy().replace('%', "%%");
    let escaped_config = config.to_string_lossy().replace('%', "%%");
    assert!(service.contains(&format!(
        "EnvironmentFile=-\"{}/telltale/telltale.env\"",
        escaped_config
    )));
    assert!(service.contains(&format!(
        "ExecStart=/usr/bin/env -- \"{}/telltale\"",
        escaped_install
    )));
    assert!(service.contains("50%%"));
    assert!(service.contains("--root \"${TELLTALE_SCAN_ROOT}\""));
    assert!(!service.contains("ExecStart=:"));
    if Command::new("systemd-analyze")
        .arg("--version")
        .output()
        .is_ok_and(|version| version.status.success())
    {
        let parsed = Command::new("systemd-analyze")
            .args([
                "verify",
                units.join("telltale-scan.service").to_str().unwrap(),
            ])
            .output()
            .expect("systemd-analyze");
        assert!(
            parsed.status.success(),
            "generated user unit did not parse: {}",
            output_text(&parsed)
        );
    }
    assert!(state.join("telltale/installer-transaction.json").is_file());
    assert!(!temp.path().join("home/.config/telltale").exists());
}

#[test]
fn duplicate_windows_named_binary_is_rejected_before_install() {
    let temp = tempdir().unwrap();
    let name = format!("telltale-v0.5.0-{}.tar.gz", target());
    let selected = archive(temp.path(), &name, "0.5.0", None);
    let sums = temp.path().join("SHA256SUMS");
    checksum(&selected, &sums);
    let install = temp.path().join("home/bin");
    fs::create_dir_all(&install).unwrap();
    regular_file(&install.join("telltale.exe"), b"duplicate\n", 0o755);
    let metadata = release_metadata(temp.path(), "v0.5.0");
    let output = run_release(temp.path(), &metadata, temp.path(), Some(&sums), &[]);
    assert!(!output.status.success());
    assert!(output_text(&output).contains("duplicate canonical binary"));
    assert!(!install.join("telltale").exists());
}
