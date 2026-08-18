#![cfg(target_os = "linux")]

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
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

fn rc4_generated_service(install: &Path, state_root: &Path, config_root: &Path) -> String {
    format!(
        "[Unit]\nDescription=Telltale one-shot agent session scan\n\n[Service]\nType=oneshot\nEnvironment=\"TELLTALE_LOG_PATH={}/telltale/logs/telltale-events.jsonl\"\nEnvironment=\"TELLTALE_STATE_PATH={}/telltale/telltale-state.json\"\nEnvironment=\"TELLTALE_SCAN_ROOT=%h\"\nEnvironmentFile=-\"{}/telltale/telltale.env\"\nExecStart=/usr/bin/env -- \"{}/telltale\" scan --once --emit-activity --root \"${{TELLTALE_SCAN_ROOT}}\" --path-profile user\nNoNewPrivileges=true\nPrivateTmp=true\n\n[Install]\nWantedBy=default.target\n",
        state_root.display(),
        state_root.display(),
        config_root.display(),
        install.display(),
    )
}

fn rc5_rc6_generated_service(install: &Path, state_root: &Path, config_root: &Path) -> String {
    format!(
        "[Unit]\nDescription=Telltale one-shot agent session scan\n\n[Service]\nType=oneshot\nEnvironment=\"TELLTALE_LOG_PATH={}/telltale/logs/telltale-events.jsonl\"\nEnvironment=\"TELLTALE_STATE_PATH={}/telltale/telltale-state.json\"\nEnvironment=\"TELLTALE_SCAN_ROOT=%h\"\nEnvironmentFile=-\"{}/telltale/telltale.env\"\nExecStart=/usr/bin/env -- \"{}/telltale\" scan --once --emit-activity --root \"${{TELLTALE_SCAN_ROOT}}\" --path-profile user\nNoNewPrivileges=true\nPrivateTmp=true\nProtectHome=no\n\n[Install]\nWantedBy=default.target\n",
        state_root.display(),
        state_root.display(),
        config_root.display(),
        install.display(),
    )
}

fn rc4_generated_timer() -> &'static str {
    "[Unit]\nDescription=Run Telltale agent session scans periodically\n\n[Timer]\nOnActiveSec=1min\nOnUnitActiveSec=5min\nUnit=telltale-scan.service\nPersistent=true\n\n[Install]\nWantedBy=timers.target\n"
}

fn telltale_binary(path: &Path, version: &str, _identity_fixture: bool) {
    let identity = "telltale";
    executable(
        path,
        &format!(
            "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then printf '%s\\n' '{identity} {version} (synthetic)'; fi\nif [ -n \"${{FAKE_EVENT_LOG:-}}\" ]; then printf 'binary:%s:%s\\n' \"$0\" \"$*\" >> \"$FAKE_EVENT_LOG\"; fi\nif [ \"${{FAKE_REQUIRE_SMOKE_FIXTURE:-0}}\" = 1 ] && [ \"$1\" = \"scan\" ]; then smoke_root=''; previous=''; for arg in \"$@\"; do if [ \"$previous\" = --root ]; then smoke_root=$arg; fi; previous=$arg; done; [ -f \"$smoke_root/codex/sessions/2026/04/telltale-installer-smoke.jsonl\" ] || exit 77; fi\nif [ \"${{FAKE_REENABLE_DURING_SMOKE:-0}}\" = 1 ] && [ \"$1\" = \"scan\" ] && [ -n \"${{FAKE_SYSTEMCTL_STATE:-}}\" ]; then awk '$1 == \"telltale-scan.timer\" {{ $3=1; $4=1 }} {{ print }}' \"$FAKE_SYSTEMCTL_STATE\" > \"$FAKE_SYSTEMCTL_STATE.tmp\"; mv \"$FAKE_SYSTEMCTL_STATE.tmp\" \"$FAKE_SYSTEMCTL_STATE\"; fi\nexit 0\n"
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
        fs::write(payload.join(member), b"unexpected archive member\n")
            .expect("write extra member");
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
    assert!(!root.join("home/.telltale-installer.lock").exists());
    assert!(!root.join("systemctl.log").exists());
}

fn release_metadata(root: &Path, tag: &str) -> PathBuf {
    release_metadata_with_flags(root, tag, false, false)
}

fn release_metadata_with_flags(root: &Path, tag: &str, draft: bool, prerelease: bool) -> PathBuf {
    let path = root.join("release.json");
    fs::write(
        &path,
        format!("{{\"tag_name\":\"{tag}\",\"draft\":{draft},\"prerelease\":{prerelease}}}\n"),
    )
    .expect("metadata");
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
    */releases/latest|*/releases/tags/*) cat "$FAKE_CURL_METADATA";;
    */SHA256SUMS) cp "$FAKE_CURL_CHECKSUMS" "$output";;
    */*.tar.gz) cp "$FAKE_CURL_ASSET_DIR/${url##*/}" "$output";;
    *) exit 22;;
esac
"####,
    );
}

fn fake_git(tools: &Path) {
    executable(
        &tools.join("git"),
        r####"#!/bin/sh
set -eu
if [ "${1:-}" != ls-remote ]; then exit 97; fi
printf '%s\n' "$*" > "${FAKE_GIT_LOG:?}"
printf '%s\n' "${FAKE_GIT_LS_REMOTE:?}"
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

fn require_effective_policy_before_binary_replacement(tools: &Path) {
    executable(
        &tools.join("install"),
        r####"#!/bin/sh
set -eu
destination=''
skip_next=0
for arg in "$@"; do
  if [ "$skip_next" = 1 ]; then skip_next=0; continue; fi
  case "$arg" in
    -m) skip_next=1;;
    -*) ;;
    *) destination=$arg;;
  esac
done
case "$destination" in
  */telltale.installing)
    awk -F '\t' '
      $1 == "EnvironmentFiles" { environment_files = 1 }
      $1 == "WorkingDirectory" { working_directory = 1 }
      END { exit !(environment_files && working_directory) }
    ' "${FAKE_EFFECTIVE_PROPERTY_LOG:?}"
    cp "$FAKE_EFFECTIVE_PROPERTY_LOG" "${FAKE_BINARY_REPLACEMENT_POLICY_LOG:?}"
    ;;
esac
real_install=/usr/bin/install
[ -x "$real_install" ] || real_install=/bin/install
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
if [ -n "${FAKE_SYSTEMCTL_DELAY:-}" ]; then sleep "$FAKE_SYSTEMCTL_DELAY"; fi
config_root=${XDG_CONFIG_HOME:-$HOME/.config}
config_root=$(realpath -m "$config_root")
unit_dir=$config_root/systemd/user
state=${FAKE_SYSTEMCTL_STATE:?}
generated=${FAKE_GENERATED_UNIT:-}

init_state() {
  : > "$state"
  for unit in telltale-scan.service telltale-scan.timer; do
    present=0
    [ "${FAKE_INITIAL_NOT_FOUND:-0}" = 1 ] || { [ -f "$unit_dir/$unit" ] && present=1; }
    [ "$unit" = "$generated" ] && present=1
    enabled=0
    active=0
    case "$unit" in
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
    state_root=${XDG_STATE_HOME:-$HOME/.local/state}
    state_root=$(realpath -m "$state_root")
    canonical_log=$state_root/telltale/logs/telltale-events.jsonl
    canonical_state=$state_root/telltale/telltale-state.json
    canonical_env=$config_root/telltale/telltale.env
    home_real=$(realpath -e "$HOME")
    service_file=$unit_dir/telltale-scan.service
    executable=${FAKE_EXPECTED_INSTALL_DIR:-$HOME/.local/bin}/telltale
    if [ -f "$service_file" ]; then
      exec_line=$(awk -F= '/^ExecStart=/{ print substr($0,11); exit }' "$service_file")
      case "$exec_line" in
        *\"*) executable=$(printf '%s\n' "$exec_line" | awk -F'"' '{ print $2 }' | sed 's/%%/%/g');;
      esac
    fi
    effective_value() {
      mutation=${FAKE_PROPERTY_MUTATION:-}
      record_effective_value() {
        if [ -n "${FAKE_EFFECTIVE_PROPERTY_LOG:-}" ]; then
          printf '%s\t%s\n' "$property" "$1" >> "$FAKE_EFFECTIVE_PROPERTY_LOG"
        fi
        printf '%s\n' "$1"
      }
      if [ "$property" = EnvironmentFiles ] && [ "${FAKE_ENVIRONMENT_FILES_VALUE+x}" = x ]; then
        record_effective_value "$FAKE_ENVIRONMENT_FILES_VALUE"
        return 0
      fi
      if [ "$property" = WorkingDirectory ] && [ "${FAKE_WORKING_DIRECTORY_VALUE+x}" = x ]; then
        record_effective_value "$FAKE_WORKING_DIRECTORY_VALUE"
        return 0
      fi
      if [ "$property" = WorkingDirectory ] && [ "${FAKE_POST_STAGE_WD_MUTATION:-0}" = 1 ] && [ -f "$service_file" ]; then
        for unit_stage in "$unit_dir"/.telltale-units.*; do
          if [ -d "$unit_stage" ]; then
            printf '%s\n' '!/tmp'
            return 0
          fi
        done
      fi
      case "$property:$mutation" in
        ExecStart:execstart) printf '%s\n' '{ path=/bin/sh ; argv[]=/bin/sh -c malicious ; ignore_errors=no ; }';;
        ExecStart:execstart-ignore) printf '{ path=/usr/bin/env ; argv[]=/usr/bin/env -- "%s" scan --once --emit-activity --root ${TELLTALE_SCAN_ROOT} --path-profile user ; ignore_errors=yes ; }\n' "$executable";;
        ExecStart:execstart-flags) printf '{ path=/usr/bin/env ; argv[]=/usr/bin/env -- "%s" scan --once --emit-activity --root ${TELLTALE_SCAN_ROOT} --path-profile user ; ignore_errors=no ; flags=bad ; }\n' "$executable";;
        ExecStart:execstart-extra) printf '{ path=/usr/bin/env ; argv[]=/usr/bin/env -- "%s" scan --once --emit-activity --root ${TELLTALE_SCAN_ROOT} --path-profile user ; ignore_errors=no ; } { path=/bin/true ; argv[]=/bin/true ; ignore_errors=no ; }\n' "$executable";;
        ExecStartPre:hook|ExecStartPost:hook|ExecCondition:hook|ExecStopPre:hook|ExecStop:hook|ExecStopPost:hook|ExecReload:hook|ExecReloadPost:hook) printf '%s\n' '{ path=/bin/sh ; argv[]=/bin/sh -c hook ; ignore_errors=no ; }';;
        ExecStopPre:stop-pre) printf '%s\n' '{ path=/bin/sh ; argv[]=/bin/sh -c hook ; ignore_errors=no ; }';;
        ExecReloadPost:reload-post) printf '%s\n' '{ path=/bin/sh ; argv[]=/bin/sh -c hook ; ignore_errors=no ; }';;
        Environment:environment) printf '%s\n' 'TELLTALE_LOG_PATH=/safe TELLTALE_STATE_PATH=/safe TELLTALE_SCAN_ROOT=%h INJECTED=1';;
         EnvironmentFiles:empty) printf '\n';;
         EnvironmentFiles:alternate) printf '%s\n' '/tmp/alternate.env (ignore_errors=yes)';;
         EnvironmentFiles:extra) printf '%s (ignore_errors=yes) /tmp/extra.env (ignore_errors=yes)\n' "$canonical_env";;
         EnvironmentFiles:reset) printf '%s\n' '(reset)';;
         EnvironmentFiles:unknown) printf '%s\n' 'unknown';;
         EnvironmentFiles:env-file) printf '%s\n' '/tmp/injected.env (ignore_errors=yes)';;
        Environment:quoted-values) printf 'TELLTALE_LOG_PATH="%s" TELLTALE_STATE_PATH="%s" TELLTALE_SCAN_ROOT="%%h"\n' "$canonical_log" "$canonical_state";;
        EnvironmentFiles:quoted-values) printf '"%s" (ignore_errors=yes)\n' "$canonical_env";;
        WorkingDirectory:path) printf '%s\n' '/tmp';;
        WorkingDirectory:alternate-missing-ok) printf '%s\n' '!/tmp';;
        WorkingDirectory:bare-home) printf '%s\n' "$HOME";;
        WorkingDirectory:tilde) printf '%s\n' '~';;
        WorkingDirectory:bang-tilde) printf '%s\n' '!~';;
        WorkingDirectory:unknown-prefix) printf '%s\n' "?${home_real}";;
        WorkingDirectory:malformed) printf '%s\n' '!';;
        WorkingDirectory:wd-empty) printf '\n';;
        WorkingDirectory:canonical-home) printf '%s\n' "$home_real";;
        RootDirectory:path|RootImage:path) printf '%s\n' '/tmp';;
        User:identity|Group:identity) printf '%s\n' 'attacker';;
        SupplementaryGroups:identity|SupplementaryGroups:supplementary|PassEnvironment:environment|PassEnvironment:pass-environment|UnsetEnvironment:environment|UnsetEnvironment:unset-environment) printf '%s\n' 'INJECTED=1';;
        Type:type) printf '%s\n' 'simple';;
        NoNewPrivileges:security) printf '%s\n' 'no';;
        PrivateTmp:security) printf '%s\n' 'no';;
        ProtectHome:security) printf '%s\n' 'yes';;
        DynamicUser:security|DynamicUser:dynamic-user|PrivateUsers:security|PrivateUsers:private-users) printf '%s\n' 'yes';;
        Unit:timer-target) printf '%s\n' 'other.service';;
        TimersMonotonic:timer-cadence) printf '%s\n' '{ OnActiveUSec=1h ; next_elapse=1 } { OnUnitActiveUSec=5min ; next_elapse=2 }';;
        TimersMonotonic:timer-extra) printf '%s\n' '{ OnActiveUSec=1min ; next_elapse=1 } { OnUnitActiveUSec=5min ; next_elapse=2 } { OnBootUSec=3min ; next_elapse=3 }';;
        TimersCalendar:timer-calendar) printf '%s\n' '{ calendar=*-*-* 00:00:00 ; next_elapse=1 }';;
        Persistent:timer-persistence) printf '%s\n' 'no';;
         WakeSystem:timer-boolean) printf '%s\n' 'yes';;
         RemainAfterElapse:timer-boolean) printf '%s\n' 'no';;
        *) return 1;;
      esac
    }
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
            if [ "${FAKE_DROP_IN_PATHS+x}" = x ]; then
              dropin_paths=$FAKE_DROP_IN_PATHS
            else
              dropin_paths=/run/user/1000/systemd/user/$unit.d/override.conf
            fi
          fi
          if [ "$value_mode" = 1 ]; then
            printf '%s\n' "$dropin_paths"
          else
            printf 'DropInPaths=%s\n' "$dropin_paths"
          fi
          ;;
        UnitFileState) [ "$enabled" = 1 ] && printf 'enabled\n' || printf 'disabled\n';;
        ActiveState) [ "$active" = 1 ] && printf 'active\n' || printf 'inactive\n';;
        *)
          if effective_value; then :; else
            case "$unit:$property" in
              telltale-scan.service:ExecStart)
                printf '{ path=/usr/bin/env ; argv[]=/usr/bin/env -- "%s" scan --once --emit-activity --root ${TELLTALE_SCAN_ROOT} --path-profile user ; ignore_errors=no ; }\n' "$executable";;
              telltale-scan.service:ExecStartPre|telltale-scan.service:ExecStartPost|\
              telltale-scan.service:ExecCondition|telltale-scan.service:ExecStopPre|\
              telltale-scan.service:ExecStop|telltale-scan.service:ExecStopPost|\
              telltale-scan.service:ExecReload|telltale-scan.service:ExecReloadPost|\
              telltale-scan.service:User|telltale-scan.service:Group|\
              telltale-scan.service:SupplementaryGroups|\
              telltale-scan.service:RootDirectory|telltale-scan.service:RootImage|\
              telltale-scan.service:PassEnvironment|telltale-scan.service:UnsetEnvironment) printf '\n';;
              telltale-scan.service:WorkingDirectory) printf '!%s\n' "$home_real";;
              telltale-scan.service:Environment)
                printf 'TELLTALE_LOG_PATH="%s" TELLTALE_STATE_PATH="%s" TELLTALE_SCAN_ROOT=%%h\n' "$canonical_log" "$canonical_state";;
              telltale-scan.service:EnvironmentFiles) printf '%s (ignore_errors=yes)\n' "$canonical_env";;
              telltale-scan.service:Type) printf 'oneshot\n';;
              telltale-scan.service:NoNewPrivileges|telltale-scan.service:PrivateTmp) printf 'yes\n';;
              telltale-scan.service:ProtectHome) printf 'no\n';;
              telltale-scan.service:DynamicUser|telltale-scan.service:PrivateUsers) printf 'no\n';;
              telltale-scan.timer:Unit) printf 'telltale-scan.service\n';;
              telltale-scan.timer:TimersMonotonic) printf '{ OnActiveUSec=1min ; next_elapse=1 } { OnUnitActiveUSec=5min ; next_elapse=2 }\n';;
              telltale-scan.timer:TimersCalendar) printf '\n';;
              telltale-scan.timer:Persistent) printf 'yes\n';;
               telltale-scan.timer:WakeSystem) printf 'no\n';;
               telltale-scan.timer:RemainAfterElapse) printf 'yes\n';;
              telltale-scan.timer:FragmentPath) printf '%s/%s\n' "$unit_dir" "$unit";;
              *) exit 1;;
            esac
          fi
          ;;
      esac
    else
        case "$property" in
        LoadState) printf 'not-found\n';;
        FragmentPath) printf '\n';;
        DropInPaths)
          dropin_paths=''
          if [ "${FAKE_DROP_IN_UNIT:-}" = "$unit" ]; then
            if [ "${FAKE_DROP_IN_PATHS+x}" = x ]; then
              dropin_paths=$FAKE_DROP_IN_PATHS
            else
              dropin_paths=/run/user/1000/systemd/user/$unit.d/override.conf
            fi
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
    if [ "${FAKE_RESET_EFFECTIVE_PROPERTY_LOG:-0}" = 1 ] && [ -n "${FAKE_EFFECTIVE_PROPERTY_LOG:-}" ]; then
      : > "$FAKE_EFFECTIVE_PROPERTY_LOG"
    fi
    if [ -f "$unit_dir/telltale-scan.service" ] && [ -n "${FAKE_MUTATE_GENERATED_UNIT:-}" ]; then
      case "$FAKE_MUTATE_GENERATED_UNIT" in
        omit) sed -i '/^EnvironmentFile=/d' "$unit_dir/telltale-scan.service";;
        alternate) sed -i 's|^EnvironmentFile=.*|EnvironmentFile=-"/tmp/alternate.env"|' "$unit_dir/telltale-scan.service";;
        *) exit 98;;
      esac
    fi
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
    fake_git(&tools);
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
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("XDG_STATE_HOME")
        .env("PATH", path)
        .env("FAKE_CURL_METADATA", metadata)
        .env("FAKE_CURL_ASSET_DIR", asset_dir)
        .env("FAKE_CURL_LOG", root.join("curl.log"))
        .env("FAKE_SYSTEMCTL_LOG", root.join("systemctl.log"))
        .env("FAKE_SYSTEMCTL_STATE", root.join("systemctl.state"))
        .env("FAKE_EVENT_LOG", root.join("events.log"));
    command.env("FAKE_EXPECTED_INSTALL_DIR", root.join("home/bin"));
    if let Some(sums) = sums {
        command.env("FAKE_CURL_CHECKSUMS", sums);
    } else {
        command.env_remove("FAKE_CURL_CHECKSUMS");
    }
    command
}

fn configure_fake_git(
    command: &mut Command,
    root: &Path,
    tag: &str,
    tag_sha: &str,
    peeled_sha: Option<&str>,
) -> PathBuf {
    let mut refs = format!("{}\trefs/tags/{tag}\n", tag_sha);
    if let Some(peeled_sha) = peeled_sha {
        refs.push_str(&format!("{}\trefs/tags/{tag}^{{}}\n", peeled_sha));
    }
    let log = root.join("git.log");
    command
        .env("FAKE_GIT_LS_REMOTE", refs)
        .env("FAKE_GIT_LOG", &log);
    log
}

fn assert_fake_git_tag_refs(log: &Path, tag: &str) {
    let args = fs::read_to_string(log).unwrap();
    assert!(
        args.contains(&format!("refs/tags/{tag} refs/tags/{tag}^{{}}")),
        "git did not request exact lightweight and peeled refs: {args}"
    );
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
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("XDG_STATE_HOME")
        .env("PATH", path)
        .env("FAKE_CURL_METADATA", metadata)
        .env("FAKE_CURL_ASSET_DIR", asset_dir)
        .env("FAKE_CURL_LOG", root.join("curl.log"))
        .env("FAKE_SYSTEMCTL_LOG", root.join("systemctl.log"))
        .env("FAKE_SYSTEMCTL_STATE", root.join("systemctl.state"))
        .env("FAKE_EVENT_LOG", root.join("events.log"));
    command.env("FAKE_EXPECTED_INSTALL_DIR", root.join("home/bin"));
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
    let name = format!("telltale-v0.5.0-{}.tar.gz", target());
    let selected = archive(temp.path(), &name, "0.5.0", None);
    let metadata = release_metadata(temp.path(), "v0.5.0");
    let sums = temp.path().join("SHA256SUMS");
    checksum(&selected, &sums);
    let tools = tools(temp.path(), false);
    reject_no_copy_mv(&tools);
    let home = temp.path().join("home");
    let mut command = installer_command(temp.path(), &metadata, temp.path(), Some(&sums), &tools);
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
fn explicit_rc_selection_uses_only_the_exact_tag_and_preserves_stable_default() {
    let temp = tempdir().unwrap();
    let tag = "v0.5.0-rc.1";
    let name = format!("telltale-{tag}-{}.tar.gz", target());
    let selected = archive(temp.path(), &name, "0.5.0-rc.1", None);
    let metadata = release_metadata_with_flags(temp.path(), tag, false, true);
    let sums = temp.path().join("SHA256SUMS");
    checksum(&selected, &sums);

    let output = run_release(
        temp.path(),
        &metadata,
        temp.path(),
        Some(&sums),
        &["--release-tag", tag, "--no-timer"],
    );
    assert_success(&output);
    assert!(temp.path().join("home/bin/telltale").is_file());

    let urls = fs::read_to_string(temp.path().join("curl.log")).unwrap();
    assert!(urls.contains("/releases/tags/v0.5.0-rc.1"));
    assert!(!urls.contains("/releases/latest"));
    assert!(urls.contains("/releases/download/v0.5.0-rc.1/"));
}

#[test]
fn explicit_rc_provenance_rejects_metadata_before_lock_or_manager_mutation() {
    let temp = tempdir().unwrap();
    let requested = "v0.5.0-rc.1";
    let metadata = release_metadata_with_flags(temp.path(), "v0.5.0-rc.2", false, true);
    let output = run_release(
        temp.path(),
        &metadata,
        temp.path(),
        None,
        &["--release-tag", requested, "--no-timer"],
    );
    assert!(!output.status.success());
    assert!(output_text(&output).contains("does not match --release-tag"));
    assert!(!temp.path().join("home/.telltale-installer.lock").exists());
    assert!(!temp.path().join("home/bin").exists());
    assert!(!temp.path().join("systemctl.log").exists());

    let draft = tempdir().unwrap();
    let draft_metadata = release_metadata_with_flags(draft.path(), requested, true, true);
    let output = run_release(
        draft.path(),
        &draft_metadata,
        draft.path(),
        None,
        &["--release-tag", requested, "--no-timer"],
    );
    assert!(!output.status.success());
    assert!(output_text(&output).contains("must not be a draft"));
    assert!(!draft.path().join("home/.telltale-installer.lock").exists());
}

#[test]
fn release_tag_validation_rejects_misclassified_or_ambiguous_candidates() {
    let stable = tempdir().unwrap();
    let stable_metadata = release_metadata_with_flags(stable.path(), "v0.5.0-rc.1", false, false);
    let output = run_release(
        stable.path(),
        &stable_metadata,
        stable.path(),
        None,
        &["--no-timer"],
    );
    assert!(!output.status.success());
    assert!(output_text(&output).contains("not a valid GitHub Release object"));
    assert!(!stable.path().join("home/.telltale-installer.lock").exists());

    let stable_prerelease = tempdir().unwrap();
    let stable_prerelease_metadata =
        release_metadata_with_flags(stable_prerelease.path(), "v0.5.0", false, true);
    let output = run_release(
        stable_prerelease.path(),
        &stable_prerelease_metadata,
        stable_prerelease.path(),
        None,
        &["--no-timer"],
    );
    assert!(!output.status.success());
    assert!(output_text(&output).contains("latest release must be stable"));
    assert!(
        !stable_prerelease
            .path()
            .join("home/.telltale-installer.lock")
            .exists()
    );

    let misclassified = tempdir().unwrap();
    let tag = "v0.5.0-rc.1";
    let metadata = release_metadata_with_flags(misclassified.path(), tag, false, false);
    let output = run_release(
        misclassified.path(),
        &metadata,
        misclassified.path(),
        None,
        &["--release-tag", tag, "--no-timer"],
    );
    assert!(!output.status.success());
    assert!(output_text(&output).contains("not a published prerelease"));
    assert!(
        !misclassified
            .path()
            .join("home/.telltale-installer.lock")
            .exists()
    );

    let ambiguous = tempdir().unwrap();
    let ambiguous_metadata = ambiguous.path().join("release.json");
    fs::write(
        &ambiguous_metadata,
        format!(
            "{{\"tag_name\":\"{tag}\",\"tag_name\":\"v0.5.0-rc.3\",\"draft\":false,\"prerelease\":true}}\n"
        ),
    )
    .unwrap();
    let output = run_release(
        ambiguous.path(),
        &ambiguous_metadata,
        ambiguous.path(),
        None,
        &["--release-tag", tag, "--no-timer"],
    );
    assert!(!output.status.success());
    assert!(output_text(&output).contains("not a valid GitHub Release object"));
    assert!(
        !ambiguous
            .path()
            .join("home/.telltale-installer.lock")
            .exists()
    );

    for (name, contents) in [
        (
            "nested",
            r#"{"release":{"tag_name":"v0.5.0-rc.1"},"draft":false,"prerelease":true}"#,
        ),
        (
            "wrong-types",
            r#"{"tag_name":["v0.5.0-rc.1"],"draft":"false","prerelease":true}"#,
        ),
        (
            "delimiter",
            r#"{"tag_name":"v0.5.0-rc.1\t0\t0\nignored","draft":false,"prerelease":true}"#,
        ),
    ] {
        let malformed = tempdir().unwrap();
        let malformed_metadata = malformed.path().join(format!("{name}.json"));
        fs::write(&malformed_metadata, contents).unwrap();
        let output = run_release(
            malformed.path(),
            &malformed_metadata,
            malformed.path(),
            None,
            &["--release-tag", tag, "--no-timer"],
        );
        assert!(!output.status.success());
        assert!(output_text(&output).contains("not a valid GitHub Release object"));
        assert!(
            !malformed
                .path()
                .join("home/.telltale-installer.lock")
                .exists()
        );
    }

    let invalid = tempdir().unwrap();
    let metadata = release_metadata_with_flags(invalid.path(), "v0.5.0-rc.01", false, true);
    let output = run_release(
        invalid.path(),
        &metadata,
        invalid.path(),
        None,
        &["--release-tag", "v0.5.0-rc.01", "--no-timer"],
    );
    assert!(!output.status.success());
    assert!(output_text(&output).contains("exact v0.5.0-rc.<n>"));
    assert!(
        !invalid
            .path()
            .join("home/.telltale-installer.lock")
            .exists()
    );

    let empty = tempdir().unwrap();
    let metadata = release_metadata(empty.path(), "v0.5.0");
    let output = run_release(
        empty.path(),
        &metadata,
        empty.path(),
        None,
        &["--release-tag", "", "--no-timer"],
    );
    assert!(!output.status.success());
    assert!(output_text(&output).contains("exact v0.5.0-rc.<n>"));
    let urls = fs::read_to_string(empty.path().join("curl.log")).unwrap_or_default();
    assert!(!urls.contains("/releases/latest"));
    assert!(!empty.path().join("home/.telltale-installer.lock").exists());
    assert!(!empty.path().join("systemctl.log").exists());
}

#[test]
fn explicit_rc_never_allows_checksum_bypass() {
    let temp = tempdir().unwrap();
    let tag = "v0.5.0-rc.1";
    let metadata = release_metadata_with_flags(temp.path(), tag, false, true);
    let output = run_release(
        temp.path(),
        &metadata,
        temp.path(),
        None,
        &["--release-tag", tag, "--skip-checksum", "--no-timer"],
    );
    assert!(!output.status.success());
    assert!(output_text(&output).contains("not permitted with --release-tag"));
    assert!(!temp.path().join("home/.telltale-installer.lock").exists());
    assert!(!temp.path().join("systemctl.log").exists());
}

#[test]
fn explicit_rc_provenance_rejects_checksum_and_binary_version_before_lock() {
    let bad_checksum = tempdir().unwrap();
    let tag = "v0.5.0-rc.1";
    let name = format!("telltale-{tag}-{}.tar.gz", target());
    let _selected = archive(bad_checksum.path(), &name, "0.5.0-rc.1", None);
    let metadata = release_metadata_with_flags(bad_checksum.path(), tag, false, true);
    let sums = bad_checksum.path().join("SHA256SUMS");
    fs::write(
        &sums,
        format!(
            "{}  {name}\n",
            "0000000000000000000000000000000000000000000000000000000000000000"
        ),
    )
    .unwrap();
    let output = run_release(
        bad_checksum.path(),
        &metadata,
        bad_checksum.path(),
        Some(&sums),
        &["--release-tag", tag, "--no-timer"],
    );
    assert!(!output.status.success());
    assert!(output_text(&output).contains("checksum mismatch"));
    assert!(
        !bad_checksum
            .path()
            .join("home/.telltale-installer.lock")
            .exists()
    );

    let bad_binary = tempdir().unwrap();
    let selected = archive(bad_binary.path(), &name, "0.5.0", None);
    let metadata = release_metadata_with_flags(bad_binary.path(), tag, false, true);
    let sums = bad_binary.path().join("SHA256SUMS");
    checksum(&selected, &sums);
    let output = run_release(
        bad_binary.path(),
        &metadata,
        bad_binary.path(),
        Some(&sums),
        &["--release-tag", tag, "--no-timer"],
    );
    assert!(!output.status.success());
    assert!(output_text(&output).contains("binary version does not match"));
    assert!(
        !bad_binary
            .path()
            .join("home/.telltale-installer.lock")
            .exists()
    );
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
    command.args([
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
    let installed = fs::read_dir(&install)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect::<Vec<_>>();
    assert_eq!(installed, vec![std::ffi::OsString::from("telltale")]);
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
fn inherited_noncanonical_environment_does_not_block_install_or_leak_values() {
    let temp = tempdir().unwrap();
    let name = format!("telltale-v0.5.0-{}.tar.gz", target());
    let selected = archive(temp.path(), &name, "0.5.0", None);
    let metadata = release_metadata(temp.path(), "v0.5.0");
    let sums = temp.path().join("SHA256SUMS");
    checksum(&selected, &sums);
    let tools = tools(temp.path(), true);
    let install = temp.path().join("home/bin");
    let mut command = installer_command(temp.path(), &metadata, temp.path(), Some(&sums), &tools);
    command
        .env("UNRELATED_LOG_PATH", "noncanonical-secret-canary")
        .env("THIRD_PARTY_EXTENSION", "allowed")
        .args(["--no-timer", "--install-dir", install.to_str().unwrap()]);
    let output = command.output().unwrap();
    assert_success(&output);
    let text = output_text(&output);
    assert!(!text.contains("noncanonical-secret-canary"));
    assert!(install.join("telltale").exists());
}

#[test]
fn inherited_generic_service_policy_is_allowed_when_effective_contract_is_canonical() {
    let temp = tempdir().unwrap();
    let name = format!("telltale-v0.5.0-{}.tar.gz", target());
    let selected = archive(temp.path(), &name, "0.5.0", None);
    let metadata = release_metadata(temp.path(), "v0.5.0");
    let sums = temp.path().join("SHA256SUMS");
    checksum(&selected, &sums);
    let install = temp.path().join("home/bin");
    let inherited_dropin = temp.path().join("systemd user/service.d/timeout-stop.conf");
    fs::create_dir_all(inherited_dropin.parent().unwrap()).unwrap();
    regular_file(
        &inherited_dropin,
        b"[Service]\nTimeoutStopFailureMode=abort\n",
        0o644,
    );
    let mut command = installer_command(
        temp.path(),
        &metadata,
        temp.path(),
        Some(&sums),
        &tools(temp.path(), true),
    );
    command
        .env("FAKE_DROP_IN_UNIT", "telltale-scan.service")
        .env(
            "FAKE_DROP_IN_PATHS",
            inherited_dropin.to_string_lossy().replace(' ', "\\x20"),
        )
        .args(["--no-timer", "--install-dir", install.to_str().unwrap()]);
    let output = command.output().unwrap();
    assert_success(&output);
    assert!(install.join("telltale").is_file());
    let calls = fs::read_to_string(temp.path().join("systemctl.log")).unwrap();
    assert!(calls.contains("show telltale-scan.service --property=FragmentPath --value"));
    assert!(calls.contains("show telltale-scan.timer --property=FragmentPath --value"));
}

#[test]
fn inherited_unicode_service_policy_with_escaped_utf8_path_is_allowed() {
    let temp = tempdir().unwrap();
    let name = format!("telltale-v0.5.0-{}.tar.gz", target());
    let selected = archive(temp.path(), &name, "0.5.0", None);
    let metadata = release_metadata(temp.path(), "v0.5.0");
    let sums = temp.path().join("SHA256SUMS");
    checksum(&selected, &sums);
    let install = temp.path().join("home/bin");
    let inherited_dropin = temp
        .path()
        .join("global/Ѐ😀/service.d/timeout\\policy.conf");
    fs::create_dir_all(inherited_dropin.parent().unwrap()).unwrap();
    regular_file(
        &inherited_dropin,
        b"[Service]\nTimeoutStopFailureMode=abort\n",
        0o644,
    );
    let escaped_dropin = inherited_dropin
        .to_str()
        .unwrap()
        .replace('Ѐ', r"\xd0\x80")
        .replace('😀', r"\xf0\x9f\x98\x80")
        .replace("\\policy", r"\x5cpolicy");
    let mut command = installer_command(
        temp.path(),
        &metadata,
        temp.path(),
        Some(&sums),
        &tools(temp.path(), true),
    );
    command
        .env("FAKE_DROP_IN_UNIT", "telltale-scan.service")
        .env("FAKE_DROP_IN_PATHS", escaped_dropin)
        .env("FAKE_PROPERTY_MUTATION", "empty")
        .args(["--no-timer", "--install-dir", install.to_str().unwrap()]);
    let output = command.output().unwrap();
    assert_success(&output);
    assert!(install.join("telltale").is_file());
}

#[test]
fn malformed_or_invalid_dropin_path_escapes_fail_closed() {
    for escaped_name in [r"benign\q1.conf", r"benign\x.conf", r"benign\xff.conf"] {
        let temp = tempdir().unwrap();
        let name = format!("telltale-v0.5.0-{}.tar.gz", target());
        let selected = archive(temp.path(), &name, "0.5.0", None);
        let metadata = release_metadata(temp.path(), "v0.5.0");
        let sums = temp.path().join("SHA256SUMS");
        checksum(&selected, &sums);
        let decoy = temp.path().join(format!("global/service.d/{escaped_name}"));
        fs::create_dir_all(decoy.parent().unwrap()).unwrap();
        regular_file(&decoy, b"[Service]\nTimeoutStopFailureMode=abort\n", 0o644);
        let install = temp.path().join("home/bin");
        let mut command = installer_command(
            temp.path(),
            &metadata,
            temp.path(),
            Some(&sums),
            &tools(temp.path(), true),
        );
        command
            .env("FAKE_DROP_IN_UNIT", "telltale-scan.service")
            .env("FAKE_DROP_IN_PATHS", decoy.to_str().unwrap())
            .env("FAKE_PROPERTY_MUTATION", "empty")
            .args(["--no-timer", "--install-dir", install.to_str().unwrap()]);
        let output = command.output().unwrap();
        assert!(!output.status.success(), "{escaped_name} must fail");
        assert!(!install.join("telltale").exists());
    }
}

#[test]
fn shell_quoted_systemd_environment_values_are_accepted() {
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
    command
        .env("FAKE_PROPERTY_MUTATION", "quoted-values")
        .args(["--no-timer", "--install-dir", install.to_str().unwrap()]);
    let output = command.output().unwrap();
    assert_success(&output);
    assert!(install.join("telltale").is_file());
}

#[test]
fn absent_optional_environment_file_accepts_empty_effective_report_after_declaration_proof() {
    let temp = tempdir().unwrap();
    let name = format!("telltale-v0.5.0-{}.tar.gz", target());
    let selected = archive(temp.path(), &name, "0.5.0", None);
    let metadata = release_metadata(temp.path(), "v0.5.0");
    let sums = temp.path().join("SHA256SUMS");
    checksum(&selected, &sums);
    let install = temp.path().join("home/bin");
    let installer_tmpdir = temp.path().join("installer tmp");
    fs::create_dir_all(&installer_tmpdir).unwrap();
    let mut command = installer_command(
        temp.path(),
        &metadata,
        temp.path(),
        Some(&sums),
        &tools(temp.path(), true),
    );
    command
        .env("TMPDIR", &installer_tmpdir)
        .env("FAKE_PROPERTY_MUTATION", "empty")
        .args(["--no-timer", "--install-dir", install.to_str().unwrap()]);
    let output = command.output().unwrap();
    assert_success(&output);
    assert!(
        !temp
            .path()
            .join("home/.config/telltale/telltale.env")
            .exists()
    );
    assert!(install.join("telltale").is_file());
    let service = fs::read_to_string(
        temp.path()
            .join("home/.config/systemd/user/telltale-scan.service"),
    )
    .unwrap();
    assert!(service.contains(&format!(
        "EnvironmentFile=-\"{}\"",
        temp.path()
            .join("home/.config/telltale/telltale.env")
            .display()
    )));
}

#[test]
fn lexically_noncanonical_home_accepts_exact_canonical_implicit_working_directory() {
    let temp = tempdir().unwrap();
    let name = format!("telltale-v0.5.0-{}.tar.gz", target());
    let selected = archive(temp.path(), &name, "0.5.0", None);
    let metadata = release_metadata(temp.path(), "v0.5.0");
    let sums = temp.path().join("SHA256SUMS");
    checksum(&selected, &sums);
    let install = temp.path().join("home/bin");
    let lexical_home = format!("{}/./", temp.path().join("home").display());
    let mut command = installer_command(
        temp.path(),
        &metadata,
        temp.path(),
        Some(&sums),
        &tools(temp.path(), true),
    );
    command.env("HOME", lexical_home).args([
        "--no-timer",
        "--install-dir",
        install.to_str().unwrap(),
    ]);
    let output = command.output().unwrap();
    assert_success(&output);
    let service = fs::read_to_string(
        temp.path()
            .join("home/.config/systemd/user/telltale-scan.service"),
    )
    .unwrap();
    assert!(
        !service
            .lines()
            .any(|line| line.starts_with("WorkingDirectory="))
    );
}

#[test]
fn present_private_optional_environment_file_accepts_exact_effective_report() {
    let temp = tempdir().unwrap();
    let name = format!("telltale-v0.5.0-{}.tar.gz", target());
    let selected = archive(temp.path(), &name, "0.5.0", None);
    let metadata = release_metadata(temp.path(), "v0.5.0");
    let sums = temp.path().join("SHA256SUMS");
    checksum(&selected, &sums);
    let env_path = temp.path().join("home/.config/telltale/telltale.env");
    fs::create_dir_all(env_path.parent().unwrap()).unwrap();
    regular_file(&env_path, b"TELLTALE_SCAN_ROOT=/synthetic\n", 0o600);
    let install = temp.path().join("home/bin");
    let mut command = installer_command(
        temp.path(),
        &metadata,
        temp.path(),
        Some(&sums),
        &tools(temp.path(), true),
    );
    command.args(["--no-timer", "--install-dir", install.to_str().unwrap()]);
    let output = command.output().unwrap();
    assert_success(&output);
    assert!(install.join("telltale").is_file());
    assert_eq!(
        fs::metadata(env_path).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

#[test]
fn effective_environment_file_reports_reject_unknown_alternate_and_extra_forms() {
    for mutation in ["alternate", "extra", "reset", "unknown"] {
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
        command.env("FAKE_PROPERTY_MUTATION", mutation).args([
            "--no-timer",
            "--install-dir",
            install.to_str().unwrap(),
        ]);
        let output = command.output().unwrap();
        assert!(!output.status.success(), "{mutation} must fail");
        assert!(output_text(&output).contains("before binary replacement"));
        assert!(!install.join("telltale").exists());
    }
}

#[test]
fn canonical_service_declaration_omission_or_mutation_fails_closed() {
    for mutation in ["omit", "alternate"] {
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
        command
            .env("FAKE_MUTATE_GENERATED_UNIT", mutation)
            .env("FAKE_PROPERTY_MUTATION", "empty")
            .args(["--no-timer", "--install-dir", install.to_str().unwrap()]);
        let output = command.output().unwrap();
        assert!(!output.status.success(), "{mutation} must fail");
        assert!(output_text(&output).contains("generated canonical service declaration"));
        assert!(!install.join("telltale").exists());
    }
}

#[test]
fn base_working_directory_declarations_fail_before_staging() {
    for (case_name, declaration) in [
        ("absolute", "/tmp".to_owned()),
        ("same-home", String::new()),
        ("tilde", "~".to_owned()),
        ("missing-ok", "-/tmp".to_owned()),
        ("reset", String::new()),
        ("specifier", "%h".to_owned()),
        ("malformed-continuation", "/tmp\\\ncontinued".to_owned()),
    ] {
        let temp = tempdir().unwrap();
        let name = format!("telltale-v0.5.0-{}.tar.gz", target());
        let selected = archive(temp.path(), &name, "0.5.0", None);
        let metadata = release_metadata(temp.path(), "v0.5.0");
        let sums = temp.path().join("SHA256SUMS");
        checksum(&selected, &sums);
        let units = temp.path().join("home/.config/systemd/user");
        fs::create_dir_all(&units).unwrap();
        let declaration = if case_name == "same-home" {
            temp.path().join("home").display().to_string()
        } else {
            declaration
        };
        let service = rc5_rc6_generated_service(
            &temp.path().join("home/bin"),
            &temp.path().join("home/.local/state"),
            &temp.path().join("home/.config"),
        )
        .replacen(
            "[Service]\n",
            &format!("[Service]\nWorkingDirectory={declaration}\n"),
            1,
        );
        regular_file(
            &units.join("telltale-scan.service"),
            service.as_bytes(),
            0o644,
        );
        let mut command = installer_command(
            temp.path(),
            &metadata,
            temp.path(),
            Some(&sums),
            &tools(temp.path(), true),
        );
        command.args([
            "--no-timer",
            "--install-dir",
            temp.path().join("home/bin").to_str().unwrap(),
        ]);
        let output = command.output().unwrap();
        assert!(!output.status.success(), "{case_name} must fail");
        assert!(output_text(&output).contains("effective canonical systemd policy"));
        assert_eq!(
            fs::read(units.join("telltale-scan.service")).unwrap(),
            service.as_bytes()
        );
        assert!(!temp.path().join("home/bin/telltale").exists());
        assert!(
            !fs::read_to_string(temp.path().join("events.log"))
                .unwrap_or_default()
                .contains("enable --now")
        );
    }
}

#[test]
fn inherited_working_directory_declarations_fail_closed_in_type_and_global_policy() {
    let cases: [(&str, &[u8], u32); 10] = [
        ("same-home", b"[Service]\nWorkingDirectory=/tmp\n", 0o644),
        ("tilde", b"[Service]\nWorkingDirectory=~\n", 0o644),
        ("missing-ok", b"[Service]\nWorkingDirectory=-/tmp\n", 0o644),
        ("reset", b"[Service]\nWorkingDirectory=\n", 0o644),
        ("specifier", b"[Service]\nWorkingDirectory=%h\n", 0o644),
        (
            "malformed-continuation",
            b"[Service]\nWorkingDirectory=/tmp\\\ncontinued\n",
            0o644,
        ),
        (
            "ambiguous",
            b"[Service]\nWorkingDirectory=/tmp\nWorkingDirectory=/other\n",
            0o644,
        ),
        (
            "unicode-control",
            b"[Service]\nWorkingDirectory=/tmp\x01\n",
            0o644,
        ),
        (
            "invalid-utf8",
            b"[Service]\nWorkingDirectory=/tmp\xff\n",
            0o644,
        ),
        ("unreadable", b"[Service]\nWorkingDirectory=/tmp\n", 0o000),
    ];
    for scope in ["global/service.d", "systemd user/service.d"] {
        for (case_name, contents, mode) in cases {
            let temp = tempdir().unwrap();
            let name = format!("telltale-v0.5.0-{}.tar.gz", target());
            let selected = archive(temp.path(), &name, "0.5.0", None);
            let metadata = release_metadata(temp.path(), "v0.5.0");
            let sums = temp.path().join("SHA256SUMS");
            checksum(&selected, &sums);
            let dropin = temp.path().join(scope).join(format!("{case_name}.conf"));
            fs::create_dir_all(dropin.parent().unwrap()).unwrap();
            let contents = if case_name == "same-home" {
                format!(
                    "[Service]\nWorkingDirectory={}\n",
                    temp.path().join("home").display()
                )
                .into_bytes()
            } else {
                contents.to_vec()
            };
            regular_file(&dropin, &contents, mode);
            let mut command = installer_command(
                temp.path(),
                &metadata,
                temp.path(),
                Some(&sums),
                &tools(temp.path(), true),
            );
            command
                .env("FAKE_DROP_IN_UNIT", "telltale-scan.service")
                .env(
                    "FAKE_DROP_IN_PATHS",
                    dropin.to_string_lossy().replace(' ', r"\x20"),
                )
                .args([
                    "--no-timer",
                    "--install-dir",
                    temp.path().join("home/bin").to_str().unwrap(),
                ]);
            let output = command.output().unwrap();
            assert!(!output.status.success(), "{scope}/{case_name} must fail");
            assert!(output_text(&output).contains("effective canonical systemd policy"));
            assert!(!temp.path().join("home/bin/telltale").exists());
            let events = fs::read_to_string(temp.path().join("events.log")).unwrap_or_default();
            assert!(!events.contains(" disable ") && !events.contains(" stop "));
        }
    }
}

#[test]
fn inherited_same_home_working_directory_is_rejected_before_quiescing_active_units() {
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
    let service = rc5_rc6_generated_service(
        &install,
        &temp.path().join("home/.local/state"),
        &temp.path().join("home/.config"),
    );
    let timer = rc4_generated_timer();
    regular_file(
        &units.join("telltale-scan.service"),
        service.as_bytes(),
        0o644,
    );
    regular_file(&units.join("telltale-scan.timer"), timer.as_bytes(), 0o644);

    let inherited_dropin = temp.path().join("systemd user/service.d/same-home.conf");
    fs::create_dir_all(inherited_dropin.parent().unwrap()).unwrap();
    regular_file(
        &inherited_dropin,
        format!(
            "[Service]\nWorkingDirectory={}\n",
            temp.path().join("home").display()
        )
        .as_bytes(),
        0o644,
    );

    let initial_state = b"telltale-scan.service 1 1 1\ntelltale-scan.timer 1 1 1\n";
    fs::write(temp.path().join("systemctl.state"), initial_state).unwrap();

    let mut command = installer_command(
        temp.path(),
        &metadata,
        temp.path(),
        Some(&sums),
        &tools(temp.path(), true),
    );
    command
        .env("FAKE_DROP_IN_UNIT", "telltale-scan.service")
        .env(
            "FAKE_DROP_IN_PATHS",
            inherited_dropin.to_string_lossy().replace(' ', r"\x20"),
        )
        .env("FAKE_PROPERTY_MUTATION", "empty")
        .args(["--no-timer", "--install-dir", install.to_str().unwrap()]);
    let output = command.output().unwrap();

    assert!(!output.status.success());
    assert!(
        output_text(&output)
            .contains("could not safely validate effective canonical systemd policy")
    );
    assert_eq!(
        fs::read(temp.path().join("systemctl.state")).unwrap(),
        initial_state
    );
    assert_eq!(
        fs::read(units.join("telltale-scan.service")).unwrap(),
        service.as_bytes()
    );
    assert_eq!(
        fs::read(units.join("telltale-scan.timer")).unwrap(),
        timer.as_bytes()
    );
    assert!(!install.join("telltale").exists());
    let install_staging = fs::read_dir(&install)
        .unwrap()
        .filter_map(Result::ok)
        .any(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with(".telltale-install.")
        });
    let unit_staging = fs::read_dir(&units)
        .unwrap()
        .filter_map(Result::ok)
        .any(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with(".telltale-units.")
        });
    assert!(!install_staging);
    assert!(!unit_staging);

    let events = fs::read_to_string(temp.path().join("events.log")).unwrap();
    assert_eq!(
        events
            .lines()
            .filter(|line| *line == "systemctl:--user daemon-reload")
            .count(),
        1,
        "parser rejection must happen during the pre-mutation validation pass: {events}"
    );
    assert!(!events.contains(" disable "));
    assert!(!events.contains(" stop "));
    assert!(!events.contains("enable --now"));
}

#[test]
fn prevalidation_failure_quiesces_only_retained_uncommitted_transactions() {
    for (case_name, prior_phase, should_quiesce) in [
        ("fresh", None, false),
        ("staging", Some("staging"), true),
        ("schedules", Some("schedules"), true),
        ("units", Some("units"), true),
        ("smoke", Some("smoke"), true),
        ("activation", Some("activation"), true),
        ("failed", Some("failed"), true),
        ("recovered", Some("recovered"), true),
    ] {
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
        let service = rc5_rc6_generated_service(
            &install,
            &temp.path().join("home/.local/state"),
            &temp.path().join("home/.config"),
        );
        regular_file(
            &units.join("telltale-scan.service"),
            service.as_bytes(),
            0o644,
        );
        regular_file(
            &units.join("telltale-scan.timer"),
            rc4_generated_timer().as_bytes(),
            0o644,
        );

        let initial_state = b"telltale-scan.service 1 1 1\ntelltale-scan.timer 1 1 1\n";
        fs::write(temp.path().join("systemctl.state"), initial_state).unwrap();
        if let Some(phase) = prior_phase {
            let journal = temp
                .path()
                .join("home/.local/state/telltale/installer-transaction.json");
            fs::create_dir_all(journal.parent().unwrap()).unwrap();
            regular_file(
                &journal,
                format!(
                    "{{\n  \"version\": \"1.0\",\n  \"phase\": \"{phase}\",\n  \"identity\": \"telltale\",\n  \"schedule\": \"telltale-scan.timer\"\n}}\n"
                )
                .as_bytes(),
                0o600,
            );
        }

        let mut command = installer_command(
            temp.path(),
            &metadata,
            temp.path(),
            Some(&sums),
            &tools(temp.path(), true),
        );
        command.env("FAKE_PROPERTY_MUTATION", "path").args([
            "--no-timer",
            "--install-dir",
            install.to_str().unwrap(),
        ]);
        let output = command.output().unwrap();

        assert!(!output.status.success(), "{case_name} must fail");
        assert!(
            output_text(&output)
                .contains("could not safely validate effective canonical systemd policy")
        );
        assert!(!install.join("telltale").exists());

        let events = fs::read_to_string(temp.path().join("events.log")).unwrap();
        if should_quiesce {
            assert_eq!(
                fs::read(temp.path().join("systemctl.state")).unwrap(),
                b"telltale-scan.service 1 0 0\ntelltale-scan.timer 1 0 0\n"
            );
            for unit in ["telltale-scan.service", "telltale-scan.timer"] {
                assert!(
                    events.contains(&format!("systemctl:--user disable {unit}")),
                    "{case_name} did not disable {unit}: {events}"
                );
                assert!(
                    events.contains(&format!("systemctl:--user stop {unit}")),
                    "{case_name} did not stop {unit}: {events}"
                );
            }
        } else {
            assert_eq!(
                fs::read(temp.path().join("systemctl.state")).unwrap(),
                initial_state
            );
            assert!(
                !events.contains(" disable ") && !events.contains(" stop "),
                "fresh pre-validation failure must not quiesce active units: {events}"
            );
        }
        assert!(!events.contains("enable --now"));
    }
}

#[test]
fn unit_specific_working_directory_dropin_is_rejected_before_staging() {
    let temp = tempdir().unwrap();
    let name = format!("telltale-v0.5.0-{}.tar.gz", target());
    let selected = archive(temp.path(), &name, "0.5.0", None);
    let metadata = release_metadata(temp.path(), "v0.5.0");
    let sums = temp.path().join("SHA256SUMS");
    checksum(&selected, &sums);
    let unit_dir = temp.path().join("home/.config/systemd/user");
    let dropin = unit_dir.join("telltale-scan.service.d/working-directory.conf");
    fs::create_dir_all(dropin.parent().unwrap()).unwrap();
    regular_file(&dropin, b"[Service]\nWorkingDirectory=/tmp\n", 0o644);
    let mut command = installer_command(
        temp.path(),
        &metadata,
        temp.path(),
        Some(&sums),
        &tools(temp.path(), true),
    );
    command.args([
        "--no-timer",
        "--install-dir",
        temp.path().join("home/bin").to_str().unwrap(),
    ]);
    let output = command.output().unwrap();
    assert!(!output.status.success());
    assert!(output_text(&output).contains("effective canonical systemd policy"));
    assert_eq!(
        fs::read(&dropin).unwrap(),
        b"[Service]\nWorkingDirectory=/tmp\n"
    );
    assert!(!temp.path().join("home/bin/telltale").exists());
}

#[test]
fn post_stage_working_directory_failure_restores_units_without_binary_or_activation() {
    let temp = tempdir().unwrap();
    let name = format!("telltale-v0.5.0-{}.tar.gz", target());
    let selected = archive(temp.path(), &name, "0.5.0", None);
    let metadata = release_metadata(temp.path(), "v0.5.0");
    let sums = temp.path().join("SHA256SUMS");
    checksum(&selected, &sums);
    let install = temp.path().join("home/bin");
    let units = temp.path().join("home/.config/systemd/user");
    let state = temp
        .path()
        .join("home/.local/state/telltale/telltale-state.json");
    fs::create_dir_all(&install).unwrap();
    fs::create_dir_all(&units).unwrap();
    fs::create_dir_all(state.parent().unwrap()).unwrap();
    telltale_binary(&install.join("telltale"), "0.4.0", false);
    let old_binary = fs::read(install.join("telltale")).unwrap();
    let old_service = rc5_rc6_generated_service(
        &install,
        &temp.path().join("home/.local/state"),
        &temp.path().join("home/.config"),
    );
    let old_timer = rc4_generated_timer();
    regular_file(
        &units.join("telltale-scan.service"),
        old_service.as_bytes(),
        0o644,
    );
    regular_file(
        &units.join("telltale-scan.timer"),
        old_timer.as_bytes(),
        0o644,
    );
    regular_file(&state, b"retained state\n", 0o600);

    let mut command = installer_command(
        temp.path(),
        &metadata,
        temp.path(),
        Some(&sums),
        &tools(temp.path(), true),
    );
    command.env("FAKE_POST_STAGE_WD_MUTATION", "1").args([
        "--no-timer",
        "--install-dir",
        install.to_str().unwrap(),
    ]);
    let output = command.output().unwrap();
    assert!(!output.status.success());
    assert!(output_text(&output).contains("before binary replacement"));
    assert_eq!(fs::read(install.join("telltale")).unwrap(), old_binary);
    assert_eq!(
        fs::read(units.join("telltale-scan.service")).unwrap(),
        old_service.as_bytes()
    );
    assert_eq!(
        fs::read(units.join("telltale-scan.timer")).unwrap(),
        old_timer.as_bytes()
    );
    assert_eq!(fs::read(&state).unwrap(), b"retained state\n");
    let events = fs::read_to_string(temp.path().join("events.log")).unwrap_or_default();
    assert!(!events.contains("enable --now"));
}

#[test]
fn inherited_environment_policy_is_rejected_even_when_referenced_file_is_absent() {
    for (case_name, contents, mode) in [
        (
            "environment-file",
            "[Service]\nEnvironmentFile=-/tmp/missing-telltale.env\n",
            0o644,
        ),
        ("reset", "[Service]\nEnvironmentFile=\n", 0o644),
        (
            "environment-injection",
            "[Service]\nEnvironment=INJECTED=1\n",
            0o644,
        ),
        (
            "continuation",
            "[Service]\nTimeoutStopFailureMode=ab\\\nort\n",
            0o644,
        ),
        ("malformed", "[Service]\nnot-a-directive\n", 0o644),
        (
            "unreadable",
            "[Service]\nTimeoutStopFailureMode=abort\n",
            0o000,
        ),
    ] {
        let temp = tempdir().unwrap();
        let name = format!("telltale-v0.5.0-{}.tar.gz", target());
        let selected = archive(temp.path(), &name, "0.5.0", None);
        let metadata = release_metadata(temp.path(), "v0.5.0");
        let sums = temp.path().join("SHA256SUMS");
        checksum(&selected, &sums);
        let dropin = temp
            .path()
            .join(format!("global/service.d/{case_name}.conf"));
        fs::create_dir_all(dropin.parent().unwrap()).unwrap();
        regular_file(&dropin, contents.as_bytes(), mode);
        let install = temp.path().join("home/bin");
        let mut command = installer_command(
            temp.path(),
            &metadata,
            temp.path(),
            Some(&sums),
            &tools(temp.path(), true),
        );
        command
            .env("FAKE_DROP_IN_UNIT", "telltale-scan.service")
            .env("FAKE_DROP_IN_PATHS", dropin.to_str().unwrap())
            .env("FAKE_PROPERTY_MUTATION", "empty")
            .args(["--no-timer", "--install-dir", install.to_str().unwrap()]);
        let output = command.output().unwrap();
        assert!(!output.status.success(), "{case_name} must fail");
        assert!(
            output_text(&output)
                .contains("could not safely validate effective canonical systemd policy")
        );
        assert!(!install.join("telltale").exists());
    }
}

#[test]
fn escaped_whitespace_inherited_environment_file_is_rejected() {
    let temp = tempdir().unwrap();
    let name = format!("telltale-v0.5.0-{}.tar.gz", target());
    let selected = archive(temp.path(), &name, "0.5.0", None);
    let metadata = release_metadata(temp.path(), "v0.5.0");
    let sums = temp.path().join("SHA256SUMS");
    checksum(&selected, &sums);
    let dropin = temp
        .path()
        .join("global policy/service.d/environment-file.conf");
    let escaped_dropin = temp
        .path()
        .join(r"global\x20policy/service.d/environment-file.conf");
    fs::create_dir_all(dropin.parent().unwrap()).unwrap();
    fs::create_dir_all(escaped_dropin.parent().unwrap()).unwrap();
    regular_file(
        &dropin,
        b"[Service]\nEnvironmentFile=-/tmp/missing-telltale.env\n",
        0o644,
    );
    regular_file(
        &escaped_dropin,
        b"[Service]\nTimeoutStopFailureMode=abort\n",
        0o644,
    );
    let install = temp.path().join("home/bin");
    let mut command = installer_command(
        temp.path(),
        &metadata,
        temp.path(),
        Some(&sums),
        &tools(temp.path(), true),
    );
    command
        .env("FAKE_DROP_IN_UNIT", "telltale-scan.service")
        .env(
            "FAKE_DROP_IN_PATHS",
            dropin.to_string_lossy().replace(' ', "\\x20"),
        )
        .env("FAKE_PROPERTY_MUTATION", "empty")
        .args(["--no-timer", "--install-dir", install.to_str().unwrap()]);
    let output = command.output().unwrap();
    assert!(!output.status.success());
    assert!(
        output_text(&output)
            .contains("could not safely validate effective canonical systemd policy")
    );
    assert!(!install.join("telltale").exists());
}

#[test]
fn unknown_dropin_hex_escape_is_rejected_before_inspecting_literal_decoy() {
    let temp = tempdir().unwrap();
    let name = format!("telltale-v0.5.0-{}.tar.gz", target());
    let selected = archive(temp.path(), &name, "0.5.0", None);
    let metadata = release_metadata(temp.path(), "v0.5.0");
    let sums = temp.path().join("SHA256SUMS");
    checksum(&selected, &sums);
    let decoy = temp.path().join(r"global/service.d/benign\x01.conf");
    fs::create_dir_all(decoy.parent().unwrap()).unwrap();
    regular_file(&decoy, b"[Service]\nTimeoutStopFailureMode=abort\n", 0o644);
    let install = temp.path().join("home/bin");
    let mut command = installer_command(
        temp.path(),
        &metadata,
        temp.path(),
        Some(&sums),
        &tools(temp.path(), true),
    );
    command
        .env("FAKE_DROP_IN_UNIT", "telltale-scan.service")
        .env("FAKE_DROP_IN_PATHS", decoy.to_str().unwrap())
        .env("FAKE_PROPERTY_MUTATION", "empty")
        .args(["--no-timer", "--install-dir", install.to_str().unwrap()]);
    let output = command.output().unwrap();
    assert!(!output.status.success());
    assert!(
        output_text(&output)
            .contains("could not safely validate effective canonical systemd policy")
    );
    assert!(!install.join("telltale").exists());
}

#[test]
fn unit_prefix_and_ambiguous_dropins_fail_closed_before_binary_replacement() {
    for dropins in [
        "/run/user/1000/systemd/user/telltale-.service.d/override.conf",
        "/run/user/1000/systemd/user/telltale-scan-.service.d/override.conf",
        "/run/user/1000/systemd/user/service.d/timeout.conf /run/user/1000/systemd/user/unknown.conf",
    ] {
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
        command
            .env("FAKE_DROP_IN_UNIT", "telltale-scan.service")
            .env("FAKE_DROP_IN_PATHS", dropins)
            .args(["--no-timer", "--install-dir", install.to_str().unwrap()]);
        let output = command.output().unwrap();
        assert!(!output.status.success());
        assert!(
            output_text(&output)
                .contains("could not safely validate effective canonical systemd policy")
        );
        assert!(!install.join("telltale").exists());
    }
}

#[test]
fn effective_service_contract_mutations_fail_closed_before_binary_replacement() {
    for mutation in [
        "execstart",
        "execstart-ignore",
        "execstart-flags",
        "execstart-extra",
        "hook",
        "stop-pre",
        "reload-post",
        "environment",
        "env-file",
        "supplementary",
        "pass-environment",
        "unset-environment",
        "path",
        "identity",
        "type",
        "security",
        "dynamic-user",
        "private-users",
        "alternate-missing-ok",
        "bare-home",
        "tilde",
        "bang-tilde",
        "unknown-prefix",
        "malformed",
        "wd-empty",
        "canonical-home",
    ] {
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
        command.env("FAKE_PROPERTY_MUTATION", mutation).args([
            "--no-timer",
            "--install-dir",
            install.to_str().unwrap(),
        ]);
        let output = command.output().unwrap();
        assert!(!output.status.success(), "mutation {mutation} must fail");
        assert!(output_text(&output).contains("before binary replacement"));
        assert!(!install.join("telltale").exists());
        assert!(
            !fs::read_to_string(temp.path().join("events.log"))
                .unwrap()
                .contains("enable --now")
        );
    }
}

#[test]
fn effective_timer_contract_is_validated_independently() {
    for mutation in [
        "timer-target",
        "timer-cadence",
        "timer-extra",
        "timer-calendar",
        "timer-persistence",
        "timer-boolean",
    ] {
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
        command.env("FAKE_PROPERTY_MUTATION", mutation).args([
            "--no-timer",
            "--install-dir",
            install.to_str().unwrap(),
        ]);
        let output = command.output().unwrap();
        assert!(
            !output.status.success(),
            "timer mutation {mutation} must fail"
        );
        assert!(output_text(&output).contains("before binary replacement"));
        assert!(!install.join("telltale").exists());
    }
}

#[test]
fn checksum_failure_and_unexpected_archive_member_are_fail_closed() {
    let temp = tempdir().unwrap();
    let name = format!("telltale-v0.5.0-{}.tar.gz", target());
    let _selected = archive(temp.path(), &name, "0.5.0", None);
    let metadata = release_metadata(temp.path(), "v0.5.0");
    let output = run_release(temp.path(), &metadata, temp.path(), None, &[]);
    assert!(!output.status.success());
    assert!(output_text(&output).contains("SHA256SUMS"));
    assert!(!temp.path().join("home/bin/telltale").exists());
    assert!(!temp.path().join("home/.telltale-installer.lock").exists());
    assert!(!temp.path().join("systemctl.log").exists());

    let bad = archive(
        temp.path(),
        &name,
        "0.5.0",
        Some("config/examples/unexpected-asset.txt"),
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
    assert!(output_text(&output).contains("exact canonical nine-member bundle"));
    assert!(!temp.path().join("home/.telltale-installer.lock").exists());
    assert!(!temp.path().join("systemctl.log").exists());
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
    assert!(
        !traversal
            .path()
            .join("home/.telltale-installer.lock")
            .exists()
    );
    assert!(!traversal.path().join("systemctl.log").exists());

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
fn source_build_is_pinned_and_produces_only_canonical_binary() {
    let temp = tempdir().unwrap();
    let tag = "v0.5.0-rc.1";
    let name = format!("telltale-{tag}-{}.tar.gz", target());
    let selected = archive(temp.path(), &name, "0.5.0-rc.1", None);
    let sums = temp.path().join("SHA256SUMS");
    checksum(&selected, &sums);
    let metadata = release_metadata_with_flags(temp.path(), tag, false, true);
    let tools = tools(temp.path(), true);
    let cargo_log = temp.path().join("cargo.log");
    let source_binary = temp.path().join("source-telltale");
    telltale_binary(&source_binary, "0.5.0-rc.1", false);
    executable(
        &tools.join("cargo"),
        &format!(
            "#!/bin/sh\nprintf '%s\\n' \"$*\" > '{}'\nroot=''\nwhile [ $# -gt 0 ]; do if [ \"$1\" = \"--root\" ]; then root=$2; shift 2; else shift; fi; done\nmkdir -p \"$root/bin\"\ncp '{}' \"$root/bin/telltale\"\n",
            cargo_log.display(),
            source_binary.display()
        ),
    );
    let mut command = installer_command(temp.path(), &metadata, temp.path(), Some(&sums), &tools);
    let git_log = configure_fake_git(
        &mut command,
        temp.path(),
        tag,
        "1111111111111111111111111111111111111111",
        Some("2222222222222222222222222222222222222222"),
    );
    command.args([
        "--from-source",
        "--release-tag",
        tag,
        "--install-dir",
        temp.path().join("home/bin").to_str().unwrap(),
    ]);
    let output = command.output().unwrap();
    assert_success(&output);
    let args = fs::read_to_string(cargo_log).unwrap();
    assert!(
        args.contains("--rev 2222222222222222222222222222222222222222")
            && args.contains("--locked")
            && args.contains("--bin telltale")
    );
    assert!(!args.contains("--tag"));
    assert_fake_git_tag_refs(&git_log, tag);
    assert!(temp.path().join("home/bin/telltale").is_file());
}

#[test]
fn source_build_wrong_binary_version_fails_before_installer_mutation() {
    let temp = tempdir().unwrap();
    let tag = "v0.5.0-rc.1";
    let name = format!("telltale-{tag}-{}.tar.gz", target());
    let selected = archive(temp.path(), &name, "0.5.0-rc.1", None);
    let sums = temp.path().join("SHA256SUMS");
    checksum(&selected, &sums);
    let metadata = release_metadata_with_flags(temp.path(), tag, false, true);
    let tools = tools(temp.path(), true);
    let source_binary = temp.path().join("wrong-source-telltale");
    telltale_binary(&source_binary, "0.5.0", false);
    executable(
        &tools.join("cargo"),
        &format!(
            "#!/bin/sh\nroot=''\nwhile [ $# -gt 0 ]; do if [ \"$1\" = \"--root\" ]; then root=$2; shift 2; else shift; fi; done\nmkdir -p \"$root/bin\"\ncp '{}' \"$root/bin/telltale\"\n",
            source_binary.display()
        ),
    );

    let install = temp.path().join("home/bin");
    let mut command = installer_command(temp.path(), &metadata, temp.path(), Some(&sums), &tools);
    let git_log = configure_fake_git(
        &mut command,
        temp.path(),
        tag,
        "3333333333333333333333333333333333333333",
        None,
    );
    command.args([
        "--from-source",
        "--release-tag",
        tag,
        "--no-timer",
        "--install-dir",
        install.to_str().unwrap(),
    ]);
    let output = command.output().unwrap();
    assert!(!output.status.success());
    assert!(output_text(&output).contains("binary version does not match"));
    assert!(!temp.path().join("home/.telltale-installer.lock").exists());
    assert!(!install.exists());
    assert!(!temp.path().join("systemctl.log").exists());
    assert_fake_git_tag_refs(&git_log, tag);
}

#[test]
fn source_build_failure_happens_before_installer_mutation() {
    let temp = tempdir().unwrap();
    let tag = "v0.5.0-rc.1";
    let name = format!("telltale-{tag}-{}.tar.gz", target());
    let selected = archive(temp.path(), &name, "0.5.0-rc.1", None);
    let sums = temp.path().join("SHA256SUMS");
    checksum(&selected, &sums);
    let metadata = release_metadata_with_flags(temp.path(), tag, false, true);
    let tools = tools(temp.path(), true);
    executable(&tools.join("cargo"), "#!/bin/sh\nexit 42\n");

    let install = temp.path().join("home/bin");
    let mut command = installer_command(temp.path(), &metadata, temp.path(), Some(&sums), &tools);
    let git_log = configure_fake_git(
        &mut command,
        temp.path(),
        tag,
        "4444444444444444444444444444444444444444",
        None,
    );
    command.args([
        "--from-source",
        "--release-tag",
        tag,
        "--no-timer",
        "--install-dir",
        install.to_str().unwrap(),
    ]);
    let output = command.output().unwrap();
    assert!(!output.status.success());
    assert!(output_text(&output).contains("cargo install failed"));
    assert!(!temp.path().join("home/.telltale-installer.lock").exists());
    assert!(!install.exists());
    assert!(!temp.path().join("systemctl.log").exists());
    assert_fake_git_tag_refs(&git_log, tag);
}

#[test]
fn default_latest_source_build_failure_happens_before_installer_mutation() {
    let temp = tempdir().unwrap();
    let tag = "v0.5.0";
    let name = format!("telltale-{tag}-{}.tar.gz", target());
    let selected = archive(temp.path(), &name, "0.5.0", None);
    let sums = temp.path().join("SHA256SUMS");
    checksum(&selected, &sums);
    let metadata = release_metadata(temp.path(), tag);
    let tools = tools(temp.path(), true);
    executable(&tools.join("cargo"), "#!/bin/sh\nexit 42\n");

    let install = temp.path().join("home/bin");
    let mut command = installer_command(temp.path(), &metadata, temp.path(), Some(&sums), &tools);
    let git_log = configure_fake_git(
        &mut command,
        temp.path(),
        tag,
        "5555555555555555555555555555555555555555",
        None,
    );
    command.args([
        "--from-source",
        "--no-timer",
        "--install-dir",
        install.to_str().unwrap(),
    ]);
    let output = command.output().unwrap();
    assert!(!output.status.success());
    assert!(output_text(&output).contains("cargo install failed"));
    assert!(!temp.path().join("home/.telltale-installer.lock").exists());
    assert!(!install.exists());
    assert!(!temp.path().join("systemctl.log").exists());
    assert_fake_git_tag_refs(&git_log, tag);
    let urls = fs::read_to_string(temp.path().join("curl.log")).unwrap();
    assert!(urls.contains("/releases/latest"));
    assert!(!urls.contains("/releases/tags/"));
}

#[test]
fn canonical_install_ignores_unrelated_files_and_never_runs_migration() {
    let temp = tempdir().unwrap();
    let name = format!("telltale-v0.5.0-{}.tar.gz", target());
    let selected = archive(temp.path(), &name, "0.5.0", None);
    let metadata = release_metadata(temp.path(), "v0.5.0");
    let sums = temp.path().join("SHA256SUMS");
    checksum(&selected, &sums);
    let units = temp.path().join("home/.config/systemd/user");
    let unrelated_binary = temp.path().join("home/bin/other-agent");
    let unrelated_unit = units.join("other-agent.timer");
    fs::create_dir_all(unrelated_binary.parent().unwrap()).unwrap();
    fs::create_dir_all(&units).unwrap();
    executable(&unrelated_binary, "#!/bin/sh\nexit 0\n");
    regular_file(&unrelated_unit, b"unrelated timer\n", 0o644);
    let tools = tools(temp.path(), true);
    let mut command = installer_command(temp.path(), &metadata, temp.path(), Some(&sums), &tools);
    command
        .env("FAKE_MIGRATION_LOG", temp.path().join("migrations.log"))
        .args([
            "--with-timer",
            "--install-dir",
            temp.path().join("home/bin").to_str().unwrap(),
        ]);
    let output = command.output().unwrap();
    assert_success(&output);
    assert!(!temp.path().join("migrations.log").exists());
    assert_eq!(fs::read(&unrelated_binary).unwrap(), b"#!/bin/sh\nexit 0\n");
    assert_eq!(fs::read(&unrelated_unit).unwrap(), b"unrelated timer\n");
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
    let calls = fs::read_to_string(temp.path().join("systemctl.log")).unwrap();
    assert!(calls.contains("enable --now telltale-scan.timer"));
    assert!(!calls.contains("other-agent"));
    let events = fs::read_to_string(temp.path().join("events.log")).unwrap();
    let candidate_version = events
        .find("telltale.new:--version")
        .expect("staged candidate version probe");
    let reload = events[candidate_version..]
        .find("systemctl:--user daemon-reload")
        .map(|offset| candidate_version + offset)
        .expect("canonical daemon reload event");
    let enable = events
        .find("systemctl:--user enable --now telltale-scan.timer")
        .expect("canonical timer enable event");
    assert!(candidate_version < reload && reload < enable);
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
    let name = format!("telltale-v0.5.0-{}.tar.gz", target());
    let selected = archive(temp.path(), &name, "0.5.0", None);
    let metadata = release_metadata(temp.path(), "v0.5.0");
    let sums = temp.path().join("SHA256SUMS");
    checksum(&selected, &sums);
    let output = {
        let tools = tools(temp.path(), false);
        let mut command =
            installer_command(temp.path(), &metadata, temp.path(), Some(&sums), &tools);
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
        .env("FAKE_SYSTEMCTL_DELAY", "0.2")
        .args(["--no-timer", "--install-dir", install_a.to_str().unwrap()]);
    let mut holder = holder.spawn().expect("spawn installer lock holder");

    let systemctl_log = temp.path().join("systemctl.log");
    let mut holder_ready = false;
    for _ in 0..250 {
        if fs::read_to_string(&systemctl_log).is_ok_and(|log| !log.trim().is_empty()) {
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
    let name = format!("telltale-v0.5.0-{}.tar.gz", target());
    let selected = archive(temp.path(), &name, "0.5.0", None);
    let metadata = release_metadata(temp.path(), "v0.5.0");
    let sums = temp.path().join("SHA256SUMS");
    checksum(&selected, &sums);
    let mut command = installer_command(
        temp.path(),
        &metadata,
        temp.path(),
        Some(&sums),
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
    let name = format!("telltale-v0.5.0-{}.tar.gz", target());
    let selected = archive(symlinked.path(), &name, "0.5.0", None);
    let symlink_metadata = release_metadata(symlinked.path(), "v0.5.0");
    let symlink_sums = symlinked.path().join("SHA256SUMS");
    checksum(&selected, &symlink_sums);
    let mut symlink_command = installer_command(
        symlinked.path(),
        &symlink_metadata,
        symlinked.path(),
        Some(&symlink_sums),
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
    let name = format!("telltale-v0.5.0-{}.tar.gz", target());
    let selected = archive(unsafe_directory.path(), &name, "0.5.0", None);
    let unsafe_metadata = release_metadata(unsafe_directory.path(), "v0.5.0");
    let unsafe_sums = unsafe_directory.path().join("SHA256SUMS");
    checksum(&selected, &unsafe_sums);
    let mut unsafe_command = installer_command(
        unsafe_directory.path(),
        &unsafe_metadata,
        unsafe_directory.path(),
        Some(&unsafe_sums),
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
    assert!(output_text(&output).contains("final canonical-schedules-disabled postcondition"));
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
fn canonical_unit_dropins_are_rejected_before_staging() {
    for unit in ["telltale-scan.service", "telltale-scan.timer"] {
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
        assert!(
            output_text(&output)
                .contains("could not safely validate effective canonical systemd policy")
        );
        assert!(units.join(unit).is_file());
        assert!(!temp.path().join("home/bin/telltale").exists());
    }

    for unit in ["telltale-scan.service", "telltale-scan.timer"] {
        let temp = tempdir().unwrap();
        let name = format!("telltale-v0.5.0-{}.tar.gz", target());
        let selected = archive(temp.path(), &name, "0.5.0", None);
        let metadata = release_metadata(temp.path(), "v0.5.0");
        let sums = temp.path().join("SHA256SUMS");
        checksum(&selected, &sums);
        let units = temp.path().join("home/.config/systemd/user");
        fs::create_dir_all(&units).unwrap();
        regular_file(&units.join(unit), b"unrelated unit\n", 0o644);
        let dropin = units.join(format!("{unit}.d/override.conf"));
        fs::create_dir_all(dropin.parent().unwrap()).unwrap();
        regular_file(
            &dropin,
            b"[Service]\nEnvironmentFile=-/tmp/missing-unit-specific.env\n",
            0o644,
        );
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
        assert!(
            output_text(&output)
                .contains("could not safely validate effective canonical systemd policy")
        );
        assert_eq!(fs::read(units.join(unit)).unwrap(), b"unrelated unit\n");
        assert_eq!(
            fs::read(dropin).unwrap(),
            b"[Service]\nEnvironmentFile=-/tmp/missing-unit-specific.env\n"
        );
        assert!(!temp.path().join("home/bin/telltale").exists());
    }
}

#[test]
fn canonical_not_found_unit_system_dropins_are_checked() {
    for unit in ["telltale-scan.service", "telltale-scan.timer"] {
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
        assert!(
            output_text(&output)
                .contains("could not safely validate effective canonical systemd policy")
        );
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

    let mut command = installer_command(
        temp.path(),
        &metadata,
        temp.path(),
        Some(&sums),
        &tools(temp.path(), true),
    );
    command
        .env("FAKE_SYSTEMCTL_FAIL_QUERY", "LoadState:telltale-scan.timer")
        .args(["--no-timer", "--install-dir", install.to_str().unwrap()]);
    let output = command.output().unwrap();
    assert!(!output.status.success());
    assert!(output_text(&output).contains("could not safely query systemd state"));
    assert_eq!(
        fs::read(install.join("telltale")).unwrap(),
        b"old canonical bytes\n"
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
    let name = format!("telltale-v0.5.0-{}.tar.gz", target());
    let selected = archive(temp.path(), &name, "0.5.0", None);
    let metadata = release_metadata(temp.path(), "v0.5.0");
    let sums = temp.path().join("SHA256SUMS");
    checksum(&selected, &sums);
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
        Some(&sums),
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
    let new_bytes = fs::read(stage.join("telltale.new")).unwrap();
    fs::copy(stage.join("telltale.new"), install.join("telltale")).unwrap();

    let name = format!("telltale-v0.5.0-{}.tar.gz", target());
    let selected = archive(temp.path(), &name, "0.5.0", None);
    let metadata = release_metadata(temp.path(), "v0.5.0");
    let sums = temp.path().join("SHA256SUMS");
    checksum(&selected, &sums);
    let mut command = installer_command(
        temp.path(),
        &metadata,
        temp.path(),
        Some(&sums),
        &tools(temp.path(), true),
    );
    command
        .env("FAKE_SYSTEMCTL_FAIL_QUERY", "LoadState:telltale-scan.timer")
        .args(["--no-timer", "--install-dir", install.to_str().unwrap()]);
    let output = command.output().unwrap();
    assert!(!output.status.success());
    assert!(output_text(&output).contains("could not safely query systemd state"));
    assert_eq!(fs::read(install.join("telltale")).unwrap(), new_bytes);
    assert_ne!(new_bytes, old_bytes);
    assert!(stage.exists(), "failed recovery must retain staging");
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
    let old_service = rc5_rc6_generated_service(
        &install,
        &temp.path().join("home/.local/state"),
        &temp.path().join("home/.config"),
    );
    let old_timer = rc4_generated_timer();
    regular_file(
        &units.join("telltale-scan.service"),
        old_service.as_bytes(),
        0o644,
    );
    regular_file(
        &units.join("telltale-scan.timer"),
        old_timer.as_bytes(),
        0o644,
    );

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
        old_service.as_bytes()
    );
    assert_eq!(
        fs::read(units.join("telltale-scan.timer")).unwrap(),
        old_timer.as_bytes()
    );
    let restored_service_ino = fs::metadata(units.join("telltale-scan.service"))
        .unwrap()
        .ino();
    let restored_timer_ino = fs::metadata(units.join("telltale-scan.timer"))
        .unwrap()
        .ino();
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
        fs::metadata(units.join("telltale-scan.service"))
            .unwrap()
            .ino(),
        restored_service_ino
    );
    assert_ne!(
        fs::metadata(units.join("telltale-scan.timer"))
            .unwrap()
            .ino(),
        restored_timer_ino
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
    let selected = archive(temp.path(), &name, "0.5.0", None);
    let metadata = release_metadata(temp.path(), "v0.5.0");
    let sums = temp.path().join("SHA256SUMS");
    checksum(&selected, &sums);
    let output = run_release(temp.path(), &metadata, temp.path(), Some(&sums), &[]);
    assert_success(&output);
    assert_eq!(fs::read(install.join("telltale")).unwrap(), new_bytes);
    assert!(!stage.exists(), "committed recovery should clean staging");
}

#[test]
fn retained_rc4_transaction_with_actual_service_bytes_recovers_without_activation() {
    let temp = tempdir().unwrap();
    let install = temp.path().join("home/bin");
    let units = temp.path().join("home/.config/systemd/user");
    let journal_dir = temp.path().join("home/.local/state/telltale");
    let state_bytes = b"pre-existing canonical state bytes\n";
    fs::create_dir_all(&install).unwrap();
    fs::create_dir_all(&units).unwrap();
    fs::create_dir_all(&journal_dir).unwrap();
    regular_file(&journal_dir.join("telltale-state.json"), state_bytes, 0o600);

    let service = rc4_generated_service(
        &install,
        &temp.path().join("home/.local/state"),
        &temp.path().join("home/.config"),
    );
    let rc5_rc6_service = rc5_rc6_generated_service(
        &install,
        &temp.path().join("home/.local/state"),
        &temp.path().join("home/.config"),
    );
    assert_ne!(service, rc5_rc6_service);
    assert!(!service.contains("ProtectHome=no"));
    assert!(rc5_rc6_service.contains("ProtectHome=no"));
    let timer = rc4_generated_timer();
    regular_file(
        &units.join("telltale-scan.service"),
        service.as_bytes(),
        0o644,
    );
    regular_file(&units.join("telltale-scan.timer"), timer.as_bytes(), 0o644);

    let install_stage = install.join(".telltale-install.rc4");
    let unit_stage = units.join(".telltale-units.rc4");
    for stage in [&install_stage, &unit_stage] {
        fs::create_dir_all(stage).unwrap();
        regular_file(
            &stage.join("transaction.marker"),
            b"telltale-installer-transaction-v1\n",
            0o600,
        );
    }
    telltale_binary(&install_stage.join("telltale.new"), "0.5.0", false);
    regular_file(
        &unit_stage.join("telltale-scan.service.new"),
        service.as_bytes(),
        0o644,
    );
    regular_file(
        &unit_stage.join("telltale-scan.timer.new"),
        timer.as_bytes(),
        0o644,
    );
    regular_file(
        &journal_dir.join("installer-transaction.json"),
        br#"{
  "version": "1.0",
  "phase": "failed",
  "identity": "telltale",
  "schedule": "telltale-scan.timer"
}
"#,
        0o600,
    );

    let name = format!("telltale-v0.5.0-{}.tar.gz", target());
    let selected = archive(temp.path(), &name, "0.5.0", None);
    let metadata = release_metadata(temp.path(), "v0.5.0");
    let sums = temp.path().join("SHA256SUMS");
    checksum(&selected, &sums);
    let mut command = installer_command(
        temp.path(),
        &metadata,
        temp.path(),
        Some(&sums),
        &tools(temp.path(), true),
    );
    command
        .env("FAKE_NEW_ENABLED", "1")
        .env("FAKE_NEW_ACTIVE", "1")
        .args(["--no-timer", "--install-dir", install.to_str().unwrap()]);
    let output = command.output().unwrap();
    assert_success(&output);
    assert!(install.join("telltale").is_file());
    assert!(!install_stage.exists());
    assert!(!unit_stage.exists());
    assert_eq!(
        fs::read(journal_dir.join("telltale-state.json")).unwrap(),
        state_bytes
    );
    let events = fs::read_to_string(temp.path().join("events.log")).unwrap();
    let disable = events
        .find("systemctl:--user disable telltale-scan.timer")
        .expect("stale timer disable event");
    let stop = events
        .find("systemctl:--user stop telltale-scan.timer")
        .expect("stale timer stop event");
    assert!(
        disable < stop,
        "stale timer must be disabled before it is stopped"
    );
    assert!(
        !events.contains("enable --now"),
        "retained rc4 recovery must not activate a schedule"
    );
}

#[test]
fn retained_rc5_and_rc6_transactions_recover_past_historical_policy_failures() {
    for historical_version in ["rc5", "rc6"] {
        let temp = tempdir().unwrap();
        let install = temp.path().join("home/bin");
        let units = temp.path().join("home/.config/systemd/user");
        let config = temp.path().join("home/.config");
        let journal_dir = temp.path().join("home/.local/state/telltale");
        let state_bytes = b"pre-existing canonical state bytes\n";
        fs::create_dir_all(&install).unwrap();
        fs::create_dir_all(&units).unwrap();
        fs::create_dir_all(&journal_dir).unwrap();
        regular_file(&journal_dir.join("telltale-state.json"), state_bytes, 0o600);

        let service =
            rc5_rc6_generated_service(&install, &temp.path().join("home/.local/state"), &config);
        assert!(service.contains("EnvironmentFile=-"));
        assert!(service.contains("ProtectHome=no"));
        assert!(
            !service
                .lines()
                .any(|line| line.starts_with("WorkingDirectory="))
        );
        let timer = rc4_generated_timer();
        regular_file(
            &units.join("telltale-scan.service"),
            service.as_bytes(),
            0o644,
        );
        regular_file(&units.join("telltale-scan.timer"), timer.as_bytes(), 0o644);

        let optional_environment_file = config.join("telltale/telltale.env");
        let environment_files = if historical_version == "rc5" {
            String::new()
        } else {
            fs::create_dir_all(optional_environment_file.parent().unwrap()).unwrap();
            regular_file(&optional_environment_file, b"TELLTALE_TEST=1\n", 0o600);
            format!(
                "{} (ignore_errors=yes)",
                optional_environment_file.display()
            )
        };
        assert_eq!(
            optional_environment_file.exists(),
            historical_version == "rc6"
        );
        let working_directory = format!("!{}", temp.path().join("home").display());

        let install_stage = install.join(format!(".telltale-install.{historical_version}"));
        let unit_stage = units.join(format!(".telltale-units.{historical_version}"));
        for stage in [&install_stage, &unit_stage] {
            fs::create_dir_all(stage).unwrap();
            regular_file(
                &stage.join("transaction.marker"),
                b"telltale-installer-transaction-v1\n",
                0o600,
            );
        }
        telltale_binary(&install_stage.join("telltale.new"), "0.5.0", false);
        regular_file(
            &unit_stage.join("telltale-scan.service.new"),
            service.as_bytes(),
            0o644,
        );
        regular_file(
            &unit_stage.join("telltale-scan.timer.new"),
            timer.as_bytes(),
            0o644,
        );
        regular_file(
            &journal_dir.join("installer-transaction.json"),
            br#"{
  "version": "1.0",
  "phase": "failed",
  "identity": "telltale",
  "schedule": "telltale-scan.timer"
}
"#,
            0o600,
        );

        let name = format!("telltale-v0.5.0-{}.tar.gz", target());
        let selected = archive(temp.path(), &name, "0.5.0", None);
        let metadata = release_metadata(temp.path(), "v0.5.0");
        let sums = temp.path().join("SHA256SUMS");
        checksum(&selected, &sums);
        let tools = tools(temp.path(), true);
        require_effective_policy_before_binary_replacement(&tools);
        let effective_properties = temp.path().join("effective-properties.log");
        let replacement_properties = temp.path().join("replacement-properties.log");
        let mut command =
            installer_command(temp.path(), &metadata, temp.path(), Some(&sums), &tools);
        command
            .env("FAKE_ENVIRONMENT_FILES_VALUE", &environment_files)
            .env("FAKE_WORKING_DIRECTORY_VALUE", &working_directory)
            .env("FAKE_EFFECTIVE_PROPERTY_LOG", &effective_properties)
            .env(
                "FAKE_BINARY_REPLACEMENT_POLICY_LOG",
                &replacement_properties,
            )
            .env("FAKE_RESET_EFFECTIVE_PROPERTY_LOG", "1")
            .env("FAKE_NEW_ENABLED", "1")
            .env("FAKE_NEW_ACTIVE", "1")
            .args(["--with-timer", "--install-dir", install.to_str().unwrap()]);
        let output = command.output().unwrap();
        assert_success(&output);
        assert!(install.join("telltale").is_file());
        assert!(!install_stage.exists());
        assert!(!unit_stage.exists());
        assert_eq!(
            fs::read(journal_dir.join("telltale-state.json")).unwrap(),
            state_bytes
        );
        assert_eq!(
            fs::read(temp.path().join("systemctl.state")).unwrap(),
            b"telltale-scan.service 1 0 0\ntelltale-scan.timer 1 1 1\n"
        );

        let properties = fs::read_to_string(&replacement_properties).unwrap();
        let environment_files_response = format!("EnvironmentFiles\t{environment_files}");
        let working_directory_response = format!("WorkingDirectory\t{working_directory}");
        assert!(
            properties
                .lines()
                .any(|line| line == environment_files_response),
            "{historical_version} EnvironmentFiles response differed: {properties}"
        );
        assert!(
            properties
                .lines()
                .filter(|line| line.starts_with("EnvironmentFiles\t"))
                .all(|line| line == environment_files_response),
            "{historical_version} returned more than its expected EnvironmentFiles value: {properties}"
        );
        assert!(
            properties
                .lines()
                .any(|line| line == working_directory_response),
            "{historical_version} WorkingDirectory response differed: {properties}"
        );
        assert!(
            properties
                .lines()
                .filter(|line| line.starts_with("WorkingDirectory\t"))
                .all(|line| line == working_directory_response),
            "{historical_version} returned more than its expected WorkingDirectory value: {properties}"
        );

        let events = fs::read_to_string(temp.path().join("events.log")).unwrap();
        let disable = events
            .find("systemctl:--user disable telltale-scan.timer")
            .expect("stale timer disable event");
        let stop = events
            .find("systemctl:--user stop telltale-scan.timer")
            .expect("stale timer stop event");
        let activation = events
            .find("systemctl:--user enable --now telltale-scan.timer")
            .expect("canonical timer activation event");
        let final_binary_validation = events.rfind("binary:").expect("binary smoke event");
        assert!(
            disable < stop,
            "stale timer must be disabled before it is stopped"
        );
        assert!(
            final_binary_validation < activation,
            "activation must follow successful binary validation: {events}"
        );
    }
}

#[test]
fn duplicate_conflicting_initial_journal_phase_and_staging_are_retained() {
    let temp = tempdir().unwrap();
    let name = format!("telltale-v0.5.0-{}.tar.gz", target());
    let selected = archive(temp.path(), &name, "0.5.0", None);
    let metadata = release_metadata(temp.path(), "v0.5.0");
    let sums = temp.path().join("SHA256SUMS");
    checksum(&selected, &sums);
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

    let output = run_release(temp.path(), &metadata, temp.path(), Some(&sums), &[]);
    assert!(!output.status.success());
    assert!(output_text(&output).contains("could not safely read the installer journal"));
    assert_eq!(fs::read(&journal).unwrap(), original_journal);
    assert!(stage.exists(), "malformed journal must retain staging");
    assert_eq!(fs::read(stage.join(".unknown")).unwrap(), b"retain this\n");
}

#[test]
fn unknown_hidden_stage_entry_is_retained_before_recursive_recovery_cleanup() {
    let temp = tempdir().unwrap();
    let name = format!("telltale-v0.5.0-{}.tar.gz", target());
    let selected = archive(temp.path(), &name, "0.5.0", None);
    let metadata = release_metadata(temp.path(), "v0.5.0");
    let sums = temp.path().join("SHA256SUMS");
    checksum(&selected, &sums);
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

    let output = run_release(temp.path(), &metadata, temp.path(), Some(&sums), &[]);
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
    let name = format!("telltale-v0.5.0-{}.tar.gz", target());
    let selected = archive(temp.path(), &name, "0.5.0", None);
    let sums = temp.path().join("SHA256SUMS");
    checksum(&selected, &sums);
    let output = run_release(temp.path(), &metadata, temp.path(), Some(&sums), &[]);
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
fn unrelated_platform_named_binary_is_ignored_without_mutation() {
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
    assert_success(&output);
    assert!(install.join("telltale").is_file());
    assert_eq!(
        fs::read(install.join("telltale.exe")).unwrap(),
        b"duplicate\n"
    );
}
