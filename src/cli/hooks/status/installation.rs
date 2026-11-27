//! Inspect the adapter's documented installation files without loading them.

use std::io::{self, Read};
use std::path::{Path, PathBuf};

use serde::Serialize;
use serde_json::Value;
use telltale_core::hooks::config::user_home;
use telltale_core::hooks::harness::{Harness, Install, MachineInstallFile};
use telltale_sources::journal::JournalFile;

use super::{Location, digest_path};

const MAX_SETTINGS_BYTES: u64 = 1024 * 1024;

#[derive(Serialize)]
pub(super) struct HarnessStatus {
    pub(super) name: &'static str,
    installed_scopes: Vec<Location>,
    settings: Vec<SettingStatus>,
}

#[derive(Serialize)]
struct SettingStatus {
    scope: Location,
    path_sha256: Option<String>,
    state: State,
}

#[derive(Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum State {
    Present,
    Missing,
    Altered,
    Unavailable,
    NotInspected,
}

pub(super) fn detect() -> Vec<HarnessStatus> {
    let project = std::env::current_dir().ok().map(|cwd| {
        cwd.ancestors()
            .find(|dir| dir.join(".git").exists())
            .map_or(cwd.clone(), Path::to_path_buf)
    });
    let home = user_home();
    Harness::ALL
        .iter()
        .map(|harness| {
            let adapter = harness.adapter();
            let install = &adapter.install;
            let user = install
                .user_config_override
                .or(adapter.home.map(|home| home.variable))
                .and_then(absolute_env)
                .or_else(|| {
                    let xdg_subdir = install.user_home.strip_prefix(".config/")?;
                    absolute_env("XDG_CONFIG_HOME").map(|root| root.join(xdg_subdir))
                })
                .or_else(|| home.as_ref().map(|home| home.join(install.user_home)));
            let mut report = HarnessStatus {
                name: adapter.name,
                installed_scopes: Vec::new(),
                settings: Vec::new(),
            };
            let user_paths = install
                .user_files
                .iter()
                .map(|file| user.as_ref().map(|base| base.join(file)));
            report.scope(install, Location::User, user_paths);
            let project_paths = install
                .project_files
                .iter()
                .map(|file| project.as_ref().map(|base| base.join(file)));
            report.scope(install, Location::Project, project_paths);
            report.scope(
                install,
                Location::System,
                install.system_files.iter().copied().map(machine_path),
            );
            report.scope(
                install,
                Location::Managed,
                install.managed_files.iter().copied().map(machine_path),
            );
            report
        })
        .collect()
}

impl HarnessStatus {
    fn scope(
        &mut self,
        install: &Install,
        scope: Location,
        paths: impl Iterator<Item = Option<PathBuf>>,
    ) {
        let mut installed = false;
        for path in paths {
            let state = path
                .as_deref()
                .map_or(State::Unavailable, |path| inspect(path, install, self.name));
            installed |= state == State::Present;
            self.settings.push(SettingStatus {
                scope,
                path_sha256: path.as_deref().map(digest_path),
                state,
            });
        }
        if installed {
            self.installed_scopes.push(scope);
        }
    }
}

fn absolute_env(name: &str) -> Option<PathBuf> {
    std::env::var_os(name)
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
}

fn machine_path(file: MachineInstallFile) -> Option<PathBuf> {
    use MachineInstallFile::{Standard, WindowsProgramFiles};
    let name = match file {
        Standard(name) | WindowsProgramFiles(name) => name,
    };
    // Like the existing evaluator fault injection, this only affects debug
    // CLI diagnostics. It never determines what a harness or hook loads.
    #[cfg(debug_assertions)]
    if let Some(root) = absolute_env("TELLTALE_HOOKS_TEST_MANAGED_SETTINGS_ROOT") {
        return Some(root.join(name.strip_prefix("/etc/").unwrap_or(name)));
    }
    if Path::new(name).is_absolute() {
        return Some(PathBuf::from(name));
    }
    #[cfg(target_os = "macos")]
    let root = Some(PathBuf::from("/Library/Application Support"));
    #[cfg(all(unix, not(target_os = "macos")))]
    let root = Some(PathBuf::from("/etc"));
    #[cfg(windows)]
    let root = match file {
        Standard(_) => crate::config::program_data(),
        WindowsProgramFiles(_) => crate::config::program_files(),
    };
    #[cfg(not(any(unix, windows)))]
    let root: Option<PathBuf> = None;
    root.map(|base| base.join(name))
}

fn inspect(path: &Path, install: &Install, harness: &str) -> State {
    let file = match JournalFile::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return State::Missing,
        Err(_) => return State::Unavailable,
    };
    if path.extension() == Some(std::ffi::OsStr::new("toml")) {
        return if file.len() > MAX_SETTINGS_BYTES {
            State::Unavailable
        } else {
            State::NotInspected
        };
    }
    let mut bytes = Vec::new();
    if file
        .into_file()
        .take(MAX_SETTINGS_BYTES + 1)
        .read_to_end(&mut bytes)
        .is_err()
        || bytes.len() as u64 > MAX_SETTINGS_BYTES
    {
        return State::Unavailable;
    }
    if let Some(matches) = install.plugin_wrapper {
        return if std::str::from_utf8(&bytes).is_ok_and(matches) {
            State::Present
        } else {
            State::Altered
        };
    }
    let Ok(Value::Object(settings)) = serde_json::from_slice::<Value>(&bytes) else {
        return State::Altered;
    };
    let Some(hooks) = settings.get("hooks") else {
        return State::Missing;
    };
    let Some(hooks) = hooks.as_object() else {
        return State::Altered;
    };
    if hooks.is_empty() {
        return State::Missing;
    }
    let marker = format!("telltale hooks {harness} hook");
    let complete = [false, true].into_iter().any(|fail_closed| {
        (install.output)(&marker, fail_closed).is_ok_and(|expected| {
            let expected_hooks = expected.document["hooks"]
                .as_object()
                .expect("installer hook table");
            expected.document.get("version").is_none_or(|version| {
                settings.get("version") == Some(version)
                // An inline settings table does not have a hook-file header.
                || path.file_name() != Some(std::ffi::OsStr::new("telltale-hooks.json"))
            }) && expected_hooks.iter().all(|(event, entries)| {
                hooks
                    .get(event)
                    .is_some_and(|actual| contains_entries(actual, entries, harness))
            })
        })
    });
    if complete {
        State::Present
    } else if hooks
        .values()
        .any(|entries| has_telltale_hook(entries, harness))
    {
        State::Altered
    } else {
        State::Missing
    }
}

fn has_telltale_hook(entries: &Value, harness: &str) -> bool {
    entries.as_array().is_none_or(|groups| {
        groups.iter().any(|group| {
            group["hooks"].as_array().is_none_or(|hooks| {
                hooks.iter().any(|hook| {
                    hook["command"].as_str().is_some_and(|command| {
                        hook_command(command, harness)
                            || command.contains(&format!("hooks {harness} hook"))
                    })
                })
            })
        })
    })
}

/// Additional hooks can coexist with the generated entries. Compare every
/// generated field, allowing either generated fail-closed variant and the
/// installer command's executable path and supported flags.
fn contains_entries(actual: &Value, expected: &Value, harness: &str) -> bool {
    match (actual, expected) {
        (Value::Object(actual), Value::Object(expected)) => {
            actual.len() == expected.len()
                && expected.iter().all(|(key, expected)| {
                    actual.get(key).is_some_and(|actual| {
                        if key == "command" {
                            actual
                                .as_str()
                                .is_some_and(|command| hook_command(command, harness))
                        } else {
                            contains_entries(actual, expected, harness)
                        }
                    })
                })
        }
        (Value::Array(actual), Value::Array(expected)) => expected.iter().all(|expected| {
            actual
                .iter()
                .any(|actual| contains_entries(actual, expected, harness))
        }),
        _ => actual == expected,
    }
}

fn hook_command(command: &str, harness: &str) -> bool {
    // The installer accepts quoted executable paths, including PowerShell's
    // call operator. Read the executable as data; never run shell parsing.
    let command = command.trim_start();
    let command = command.strip_prefix("& ").unwrap_or(command).trim_start();
    let (executable, rest) = if let Some(quoted) = command.strip_prefix('"') {
        let Some(pair) = quoted.split_once('"') else {
            return false;
        };
        pair
    } else if let Some(quoted) = command.strip_prefix('\'') {
        let Some(pair) = quoted.split_once('\'') else {
            return false;
        };
        pair
    } else {
        let Some(pair) = command.split_once(char::is_whitespace) else {
            return false;
        };
        pair
    };
    if !rest.starts_with(char::is_whitespace) && command.starts_with(['\'', '"']) {
        return false;
    }
    let name = executable.rsplit(['/', '\\']).next().unwrap_or_default();
    if !(name.eq_ignore_ascii_case("telltale") || name.eq_ignore_ascii_case("telltale.exe")) {
        return false;
    }
    let Some(words) = super::super::plain_words(rest) else {
        return false;
    };
    let words: Vec<_> = words.iter().map(String::as_str).collect();
    let ["hooks", name, "hook", flags @ ..] = words.as_slice() else {
        return false;
    };
    *name == harness && super::super::hook_flags_for_installation(flags)
}
