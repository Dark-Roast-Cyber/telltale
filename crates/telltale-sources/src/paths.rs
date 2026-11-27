//! Default JSONL log and scanner state paths per path profile and platform,
//! with `TELLTALE_LOG_PATH` and `TELLTALE_STATE_PATH` overrides. Embedding
//! hosts and the local event feed reuse this resolver instead of copying
//! defaults.

use std::env;
use std::path::PathBuf;

pub const LOG_PATH_ENV: &str = "TELLTALE_LOG_PATH";
pub const STATE_PATH_ENV: &str = "TELLTALE_STATE_PATH";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PathProfile {
    User,
    System,
    Project,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HostPlatform {
    Linux,
    MacOs,
    Windows,
}

#[derive(Debug, Default)]
struct PathEnvironment {
    home: Option<PathBuf>,
    xdg_state_home: Option<PathBuf>,
    local_app_data: Option<PathBuf>,
    app_data: Option<PathBuf>,
    program_data: Option<PathBuf>,
    log_path: Option<PathBuf>,
    state_path: Option<PathBuf>,
}

impl PathEnvironment {
    fn current() -> Self {
        Self {
            home: env_path("HOME").or_else(|| env_path("USERPROFILE")),
            xdg_state_home: env_path("XDG_STATE_HOME"),
            local_app_data: env_path("LOCALAPPDATA"),
            app_data: env_path("APPDATA"),
            program_data: env_path("ProgramData"),
            log_path: env_path(LOG_PATH_ENV),
            state_path: env_path(STATE_PATH_ENV),
        }
    }
}

pub fn resolve_log_path(profile: PathProfile, explicit: Option<PathBuf>) -> PathBuf {
    resolve_log_path_with_env(
        profile,
        explicit,
        current_host_platform(),
        &PathEnvironment::current(),
    )
}

pub fn resolve_state_path(profile: PathProfile, explicit: Option<PathBuf>) -> PathBuf {
    resolve_state_path_with_env(
        profile,
        explicit,
        current_host_platform(),
        &PathEnvironment::current(),
    )
}

fn resolve_log_path_with_env(
    profile: PathProfile,
    explicit: Option<PathBuf>,
    platform: HostPlatform,
    env: &PathEnvironment,
) -> PathBuf {
    explicit
        .or_else(|| env.log_path.clone())
        .unwrap_or_else(|| default_log_path(profile, platform, env))
}

fn resolve_state_path_with_env(
    profile: PathProfile,
    explicit: Option<PathBuf>,
    platform: HostPlatform,
    env: &PathEnvironment,
) -> PathBuf {
    explicit
        .or_else(|| env.state_path.clone())
        .unwrap_or_else(|| default_state_path(profile, platform, env))
}

fn default_log_path(
    profile: PathProfile,
    platform: HostPlatform,
    env: &PathEnvironment,
) -> PathBuf {
    match profile {
        PathProfile::Project => PathBuf::from("logs/telltale-events.jsonl"),
        PathProfile::System => match platform {
            HostPlatform::Linux => PathBuf::from("/var/log/telltale/telltale-events.jsonl"),
            HostPlatform::MacOs => PathBuf::from("/Library/Logs/Telltale/telltale-events.jsonl"),
            HostPlatform::Windows => program_data(env).join("Telltale/Logs/telltale-events.jsonl"),
        },
        PathProfile::User => match platform {
            HostPlatform::Linux => {
                linux_user_state_root(env).join("telltale/logs/telltale-events.jsonl")
            }
            HostPlatform::MacOs => home(env).join("Library/Logs/Telltale/telltale-events.jsonl"),
            HostPlatform::Windows => {
                windows_user_data_root(env).join("Telltale/Logs/telltale-events.jsonl")
            }
        },
    }
}

fn default_state_path(
    profile: PathProfile,
    platform: HostPlatform,
    env: &PathEnvironment,
) -> PathBuf {
    match profile {
        PathProfile::Project => PathBuf::from("state/telltale-state.json"),
        PathProfile::System => match platform {
            HostPlatform::Linux => PathBuf::from("/var/lib/telltale/telltale-state.json"),
            HostPlatform::MacOs => {
                PathBuf::from("/Library/Application Support/Telltale/telltale-state.json")
            }
            HostPlatform::Windows => program_data(env).join("Telltale/State/telltale-state.json"),
        },
        PathProfile::User => match platform {
            HostPlatform::Linux => linux_user_state_root(env).join("telltale/telltale-state.json"),
            HostPlatform::MacOs => {
                home(env).join("Library/Application Support/Telltale/telltale-state.json")
            }
            HostPlatform::Windows => {
                windows_user_data_root(env).join("Telltale/State/telltale-state.json")
            }
        },
    }
}

fn linux_user_state_root(env: &PathEnvironment) -> PathBuf {
    env.xdg_state_home
        .clone()
        .unwrap_or_else(|| home(env).join(".local/state"))
}

fn windows_user_data_root(env: &PathEnvironment) -> PathBuf {
    env.local_app_data
        .clone()
        .or_else(|| env.app_data.clone())
        .unwrap_or_else(|| home(env).join("AppData/Local"))
}

fn program_data(env: &PathEnvironment) -> PathBuf {
    env.program_data
        .clone()
        .unwrap_or_else(|| PathBuf::from("C:/ProgramData"))
}

fn home(env: &PathEnvironment) -> PathBuf {
    env.home.clone().unwrap_or_else(|| PathBuf::from("."))
}

fn current_host_platform() -> HostPlatform {
    if cfg!(target_os = "windows") {
        HostPlatform::Windows
    } else if cfg!(target_os = "macos") {
        HostPlatform::MacOs
    } else {
        HostPlatform::Linux
    }
}

fn env_path(name: &str) -> Option<PathBuf> {
    env::var_os(name)
        .filter(|value| !value.as_os_str().is_empty())
        .map(PathBuf::from)
}

#[cfg(test)]
mod tests;
