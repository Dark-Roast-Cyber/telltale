use std::env;
use std::path::PathBuf;

pub const LOG_PATH_ENV: &str = "ADR_LOG_PATH";
pub const STATE_PATH_ENV: &str = "ADR_STATE_PATH";

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
        PathProfile::Project => PathBuf::from("logs/adr-events.jsonl"),
        PathProfile::System => match platform {
            HostPlatform::Linux => PathBuf::from("/var/log/telltale/adr-events.jsonl"),
            HostPlatform::MacOs => PathBuf::from("/Library/Logs/Telltale/adr-events.jsonl"),
            HostPlatform::Windows => program_data(env).join("Telltale/Logs/adr-events.jsonl"),
        },
        PathProfile::User => match platform {
            HostPlatform::Linux => {
                linux_user_state_root(env).join("telltale/logs/adr-events.jsonl")
            }
            HostPlatform::MacOs => home(env).join("Library/Logs/Telltale/adr-events.jsonl"),
            HostPlatform::Windows => {
                windows_user_data_root(env).join("Telltale/Logs/adr-events.jsonl")
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
        PathProfile::Project => PathBuf::from("state/adr-state.json"),
        PathProfile::System => match platform {
            HostPlatform::Linux => PathBuf::from("/var/lib/telltale/adr-state.json"),
            HostPlatform::MacOs => {
                PathBuf::from("/Library/Application Support/Telltale/adr-state.json")
            }
            HostPlatform::Windows => program_data(env).join("Telltale/State/adr-state.json"),
        },
        PathProfile::User => match platform {
            HostPlatform::Linux => linux_user_state_root(env).join("telltale/adr-state.json"),
            HostPlatform::MacOs => {
                home(env).join("Library/Application Support/Telltale/adr-state.json")
            }
            HostPlatform::Windows => {
                windows_user_data_root(env).join("Telltale/State/adr-state.json")
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
mod tests {
    use super::*;

    fn env_with_home(home: &str) -> PathEnvironment {
        PathEnvironment {
            home: Some(PathBuf::from(home)),
            ..PathEnvironment::default()
        }
    }

    #[test]
    fn project_profile_preserves_repo_relative_paths() {
        let env = env_with_home("/home/alice");

        assert_eq!(
            resolve_log_path_with_env(PathProfile::Project, None, HostPlatform::Linux, &env),
            PathBuf::from("logs/adr-events.jsonl")
        );
        assert_eq!(
            resolve_state_path_with_env(PathProfile::Project, None, HostPlatform::Linux, &env),
            PathBuf::from("state/adr-state.json")
        );
    }

    #[test]
    fn explicit_paths_override_environment_and_profile_defaults() {
        let mut env = env_with_home("/home/alice");
        env.log_path = Some(PathBuf::from("/env/adr-events.jsonl"));
        env.state_path = Some(PathBuf::from("/env/adr-state.json"));

        assert_eq!(
            resolve_log_path_with_env(
                PathProfile::System,
                Some(PathBuf::from("/explicit/events.jsonl")),
                HostPlatform::Linux,
                &env,
            ),
            PathBuf::from("/explicit/events.jsonl")
        );
        assert_eq!(
            resolve_state_path_with_env(
                PathProfile::System,
                Some(PathBuf::from("/explicit/state.json")),
                HostPlatform::Linux,
                &env,
            ),
            PathBuf::from("/explicit/state.json")
        );
    }

    #[test]
    fn environment_paths_override_profile_defaults() {
        let mut env = env_with_home("/home/alice");
        env.log_path = Some(PathBuf::from("/env/adr-events.jsonl"));
        env.state_path = Some(PathBuf::from("/env/adr-state.json"));

        assert_eq!(
            resolve_log_path_with_env(PathProfile::User, None, HostPlatform::Linux, &env),
            PathBuf::from("/env/adr-events.jsonl")
        );
        assert_eq!(
            resolve_state_path_with_env(PathProfile::User, None, HostPlatform::Linux, &env),
            PathBuf::from("/env/adr-state.json")
        );
    }

    #[test]
    fn linux_user_profile_prefers_xdg_state_home() {
        let mut env = env_with_home("/home/alice");
        env.xdg_state_home = Some(PathBuf::from("/home/alice/.state"));

        assert_eq!(
            resolve_log_path_with_env(PathProfile::User, None, HostPlatform::Linux, &env),
            PathBuf::from("/home/alice/.state/telltale/logs/adr-events.jsonl")
        );
        assert_eq!(
            resolve_state_path_with_env(PathProfile::User, None, HostPlatform::Linux, &env),
            PathBuf::from("/home/alice/.state/telltale/adr-state.json")
        );
    }

    #[test]
    fn linux_system_profile_uses_var_paths() {
        let env = env_with_home("/home/alice");

        assert_eq!(
            resolve_log_path_with_env(PathProfile::System, None, HostPlatform::Linux, &env),
            PathBuf::from("/var/log/telltale/adr-events.jsonl")
        );
        assert_eq!(
            resolve_state_path_with_env(PathProfile::System, None, HostPlatform::Linux, &env),
            PathBuf::from("/var/lib/telltale/adr-state.json")
        );
    }

    #[test]
    fn macos_profiles_use_library_paths() {
        let env = env_with_home("/Users/alice");

        assert_eq!(
            resolve_log_path_with_env(PathProfile::User, None, HostPlatform::MacOs, &env),
            PathBuf::from("/Users/alice/Library/Logs/Telltale/adr-events.jsonl")
        );
        assert_eq!(
            resolve_state_path_with_env(PathProfile::User, None, HostPlatform::MacOs, &env),
            PathBuf::from("/Users/alice/Library/Application Support/Telltale/adr-state.json")
        );
        assert_eq!(
            resolve_log_path_with_env(PathProfile::System, None, HostPlatform::MacOs, &env),
            PathBuf::from("/Library/Logs/Telltale/adr-events.jsonl")
        );
        assert_eq!(
            resolve_state_path_with_env(PathProfile::System, None, HostPlatform::MacOs, &env),
            PathBuf::from("/Library/Application Support/Telltale/adr-state.json")
        );
    }

    #[test]
    fn windows_profiles_use_appdata_and_programdata_paths() {
        let mut env = env_with_home("C:/Users/Alice");
        env.local_app_data = Some(PathBuf::from("C:/Users/Alice/AppData/Local"));
        env.program_data = Some(PathBuf::from("C:/ProgramData"));

        assert_eq!(
            resolve_log_path_with_env(PathProfile::User, None, HostPlatform::Windows, &env),
            PathBuf::from("C:/Users/Alice/AppData/Local/Telltale/Logs/adr-events.jsonl")
        );
        assert_eq!(
            resolve_state_path_with_env(PathProfile::User, None, HostPlatform::Windows, &env),
            PathBuf::from("C:/Users/Alice/AppData/Local/Telltale/State/adr-state.json")
        );
        assert_eq!(
            resolve_log_path_with_env(PathProfile::System, None, HostPlatform::Windows, &env),
            PathBuf::from("C:/ProgramData/Telltale/Logs/adr-events.jsonl")
        );
        assert_eq!(
            resolve_state_path_with_env(PathProfile::System, None, HostPlatform::Windows, &env),
            PathBuf::from("C:/ProgramData/Telltale/State/adr-state.json")
        );
    }
}
