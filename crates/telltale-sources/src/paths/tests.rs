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
        PathBuf::from("logs/telltale-events.jsonl")
    );
    assert_eq!(
        resolve_state_path_with_env(PathProfile::Project, None, HostPlatform::Linux, &env),
        PathBuf::from("state/telltale-state.json")
    );
}

#[test]
fn explicit_paths_override_environment_and_profile_defaults() {
    let mut env = env_with_home("/home/alice");
    env.log_path = Some(PathBuf::from("/env/telltale-events.jsonl"));
    env.state_path = Some(PathBuf::from("/env/telltale-state.json"));

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
    env.log_path = Some(PathBuf::from("/env/telltale-events.jsonl"));
    env.state_path = Some(PathBuf::from("/env/telltale-state.json"));

    assert_eq!(
        resolve_log_path_with_env(PathProfile::User, None, HostPlatform::Linux, &env),
        PathBuf::from("/env/telltale-events.jsonl")
    );
    assert_eq!(
        resolve_state_path_with_env(PathProfile::User, None, HostPlatform::Linux, &env),
        PathBuf::from("/env/telltale-state.json")
    );
}

#[test]
fn linux_user_profile_prefers_xdg_state_home() {
    let mut env = env_with_home("/home/alice");
    env.xdg_state_home = Some(PathBuf::from("/home/alice/.state"));

    assert_eq!(
        resolve_log_path_with_env(PathProfile::User, None, HostPlatform::Linux, &env),
        PathBuf::from("/home/alice/.state/telltale/logs/telltale-events.jsonl")
    );
    assert_eq!(
        resolve_state_path_with_env(PathProfile::User, None, HostPlatform::Linux, &env),
        PathBuf::from("/home/alice/.state/telltale/telltale-state.json")
    );
}

#[test]
fn linux_system_profile_uses_var_paths() {
    let env = env_with_home("/home/alice");

    assert_eq!(
        resolve_log_path_with_env(PathProfile::System, None, HostPlatform::Linux, &env),
        PathBuf::from("/var/log/telltale/telltale-events.jsonl")
    );
    assert_eq!(
        resolve_state_path_with_env(PathProfile::System, None, HostPlatform::Linux, &env),
        PathBuf::from("/var/lib/telltale/telltale-state.json")
    );
}

#[test]
fn macos_profiles_use_library_paths() {
    let env = env_with_home("/Users/alice");

    assert_eq!(
        resolve_log_path_with_env(PathProfile::User, None, HostPlatform::MacOs, &env),
        PathBuf::from("/Users/alice/Library/Logs/Telltale/telltale-events.jsonl")
    );
    assert_eq!(
        resolve_state_path_with_env(PathProfile::User, None, HostPlatform::MacOs, &env),
        PathBuf::from("/Users/alice/Library/Application Support/Telltale/telltale-state.json")
    );
    assert_eq!(
        resolve_log_path_with_env(PathProfile::System, None, HostPlatform::MacOs, &env),
        PathBuf::from("/Library/Logs/Telltale/telltale-events.jsonl")
    );
    assert_eq!(
        resolve_state_path_with_env(PathProfile::System, None, HostPlatform::MacOs, &env),
        PathBuf::from("/Library/Application Support/Telltale/telltale-state.json")
    );
}

#[test]
fn windows_profiles_use_appdata_and_programdata_paths() {
    let mut env = env_with_home("C:/Users/Alice");
    env.local_app_data = Some(PathBuf::from("C:/Users/Alice/AppData/Local"));
    env.program_data = Some(PathBuf::from("C:/ProgramData"));

    assert_eq!(
        resolve_log_path_with_env(PathProfile::User, None, HostPlatform::Windows, &env),
        PathBuf::from("C:/Users/Alice/AppData/Local/Telltale/Logs/telltale-events.jsonl")
    );
    assert_eq!(
        resolve_state_path_with_env(PathProfile::User, None, HostPlatform::Windows, &env),
        PathBuf::from("C:/Users/Alice/AppData/Local/Telltale/State/telltale-state.json")
    );
    assert_eq!(
        resolve_log_path_with_env(PathProfile::System, None, HostPlatform::Windows, &env),
        PathBuf::from("C:/ProgramData/Telltale/Logs/telltale-events.jsonl")
    );
    assert_eq!(
        resolve_state_path_with_env(PathProfile::System, None, HostPlatform::Windows, &env),
        PathBuf::from("C:/ProgramData/Telltale/State/telltale-state.json")
    );
}
