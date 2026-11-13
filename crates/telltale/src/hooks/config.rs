//! Operator configuration. Everything here is host policy: Telltale owns
//! detection semantics, the host owns promotion thresholds and enforcement
//! (docs/embedding.md "Contract at a glance").

use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::hooks::identity;

/// Whether decisions are returned to the harness or only recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    /// Return allow/ask/deny decisions to the harness.
    Enforce,
    /// Record the decision that would have been made; never influence the harness.
    Observe,
}

/// What the hook tells the harness when it cannot evaluate an action.
/// Ordered from least to most strict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OnError {
    /// Fail open: express no opinion, the harness's own permission flow decides.
    Allow,
    /// Ask the human (in headless runs the harness treats this as a denial).
    Ask,
    /// Fail closed.
    Deny,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Thresholds {
    /// Telltale action `promotion_score` at or above which the action needs approval.
    pub action_ask: u64,
    /// Action `promotion_score` at or above which the action is denied.
    pub action_deny: u64,
    /// Cumulative session score (distinct scored actions, including denied
    /// attempts) at or above which any further scored action needs approval.
    pub session_ask: u64,
    /// Cumulative session score at or above which any further scored action is denied.
    pub session_deny: u64,
    /// After this many denied attempts in one session, any further scored action is denied.
    /// Zero disables the rule.
    pub repeated_denials: u32,
}

impl Default for Thresholds {
    fn default() -> Self {
        // Telltale's Event 3 bands are 20/50/70/90 (docs/detection-model.md).
        // Ask from "medium"; deny from "critical".
        Self {
            action_ask: 50,
            action_deny: 90,
            session_ask: 150,
            session_deny: 300,
            repeated_denials: 3,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Window {
    /// Most recent journal records evaluated together with the pending action.
    pub max_records: usize,
    /// Byte bound on the journal tail that is read.
    pub max_bytes: u64,
    /// Bound on one tool result stored in the journal (bytes, UTF-8 safe cut).
    pub max_result_bytes: usize,
}

impl Default for Window {
    fn default() -> Self {
        Self {
            max_records: 256,
            max_bytes: 2 * 1024 * 1024,
            max_result_bytes: 16 * 1024,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TelltaleSettings {
    /// Include the embedded `telltale.community` package (mirrors `--no-community-rules`).
    pub community_rules: bool,
    /// Opt into the bundled process-chain pack in the same pass.
    pub process_chain: bool,
    /// Additional Rule v1 documents (additive, like `--rules`).
    pub rules: Vec<PathBuf>,
    /// Additional namespaced rule packages (additive, like `rule-packages.d`).
    pub rule_packages: Vec<PathBuf>,
    /// Policy document (enable/disable, like `--policy`).
    pub policy: Option<PathBuf>,
    /// Load the bundled host self-protection rules (`engine::HOST_RULE_DOCUMENTS`)
    /// and the generated rule for this installation's own paths.
    pub self_protection_rules: bool,
}

impl Default for TelltaleSettings {
    fn default() -> Self {
        Self {
            community_rules: true,
            process_chain: true,
            rules: Vec::new(),
            rule_packages: Vec::new(),
            policy: None,
            self_protection_rules: true,
        }
    }
}

/// How much a deny/ask reason discloses to the model (and the user).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReasonDetail {
    /// Basis, scores, thresholds and matched rule IDs.
    Full,
    /// Deny/ask reasons carry only the verdict kind and the telemetry record
    /// ID, and post-result advisory context omits scores and rule IDs, so an
    /// adversarial agent learns nothing about which rule matched; operators
    /// look the record up. A human approving an `ask` prompt also sees only
    /// that, so prefer `Full` where a person reviews prompts.
    Minimal,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub mode: Mode,
    /// Infrastructure failures (state, engine build): the hook could not run.
    pub on_error: OnError,
    /// Agent-controllable gaps: the tool input itself could not be evaluated
    /// (oversized, too deeply nested, unparseable). Never fails open by default.
    pub on_unevaluable: OnError,
    /// What deny/ask reasons disclose (docs/threat-model.md "Learn the rules
    /// from deny reasons").
    pub reason_detail: ReasonDetail,
    /// Directory for per-session journals and state.
    pub state_dir: Option<PathBuf>,
    /// Telemetry JSONL path. Defaults to `<state_dir>/telemetry.jsonl`.
    pub telemetry_path: Option<PathBuf>,
    pub thresholds: Thresholds,
    pub window: Window,
    pub telltale: TelltaleSettings,
    /// The file this configuration was loaded from, if any.
    #[serde(skip)]
    pub source: Option<PathBuf>,
    pub evaluator: EvaluatorSettings,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct EvaluatorSettings {
    /// Try the long-lived evaluator before evaluating in-process.
    pub enabled: bool,
    /// Start a detached evaluator when none answers (the current hook still
    /// evaluates in-process, so correctness never depends on the daemon).
    pub autostart: bool,
    /// The evaluator exits after this long without requests.
    pub idle_timeout_secs: u64,
    /// How long a hook waits for the evaluator before falling back.
    pub request_timeout_ms: u64,
    /// Socket path. Defaults to `<state_dir>/evaluator.sock`.
    pub socket: Option<PathBuf>,
}

impl Default for EvaluatorSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            autostart: true,
            idle_timeout_secs: 30 * 60,
            request_timeout_ms: 10_000,
            socket: None,
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            mode: Mode::Enforce,
            on_error: OnError::Allow,
            on_unevaluable: OnError::Ask,
            reason_detail: ReasonDetail::Full,
            state_dir: None,
            telemetry_path: None,
            thresholds: Thresholds::default(),
            window: Window::default(),
            telltale: TelltaleSettings::default(),
            source: None,
            evaluator: EvaluatorSettings::default(),
        }
    }
}

#[derive(Debug)]
pub enum ConfigError {
    Read(PathBuf, std::io::Error),
    Parse(PathBuf, String),
    Invalid(&'static str),
    /// A referenced rule, package or policy file is missing or not a regular file.
    RuleFile(PathBuf, std::io::Error),
    NoStateDir,
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Read(path, error) => write!(f, "cannot read config {}: {error}", path.display()),
            Self::RuleFile(path, error) => write!(
                f,
                "invalid config: referenced file {} is unusable: {error}",
                path.display()
            ),
            Self::Parse(path, error) => write!(f, "invalid config {}: {error}", path.display()),
            Self::Invalid(what) => write!(f, "invalid config: {what}"),
            Self::NoStateDir => write!(f, "no state directory: set {NO_STATE_DIR_HINT}"),
        }
    }
}

impl std::error::Error for ConfigError {}

#[cfg(not(windows))]
const NO_STATE_DIR_HINT: &str = "TELLTALE_HOOKS_STATE_DIR, XDG_STATE_HOME or HOME";
#[cfg(windows)]
const NO_STATE_DIR_HINT: &str = "TELLTALE_HOOKS_STATE_DIR or LOCALAPPDATA";

pub const CONFIG_ENV: &str = "TELLTALE_HOOKS_CONFIG";
pub const STATE_DIR_ENV: &str = "TELLTALE_HOOKS_STATE_DIR";
pub const TELEMETRY_ENV: &str = "TELLTALE_HOOKS_TELEMETRY";
/// `0`/`off` disables the long-lived evaluator for this process (tests, debugging).
pub const EVALUATOR_ENV: &str = "TELLTALE_HOOKS_EVALUATOR";

impl Config {
    /// Load from `TELLTALE_HOOKS_CONFIG`, else the platform default config file
    /// (`default_config_path`) when present, else defaults.
    /// An explicitly named file that cannot be read is an error, never a silent default.
    pub fn load() -> Result<Self, ConfigError> {
        let explicit = std::env::var_os(CONFIG_ENV).map(PathBuf::from);
        let path = match explicit {
            Some(path) => Some(path),
            None => default_config_path().filter(|path| path.is_file()),
        };
        let mut config = match path {
            Some(path) => {
                let mut config = Self::from_file(&path)?;
                config.source = Some(path);
                config
            }
            None => Self::default(),
        };
        if let Some(dir) = std::env::var_os(STATE_DIR_ENV) {
            config.state_dir = Some(PathBuf::from(dir));
        }
        if let Some(path) = std::env::var_os(TELEMETRY_ENV) {
            config.telemetry_path = Some(PathBuf::from(path));
        }
        if let Ok(value) = std::env::var(EVALUATOR_ENV) {
            match value.as_str() {
                "0" | "off" | "false" => config.evaluator.enabled = false,
                "1" | "on" | "true" => config.evaluator.enabled = true,
                _ => {
                    return Err(ConfigError::Invalid(
                        "TELLTALE_HOOKS_EVALUATOR must be 0 or 1",
                    ));
                }
            }
        }
        config.validate()?;
        config.make_paths_absolute();
        Ok(config)
    }

    pub fn from_file(path: &Path) -> Result<Self, ConfigError> {
        // An operator input: a symlink is followed, but the target must be a
        // regular file. A FIFO or directory is refused like an unreadable
        // config (tool calls are then denied), never waited on.
        let text = crate::hooks::state::read_operator_input(path)
            .map_err(|e| ConfigError::Read(path.to_owned(), e))?;
        let config = Self::from_toml(&text).map_err(|e| match e {
            ConfigError::Parse(_, message) => ConfigError::Parse(path.to_owned(), message),
            other => other,
        })?;
        config.validate_files()?;
        Ok(config)
    }

    /// Parse and validate values only; `from_file` also validates the files
    /// the configuration references.
    pub fn from_toml(text: &str) -> Result<Self, ConfigError> {
        let config: Self =
            toml::from_str(text).map_err(|e| ConfigError::Parse(PathBuf::new(), e.to_string()))?;
        config.validate()?;
        Ok(config)
    }

    /// Rule, package and policy files referenced by the configuration.
    pub fn referenced_files(&self) -> impl Iterator<Item = &PathBuf> {
        let t = &self.telltale;
        t.rules
            .iter()
            .chain(&t.rule_packages)
            .chain(t.policy.iter())
    }

    /// Every referenced file must exist and resolve to a regular file at load
    /// time; otherwise the configuration is invalid and tool calls are denied
    /// (the documented loud path) instead of silently running without the
    /// content the operator asked for. Checked by a non-blocking open, so a
    /// FIFO is refused rather than waited on.
    fn validate_files(&self) -> Result<(), ConfigError> {
        for path in self.referenced_files() {
            crate::hooks::state::open_operator_input(path)
                .map_err(|e| ConfigError::RuleFile(path.clone(), e))?;
        }
        Ok(())
    }

    fn validate(&self) -> Result<(), ConfigError> {
        let t = &self.thresholds;
        if t.action_ask == 0 || t.action_deny == 0 {
            return Err(ConfigError::Invalid("action thresholds must be positive"));
        }
        if t.action_ask > t.action_deny {
            return Err(ConfigError::Invalid(
                "thresholds.action_ask exceeds action_deny",
            ));
        }
        if t.session_ask > t.session_deny {
            return Err(ConfigError::Invalid(
                "thresholds.session_ask exceeds session_deny",
            ));
        }
        if self.window.max_records == 0 || self.window.max_bytes == 0 {
            return Err(ConfigError::Invalid("window bounds must be positive"));
        }
        Ok(())
    }

    pub fn resolved_state_dir(&self) -> Result<PathBuf, ConfigError> {
        if let Some(dir) = &self.state_dir {
            return Ok(dir.clone());
        }
        default_state_dir().ok_or(ConfigError::NoStateDir)
    }

    /// Paths an agent must not modify: state, telemetry and configuration.
    pub fn protected_paths(&self) -> Vec<PathBuf> {
        let mut paths = Vec::new();
        paths.extend(self.resolved_state_dir().ok());
        paths.extend(self.resolved_telemetry_path().ok());
        // Only Unix has an evaluator socket.
        #[cfg(unix)]
        paths.extend(self.resolved_socket_path().ok());
        paths.extend(self.source.clone());
        paths.extend(default_config_path());
        // Rule, package and policy files: tampering with them changes what
        // is detected, so the generated self-protection rule covers them.
        paths.extend(self.referenced_files().cloned());
        paths
    }

    /// `<state_dir>/evaluator.sock`, unless that exceeds the Unix socket path
    /// limit (108 bytes on Linux, 104 on macOS): then a short per-user path
    /// under `$XDG_RUNTIME_DIR` or `/tmp`, keyed by the state dir. Verified in
    /// a real run where a long state dir made every bind fail.
    pub fn resolved_socket_path(&self) -> Result<PathBuf, ConfigError> {
        use sha2::{Digest, Sha256};
        if let Some(path) = &self.evaluator.socket {
            return Ok(path.clone());
        }
        let state = self.resolved_state_dir()?;
        let default = state.join("evaluator.sock");
        if default.as_os_str().len() <= MAX_SOCKET_PATH_BYTES {
            return Ok(default);
        }
        let base = std::env::var_os("XDG_RUNTIME_DIR")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/tmp"));
        let digest = hex::encode(Sha256::digest(state.as_os_str().as_encoded_bytes()));
        Ok(base
            .join(format!("telltale-hooks-{}", current_uid()))
            .join(format!("{}.sock", &digest[..16])))
    }

    /// Identity of everything that changes evaluation results: the effective
    /// configuration, the bytes of every referenced rule or policy file, and
    /// this build. A long-lived evaluator serves only clients whose
    /// fingerprint equals its own.
    pub fn fingerprint(&self) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        let mut part = |label: &str, bytes: &[u8]| {
            hasher.update((label.len() as u64).to_be_bytes());
            hasher.update(label.as_bytes());
            hasher.update((bytes.len() as u64).to_be_bytes());
            hasher.update(bytes);
        };
        // The running build (identity module): package version, host build
        // metadata and the executable file itself, so a rebuilt or upgraded
        // binary never shares an evaluator with the old one.
        part("build", identity::PACKAGE_VERSION.as_bytes());
        part("host_build", identity::host_build().as_bytes());
        part("executable", identity::executable_identity().as_bytes());
        part("revision", identity::revision().as_bytes());
        part("config", format!("{self:?}").as_bytes());
        // Every input to Engine::new, including environment-derived paths
        // (XDG_CONFIG_HOME, HOME, XDG_RUNTIME_DIR; APPDATA, LOCALAPPDATA,
        // USERPROFILE on Windows; CODEX_HOME, COPILOT_HOME).
        let state = self.resolved_state_dir().ok();
        let telemetry = self.resolved_telemetry_path().ok();
        let socket = self.resolved_socket_path().ok();
        part(
            "paths",
            format!(
                "{state:?}|{telemetry:?}|{socket:?}|{:?}|{:?}|{:?}",
                self.protected_paths(),
                harness_homes(),
                user_home()
            )
            .as_bytes(),
        );
        for path in self.referenced_files() {
            let text = crate::hooks::state::read_operator_input(path)
                .unwrap_or_else(|_| "<unreadable>".to_owned());
            part(&path.to_string_lossy(), text.as_bytes());
        }
        hex::encode(hasher.finalize())
    }

    /// Configured paths become absolute (a relative state dir would otherwise
    /// split one session's journal between the daemon and in-process runs).
    pub fn make_paths_absolute(&mut self) {
        for path in self
            .state_dir
            .iter_mut()
            .chain(self.telemetry_path.iter_mut())
            .chain(self.evaluator.socket.iter_mut())
            .chain(self.source.iter_mut())
            .chain(self.telltale.rules.iter_mut())
            .chain(self.telltale.rule_packages.iter_mut())
            .chain(self.telltale.policy.iter_mut())
        {
            absolute(path);
        }
    }

    pub fn resolved_telemetry_path(&self) -> Result<PathBuf, ConfigError> {
        match &self.telemetry_path {
            Some(path) => Ok(path.clone()),
            None => Ok(self.resolved_state_dir()?.join("telemetry.jsonl")),
        }
    }
}

/// Resolve a relative path against the current directory, so a daemon
/// started from another directory reads and writes the same files.
fn absolute(path: &mut PathBuf) {
    if path.is_relative()
        && let Ok(cwd) = std::env::current_dir()
    {
        *path = cwd.join(&*path);
    }
}

/// Conservative bound under every platform's `sun_path` size.
pub const MAX_SOCKET_PATH_BYTES: usize = 100;

#[cfg(unix)]
pub fn current_uid() -> u32 {
    // SAFETY: getuid has no preconditions and cannot fail.
    unsafe { libc::getuid() }
}

#[cfg(not(unix))]
pub fn current_uid() -> u32 {
    0
}

/// A harness configuration home named by this process's environment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HarnessHome {
    pub variable: &'static str,
    pub path: PathBuf,
}

/// `CODEX_HOME` and `COPILOT_HOME` as the hook sees them. A harness moved there
/// loads its hooks from that directory, and static rules can only know the
/// variable's name and the default directory, so the engine generates rules
/// for these literal paths. A hook inherits these from the harness, so this
/// covers the home of the session being monitored. Relative values and whatever
/// resolves to a root are ignored: they would match unrelated paths, or every
/// path. Each is also listed as its canonical path when that differs (Codex
/// canonicalizes `CODEX_HOME`).
pub fn harness_homes() -> Vec<HarnessHome> {
    let mut homes = Vec::new();
    for variable in ["CODEX_HOME", "COPILOT_HOME"] {
        let Some(path) = env_path(variable) else {
            continue;
        };
        if !path.is_absolute() || !names_below_root(&path) {
            continue;
        }
        let canonical = std::fs::canonicalize(&path).ok().map(|canonical| {
            let text = canonical.to_string_lossy();
            // Windows verbatim prefix: no one spells a path this way.
            match text.strip_prefix(r"\\?\") {
                Some(plain) => PathBuf::from(plain),
                None => canonical.clone(),
            }
        });
        // `/usr/..`, or a link to `/`.
        if canonical
            .as_deref()
            .is_some_and(|path| !names_below_root(path))
        {
            continue;
        }
        homes.push(HarnessHome {
            variable,
            path: path.clone(),
        });
        if let Some(canonical) = canonical.filter(|canonical| *canonical != path) {
            homes.push(HarnessHome {
                variable,
                path: canonical,
            });
        }
    }
    homes
}

/// The user's home as this process sees it, which a shell also spells `~`.
pub fn user_home() -> Option<PathBuf> {
    env_path(if cfg!(windows) { "USERPROFILE" } else { "HOME" })
        .filter(|path| path.is_absolute() && names_below_root(path))
}

/// False for `/`, `//`, `/.`, `.` and `C:\`: a rule for such a path would match
/// any path, and so deny every write.
pub fn names_below_root(path: &Path) -> bool {
    path.components()
        .any(|component| matches!(component, std::path::Component::Normal(_)))
}

/// A non-empty environment variable as a path.
fn env_path(name: &str) -> Option<PathBuf> {
    std::env::var_os(name)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
}

/// Linux and macOS: `$XDG_CONFIG_HOME/telltale-hooks/config.toml`, else
/// `~/.config/telltale-hooks/config.toml`.
#[cfg(not(windows))]
fn default_config_path() -> Option<PathBuf> {
    if let Some(dir) = env_path("XDG_CONFIG_HOME") {
        return Some(dir.join("telltale-hooks/config.toml"));
    }
    env_path("HOME").map(|home| home.join(".config/telltale-hooks/config.toml"))
}

/// Windows: `%APPDATA%\telltale-hooks\config.toml` (roaming settings).
#[cfg(windows)]
fn default_config_path() -> Option<PathBuf> {
    env_path("APPDATA").map(|dir| dir.join("telltale-hooks").join("config.toml"))
}

/// Linux and macOS: `$XDG_STATE_HOME/telltale-hooks`, else
/// `~/.local/state/telltale-hooks`.
#[cfg(not(windows))]
fn default_state_dir() -> Option<PathBuf> {
    if let Some(dir) = env_path("XDG_STATE_HOME") {
        return Some(dir.join("telltale-hooks"));
    }
    env_path("HOME").map(|home| home.join(".local/state/telltale-hooks"))
}

/// Windows: `%LOCALAPPDATA%\telltale-hooks` (machine-local, never roamed).
#[cfg(windows)]
fn default_state_dir() -> Option<PathBuf> {
    env_path("LOCALAPPDATA").map(|dir| dir.join("telltale-hooks"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_valid_and_enforcing() {
        let config = Config::from_toml("").unwrap();
        assert_eq!(config.mode, Mode::Enforce);
        assert_eq!(config.on_error, OnError::Allow);
        assert_eq!(config.thresholds.action_deny, 90);
    }

    #[test]
    fn rejects_unknown_keys_and_inverted_thresholds() {
        assert!(Config::from_toml("modee = \"observe\"").is_err());
        assert!(Config::from_toml("[thresholds]\naction_ask = 95\naction_deny = 90").is_err());
    }

    #[test]
    fn fingerprint_tracks_configuration_and_rule_content() {
        let dir = tempfile::tempdir().unwrap();
        let rules = dir.path().join("r.yaml");
        std::fs::write(&rules, "a").unwrap();
        let mut config = Config {
            state_dir: Some(dir.path().to_owned()),
            ..Config::default()
        };
        config.telltale.rules = vec![rules.clone()];
        let first = config.fingerprint();
        assert_eq!(first, config.fingerprint());
        std::fs::write(&rules, "b").unwrap();
        let second = config.fingerprint();
        assert_ne!(first, second, "rule content change");
        config.thresholds.action_deny = 95;
        assert_ne!(second, config.fingerprint(), "policy change");
    }

    #[test]
    fn long_state_dirs_get_a_short_socket_path() {
        let mut config = Config {
            state_dir: Some(PathBuf::from("/s")),
            ..Config::default()
        };
        assert_eq!(
            config.resolved_socket_path().unwrap(),
            PathBuf::from("/s/evaluator.sock")
        );
        config.state_dir = Some(PathBuf::from(format!("/{}", "d".repeat(120))));
        let socket = config.resolved_socket_path().unwrap();
        assert!(
            socket.as_os_str().len() <= MAX_SOCKET_PATH_BYTES,
            "{socket:?}"
        );
        assert!(
            socket
                .to_string_lossy()
                .contains(&format!("telltale-hooks-{}", current_uid()))
        );
    }

    #[test]
    fn relative_paths_become_absolute() {
        let mut config =
            Config::from_toml("state_dir = \"rel/state\"\n[telltale]\nrules = [\"r.yaml\"]")
                .unwrap();
        config.make_paths_absolute();
        assert!(config.state_dir.as_ref().unwrap().is_absolute());
        assert!(config.telltale.rules[0].is_absolute());
    }

    #[test]
    fn fingerprint_names_the_build_and_its_paths() {
        let a = Config {
            state_dir: Some(PathBuf::from("/a")),
            ..Config::default()
        };
        let b = Config {
            state_dir: Some(PathBuf::from("/a")),
            evaluator: EvaluatorSettings {
                socket: Some(PathBuf::from("/elsewhere.sock")),
                ..EvaluatorSettings::default()
            },
            ..Config::default()
        };
        assert_ne!(a.fingerprint(), b.fingerprint());
    }

    #[test]
    fn parses_observe_mode() {
        let config = Config::from_toml("mode = \"observe\"\non_error = \"deny\"").unwrap();
        assert_eq!(config.mode, Mode::Observe);
        assert_eq!(config.on_error, OnError::Deny);
    }
}
