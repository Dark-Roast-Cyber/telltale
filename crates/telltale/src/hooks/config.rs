//! Operator configuration. Everything here is host policy: Telltale owns
//! detection semantics, the host owns promotion thresholds and enforcement
//! (docs/embedding.md "Contract at a glance").
//!
//! Typed values only: the CLI reads them from the `hooks:` section of
//! `settings.d` and the `TELLTALE_HOOKS_*` environment, and embedders build a
//! [`Config`] directly.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::hooks::harness::{Harness, Home};
use crate::hooks::identity;
use crate::rule_resolution::RulePackPaths;

/// What every ID of a host self-protection rule, bundled or generated, starts
/// with. With [`RuleContent::tamper_prevention`] on, the namespace is the
/// host's: no user rule content may name an ID in it.
pub const HOST_RULE_ID_PREFIX: &str = "tth.tamper.";

/// What the ID of every enforcement test signature starts with
/// ([`RuleContent::test_signatures`]).
pub const TEST_RULE_ID_PREFIX: &str = "tth.test.";

/// The category of every host and generated rule.
pub const HOST_RULE_CATEGORY: &str = "approval_bypass";

/// Whether decisions are returned to the harness or only recorded.
///
/// Detect-only (`observe`) is the default. Blocking needs a configuration that
/// was read and says `mode: enforce`: see [`crate::hooks::gate`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    /// Return ask/deny decisions to the harness.
    Enforce,
    /// Detect only: record the decision that would have been made and never
    /// influence the harness. Also spelled `detect`.
    #[serde(alias = "detect")]
    Observe,
}

/// What the hook tells the harness when it cannot evaluate an action.
/// Ordered from least to most strict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OnError {
    /// Fail open: express no opinion, the harness's own permission flow decides.
    Allow,
    /// Ask the human (in headless runs the harness treats this as a denial).
    Ask,
    /// Fail closed.
    Deny,
}

#[derive(Debug, Clone)]
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

#[derive(Debug, Clone)]
pub struct Window {
    /// Most recent journal records evaluated together with the pending action.
    pub max_records: usize,
    /// Byte bound on the journal tail that is read.
    pub max_bytes: u64,
    /// Bound on one prompt or tool result stored in the journal: bytes as the
    /// journal line encodes the text (escaped JSON), cut on a char boundary.
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

/// The rule content hooks evaluate with: the same packages, rule folders,
/// overrides and policy as `scan`, resolved by [`crate::rule_resolution`],
/// plus the bundled host self-protection rules.
#[derive(Debug, Clone)]
pub struct RuleContent {
    /// Rule packages, the organization, deployment and local rule documents,
    /// and whether community rules take part.
    pub packs: RulePackPaths,
    /// Rule override documents (`overrides.d`), applied in order.
    pub overrides: Vec<PathBuf>,
    /// Policy document (`policies.d`, enable/disable).
    pub policy: Option<PathBuf>,
    /// The bundled process-chain pack in the same pass.
    pub process_chain: bool,
    /// The bundled host self-protection rules (`engine::host_rule_documents`)
    /// and the generated rule for this installation's own paths.
    pub self_protection: bool,
    /// Tamper prevention: the self-protection rules are locked. Rule content
    /// that names one of their IDs, and a policy under which one would not
    /// stay enabled, is invalid configuration. Off by default: the rules are
    /// then ordinary bundled rules that overrides, policies and replacement
    /// rules can tune or disable. Needs [`Self::self_protection`].
    pub tamper_prevention: bool,
    /// The enforcement test signatures (`engine::test_signature_document`):
    /// rules that match one harmless command each, for checking what a hook
    /// does end to end. Off by default. While on, a call that only those
    /// rules match (`Engine::test_signatures`) is decided on its own score
    /// and stays out of its session's score and attempts.
    pub test_signatures: bool,
}

impl Default for RuleContent {
    fn default() -> Self {
        Self {
            packs: RulePackPaths::default(),
            overrides: Vec::new(),
            policy: None,
            process_chain: true,
            self_protection: true,
            tamper_prevention: false,
            test_signatures: false,
        }
    }
}

impl RuleContent {
    /// The first file of user rule content that names an ID in the host rules'
    /// namespace (an override entry, or a rule or modifier in a rule document
    /// or package), while tamper prevention is on. A file that does not parse
    /// is not reported here: building the rules fails on it.
    fn host_rule_claim(&self) -> Option<&Path> {
        if !self.tamper_prevention {
            return None;
        }
        let read = |path: &Path| crate::hooks::state::read_operator_input(path).ok();
        let reserved = |id: &str| id.starts_with(HOST_RULE_ID_PREFIX);
        let in_set = |set: &telltale_rules::LoadedRules| {
            set.definitions()
                .iter()
                .any(|definition| reserved(definition.id()))
        };
        let packs = &self.packs;
        let documents = packs
            .organization
            .iter()
            .chain(&packs.deployment)
            .chain(&packs.local)
            .find(|path| {
                read(path)
                    .and_then(|text| telltale_rules::LoadedRules::parse(&text).ok())
                    .is_some_and(|set| in_set(&set))
            });
        let packages = packs.packages.iter().find(|path| {
            read(path)
                .and_then(|text| telltale_rules::package::RulePackage::parse(&text).ok())
                .is_some_and(|package| package.documents().iter().any(in_set))
        });
        let overrides = self.overrides.iter().find(|path| {
            read(path)
                .and_then(|text| {
                    serde_yaml::from_str::<telltale_rules::RuleOverrideDocument>(&text).ok()
                })
                .is_some_and(|document| document.rule_ids().any(reserved))
        });
        documents.or(packages).or(overrides).map(PathBuf::as_path)
    }

    /// Every rule, package, override and policy file.
    pub fn files(&self) -> impl Iterator<Item = &PathBuf> {
        let packs = &self.packs;
        packs
            .packages
            .iter()
            .chain(&packs.organization)
            .chain(&packs.deployment)
            .chain(&packs.local)
            .chain(&self.overrides)
            .chain(self.policy.iter())
    }
}

/// How much a deny/ask reason discloses to the model (and the user).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
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

/// How an `ask` verdict reaches the user.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AskRoute {
    /// The harness's own approval prompt, where the harness has one that a
    /// human answers (`Adapter::can_ask`). A harness without one is given
    /// the ask as [`Self::Model`] does.
    Human,
    /// Through the model, on every harness: the call is returned as a deny
    /// whose reason tells the model to stop and ask the user how to proceed
    /// (`runtime::ASK_THROUGH_MODEL_NOTE`). The harness's approval prompt is
    /// not used. Telltale takes no approval from the conversation: the same
    /// call asked again is not run either.
    Model,
}

impl AskRoute {
    /// Whether an ask is put to a human by a harness that can (`can_ask`).
    pub fn prompts_human(self, can_ask: bool) -> bool {
        can_ask && self == Self::Human
    }
}

/// Grants (`hooks.grants`): the user allows a call the hook stopped by typing
/// a grant line as a prompt of its own, on a harness that raises an event for
/// the prompt of the person using it (`Adapter::can_grant`). Telltale still
/// never returns `allow`: a covered call is given no opinion, and the
/// harness's own permission rules still apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Grants {
    /// Off by default: no grant is offered or taken.
    pub enabled: bool,
    /// Which stopped calls a grant can cover.
    pub covers: GrantCover,
}

impl Default for Grants {
    fn default() -> Self {
        Self {
            enabled: false,
            covers: GrantCover::AskAndDeny,
        }
    }
}

/// Which policy verdicts a grant can cover. Host self-protection rules are
/// never covered, whatever this says.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantCover {
    /// Only calls the policy asked about.
    Ask,
    /// Calls the policy asked about or denied.
    AskAndDeny,
}

#[derive(Debug, Clone)]
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
    /// How an `ask` reaches the user (`hooks.ask`).
    pub ask: AskRoute,
    /// Whether and what the user can allow from the harness's prompt.
    pub grants: Grants,
    /// Directory for per-session journals and state.
    pub state_dir: Option<PathBuf>,
    /// Telemetry JSONL path. Defaults to `<state_dir>/telemetry.jsonl`.
    pub telemetry_path: Option<PathBuf>,
    pub thresholds: Thresholds,
    pub window: Window,
    pub rules: RuleContent,
    /// Where this configuration came from: the config folders that were read
    /// and the settings files in them. Self-protection covers them, so an
    /// agent cannot quietly change what the hook reads next.
    pub sources: Vec<PathBuf>,
    pub evaluator: EvaluatorSettings,
    /// The sources whose different value a pin on the hook command replaced
    /// in this invocation's launch, by name only (an environment variable, or
    /// a settings key such as `hooks.state_dir`), sorted: the `session_start`
    /// record lists them in `lifecycle.pinned_over`. Empty when nothing was
    /// pinned over. Not part of [`Self::fingerprint`].
    pub pinned_over: Vec<String>,
}

#[derive(Debug, Clone)]
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

/// The default `request_timeout_ms`.
pub const DEFAULT_REQUEST_TIMEOUT_MS: u64 = 10_000;

impl Default for EvaluatorSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            autostart: true,
            idle_timeout_secs: 30 * 60,
            request_timeout_ms: DEFAULT_REQUEST_TIMEOUT_MS,
            socket: None,
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            mode: Mode::Observe,
            on_error: OnError::Allow,
            on_unevaluable: OnError::Ask,
            reason_detail: ReasonDetail::Full,
            ask: AskRoute::Human,
            grants: Grants::default(),
            state_dir: None,
            telemetry_path: None,
            thresholds: Thresholds::default(),
            window: Window::default(),
            rules: RuleContent::default(),
            sources: Vec::new(),
            evaluator: EvaluatorSettings::default(),
            pinned_over: Vec::new(),
        }
    }
}

#[derive(Debug)]
pub enum ConfigError {
    Invalid(&'static str),
    /// A rule, package or override file names a host rule ID.
    HostRuleClaimed(PathBuf),
    /// The policy file would leave a host rule out of the rules.
    PolicyDropsHostRule(PathBuf),
    NoStateDir,
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(what) => write!(f, "invalid config: {what}"),
            Self::HostRuleClaimed(path) => write!(
                f,
                "invalid config: {} names a rule ID under {HOST_RULE_ID_PREFIX}*, which hooks reserves for its self-protection rules while hooks.tamper_prevention.enabled is on",
                path.display()
            ),
            Self::PolicyDropsHostRule(path) => write!(
                f,
                "invalid config: the policy {} would turn off hooks self-protection rules, which stay on while hooks.tamper_prevention.enabled is on; a policy that selects by category must include {HOST_RULE_CATEGORY}, and one that selects by rule ID must list every {HOST_RULE_ID_PREFIX}* rule",
                path.display()
            ),
            Self::NoStateDir => write!(f, "no state directory: set {NO_STATE_DIR_HINT}"),
        }
    }
}

impl std::error::Error for ConfigError {}

#[cfg(not(windows))]
const NO_STATE_DIR_HINT: &str = "hooks.state_dir, TELLTALE_HOOKS_STATE_DIR, XDG_STATE_HOME or HOME";
#[cfg(windows)]
const NO_STATE_DIR_HINT: &str = "hooks.state_dir, TELLTALE_HOOKS_STATE_DIR or LOCALAPPDATA";

impl Config {
    /// What a detect-only hook runs on when its configuration could not be
    /// loaded: the defaults, with the state and telemetry paths the caller
    /// could still determine, evaluated in-process (an evaluator is keyed by a
    /// configuration this hook does not have). Detection continues and the
    /// failure is recorded.
    pub fn detect_only_fallback(
        state_dir: Option<PathBuf>,
        telemetry_path: Option<PathBuf>,
    ) -> Self {
        let mut config = Self {
            mode: Mode::Observe,
            state_dir,
            telemetry_path,
            evaluator: EvaluatorSettings {
                enabled: false,
                ..EvaluatorSettings::default()
            },
            ..Self::default()
        };
        config.make_paths_absolute();
        config
    }

    /// Values that constrain each other, and rule content that may not exist
    /// next to the host rules, checked before the configuration is used.
    pub fn validate(&self) -> Result<(), ConfigError> {
        let t = &self.thresholds;
        if t.action_ask == 0 || t.action_deny == 0 {
            return Err(ConfigError::Invalid("action thresholds must be positive"));
        }
        if t.action_ask > t.action_deny {
            return Err(ConfigError::Invalid(
                "hooks.thresholds.action_ask exceeds action_deny",
            ));
        }
        if t.session_ask > t.session_deny {
            return Err(ConfigError::Invalid(
                "hooks.thresholds.session_ask exceeds session_deny",
            ));
        }
        if self.window.max_records == 0 || self.window.max_bytes == 0 {
            return Err(ConfigError::Invalid("window bounds must be positive"));
        }
        if self.rules.tamper_prevention && !self.rules.self_protection {
            return Err(ConfigError::Invalid(
                "hooks.tamper_prevention.enabled needs hooks.self_protection_rules: it locks those rules",
            ));
        }
        if self.grants.enabled && !self.rules.self_protection {
            return Err(ConfigError::Invalid(
                "hooks.grants.enabled needs hooks.self_protection_rules: those rules protect the session state that holds a grant",
            ));
        }
        if let Some(path) = self.rules.host_rule_claim() {
            return Err(ConfigError::HostRuleClaimed(path.to_owned()));
        }
        if self.rules.tamper_prevention
            && let Some(policy) = &self.rules.policy
            && crate::hooks::engine::policy_drops_host_rule(
                policy,
                self.grants.enabled,
                &self.protected_paths(),
            )
        {
            return Err(ConfigError::PolicyDropsHostRule(policy.clone()));
        }
        Ok(())
    }

    pub fn resolved_state_dir(&self) -> Result<PathBuf, ConfigError> {
        if let Some(dir) = &self.state_dir {
            return Ok(dir.clone());
        }
        default_state_dir().ok_or(ConfigError::NoStateDir)
    }

    /// Paths an agent must not modify: state, telemetry, the configuration
    /// and the rule content it names.
    pub fn protected_paths(&self) -> Vec<PathBuf> {
        let mut paths = Vec::new();
        paths.extend(self.resolved_state_dir().ok());
        paths.extend(self.resolved_telemetry_path().ok());
        // Only Unix has an evaluator socket.
        #[cfg(unix)]
        paths.extend(self.resolved_socket_path().ok());
        paths.extend(self.sources.iter().cloned());
        // Rule, package, override and policy files: tampering with them
        // changes what is detected, so the generated self-protection rule
        // covers them.
        paths.extend(self.rules.files().cloned());
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
    /// configuration, the bytes of every rule, package, override or policy
    /// file, and this build. A long-lived evaluator serves only clients whose
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
        // `pinned_over` describes one invocation's launch, not what is
        // evaluated: hooks launched differently share an evaluator.
        let evaluated = Self {
            pinned_over: Vec::new(),
            ..self.clone()
        };
        part("config", format!("{evaluated:?}").as_bytes());
        // Every input to Engine::new, including environment-derived paths
        // (XDG_STATE_HOME, HOME, XDG_RUNTIME_DIR; LOCALAPPDATA, USERPROFILE on
        // Windows; each harness's home variable).
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
        for path in self.rules.files() {
            let text = crate::hooks::state::read_operator_input(path)
                .unwrap_or_else(|_| "<unreadable>".to_owned());
            part(&path.to_string_lossy(), text.as_bytes());
        }
        hex::encode(hasher.finalize())
    }

    /// Configured paths become absolute (a relative state dir would otherwise
    /// split one session's journal between the daemon and in-process runs).
    pub fn make_paths_absolute(&mut self) {
        let packs = &mut self.rules.packs;
        for path in self
            .state_dir
            .iter_mut()
            .chain(self.telemetry_path.iter_mut())
            .chain(self.evaluator.socket.iter_mut())
            .chain(self.sources.iter_mut())
            .chain(packs.packages.iter_mut())
            .chain(packs.organization.iter_mut())
            .chain(packs.deployment.iter_mut())
            .chain(packs.local.iter_mut())
            .chain(self.rules.overrides.iter_mut())
            .chain(self.rules.policy.iter_mut())
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
    /// Pattern text for the hook files below the home (`harness::Home`).
    pub hook_files: &'static str,
    pub path: PathBuf,
}

/// Every adapter's relocatable config home (`Adapter::home`) as the hook sees
/// it. A harness moved there
/// loads its hooks from that directory, and static rules can only know the
/// variable's name and the default directory, so the engine generates rules
/// for these literal paths. A hook inherits these from the harness, so this
/// covers the home of the session being monitored. Relative values and whatever
/// resolves to a root are ignored: they would match unrelated paths, or every
/// path. Each is also listed as its canonical path when that differs (Codex
/// canonicalizes `CODEX_HOME`).
pub fn harness_homes() -> Vec<HarnessHome> {
    let mut homes = Vec::new();
    let declared = Harness::ALL
        .iter()
        .filter_map(|harness| harness.adapter().home);
    for Home {
        variable,
        hook_files,
    } in declared
    {
        let Some(path) = env_path(variable) else {
            continue;
        };
        if !path.is_absolute() || !names_below_root(&path) {
            continue;
        }
        let canonical = plain_canonical(&path);
        // `/usr/..`, or a link to `/`.
        if canonical
            .as_deref()
            .is_some_and(|path| !names_below_root(path))
        {
            continue;
        }
        homes.push(HarnessHome {
            variable,
            hook_files,
            path: path.clone(),
        });
        if let Some(canonical) = canonical.filter(|canonical| *canonical != path) {
            homes.push(HarnessHome {
                variable,
                hook_files,
                path: canonical,
            });
        }
    }
    homes
}

/// `path` canonicalized, without the Windows verbatim prefix (`\\?\`): no
/// one spells a path that way, so a rule for it would never match.
pub fn plain_canonical(path: &Path) -> Option<PathBuf> {
    let canonical = std::fs::canonicalize(path).ok()?;
    let plain = canonical
        .to_str()
        .and_then(|text| text.strip_prefix(r"\\?\"))
        .map(PathBuf::from);
    Some(plain.unwrap_or(canonical))
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

fn default_state_dir() -> Option<PathBuf> {
    default_state_dir_source().map(|(_, dir)| dir)
}

/// The state directory used when none is configured, and the environment
/// variable that decided it. Linux and macOS: `$XDG_STATE_HOME/telltale/hooks`,
/// else `~/.local/state/telltale/hooks`.
#[cfg(not(windows))]
pub fn default_state_dir_source() -> Option<(&'static str, PathBuf)> {
    if let Some(dir) = env_path("XDG_STATE_HOME") {
        return Some(("XDG_STATE_HOME", dir.join("telltale/hooks")));
    }
    env_path("HOME").map(|home| ("HOME", home.join(".local/state/telltale/hooks")))
}

/// Windows: `%LOCALAPPDATA%\telltale\hooks` (machine-local, never roamed).
#[cfg(windows)]
pub fn default_state_dir_source() -> Option<(&'static str, PathBuf)> {
    env_path("LOCALAPPDATA").map(|dir| ("LOCALAPPDATA", dir.join("telltale").join("hooks")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_valid_and_detect_only() {
        let config = Config::default();
        config.validate().unwrap();
        assert_eq!(config.mode, Mode::Observe);
        assert_eq!(config.on_error, OnError::Allow);
        assert_eq!(config.thresholds.action_deny, 90);
        assert!(config.rules.self_protection);
        assert!(!config.rules.tamper_prevention);
        assert!(!config.rules.test_signatures);
        // Pipelines that do not carry the self-protection rules or the test
        // signatures leave out override entries for them by these prefixes.
        assert_eq!(
            crate::rule_resolution::HOOKS_RULE_PREFIXES,
            [HOST_RULE_ID_PREFIX, TEST_RULE_ID_PREFIX]
        );
        assert!(config.rules.process_chain);
    }

    /// Grants need the self-protection rules: they keep a tool call from
    /// writing the session state or raising a prompt of its own.
    #[test]
    fn grants_without_the_self_protection_rules_are_invalid() {
        let mut config = Config::default();
        config.grants.enabled = true;
        config.validate().unwrap();
        config.rules.self_protection = false;
        let error = config.validate().unwrap_err().to_string();
        assert!(
            error.contains("hooks.grants.enabled needs hooks.self_protection_rules"),
            "{error}"
        );
        config.grants.enabled = false;
        config.validate().unwrap();
    }

    #[test]
    fn rejects_inverted_thresholds() {
        let mut config = Config::default();
        config.thresholds.action_ask = 95;
        assert!(config.validate().is_err());
        let mut config = Config::default();
        config.thresholds.session_ask = config.thresholds.session_deny + 1;
        assert!(config.validate().is_err());
        let mut config = Config::default();
        config.window.max_records = 0;
        assert!(config.validate().is_err());
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
        config.rules.packs.deployment = vec![rules.clone()];
        let first = config.fingerprint();
        assert_eq!(first, config.fingerprint());
        std::fs::write(&rules, "b").unwrap();
        let second = config.fingerprint();
        assert_ne!(first, second, "rule content change");
        config.thresholds.action_deny = 95;
        assert_ne!(second, config.fingerprint(), "policy change");
        let third = config.fingerprint();
        config.grants.enabled = true;
        assert_ne!(third, config.fingerprint(), "grants change");
        let fourth = config.fingerprint();
        config.grants.covers = GrantCover::Ask;
        assert_ne!(fourth, config.fingerprint(), "grant cover change");
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
        let length = socket.as_os_str().len();
        assert!(
            length <= MAX_SOCKET_PATH_BYTES,
            "socket path of {length} bytes"
        );
        assert!(
            socket
                .to_string_lossy()
                .contains(&format!("telltale-hooks-{}", current_uid()))
        );
    }

    #[test]
    fn relative_paths_become_absolute() {
        let mut config = Config {
            state_dir: Some(PathBuf::from("rel/state")),
            ..Config::default()
        };
        config.rules.packs.deployment = vec![PathBuf::from("r.yaml")];
        config.sources = vec![PathBuf::from("settings.d")];
        config.make_paths_absolute();
        assert!(config.state_dir.as_ref().unwrap().is_absolute());
        assert!(config.rules.packs.deployment[0].is_absolute());
        assert!(config.sources[0].is_absolute());
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
        let c = Config {
            state_dir: Some(PathBuf::from("/a")),
            sources: vec![PathBuf::from("/etc/telltale")],
            ..Config::default()
        };
        assert_ne!(a.fingerprint(), c.fingerprint(), "config folders");
    }

    #[test]
    fn configuration_sources_and_rule_files_are_protected() {
        let mut config = Config {
            state_dir: Some(PathBuf::from("/state")),
            sources: vec![PathBuf::from("/etc/telltale")],
            ..Config::default()
        };
        config.rules.policy = Some(PathBuf::from("/etc/telltale/policies.d/p.yaml"));
        let protected = config.protected_paths();
        assert!(protected.contains(&PathBuf::from("/state")));
        assert!(protected.contains(&PathBuf::from("/etc/telltale")));
        assert!(protected.contains(&PathBuf::from("/etc/telltale/policies.d/p.yaml")));
    }

    /// The names a pin replaced describe one invocation's launch, not the
    /// configuration: they do not key the evaluator.
    #[test]
    fn fingerprint_ignores_the_sources_a_pin_replaced() {
        let plain = Config::default();
        let pinned = Config {
            pinned_over: vec!["TELLTALE_HOOKS_STATE_DIR".into()],
            ..Config::default()
        };
        assert_eq!(plain.fingerprint(), pinned.fingerprint());
    }

    #[test]
    fn modes_parse_with_two_detect_only_spellings() {
        for spelling in ["observe", "detect"] {
            let mode: Mode = serde_json::from_value(serde_json::json!(spelling)).unwrap();
            assert_eq!(mode, Mode::Observe, "{spelling}");
        }
        let mode: Mode = serde_json::from_value(serde_json::json!("enforce")).unwrap();
        assert_eq!(mode, Mode::Enforce);
        assert!(serde_json::from_value::<Mode>(serde_json::json!("block")).is_err());
    }
}
