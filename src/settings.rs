//! Operator settings: each setting is defined once, with its default, its
//! validation, and the file key and any environment variable or flag that set
//! it.
//!
//! Precedence, lowest to highest: compiled defaults, `settings.d/*.yaml` in
//! config-root order (sorted within a root, so a later file wins per key),
//! `TELLTALE_*` environment variables, then explicit CLI flags. Settings are
//! resolved once when a command starts; a service restart applies changes.
//! Values that constrain each other, such as the risk threshold order, are
//! checked after the merge and before anything is activated.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use telltale_schema::event::{OperationalAlertConfig, path_hash};
use telltale_schema::scoring::RiskThresholds;

use crate::sink::RotationConfig;

const SUPPORTED_SETTINGS_VERSION: u32 = 1;
/// Settings files are small; a larger file is rejected before it is parsed.
const MAX_SETTINGS_FILE_BYTES: u64 = 64 * 1024;

/// An environment value that does not parse. The message names only the
/// variable, so it is safe wherever errors must stay bounded.
#[derive(Debug)]
pub(crate) struct InvalidEnvironment {
    name: &'static str,
    expected: &'static str,
}

impl std::fmt::Display for InvalidEnvironment {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "invalid {}: expected {}",
            self.name, self.expected
        )
    }
}

impl std::error::Error for InvalidEnvironment {}

#[derive(Debug)]
pub(crate) enum Origin {
    Default,
    File(PathBuf),
    Environment(&'static str),
    Cli(&'static str),
}

#[derive(Debug)]
pub(crate) struct Setting<T> {
    pub(crate) value: T,
    default: T,
    origin: Origin,
}

impl<T: Clone> Setting<T> {
    fn new(default: T) -> Self {
        Self {
            value: default.clone(),
            default,
            origin: Origin::Default,
        }
    }

    fn set(&mut self, value: Option<T>, origin: Origin) {
        if let Some(value) = value {
            self.value = value;
            self.origin = origin;
        }
    }
}

impl<T: Clone + EnvValue> Setting<T> {
    fn set_env(
        &mut self,
        env: &dyn Fn(&str) -> Option<String>,
        name: &'static str,
    ) -> Result<(), InvalidEnvironment> {
        let value = match env(name) {
            Some(raw) if !raw.trim().is_empty() => {
                Some(T::parse_env(&raw).ok_or(InvalidEnvironment {
                    name,
                    expected: T::EXPECTED,
                })?)
            }
            _ => None,
        };
        self.set(value, Origin::Environment(name));
        Ok(())
    }
}

pub(crate) trait EnvValue: Sized {
    const EXPECTED: &'static str;
    fn parse_env(raw: &str) -> Option<Self>;
}

impl EnvValue for bool {
    const EXPECTED: &'static str = "0, 1, false, true, off, on, no, or yes";
    fn parse_env(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "0" | "false" | "off" | "no" => Some(false),
            "1" | "true" | "on" | "yes" => Some(true),
            _ => None,
        }
    }
}

macro_rules! env_integer {
    ($($ty:ty),*) => {$(
        impl EnvValue for $ty {
            const EXPECTED: &'static str = "a non-negative integer";
            // Not trimmed: a padded value that earlier releases ignored fails
            // instead of silently taking effect.
            fn parse_env(raw: &str) -> Option<Self> {
                raw.parse().ok()
            }
        }
    )*};
}
env_integer!(u32, u64, usize);

/// A path setting: any non-blank value, taken as written (no `~` expansion).
impl EnvValue for Option<PathBuf> {
    const EXPECTED: &'static str = "a path";
    fn parse_env(raw: &str) -> Option<Self> {
        Some(Some(PathBuf::from(raw)))
    }
}

/// Flags that override settings for one invocation.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct CliSettings {
    pub(crate) no_community_rules: bool,
    pub(crate) log_rotate_max_size: Option<u64>,
    pub(crate) log_rotate_keep: Option<usize>,
    pub(crate) log_rotate_disabled: bool,
    pub(crate) install_inventory_interval_seconds: Option<u64>,
    pub(crate) install_inventory_disabled: bool,
    pub(crate) health_heartbeat_interval_seconds: Option<u64>,
    pub(crate) emit_activity: bool,
    pub(crate) emit_session_risk_summary: bool,
    pub(crate) baseline_deviation_scoring: bool,
    pub(crate) watch_debounce_ms: Option<u64>,
    pub(crate) watch_min_scan_interval_ms: Option<u64>,
}

#[derive(Debug)]
pub(crate) struct Settings {
    files: Vec<PathBuf>,
    pub(crate) community_rules: Setting<bool>,
    pub(crate) process_chain: Setting<bool>,
    risk_low: Setting<u32>,
    risk_medium: Setting<u32>,
    risk_high: Setting<u32>,
    risk_critical: Setting<u32>,
    max_scanner_errors: Setting<u32>,
    max_scan_duration_ms: Setting<u64>,
    log_rotate_max_size: Setting<u64>,
    log_rotate_keep: Setting<usize>,
    install_inventory: Setting<bool>,
    install_inventory_interval_seconds: Setting<u64>,
    health_heartbeat_interval_seconds: Setting<u64>,
    pub(crate) emit_activity: Setting<bool>,
    pub(crate) emit_session_risk_summary: Setting<bool>,
    pub(crate) baseline_deviation_scoring: Setting<bool>,
    pub(crate) watch_debounce_ms: Setting<u64>,
    pub(crate) watch_min_scan_interval_ms: Setting<u64>,
    #[cfg(feature = "hooks")]
    pub(crate) hooks: HooksSettings,
}

impl Default for Settings {
    fn default() -> Self {
        let thresholds = RiskThresholds::default();
        let alerts = OperationalAlertConfig::default();
        let rotation = RotationConfig::default();
        Self {
            files: Vec::new(),
            community_rules: Setting::new(true),
            process_chain: Setting::new(true),
            risk_low: Setting::new(thresholds.low),
            risk_medium: Setting::new(thresholds.medium),
            risk_high: Setting::new(thresholds.high),
            risk_critical: Setting::new(thresholds.critical),
            max_scanner_errors: Setting::new(alerts.max_scanner_errors),
            max_scan_duration_ms: Setting::new(alerts.max_scan_duration_ms),
            log_rotate_max_size: Setting::new(rotation.max_size_bytes),
            log_rotate_keep: Setting::new(rotation.keep),
            install_inventory: Setting::new(true),
            install_inventory_interval_seconds: Setting::new(
                telltale_core::DEFAULT_INSTALL_INVENTORY_INTERVAL_SECONDS,
            ),
            health_heartbeat_interval_seconds: Setting::new(0),
            emit_activity: Setting::new(false),
            emit_session_risk_summary: Setting::new(false),
            baseline_deviation_scoring: Setting::new(false),
            watch_debounce_ms: Setting::new(500),
            watch_min_scan_interval_ms: Setting::new(10_000),
            #[cfg(feature = "hooks")]
            hooks: HooksSettings::default(),
        }
    }
}

/// `settings.d` document, version 1. Every key is optional.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SettingsDocument {
    version: u32,
    #[serde(default)]
    rules: RulesSection,
    #[serde(default)]
    detections: DetectionsSection,
    #[serde(default)]
    risk_thresholds: RiskThresholdsSection,
    #[serde(default)]
    operational_alerts: OperationalAlertsSection,
    #[serde(default)]
    log_rotation: LogRotationSection,
    #[serde(default)]
    install_inventory: InstallInventorySection,
    #[serde(default)]
    events: EventsSection,
    #[serde(default)]
    watch: WatchSection,
    #[cfg(feature = "hooks")]
    #[serde(default)]
    hooks: HooksSection,
    /// A build without hooks accepts and ignores the section, so one
    /// `settings.d` serves both builds.
    #[cfg(not(feature = "hooks"))]
    #[serde(default)]
    #[allow(dead_code)]
    hooks: Option<serde::de::IgnoredAny>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RulesSection {
    community: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct DetectionsSection {
    process_chain: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RiskThresholdsSection {
    low: Option<u32>,
    medium: Option<u32>,
    high: Option<u32>,
    critical: Option<u32>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct OperationalAlertsSection {
    max_scanner_errors: Option<u32>,
    max_scan_duration_ms: Option<u64>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct LogRotationSection {
    max_size_bytes: Option<u64>,
    keep: Option<usize>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct InstallInventorySection {
    enabled: Option<bool>,
    interval_seconds: Option<u64>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct EventsSection {
    emit_activity: Option<bool>,
    emit_session_risk_summary: Option<bool>,
    baseline_deviation_scoring: Option<bool>,
    health_heartbeat_interval_seconds: Option<u64>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct WatchSection {
    debounce_ms: Option<u64>,
    min_scan_interval_ms: Option<u64>,
}

/// Discover, resolve, and apply settings for this process. Event 3 risk
/// thresholds are process-wide, so this configures them before any event is
/// built.
pub(crate) fn load(
    config_dirs: &[PathBuf],
    no_local_config: bool,
    cli: &CliSettings,
) -> Result<Settings, Box<dyn std::error::Error>> {
    let files = crate::config::discover_settings_files(config_dirs, no_local_config)?;
    let settings = resolve(
        &files,
        &|name| std::env::var_os(name).map(|value| value.to_string_lossy().into_owned()),
        cli,
    )?;
    telltale_schema::scoring::configure_thresholds(settings.risk_thresholds())?;
    Ok(settings)
}

/// Open a settings file without waiting on it: discovery checked the type,
/// but the entry can change before the open, and a FIFO would block the
/// command (for a hook, before it can answer). The handle must be a regular
/// file.
fn open_settings_file(path: &Path) -> std::io::Result<fs::File> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "not a regular file",
        ));
    }
    Ok(file)
}

fn resolve(
    files: &[PathBuf],
    env: &dyn Fn(&str) -> Option<String>,
    cli: &CliSettings,
) -> Result<Settings, Box<dyn std::error::Error>> {
    let mut settings = Settings {
        files: files.to_vec(),
        ..Settings::default()
    };
    for path in files {
        let mut bytes = Vec::new();
        open_settings_file(path)
            .and_then(|file| {
                file.take(MAX_SETTINGS_FILE_BYTES + 1)
                    .read_to_end(&mut bytes)
            })
            .map_err(|err| format!("could not read settings file {}: {err}", path.display()))?;
        if bytes.len() as u64 > MAX_SETTINGS_FILE_BYTES {
            return Err(format!(
                "settings file {} exceeds {MAX_SETTINGS_FILE_BYTES} bytes",
                path.display()
            )
            .into());
        }
        let document: SettingsDocument = serde_yaml::from_slice(&bytes)
            .map_err(|err| format!("invalid settings file {}: {err}", path.display()))?;
        if document.version != SUPPORTED_SETTINGS_VERSION {
            return Err(format!(
                "settings file {}: version {} is not supported by this Telltale build (expected {SUPPORTED_SETTINGS_VERSION})",
                path.display(),
                document.version
            )
            .into());
        }
        settings.apply_document(document, path);
    }
    settings.apply_environment(env)?;
    settings.apply_cli(cli);
    settings.check_risk_threshold_order()?;
    Ok(settings)
}

impl Settings {
    fn apply_document(&mut self, document: SettingsDocument, path: &Path) {
        let origin = || Origin::File(path.to_path_buf());
        self.community_rules.set(document.rules.community, origin());
        self.process_chain
            .set(document.detections.process_chain, origin());
        self.risk_low.set(document.risk_thresholds.low, origin());
        self.risk_medium
            .set(document.risk_thresholds.medium, origin());
        self.risk_high.set(document.risk_thresholds.high, origin());
        self.risk_critical
            .set(document.risk_thresholds.critical, origin());
        self.max_scanner_errors
            .set(document.operational_alerts.max_scanner_errors, origin());
        self.max_scan_duration_ms
            .set(document.operational_alerts.max_scan_duration_ms, origin());
        self.log_rotate_max_size
            .set(document.log_rotation.max_size_bytes, origin());
        self.log_rotate_keep
            .set(document.log_rotation.keep, origin());
        self.install_inventory
            .set(document.install_inventory.enabled, origin());
        self.install_inventory_interval_seconds
            .set(document.install_inventory.interval_seconds, origin());
        self.emit_activity
            .set(document.events.emit_activity, origin());
        self.emit_session_risk_summary
            .set(document.events.emit_session_risk_summary, origin());
        self.baseline_deviation_scoring
            .set(document.events.baseline_deviation_scoring, origin());
        self.health_heartbeat_interval_seconds
            .set(document.events.health_heartbeat_interval_seconds, origin());
        self.watch_debounce_ms
            .set(document.watch.debounce_ms, origin());
        self.watch_min_scan_interval_ms
            .set(document.watch.min_scan_interval_ms, origin());
        #[cfg(feature = "hooks")]
        self.hooks.apply_document(document.hooks, path);
    }

    fn apply_environment(
        &mut self,
        env: &dyn Fn(&str) -> Option<String>,
    ) -> Result<(), InvalidEnvironment> {
        self.community_rules
            .set_env(env, "TELLTALE_COMMUNITY_RULES")?;
        self.process_chain
            .set_env(env, "TELLTALE_PROCESS_CHAIN_DETECTIONS")?;
        self.risk_low.set_env(env, "TELLTALE_RISK_THRESHOLD_LOW")?;
        self.risk_medium
            .set_env(env, "TELLTALE_RISK_THRESHOLD_MEDIUM")?;
        self.risk_high
            .set_env(env, "TELLTALE_RISK_THRESHOLD_HIGH")?;
        self.risk_critical
            .set_env(env, "TELLTALE_RISK_THRESHOLD_CRITICAL")?;
        self.max_scanner_errors
            .set_env(env, "TELLTALE_OP_ALERT_MAX_SCANNER_ERRORS")?;
        self.max_scan_duration_ms
            .set_env(env, "TELLTALE_OP_ALERT_MAX_SCAN_DURATION_MS")?;
        self.log_rotate_max_size
            .set_env(env, "TELLTALE_LOG_ROTATE_MAX_SIZE")?;
        self.log_rotate_keep
            .set_env(env, "TELLTALE_LOG_ROTATE_KEEP")?;
        self.install_inventory_interval_seconds
            .set_env(env, "TELLTALE_INSTALL_INVENTORY_INTERVAL_SECONDS")?;
        self.health_heartbeat_interval_seconds
            .set_env(env, "TELLTALE_HEALTH_HEARTBEAT_INTERVAL_SECONDS")?;
        #[cfg(feature = "hooks")]
        self.hooks.apply_environment(env)?;
        Ok(())
    }

    fn apply_cli(&mut self, cli: &CliSettings) {
        self.community_rules.set(
            cli.no_community_rules.then_some(false),
            Origin::Cli("--no-community-rules"),
        );
        self.log_rotate_max_size.set(
            cli.log_rotate_max_size,
            Origin::Cli("--log-rotate-max-size"),
        );
        self.log_rotate_keep
            .set(cli.log_rotate_keep, Origin::Cli("--log-rotate-keep"));
        self.log_rotate_max_size.set(
            cli.log_rotate_disabled.then_some(0),
            Origin::Cli("--log-rotate-disabled"),
        );
        self.install_inventory_interval_seconds.set(
            cli.install_inventory_interval_seconds,
            Origin::Cli("--install-inventory-interval-seconds"),
        );
        self.install_inventory.set(
            cli.install_inventory_disabled.then_some(false),
            Origin::Cli("--install-inventory-disabled"),
        );
        self.health_heartbeat_interval_seconds.set(
            cli.health_heartbeat_interval_seconds,
            Origin::Cli("--health-heartbeat-interval-seconds"),
        );
        // These flags can only turn their settings on.
        self.emit_activity.set(
            cli.emit_activity.then_some(true),
            Origin::Cli("--emit-activity"),
        );
        self.emit_session_risk_summary.set(
            cli.emit_session_risk_summary.then_some(true),
            Origin::Cli("--emit-session-risk-summary"),
        );
        self.baseline_deviation_scoring.set(
            cli.baseline_deviation_scoring.then_some(true),
            Origin::Cli("--baseline-deviation-scoring"),
        );
        self.watch_debounce_ms
            .set(cli.watch_debounce_ms, Origin::Cli("--debounce-ms"));
        self.watch_min_scan_interval_ms.set(
            cli.watch_min_scan_interval_ms,
            Origin::Cli("--min-scan-interval-ms"),
        );
    }

    /// Severity bands are checked from critical down, so a lower threshold
    /// above a higher one silently relabels scores. The check runs on the
    /// merged values: each source can be valid alone and still invert them.
    /// Equal thresholds are allowed; they only empty a band.
    ///
    /// The error names the first inverted pair and where each value came
    /// from. It stays short because the binary bounds diagnostics, and it
    /// names a file by its escaped basename because full paths are redacted
    /// there.
    fn check_risk_threshold_order(&self) -> Result<(), String> {
        let thresholds = [
            ("low", &self.risk_low),
            ("medium", &self.risk_medium),
            ("high", &self.risk_high),
            ("critical", &self.risk_critical),
        ];
        let Some(pair) = thresholds
            .windows(2)
            .find(|pair| pair[0].1.value > pair[1].1.value)
        else {
            return Ok(());
        };
        let describe = |(name, setting): (&str, &Setting<u32>)| {
            let origin = match &setting.origin {
                Origin::Default => "default".to_string(),
                // A writable config root can choose any name; escape it so
                // it cannot carry terminal control or bidirectional text.
                Origin::File(path) => format!(
                    "settings file {}",
                    path.file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .escape_default()
                ),
                Origin::Environment(name) | Origin::Cli(name) => name.to_string(),
            };
            format!("{name}={} ({origin})", setting.value)
        };
        Err(format!(
            "invalid risk thresholds: {} is above {}; expected low <= medium <= high <= critical",
            describe(pair[0]),
            describe(pair[1]),
        ))
    }

    pub(crate) fn files(&self) -> &[PathBuf] {
        &self.files
    }

    pub(crate) fn risk_thresholds(&self) -> RiskThresholds {
        RiskThresholds {
            low: self.risk_low.value,
            medium: self.risk_medium.value,
            high: self.risk_high.value,
            critical: self.risk_critical.value,
        }
    }

    pub(crate) fn operational_alerts(&self) -> OperationalAlertConfig {
        OperationalAlertConfig {
            max_scanner_errors: self.max_scanner_errors.value,
            max_scan_duration_ms: self.max_scan_duration_ms.value,
        }
    }

    pub(crate) fn rotation(&self) -> RotationConfig {
        RotationConfig {
            max_size_bytes: self.log_rotate_max_size.value,
            keep: self.log_rotate_keep.value,
        }
    }

    pub(crate) fn install_inventory_interval_seconds(&self) -> Option<u64> {
        self.install_inventory
            .value
            .then_some(self.install_inventory_interval_seconds.value)
    }

    /// Seconds between liveness `health` events, or `None` when off (0).
    pub(crate) fn health_heartbeat_interval_seconds(&self) -> Option<u64> {
        let seconds = self.health_heartbeat_interval_seconds.value;
        (seconds > 0).then_some(seconds)
    }

    /// Each effective value with its default and origin, keyed by its
    /// `settings.d` path. A winning file appears only as its path hash.
    pub(crate) fn to_json(&self) -> serde_json::Value {
        #[cfg_attr(not(feature = "hooks"), allow(unused_mut))]
        let mut json = serde_json::json!({
            "rules.community": entry(&self.community_rules),
            "detections.process_chain": entry(&self.process_chain),
            "risk_thresholds.low": entry(&self.risk_low),
            "risk_thresholds.medium": entry(&self.risk_medium),
            "risk_thresholds.high": entry(&self.risk_high),
            "risk_thresholds.critical": entry(&self.risk_critical),
            "operational_alerts.max_scanner_errors": entry(&self.max_scanner_errors),
            "operational_alerts.max_scan_duration_ms": entry(&self.max_scan_duration_ms),
            "log_rotation.max_size_bytes": entry(&self.log_rotate_max_size),
            "log_rotation.keep": entry(&self.log_rotate_keep),
            "install_inventory.enabled": entry(&self.install_inventory),
            "install_inventory.interval_seconds": entry(&self.install_inventory_interval_seconds),
            "events.emit_activity": entry(&self.emit_activity),
            "events.emit_session_risk_summary": entry(&self.emit_session_risk_summary),
            "events.baseline_deviation_scoring": entry(&self.baseline_deviation_scoring),
            "events.health_heartbeat_interval_seconds": entry(&self.health_heartbeat_interval_seconds),
            "watch.debounce_ms": entry(&self.watch_debounce_ms),
            "watch.min_scan_interval_ms": entry(&self.watch_min_scan_interval_ms),
        });
        #[cfg(feature = "hooks")]
        if let serde_json::Value::Object(map) = &mut json {
            self.hooks.extend_json(map);
        }
        json
    }
}

fn described<T>(
    setting: &Setting<T>,
    value: serde_json::Value,
    default: serde_json::Value,
) -> serde_json::Value {
    let (origin, source) = match &setting.origin {
        Origin::Default => ("default", None),
        Origin::File(path) => ("settings_file", Some(path_hash(path))),
        Origin::Environment(name) => ("environment", Some(name.to_string())),
        Origin::Cli(flag) => ("cli", Some(flag.to_string())),
    };
    serde_json::json!({
        "value": value,
        "default": default,
        "origin": origin,
        "source": source,
    })
}

fn entry<T: Clone + serde::Serialize>(setting: &Setting<T>) -> serde_json::Value {
    described(
        setting,
        serde_json::json!(setting.value),
        serde_json::json!(setting.default),
    )
}

/// A path appears only as its hash, like a settings file.
#[cfg(feature = "hooks")]
fn path_entry(setting: &Setting<Option<PathBuf>>) -> serde_json::Value {
    let hashed = |path: &Option<PathBuf>| serde_json::json!(path.as_deref().map(path_hash));
    described(setting, hashed(&setting.value), hashed(&setting.default))
}

#[cfg(feature = "hooks")]
use hooks_section::HooksSection;
#[cfg(feature = "hooks")]
pub(crate) use hooks_section::{HooksSettings, STATE_DIR_ENV, TELEMETRY_ENV};

/// The `hooks:` section: `telltale hooks` settings (docs/hooks/README.md).
#[cfg(feature = "hooks")]
mod hooks_section {
    use std::path::{Path, PathBuf};

    use serde::Deserialize;
    use telltale_core::hooks::config::{
        Config, EvaluatorSettings, Mode, OnError, ReasonDetail, Thresholds, Window,
    };

    use super::{InvalidEnvironment, Origin, Setting, entry, path_entry};

    /// Paths in the environment, as hooks read them when settings do not load.
    pub(crate) const STATE_DIR_ENV: &str = "TELLTALE_HOOKS_STATE_DIR";
    pub(crate) const TELEMETRY_ENV: &str = "TELLTALE_HOOKS_TELEMETRY";
    const EVALUATOR_ENV: &str = "TELLTALE_HOOKS_EVALUATOR";

    #[derive(Debug, Default, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub(super) struct HooksSection {
        mode: Option<Mode>,
        on_error: Option<OnError>,
        on_unevaluable: Option<OnError>,
        reason_detail: Option<ReasonDetail>,
        state_dir: Option<PathBuf>,
        telemetry_path: Option<PathBuf>,
        self_protection_rules: Option<bool>,
        #[serde(default)]
        thresholds: ThresholdsSection,
        #[serde(default)]
        window: WindowSection,
        #[serde(default)]
        evaluator: EvaluatorSection,
    }

    #[derive(Debug, Default, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ThresholdsSection {
        action_ask: Option<u64>,
        action_deny: Option<u64>,
        session_ask: Option<u64>,
        session_deny: Option<u64>,
        repeated_denials: Option<u32>,
    }

    #[derive(Debug, Default, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct WindowSection {
        max_records: Option<usize>,
        max_bytes: Option<u64>,
        max_result_bytes: Option<usize>,
    }

    #[derive(Debug, Default, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct EvaluatorSection {
        enabled: Option<bool>,
        autostart: Option<bool>,
        idle_timeout_secs: Option<u64>,
        request_timeout_ms: Option<u64>,
        socket: Option<PathBuf>,
    }

    #[derive(Debug)]
    pub(crate) struct HooksSettings {
        mode: Setting<Mode>,
        on_error: Setting<OnError>,
        on_unevaluable: Setting<OnError>,
        reason_detail: Setting<ReasonDetail>,
        state_dir: Setting<Option<PathBuf>>,
        telemetry_path: Setting<Option<PathBuf>>,
        pub(crate) self_protection_rules: Setting<bool>,
        action_ask: Setting<u64>,
        action_deny: Setting<u64>,
        session_ask: Setting<u64>,
        session_deny: Setting<u64>,
        repeated_denials: Setting<u32>,
        max_records: Setting<usize>,
        max_bytes: Setting<u64>,
        max_result_bytes: Setting<usize>,
        evaluator_enabled: Setting<bool>,
        evaluator_autostart: Setting<bool>,
        evaluator_idle_timeout_secs: Setting<u64>,
        evaluator_request_timeout_ms: Setting<u64>,
        evaluator_socket: Setting<Option<PathBuf>>,
    }

    impl Default for HooksSettings {
        fn default() -> Self {
            let config = Config::default();
            let Thresholds {
                action_ask,
                action_deny,
                session_ask,
                session_deny,
                repeated_denials,
            } = config.thresholds;
            let Window {
                max_records,
                max_bytes,
                max_result_bytes,
            } = config.window;
            let EvaluatorSettings {
                enabled,
                autostart,
                idle_timeout_secs,
                request_timeout_ms,
                socket,
            } = config.evaluator;
            Self {
                mode: Setting::new(config.mode),
                on_error: Setting::new(config.on_error),
                on_unevaluable: Setting::new(config.on_unevaluable),
                reason_detail: Setting::new(config.reason_detail),
                state_dir: Setting::new(config.state_dir),
                telemetry_path: Setting::new(config.telemetry_path),
                self_protection_rules: Setting::new(config.rules.self_protection),
                action_ask: Setting::new(action_ask),
                action_deny: Setting::new(action_deny),
                session_ask: Setting::new(session_ask),
                session_deny: Setting::new(session_deny),
                repeated_denials: Setting::new(repeated_denials),
                max_records: Setting::new(max_records),
                max_bytes: Setting::new(max_bytes),
                max_result_bytes: Setting::new(max_result_bytes),
                evaluator_enabled: Setting::new(enabled),
                evaluator_autostart: Setting::new(autostart),
                evaluator_idle_timeout_secs: Setting::new(idle_timeout_secs),
                evaluator_request_timeout_ms: Setting::new(request_timeout_ms),
                evaluator_socket: Setting::new(socket),
            }
        }
    }

    impl HooksSettings {
        pub(super) fn apply_document(&mut self, section: HooksSection, path: &Path) {
            let origin = || Origin::File(path.to_path_buf());
            self.mode.set(section.mode, origin());
            self.on_error.set(section.on_error, origin());
            self.on_unevaluable.set(section.on_unevaluable, origin());
            self.reason_detail.set(section.reason_detail, origin());
            self.state_dir.set(section.state_dir.map(Some), origin());
            self.telemetry_path
                .set(section.telemetry_path.map(Some), origin());
            self.self_protection_rules
                .set(section.self_protection_rules, origin());
            let thresholds = section.thresholds;
            self.action_ask.set(thresholds.action_ask, origin());
            self.action_deny.set(thresholds.action_deny, origin());
            self.session_ask.set(thresholds.session_ask, origin());
            self.session_deny.set(thresholds.session_deny, origin());
            self.repeated_denials
                .set(thresholds.repeated_denials, origin());
            let window = section.window;
            self.max_records.set(window.max_records, origin());
            self.max_bytes.set(window.max_bytes, origin());
            self.max_result_bytes.set(window.max_result_bytes, origin());
            let evaluator = section.evaluator;
            self.evaluator_enabled.set(evaluator.enabled, origin());
            self.evaluator_autostart.set(evaluator.autostart, origin());
            self.evaluator_idle_timeout_secs
                .set(evaluator.idle_timeout_secs, origin());
            self.evaluator_request_timeout_ms
                .set(evaluator.request_timeout_ms, origin());
            self.evaluator_socket
                .set(evaluator.socket.map(Some), origin());
        }

        pub(super) fn apply_environment(
            &mut self,
            env: &dyn Fn(&str) -> Option<String>,
        ) -> Result<(), InvalidEnvironment> {
            self.state_dir.set_env(env, STATE_DIR_ENV)?;
            self.telemetry_path.set_env(env, TELEMETRY_ENV)?;
            self.evaluator_enabled.set_env(env, EVALUATOR_ENV)
        }

        pub(super) fn extend_json(&self, map: &mut serde_json::Map<String, serde_json::Value>) {
            for (key, value) in [
                ("hooks.mode", entry(&self.mode)),
                ("hooks.on_error", entry(&self.on_error)),
                ("hooks.on_unevaluable", entry(&self.on_unevaluable)),
                ("hooks.reason_detail", entry(&self.reason_detail)),
                ("hooks.state_dir", path_entry(&self.state_dir)),
                ("hooks.telemetry_path", path_entry(&self.telemetry_path)),
                (
                    "hooks.self_protection_rules",
                    entry(&self.self_protection_rules),
                ),
                ("hooks.thresholds.action_ask", entry(&self.action_ask)),
                ("hooks.thresholds.action_deny", entry(&self.action_deny)),
                ("hooks.thresholds.session_ask", entry(&self.session_ask)),
                ("hooks.thresholds.session_deny", entry(&self.session_deny)),
                (
                    "hooks.thresholds.repeated_denials",
                    entry(&self.repeated_denials),
                ),
                ("hooks.window.max_records", entry(&self.max_records)),
                ("hooks.window.max_bytes", entry(&self.max_bytes)),
                (
                    "hooks.window.max_result_bytes",
                    entry(&self.max_result_bytes),
                ),
                ("hooks.evaluator.enabled", entry(&self.evaluator_enabled)),
                (
                    "hooks.evaluator.autostart",
                    entry(&self.evaluator_autostart),
                ),
                (
                    "hooks.evaluator.idle_timeout_secs",
                    entry(&self.evaluator_idle_timeout_secs),
                ),
                (
                    "hooks.evaluator.request_timeout_ms",
                    entry(&self.evaluator_request_timeout_ms),
                ),
                ("hooks.evaluator.socket", path_entry(&self.evaluator_socket)),
            ] {
                map.insert(key.to_owned(), value);
            }
        }

        /// The hooks configuration these settings describe. Rule content and
        /// the configuration's sources are the caller's: they come from the
        /// config folders, not from this section.
        pub(crate) fn config(&self) -> Config {
            Config {
                mode: self.mode.value,
                on_error: self.on_error.value,
                on_unevaluable: self.on_unevaluable.value,
                reason_detail: self.reason_detail.value,
                state_dir: self.state_dir.value.clone(),
                telemetry_path: self.telemetry_path.value.clone(),
                thresholds: Thresholds {
                    action_ask: self.action_ask.value,
                    action_deny: self.action_deny.value,
                    session_ask: self.session_ask.value,
                    session_deny: self.session_deny.value,
                    repeated_denials: self.repeated_denials.value,
                },
                window: Window {
                    max_records: self.max_records.value,
                    max_bytes: self.max_bytes.value,
                    max_result_bytes: self.max_result_bytes.value,
                },
                evaluator: EvaluatorSettings {
                    enabled: self.evaluator_enabled.value,
                    autostart: self.evaluator_autostart.value,
                    idle_timeout_secs: self.evaluator_idle_timeout_secs.value,
                    request_timeout_ms: self.evaluator_request_timeout_ms.value,
                    socket: self.evaluator_socket.value.clone(),
                },
                ..Config::default()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;
    use std::path::{Path, PathBuf};

    use telltale_schema::event::path_hash;
    use tempfile::tempdir;

    use super::{CliSettings, MAX_SETTINGS_FILE_BYTES, Origin, Settings, resolve};

    fn write(dir: &Path, name: &str, text: &str) -> PathBuf {
        let path = dir.join(name);
        fs::write(&path, text).expect("write settings");
        path
    }

    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map = pairs
            .iter()
            .map(|(name, value)| (name.to_string(), value.to_string()))
            .collect::<BTreeMap<_, _>>();
        move |name| map.get(name).cloned()
    }

    fn origin(settings: &Settings, key: &str) -> (String, serde_json::Value) {
        let json = settings.to_json();
        (
            json[key]["origin"].as_str().expect("origin").to_string(),
            json[key]["source"].clone(),
        )
    }

    #[test]
    fn defaults_match_the_owning_components() {
        let settings = resolve(&[], &env(&[]), &CliSettings::default()).expect("defaults");
        assert_eq!(
            settings.risk_thresholds(),
            telltale_schema::scoring::RiskThresholds::default()
        );
        assert_eq!(
            settings.operational_alerts(),
            telltale_schema::event::OperationalAlertConfig::default()
        );
        assert_eq!(settings.rotation(), crate::sink::RotationConfig::default());
        assert_eq!(
            settings.install_inventory_interval_seconds(),
            Some(telltale_core::DEFAULT_INSTALL_INVENTORY_INTERVAL_SECONDS)
        );
        assert_eq!(settings.health_heartbeat_interval_seconds(), None);
        assert!(settings.community_rules.value && settings.process_chain.value);
        let json = settings.to_json();
        for (key, entry) in json.as_object().expect("object") {
            assert_eq!(entry["origin"], "default", "{key}");
            assert_eq!(entry["value"], entry["default"], "{key}");
        }
    }

    #[test]
    fn files_then_environment_then_cli_win_per_key() {
        let temp = tempdir().expect("tempdir");
        let first = write(
            temp.path(),
            "10-vendor.yaml",
            "version: 1\nrisk_thresholds: {low: 10, high: 60}\nlog_rotation: {keep: 2}\ndetections: {process_chain: false}\n",
        );
        let second = write(
            temp.path(),
            "90-local.yaml",
            "version: 1\nrisk_thresholds: {high: 65}\nlog_rotation: {keep: 3, max_size_bytes: 1024}\nevents: {emit_activity: true}\nwatch: {debounce_ms: 50, min_scan_interval_ms: 100}\n",
        );
        let settings = resolve(
            &[first.clone(), second.clone()],
            &env(&[
                ("TELLTALE_LOG_ROTATE_KEEP", "4"),
                ("TELLTALE_RISK_THRESHOLD_CRITICAL", "95"),
                ("TELLTALE_COMMUNITY_RULES", ""),
            ]),
            &CliSettings {
                log_rotate_max_size: Some(2048),
                emit_session_risk_summary: true,
                watch_min_scan_interval_ms: Some(200),
                ..CliSettings::default()
            },
        )
        .expect("resolve");

        assert_eq!(settings.risk_thresholds().low, 10);
        assert_eq!(settings.risk_thresholds().high, 65);
        assert_eq!(settings.risk_thresholds().critical, 95);
        assert_eq!(settings.rotation().keep, 4);
        assert_eq!(settings.rotation().max_size_bytes, 2048);
        assert!(!settings.process_chain.value);
        assert!(settings.emit_activity.value && settings.emit_session_risk_summary.value);
        assert!(!settings.baseline_deviation_scoring.value);
        assert_eq!(settings.watch_debounce_ms.value, 50);
        assert_eq!(settings.watch_min_scan_interval_ms.value, 200);
        assert_eq!(
            origin(&settings, "watch.min_scan_interval_ms"),
            ("cli".into(), "--min-scan-interval-ms".into())
        );
        assert_eq!(
            origin(&settings, "risk_thresholds.low"),
            ("settings_file".into(), path_hash(&first).into())
        );
        assert_eq!(
            origin(&settings, "risk_thresholds.high"),
            ("settings_file".into(), path_hash(&second).into())
        );
        assert_eq!(
            origin(&settings, "log_rotation.keep"),
            ("environment".into(), "TELLTALE_LOG_ROTATE_KEEP".into())
        );
        assert_eq!(
            origin(&settings, "log_rotation.max_size_bytes"),
            ("cli".into(), "--log-rotate-max-size".into())
        );
        // An empty variable is unset rather than invalid.
        assert_eq!(
            origin(&settings, "rules.community"),
            ("default".into(), serde_json::Value::Null)
        );
    }

    #[test]
    fn disabling_flags_win_over_configured_values() {
        let temp = tempdir().expect("tempdir");
        let file = write(
            temp.path(),
            "settings.yaml",
            "version: 1\nrules: {community: true}\nlog_rotation: {max_size_bytes: 1024}\ninstall_inventory: {interval_seconds: 60}\n",
        );
        let settings = resolve(
            &[file],
            &env(&[("TELLTALE_LOG_ROTATE_MAX_SIZE", "4096")]),
            &CliSettings {
                no_community_rules: true,
                log_rotate_max_size: Some(8192),
                log_rotate_disabled: true,
                install_inventory_disabled: true,
                ..CliSettings::default()
            },
        )
        .expect("resolve");
        assert!(!settings.community_rules.value);
        assert!(!settings.rotation().is_enabled());
        assert_eq!(settings.install_inventory_interval_seconds(), None);
        assert_eq!(
            origin(&settings, "log_rotation.max_size_bytes"),
            ("cli".into(), "--log-rotate-disabled".into())
        );
    }

    #[test]
    fn health_heartbeat_interval_follows_file_environment_flag_precedence() {
        let temp = tempdir().expect("tempdir");
        let file = write(
            temp.path(),
            "settings.yaml",
            "version: 1\nevents: {health_heartbeat_interval_seconds: 900}\n",
        );
        let resolved = |env_value: Option<&str>, flag: Option<u64>| {
            let pairs = env_value
                .map(|value| vec![("TELLTALE_HEALTH_HEARTBEAT_INTERVAL_SECONDS", value)])
                .unwrap_or_default();
            resolve(
                std::slice::from_ref(&file),
                &env(&pairs),
                &CliSettings {
                    health_heartbeat_interval_seconds: flag,
                    ..CliSettings::default()
                },
            )
            .expect("resolve")
        };
        let key = "events.health_heartbeat_interval_seconds";

        let settings = resolved(None, None);
        assert_eq!(settings.health_heartbeat_interval_seconds(), Some(900));
        assert_eq!(
            origin(&settings, key),
            ("settings_file".into(), path_hash(&file).into())
        );

        let settings = resolved(Some("300"), None);
        assert_eq!(settings.health_heartbeat_interval_seconds(), Some(300));
        assert_eq!(
            origin(&settings, key),
            (
                "environment".into(),
                "TELLTALE_HEALTH_HEARTBEAT_INTERVAL_SECONDS".into()
            )
        );

        // An explicit 0 turns the heartbeat off over a configured interval.
        let settings = resolved(Some("300"), Some(0));
        assert_eq!(settings.health_heartbeat_interval_seconds(), None);
        assert_eq!(settings.to_json()[key]["value"], 0);
        assert_eq!(
            origin(&settings, key),
            ("cli".into(), "--health-heartbeat-interval-seconds".into())
        );
    }

    #[test]
    fn boolean_environment_values_are_case_insensitive() {
        for (raw, expected) in [
            ("0", false),
            ("FALSE", false),
            (" Off ", false),
            ("No", false),
            ("1", true),
            ("Yes", true),
            ("ON", true),
        ] {
            let settings = resolve(
                &[],
                &env(&[("TELLTALE_PROCESS_CHAIN_DETECTIONS", raw)]),
                &CliSettings::default(),
            )
            .expect("resolve");
            assert_eq!(settings.process_chain.value, expected, "{raw:?}");
        }
    }

    #[test]
    fn invalid_environment_values_fail_and_name_only_the_variable() {
        for (name, raw) in [
            ("TELLTALE_COMMUNITY_RULES", "maybe-SECRET"),
            ("TELLTALE_RISK_THRESHOLD_HIGH", "high-SECRET"),
            ("TELLTALE_LOG_ROTATE_KEEP", "-1"),
            // Earlier releases ignored padded integers, so they fail rather
            // than start to apply.
            ("TELLTALE_LOG_ROTATE_KEEP", " 0 "),
            ("TELLTALE_RISK_THRESHOLD_CRITICAL", "95\r"),
            ("TELLTALE_INSTALL_INVENTORY_INTERVAL_SECONDS", "1.5"),
            ("TELLTALE_HEALTH_HEARTBEAT_INTERVAL_SECONDS", "1h-SECRET"),
        ] {
            let error = resolve(&[], &env(&[(name, raw)]), &CliSettings::default())
                .expect_err("invalid environment value")
                .to_string();
            assert!(
                error.starts_with(&format!("invalid {name}: expected")),
                "{error}"
            );
            assert!(!error.contains("SECRET"), "{error}");
        }
    }

    #[test]
    fn integer_environment_values_accept_a_leading_plus_like_yaml() {
        let settings = resolve(
            &[],
            &env(&[("TELLTALE_LOG_ROTATE_KEEP", "+5")]),
            &CliSettings::default(),
        )
        .expect("resolve");
        assert_eq!(settings.rotation().keep, 5);
    }

    #[test]
    fn risk_thresholds_are_checked_after_files_and_environment_merge() {
        let temp = tempdir().expect("tempdir");
        let unordered = write(
            temp.path(),
            "50-unordered.yaml",
            "version: 1\nrisk_thresholds: {low: 90, medium: 50, high: 10, critical: 5}\n",
        );
        let error = resolve(
            std::slice::from_ref(&unordered),
            &env(&[]),
            &CliSettings::default(),
        )
        .expect_err("unordered thresholds")
        .to_string();
        assert_eq!(
            error,
            "invalid risk thresholds: low=90 (settings file 50-unordered.yaml) is above \
             medium=50 (settings file 50-unordered.yaml); expected low <= medium <= high <= critical"
        );
        assert!(!error.contains(&*temp.path().to_string_lossy()), "{error}");

        // Each file is valid alone; the environment inverts the merged result.
        let ordered = write(
            temp.path(),
            "10-ordered.yaml",
            "version: 1\nrisk_thresholds: {low: 10, medium: 20, high: 30, critical: 40}\n",
        );
        let error = resolve(
            std::slice::from_ref(&ordered),
            &env(&[("TELLTALE_RISK_THRESHOLD_CRITICAL", "25")]),
            &CliSettings::default(),
        )
        .expect_err("environment inverts a valid file")
        .to_string();
        assert!(
            error.contains(
                "high=30 (settings file 10-ordered.yaml) is above \
                 critical=25 (TELLTALE_RISK_THRESHOLD_CRITICAL)"
            ),
            "{error}"
        );

        // A lone high override below the default medium is inverted too.
        let error = resolve(
            &[],
            &env(&[("TELLTALE_RISK_THRESHOLD_HIGH", "1")]),
            &CliSettings::default(),
        )
        .expect_err("high below default medium")
        .to_string();
        assert!(
            error.contains("medium=50 (default) is above high=1 (TELLTALE_RISK_THRESHOLD_HIGH)"),
            "{error}"
        );

        // An invalid file can be repaired by a later source.
        let partial = write(
            temp.path(),
            "60-partial.yaml",
            "version: 1\nrisk_thresholds: {high: 10, critical: 10}\n",
        );
        let settings = resolve(
            &[partial],
            &env(&[
                ("TELLTALE_RISK_THRESHOLD_LOW", "1"),
                ("TELLTALE_RISK_THRESHOLD_MEDIUM", "5"),
            ]),
            &CliSettings::default(),
        )
        .expect("merged thresholds are ordered");
        assert_eq!(
            settings.risk_thresholds(),
            telltale_schema::scoring::RiskThresholds {
                low: 1,
                medium: 5,
                high: 10,
                critical: 10,
            }
        );
    }

    #[test]
    fn risk_threshold_errors_escape_settings_file_names() {
        // Rendering only: Windows cannot create this name, so the origin is
        // built in memory instead of read from a real file.
        let mut settings = Settings::default();
        settings.risk_low.set(
            Some(90),
            Origin::File(PathBuf::from("synthetic-root/x\u{1b}[31mRED\u{202e}.yaml")),
        );
        let error = settings
            .check_risk_threshold_order()
            .expect_err("unordered thresholds");
        assert!(
            !error.contains('\u{1b}') && !error.contains('\u{202e}'),
            "{error:?}"
        );
        assert!(
            error.contains("low=90 (settings file x\\u{1b}[31mRED\\u{202e}.yaml)"),
            "{error}"
        );
    }

    #[test]
    fn equal_risk_thresholds_remain_valid() {
        let temp = tempdir().expect("tempdir");
        let file = write(
            temp.path(),
            "settings.yaml",
            "version: 1\nrisk_thresholds: {low: 1, medium: 1, high: 1, critical: 1}\n",
        );
        resolve(&[file], &env(&[]), &CliSettings::default()).expect("equal thresholds");
    }

    #[test]
    fn invalid_documents_fail_before_activation() {
        let temp = tempdir().expect("tempdir");
        for (text, expected) in [
            ("version: 2\n", "version 2 is not supported"),
            ("risk_thresholds: {low: 1}\n", "missing field `version`"),
            (
                "version: 1\nrisk_thresholds: {lowest: 1}\n",
                "unknown field `lowest`",
            ),
            (
                "version: 1\nscan: {interval_seconds: 1}\n",
                "unknown field `scan`",
            ),
            ("version: 1\nlog_rotation: {keep: -1}\n", "expected usize"),
        ] {
            let path = write(temp.path(), "settings.yaml", text);
            let error = resolve(&[path], &env(&[]), &CliSettings::default())
                .expect_err("invalid document")
                .to_string();
            assert!(error.contains(expected), "{text:?}: {error}");
        }

        let oversized = format!(
            "version: 1\n#{}\n",
            "x".repeat(MAX_SETTINGS_FILE_BYTES as usize)
        );
        let path = write(temp.path(), "settings.yaml", &oversized);
        let error = resolve(&[path], &env(&[]), &CliSettings::default())
            .expect_err("oversized document")
            .to_string();
        assert!(error.contains("exceeds 65536 bytes"), "{error}");
    }

    /// A settings entry that became a FIFO after discovery is refused at
    /// once: waiting on it would hold a hook before it can answer.
    #[cfg(unix)]
    #[test]
    fn a_fifo_settings_file_is_refused_without_blocking() {
        use std::os::unix::ffi::OsStrExt;
        let dir = tempfile::tempdir().unwrap();
        let fifo = dir.path().join("hooks.yaml");
        let name = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: a valid NUL-terminated path; mkfifo only creates the entry.
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        let error = super::open_settings_file(&fifo).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    }
}
