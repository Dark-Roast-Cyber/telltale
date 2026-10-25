//! Operator settings: each setting is defined once, with its default, its
//! validation, and the file key and any environment variable or flag that set
//! it.
//!
//! Precedence, lowest to highest: compiled defaults, `settings.d/*.yaml` in
//! config-root order (sorted within a root, so a later file wins per key),
//! `TELLTALE_*` environment variables, then explicit CLI flags. Settings are
//! resolved once when a command starts; a service restart applies changes.

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

/// Flags that override settings for one invocation.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct CliSettings {
    pub(crate) no_community_rules: bool,
    pub(crate) log_rotate_max_size: Option<u64>,
    pub(crate) log_rotate_keep: Option<usize>,
    pub(crate) log_rotate_disabled: bool,
    pub(crate) install_inventory_interval_seconds: Option<u64>,
    pub(crate) install_inventory_disabled: bool,
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
    pub(crate) emit_activity: Setting<bool>,
    pub(crate) emit_session_risk_summary: Setting<bool>,
    pub(crate) baseline_deviation_scoring: Setting<bool>,
    pub(crate) watch_debounce_ms: Setting<u64>,
    pub(crate) watch_min_scan_interval_ms: Setting<u64>,
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
            emit_activity: Setting::new(false),
            emit_session_risk_summary: Setting::new(false),
            baseline_deviation_scoring: Setting::new(false),
            watch_debounce_ms: Setting::new(500),
            watch_min_scan_interval_ms: Setting::new(10_000),
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
        fs::File::open(path)
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
        self.watch_debounce_ms
            .set(document.watch.debounce_ms, origin());
        self.watch_min_scan_interval_ms
            .set(document.watch.min_scan_interval_ms, origin());
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
            .set_env(env, "TELLTALE_INSTALL_INVENTORY_INTERVAL_SECONDS")
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

    /// Each effective value with its default and origin, keyed by its
    /// `settings.d` path. A winning file appears only as its path hash.
    pub(crate) fn to_json(&self) -> serde_json::Value {
        fn entry<T: Clone + serde::Serialize>(setting: &Setting<T>) -> serde_json::Value {
            let (origin, source) = match &setting.origin {
                Origin::Default => ("default", None),
                Origin::File(path) => ("settings_file", Some(path_hash(path))),
                Origin::Environment(name) => ("environment", Some(name.to_string())),
                Origin::Cli(flag) => ("cli", Some(flag.to_string())),
            };
            serde_json::json!({
                "value": setting.value,
                "default": setting.default,
                "origin": origin,
                "source": source,
            })
        }
        serde_json::json!({
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
            "watch.debounce_ms": entry(&self.watch_debounce_ms),
            "watch.min_scan_interval_ms": entry(&self.watch_min_scan_interval_ms),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;
    use std::path::{Path, PathBuf};

    use telltale_schema::event::path_hash;
    use tempfile::tempdir;

    use super::{CliSettings, MAX_SETTINGS_FILE_BYTES, Settings, resolve};

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
}
