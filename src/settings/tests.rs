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
fn each_diagnostics_category_resolves_on_its_own() {
    use crate::diagnostics::Categories;

    let defaults = resolve(&[], &env(&[]), &CliSettings::default()).expect("defaults");
    assert_eq!(defaults.diagnostics_categories(), Categories::default());
    assert_eq!(defaults.diagnostics_path(), None);

    let temp = tempdir().expect("tempdir");
    let file = write(
        temp.path(),
        "settings.yaml",
        "version: 1\ndiagnostics: {scan_phases: true, process_resources: true, path: from-file.jsonl}\n",
    );
    // The file turns both on; the environment turns one off again and
    // moves the file.
    let settings = resolve(
        std::slice::from_ref(&file),
        &env(&[
            ("TELLTALE_DIAGNOSTICS_PROCESS_RESOURCES", "off"),
            ("TELLTALE_DIAGNOSTICS_PATH", "from-env.jsonl"),
        ]),
        &CliSettings::default(),
    )
    .expect("resolve");
    assert_eq!(
        settings.diagnostics_categories(),
        Categories {
            scan_phases: true,
            process_resources: false,
        }
    );
    assert_eq!(
        settings.diagnostics_path(),
        Some(Path::new("from-env.jsonl"))
    );
    assert_eq!(
        origin(&settings, "diagnostics.scan_phases"),
        ("settings_file".into(), path_hash(&file).into())
    );
    assert_eq!(
        origin(&settings, "diagnostics.process_resources"),
        (
            "environment".into(),
            "TELLTALE_DIAGNOSTICS_PROCESS_RESOURCES".into()
        )
    );
    // The path is reported only as its hash.
    assert_eq!(
        settings.to_json()["diagnostics.path"]["value"],
        path_hash(Path::new("from-env.jsonl"))
    );

    // The flag turns a category on over the environment; the other
    // category keeps the environment's value.
    let settings = resolve(
        std::slice::from_ref(&file),
        &env(&[
            ("TELLTALE_DIAGNOSTICS_PROCESS_RESOURCES", "off"),
            ("TELLTALE_DIAGNOSTICS_SCAN_PHASES", "0"),
        ]),
        &CliSettings {
            diagnostics: Categories {
                scan_phases: false,
                process_resources: true,
            },
            diagnostics_path: Some("from-cli.jsonl".into()),
            ..CliSettings::default()
        },
    )
    .expect("resolve");
    assert_eq!(
        settings.diagnostics_categories(),
        Categories {
            scan_phases: false,
            process_resources: true,
        }
    );
    assert_eq!(
        origin(&settings, "diagnostics.process_resources"),
        ("cli".into(), "--diagnostics".into())
    );
    assert_eq!(
        origin(&settings, "diagnostics.scan_phases"),
        (
            "environment".into(),
            "TELLTALE_DIAGNOSTICS_SCAN_PHASES".into()
        )
    );
    assert_eq!(
        settings.diagnostics_path(),
        Some(Path::new("from-cli.jsonl"))
    );
    assert_eq!(
        origin(&settings, "diagnostics.path"),
        ("cli".into(), "--diagnostics-path".into())
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
