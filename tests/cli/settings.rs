use super::*;

fn codex_store(root: &Path) {
    let sessions = root.join("codex/sessions/2026/04");
    fs::create_dir_all(&sessions).expect("codex sessions dir");
    fs::write(
        sessions.join("uc001-positive.jsonl"),
        include_str!(
            "../../tests/fixtures/session_stores/codex/sessions/2026/04/uc001-positive.jsonl"
        ),
    )
    .expect("uc001 fixture");
}

fn settings_file(config_root: &Path, name: &str, text: &str) -> std::path::PathBuf {
    let dir = config_root.join("settings.d");
    fs::create_dir_all(&dir).expect("settings dir");
    let path = dir.join(name);
    fs::write(&path, text).expect("settings file");
    path
}

fn telltale(home: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_telltale"));
    command.env_clear().env("HOME", home);
    command
}

#[test]
fn deployed_settings_drive_scan_and_report_each_origin() {
    let temp = tempdir().expect("tempdir");
    let stores = temp.path().join("session_stores");
    codex_store(&stores);
    let config_root = temp.path().join("config");
    let deployed = settings_file(
        &config_root,
        "10-deployed.yaml",
        "version: 1\nrisk_thresholds: {low: 1, medium: 1, high: 1, critical: 1}\ninstall_inventory: {enabled: false}\nevents: {emit_activity: true}\n",
    );
    let log_path = temp.path().join("events.jsonl");

    let output = telltale(temp.path())
        .env("TELLTALE_OP_ALERT_MAX_SCANNER_ERRORS", "7")
        .args(["scan", "--once", "--allow-fixtures", "--client", "codex"])
        .arg("--config-dir")
        .arg(&config_root)
        .arg("--root")
        .arg(&stores)
        .arg("--log-path")
        .arg(&log_path)
        .arg("--state-path")
        .arg(temp.path().join("state.json"))
        .args(["--log-rotate-keep", "2"])
        .output()
        .expect("run telltale scan");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let events = fs::read_to_string(&log_path)
        .expect("event log")
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("event json"))
        .collect::<Vec<_>>();
    let detection = events
        .iter()
        .find(|event| event["event_type"] == "detection")
        .expect("detection event");
    assert_eq!(detection["severity"], "critical");
    assert!(
        !events
            .iter()
            .any(|event| event["event_type"] == "install_inventory")
    );
    assert!(events.iter().any(|event| event["event_type"] == "activity"));

    let summary: Value = serde_json::from_slice(&output.stdout).expect("summary json");
    let settings = &summary["effective_configuration"]["settings"];
    assert_eq!(
        settings["risk_thresholds.high"],
        serde_json::json!({
            "value": 1,
            "default": 70,
            "origin": "settings_file",
            "source": path_hash(&deployed),
        })
    );
    assert_eq!(settings["install_inventory.enabled"]["value"], false);
    assert_eq!(
        settings["operational_alerts.max_scanner_errors"]["source"],
        "TELLTALE_OP_ALERT_MAX_SCANNER_ERRORS"
    );
    assert_eq!(settings["log_rotation.keep"]["source"], "--log-rotate-keep");
    assert_eq!(settings["rules.community"]["origin"], "default");
    assert_eq!(settings["events.emit_activity"]["origin"], "settings_file");

    // Provenance represents what the deployed file enables.
    let output = telltale(temp.path())
        .args(["config", "provenance", "--config-dir"])
        .arg(&config_root)
        .output()
        .expect("run telltale config provenance");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let manifest: Value = serde_json::from_slice(&output.stdout).expect("provenance json");
    assert_eq!(manifest["features"]["emit_activity"], true);
    assert_eq!(manifest["features"]["install_inventory"], false);
}

#[test]
fn documented_settings_file_sets_every_key_to_its_default() {
    // Windows checkouts may convert the guide to CRLF.
    let install = fs::read_to_string("docs/install.md")
        .expect("install docs")
        .replace("\r\n", "\n");
    let block = install
        .split("### Operational settings")
        .nth(1)
        .and_then(|section| section.split("```yaml\n").nth(1))
        .and_then(|rest| rest.split("```").next())
        .expect("documented settings block");
    let temp = tempdir().expect("tempdir");
    let config_root = temp.path().join("config");
    settings_file(&config_root, "settings.yaml", block);

    let output = telltale(temp.path())
        .args(["config", "show", "--config-dir"])
        .arg(&config_root)
        .output()
        .expect("run telltale config show");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let shown: Value = serde_json::from_slice(&output.stdout).expect("config show json");
    for (key, entry) in shown["settings"].as_object().expect("settings") {
        assert_eq!(entry["origin"], "settings_file", "{key} is undocumented");
        assert_eq!(entry["value"], entry["default"], "{key}");
    }
}

#[test]
fn invalid_setting_fails_before_any_output_and_names_only_the_variable() {
    let temp = tempdir().expect("tempdir");
    let stores = temp.path().join("session_stores");
    codex_store(&stores);
    let log_path = temp.path().join("events.jsonl");

    let output = telltale(temp.path())
        .env("TELLTALE_LOG_ROTATE_KEEP", "many-CONTROLLED")
        .args(["scan", "--once", "--allow-fixtures", "--no-local-config"])
        .arg("--root")
        .arg(&stores)
        .arg("--log-path")
        .arg(&log_path)
        .arg("--state-path")
        .arg(temp.path().join("state.json"))
        .output()
        .expect("run telltale scan");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("invalid TELLTALE_LOG_ROTATE_KEEP"),
        "{stderr}"
    );
    assert!(!stderr.contains("CONTROLLED"), "{stderr}");
    assert!(!log_path.exists());

    // Provenance keeps its other errors private but still names the variable.
    let output = telltale(temp.path())
        .env("TELLTALE_RISK_THRESHOLD_HIGH", "high-CONTROLLED")
        .args(["config", "provenance", "--no-local-config"])
        .output()
        .expect("run telltale config provenance");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("invalid TELLTALE_RISK_THRESHOLD_HIGH"),
        "{stderr}"
    );
    assert!(!stderr.contains("CONTROLLED"), "{stderr}");

    let config_root = temp.path().join("config");
    settings_file(
        &config_root,
        "bad.yaml",
        "version: 1\nlog_rotation: {copies: 2}\n",
    );
    let output = telltale(temp.path())
        .args(["config", "validate", "--config-dir"])
        .arg(&config_root)
        .output()
        .expect("run telltale config validate");
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("unknown field `copies`"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn config_show_explains_files_environment_and_defaults() {
    let temp = tempdir().expect("tempdir");
    let vendor_root = temp.path().join("vendor");
    let local_root = temp.path().join("local");
    // The same file name in two roots stays distinguishable.
    let vendor = settings_file(
        &vendor_root,
        "50-settings.yaml",
        "version: 1\nlog_rotation: {keep: 2}\nrules: {community: false}\n",
    );
    let local = settings_file(
        &local_root,
        "50-settings.yaml",
        "version: 1\nlog_rotation: {keep: 3}\n",
    );

    let show = |args: &[&str]| -> Value {
        let output = telltale(temp.path())
            .env("TELLTALE_RISK_THRESHOLD_CRITICAL", "95")
            .args(["config", "show"])
            .args(args)
            .output()
            .expect("run telltale config show");
        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).expect("config show json")
    };

    let vendor_root_arg = vendor_root.to_string_lossy().into_owned();
    let local_root_arg = local_root.to_string_lossy().into_owned();
    let shown = show(&[
        "--config-dir",
        &vendor_root_arg,
        "--config-dir",
        &local_root_arg,
    ]);
    let files = shown["files"].as_array().expect("files");
    assert_eq!(
        files
            .iter()
            .map(|file| file["path_hash"].clone())
            .collect::<Vec<_>>(),
        [path_hash(&vendor), path_hash(&local)]
    );
    let settings = &shown["settings"];
    assert_eq!(settings["log_rotation.keep"]["value"], 3);
    assert_eq!(settings["log_rotation.keep"]["origin"], "settings_file");
    assert_eq!(settings["log_rotation.keep"]["source"], path_hash(&local));
    assert_eq!(settings["rules.community"]["value"], false);
    assert_eq!(settings["rules.community"]["source"], path_hash(&vendor));
    assert_eq!(settings["risk_thresholds.critical"]["value"], 95);
    assert_eq!(
        settings["risk_thresholds.critical"]["origin"],
        "environment"
    );
    assert_eq!(settings["risk_thresholds.low"]["origin"], "default");

    let without_files = show(&["--no-local-config"]);
    assert_eq!(without_files["files"], serde_json::json!([]));
    assert_eq!(
        without_files["settings"]["log_rotation.keep"]["origin"],
        "default"
    );
    assert_eq!(without_files["settings"]["rules.community"]["value"], true);
}

#[test]
fn unordered_risk_thresholds_fail_every_consumer_before_output() {
    let temp = tempdir().expect("tempdir");
    let stores = temp.path().join("session_stores");
    codex_store(&stores);
    let config_root = temp.path().join("config");
    let unordered = "version: 1\nrisk_thresholds: {low: 90, medium: 50, high: 10, critical: 5}\n";
    settings_file(&config_root, "50-unordered.yaml", unordered);
    // `export --correlate` reads only the default roots.
    settings_file(
        &temp.path().join(".config/telltale"),
        "50-unordered.yaml",
        unordered,
    );
    let log_path = temp.path().join("events.jsonl");
    let state_path = temp.path().join("state.json");
    let config_dir = config_root.to_string_lossy().into_owned();
    let root = stores.to_string_lossy().into_owned();
    let log = log_path.to_string_lossy().into_owned();
    let state = state_path.to_string_lossy().into_owned();
    let runtime = [
        "--allow-fixtures",
        "--config-dir",
        &config_dir,
        "--root",
        &root,
        "--log-path",
        &log,
        "--state-path",
        &state,
    ];

    let mut commands: Vec<Vec<&str>> = vec![
        vec!["config", "validate", "--config-dir", &config_dir],
        vec!["config", "show", "--config-dir", &config_dir],
        vec!["config", "provenance", "--config-dir", &config_dir],
        vec!["rules", "validate", "--config-dir", &config_dir],
        vec!["export", "--correlate", "--log-path", &log],
    ];
    commands.push([&["scan", "--once"][..], &runtime].concat());
    commands.push([&["watch", "--iterations", "1"][..], &runtime].concat());
    for args in commands {
        let output = telltale(temp.path())
            .args(&args)
            .output()
            .expect("run telltale");
        assert!(
            !output.status.success(),
            "{args:?} accepted unordered thresholds"
        );
        assert!(output.stdout.is_empty(), "{args:?} wrote stdout");
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Provenance keeps file-derived errors private.
        if args[1] != "provenance" {
            assert_eq!(
                stderr.trim_end(),
                "invalid risk thresholds: low=90 (settings file 50-unordered.yaml) is above \
                 medium=50 (settings file 50-unordered.yaml); expected low <= medium <= high <= critical",
                "{args:?}"
            );
        }
        assert!(!log_path.exists() && !state_path.exists(), "{args:?}");
    }

    // A valid file inverted by the environment fails the same way, and the
    // same environment still applies with --no-local-config.
    let ordered_root = temp.path().join("ordered");
    settings_file(
        &ordered_root,
        "10-ordered.yaml",
        "version: 1\nrisk_thresholds: {low: 10, medium: 20, high: 30, critical: 40}\n",
    );
    let ordered_dir = ordered_root.to_string_lossy().into_owned();
    for local in [
        vec!["--config-dir", ordered_dir.as_str()],
        vec!["--no-local-config"],
    ] {
        let output = telltale(temp.path())
            .env("TELLTALE_RISK_THRESHOLD_HIGH", "60")
            .env("TELLTALE_RISK_THRESHOLD_CRITICAL", "55")
            .args(["scan", "--once", "--allow-fixtures"])
            .args(&local)
            .args(["--root", &root, "--log-path", &log, "--state-path", &state])
            .output()
            .expect("run telltale scan");
        assert!(!output.status.success(), "{local:?}");
        assert!(output.stdout.is_empty(), "{local:?}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains(
                "high=60 (TELLTALE_RISK_THRESHOLD_HIGH) is above \
                 critical=55 (TELLTALE_RISK_THRESHOLD_CRITICAL)"
            ),
            "{local:?}: {stderr}"
        );
        assert!(!log_path.exists() && !state_path.exists());
    }
}
