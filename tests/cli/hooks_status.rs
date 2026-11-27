use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::{Value, json};

const TOKEN: &str = "sk-proj-SyntheticStatusPrivacyPlant0123456789";
const HOME_MARKER: &str = "synthetic-status-home-alice";

struct Fixture {
    _temp: tempfile::TempDir,
    home: PathBuf,
    project: PathBuf,
    config: PathBuf,
    state: PathBuf,
    system: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join(HOME_MARKER);
        let project = temp.path().join("project");
        let config = home.join("config/telltale");
        let state = home.join("state");
        let system = temp.path().join("system");
        for dir in [&home, &project, &config, &system] {
            fs::create_dir_all(dir).unwrap();
        }
        fs::create_dir(project.join(".git")).unwrap();
        Self {
            _temp: temp,
            home,
            project,
            config,
            state,
            system,
        }
    }

    fn run(&self, args: &[&str]) -> Output {
        self.run_at(args, &self.config)
    }

    fn run_at(&self, args: &[&str], config: &Path) -> Output {
        let output = self
            .command()
            .args(args)
            .arg("--config-dir")
            .arg(config)
            .output()
            .unwrap();
        for bytes in [&output.stdout, &output.stderr] {
            let text = String::from_utf8_lossy(bytes);
            assert!(!text.contains(HOME_MARKER), "{text}");
            assert!(!text.contains(TOKEN), "{text}");
        }
        output
    }

    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_telltale"));
        command
            .env_clear()
            .env("HOME", &self.home)
            .env("USERPROFILE", &self.home)
            .env("LOCALAPPDATA", self.home.join("local"))
            .env("APPDATA", self.home.join("roaming"))
            .env("XDG_CONFIG_HOME", self.home.join("config"))
            .env("XDG_RUNTIME_DIR", self._temp.path())
            .env("TELLTALE_HOOKS_STATE_DIR", &self.state)
            .env("TELLTALE_HOOKS_TEST_MANAGED_SETTINGS_ROOT", &self.system)
            .current_dir(&self.project)
            .arg("hooks");
        command
    }

    fn status(&self) -> Value {
        self.status_at(&self.config)
    }

    fn status_at(&self, config: &Path) -> Value {
        let output = self.run_at(&["status", "--json"], config);
        assert!(output.status.success(), "{output:?}");
        let document = serde_json::from_slice(&output.stdout).unwrap();
        let schema: Value = serde_json::from_slice(
            &fs::read(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/schemas/telltale-hooks-status-v1.schema.json"
            ))
            .unwrap(),
        )
        .unwrap();
        jsonschema::validator_for(&schema)
            .unwrap()
            .validate(&document)
            .unwrap();
        document
    }

    fn write(&self, path: &Path, bytes: impl AsRef<[u8]>) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
    }
}

#[test]
fn hooks_status_and_check_share_a_private_configuration_view() {
    let fixture = Fixture::new();
    fixture.write(
        &fixture.config.join("settings.d/10-hooks.yaml"),
        format!("version: 1\n# {TOKEN}\nhooks:\n  mode: enforce\n  on_error: deny\n"),
    );
    let status = fixture.status();
    assert_eq!(status["schema"], "telltale_hooks.status.v1");
    let check = fixture.run(&["check", "--json"]);
    assert!(check.status.success(), "{check:?}");
    assert_eq!(
        serde_json::from_slice::<Value>(&check.stdout).unwrap(),
        status["configuration"]
    );
    assert_eq!(status["configuration"]["mode"], "enforce");
    assert_eq!(status["configuration"]["on_error"], "deny");
    assert_eq!(status["configuration"]["origin"], "user");
    assert_eq!(status["configuration"]["valid"], true);
    let original_hash = status["configuration"]["content_sha256"].clone();
    fixture.write(
        &fixture.config.join("settings.d/10-hooks.yaml"),
        "version: 1\n# A different file with the same behavior\nhooks:\n  mode: enforce\n  on_error: deny\n",
    );
    let changed = fixture.status();
    assert_ne!(changed["configuration"]["content_sha256"], original_hash);
    assert_eq!(
        changed["configuration"]["semantic_identity"],
        status["configuration"]["semantic_identity"]
    );
    let text = fixture.run(&["status"]);
    assert!(text.status.success(), "{text:?}");
    let text = String::from_utf8(text.stdout).unwrap();
    assert!(text.contains("mode: enforce"));
    assert!(
        text.contains(
            status["configuration"]["semantic_identity"]
                .as_str()
                .unwrap()
        )
    );
    assert!(!fixture.state.exists());
}

#[test]
fn hooks_status_describes_invalid_and_managed_configuration() {
    let fixture = Fixture::new();
    fixture.write(
        &fixture.system.join("settings.d/10-hooks.yaml"),
        "version: 1\nhooks:\n  mode: enforce\n",
    );
    let managed = fixture.status_at(&fixture.system);
    assert_eq!(managed["configuration"]["origin"], "managed");
    fixture.write(
        &fixture.system.join("settings.d/10-hooks.yaml"),
        format!("version: 1\nhooks:\n  mode: {TOKEN}\n"),
    );
    let invalid = fixture.status_at(&fixture.system);
    assert_eq!(invalid["configuration"]["valid"], false);
    assert!(invalid["configuration"]["error_code"].is_string());
    assert!(invalid["configuration"]["semantic_identity"].is_null());
    let check = fixture.run_at(&["check", "--json"], &fixture.system);
    assert_eq!(check.status.code(), Some(1));
    assert_eq!(
        serde_json::from_slice::<Value>(&check.stdout).unwrap(),
        invalid["configuration"]
    );
    // Failed hook configurations emit to the runtime fallback path.
    fixture.write(&fixture.state.join("telemetry.jsonl"), b"not json\n");
    let invalid = fixture.status_at(&fixture.system);
    assert_eq!(invalid["telemetry"]["state"], "active");
    assert_eq!(invalid["telemetry"]["rejected_counts"]["malformed_json"], 1);
}

#[test]
fn hooks_status_without_install_or_records_does_not_create_state() {
    let fixture = Fixture::new();
    fixture.write(
        &fixture.config.join("settings.d/10-hooks.yaml"),
        "version: 1\nhooks:\n  evaluator:\n    enabled: false\n",
    );
    let status = fixture.status();
    assert_eq!(status["harnesses"].as_array().unwrap().len(), 4);
    for harness in status["harnesses"].as_array().unwrap() {
        assert_eq!(harness["installed_scopes"], json!([]));
    }
    assert_eq!(status["evaluator"], "not_configured");
    assert_eq!(status["telemetry"]["state"], "missing");
    assert_eq!(status["telemetry"]["complete"], true);
    assert!(!fixture.state.exists());
}

#[test]
fn hooks_status_reports_active_telemetry_without_echoing_records_or_writing_state() {
    use std::io::Write;

    let fixture = Fixture::new();
    let path = fixture.state.join("telemetry.jsonl");
    let mut row = json!({
        "schema": "telltale_hooks.record.v1",
        "record_id": "tth:0123456789abcdef0123456789abcdef",
        "recorded_at": "2026-11-26T12:34:56Z", "kind": "error",
        "producer": {"name": "telltale-hooks", "version": "0.8.0",
            "telltale_rev": "0123456789012345678901234567890123456789", "semantic_identity": null},
        "harness": {"name": "claude-code", "hook_event": "", "permission_mode": null},
        "session": {"session_id": TOKEN, "agent_id": null, "agent_type": null, "prompt_id": null, "cwd_sha256": null},
        "error_code": "payload_invalid_json", "telltale": []
    });
    let rejected = format!("{row}\n");
    row["session"]["session_id"] = json!("");
    fixture.write(&path, format!("{row}\n{row}\n{rejected}not json {TOKEN}\n"));
    let mut file = fs::OpenOptions::new().append(true).open(&path).unwrap();
    row["error_code"] = json!("synthetic_alice_private");
    writeln!(file, "{row}").unwrap();
    row.as_object_mut().unwrap().remove("error_code");
    row["kind"] = json!("decision");
    row["harness"]["hook_event"] = json!("PreToolUse");
    row["session"]["session_id"] = json!("synthetic-session");
    row["recorded_at"] = json!("2026-11-26T12:35:00Z");
    row["action"] = json!({"tool_use_id": "synthetic-private-call", "tool_name": "Read", "input_sha256": "ab".repeat(32)});
    row["evaluation"] = json!({
        "status": "complete", "coverage": "whole_source", "visibility_limits": [],
        "failure_code": null, "window_records": 1, "window_truncated": false,
        "build_ms": null, "scan_ms": null, "evaluator": "in_process", "evaluator_fallback": null
    });
    row["decision"] = json!({
        "mode": "observe", "verdict": "allow", "returned": false, "basis": "no_finding",
        "action_score": 0, "session_score_before": 0, "session_score_after": 0,
        "denied_attempts_before": 0, "rule_ids": [], "categories": []
    });
    writeln!(file, "{row}").unwrap();
    row["recorded_at"] = json!("2026-11-26T12:36:00Z");
    let archive = fixture.state.join("telemetry-2026-11-26.jsonl");
    fixture.write(&archive, format!("{row}\n"));
    file.write_all(&vec![b'x'; telltale_core::HOOKS_RECORD_MAX_INPUT_BYTES])
        .unwrap();
    writeln!(file).unwrap();
    drop(file);
    let before = fs::read(&path).unwrap();
    let archived = fs::read(&archive).unwrap();
    let status = fixture.status();
    assert_eq!(
        status["telemetry"]["error_counts"]["payload_invalid_json"],
        2
    );
    assert_eq!(status["telemetry"]["error_counts"]["other"], 1);
    assert_eq!(
        status["telemetry"]["last_decision_at"],
        "2026-11-26T12:35:00Z"
    );
    assert!(!status.to_string().contains("synthetic_alice_private"));
    assert!(!status.to_string().contains("synthetic-private-call"));
    assert_eq!(status["telemetry"]["rejected_counts"]["malformed_json"], 1);
    assert_eq!(status["telemetry"]["rejected_counts"]["input_too_large"], 1);
    assert_eq!(status["telemetry"]["complete"], true);
    assert_eq!(fs::read(&path).unwrap(), before);
    assert_eq!(fs::read(&archive).unwrap(), archived);
    assert_eq!(fs::read_dir(&fixture.state).unwrap().count(), 2);
    assert!(fixture.run(&["status"]).status.success());
}

#[test]
fn hooks_status_marks_a_bounded_active_suffix_incomplete() {
    use std::io::{Seek, SeekFrom, Write};

    let fixture = Fixture::new();
    let path = fixture.state.join("telemetry.jsonl");
    fixture.write(&path, b"");
    let mut file = fs::OpenOptions::new().write(true).open(path).unwrap();
    file.seek(SeekFrom::Start(64 * 1024 * 1024)).unwrap();
    writeln!(file, "\ninvalid").unwrap();
    drop(file);
    let status = fixture.status();
    assert_eq!(status["telemetry"]["complete"], false);
    assert_eq!(
        status["telemetry"]["rejected_counts"],
        json!({"malformed_json": 1})
    );
}

#[test]
fn hooks_status_compares_installed_entries_with_the_adapter_output() {
    let fixture = Fixture::new();
    for (name, user, project) in [
        (
            "claude-code",
            ".claude/settings.json",
            ".claude/settings.json",
        ),
        ("codex-cli", ".codex/hooks.json", ".codex/hooks.json"),
        (
            "copilot-cli",
            ".copilot/hooks/telltale-hooks.json",
            ".github/hooks/telltale-hooks.json",
        ),
    ] {
        let output = fixture
            .command()
            .args([
                name,
                "settings",
                &format!("telltale hooks {name} hook --config-dir synthetic"),
            ])
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        let mut settings: Value = serde_json::from_slice(&output.stdout).unwrap();
        settings["synthetic_privacy_plant"] = json!(TOKEN);
        fixture.write(&fixture.home.join(user), settings.to_string());
        fixture.write(&fixture.project.join(project), settings.to_string());
        let status = fixture.status();
        let harness = status["harnesses"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["name"] == name)
            .unwrap();
        assert_eq!(harness["installed_scopes"], json!(["user", "project"]));
        assert!(
            harness["settings"]
                .as_array()
                .unwrap()
                .iter()
                .any(|entry| entry["scope"] == "user" && entry["state"] == "present")
        );
        settings["hooks"] = json!({});
        fixture.write(&fixture.home.join(user), settings.to_string());
        settings["hooks"] = json!("not a hook table");
        fixture.write(&fixture.project.join(project), settings.to_string());
        let status = fixture.status();
        let harness = status["harnesses"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["name"] == name)
            .unwrap();
        let entries = harness["settings"].as_array().unwrap();
        assert!(
            entries
                .iter()
                .any(|entry| entry["scope"] == "user" && entry["state"] == "missing")
        );
        assert!(
            entries
                .iter()
                .any(|entry| entry["scope"] == "project" && entry["state"] == "altered")
        );
    }
}

#[cfg(debug_assertions)]
#[test]
fn hooks_status_reports_managed_harness_files_without_using_machine_settings() {
    let fixture = Fixture::new();
    let cases = [
        (
            "claude-code",
            if cfg!(any(windows, target_os = "macos")) {
                "ClaudeCode/managed-settings.json"
            } else {
                "claude-code/managed-settings.json"
            },
        ),
        (
            "copilot-cli",
            if cfg!(windows) {
                "GitHub/Copilot/policy.d/telltale-hooks.json"
            } else {
                "github-copilot/policy.d/telltale-hooks.json"
            },
        ),
    ];
    for (name, file) in cases {
        let output = fixture
            .command()
            .args([
                name,
                "settings",
                &format!("telltale hooks {name} hook --config-dir synthetic"),
            ])
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        let path = fixture.system.join(file);
        fixture.write(&path, &output.stdout);
        let status = fixture.status();
        let harness = status["harnesses"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["name"] == name)
            .unwrap();
        assert_eq!(harness["installed_scopes"], json!(["managed"]));
        fixture.write(&path, format!("not json {TOKEN}"));
        let status = fixture.status();
        assert!(
            status["harnesses"]
                .as_array()
                .unwrap()
                .iter()
                .find(|entry| entry["name"] == name)
                .unwrap()["settings"]
                .as_array()
                .unwrap()
                .iter()
                .any(|entry| entry["scope"] == "managed" && entry["state"] == "altered")
        );
        fs::remove_file(path).unwrap();
        let status = fixture.status();
        assert!(
            status["harnesses"]
                .as_array()
                .unwrap()
                .iter()
                .find(|entry| entry["name"] == name)
                .unwrap()["settings"]
                .as_array()
                .unwrap()
                .iter()
                .any(|entry| entry["scope"] == "managed" && entry["state"] == "missing")
        );
    }
}

#[test]
fn hooks_status_reports_the_opencode_pilot_wrapper_by_scope() {
    let fixture = Fixture::new();
    let user = fixture.home.join("config/opencode/plugins/telltale.js");
    let project = fixture.project.join(".opencode/plugins/telltale.js");
    let wrapper = format!(
        "import {{ createPlugin }} from \"/{HOME_MARKER}/opencode-v2.mjs\"\n\
         export default createPlugin({{ executable: \"/{HOME_MARKER}/telltale\", configDirs: [\"/{HOME_MARKER}/config\"], mode: \"detect_only\" }})\n\
         // {TOKEN}\n"
    );
    fixture.write(&user, &wrapper);
    fixture.write(&project, &wrapper);
    let status = fixture.status();
    let report = status["harnesses"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["name"] == "opencode")
        .unwrap();
    assert_eq!(report["installed_scopes"], json!(["user", "project"]));
    fs::remove_file(user).unwrap();
    fixture.write(&project, format!("// {TOKEN}\nexport default {{}};\n"));
    let status = fixture.status();
    let report = status["harnesses"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["name"] == "opencode")
        .unwrap();
    assert!(
        report["settings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["scope"] == "user" && entry["state"] == "missing")
    );
    assert!(
        report["settings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["scope"] == "project" && entry["state"] == "altered")
    );
}

#[test]
fn hooks_status_evaluator_probe_is_read_only() {
    let fixture = Fixture::new();
    fixture.write(
        &fixture.config.join("settings.d/10-hooks.yaml"),
        "version: 1\nhooks:\n  evaluator:\n    enabled: true\n    autostart: true\n",
    );
    let status = fixture.status();
    let expected = if cfg!(unix) {
        "not_running"
    } else {
        "unsupported_platform"
    };
    assert_eq!(status["evaluator"], expected);
    assert!(!fixture.state.exists());
}

#[cfg(unix)]
#[test]
fn hooks_status_probes_a_listener_without_sending_a_hook_request() {
    use std::io::Read;
    use std::os::unix::net::UnixListener;

    let fixture = Fixture::new();
    let socket = fixture._temp.path().join("s");
    fixture.write(
        &fixture.config.join("settings.d/10-hooks.yaml"),
        format!(
            "version: 1\nhooks:\n  evaluator:\n    enabled: true\n    socket: {}\n",
            serde_json::to_string(&socket).unwrap()
        ),
    );
    let listener = UnixListener::bind(&socket).unwrap();
    listener.set_nonblocking(true).unwrap();
    assert_eq!(fixture.status()["evaluator"], "running");
    let (mut stream, _) = listener.accept().unwrap();
    // The probe has exited, so the peer is closed and the read ends at once.
    // macOS refuses a socket option on a stream whose peer has closed, so
    // the timeout is only a bound where it can be set.
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_millis(100)));
    assert_eq!(stream.read(&mut [0]).unwrap(), 0);
    drop(listener); // Leaves a stale socket node.
    assert_eq!(fixture.status()["evaluator"], "unreachable");
    assert!(!fixture.state.exists());
}

fn assert_codex_user_settings(report: &Value, toml_state: &str) {
    let codex = report["harnesses"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["name"] == "codex-cli")
        .unwrap();
    let states: Vec<_> = codex["settings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|entry| entry["scope"] == "user")
        .map(|entry| entry["state"].as_str().unwrap())
        .collect();
    assert_eq!(states, ["missing", toml_state]);
    assert_eq!(codex["installed_scopes"], json!([]));
}

#[test]
fn hooks_status_does_not_inspect_codex_toml_with_inline_hooks() {
    let fixture = Fixture::new();
    fixture.write(
        &fixture.home.join(".codex/config.toml"),
        "[[hooks.PreToolUse]]\n[[hooks.PreToolUse.hooks]]\n\
         type = \"command\"\ncommand = \"telltale hooks codex-cli hook\"\ntimeout = 30\n",
    );
    assert_codex_user_settings(&fixture.status(), "not_inspected");
    let text = fixture.run(&["status"]);
    assert!(text.status.success());
    assert!(
        String::from_utf8(text.stdout)
            .unwrap()
            .contains("not_inspected")
    );
}

#[test]
fn hooks_status_does_not_inspect_codex_toml_without_hooks() {
    let fixture = Fixture::new();
    let path = fixture.home.join(".codex/config.toml");
    fixture.write(&path, format!("# {TOKEN}\nmodel = \"synthetic\"\n"));
    assert_codex_user_settings(&fixture.status(), "not_inspected");
    fs::remove_file(path).unwrap();
    assert_codex_user_settings(&fixture.status(), "missing");
}

#[test]
fn hooks_status_marks_unavailable_codex_toml_before_inspection() {
    let fixture = Fixture::new();
    let path = fixture.home.join(".codex/config.toml");
    fixture.write(&path, b"");
    fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .unwrap()
        .set_len(1024 * 1024 + 1)
        .unwrap();
    assert_codex_user_settings(&fixture.status(), "unavailable");
    fs::remove_file(&path).unwrap();
    fs::create_dir(path).unwrap();
    assert_codex_user_settings(&fixture.status(), "unavailable");
}
