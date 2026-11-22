//! The user config root a hook reads is pinned in the hook command that
//! `telltale hooks <harness> settings` prints, so the environment a harness is
//! launched with cannot move it. Without the pin, a user-level install found its
//! settings through `HOME` or `XDG_CONFIG_HOME`; a harness started with either
//! changed, emptied or removed read no settings at all and was detect-only on
//! the defaults, with no record. These tests generate the settings, then run
//! the printed hook command through `sh` as a harness does. Tool-call commands
//! are data on the hook's stdin; nothing ever runs them.

#![cfg(unix)]

use crate::hooks_common as common;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde_json::{Value, json};

/// Denied by a bundled rule, whatever the configuration adds.
const DENIED: &str = "rm -f ~/.claude/settings.json";

/// A test home whose user config root enforces, and the paths around it.
struct Install {
    base: tempfile::TempDir,
}

impl Install {
    /// An install whose user config root sets `hooks.mode: <mode>`, or none.
    fn new(mode: Option<&str>) -> Self {
        let install = Install {
            base: tempfile::tempdir().unwrap(),
        };
        std::fs::create_dir_all(install.home()).unwrap();
        if let Some(mode) = mode {
            let settings = install.user_root().join("settings.d");
            std::fs::create_dir_all(&settings).unwrap();
            std::fs::write(
                settings.join("hooks.yaml"),
                format!("version: 1\nhooks:\n  mode: {mode}\n"),
            )
            .unwrap();
        }
        install
    }

    /// A path with a space and a quote, which the printed command must quote.
    fn home(&self) -> PathBuf {
        self.base.path().join("it's my home")
    }

    fn user_root(&self) -> PathBuf {
        self.home().join(".config").join("telltale")
    }

    /// The records file of the hook command `settings` prints: the one in
    /// the state directory it pins.
    fn telemetry(&self) -> PathBuf {
        self.base.path().join("state").join("telemetry.jsonl")
    }

    /// The process environment of the install, as the operator ran `settings`.
    fn environment(&self, command: &mut Command) {
        command
            .env_remove("XDG_CONFIG_HOME")
            .env("HOME", self.home())
            .env("TELLTALE_HOOKS_STATE_DIR", self.base.path().join("state"))
            .env(
                "TELLTALE_HOOKS_TELEMETRY",
                self.base.path().join("telemetry.jsonl"),
            )
            .env("TELLTALE_HOOKS_EVALUATOR", "0");
    }

    /// The PreToolUse hook command that `claude-code settings` prints, and
    /// its stderr.
    fn generated_command(&self) -> (String, String) {
        let binary = env!("CARGO_BIN_EXE_telltale");
        let mut settings = Command::new(binary);
        settings.args([
            "hooks",
            "claude-code",
            "settings",
            &format!("'{binary}' hooks claude-code hook"),
        ]);
        self.environment(&mut settings);
        let out = settings.output().unwrap();
        assert!(out.status.success(), "{out:?}");
        let document: Value = serde_json::from_slice(&out.stdout).unwrap();
        let command = document["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
            .as_str()
            .unwrap()
            .to_owned();
        (command, String::from_utf8_lossy(&out.stderr).into_owned())
    }

    /// Run the hook `command` through `sh -c` with a Bash call to `DENIED`,
    /// after `launch` changed the environment. The verdict (none means the
    /// call runs) and the hook's stderr.
    fn run(&self, command: &str, launch: impl Fn(&mut Command)) -> (Option<String>, String) {
        let (verdict, stderr, _) = self.run_call(command, DENIED, launch);
        (verdict, stderr)
    }

    /// [`Install::run`] for a Bash call to `call`, with the exit status.
    fn run_call(
        &self,
        command: &str,
        call: &str,
        launch: impl Fn(&mut Command),
    ) -> (Option<String>, String, Option<i32>) {
        let mut payload = common::template("PreToolUse", Some("Bash"));
        payload["tool_use_id"] = "toolu_pinned".into();
        payload["tool_input"] = json!({"command": call});
        self.send(command, &payload, launch)
    }

    /// Send `payload` to the hook `command` through `sh -c`, after `launch`
    /// changed the environment: the verdict, stderr and exit status.
    fn send(
        &self,
        command: &str,
        payload: &Value,
        launch: impl Fn(&mut Command),
    ) -> (Option<String>, String, Option<i32>) {
        let mut hook = Command::new("sh");
        hook.arg("-c").arg(command);
        self.environment(&mut hook);
        launch(&mut hook);
        let mut child = hook
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(&serde_json::to_vec(payload).unwrap())
            .unwrap();
        let out = child.wait_with_output().unwrap();
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        let stdout = String::from_utf8_lossy(&out.stdout);
        if stdout.trim().is_empty() {
            return (None, stderr, out.status.code());
        }
        let output: Value = serde_json::from_str(stdout.trim()).unwrap();
        let verdict = output["hookSpecificOutput"]["permissionDecision"]
            .as_str()
            .map(str::to_owned);
        (verdict, stderr, out.status.code())
    }
}

/// A change a launch makes to the hook's environment.
type Launch = Box<dyn Fn(&mut Command)>;

/// The ways a launch can move the user config root away from the install.
fn launches(other: &Path) -> Vec<(&'static str, Launch)> {
    let other = other.to_owned();
    let other_home = other.clone();
    vec![
        ("unchanged", Box::new(|_: &mut Command| {})),
        (
            "HOME changed",
            Box::new(move |c: &mut Command| {
                c.env("HOME", &other_home);
            }),
        ),
        (
            "XDG_CONFIG_HOME set",
            Box::new(move |c: &mut Command| {
                c.env("XDG_CONFIG_HOME", &other);
            }),
        ),
        (
            "HOME emptied",
            Box::new(|c: &mut Command| {
                c.env("HOME", "");
            }),
        ),
        (
            "HOME removed",
            Box::new(|c: &mut Command| {
                c.env_remove("HOME");
            }),
        ),
    ]
}

/// An enforcing user-level install keeps denying a rule-denied call however
/// the launch changes `HOME` or `XDG_CONFIG_HOME`.
#[test]
fn an_enforcing_user_install_keeps_enforcing_when_the_environment_moves() {
    let install = Install::new(Some("enforce"));
    let (command, _) = install.generated_command();
    let other = install.base.path().join("elsewhere");
    std::fs::create_dir_all(&other).unwrap();
    let mut failures = Vec::new();
    for (launch, change) in launches(&other) {
        let (verdict, stderr) = install.run(&command, change);
        if verdict.as_deref() != Some("deny") {
            failures.push(format!("{launch}: verdict {verdict:?}\n{stderr}"));
        }
    }
    assert!(failures.is_empty(), "{command}\n{}", failures.join("\n"));
}

/// An enforcing install's command carries `--expect-enforce`, so with its
/// pinned root gone the configuration that does not load still enforces: a
/// call a rule denies and a clean call are both denied as misconfigured.
#[test]
fn an_enforcing_install_whose_pinned_root_is_gone_denies_every_call() {
    let install = Install::new(Some("enforce"));
    let (command, stderr) = install.generated_command();
    assert!(command.ends_with(" --expect-enforce"), "{command}");
    assert!(stderr.contains("carries --expect-enforce"), "{stderr}");
    std::fs::remove_dir_all(install.user_root()).unwrap();
    for call in [DENIED, "ls"] {
        let (verdict, stderr, _) = install.run_call(&command, call, |_| {});
        assert_eq!(verdict.as_deref(), Some("deny"), "{call}: {stderr}");
        assert!(
            stderr.contains("pinned user config root"),
            "{call}: {stderr}"
        );
    }
    // Each denied call is recorded as a configuration that did not load.
    let telemetry = std::fs::read_to_string(install.telemetry()).unwrap_or_default();
    let codes: Vec<Value> = telemetry
        .lines()
        .map(|line| {
            let record: Value = serde_json::from_str(line).unwrap();
            assert!(crate::hooks_record_validator().is_valid(&record), "{line}");
            record["error_code"].clone()
        })
        .collect();
    assert_eq!(codes, [json!("config_invalid"), json!("config_invalid")]);
}

/// A session that starts with `XDG_CONFIG_HOME` naming another user root
/// names that variable, and nothing of its value, in its `session_start`
/// record. One that starts in the install's environment names nothing.
#[test]
fn a_session_start_names_the_config_variable_the_pin_replaced() {
    let install = Install::new(Some("observe"));
    let (command, _) = install.generated_command();
    assert!(command.contains("--user-config-dir"), "{command}");
    let other = install.base.path().join("elsewhere");
    let state = install.base.path().join("state");
    let payload = common::template("SessionStart", None);
    let moved = move |c: &mut Command| {
        c.env("XDG_CONFIG_HOME", &other)
            .env_remove("TELLTALE_HOOKS_TELEMETRY");
    };
    let (_, stderr, _) = install.send(&command, &payload, moved);
    let unchanged = |c: &mut Command| {
        c.env_remove("TELLTALE_HOOKS_TELEMETRY");
    };
    let (_, stderr_unchanged, _) = install.send(&command, &payload, unchanged);
    let telemetry = std::fs::read_to_string(state.join("telemetry.jsonl")).unwrap_or_default();
    let starts: Vec<Value> = telemetry
        .lines()
        .map(|line| {
            let record: Value = serde_json::from_str(line).unwrap();
            assert!(crate::hooks_record_validator().is_valid(&record), "{line}");
            record["lifecycle"].clone()
        })
        .collect();
    assert_eq!(
        starts,
        [
            json!({"event": "session_start", "source": "startup",
                   "pinned_over": ["XDG_CONFIG_HOME"]}),
            json!({"event": "session_start", "source": "startup"}),
        ],
        "{stderr}\n{stderr_unchanged}"
    );
    assert!(!telemetry.contains("elsewhere"), "{telemetry}");
}

/// Without `XDG_CONFIG_HOME`, `HOME` names the user root; a session that
/// starts with it naming another one names `HOME`.
#[test]
fn a_session_start_names_home_when_it_names_another_user_root() {
    let install = Install::new(Some("observe"));
    let (command, _) = install.generated_command();
    let other = install.base.path().join("other home");
    let launch = move |c: &mut Command| {
        c.env("HOME", &other).env_remove("TELLTALE_HOOKS_TELEMETRY");
    };
    let payload = common::template("SessionStart", None);
    let (_, stderr, _) = install.send(&command, &payload, launch);
    let telemetry = std::fs::read_to_string(install.telemetry()).unwrap_or_default();
    let record: Value = serde_json::from_str(telemetry.trim()).unwrap();
    assert_eq!(
        record["lifecycle"],
        json!({"event": "session_start", "source": "startup",
               "pinned_over": ["HOME"]}),
        "{stderr}"
    );
}

/// A detect-only install gets no marker. With its pinned root gone the hook
/// stays detect-only: nothing on stdout, exit 0, a `config_invalid` record.
#[test]
fn an_observing_install_whose_pinned_root_is_gone_records_and_never_blocks() {
    let install = Install::new(Some("observe"));
    let (command, stderr) = install.generated_command();
    assert!(command.contains("--user-config-dir"), "{command}");
    assert!(!command.contains("--expect-enforce"), "{command}");
    assert!(stderr.contains("no --expect-enforce"), "{stderr}");
    std::fs::remove_dir_all(install.user_root()).unwrap();
    let (verdict, stderr, code) = install.run_call(&command, DENIED, |_| {});
    assert_eq!((verdict, code), (None, Some(0)), "{stderr}");
    assert!(stderr.contains("did not load"), "{stderr}");
    let telemetry = std::fs::read_to_string(install.telemetry()).unwrap_or_default();
    assert!(
        telemetry.contains("\"error_code\":\"config_invalid\""),
        "{command}\ntelemetry: {telemetry}"
    );
}

/// The marker never enables enforcement for a configuration that loads.
#[test]
fn the_marker_enables_nothing_for_a_configuration_that_loads() {
    let install = Install::new(Some("observe"));
    let (command, _) = install.generated_command();
    let command = format!("{command} --expect-enforce");
    let (verdict, stderr, code) = install.run_call(&command, DENIED, |_| {});
    assert_eq!((verdict, code), (None, Some(0)), "{stderr}");
}

/// The marker asks for more than the configuration says, `--detect-only` for
/// less: together they are a usage error.
#[test]
fn the_marker_beside_detect_only_is_refused() {
    let out = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args([
            "hooks",
            "claude-code",
            "hook",
            "--expect-enforce",
            "--detect-only",
        ])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(64), "{out:?}");
}

/// With no user config root when `settings` runs, nothing depends on one: the
/// command is printed as given, stderr says the hook follows the environment,
/// and a call is not failed for a root that never existed.
#[test]
fn without_a_user_root_the_command_is_not_pinned() {
    let install = Install::new(None);
    let (command, stderr) = install.generated_command();
    assert!(!command.contains("--user-config-dir"), "{command}");
    assert!(stderr.contains("not pinned"), "{stderr}");
    let (verdict, stderr) = install.run(&command, |_| {});
    assert_eq!(verdict, None, "{stderr}");
    assert!(!stderr.contains("did not load"), "{stderr}");
}

/// `check` names the roots the hook reads and which one is pinned.
#[test]
fn check_shows_the_pinned_user_root() {
    let install = Install::new(Some("enforce"));
    let mut check = Command::new(env!("CARGO_BIN_EXE_telltale"));
    check
        .args(["hooks", "check", "--user-config-dir"])
        .arg(install.user_root());
    install.environment(&mut check);
    check.env("HOME", install.base.path());
    let out = check.output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{out:?}");
    assert!(
        stdout.contains(&format!(
            "config root: {} (user, pinned)",
            install.user_root().display()
        )),
        "{stdout}"
    );
    assert!(stdout.contains("mode: enforce"), "{stdout}");
}

/// The pin replaces only the user root, so it cannot be combined with
/// `--config-dir`, which replaces every root.
#[test]
fn a_pin_with_explicit_roots_is_refused() {
    let install = Install::new(Some("enforce"));
    let out = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args(["hooks", "check", "--config-dir"])
        .arg(install.user_root())
        .arg("--user-config-dir")
        .arg(install.user_root())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(64), "{out:?}");
}
