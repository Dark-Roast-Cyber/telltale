//! A path in the environment or the configuration reaches the generated
//! self-protection rules. A character the YAML reader refuses used to take the
//! whole rule document down, and the pipeline with it: `pipeline_build_failed`,
//! which with no operator files answered `on_error`, `allow` by default, so every
//! call went through. These tests drive the real binary: `check` for the build,
//! `claude-code hook` for the verdict. Commands are data on the hook's stdin;
//! nothing ever runs them.

use crate::hooks_common as common;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde_json::{Value, json};
use telltale_core::hooks::config::TelltaleSettings;
use telltale_core::hooks::engine::Engine;

/// One character of each class the YAML reader refuses: C0, the escape that
/// starts a terminal sequence, DEL, C1 and the non-characters.
const REFUSED: [char; 6] = ['\x01', '\x1b', '\x7f', '\u{9f}', '\u{fffe}', '\u{ffff}'];

/// Denied by a bundled rule, whatever the paths are.
const DENIED: &str = "rm -f ~/.claude/settings.json";

type Env = Vec<(&'static str, PathBuf)>;

/// The binary with safe paths everywhere but `env`, on every platform.
fn binary(base: &Path, env: &Env) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_telltale"));
    command.arg("hooks");
    for var in [
        "XDG_CONFIG_HOME",
        "XDG_STATE_HOME",
        "XDG_RUNTIME_DIR",
        "TELLTALE_HOOKS_CONFIG",
        "TELLTALE_HOOKS_STATE_DIR",
        "TELLTALE_HOOKS_TELEMETRY",
    ] {
        command.env_remove(var);
    }
    for var in ["HOME", "APPDATA", "LOCALAPPDATA"] {
        command.env(var, base.join("home"));
    }
    command.env("TELLTALE_HOOKS_EVALUATOR", "0");
    command.envs(env.iter().map(|(name, value)| (name, value)));
    command
}

/// The verdict and reason for a Bash call; no verdict means the call is allowed.
fn hook(base: &Path, env: &Env, command: &str) -> (Option<String>, String) {
    let mut payload = common::template("PreToolUse", Some("Bash"));
    payload["tool_use_id"] = "toolu_generated".into();
    payload["tool_input"] = json!({"command": command});
    let mut child = binary(base, env)
        .args(["claude-code", "hook"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&serde_json::to_vec(&payload).unwrap())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    if stdout.trim().is_empty() {
        return (None, String::new());
    }
    let output: Value = serde_json::from_str(stdout.trim()).unwrap();
    let decision = &output["hookSpecificOutput"];
    (
        decision["permissionDecision"].as_str().map(str::to_owned),
        decision["permissionDecisionReason"]
            .as_str()
            .unwrap_or_default()
            .to_owned(),
    )
}

/// `path` as a TOML basic string, where control characters must be escaped.
fn toml_string(path: &Path) -> String {
    let mut text = String::from("\"");
    for c in path.to_str().unwrap().chars() {
        match c {
            '"' | '\\' => text.extend(['\\', c]),
            ' '..='~' => text.push(c),
            _ => text.push_str(&format!("\\U{:08X}", c as u32)),
        }
    }
    text.push('"');
    text
}

/// A config file at a safe path holding `toml`, as the environment of a source.
fn config(base: &Path, toml: &str) -> Env {
    let path = base.join("config.toml");
    std::fs::write(&path, toml).unwrap();
    vec![("TELLTALE_HOOKS_CONFIG", path)]
}

/// With every refused character in the value of one source, `check` builds the
/// pipeline and a call a rule denies is still denied. `source` gets a safe base
/// directory and a directory named with the character. Failures are collected, so
/// a run names every character that failed.
fn assert_keeps_enforcing(name: &str, source: impl Fn(&Path, &Path) -> Env) {
    let mut failures = Vec::new();
    for c in REFUSED {
        let dir = tempfile::tempdir().unwrap();
        let value = dir.path().join(format!("a{c}b"));
        // Windows refuses control characters in a name; the sweep below needs no
        // filesystem and still covers them there.
        if std::fs::create_dir_all(&value).is_err() {
            eprintln!("{name}: this filesystem refuses {c:?}");
            continue;
        }
        let env = source(dir.path(), &value);
        let check = binary(dir.path(), &env).arg("check").output().unwrap();
        if !check.status.success() {
            let stderr = String::from_utf8_lossy(&check.stderr);
            let code = stderr.split(':').nth(1).unwrap_or_default().trim();
            failures.push(format!("{name} {c:?}: check failed ({code})"));
        }
        let (verdict, _) = hook(dir.path(), &env, DENIED);
        if verdict.as_deref() != Some("deny") {
            failures.push(format!("{name} {c:?}: verdict {verdict:?}, expected deny"));
        }
    }
    assert!(failures.is_empty(), "\n{}", failures.join("\n"));
}

#[cfg(not(windows))]
#[test]
fn home_keeps_enforcing() {
    assert_keeps_enforcing("HOME", |_, value| vec![("HOME", value.to_owned())]);
}

#[cfg(not(windows))]
#[test]
fn xdg_config_home_keeps_enforcing() {
    assert_keeps_enforcing("XDG_CONFIG_HOME", |_, value| {
        vec![("XDG_CONFIG_HOME", value.to_owned())]
    });
}

#[cfg(not(windows))]
#[test]
fn xdg_state_home_keeps_enforcing() {
    assert_keeps_enforcing("XDG_STATE_HOME", |_, value| {
        vec![("XDG_STATE_HOME", value.to_owned())]
    });
}

/// The socket moves under `XDG_RUNTIME_DIR` when the state dir is too long for it.
#[cfg(not(windows))]
#[test]
fn xdg_runtime_dir_keeps_enforcing() {
    assert_keeps_enforcing("XDG_RUNTIME_DIR", |base, value| {
        vec![
            ("XDG_RUNTIME_DIR", value.to_owned()),
            ("TELLTALE_HOOKS_STATE_DIR", base.join("d".repeat(120))),
        ]
    });
}

#[cfg(windows)]
#[test]
fn appdata_keeps_enforcing() {
    assert_keeps_enforcing("APPDATA", |_, value| vec![("APPDATA", value.to_owned())]);
}

#[cfg(windows)]
#[test]
fn localappdata_keeps_enforcing() {
    assert_keeps_enforcing("LOCALAPPDATA", |_, value| {
        vec![("LOCALAPPDATA", value.to_owned())]
    });
}

#[test]
fn telltale_hooks_state_dir_keeps_enforcing() {
    assert_keeps_enforcing("TELLTALE_HOOKS_STATE_DIR", |_, value| {
        vec![("TELLTALE_HOOKS_STATE_DIR", value.to_owned())]
    });
}

#[test]
fn telltale_hooks_telemetry_keeps_enforcing() {
    assert_keeps_enforcing("TELLTALE_HOOKS_TELEMETRY", |_, value| {
        vec![("TELLTALE_HOOKS_TELEMETRY", value.join("telemetry.jsonl"))]
    });
}

#[test]
fn telltale_hooks_config_path_keeps_enforcing() {
    assert_keeps_enforcing("TELLTALE_HOOKS_CONFIG", |_, value| {
        let path = value.join("config.toml");
        std::fs::write(&path, "mode = \"enforce\"\n").unwrap();
        vec![("TELLTALE_HOOKS_CONFIG", path)]
    });
}

#[test]
fn toml_state_dir_keeps_enforcing() {
    assert_keeps_enforcing("TOML state_dir", |base, value| {
        config(base, &format!("state_dir = {}\n", toml_string(value)))
    });
}

#[test]
fn toml_telemetry_path_keeps_enforcing() {
    assert_keeps_enforcing("TOML telemetry_path", |base, value| {
        let path = toml_string(&value.join("telemetry.jsonl"));
        config(base, &format!("telemetry_path = {path}\n"))
    });
}

/// Only Unix has an evaluator socket among the protected paths.
#[cfg(unix)]
#[test]
fn toml_evaluator_socket_keeps_enforcing() {
    assert_keeps_enforcing("TOML [evaluator] socket", |base, value| {
        let path = toml_string(&value.join("evaluator.sock"));
        config(base, &format!("[evaluator]\nsocket = {path}\n"))
    });
}

/// A rule file's path is protected too. Before the fix this one was an `ask`, not
/// an allow, because an operator file was configured; the build failed the same way.
#[test]
fn toml_rule_file_path_keeps_enforcing() {
    assert_keeps_enforcing("TOML [telltale] rules", |base, value| {
        let path = value.join("rules.yaml");
        std::fs::copy(common::marker_rules(), &path).unwrap();
        let toml = format!("[telltale]\nrules = [{}]\n", toml_string(&path));
        config(base, &toml)
    });
}

/// Every character the YAML reader refuses, by the ranges it accepts
/// (`libyaml-rs` `reader.rs`), through one real pipeline build. No filesystem
/// is involved, so this holds where a name cannot carry them.
#[test]
fn every_character_yaml_refuses_builds_a_real_pipeline() {
    let accepted = |c: u32| {
        matches!(c,
            0x9 | 0xa | 0xd | 0x20..=0x7e | 0x85 | 0xa0..=0xd7ff | 0xe000..=0xfffd | 0x1_0000..=0x10_ffff)
    };
    let refused: String = (0..=0x10_ffff)
        .filter(|c| !accepted(*c))
        .filter_map(char::from_u32)
        .collect();
    assert_eq!(refused.chars().count(), 63);
    let path = PathBuf::from(format!("/srv/{refused}"));
    let built = Engine::new(&TelltaleSettings::default(), &[path]);
    assert!(
        built.is_ok(),
        "{:?}",
        built.err().map(|error| error.to_string())
    );
}

/// Building is not enough: the generated rule must still mean that path. Line
/// breaks are characters YAML accepts and then folds into a space, which used to
/// leave a rule that builds and never matches. The rest of this list reaches the
/// regex unchanged with today's parser, or is a line break in another YAML version.
#[test]
fn the_generated_rule_still_matches_a_path_holding_such_a_character() {
    let also = ['\t', '\n', '\u{85}', '\u{2028}', '\u{2029}', '\u{feff}'];
    let mut failures = Vec::new();
    for c in REFUSED.into_iter().chain(also) {
        let dir = tempfile::tempdir().unwrap();
        let value = dir.path().join(format!("a{c}b"));
        if std::fs::create_dir_all(&value).is_err() {
            eprintln!("this filesystem refuses {c:?}");
            continue;
        }
        let env = vec![("TELLTALE_HOOKS_STATE_DIR", value.clone())];
        let check = binary(dir.path(), &env).arg("check").output().unwrap();
        let command = format!("rm -rf {}", value.join("journal").display());
        let (verdict, reason) = hook(dir.path(), &env, &command);
        if !check.status.success()
            || verdict.as_deref() != Some("deny")
            || !reason.contains("tth.tamper.own_state_command")
        {
            let built = check.status.success();
            failures.push(format!(
                "{c:?}: check passed {built}, verdict {verdict:?}, reason {reason:?}"
            ));
        }
    }
    assert!(failures.is_empty(), "\n{}", failures.join("\n"));
}

/// What the reason promises, through the binary. A broken rule file is the way to
/// fail a build from outside; `runtime.rs` tests the same with no operator files.
#[test]
fn a_build_failure_names_check_and_no_environment_value() {
    let dir = tempfile::tempdir().unwrap();
    let broken = dir.path().join("broken.yaml");
    std::fs::write(&broken, "version: 1\nrules: [ { id: x, regex: '(' } ]\n").unwrap();
    let toml = format!("[telltale]\nrules = [{}]\n", toml_string(&broken));
    let mut env = config(dir.path(), &toml);
    env.push(("TELLTALE_HOOKS_STATE_DIR", dir.path().join("state")));

    let (verdict, reason) = hook(dir.path(), &env, "ls");
    assert_eq!(verdict.as_deref(), Some("ask"), "{reason}");
    assert!(reason.contains("the rules did not build"), "{reason}");
    assert!(reason.contains("`telltale hooks check`"), "{reason}");
    let base = dir.path().file_name().unwrap().to_string_lossy();
    assert!(!reason.contains(&*base), "{reason}");

    let check = binary(dir.path(), &env).arg("check").output().unwrap();
    assert!(!check.status.success());
    let stderr = String::from_utf8_lossy(&check.stderr);
    assert!(stderr.contains("pipeline_build_failed"), "{stderr}");
}
