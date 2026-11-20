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
use telltale_core::hooks::config::RuleContent;
use telltale_core::hooks::engine::Engine;

/// One character of each class the YAML reader refuses: C0, the escape that
/// starts a terminal sequence, DEL, C1 and the non-characters.
const REFUSED: [char; 6] = ['\x01', '\x1b', '\x7f', '\u{9f}', '\u{fffe}', '\u{ffff}'];

/// Denied by a bundled rule, whatever the paths are.
const DENIED: &str = "rm -f ~/.claude/settings.json";

/// Where the paths come from: environment variables, and the config roots
/// passed with `--config-dir` (none: the default roots).
struct Source {
    env: Vec<(&'static str, PathBuf)>,
    roots: Vec<PathBuf>,
}

/// `env`, with the enforcing test config root.
fn env(env: Vec<(&'static str, PathBuf)>) -> Source {
    Source {
        env,
        roots: vec![common::enforce_config()],
    }
}

/// The binary running `args` with safe paths everywhere but `source`, on every
/// platform.
fn binary(base: &Path, source: &Source, args: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_telltale"));
    command.arg("hooks").args(args);
    for root in &source.roots {
        command.arg("--config-dir").arg(root);
    }
    for var in [
        "XDG_CONFIG_HOME",
        "XDG_STATE_HOME",
        "XDG_RUNTIME_DIR",
        "TELLTALE_HOOKS_STATE_DIR",
        "TELLTALE_HOOKS_TELEMETRY",
    ] {
        command.env_remove(var);
    }
    for var in ["HOME", "APPDATA", "LOCALAPPDATA"] {
        command.env(var, base.join("home"));
    }
    command.env("TELLTALE_HOOKS_EVALUATOR", "0");
    command.envs(source.env.iter().map(|(name, value)| (name, value)));
    command
}

fn check(base: &Path, source: &Source) -> std::process::Output {
    binary(base, source, &["check"]).output().unwrap()
}

/// The verdict and reason for a Bash call; no verdict means the call is allowed.
fn hook(base: &Path, source: &Source, command: &str) -> (Option<String>, String) {
    let (verdict, reason, _) = hook_with_stderr(base, source, command);
    (verdict, reason)
}

/// [`hook`], and what the hook wrote to stderr.
fn hook_with_stderr(
    base: &Path,
    source: &Source,
    command: &str,
) -> (Option<String>, String, String) {
    let mut payload = common::template("PreToolUse", Some("Bash"));
    payload["tool_use_id"] = "toolu_generated".into();
    payload["tool_input"] = json!({"command": command});
    let mut child = binary(base, source, &["claude-code", "hook"])
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
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    if stdout.trim().is_empty() {
        return (None, String::new(), stderr);
    }
    let output: Value = serde_json::from_str(stdout.trim()).unwrap();
    let decision = &output["hookSpecificOutput"];
    (
        decision["permissionDecision"].as_str().map(str::to_owned),
        decision["permissionDecisionReason"]
            .as_str()
            .unwrap_or_default()
            .to_owned(),
        stderr,
    )
}

/// `path` as a YAML double-quoted string, where control characters must be
/// escaped.
fn yaml_string(path: &Path) -> String {
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

/// An enforcing settings file in config root `root`, with more of the `hooks:`
/// section in `hooks`.
fn write_settings(root: &Path, hooks: &str) {
    let settings = root.join("settings.d");
    std::fs::create_dir_all(&settings).unwrap();
    std::fs::write(
        settings.join("hooks.yaml"),
        format!("version: 1\nhooks:\n  mode: enforce\n{hooks}"),
    )
    .unwrap();
}

/// A config root at a safe path, with more of the `hooks:` section in `hooks`.
fn config(base: &Path, hooks: &str) -> Source {
    let root = base.join("config");
    write_settings(&root, hooks);
    Source {
        env: Vec::new(),
        roots: vec![root],
    }
}

/// With every refused character in the value of one source, `check` builds the
/// pipeline and a call a rule denies is still denied. `source` gets a safe base
/// directory and a directory named with the character. Failures are collected, so
/// a run names every character that failed.
fn assert_keeps_enforcing(name: &str, source: impl Fn(&Path, &Path) -> Source) {
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
        let source = source(dir.path(), &value);
        let check = check(dir.path(), &source);
        if !check.status.success() {
            let stderr = String::from_utf8_lossy(&check.stderr);
            let code = stderr.split(':').nth(1).unwrap_or_default().trim();
            failures.push(format!("{name} {c:?}: check failed ({code})"));
        }
        let (verdict, _) = hook(dir.path(), &source, DENIED);
        if verdict.as_deref() != Some("deny") {
            failures.push(format!("{name} {c:?}: verdict {verdict:?}, expected deny"));
        }
    }
    assert!(failures.is_empty(), "\n{}", failures.join("\n"));
}

/// The default user config root, under `HOME`, enforcing.
#[cfg(not(windows))]
#[test]
fn home_keeps_enforcing() {
    assert_keeps_enforcing("HOME", |_, value| {
        write_settings(&value.join(".config").join("telltale"), "");
        Source {
            env: vec![("HOME", value.to_owned())],
            roots: Vec::new(),
        }
    });
}

/// The default user config root, under `XDG_CONFIG_HOME`, enforcing.
#[cfg(not(windows))]
#[test]
fn xdg_config_home_keeps_enforcing() {
    assert_keeps_enforcing("XDG_CONFIG_HOME", |_, value| {
        write_settings(&value.join("telltale"), "");
        Source {
            env: vec![("XDG_CONFIG_HOME", value.to_owned())],
            roots: Vec::new(),
        }
    });
}

#[cfg(not(windows))]
#[test]
fn xdg_state_home_keeps_enforcing() {
    assert_keeps_enforcing("XDG_STATE_HOME", |_, value| {
        env(vec![("XDG_STATE_HOME", value.to_owned())])
    });
}

/// The socket moves under `XDG_RUNTIME_DIR` when the state dir is too long for it.
#[cfg(not(windows))]
#[test]
fn xdg_runtime_dir_keeps_enforcing() {
    assert_keeps_enforcing("XDG_RUNTIME_DIR", |base, value| {
        env(vec![
            ("XDG_RUNTIME_DIR", value.to_owned()),
            ("TELLTALE_HOOKS_STATE_DIR", base.join("d".repeat(120))),
        ])
    });
}

#[cfg(windows)]
#[test]
fn localappdata_keeps_enforcing() {
    assert_keeps_enforcing("LOCALAPPDATA", |_, value| {
        env(vec![("LOCALAPPDATA", value.to_owned())])
    });
}

#[test]
fn telltale_hooks_state_dir_keeps_enforcing() {
    assert_keeps_enforcing("TELLTALE_HOOKS_STATE_DIR", |_, value| {
        env(vec![("TELLTALE_HOOKS_STATE_DIR", value.to_owned())])
    });
}

#[test]
fn telltale_hooks_telemetry_keeps_enforcing() {
    assert_keeps_enforcing("TELLTALE_HOOKS_TELEMETRY", |_, value| {
        env(vec![(
            "TELLTALE_HOOKS_TELEMETRY",
            value.join("telemetry.jsonl"),
        )])
    });
}

/// A config root named with `--config-dir`, and its settings file.
#[test]
fn config_dir_keeps_enforcing() {
    assert_keeps_enforcing("--config-dir", |_, value| {
        write_settings(value, "");
        Source {
            env: Vec::new(),
            roots: vec![value.to_owned()],
        }
    });
}

#[test]
fn settings_state_dir_keeps_enforcing() {
    assert_keeps_enforcing("hooks.state_dir", |base, value| {
        config(base, &format!("  state_dir: {}\n", yaml_string(value)))
    });
}

#[test]
fn settings_telemetry_path_keeps_enforcing() {
    assert_keeps_enforcing("hooks.telemetry_path", |base, value| {
        let path = yaml_string(&value.join("telemetry.jsonl"));
        config(base, &format!("  telemetry_path: {path}\n"))
    });
}

/// Only Unix has an evaluator socket among the protected paths.
#[cfg(unix)]
#[test]
fn settings_evaluator_socket_keeps_enforcing() {
    assert_keeps_enforcing("hooks.evaluator.socket", |base, value| {
        let path = yaml_string(&value.join("evaluator.sock"));
        config(base, &format!("  evaluator:\n    socket: {path}\n"))
    });
}

/// A rule file's path is protected too. Before the fix this one was an `ask`, not
/// an allow, because an operator file was configured; the build failed the same way.
#[test]
fn rule_file_path_keeps_enforcing() {
    assert_keeps_enforcing("rules.d file", |_, value| {
        write_settings(value, "");
        let rules = value.join("rules.d");
        std::fs::create_dir_all(&rules).unwrap();
        std::fs::copy(common::marker_rules(), rules.join("markers.yaml")).unwrap();
        Source {
            env: Vec::new(),
            roots: vec![value.to_owned()],
        }
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
    let built = Engine::new(&RuleContent::default(), &[path]);
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
        let source = env(vec![("TELLTALE_HOOKS_STATE_DIR", value.clone())]);
        let check = check(dir.path(), &source);
        let command = format!("rm -rf {}", value.join("journal").display());
        let (verdict, reason) = hook(dir.path(), &source, &command);
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
    let mut source = config(dir.path(), "");
    let rules = source.roots[0].join("rules.d");
    std::fs::create_dir_all(&rules).unwrap();
    std::fs::write(
        rules.join("broken.yaml"),
        "version: 1\nrules: [ { id: x, regex: '(' } ]\n",
    )
    .unwrap();
    source
        .env
        .push(("TELLTALE_HOOKS_STATE_DIR", dir.path().join("state")));

    let (verdict, reason) = hook(dir.path(), &source, "ls");
    assert_eq!(verdict.as_deref(), Some("ask"), "{reason}");
    assert!(reason.contains("the rules did not build"), "{reason}");
    assert!(reason.contains("`telltale hooks check`"), "{reason}");
    let base = dir.path().file_name().unwrap().to_string_lossy();
    assert!(!reason.contains(&*base), "{reason}");

    let check = check(dir.path(), &source);
    assert!(!check.status.success());
    let stderr = String::from_utf8_lossy(&check.stderr);
    assert!(stderr.contains("pipeline_build_failed"), "{stderr}");
}

// ---- No state directory

/// A config root that enforces with more of the `hooks:` section in `hooks`, and an
/// environment where no state directory resolves: `HOME` and `LOCALAPPDATA` are empty
/// and nothing else names one. An agent can launch its harness that way. The
/// temporary directory is `temp`; with `telemetry`, records go to that file.
fn no_state_dir(base: &Path, hooks: &str, temp: &Path, telemetry: Option<&Path>) -> Source {
    let mut source = config(base, hooks);
    for var in ["HOME", "LOCALAPPDATA"] {
        source.env.push((var, PathBuf::new()));
    }
    for var in ["TMPDIR", "TEMP", "TMP"] {
        source.env.push((var, temp.to_owned()));
    }
    if let Some(path) = telemetry {
        source
            .env
            .push(("TELLTALE_HOOKS_TELEMETRY", path.to_owned()));
    }
    source
}

fn records(telemetry: &Path, kind: &str) -> Vec<Value> {
    std::fs::read_to_string(telemetry)
        .unwrap_or_default()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .filter(|record| record["kind"] == kind)
        .collect()
}

/// The two policies a hook is tested under, as `hooks:` lines, with what a call
/// that cannot be evaluated gets under each.
const POLICIES: [(&str, &str, Option<&str>); 2] = [
    ("default", "", Some("ask")),
    ("fail-open", "  on_unevaluable: allow\n", None),
];

/// With no state directory the call is still evaluated, alone, in a fresh
/// owner-only directory under the temporary directory, which is removed
/// afterwards. A rule's deny stays a deny under every policy, and a clean call
/// gets the stricter of `on_error` and `on_unevaluable`: it was evaluated without
/// its session's history. Before, both were allowed with no record.
#[cfg(unix)]
#[test]
fn with_no_state_directory_a_rule_deny_stays_a_deny() {
    for (policy, hooks, clean) in POLICIES {
        let dir = tempfile::tempdir().unwrap();
        let temp = dir.path().join("tmp");
        std::fs::create_dir(&temp).unwrap();
        let telemetry = dir.path().join("records").join("telemetry.jsonl");
        let source = no_state_dir(dir.path(), hooks, &temp, Some(&telemetry));
        assert!(!check(dir.path(), &source).status.success(), "{policy}");

        let (verdict, reason, stderr) = hook_with_stderr(dir.path(), &source, DENIED);
        assert_eq!(
            verdict.as_deref(),
            Some("deny"),
            "{policy}: {reason} {stderr}"
        );
        assert!(reason.contains("tth.tamper."), "{policy}: {reason}");
        let (verdict, reason, stderr) = hook_with_stderr(dir.path(), &source, "ls");
        assert_eq!(verdict.as_deref(), clean, "{policy}: {reason} {stderr}");
        if clean.is_some() {
            assert!(reason.contains("no state directory"), "{policy}: {reason}");
        }
        // Nothing is left under the temporary directory.
        let left: Vec<_> = std::fs::read_dir(&temp).unwrap().collect();
        assert!(left.is_empty(), "{policy}: {left:?}");

        // Both calls are recorded, and the records say why.
        let decisions = records(&telemetry, "decision");
        assert_eq!(decisions.len(), 2, "{policy}: {decisions:#?}");
        for record in &decisions {
            let limits = record["evaluation"]["visibility_limits"].to_string();
            assert!(
                limits.contains("state_dir_unresolved"),
                "{policy}: {record:#}"
            );
        }
        assert_eq!(decisions[0]["decision"]["verdict"], "deny", "{policy}");
        assert_eq!(
            decisions[0]["decision"]["basis"], "action_score",
            "{policy}"
        );
        let (verdict, basis) = match clean {
            Some(_) => ("ask", "evaluation_gap"),
            None => ("allow", "no_finding"),
        };
        assert_eq!(decisions[1]["decision"]["verdict"], verdict, "{policy}");
        assert_eq!(decisions[1]["decision"]["basis"], basis, "{policy}");
    }
}

/// With no state directory and no telemetry path, the decision cannot be
/// recorded anywhere: one line on stderr says so, and what was decided.
#[cfg(unix)]
#[test]
fn with_no_state_directory_and_no_record_location_stderr_says_so() {
    let dir = tempfile::tempdir().unwrap();
    let temp = dir.path().join("tmp");
    std::fs::create_dir(&temp).unwrap();
    let source = no_state_dir(dir.path(), "", &temp, None);
    for (command, verdict) in [(DENIED, "deny"), ("ls", "ask")] {
        let (returned, _, stderr) = hook_with_stderr(dir.path(), &source, command);
        assert_eq!(returned.as_deref(), Some(verdict), "{stderr}");
        let lines: Vec<&str> = stderr.lines().collect();
        assert_eq!(lines.len(), 1, "{stderr}");
        assert!(lines[0].contains("no state directory"), "{stderr}");
        assert!(lines[0].contains(verdict), "{stderr}");
    }
}

/// Where no fresh temporary directory can be made (here: the temporary directory
/// does not exist; on Windows always, see `ScratchDir`), the call is not
/// evaluated and gets the stricter of `on_error` and `on_unevaluable`, a rule's
/// deny included. Never a silent allow by default, and never unrecorded: an
/// `error` record, or a line on stderr when there is nowhere to write one.
#[test]
fn with_no_state_directory_and_no_temporary_directory_the_strict_policy_applies() {
    for (policy, hooks, strict) in POLICIES {
        let dir = tempfile::tempdir().unwrap();
        let temp = dir.path().join("missing");
        let telemetry = dir.path().join("records").join("telemetry.jsonl");
        let source = no_state_dir(dir.path(), hooks, &temp, Some(&telemetry));
        for command in [DENIED, "ls"] {
            let (verdict, reason, stderr) = hook_with_stderr(dir.path(), &source, command);
            assert_eq!(verdict.as_deref(), strict, "{policy}: {reason} {stderr}");
        }
        let errors = records(&telemetry, "error");
        assert_eq!(errors.len(), 2, "{policy}: {errors:#?}");
        for record in &errors {
            assert_eq!(record["error_code"], "state_dir_unresolved", "{policy}");
        }
        assert!(!temp.exists(), "{policy}");

        let source = no_state_dir(dir.path(), hooks, &temp, None);
        let (verdict, _, stderr) = hook_with_stderr(dir.path(), &source, DENIED);
        assert_eq!(verdict.as_deref(), strict, "{policy}");
        let lines: Vec<&str> = stderr.lines().collect();
        assert_eq!(lines.len(), 1, "{policy}: {stderr}");
        assert!(
            lines[0].contains("state_dir_unresolved"),
            "{policy}: {stderr}"
        );
    }
}

// ---- A long state directory under the home

/// A state directory `length` bytes below the home, in nested 19-byte names.
fn below_home(length: usize) -> String {
    let mut rest = String::from("s_");
    while rest.len() < length {
        rest.push_str("/dddddddddddddddddd");
    }
    rest.truncate(length);
    rest.trim_end_matches('/').to_owned()
}

/// A state directory under the home is also written from it (`~/...`,
/// `$HOME/...`). Past what one rule holds, that spelling is matched by its last
/// bytes like the literal path, and `check` lists it. It used to be dropped
/// silently once it no longer fit one rule, so a write through `~/` went
/// unmatched for lengths about one home path wide.
#[cfg(not(windows))]
#[test]
fn a_long_state_dir_under_the_home_is_covered_in_every_spelling() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    let failures = std::sync::Mutex::new(Vec::new());
    let lengths: Vec<usize> = (100..=420).step_by(8).collect();
    std::thread::scope(|scope| {
        for chunk in lengths.chunks(lengths.len().div_ceil(8)) {
            let (dir, home, failures) = (&dir, &home, &failures);
            scope.spawn(move || {
                for &length in chunk {
                    let rest = below_home(length);
                    let state = home.join(&rest);
                    let source = env(vec![("TELLTALE_HOOKS_STATE_DIR", state.clone())]);
                    for command in [
                        format!("rm -f ~/{rest}/x"),
                        format!("rm -f $HOME/{rest}/x"),
                        format!("rm -f {}/x", state.display()),
                    ] {
                        let (verdict, reason) = hook(dir.path(), &source, &command);
                        if verdict.as_deref() != Some("deny") {
                            let spelling = &command[..8];
                            failures
                                .lock()
                                .unwrap()
                                .push(format!("{length} bytes, {spelling}: {verdict:?} {reason}"));
                        }
                    }
                }
            });
        }
    });
    let failures = failures.into_inner().unwrap();
    assert!(failures.is_empty(), "\n{}", failures.join("\n"));

    let rest = below_home(420);
    let source = env(vec![("TELLTALE_HOOKS_STATE_DIR", home.join(&rest))]);
    let check = check(dir.path(), &source);
    let stdout = String::from_utf8_lossy(&check.stdout);
    assert!(
        stdout
            .lines()
            .any(|line| line.contains("matched by its last bytes") && line.contains("\"~/s_")),
        "{stdout}"
    );
}
