//! `telltale hooks`: pre-execution hooks for agent harnesses.
//!
//! The runtime, adapters and evaluator live in `telltale_core::hooks`; this
//! module is the process boundary: it reads one hook payload from stdin and
//! answers on stdout and with its exit code. A hook invocation is dispatched
//! before the rest of the CLI starts (`run` checks for it first), so a tool
//! call never waits for the scanner's startup work, and the exit codes below
//! are the hooks' own rather than the CLI's.

#[cfg(unix)]
use std::ffi::OsString;
use std::io::{Read, Write};
use std::path::PathBuf;

use telltale_core::hooks::config::{Config, OnError, RuleContent};
use telltale_core::hooks::engine::Engine;
use telltale_core::hooks::evaluator;
#[cfg(unix)]
use telltale_core::hooks::evaluator::ClientOutcome;
use telltale_core::hooks::gate::{Answer, DETECT_ONLY_DEADLINE, Gate};
use telltale_core::hooks::harness::{Harness, NamelessBlock, Parsed, names_event};
use telltale_core::hooks::harnesses::codex_cli;
use telltale_core::hooks::identity;
use telltale_core::hooks::runtime::{Context, Event, Runtime};

/// Hook payloads larger than this are refused rather than buffered.
const MAX_PAYLOAD_BYTES: u64 = 32 * 1024 * 1024;

/// The usage text: each registered harness's `hook` and `settings` lines
/// (`Adapter::install`), then the commands that belong to no adapter.
fn usage() -> String {
    let mut text = String::from("usage:\n");
    for harness in Harness::ALL {
        let adapter = harness.adapter();
        let hook = format!("  telltale hooks {} hook", adapter.name);
        text.push_str(&format!(
            "{hook:<50}handle one {} hook (stdin -> stdout)\n{}\n",
            adapter.display_name, adapter.install.usage
        ));
    }
    text.push_str(COMMON_USAGE);
    text
}

const COMMON_USAGE: &str = "  telltale hooks codex-cli execpolicy             print Codex exec-policy rules that refuse nested Codex
                                                  launches natively, even if the hook fails
  telltale hooks harnesses                        list the harnesses this build has an adapter for
  telltale hooks serve                            run the long-lived evaluator (normally autostarted;
                                                  Linux and macOS only, elsewhere hooks evaluate in-process)
  telltale hooks check                            validate config and build the Telltale pipeline
  telltale hooks version                          print the version, Git hash and build revision

hook, serve and check accept --config-dir DIR (repeatable): read these Telltale
config roots instead of the default ones (/etc/telltale, on Windows %ProgramData%\\telltale,
then $XDG_CONFIG_HOME/telltale or ~/.config/telltale). Settings are the hooks: section of settings.d/*.yaml; rule
content is the same rules.d, rule-packages.d, overrides.d and policies.d as scan.

environment:
  TELLTALE_HOOKS_STATE_DIR  per-session journals and state (hooks.state_dir), default:
                              Linux, macOS: $XDG_STATE_HOME/telltale/hooks or ~/.local/state/telltale/hooks
                              Windows:      %LOCALAPPDATA%\\telltale\\hooks
  TELLTALE_HOOKS_TELEMETRY  telemetry JSONL (hooks.telemetry_path, default <state dir>/telemetry.jsonl)
  TELLTALE_HOOKS_EVALUATOR  0 or 1: use the long-lived evaluator (hooks.evaluator.enabled)";

/// Run `telltale hooks <args>` and return the process exit status.
pub(crate) fn exit_code(args: &[String]) -> i32 {
    // Before anything reads the build identity: the CLI's Git hash.
    identity::set_host_build(env!("TELLTALE_GIT_HASH"));
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    match args.as_slice() {
        ["-h"] | ["--help"] | ["help"] => {
            println!("{}", usage());
            0
        }
        ["harnesses"] => {
            for harness in Harness::ALL {
                let adapter = harness.adapter();
                println!("{:<14}{}", adapter.name, adapter.display_name);
            }
            0
        }
        [name, "execpolicy"] if *name == codex_cli::HARNESS => {
            print!("{}", codex_cli::execpolicy_rules());
            0
        }
        [name, "settings", rest @ ..] => match Harness::from_name(name) {
            Some(harness) => print_settings(harness, rest),
            None => {
                eprintln!("{}", usage());
                64
            }
        },
        [name, "hook", flags @ ..] => match (Harness::from_name(name), config_dirs(flags)) {
            (Some(harness), Some(dirs)) => hook(harness, &dirs),
            _ => {
                eprintln!("{}", usage());
                64
            }
        },
        ["check", flags @ ..] => match config_dirs(flags) {
            Some(dirs) => check(&dirs),
            None => {
                eprintln!("{}", usage());
                64
            }
        },
        ["serve", flags @ ..] => match config_dirs(flags) {
            Some(dirs) => serve(&dirs),
            None => {
                eprintln!("{}", usage());
                64
            }
        },
        ["version"] | ["--version"] => {
            println!(
                "telltale hooks {} ({}), build revision {}",
                identity::PACKAGE_VERSION,
                identity::host_build(),
                identity::revision()
            );
            0
        }
        _ => {
            eprintln!("{}", usage());
            64
        }
    }
}

fn print_settings(harness: Harness, args: &[&str]) -> i32 {
    let (flags, positional): (Vec<&str>, Vec<&str>) =
        args.iter().copied().partition(|a| a.starts_with('-'));
    // A mistyped flag must not silently print a hook with weaker enforcement, or
    // become a hook command that can never run.
    if flags.iter().any(|flag| *flag != "--fail-closed") {
        eprintln!("{}", usage());
        return 64;
    }
    let fail_closed = !flags.is_empty();
    let default = format!("telltale hooks {} hook", harness.name());
    let command = match positional.as_slice() {
        [] => default.as_str(),
        [command] => command,
        _ => {
            eprintln!("{}", usage());
            return 64;
        }
    };
    // An adapter that cannot honor the request prints nothing and fails rather
    // than pretending. Install and trust notes go to stderr.
    let fragment = match (harness.adapter().install.output)(command, fail_closed) {
        Ok(output) => {
            if let Some(notes) = output.notes {
                eprintln!("{notes}");
            }
            output.document
        }
        Err(refusal) => {
            eprintln!("{refusal}");
            return 1;
        }
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&fragment).unwrap_or_default()
    );
    0
}

/// `--config-dir DIR` or `--config-dir=DIR`, repeated; `None` for anything else.
fn config_dirs(flags: &[&str]) -> Option<Vec<PathBuf>> {
    let mut dirs = Vec::new();
    let mut flags = flags.iter();
    while let Some(flag) = flags.next() {
        let dir = match flag.strip_prefix("--config-dir") {
            Some("") => *flags.next()?,
            Some(value) => value.strip_prefix('=')?,
            None => return None,
        };
        if dir.is_empty() {
            return None;
        }
        dirs.push(PathBuf::from(dir));
    }
    Some(dirs)
}

/// The folders of a config root that hooks read (src/config.rs discovery).
const HOOKS_CONFIG_FOLDERS: &[&str] = &[
    "settings.d",
    "organization-rules.d",
    "rules.d",
    "ui-rules.d",
    "rule-packages.d",
    "overrides.d",
    "policies.d",
];

/// The hooks configuration in `config_dirs` (or the default config roots):
/// the `hooks:` section of `settings.d` and the environment, and the same
/// rule content and rule settings as `scan`. An error is described for stderr
/// only, because it can name a path.
fn load_config(config_dirs: &[PathBuf]) -> Result<Config, String> {
    let settings =
        crate::settings::load(config_dirs, false, &crate::settings::CliSettings::default())
            .map_err(|error| error.to_string())?;
    let discovered = crate::config::discover_local_config_files(
        config_dirs,
        false,
        crate::config::LocalConfigDiscoveryKind::Rules,
    )
    .map_err(|error| error.to_string())?;
    let policy = crate::config::resolve_policy_path(None, &discovered.policy_paths)
        .map_err(|error| error.to_string())?;
    let mut config = settings.hooks.config();
    config.rules = RuleContent {
        packs: crate::rules::RulePackPaths {
            organization: discovered.organization_rule_paths,
            deployment: discovered.deployment_rule_paths,
            local: discovered.local_rule_paths,
            packages: discovered.rule_package_paths,
            community: super::community_rules(settings.community_rules.value),
        },
        overrides: discovered.override_paths,
        policy,
        process_chain: settings.process_chain.value,
        self_protection: settings.hooks.self_protection_rules.value,
    };
    let roots = crate::config::config_roots(config_dirs);
    // Discovery follows symlinks (dotfile managers link a root, a folder or a
    // file), so a link's target is protected too, including files added to a
    // linked folder later.
    let targets = roots
        .iter()
        .flat_map(|root| {
            std::iter::once(root.clone())
                .chain(HOOKS_CONFIG_FOLDERS.iter().map(|folder| root.join(folder)))
        })
        .chain(settings.files().iter().cloned())
        .chain(config.rules.files().cloned())
        .filter_map(|path| {
            telltale_core::hooks::config::plain_canonical(&path).filter(|target| {
                *target != path && telltale_core::hooks::config::names_below_root(target)
            })
        })
        .collect::<Vec<_>>();
    config.sources = roots;
    config.sources.extend(settings.files().iter().cloned());
    config.sources.extend(targets);
    config.validate().map_err(|error| error.to_string())?;
    config.make_paths_absolute();
    Ok(config)
}

/// Whether a settings file in `config_dirs` says `hooks.mode: enforce`, asked
/// only when the configuration did not load. Lenient on purpose: it reads
/// every `settings.d` file it can, skipping what it cannot, and as plain lines
/// when a file is not YAML. One such file is enough, so a broken file next to
/// one that enforces cannot turn enforcement off.
fn settings_declare_enforce(config_dirs: &[PathBuf]) -> bool {
    crate::config::config_roots(config_dirs).iter().any(|root| {
        let Ok(entries) = std::fs::read_dir(root.join("settings.d")) else {
            return false;
        };
        entries.flatten().any(|entry| {
            let path = entry.path();
            let yaml = path
                .extension()
                .is_some_and(|extension| extension == "yaml" || extension == "yml");
            yaml && telltale_core::hooks::state::read_operator_input(&path)
                .is_ok_and(|text| declares_enforce(&text))
        })
    })
}

/// Whether settings text sets `hooks.mode` to `enforce`.
fn declares_enforce(text: &str) -> bool {
    if let Ok(document) = serde_yaml::from_str::<serde_yaml::Value>(text) {
        return document
            .get("hooks")
            .and_then(|hooks| hooks.get("mode"))
            .and_then(serde_yaml::Value::as_str)
            == Some("enforce");
    }
    // Not YAML: any `mode: enforce` pair, in block or flow style, quoted or
    // not, wherever it sits. Only `hooks` has a `mode`, and a stray match in a
    // configuration that does not load only makes the hook deny as
    // misconfigured.
    fn unquote(text: &str) -> &str {
        text.trim().trim_matches(['"', '\''])
    }
    text.lines()
        .map(|line| line.split('#').next().unwrap_or_default())
        .flat_map(|line| line.split(['{', '}', ',']))
        .filter_map(|pair| pair.split_once(':'))
        .any(|(key, value)| unquote(key) == "mode" && unquote(value) == "enforce")
}

/// A non-empty environment variable as a path.
fn env_path(name: &str) -> Option<PathBuf> {
    std::env::var_os(name)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

fn check(config_dirs: &[PathBuf]) -> i32 {
    let config = match load_config(config_dirs) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("config: {error}");
            return 1;
        }
    };
    match Engine::new(&config.rules, &config.protected_paths()) {
        Ok(engine) => {
            println!("build revision: {}", identity::revision());
            println!("semantic identity: {}", engine.semantic_identity());
            println!("pipeline build: {} ms", engine.build_ms);
            println!(
                "mode: {} ({}), on_error: {:?}, on_unevaluable: {:?}",
                Gate::for_mode(config.mode).as_str(),
                match Gate::for_mode(config.mode) {
                    Gate::DetectOnly =>
                        "verdicts are recorded and never returned; set hooks.mode: enforce to block",
                    Gate::Enforce => "ask and deny verdicts are returned to the harness",
                },
                config.on_error,
                config.on_unevaluable
            );
            let generated = engine.generated_coverage();
            println!(
                "self-protection: {} paths in {} generated rules",
                generated.paths, generated.rules
            );
            for path in &generated.reduced {
                println!(
                    "self-protection: too long for one rule, matched by its last bytes: {path:?}"
                );
            }
            for path in &generated.unrepresentable {
                println!("self-protection: not UTF-8, no generated rule: {path:?}");
            }
            match (
                config.resolved_state_dir(),
                config.resolved_telemetry_path(),
            ) {
                (Ok(state), Ok(telemetry)) => {
                    println!("state dir: {}", state.display());
                    println!("telemetry: {}", telemetry.display());
                }
                (Err(error), _) | (_, Err(error)) => {
                    eprintln!("paths: {error}");
                    return 1;
                }
            }
            0
        }
        Err(error) => {
            eprintln!("telltale: {error}");
            1
        }
    }
}

fn time_now() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}

/// Write a released answer and return its exit status. The only writer of a
/// hook's stdout: everything a hook does ends in [`Gate::release`] and then
/// here.
fn deliver(answer: Answer) -> i32 {
    if let Some(output) = &answer.output {
        let mut stdout = std::io::stdout().lock();
        // A closed stdout leaves the harness without our answer; nothing more to do.
        let _ = writeln!(stdout, "{output}");
        let _ = stdout.flush();
    }
    answer.exit_code
}

/// The policy for a tool call the hook could not read: the stricter of
/// `on_error` and `on_unevaluable`, the runtime's rule for a failure an agent
/// can bring about. It is answered on stdout because no exit code is an answer
/// on every harness: Copilot blocks on exit 1, Codex runs the call, and Claude
/// Code treats it as a non-blocking error.
fn unreadable_call_policy(config: &Config) -> OnError {
    config.on_error.max(config.on_unevaluable)
}

/// Handle one hook event for `harness`: stdin payload, stdout answer.
///
/// The gate is settled first, from the configuration alone, and everything
/// else only builds an [`Answer`] for it. Detect-only (the default) therefore
/// holds whatever happens below: nothing is written to stdout, the exit
/// status is 0, and the process ends by [`DETECT_ONLY_DEADLINE`], including
/// when the payload is unreadable, the configuration is broken or the code
/// panics. Only `hooks.mode: enforce` in a configuration that was read lets
/// an answer through.
fn hook(harness: Harness, config_dirs: &[PathBuf]) -> i32 {
    let loaded = load_config(config_dirs);
    let gate = Gate::for_config(&loaded, || settings_declare_enforce(config_dirs));
    if gate == Gate::DetectOnly {
        // Detached: the process exits when `hook` returns.
        std::thread::spawn(|| {
            std::thread::sleep(DETECT_ONLY_DEADLINE);
            eprintln!(
                "telltale hooks: detect-only hook gave up after {} s without an answer",
                DETECT_ONLY_DEADLINE.as_secs()
            );
            std::process::exit(0);
        });
    }
    // What a tool call gets if evaluating it panics while enforcing: the
    // policy for a failure an agent can bring about, not a crash that most
    // harnesses read as "run the call".
    let panic_policy = match &loaded {
        Ok(config) => unreadable_call_policy(config),
        Err(_) => OnError::Deny,
    };
    let Some(bytes) = read_payload() else {
        return deliver(gate.release(Answer::exit(1)));
    };
    let answer = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        evaluate(harness, loaded, gate, &bytes, config_dirs)
    }))
    .unwrap_or_else(|_| {
        eprintln!("telltale hooks: the hook panicked (hook_panicked)");
        if harness.looks_like_pre_tool_use(&bytes) {
            Answer::output(harness.render_verdict(
                panic_policy,
                "Telltale Hooks failed while evaluating this tool call (hook_panicked).",
            ))
        } else {
            Answer::exit(1)
        }
    });
    deliver(gate.release(answer))
}

/// One hook payload from stdin, bounded: at most one byte past
/// [`MAX_PAYLOAD_BYTES`], which marks it as oversized.
fn read_payload() -> Option<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut stdin = std::io::stdin().lock();
    if let Err(error) = (&mut stdin)
        .take(MAX_PAYLOAD_BYTES + 1)
        .read_to_end(&mut bytes)
    {
        eprintln!("telltale hooks: cannot read hook payload: {error}");
        return None;
    }
    // Keep memory bounded but drain the rest, so the harness never sees a
    // broken pipe while writing a large payload (its handling is unknown).
    if bytes.len() as u64 > MAX_PAYLOAD_BYTES {
        let _ = std::io::copy(&mut stdin, &mut std::io::sink());
    }
    Some(bytes)
}

/// Build the answer for one payload. Tries the long-lived evaluator, then
/// evaluates in-process; an unanswered pre-execution event never turns into
/// an allow. Writes nothing to stdout and exits nothing: the caller's gate
/// releases the answer or does not.
fn evaluate(
    harness: Harness,
    loaded: Result<Config, String>,
    gate: Gate,
    bytes: &[u8],
    config_dirs: &[PathBuf],
) -> Answer {
    let oversized = bytes.len() as u64 > MAX_PAYLOAD_BYTES;
    let parsed = if oversized {
        Parsed::Invalid("payload_oversized")
    } else {
        harness.parse(bytes)
    };
    let config = resolve_config(harness, loaded, gate);
    // Split into the hook event name and either the runtime event or the
    // reason it is unusable; an unreadable payload is answered right here.
    let (hook_event, usable) = match parsed {
        Parsed::Event(ctx, event) => (ctx.hook_event.clone(), Ok((ctx, event))),
        Parsed::Unusable { hook_event, code } => (hook_event, Err(code)),
        Parsed::Invalid(code) => return invalid_payload_answer(harness, &config, code, bytes),
    };
    let Ok(config) = config else {
        if harness.is_pre_tool_use(&hook_event) {
            return Answer::output(harness.render_event_verdict(
                &hook_event,
                OnError::Deny,
                "Telltale Hooks is misconfigured and fails closed (config_invalid); details are on the hook's stderr.",
            ));
        }
        return Answer::exit(1);
    };
    let (ctx, event) = match usable {
        Ok(pair) => pair,
        Err(code) => return unusable_event_answer(harness, &config, &hook_event, code),
    };
    answer_from_runtime(harness, config, ctx, event, bytes, config_dirs)
}

/// The configuration an event is evaluated under, or `Err(())` when it did not
/// load and the gate is enforcing.
fn resolve_config(
    harness: Harness,
    loaded: Result<Config, String>,
    gate: Gate,
) -> Result<Config, ()> {
    // A configuration that does not load and asks for enforcement fails closed
    // for tool calls: an operator error should be visible at once, not
    // silently disable enforcement. One that never asked for it is detect-only
    // (the gate is already closed): detection carries on with the defaults and
    // the failure is recorded.
    match loaded {
        Ok(config) => Ok(config),
        Err(error) => {
            // Details (which may include a path) go to stderr only.
            eprintln!("telltale hooks: {error}");
            if gate == Gate::Enforce {
                Err(())
            } else {
                eprintln!(
                    "telltale hooks: the configuration did not load and does not set hooks.mode: enforce: detect-only with the defaults"
                );
                let config = Config::detect_only_fallback(
                    env_path(crate::settings::STATE_DIR_ENV),
                    env_path(crate::settings::TELEMETRY_ENV),
                );
                Runtime::new(config.clone()).record_unhandled(harness.name(), "", "config_invalid");
                Ok(config)
            }
        }
    }
}

/// The answer for a payload that could not be parsed at all (oversized or
/// malformed).
fn invalid_payload_answer(
    harness: Harness,
    config: &Result<Config, ()>,
    code: &'static str,
    bytes: &[u8],
) -> Answer {
    eprintln!("telltale hooks: unusable hook payload ({code})");
    if let Ok(config) = config {
        Runtime::new(config.clone()).record_unhandled(harness.name(), "", code);
    }
    // An oversized or malformed payload is agent-influenced (a huge
    // tool input), so a PreToolUse gets a verdict rather than a
    // non-blocking exit that the harness treats as allow.
    if harness.looks_like_pre_tool_use(bytes) {
        let policy = match config {
            Ok(config) => unreadable_call_policy(config),
            Err(()) => OnError::Deny,
        };
        return Answer::output(harness.render_verdict(
            policy,
            "Telltale Hooks could not read this tool call (payload too large or malformed).",
        ));
    }
    let fail_closed = matches!(config, Ok(c) if c.on_error == OnError::Deny);
    // A named event is not pre-execution by now, and exit 2 there is
    // not a block: on a Stop it is a prompt to continue, so a damaged
    // Stop would re-prompt the model without limit (Codex: E2E
    // `damaged-stop-*`).
    if !fail_closed || names_event(bytes) {
        return Answer::exit(1);
    }
    // No event name: this could be a tool call, so block one without
    // making a prompt of anything else.
    match harness.adapter().nameless_block {
        NamelessBlock::DenyOnStdout => Answer::output(harness.render_verdict(
            OnError::Deny,
            "Telltale Hooks could not read this hook payload and fails closed.",
        )),
        NamelessBlock::Exit(status) => Answer::exit(status),
    }
}

/// The answer for a payload that parsed but lacks what the event needs.
fn unusable_event_answer(
    harness: Harness,
    config: &Config,
    hook_event: &str,
    code: &'static str,
) -> Answer {
    eprintln!("telltale hooks: unusable hook payload ({code})");
    Runtime::new(config.clone()).record_unhandled(harness.name(), hook_event, code);
    if harness.is_pre_tool_use(hook_event) {
        return Answer::output(harness.render_event_verdict(
            hook_event,
            unreadable_call_policy(config),
            "Telltale Hooks could not read this tool call (required fields are missing).",
        ));
    }
    Answer::exit(1)
}

/// Evaluate a readable event: the long-lived evaluator first, then in-process.
fn answer_from_runtime(
    harness: Harness,
    config: Config,
    ctx: Context,
    event: Event,
    bytes: &[u8],
    config_dirs: &[PathBuf],
) -> Answer {
    // No evaluator transport off Unix: skip the socket path and the
    // fingerprint (which hashes rule files) and record why.
    #[cfg(not(unix))]
    let fallback = config
        .evaluator
        .enabled
        .then_some(evaluator::UNSUPPORTED_PLATFORM);
    // Only the evaluator transport sends the raw payload and starts an
    // evaluator with these config roots.
    #[cfg(not(unix))]
    let _ = (bytes, config_dirs);
    #[cfg(unix)]
    let mut fallback = None;
    #[cfg(unix)]
    if config.evaluator.enabled
        && let Ok(socket) = config.resolved_socket_path()
    {
        let timeout = std::time::Duration::from_millis(config.evaluator.request_timeout_ms);
        let asked_at = telltale_core::hooks::runtime::now_ms();
        match evaluator::request(&socket, harness, &config.fingerprint(), bytes, timeout) {
            ClientOutcome::Answered(output) => return Answer::output(output),
            ClientOutcome::DeliveredNoAnswer(code) => {
                let mut runtime = Runtime::new(config);
                let response = runtime.handle_unanswered(&ctx, event, code, asked_at);
                return Answer::output(harness.render(&ctx.hook_event, &response));
            }
            ClientOutcome::NotDelivered(code) => {
                if code == "evaluator_unreachable"
                    && config.evaluator.autostart
                    && let Ok(state_dir) = config.resolved_state_dir()
                {
                    // Best effort; this hook still evaluates in-process below.
                    let _ = evaluator::spawn_detached(&state_dir, &serve_args(config_dirs));
                }
                fallback = Some(code);
            }
        }
    }
    let mut runtime = Runtime::new(config);
    runtime.set_evaluator("in_process", fallback);
    let response = runtime.handle(&ctx, event);
    Answer::output(harness.render(&ctx.hook_event, &response))
}

/// `hooks serve` arguments for an evaluator that reads the configuration this
/// hook read.
#[cfg(unix)]
fn serve_args(config_dirs: &[PathBuf]) -> Vec<OsString> {
    let mut args = vec![OsString::from("hooks"), OsString::from("serve")];
    for dir in config_dirs {
        args.push(OsString::from("--config-dir"));
        args.push(
            std::path::absolute(dir)
                .unwrap_or_else(|_| dir.clone())
                .into_os_string(),
        );
    }
    args
}

fn serve(config_dirs: &[PathBuf]) -> i32 {
    let config = match load_config(config_dirs) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("config: {error}");
            return 1;
        }
    };
    let log = config
        .resolved_state_dir()
        .ok()
        .map(|dir| dir.join("evaluator.log"));
    match evaluator::serve(config) {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("telltale hooks serve: {error}");
            // An autostarted evaluator has no stderr; leave a trace (bounded).
            if let Some(log) = log
                && std::fs::symlink_metadata(&log)
                    .map(|m| m.len())
                    .unwrap_or(0)
                    < 1024 * 1024
                && let Ok(mut file) = telltale_core::hooks::state::open_regular(
                    std::fs::OpenOptions::new().create(true).append(true),
                    &log,
                )
            {
                let _ = writeln!(file, "{} serve failed: {error}", time_now());
            }
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::{config_dirs, declares_enforce, load_config};

    #[test]
    fn config_dirs_reads_repeated_flags_and_refuses_anything_else() {
        assert_eq!(config_dirs(&[]), Some(Vec::new()));
        assert_eq!(
            config_dirs(&["--config-dir", "a", "--config-dir=b"]),
            Some(vec![PathBuf::from("a"), PathBuf::from("b")])
        );
        for refused in [
            &["--config-dir"][..],
            &["--config-dir="],
            &["--config-dir", ""],
            &["--config-dirs=a"],
            &["--bogus"],
            &["--config-dir", "a", "extra"],
        ] {
            assert_eq!(config_dirs(refused), None, "{refused:?}");
        }
    }

    #[test]
    fn only_hooks_mode_enforce_declares_enforcement() {
        for enforcing in [
            "version: 1\nhooks:\n  mode: enforce\n",
            "hooks:\n  mode: \"enforce\"\n  bogus: 1\n",
            // Not YAML, so read as `key: value` pairs: any spelling of the
            // pair counts, wherever it sits (fail closed).
            "hooks:\n  on_error: deny\n  mode: enforce\n  thresholds: [\n",
            "hooks:\n    mode: 'enforce'  # on\n  : : [\n",
            "hooks: {mode: enforce, bogus: [}\n",
            "version: 1\n\"hooks\":\n  mode: enforce\nbroken: [\n",
            "hooks:\n  \"mode\": enforce\nbroken: [\n",
            "hooks: {\n  on_error: deny,\n  mode: enforce\n}\nbroken: [\n",
            "hooks:\r\n  mode: enforce\r\nbroken: [\r\n",
            "other:\n  mode: enforce\n  bogus: [\n",
        ] {
            assert!(declares_enforce(enforcing), "{enforcing}");
        }
        for not_enforcing in [
            "",
            "version: 1\n",
            "hooks:\n  mode: observe\n",
            "mode: enforce\n",
            "hooks:\n  # mode: enforce\n",
            "hooks:\n  evaluator:\n    mode: enforce\n",
            "other:\n  mode: enforce\nhooks:\n  mode: detect\n",
            // Not YAML, and no `mode: enforce` outside a comment.
            "hooks:\n  # mode: enforce\n  : : [\n",
            "hooks:\n  mode: observe\n  bogus: [\n",
        ] {
            assert!(!declares_enforce(not_enforcing), "{not_enforcing}");
        }
    }

    fn write(root: &Path, relative: &str, text: &str) -> PathBuf {
        let path = root.join(relative);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, text).unwrap();
        path
    }

    /// The hooks configuration takes its rule content from the same folders as
    /// `scan`, and its settings from the `hooks:` section, later roots winning.
    #[test]
    fn load_config_reads_the_hooks_section_and_the_shared_rule_folders() {
        let dir = tempfile::tempdir().unwrap();
        let first = dir.path().join("first");
        let second = dir.path().join("second");
        write(
            &first,
            "settings.d/10-hooks.yaml",
            "version: 1\nhooks:\n  mode: enforce\n  on_error: deny\n  thresholds:\n    action_ask: 30\n",
        );
        let settings = write(
            &second,
            "settings.d/10-hooks.yaml",
            "version: 1\nhooks:\n  on_error: ask\n  self_protection_rules: false\n",
        );
        let rules = write(&first, "rules.d/local.yaml", "version: 1\nrules: []\n");
        let organization = write(
            &second,
            "organization-rules.d/org.yaml",
            "version: 1\nrules: []\n",
        );
        let override_file = write(&second, "overrides.d/quiet.yaml", "version: 1\n");
        let policy = write(&second, "policies.d/policy.yaml", "version: 1\n");

        let config = load_config(&[first.clone(), second.clone()]).unwrap();
        assert_eq!(config.mode, telltale_core::hooks::config::Mode::Enforce);
        assert_eq!(
            config.on_error,
            telltale_core::hooks::config::OnError::Ask,
            "the later root wins"
        );
        assert_eq!(config.thresholds.action_ask, 30);
        assert!(!config.rules.self_protection);
        let absolute = |path: &Path| std::path::absolute(path).unwrap();
        assert_eq!(config.rules.packs.deployment, vec![absolute(&rules)]);
        assert_eq!(
            config.rules.packs.organization,
            vec![absolute(&organization)]
        );
        assert_eq!(config.rules.overrides, vec![absolute(&override_file)]);
        assert_eq!(config.rules.policy, Some(absolute(&policy)));
        // The roots and settings files are protected, like the rule files.
        let protected = config.protected_paths();
        for path in [&first, &second, &settings, &rules, &policy] {
            assert!(protected.contains(&absolute(path)), "{}", path.display());
        }
    }

    #[test]
    fn load_config_refuses_unknown_hooks_keys_and_invalid_thresholds() {
        let dir = tempfile::tempdir().unwrap();
        for (body, expected) in [
            ("hooks:\n  bogus: 1\n", "bogus"),
            (
                "hooks:\n  thresholds:\n    action_ask: 90\n    action_deny: 80\n",
                "hooks.thresholds",
            ),
        ] {
            let root = dir.path().join(expected);
            write(
                &root,
                "settings.d/hooks.yaml",
                &format!("version: 1\n{body}"),
            );
            let error = load_config(&[root]).unwrap_err();
            assert!(error.contains(expected), "{body}: {error}");
        }
    }

    /// A linked root, folder or file is read through the link, so its target
    /// is protected too: a file added to a linked `settings.d` later must not
    /// be an unprotected way to change the configuration.
    #[cfg(unix)]
    #[test]
    fn link_targets_in_a_config_root_are_protected() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().canonicalize().unwrap();
        let dropins = base.join("dropins");
        write(
            &dropins,
            "hooks.yaml",
            "version: 1\nhooks:\n  mode: enforce\n",
        );
        let rule_target = write(&base.join("elsewhere"), "local.yaml", "rules: []\n");
        let root = base.join("root");
        std::fs::create_dir_all(root.join("rules.d")).unwrap();
        symlink(&dropins, root.join("settings.d")).unwrap();
        symlink(&rule_target, root.join("rules.d/local.yaml")).unwrap();
        let linked_root = base.join("linked-root");
        symlink(&root, &linked_root).unwrap();

        let config = load_config(&[linked_root]).unwrap();
        assert_eq!(config.mode, telltale_core::hooks::config::Mode::Enforce);
        let protected = config.protected_paths();
        for target in [&root, &dropins, &dropins.join("hooks.yaml"), &rule_target] {
            assert!(
                protected.contains(target),
                "{} not in {protected:?}",
                target.display()
            );
        }
    }
}
