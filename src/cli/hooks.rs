//! `telltale hooks`: pre-execution hooks for agent harnesses.
//!
//! The runtime, adapters and evaluator live in `telltale_core::hooks`; this
//! module is the process boundary: it reads one hook payload from stdin and
//! answers on stdout and with its exit code. A hook invocation is dispatched
//! before the rest of the CLI starts (`run` checks for it first), so a tool
//! call never waits for the scanner's startup work, and the exit codes below
//! are the hooks' own rather than the CLI's.

use std::io::{Read, Write};

use telltale_core::hooks::claude_code;
use telltale_core::hooks::codex_cli;
use telltale_core::hooks::config::{Config, OnError};
use telltale_core::hooks::copilot_cli;
use telltale_core::hooks::engine::Engine;
use telltale_core::hooks::evaluator;
#[cfg(unix)]
use telltale_core::hooks::evaluator::ClientOutcome;
use telltale_core::hooks::harness::{Harness, Parsed, names_event};
use telltale_core::hooks::identity;
use telltale_core::hooks::runtime::Runtime;

/// Hook payloads larger than this are refused rather than buffered.
const MAX_PAYLOAD_BYTES: u64 = 32 * 1024 * 1024;

const USAGE: &str = "\
usage:
  telltale hooks claude-code hook                 handle one Claude Code hook (stdin -> stdout)
  telltale hooks claude-code settings [--fail-closed] [COMMAND]
                                                  print the Claude Code hooks settings fragment;
                                                  --fail-closed blocks tool calls if the hook fails
  telltale hooks codex-cli hook                   handle one Codex CLI hook (stdin -> stdout)
  telltale hooks codex-cli settings [COMMAND]     print $CODEX_HOME/hooks.json (install and trust steps
                                                  on stderr); Codex has no fail-closed option, so
                                                  --fail-closed is refused
  telltale hooks codex-cli execpolicy             print Codex exec-policy rules that refuse nested Codex
                                                  launches natively, even if the hook fails
  telltale hooks copilot-cli hook                 handle one GitHub Copilot CLI hook (stdin -> stdout)
  telltale hooks copilot-cli settings [--fail-closed] [COMMAND]
                                                  print the Copilot CLI hook file (for example
                                                  ~/.copilot/hooks/telltale-hooks.json); Copilot
                                                  always fails closed on a crash or missing binary
                                                  and open on a timeout, so --fail-closed changes nothing;
                                                  on Windows COMMAND runs under PowerShell, so quote a
                                                  path with spaces as '& \"C:\\...\\telltale.exe\" hooks ...'
  telltale hooks serve                            run the long-lived evaluator (normally autostarted;
                                                  Linux and macOS only, elsewhere hooks evaluate in-process)
  telltale hooks check                            validate config and build the Telltale pipeline
  telltale hooks version                          print the version, Git hash and build revision

environment:
  TELLTALE_HOOKS_CONFIG     config TOML, default if present:
                              Linux, macOS: $XDG_CONFIG_HOME or ~/.config, then telltale-hooks/config.toml
                              Windows:      %APPDATA%\\telltale-hooks\\config.toml
  TELLTALE_HOOKS_STATE_DIR  per-session journals and state, default:
                              Linux, macOS: $XDG_STATE_HOME/telltale-hooks or ~/.local/state/telltale-hooks
                              Windows:      %LOCALAPPDATA%\\telltale-hooks
  TELLTALE_HOOKS_TELEMETRY  telemetry JSONL (default <state dir>/telemetry.jsonl)";

/// Run `telltale hooks <args>` and return the process exit status.
pub(crate) fn exit_code(args: &[String]) -> i32 {
    // Before anything reads the build identity: the CLI's Git hash.
    identity::set_host_build(env!("TELLTALE_GIT_HASH"));
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    match args.as_slice() {
        ["-h"] | ["--help"] | ["help"] => {
            println!("{USAGE}");
            0
        }
        ["claude-code", "settings", rest @ ..] => print_settings(Harness::ClaudeCode, rest),
        ["copilot-cli", "settings", rest @ ..] => print_settings(Harness::CopilotCli, rest),
        ["codex-cli", "settings", rest @ ..] => print_settings(Harness::CodexCli, rest),
        ["codex-cli", "execpolicy"] => {
            print!("{}", codex_cli::execpolicy_rules());
            0
        }
        [name, "hook"] => match Harness::from_name(name) {
            Some(harness) => hook(harness),
            None => {
                eprintln!("{USAGE}");
                64
            }
        },
        ["check"] => check(),
        ["serve"] => serve(),
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
            eprintln!("{USAGE}");
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
        eprintln!("{USAGE}");
        return 64;
    }
    let fail_closed = !flags.is_empty();
    let default = format!("telltale hooks {} hook", harness.name());
    let command = match positional.as_slice() {
        [] => default.as_str(),
        [command] => command,
        _ => {
            eprintln!("{USAGE}");
            return 64;
        }
    };
    let fragment = match harness {
        Harness::ClaudeCode => claude_code::settings_fragment(command, fail_closed),
        // Codex cannot fail closed, so `--fail-closed` prints nothing and fails
        // rather than pretending. Install and trust notes go to stderr.
        Harness::CodexCli => {
            if fail_closed {
                eprintln!("{}", codex_cli::NO_FAIL_CLOSED);
                return 1;
            }
            eprintln!("{}", codex_cli::INSTALL_NOTES);
            codex_cli::hooks_file(command)
        }
        Harness::CopilotCli => {
            if fail_closed {
                eprintln!(
                    "telltale hooks: Copilot CLI already blocks a tool call when its hook crashes, exits non-zero or is missing, and always lets it run when the hook times out; --fail-closed changes nothing."
                );
            }
            copilot_cli::hooks_file(command)
        }
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&fragment).unwrap_or_default()
    );
    0
}

fn check() -> i32 {
    let config = match Config::load() {
        Ok(config) => config,
        Err(error) => {
            eprintln!("config: {error}");
            return 1;
        }
    };
    match Engine::new(&config.telltale, &config.protected_paths()) {
        Ok(engine) => {
            println!("build revision: {}", identity::revision());
            println!("semantic identity: {}", engine.semantic_identity());
            println!("pipeline build: {} ms", engine.build_ms);
            println!("mode: {:?}, on_error: {:?}", config.mode, config.on_error);
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

fn emit(value: &serde_json::Value) {
    let mut stdout = std::io::stdout().lock();
    // A closed stdout leaves the harness without our answer; nothing more to do.
    let _ = writeln!(stdout, "{value}");
    let _ = stdout.flush();
}

/// Emit `output` (if any) and exit successfully.
fn answer(output: Option<serde_json::Value>) -> i32 {
    if let Some(output) = output {
        emit(&output);
    }
    0
}

/// The policy for a tool call the hook could not read: the stricter of
/// `on_error` and `on_unevaluable`, the runtime's rule for a failure an agent
/// can bring about. It is answered on stdout because no exit code is an answer
/// on every harness: Copilot blocks on exit 1, Codex runs the call, and Claude
/// Code treats it as a non-blocking error.
fn unreadable_call_policy(config: &Config) -> OnError {
    config.on_error.max(config.on_unevaluable)
}

/// Handle one hook event for `harness`: stdin payload, stdout answer. Tries
/// the long-lived evaluator, then evaluates in-process; an unanswered
/// pre-execution event never turns into an allow.
fn hook(harness: Harness) -> i32 {
    let mut bytes = Vec::new();
    let mut stdin = std::io::stdin().lock();
    if let Err(error) = (&mut stdin)
        .take(MAX_PAYLOAD_BYTES + 1)
        .read_to_end(&mut bytes)
    {
        eprintln!("telltale hooks: cannot read hook payload: {error}");
        return 1;
    }
    // Keep memory bounded but drain the rest, so the harness never sees a
    // broken pipe while writing a large payload (its handling is unknown).
    if bytes.len() as u64 > MAX_PAYLOAD_BYTES {
        let _ = std::io::copy(&mut stdin, &mut std::io::sink());
    }
    drop(stdin);
    let oversized = bytes.len() as u64 > MAX_PAYLOAD_BYTES;
    let parsed = if oversized {
        Parsed::Invalid("payload_oversized")
    } else {
        harness.parse(&bytes)
    };
    // Config problems fail closed for tool calls: an operator error should be
    // visible at once, not silently disable monitoring. Other events continue.
    let config = Config::load();
    // Split into the hook event name and either the runtime event or the
    // reason it is unusable; an unreadable payload is answered right here.
    let (hook_event, usable) = match parsed {
        Parsed::Event(ctx, event) => (ctx.hook_event.clone(), Ok((ctx, event))),
        Parsed::Unusable { hook_event, code } => (hook_event, Err(code)),
        Parsed::Invalid(code) => {
            eprintln!("telltale hooks: unusable hook payload ({code})");
            // An oversized or malformed payload is agent-influenced (a huge
            // tool input), so a PreToolUse gets a verdict rather than a
            // non-blocking exit that the harness treats as allow.
            if harness.looks_like_pre_tool_use(&bytes) {
                let policy = match &config {
                    Ok(config) => unreadable_call_policy(config),
                    Err(_) => OnError::Deny,
                };
                return answer(harness.render_verdict(
                    policy,
                    "Telltale Hooks could not read this tool call (payload too large or malformed).",
                ));
            }
            let fail_closed = matches!(&config, Ok(c) if c.on_error == OnError::Deny);
            // A named event is not pre-execution by now, and exit 2 there is
            // not a block: on a Stop it is a prompt to continue, so a damaged
            // Stop would re-prompt the model without limit (Codex: E2E
            // `damaged-stop-*`).
            if !fail_closed || names_event(&bytes) {
                return 1;
            }
            // No event name: this could be a tool call, so block one without
            // making a prompt of anything else.
            return match harness {
                // A deny on stdout is honored on a PreToolUse and rejected as
                // invalid output on every other event (E2E `damaged-*-nameless`).
                Harness::CodexCli => answer(harness.render_verdict(
                    OnError::Deny,
                    "Telltale Hooks could not read this hook payload and fails closed.",
                )),
                // Blocks a preToolUse; other events continue (E2E `fail-exit1`).
                Harness::CopilotCli => 1,
                // The only block that does not need the event, but on a Stop it
                // still prompts: the known residual for this harness.
                Harness::ClaudeCode => 2,
            };
        }
    };
    let config = match config {
        Ok(config) => config,
        Err(error) => {
            // Details (which may include a path) go to stderr only.
            eprintln!("telltale hooks: {error}");
            if harness.is_pre_tool_use(&hook_event) {
                return answer(harness.render_event_verdict(
                    &hook_event,
                    OnError::Deny,
                    "Telltale Hooks is misconfigured and fails closed (config_invalid); details are on the hook's stderr.",
                ));
            }
            return 1;
        }
    };
    let (ctx, event) = match usable {
        Ok(pair) => pair,
        Err(code) => {
            eprintln!("telltale hooks: unusable hook payload ({code})");
            if harness.is_pre_tool_use(&hook_event) {
                return answer(harness.render_event_verdict(
                    &hook_event,
                    unreadable_call_policy(&config),
                    "Telltale Hooks could not read this tool call (required fields are missing).",
                ));
            }
            return 1;
        }
    };
    // No evaluator transport off Unix: skip the socket path and the
    // fingerprint (which hashes rule files) and record why.
    #[cfg(not(unix))]
    let fallback = config
        .evaluator
        .enabled
        .then_some(evaluator::UNSUPPORTED_PLATFORM);
    #[cfg(unix)]
    let mut fallback = None;
    #[cfg(unix)]
    if config.evaluator.enabled
        && let Ok(socket) = config.resolved_socket_path()
    {
        let timeout = std::time::Duration::from_millis(config.evaluator.request_timeout_ms);
        let asked_at = telltale_core::hooks::runtime::now_ms();
        match evaluator::request(&socket, harness, &config.fingerprint(), &bytes, timeout) {
            ClientOutcome::Answered(output) => return answer(output),
            ClientOutcome::DeliveredNoAnswer(code) => {
                let mut runtime = Runtime::new(config);
                let response = runtime.handle_unanswered(&ctx, event, code, asked_at);
                return answer(harness.render(&ctx.hook_event, &response));
            }
            ClientOutcome::NotDelivered(code) => {
                if code == "evaluator_unreachable"
                    && config.evaluator.autostart
                    && let Ok(state_dir) = config.resolved_state_dir()
                {
                    // Best effort; this hook still evaluates in-process below.
                    let _ = evaluator::spawn_detached(&state_dir);
                }
                fallback = Some(code);
            }
        }
    }
    let mut runtime = Runtime::new(config);
    runtime.set_evaluator("in_process", fallback);
    let response = runtime.handle(&ctx, event);
    answer(harness.render(&ctx.hook_event, &response))
}

fn serve() -> i32 {
    let config = match Config::load() {
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
