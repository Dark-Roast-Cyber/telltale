//! `telltale hooks`: pre-execution hooks for agent harnesses.
//!
//! The runtime, adapters and evaluator live in `telltale_core::hooks`; this
//! module is the process boundary: it reads one hook payload from stdin and
//! answers on stdout and with its exit code. A hook invocation is dispatched
//! before the rest of the CLI starts (`run` checks for it first), so a tool
//! call never waits for the scanner's startup work, and the exit codes below
//! are the hooks' own rather than the CLI's.
//!
//! A panic on the way to an answer is caught here and answered like a tool
//! call the hook could not read. That needs unwinding, so a build that
//! aborts on panic does not compile.

// A profile, `RUSTFLAGS` or target that sets `panic = "abort"` would turn
// every caught panic into a crash that most harnesses read as "run the call".
#[cfg(not(panic = "unwind"))]
compile_error!(
    "telltale hooks needs panic = \"unwind\": it answers a panic with the strict failure policy"
);

#[cfg(unix)]
use std::ffi::OsString;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::time::Instant;

use telltale_core::hooks::config::{Config, OnError, RuleContent};
use telltale_core::hooks::engine::Engine;
#[cfg(unix)]
use telltale_core::hooks::engine::Limits;
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
  telltale hooks check [--rules]                  validate config and build the Telltale pipeline; --rules
                                                  lists every rule and chain the hook evaluates as it takes
                                                  effect: enabled or what turned it off, score, tier, overrides
  telltale hooks version                          print the version, Git hash and build revision

hook, serve and check accept --config-dir DIR (repeatable): read these Telltale
config roots instead of the default ones (/etc/telltale, on Windows %ProgramData%\\telltale,
then $XDG_CONFIG_HOME/telltale or ~/.config/telltale). Settings are the hooks: section of settings.d/*.yaml; rule
content is the same rules.d, rule-packages.d, overrides.d and policies.d as scan.
--user-config-dir DIR replaces only the user root, which must then exist; settings
adds it to the hook command when the user root exists, so the environment a harness
is launched with cannot move it.
--state-dir DIR sets the state directory, and the environment decides neither it nor
the records file (hooks.telemetry_path from settings files applies);
settings adds it to the hook command with the state directory in use, which a hook
creates owner-only when it is missing.
hook also accepts --json-reply: frame the gated native output (including null)
as telltale.hook-reply.v1 for subprocess adapters, not native command hooks.
--detect-only can only restrict the loaded mode, never enable enforcement.
--expect-enforce (added by settings when the configuration enforces) treats a
configuration that does not load as one that enforces; it never changes the mode
of a configuration that loads, and is refused beside --detect-only.

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
        [name, "hook", flags @ ..] => match (Harness::from_name(name), pinned(flags, hook_flags)) {
            (Some(harness), Some((dirs, json_reply, detect_only, expect_enforce))) => {
                hook(harness, &dirs, json_reply, detect_only, expect_enforce)
            }
            _ => {
                eprintln!("{}", usage());
                64
            }
        },
        ["check", flags @ ..] => match pinned(flags, check_flags) {
            Some((dirs, list_rules)) => check(&dirs, list_rules),
            None => {
                eprintln!("{}", usage());
                64
            }
        },
        ["serve", flags @ ..] => match pinned(flags, config_dirs) {
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
    // A user-level install is found through HOME or XDG_CONFIG_HOME, which a
    // harness can be launched without; pin the root the hook reads now. A
    // command that names its own roots is the operator's.
    let own_roots = command.contains("--config-dir") || command.contains(USER_CONFIG_DIR);
    let loaded = (!own_roots).then(|| load_config(&[]));
    let (pinned, pin_note) = if own_roots {
        (None, None)
    } else {
        match user_root_to_pin() {
                Some(root) => match pin_command(command, USER_CONFIG_DIR, &root, cfg!(windows)) {
                    Some(pinned) => (
                        Some(pinned),
                        Some(format!(
                            "telltale hooks: the hook reads the user config root {} whatever HOME or XDG_CONFIG_HOME is when the harness starts; run settings again if it moves",
                            root.display()
                        )),
                    ),
                    None => (
                        None,
                        Some(format!(
                            "telltale hooks: the user config root {} cannot be quoted for the hook command; it is not pinned, so the hook follows HOME and XDG_CONFIG_HOME",
                            root.display()
                        )),
                    ),
                },
                None => (
                    None,
                    Some("telltale hooks: no user config root exists, so the hook command is not pinned and the hook follows HOME and XDG_CONFIG_HOME; run settings again after creating one".to_owned()),
                ),
            }
    };
    // An enforcing configuration that later does not load must not fall to
    // detect-only: the command says enforcement was expected.
    let (expect_enforce, enforce_note) = match &loaded {
        None => (false, None),
        Some(_) if command.contains(EXPECT_ENFORCE) => (false, None),
        Some(loaded) => match loaded {
            Ok(config) if Gate::for_mode(config.mode) == Gate::Enforce => (
                true,
                Some(
                    "telltale hooks: the configuration says hooks.mode: enforce, so the hook command carries --expect-enforce: if the configuration later does not load, tool calls are denied (config_invalid) rather than run detect-only",
                ),
            ),
            Ok(_) => (
                false,
                Some(
                    "telltale hooks: the configuration does not say hooks.mode: enforce, so the hook command carries no --expect-enforce; run settings again after enabling enforcement",
                ),
            ),
            Err(_) => (
                false,
                Some(
                    "telltale hooks: the configuration does not load, so the hook command carries no --expect-enforce; fix it (telltale hooks check) and run settings again",
                ),
            ),
        },
    };
    let mut generated = pinned.unwrap_or_else(|| command.to_owned());
    // Session history and records follow the state-locating variables, which
    // a harness can be launched with moved; pin the directory the hook uses
    // now, so the environment never decides it. A command that names its own
    // roots pins the directory the configuration in those roots resolves.
    let own_loaded = (own_roots && !command.contains(STATE_DIR))
        .then(|| command_roots(command))
        .map(|roots| {
            roots.map(|(dirs, user)| {
                if let Some(user) = user {
                    crate::config::pin_user_config_root(user);
                }
                load_config(&dirs)
            })
        });
    let state_loaded = match (&loaded, &own_loaded) {
        (Some(loaded), _) | (_, Some(Some(loaded))) => Some(loaded),
        _ => None,
    };
    let state_note = match state_loaded {
        _ if command.contains(STATE_DIR) => None,
        None => Some(format!(
            "telltale hooks: the config roots this command names cannot be read plainly, so its state directory is not pinned and the hook follows {STATE_LOCATING}; add --state-dir DIR to the command"
        )),
        Some(loaded) => Some(match state_dir_to_pin(loaded) {
            Some(dir) => match pin_command(&generated, STATE_DIR, &dir, cfg!(windows)) {
                Some(with_state) => {
                    generated = with_state;
                    format!(
                        "telltale hooks: the hook keeps session state in {} whatever {STATE_LOCATING} is when the harness starts; run settings again to move it",
                        dir.display()
                    )
                }
                None => format!(
                    "telltale hooks: the state directory {} cannot be quoted for the hook command; it is not pinned, so the hook follows {STATE_LOCATING}",
                    dir.display()
                ),
            },
            None => format!(
                "telltale hooks: no state directory resolves, so the hook command is not pinned and the hook follows {STATE_LOCATING}; run settings again after setting one"
            ),
        }),
    };
    if expect_enforce {
        generated.push(' ');
        generated.push_str(EXPECT_ENFORCE);
    }
    let command = generated.as_str();
    // An adapter that cannot honor the request prints nothing and fails rather
    // than pretending. Install and trust notes go to stderr.
    let fragment = match (harness.adapter().install.output)(command, fail_closed) {
        Ok(output) => {
            if let Some(notes) = output.notes {
                eprintln!("{notes}");
            }
            for note in pin_note
                .iter()
                .chain(&state_note)
                .map(String::as_str)
                .chain(enforce_note)
            {
                eprintln!("{note}");
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

/// The hook switch `settings` adds when the configuration enforces.
const EXPECT_ENFORCE: &str = "--expect-enforce";

/// The switch that pins the user config root.
const USER_CONFIG_DIR: &str = "--user-config-dir";

/// The switch that pins the hooks state directory.
const STATE_DIR: &str = "--state-dir";

/// What a state directory that is not pinned follows.
#[cfg(not(windows))]
const STATE_LOCATING: &str = "TELLTALE_HOOKS_STATE_DIR, XDG_STATE_HOME and HOME";
#[cfg(windows)]
const STATE_LOCATING: &str = "TELLTALE_HOOKS_STATE_DIR and LOCALAPPDATA";

/// The hooks state directory `--state-dir` pinned for this process. It
/// replaces every other source of the state directory: the environment never
/// decides it.
static PINNED_STATE_DIR: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();

/// `parse` of `flags` without one `--user-config-dir DIR` and one
/// `--state-dir DIR` (or `=DIR`), which pin the user config root and the state
/// directory for this process. `None` for a repeated or empty pin, or a user
/// root pin beside `--config-dir`, which replaces every root.
fn pinned<T>(flags: &[&str], parse: impl Fn(&[&str]) -> Option<T>) -> Option<T> {
    let (rest, user) = split_pin(flags, USER_CONFIG_DIR)?;
    let (rest, state) = split_pin(&rest, STATE_DIR)?;
    let explicit = rest.iter().any(|flag| flag.starts_with("--config-dir"));
    let parsed = parse(&rest)?;
    if let Some(user) = user {
        if explicit {
            return None;
        }
        crate::config::pin_user_config_root(user);
    }
    if let Some(state) = state {
        let _ = PINNED_STATE_DIR.set(std::path::absolute(&state).unwrap_or(state));
    }
    Some(parsed)
}

/// `flags` without its `switch DIR` (or `switch=DIR`), and that directory. The
/// value of another switch that takes a directory is passed over, so a
/// directory named like the switch is not one.
fn split_pin<'a>(flags: &[&'a str], switch: &str) -> Option<(Vec<&'a str>, Option<PathBuf>)> {
    let (mut rest, mut pin) = (Vec::new(), None);
    let mut flags = flags.iter().copied();
    while let Some(flag) = flags.next() {
        let value = match flag.strip_prefix(switch) {
            Some("") => flags.next()?,
            Some(value) => value.strip_prefix('=')?,
            None => {
                rest.push(flag);
                if ["--config-dir", USER_CONFIG_DIR, STATE_DIR].contains(&flag) {
                    rest.push(flags.next()?);
                }
                continue;
            }
        };
        if value.is_empty() || pin.replace(PathBuf::from(value)).is_some() {
            return None;
        }
    }
    Some((rest, pin))
}

/// The state directory the hook uses now, to pin in a generated hook
/// command: the configured one, else the one the environment names. One
/// that does not exist yet is pinned too; the hook creates it owner-only.
fn state_dir_to_pin(loaded: &Result<Config, String>) -> Option<PathBuf> {
    let dir = match loaded {
        Ok(config) => config.resolved_state_dir(),
        // What a hook whose configuration did not load uses.
        Err(_) => Config::detect_only_fallback(env_path(crate::settings::STATE_DIR_ENV), None)
            .resolved_state_dir(),
    };
    std::path::absolute(dir.ok()?).ok()
}

/// The `--config-dir` roots and the `--user-config-dir` root a hook command
/// names. `None` when a word of the command is not plainly readable
/// ([`plain_words`]), or when the roots are not ones a hook would accept.
fn command_roots(command: &str) -> Option<(Vec<PathBuf>, Option<PathBuf>)> {
    let words = plain_words(command)?;
    let words: Vec<&str> = words.iter().map(String::as_str).collect();
    let (rest, user) = split_pin(&words, USER_CONFIG_DIR)?;
    let mut dirs = Vec::new();
    let mut rest = rest.into_iter();
    while let Some(word) = rest.next() {
        let dir = match word.strip_prefix("--config-dir") {
            Some("") => rest.next()?,
            Some(value) => value.strip_prefix('=')?,
            None => continue,
        };
        if dir.is_empty() {
            return None;
        }
        dirs.push(PathBuf::from(dir));
    }
    if user.is_some() && !dirs.is_empty() {
        return None;
    }
    Some((dirs, user))
}

/// The words of `command` as every shell a harness runs it with reads them
/// alike (POSIX sh, PowerShell, Git Bash): plain characters and
/// single-quoted strings. `None` for anything those shells read differently
/// or expand (other quotes, escapes, variables, globs, operators).
fn plain_words(command: &str) -> Option<Vec<String>> {
    // Not `@` or `,`, which PowerShell reads as splatting and arrays.
    const PLAIN: &[char] = &['/', '.', '_', '-', '=', ':'];
    const QUOTES: &[char] = &['\u{2018}', '\u{2019}', '\u{201a}', '\u{201b}'];
    let (mut words, mut word, mut started) = (Vec::new(), String::new(), false);
    let mut chars = command.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\'' {
            started = true;
            loop {
                match chars.next()? {
                    '\'' => break,
                    c if QUOTES.contains(&c) => return None,
                    c => word.push(c),
                }
            }
            // `''` is a quote inside PowerShell's single quotes, nothing in sh.
            if chars.peek() == Some(&'\'') {
                return None;
            }
        } else if c == ' ' || c == '\t' {
            if started {
                words.push(std::mem::take(&mut word));
                started = false;
            }
        } else if c.is_alphanumeric() || PLAIN.contains(&c) {
            started = true;
            word.push(c);
        } else {
            return None;
        }
    }
    if started {
        words.push(word);
    }
    Some(words)
}

/// The pinned state directory, if `--state-dir` pinned one.
fn pinned_state_dir() -> Option<PathBuf> {
    PINNED_STATE_DIR.get().cloned()
}

/// The user config root to pin in a generated hook command: the one the
/// environment names now, if it exists. One that does not exist is not pinned,
/// because most installs have no config and a pinned root that is missing does
/// not load.
fn user_root_to_pin() -> Option<PathBuf> {
    crate::config::user_config_root().filter(|root| std::fs::symlink_metadata(root).is_ok())
}

/// `command` with `switch root` appended, quoted for the shell the harness
/// runs it with: POSIX sh, or on Windows PowerShell or Git Bash, where single
/// quotes are literal in both (`None` when `root` holds a quote there, or is
/// not UTF-8).
fn pin_command(
    command: &str,
    switch: &str,
    root: &std::path::Path,
    windows: bool,
) -> Option<String> {
    let root = root.to_str()?;
    let quoted = if windows {
        if root.contains(['\'', '‘', '’', '‚', '‛']) {
            return None;
        }
        format!("'{root}'")
    } else {
        format!("'{}'", root.replace('\'', r"'\''"))
    };
    Some(format!("{command} {switch} {quoted}"))
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

/// `check` switches: the config roots, and `--rules`.
fn check_flags(flags: &[&str]) -> Option<(Vec<PathBuf>, bool)> {
    let mut roots = Vec::new();
    let mut list_rules = false;
    let mut flags = flags.iter().copied();
    while let Some(flag) = flags.next() {
        match flag {
            "--rules" => list_rules = true,
            "--config-dir" => {
                roots.push(flag);
                roots.push(flags.next()?);
            }
            _ => roots.push(flag),
        }
    }
    Some((config_dirs(&roots)?, list_rules))
}

/// Hook-only switches, without mistaking a config directory's spelling for
/// a switch. The common parser still owns config-root validation.
fn hook_flags(flags: &[&str]) -> Option<(Vec<PathBuf>, bool, bool, bool)> {
    let mut roots = Vec::new();
    let (mut json_reply, mut detect_only, mut expect_enforce) = (false, false, false);
    let mut flags = flags.iter().copied();
    while let Some(flag) = flags.next() {
        match flag {
            "--json-reply" => json_reply = true,
            "--detect-only" => detect_only = true,
            EXPECT_ENFORCE => expect_enforce = true,
            "--config-dir" => {
                roots.push(flag);
                roots.push(flags.next()?);
            }
            _ => roots.push(flag),
        }
    }
    // One asks for less than the configuration says, the other for more.
    if detect_only && expect_enforce {
        return None;
    }
    Some((
        config_dirs(&roots)?,
        json_reply,
        detect_only,
        expect_enforce,
    ))
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
    evaluator::panic_if_forced("config");
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
        tamper_prevention: settings.hooks.tamper_prevention_enabled.value,
        test_signatures: settings.hooks.test_signatures_enabled.value,
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
    config.pinned_over = pinned_over(&settings.hooks);
    if let Some(state) = pinned_state_dir() {
        // A pinned state directory holds the records file, unless the
        // settings files name one.
        config.telemetry_path = settings.hooks.telemetry_path_in_files().0;
        config.state_dir = Some(state);
    }
    config.validate().map_err(|error| error.to_string())?;
    config.make_paths_absolute();
    Ok(config)
}

/// The sources whose value a pin on this hook command replaced, by name,
/// sorted: a source counts when it is set and its value differs from what
/// the pin put in its place. `--state-dir` replaces the source that would
/// have decided the state directory (its variable, `hooks.state_dir`, or the
/// variable the default follows), and the records file variable: the records
/// file of a hook with `--state-dir` is the one its state directory and
/// settings files give. `--user-config-dir` replaces the variable that names
/// the user root. `--config-dir` names nothing.
fn pinned_over(hooks: &crate::settings::HooksSettings) -> Vec<String> {
    let absolute = |path: &std::path::Path| std::path::absolute(path).unwrap_or(path.to_owned());
    let mut names = std::collections::BTreeSet::new();
    if let Some(state) = pinned_state_dir()
        && let Some((name, dir)) = hooks
            .state_dir_source()
            .or_else(telltale_core::hooks::config::default_state_dir_source)
        && absolute(&dir) != state
    {
        names.insert(name);
    }
    if let Some(state) = pinned_state_dir()
        && let (in_files, Some(environment)) = hooks.telemetry_path_in_files()
        && absolute(&environment) != absolute(&in_files.unwrap_or(state.join("telemetry.jsonl")))
    {
        names.insert(crate::settings::TELEMETRY_ENV);
    }
    if let Some(pinned) = crate::config::pinned_user_config_root()
        && let Some((name, root)) = crate::config::user_config_root_source()
        && absolute(&root) != absolute(pinned)
    {
        names.insert(name);
    }
    names.into_iter().map(str::to_owned).collect()
}

/// Whether a settings file in `config_dirs` says `hooks.mode: enforce`, asked
/// only when the configuration did not load. Lenient on purpose: it reads
/// every `settings.d` file it can, skipping what it cannot, and as plain lines
/// when a file is not YAML. One such file is enough, so a broken file next to
/// one that enforces cannot turn enforcement off.
fn settings_declare_enforce(config_dirs: &[PathBuf]) -> bool {
    evaluator::panic_if_forced("declare");
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

/// The config roots `check` read, in precedence order, and where each comes
/// from. A user root that is not pinned follows the environment, so a hook
/// launched in another one can read another root.
fn print_config_roots(config_dirs: &[PathBuf]) {
    let pinned = crate::config::pinned_user_config_root();
    for root in crate::config::config_roots(config_dirs) {
        let origin = if !config_dirs.is_empty() {
            "--config-dir"
        } else if pinned == Some(root.as_path()) {
            "user, pinned"
        } else if crate::config::user_config_root().as_ref() == Some(&root) {
            "user, from XDG_CONFIG_HOME or HOME: not pinned"
        } else {
            "system"
        };
        let missing = if root.exists() { "" } else { ", absent" };
        println!("config root: {} ({origin}{missing})", root.display());
    }
}

/// What each enforcement test signature gets under the configuration in
/// effect, one line per rule under `tth.test.`: its command, score and the
/// verdict a hook reaches for it, or what turned it off.
fn test_signature_lines(
    effective: &telltale_core::EffectiveConfigurationV1,
    config: &Config,
) -> Vec<String> {
    use telltale_core::hooks::config::TEST_RULE_ID_PREFIX;
    use telltale_core::hooks::policy::{self, Inputs};
    use telltale_core::hooks::state::Verdict;
    use telltale_core::{DefinitionKindV1, DisabledByV1, RuleTierV1};
    effective
        .definitions
        .iter()
        .filter(|definition| {
            definition.kind == DefinitionKindV1::Rule
                && definition.id.starts_with(TEST_RULE_ID_PREFIX)
        })
        .map(|definition| {
            let id: String = definition
                .id
                .chars()
                .map(|c| if c.is_control() { ' ' } else { c })
                .collect();
            let off = match definition.disabled_by {
                None => None,
                Some(DisabledByV1::Definition) => Some("its definition"),
                Some(DisabledByV1::Override) => Some("an override"),
                Some(DisabledByV1::Policy) => Some("the policy"),
            };
            if let Some(by) = off {
                return format!("  {id}: off (disabled by {by})");
            }
            let score = definition.action_score.unwrap_or(definition.session_score);
            let verdict = match policy::decide(
                Inputs {
                    action_score: score,
                    session_score: 0,
                    denied_attempts: 0,
                },
                &config.thresholds,
            )
            .verdict
            {
                Verdict::Deny => "deny",
                Verdict::Ask => "ask",
                Verdict::Allow => "no opinion (below the ask threshold)",
            };
            // The bundled rule's command is its marker; a replacement from a
            // config root may match something else.
            let command = match (definition.tier, id.strip_prefix(TEST_RULE_ID_PREFIX)) {
                (RuleTierV1::Builtin, Some(marker)) => {
                    format!("`echo TELLTALE_TEST_{}` ", marker.to_ascii_uppercase())
                }
                _ => "replaced by a rule from a config root, ".to_owned(),
            };
            format!("  {id}: {command}scores {score}: {verdict}")
        })
        .collect()
}

/// One line of `check --rules`: a rule or chain as it takes effect.
/// Tab-separated: name, kind, `enabled` or what turned it off, score, tier
/// (and the tier it replaced), then each override applied to it in order.
fn effective_rule_line(definition: &telltale_core::EffectiveDefinitionV1) -> String {
    use telltale_core::{DefinitionKindV1, DisabledByV1};
    // Rule names and override reasons are operator text.
    let plain = |text: &str| -> String {
        text.chars()
            .map(|c| if c.is_control() { ' ' } else { c })
            .collect()
    };
    // The tier's name as the effective configuration spells it.
    fn label(tier: telltale_core::RuleTierV1) -> String {
        serde_json::to_value(tier)
            .ok()
            .and_then(|value| value.as_str().map(str::to_owned))
            .unwrap_or_default()
    }
    let kind = match definition.kind {
        DefinitionKindV1::Rule => "rule",
        DefinitionKindV1::Modifier => "chain",
        DefinitionKindV1::ProcessChain => "process-chain",
    };
    let state = match definition.disabled_by {
        None => "enabled",
        Some(DisabledByV1::Definition) => "disabled by its definition",
        Some(DisabledByV1::Override) => "disabled by override",
        Some(DisabledByV1::Policy) => "disabled by policy",
    };
    let tier = match definition.replaced_tier {
        Some(replaced) => format!("{} (replaces {})", label(definition.tier), label(replaced)),
        None => label(definition.tier),
    };
    // Hooks decide on action scores, which for some bundled rules and chains
    // differ from the score a session event carries.
    let score = match definition.action_score {
        Some(action) if action != definition.session_score => {
            format!("score {} (action {action})", definition.session_score)
        }
        _ => format!("score {}", definition.session_score),
    };
    let overrides = if definition.overrides.is_empty() {
        "-".to_owned()
    } else {
        definition
            .overrides
            .iter()
            .map(|applied| {
                let mut sets = Vec::new();
                if let Some(enabled) = applied.enabled {
                    sets.push(format!("enabled={enabled}"));
                }
                if let Some(score) = applied.score {
                    sets.push(format!("score={score}"));
                }
                format!("override {} ({})", sets.join(" "), plain(&applied.reason))
            })
            .collect::<Vec<_>>()
            .join("; ")
    };
    format!(
        "{}\t{kind}\t{state}\t{score}\t{tier}\t{overrides}",
        plain(&definition.id)
    )
}

fn check(config_dirs: &[PathBuf], list_rules: bool) -> i32 {
    let config = match load_config(config_dirs) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("config: {error}");
            return 1;
        }
    };
    match Engine::new(&config.rules, &config.protected_paths()) {
        Ok(engine) => {
            print_config_roots(config_dirs);
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
            let thresholds = &config.thresholds;
            println!(
                "thresholds: ask at action score {} or session score {}, deny at action score {} or session score {}, repeated denials: {}",
                thresholds.action_ask,
                thresholds.session_ask,
                thresholds.action_deny,
                thresholds.session_deny,
                thresholds.repeated_denials
            );
            let effective = match engine.effective_configuration() {
                Ok(effective) => effective,
                Err(error) => {
                    eprintln!("telltale: {error}");
                    return 1;
                }
            };
            let generated = engine.generated_coverage();
            if config.rules.self_protection {
                println!(
                    "self-protection: {} paths in {} generated rules",
                    generated.paths, generated.rules
                );
                // Without tamper prevention an override, a policy or a
                // replacement can turn these rules off; say how many run.
                let (enabled, all) = effective
                    .definitions
                    .iter()
                    .filter(|definition| {
                        definition
                            .id
                            .starts_with(telltale_core::hooks::config::HOST_RULE_ID_PREFIX)
                    })
                    .fold((0, 0), |(enabled, all), definition| {
                        (
                            enabled + usize::from(definition.disabled_by.is_none()),
                            all + 1,
                        )
                    });
                println!(
                    "self-protection rules: {enabled} of {all} enabled{}",
                    if enabled == all {
                        ""
                    } else {
                        " (an override or the policy turned the others off: check --rules lists them)"
                    }
                );
            } else {
                println!("self-protection: off (hooks.self_protection_rules: false)");
            }
            for id in engine.skipped_overrides() {
                let id: String = id
                    .chars()
                    .map(|c| if c.is_control() { ' ' } else { c })
                    .collect();
                println!("override left out: {id} names no rule that is loaded");
            }
            println!(
                "tamper prevention: {}",
                if config.rules.tamper_prevention {
                    "on (hooks.tamper_prevention.enabled: true): rule content that names a tth.tamper.* rule, or a policy that turns one off, is invalid configuration"
                } else {
                    "off (hooks.tamper_prevention.enabled: false): overrides, policies and replacement rules can tune or turn off the tth.tamper.* rules"
                }
            );
            if config.rules.test_signatures {
                println!(
                    "test signatures: on (hooks.test_signatures.enabled: true), {}",
                    match config.mode {
                        telltale_core::hooks::config::Mode::Enforce =>
                            "verdicts are returned to the harness (an ask as a deny where the harness cannot ask)",
                        telltale_core::hooks::config::Mode::Observe =>
                            "verdicts are recorded and nothing is returned (detect-only)",
                    }
                );
                for line in test_signature_lines(&effective, &config) {
                    println!("{line}");
                }
            } else {
                println!("test signatures: off (hooks.test_signatures.enabled: false)");
            }
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
                    let origin = if pinned_state_dir().is_some() {
                        "pinned".to_owned()
                    } else {
                        format!("from hooks.state_dir or {STATE_LOCATING}: not pinned")
                    };
                    println!("state dir: {} ({origin})", state.display());
                    println!("telemetry: {}", telemetry.display());
                    for name in &config.pinned_over {
                        println!("pinned over: {name}");
                    }
                }
                (Err(error), _) | (_, Err(error)) => {
                    eprintln!("paths: {error}");
                    return 1;
                }
            }
            println!(
                "harness protections (what a harness does on its own, where no Telltale setting turns it on or off; check does not read harness files):"
            );
            for harness in Harness::ALL {
                let adapter = harness.adapter();
                for protection in adapter.harness_protections {
                    println!("  {}: {protection}", adapter.name);
                }
            }
            if list_rules {
                for definition in &effective.definitions {
                    println!("rule: {}", effective_rule_line(definition));
                }
            }
            0
        }
        Err(error) => {
            eprintln!("telltale: {error}");
            // The cause names the file and the rule ID an operator must fix;
            // like every configuration detail it goes to stderr only.
            let mut cause = std::error::Error::source(&error);
            while let Some(source) = cause {
                eprintln!("  caused by: {source}");
                cause = source.source();
            }
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
///
/// While enforcing, a panic gets the answer of a payload the hook could not
/// read, with an `error` record (`hook_panicked`): during evaluation, the
/// stricter of `on_error` and `on_unevaluable` for a tool call; while reading
/// the payload, the block for one that names no event; while loading the
/// configuration, the answer of a configuration that did not load.
fn hook(
    harness: Harness,
    config_dirs: &[PathBuf],
    json_reply: bool,
    detect_only: bool,
    expect_enforce: bool,
) -> i32 {
    // The hook's one deadline counts from here (`Limits::hook_deadline`).
    let started = Instant::now();
    // A panic anywhere before the answer is caught, since most harnesses read
    // a crash as "run the call". A configuration whose loading panicked did
    // not load.
    let loaded = caught(|| load_config(config_dirs))
        .unwrap_or_else(|| {
            Err(format!(
                "loading the configuration panicked ({HOOK_PANICKED})"
            ))
        })
        .map(|mut config| {
            if detect_only {
                config.mode = telltale_core::hooks::config::Mode::Observe;
            }
            config
        });
    let gate = if detect_only {
        Gate::DetectOnly
    } else {
        // A panic while asking whether a configuration that did not load
        // asks for enforcement is no answer of "no": as with a broken file
        // next to one that enforces, breakage cannot turn enforcement off.
        // `--expect-enforce` counts only for a configuration that did not
        // load, like a settings file that says `hooks.mode: enforce`.
        caught(|| {
            Gate::for_config(&loaded, || {
                expect_enforce || settings_declare_enforce(config_dirs)
            })
        })
        .unwrap_or(Gate::Enforce)
    };
    if gate == Gate::DetectOnly {
        // Detached: the process exits when `hook` returns. A thread that
        // cannot start leaves the harness's own timeout.
        let _ = std::thread::Builder::new().spawn(|| {
            std::thread::sleep(DETECT_ONLY_DEADLINE);
            eprintln!(
                "telltale hooks: detect-only hook gave up after {} s without an answer",
                DETECT_ONLY_DEADLINE.as_secs()
            );
            std::process::exit(0);
        });
    }
    let config = caught(|| resolve_config(harness, loaded, gate)).unwrap_or(Err(()));
    let answer = match caught(read_payload) {
        Some(None) => Answer::exit(1),
        Some(Some(bytes)) => caught(|| evaluate(harness, &config, &bytes, config_dirs, started))
            .unwrap_or_else(|| unreadable_answer(harness, &config, HOOK_PANICKED, &bytes)),
        // The payload is lost with the panic: it names no event.
        None => unreadable_answer(harness, &config, HOOK_PANICKED, &[]),
    };
    let answer = gate.release(answer);
    if json_reply {
        // Optional subprocess framing, AFTER the gate. A no-op is explicit;
        // empty/truncated stdout is never a successful reply. Native command
        // hooks keep their original stdout and exit semantics.
        deliver(Answer {
            output: Some(serde_json::json!({
                "protocol": "telltale.hook-reply.v1",
                "mode": gate.as_str(),
                "output": answer.output,
            })),
            exit_code: answer.exit_code,
        })
    } else {
        deliver(answer)
    }
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
    evaluator::panic_if_forced("read");
    Some(bytes)
}

/// The error code of a hook that panicked, recorded and named in its answer.
const HOOK_PANICKED: &str = "hook_panicked";

/// `f`'s value, or `None` if it panicked. Release builds unwind (the
/// `compile_error!` above), so a panic reaches this rather than ending the
/// process with a status the harness may read as "run the call".
fn caught<T>(f: impl FnOnce() -> T) -> Option<T> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).ok()
}

/// [`Runtime::record_unhandled`] under `config`. A panic while recording is
/// caught here, so it cannot change an answer already decided.
fn record_unhandled(config: &Config, harness: Harness, hook_event: &str, code: &str) {
    let recorded = caught(|| {
        evaluator::panic_if_forced("record");
        Runtime::new(config.clone()).record_unhandled(harness.name(), hook_event, code);
    });
    if recorded.is_none() {
        eprintln!("telltale hooks: recording {code} panicked");
    }
}

/// Build the answer for one payload under `config` (`Err` when it did not
/// load and the gate is enforcing). Tries the long-lived evaluator, then
/// evaluates in-process; an unanswered pre-execution event never turns into
/// an allow. Writes nothing to stdout and exits nothing: the caller's gate
/// releases the answer or does not.
fn evaluate(
    harness: Harness,
    config: &Result<Config, ()>,
    bytes: &[u8],
    config_dirs: &[PathBuf],
    started: Instant,
) -> Answer {
    let oversized = bytes.len() as u64 > MAX_PAYLOAD_BYTES;
    let parsed = if oversized {
        Parsed::Invalid("payload_oversized")
    } else {
        harness.parse(bytes)
    };
    // Split into the hook event name and either the runtime event or the
    // reason it is unusable; an unreadable payload is answered right here.
    let (hook_event, usable) = match parsed {
        Parsed::Event(ctx, event) => (ctx.hook_event.clone(), Ok((ctx, event))),
        Parsed::Unusable { hook_event, code } => (hook_event, Err(code)),
        Parsed::Invalid(code) => return unreadable_answer(harness, config, code, bytes),
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
        Err(code) => return unusable_event_answer(harness, config, &hook_event, code),
    };
    answer_from_runtime(
        harness,
        config.clone(),
        ctx,
        event,
        bytes,
        config_dirs,
        started,
    )
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
    // (the gate is already closed): detection carries on with the defaults.
    // Either way the failure is recorded where records go without a
    // configuration (best effort: it never changes the answer).
    match loaded {
        Ok(config) => Ok(config),
        Err(error) => {
            // Details (which may include a path) go to stderr only.
            eprintln!("telltale hooks: {error}");
            let config = fallback_config();
            record_unhandled(&config, harness, "", "config_invalid");
            if gate == Gate::Enforce {
                Err(())
            } else {
                eprintln!(
                    "telltale hooks: the configuration did not load and does not set hooks.mode: enforce: detect-only with the defaults"
                );
                Ok(config)
            }
        }
    }
}

/// The configuration of a hook whose configuration did not load: the
/// defaults, with the state directory and records file it can determine. A
/// pinned state directory holds the records file.
fn fallback_config() -> Config {
    match pinned_state_dir() {
        Some(state) => Config::detect_only_fallback(Some(state), None),
        None => Config::detect_only_fallback(
            env_path(crate::settings::STATE_DIR_ENV),
            env_path(crate::settings::TELEMETRY_ENV),
        ),
    }
}

/// The answer for a payload that could not be parsed at all (oversized or
/// malformed), or for one whose handling panicked (`hook_panicked`), under
/// `config` (`Err` when it did not load and the gate is enforcing). Either is
/// agent-influenced (a huge or damaged tool input, or one that makes the hook
/// panic), so it gets the policy for a call the hook could not read rather
/// than a non-blocking exit that the harness treats as allow.
fn unreadable_answer(
    harness: Harness,
    config: &Result<Config, ()>,
    code: &'static str,
    bytes: &[u8],
) -> Answer {
    let (call_reason, payload_reason) = if code == HOOK_PANICKED {
        eprintln!("telltale hooks: the hook panicked ({code})");
        let reason = "Telltale Hooks failed while evaluating this tool call (hook_panicked).";
        (reason, reason)
    } else {
        eprintln!("telltale hooks: unusable hook payload ({code})");
        (
            "Telltale Hooks could not read this tool call (payload too large or malformed).",
            "Telltale Hooks could not read this hook payload and fails closed.",
        )
    };
    let policy = match config {
        Ok(config) => unreadable_call_policy(config),
        Err(()) => OnError::Deny,
    };
    let answer = if harness.looks_like_pre_tool_use(bytes) {
        Answer::output(harness.render_verdict(policy, call_reason))
    } else if policy == OnError::Allow || names_event(bytes) {
        // A named event is not pre-execution by now, and exit 2 there is
        // not a block: on a Stop it is a prompt to continue, so a damaged
        // Stop would re-prompt the model without limit (Codex: E2E
        // `damaged-stop-*`).
        Answer::exit(1)
    } else {
        // No event name: this could be a tool call. Without its event it
        // cannot be asked about, so `ask` blocks as `deny` does, with the
        // harness's block that makes no prompt of anything else.
        match harness.adapter().nameless_block {
            NamelessBlock::DenyOnStdout => {
                Answer::output(harness.render_verdict(OnError::Deny, payload_reason))
            }
            NamelessBlock::Exit(status) => Answer::exit(status),
        }
    };
    if let Ok(config) = config {
        record_unhandled(config, harness, "", code);
    }
    answer
}

/// The answer for a payload that parsed but lacks what the event needs.
fn unusable_event_answer(
    harness: Harness,
    config: &Config,
    hook_event: &str,
    code: &'static str,
) -> Answer {
    eprintln!("telltale hooks: unusable hook payload ({code})");
    record_unhandled(config, harness, hook_event, code);
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
    started: Instant,
) -> Answer {
    // The runtime's waits are cut to what is left of the hook's deadline, and
    // so is the wait for the evaluator.
    let runtime = |config: Config| Runtime::new(config).started_at(started);
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
    // A session start is recorded in-process, with the sources this
    // invocation's pins replaced (`Config::pinned_over`). It builds no
    // pipeline, so the evaluator would save nothing; the next evaluated
    // event starts the evaluator when none is running.
    #[cfg(unix)]
    if config.evaluator.enabled
        && !matches!(event, Event::SessionStart { .. })
        && let Ok(socket) = config.resolved_socket_path()
    {
        let remaining = Limits::default()
            .hook_deadline
            .saturating_sub(started.elapsed());
        let timeout =
            std::time::Duration::from_millis(config.evaluator.request_timeout_ms).min(remaining);
        let asked_at = telltale_core::hooks::runtime::now_ms();
        match evaluator::request(&socket, harness, &config.fingerprint(), bytes, timeout) {
            ClientOutcome::Answered(output) => return Answer::output(output),
            ClientOutcome::DeliveredNoAnswer(code) => {
                let mut runtime = runtime(config);
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
    let mut runtime = runtime(config);
    runtime.set_evaluator("in_process", fallback);
    evaluator::panic_if_forced("evaluate");
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
    if let Some(root) = crate::config::pinned_user_config_root() {
        args.push(OsString::from(USER_CONFIG_DIR));
        args.push(
            std::path::absolute(root)
                .unwrap_or_else(|_| root.to_path_buf())
                .into_os_string(),
        );
    }
    if let Some(state) = pinned_state_dir() {
        args.push(OsString::from(STATE_DIR));
        args.push(state.into_os_string());
    }
    args
}

fn serve(config_dirs: &[PathBuf]) -> i32 {
    let config = match load_config(config_dirs) {
        // The evaluator's own launch is no hook's: it names nothing.
        Ok(config) => Config {
            pinned_over: Vec::new(),
            ..config
        },
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

    use super::{
        STATE_DIR, USER_CONFIG_DIR, command_roots, config_dirs, declares_enforce, hook_flags,
        load_config, pin_command, split_pin,
    };

    #[test]
    fn each_pin_is_one_value_and_passes_over_other_directory_values() {
        for switch in [USER_CONFIG_DIR, STATE_DIR] {
            assert_eq!(
                split_pin(&["--json-reply", switch, "/a b"], switch),
                Some((vec!["--json-reply"], Some(PathBuf::from("/a b")))),
                "{switch}"
            );
            assert_eq!(
                split_pin(&["--config-dir", switch], switch),
                Some((vec!["--config-dir", switch], None)),
                "{switch}"
            );
            let joined = format!("{switch}=/a");
            assert_eq!(
                split_pin(&[joined.as_str()], switch),
                Some((Vec::new(), Some(PathBuf::from("/a")))),
                "{switch}"
            );
            let (empty, glued) = (format!("{switch}="), format!("{switch}x"));
            for refused in [
                &[switch][..],
                &[empty.as_str()],
                &[switch, ""],
                &[switch, "/a", switch, "/b"],
                &[glued.as_str()],
            ] {
                assert_eq!(split_pin(refused, switch), None, "{refused:?}");
            }
        }
        // Either pin's value may be spelled like the other switch.
        assert_eq!(
            split_pin(&[STATE_DIR, USER_CONFIG_DIR], USER_CONFIG_DIR),
            Some((vec![STATE_DIR, USER_CONFIG_DIR], None))
        );
        assert_eq!(
            split_pin(&[USER_CONFIG_DIR, STATE_DIR], STATE_DIR),
            Some((vec![USER_CONFIG_DIR, STATE_DIR], None))
        );
    }

    /// POSIX sh reads `'\''` as a quote inside single quotes; PowerShell and Git
    /// Bash both read single quotes literally, and have no common escape for
    /// one, so a Windows path holding a quote is not pinned.
    #[test]
    fn the_pin_is_quoted_for_the_harness_shell() {
        for switch in [USER_CONFIG_DIR, STATE_DIR] {
            assert_eq!(
                pin_command(
                    "t hooks claude-code hook",
                    switch,
                    Path::new("/h/it's a $dir"),
                    false
                ),
                Some(format!(
                    r"t hooks claude-code hook {switch} '/h/it'\''s a $dir'"
                ))
            );
            assert_eq!(
                pin_command(
                    "t hooks copilot-cli hook",
                    switch,
                    Path::new(r"C:\Users\a b\AppData\Local\telltale"),
                    true
                ),
                Some(format!(
                    r"t hooks copilot-cli hook {switch} 'C:\Users\a b\AppData\Local\telltale'"
                ))
            );
        }
        for quoted in [r"C:\Users\o'b\.config", "C:\\Users\\o\u{2019}b\\.config"] {
            for switch in [USER_CONFIG_DIR, STATE_DIR] {
                let pinned = pin_command("t", switch, Path::new(quoted), true);
                assert_eq!(pinned, None, "{quoted}");
            }
        }
    }

    /// Only what every harness shell reads alike names a command's roots.
    #[test]
    fn a_command_names_its_roots_only_when_every_shell_reads_them_alike() {
        assert_eq!(
            command_roots("'/opt/t b' hooks x hook --config-dir '/a b' --config-dir=/c"),
            Some((vec![PathBuf::from("/a b"), PathBuf::from("/c")], None))
        );
        assert_eq!(
            command_roots(r"'C:\t.exe' hooks x hook --user-config-dir 'C:\u r'"),
            Some((Vec::new(), Some(PathBuf::from(r"C:\u r"))))
        );
        for unreadable in [
            "t hook --config-dir \"/a b\"",
            r"t hook --config-dir /a\ b",
            "t hook --config-dir $HOME/c",
            "t hook --config-dir '/it'\\''s'",
            "t hook --config-dir 'a''b'",
            "t hook --config-dir '/a",
            "t hook --config-dir /a; rm x",
            "t hook --config-dir",
            "t hook --config-dir /a --user-config-dir /b",
        ] {
            assert_eq!(command_roots(unreadable), None, "{unreadable}");
        }
    }

    #[test]
    fn hook_switches_do_not_consume_a_config_directory_named_like_a_switch() {
        assert_eq!(
            hook_flags(&["--json-reply", "--config-dir", "--detect-only"]),
            Some((vec![PathBuf::from("--detect-only")], true, false, false))
        );
        assert_eq!(
            hook_flags(&["--detect-only", "--config-dir=root", "--json-reply"]),
            Some((vec![PathBuf::from("root")], true, true, false))
        );
        assert_eq!(hook_flags(&["--json-reply", "--config-dir"]), None);
        assert_eq!(
            hook_flags(&["--expect-enforce"]),
            Some((Vec::new(), false, false, true))
        );
        assert_eq!(hook_flags(&["--expect-enforce", "--detect-only"]), None);
    }

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
