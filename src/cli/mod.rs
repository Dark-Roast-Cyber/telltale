use std::fs;
use std::path::{Path, PathBuf};

use crate::clients::{ClientId, SourceKind, supported_clients};
use crate::detection::detect_sources_with_rules;
use crate::discovery::Source;
use crate::paths::{self, PathProfile};
use crate::rules::{RuleLoadMode, load_rule_set_from_paths_with_mode_and_override_paths};
use clap::{Args as ClapArgs, Parser, Subcommand, ValueEnum};

mod coverage;
mod export;
mod rules_server;
mod scan;

#[derive(Debug, Parser)]
#[command(
    name = "adr",
    about = "Telltale detection layer for AI coding agent sessions",
    version = concat!(env!("CARGO_PKG_VERSION"), " (", env!("ADR_GIT_HASH"), ")")
)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Discover supported local session sources.
    Scan {
        /// Run one batch scan and exit.
        #[arg(long)]
        once: bool,

        /// Seconds to wait between periodic scans.
        #[arg(long)]
        interval_seconds: Option<u64>,

        /// Cap periodic scans after this many iterations.
        #[arg(long)]
        iterations: Option<u32>,

        /// Root containing codex/ and opencode/ session stores.
        #[arg(long, default_value = ".")]
        root: PathBuf,

        /// Default path profile used when --log-path or --state-path is not set.
        #[arg(long, value_enum, default_value = "user")]
        path_profile: CliPathProfile,

        /// Append-only JSONL event path. Defaults to ADR_LOG_PATH or the selected path profile.
        #[arg(long)]
        log_path: Option<PathBuf>,

        /// Optional Splunk HEC collector URL. Requires --splunk-hec-token.
        #[arg(long)]
        splunk_hec_endpoint: Option<String>,

        /// Optional Splunk HEC token. Requires --splunk-hec-endpoint.
        #[arg(long)]
        splunk_hec_token: Option<String>,

        /// JSON state path for duplicate suppression. Defaults to ADR_STATE_PATH or the selected path profile.
        #[arg(long)]
        state_path: Option<PathBuf>,

        /// Print the event summary without writing JSONL.
        #[arg(long)]
        dry_run: bool,

        /// Emit per-session activity summary events in addition to detections.
        #[arg(long)]
        emit_activity: bool,

        /// Emit per-session risk summary events derived from activity and detection events.
        #[arg(long)]
        emit_session_risk_summary: bool,

        /// Allow scanning fixture/demo roots and writing events to log paths.
        /// Without this flag, non-dry-run scans refuse fixture roots to prevent
        /// synthetic data from mixing into production telemetry.
        #[arg(long)]
        allow_fixtures: bool,

        /// Skip duplicate suppression for a one-time retroactive backfill.
        /// All events are emitted regardless of state file contents.
        #[arg(long)]
        backfill: bool,

        /// Reparse all discovered sources to rebuild precise baseline/source-observation state.
        /// Detection duplicate suppression still uses existing state.
        #[arg(long)]
        rebuild_baselines: bool,

        /// YAML rule file to add. Repeat to load multiple files in addition to bundled rules.
        #[arg(long = "rules")]
        rule_paths: Vec<PathBuf>,

        #[command(flatten)]
        local_config: LocalConfigCliArgs,

        /// Do not load bundled default rules. Use only rules passed with --rules.
        #[arg(long)]
        no_default_rules: bool,

        /// YAML policy file that selects active rule categories and rule ids.
        #[arg(long)]
        policy: Option<PathBuf>,

        /// YAML allowlist file that marks matching detections as suppressed.
        #[arg(long)]
        allowlist: Option<PathBuf>,

        /// Opt in to bounded risk-score modifiers for model baseline deviations in activity events.
        /// Has effect only when --emit-activity is also set.
        #[arg(long)]
        baseline_deviation_scoring: bool,

        /// Limit scan discovery to one supported client. Repeat to include multiple clients.
        #[arg(long = "client", value_parser = parse_client_id)]
        clients: Vec<ClientId>,

        /// Deterministically cap discovered sources after client filtering.
        #[arg(long, value_parser = parse_nonzero_usize)]
        max_sources: Option<usize>,

        /// Project config YAML file listing project roots. Repeat for multiple files.
        #[arg(long = "project-config")]
        project_config_paths: Vec<PathBuf>,

        /// Maximum size in bytes before the active JSONL file is rotated.
        /// Defaults to ADR_LOG_ROTATE_MAX_SIZE or 104857600 (100 MB). 0 disables rotation.
        #[arg(long)]
        log_rotate_max_size: Option<u64>,

        /// Number of rotated files to keep. Defaults to ADR_LOG_ROTATE_KEEP or 5.
        #[arg(long)]
        log_rotate_keep: Option<usize>,

        /// Disable built-in rotation. Use when an external rotator (logrotate, newsyslog) manages the file.
        #[arg(long)]
        log_rotate_disabled: bool,

        /// Seconds between metadata-only installed-agent inventory observations.
        /// Defaults to ADR_INSTALL_INVENTORY_INTERVAL_SECONDS or 86400. Use 0 to collect every scan.
        #[arg(long)]
        install_inventory_interval_seconds: Option<u64>,

        /// Disable installed-agent inventory observations for this scan.
        #[arg(long)]
        install_inventory_disabled: bool,
    },

    /// Watch local session stores and scan when files change.
    Watch {
        /// Root containing codex/ and opencode/ session stores.
        #[arg(long, default_value = ".")]
        root: PathBuf,

        /// Default path profile used when --log-path or --state-path is not set.
        #[arg(long, value_enum, default_value = "user")]
        path_profile: CliPathProfile,

        /// Append-only JSONL event path. Defaults to ADR_LOG_PATH or the selected path profile.
        #[arg(long)]
        log_path: Option<PathBuf>,

        /// JSON state path for duplicate suppression. Defaults to ADR_STATE_PATH or the selected path profile.
        #[arg(long)]
        state_path: Option<PathBuf>,

        /// Print event summaries without writing JSONL.
        #[arg(long)]
        dry_run: bool,

        /// Emit per-session activity summary events in addition to detections.
        #[arg(long)]
        emit_activity: bool,

        /// Emit per-session risk summary events derived from activity and detection events.
        #[arg(long)]
        emit_session_risk_summary: bool,

        /// Allow scanning fixture/demo roots and writing events to log paths.
        #[arg(long)]
        allow_fixtures: bool,

        /// Cap watch-triggered scans after this many iterations.
        #[arg(long)]
        iterations: Option<u32>,

        /// Milliseconds to wait after a filesystem event before scanning.
        #[arg(long, default_value_t = 500)]
        debounce_ms: u64,

        /// YAML rule file to add. Repeat to load multiple files in addition to bundled rules.
        #[arg(long = "rules")]
        rule_paths: Vec<PathBuf>,

        #[command(flatten)]
        local_config: LocalConfigCliArgs,

        /// Do not load bundled default rules. Use only rules passed with --rules.
        #[arg(long)]
        no_default_rules: bool,

        /// YAML policy file that selects active rule categories and rule ids.
        #[arg(long)]
        policy: Option<PathBuf>,

        /// YAML allowlist file that marks matching detections as suppressed.
        #[arg(long)]
        allowlist: Option<PathBuf>,

        /// Opt in to bounded risk-score modifiers for model baseline deviations in activity events.
        /// Has effect only when --emit-activity is also set.
        #[arg(long)]
        baseline_deviation_scoring: bool,

        /// Limit watched scan discovery to one supported client. Repeat to include multiple clients.
        #[arg(long = "client", value_parser = parse_client_id)]
        clients: Vec<ClientId>,

        /// Project config YAML file listing project roots. Repeat for multiple files.
        #[arg(long = "project-config")]
        project_config_paths: Vec<PathBuf>,

        /// Maximum size in bytes before the active JSONL file is rotated.
        /// Defaults to ADR_LOG_ROTATE_MAX_SIZE or 104857600 (100 MB). 0 disables rotation.
        #[arg(long)]
        log_rotate_max_size: Option<u64>,

        /// Number of rotated files to keep. Defaults to ADR_LOG_ROTATE_KEEP or 5.
        #[arg(long)]
        log_rotate_keep: Option<usize>,

        /// Disable built-in rotation. Use when an external rotator (logrotate, newsyslog) manages the file.
        #[arg(long)]
        log_rotate_disabled: bool,

        /// Seconds between metadata-only installed-agent inventory observations.
        /// Defaults to ADR_INSTALL_INVENTORY_INTERVAL_SECONDS or 86400. Use 0 to collect every scan.
        #[arg(long)]
        install_inventory_interval_seconds: Option<u64>,

        /// Disable installed-agent inventory observations for watched scans.
        #[arg(long)]
        install_inventory_disabled: bool,
    },

    /// Inspect and validate Telltale detection rules.
    Rules {
        #[command(subcommand)]
        command: RulesCommand,
    },

    /// Validate local Telltale configuration.
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },

    /// Show scanner status from the most recent health event.
    Status {
        /// Default path profile used when --log-path or --state-path is not set.
        #[arg(long, value_enum, default_value = "user")]
        path_profile: CliPathProfile,

        /// Append-only JSONL event path. Defaults to ADR_LOG_PATH or the selected path profile.
        #[arg(long)]
        log_path: Option<PathBuf>,

        /// JSON state path for duplicate suppression. Defaults to ADR_STATE_PATH or the selected path profile.
        #[arg(long)]
        state_path: Option<PathBuf>,
    },

    /// Export filtered events from a Telltale JSONL log.
    Export {
        /// Default path profile used when --log-path is not set.
        #[arg(long, value_enum, default_value = "user")]
        path_profile: CliPathProfile,

        /// Append-only JSONL event path. Defaults to ADR_LOG_PATH or the selected path profile.
        #[arg(long)]
        log_path: Option<PathBuf>,

        /// Include only events with this severity. Repeat for multiple severities.
        #[arg(long = "severity")]
        severities: Vec<String>,

        /// Include only events for this client. Repeat for multiple clients.
        #[arg(long = "client")]
        clients: Vec<String>,

        /// Include only events for this session id. Repeat for multiple sessions.
        #[arg(long = "session-id")]
        session_ids: Vec<String>,

        /// Include only detections containing this rule id. Repeat for multiple rules.
        #[arg(long = "rule-id")]
        rule_ids: Vec<String>,

        /// Include only events at or after this RFC3339 timestamp.
        #[arg(long)]
        since: Option<String>,

        /// Include only events at or before this RFC3339 timestamp.
        #[arg(long)]
        until: Option<String>,

        /// Output format.
        #[arg(long, value_enum, default_value_t = ExportFormat::Jsonl)]
        format: ExportFormat,

        /// Emit cross-session correlation events derived from filtered detections.
        #[arg(long)]
        correlate: bool,

        /// Produce a redacted session timeline from the filtered events.
        /// Requires --session-id to select a single session; add --client when a session id is ambiguous across clients.
        /// Outputs a structured timeline with detection anchors and triage context.
        #[arg(long)]
        timeline: bool,

        /// Read session stores from this root for --timeline instead of building from JSONL events.
        #[arg(long)]
        source_root: Option<PathBuf>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum CliPathProfile {
    User,
    System,
    Project,
}

impl From<CliPathProfile> for PathProfile {
    fn from(value: CliPathProfile) -> Self {
        match value {
            CliPathProfile::User => PathProfile::User,
            CliPathProfile::System => PathProfile::System,
            CliPathProfile::Project => PathProfile::Project,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub(crate) enum ExportFormat {
    Jsonl,
    Summary,
    TimelineText,
    ElasticBulk,
}

#[derive(Debug, Subcommand)]
enum ConfigCommand {
    /// Validate effective rules, policy, and allowlist configuration.
    Validate {
        /// YAML rule file to add. Repeat to load multiple files in addition to bundled rules.
        #[arg(long = "rules")]
        rule_paths: Vec<PathBuf>,

        #[command(flatten)]
        local_config: LocalConfigCliArgs,

        /// Do not load bundled default rules. Use only rules passed with --rules.
        #[arg(long)]
        no_default_rules: bool,

        /// YAML policy file that selects active rule categories and rule ids.
        #[arg(long)]
        policy: Option<PathBuf>,

        /// YAML allowlist file that marks matching detections as suppressed.
        #[arg(long)]
        allowlist: Option<PathBuf>,
    },
}

#[derive(Debug, Subcommand)]
enum RulesCommand {
    /// List loaded rules.
    List {
        /// YAML rule file to add. Repeat to load multiple files in addition to bundled rules.
        #[arg(long = "rules")]
        rule_paths: Vec<PathBuf>,

        #[command(flatten)]
        local_config: LocalConfigCliArgs,

        /// Do not load bundled default rules. Use only rules passed with --rules.
        #[arg(long)]
        no_default_rules: bool,

        /// YAML policy file that selects active rule categories and rule ids.
        #[arg(long)]
        policy: Option<PathBuf>,
    },

    /// Validate rule and policy YAML.
    Validate {
        /// YAML rule file to add. Repeat to load multiple files in addition to bundled rules.
        #[arg(long = "rules")]
        rule_paths: Vec<PathBuf>,

        #[command(flatten)]
        local_config: LocalConfigCliArgs,

        /// Do not load bundled default rules. Use only rules passed with --rules.
        #[arg(long)]
        no_default_rules: bool,

        /// YAML policy file that selects active rule categories and rule ids.
        #[arg(long)]
        policy: Option<PathBuf>,
    },

    /// Evaluate one Codex-shaped JSONL fixture with the loaded rules.
    Test {
        /// Fixture file to evaluate.
        fixture: PathBuf,

        /// YAML rule file to add. Repeat to load multiple files in addition to bundled rules.
        #[arg(long = "rules")]
        rule_paths: Vec<PathBuf>,

        #[command(flatten)]
        local_config: LocalConfigCliArgs,

        /// Do not load bundled default rules. Use only rules passed with --rules.
        #[arg(long)]
        no_default_rules: bool,

        /// YAML policy file that selects active rule categories and rule ids.
        #[arg(long)]
        policy: Option<PathBuf>,
    },

    /// Serve a read-only local rule editor shell.
    Serve {
        /// Loopback address for the read-only rule editor server.
        #[arg(long, default_value = "127.0.0.1:8787")]
        addr: std::net::SocketAddr,

        /// YAML rule file to add. Repeat to load multiple files in addition to bundled rules.
        #[arg(long = "rules")]
        rule_paths: Vec<PathBuf>,

        #[command(flatten)]
        local_config: LocalConfigCliArgs,

        /// Do not load bundled default rules. Use only rules passed with --rules.
        #[arg(long)]
        no_default_rules: bool,

        /// YAML policy file that selects active rule categories and rule ids.
        #[arg(long)]
        policy: Option<PathBuf>,

        /// Handle one HTTP request and exit. Intended for CLI integration tests.
        #[arg(long, hide = true)]
        once: bool,
    },

    /// Report rule fixture coverage, client coverage, and false-positive notes.
    Coverage {
        /// Root containing session store fixtures for coverage analysis.
        #[arg(long, default_value = "tests/fixtures/session_stores")]
        root: PathBuf,

        /// YAML rule file to add. Repeat to load multiple files in addition to bundled rules.
        #[arg(long = "rules")]
        rule_paths: Vec<PathBuf>,

        #[command(flatten)]
        local_config: LocalConfigCliArgs,

        /// Do not load bundled default rules. Use only rules passed with --rules.
        #[arg(long)]
        no_default_rules: bool,

        /// YAML policy file that selects active rule categories and rule ids.
        #[arg(long)]
        policy: Option<PathBuf>,
    },

    /// Export the bundled default rule YAML for inspection or local forking.
    ExportDefault {
        /// Write the bundled default rule YAML to this path instead of stdout.
        #[arg(long)]
        output: Option<PathBuf>,

        /// Overwrite --output if it already exists.
        #[arg(long)]
        force: bool,
    },
}

#[derive(Debug, Clone, Default, ClapArgs)]
struct LocalConfigCliArgs {
    /// Local Telltale config root. Repeat to load multiple roots instead of default local roots.
    #[arg(long = "config-dir")]
    config_dirs: Vec<PathBuf>,

    /// Disable local config discovery from rules.d, overrides.d, policies.d, and allowlists.d.
    #[arg(long)]
    no_local_config: bool,
}

struct ResolvedRuleConfig {
    rule_paths: Vec<PathBuf>,
    editable_rule_paths: Vec<PathBuf>,
    override_paths: Vec<PathBuf>,
    policy_path: Option<PathBuf>,
}

struct ResolvedScanConfig {
    rule_paths: Vec<PathBuf>,
    override_paths: Vec<PathBuf>,
    policy_path: Option<PathBuf>,
    allowlist_path: Option<PathBuf>,
    discovered: crate::config::LocalConfigFiles,
}

fn parse_client_id(value: &str) -> Result<ClientId, String> {
    supported_clients()
        .iter()
        .find(|client| client.id.as_str() == value)
        .map(|client| client.id)
        .ok_or_else(|| {
            let expected = supported_clients()
                .iter()
                .map(|client| client.id.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            format!("unsupported client '{value}'; expected one of: {expected}")
        })
}

fn rule_load_mode(no_default_rules: bool) -> RuleLoadMode {
    if no_default_rules {
        RuleLoadMode::CustomOnly
    } else {
        RuleLoadMode::IncludeDefault
    }
}

fn resolve_rule_config(
    local_config: &LocalConfigCliArgs,
    rule_paths: &[PathBuf],
    policy: Option<&Path>,
) -> Result<ResolvedRuleConfig, Box<dyn std::error::Error>> {
    let discovered = crate::config::discover_local_config_files(
        &local_config.config_dirs,
        local_config.no_local_config,
        crate::config::LocalConfigDiscoveryKind::Rules,
    )?;
    Ok(ResolvedRuleConfig {
        rule_paths: crate::config::effective_rule_paths(&discovered.rule_paths, rule_paths),
        editable_rule_paths: rule_paths.to_vec(),
        override_paths: discovered.override_paths.clone(),
        policy_path: crate::config::resolve_policy_path(policy, &discovered.policy_paths)?,
    })
}

fn resolve_scan_config(
    local_config: &LocalConfigCliArgs,
    rule_paths: &[PathBuf],
    policy: Option<&Path>,
    allowlist: Option<&Path>,
) -> Result<ResolvedScanConfig, Box<dyn std::error::Error>> {
    let discovered = crate::config::discover_local_config_files(
        &local_config.config_dirs,
        local_config.no_local_config,
        crate::config::LocalConfigDiscoveryKind::Scan,
    )?;
    let effective_rule_paths =
        crate::config::effective_rule_paths(&discovered.rule_paths, rule_paths);
    let policy_path = crate::config::resolve_policy_path(policy, &discovered.policy_paths)?;
    let allowlist_path =
        crate::config::resolve_allowlist_path(allowlist, &discovered.allowlist_paths)?;

    Ok(ResolvedScanConfig {
        rule_paths: effective_rule_paths,
        override_paths: discovered.override_paths.clone(),
        policy_path,
        allowlist_path,
        discovered,
    })
}

fn display_paths(paths: &[PathBuf]) -> Vec<String> {
    paths
        .iter()
        .map(|path| path.display().to_string())
        .collect()
}

fn display_path(path: Option<&Path>) -> Option<String> {
    path.map(|path| path.display().to_string())
}

fn run_config_validate(
    local_config: &LocalConfigCliArgs,
    rule_paths: &[PathBuf],
    no_default_rules: bool,
    policy: Option<&Path>,
    allowlist: Option<&Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    let resolved_config = resolve_scan_config(local_config, rule_paths, policy, allowlist)?;
    let rule_set = load_rule_set_from_paths_with_mode_and_override_paths(
        &resolved_config.rule_paths,
        resolved_config.policy_path.as_deref(),
        rule_load_mode(no_default_rules),
        &resolved_config.override_paths,
    )?;
    crate::allowlist::load_allowlist(resolved_config.allowlist_path.as_deref())?;

    println!(
        "{}",
        serde_json::to_string(&serde_json::json!({
            "status": "ok",
            "rule_count": rule_set.rule_count(),
            "default_rules": !no_default_rules,
            "policy_name": rule_set.policy_name(),
            "local_config": {
                "enabled": !local_config.no_local_config,
                "explicit_config_dirs": if local_config.no_local_config {
                    Vec::<String>::new()
                } else {
                    display_paths(&local_config.config_dirs)
                },
                "discovered_rule_count": resolved_config.discovered.rule_paths.len(),
                "discovered_override_count": resolved_config.discovered.override_paths.len(),
                "discovered_policy_count": resolved_config.discovered.policy_paths.len(),
                "discovered_allowlist_count": resolved_config.discovered.allowlist_paths.len(),
            },
            "rules": {
                "paths": display_paths(&resolved_config.rule_paths),
                "explicit_count": rule_paths.len(),
                "discovered_count": resolved_config.discovered.rule_paths.len(),
            },
            "overrides": {
                "paths": display_paths(&resolved_config.override_paths),
                "discovered_count": resolved_config.discovered.override_paths.len(),
            },
            "policy_path": display_path(resolved_config.policy_path.as_deref()),
            "allowlist_path": display_path(resolved_config.allowlist_path.as_deref()),
        }))?
    );

    Ok(())
}

fn run_rules_export_default(
    output: Option<&Path>,
    force: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let yaml = crate::rules::bundled_default_rule_yaml();
    if let Some(path) = output {
        if path.exists() && !force {
            return Err(format!(
                "{} already exists; pass --force to overwrite",
                path.display()
            )
            .into());
        }
        fs::write(path, yaml)?;
    } else {
        print!("{yaml}");
    }
    Ok(())
}

fn parse_nonzero_usize(value: &str) -> Result<usize, String> {
    let parsed = value
        .parse::<usize>()
        .map_err(|_| format!("expected a positive integer, got '{value}'"))?;
    if parsed == 0 {
        return Err("--max-sources must be greater than 0".to_string());
    }
    Ok(parsed)
}

pub(crate) fn read_jsonl_events(
    log_path: &Path,
) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    let contents = fs::read_to_string(log_path)?;
    let mut events = Vec::new();
    for (index, line) in contents.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let event = serde_json::from_str::<serde_json::Value>(line).map_err(|err| {
            format!(
                "invalid JSONL at {}:{}: {err}",
                log_path.display(),
                index + 1
            )
        })?;
        events.push(event);
    }
    Ok(events)
}

/// Resolve rotation config from CLI flags and environment variables.
///
/// Precedence: `--log-rotate-disabled` > `--log-rotate-max-size`/`ADR_LOG_ROTATE_MAX_SIZE` >
/// `--log-rotate-keep`/`ADR_LOG_ROTATE_KEEP` > defaults (100 MB, keep 5).
fn resolve_rotation_config(
    max_size: Option<u64>,
    keep: Option<usize>,
    disabled: bool,
) -> crate::sink::RotationConfig {
    if disabled {
        return crate::sink::RotationConfig::disabled();
    }

    let max_size_bytes = max_size.unwrap_or_else(|| {
        std::env::var("ADR_LOG_ROTATE_MAX_SIZE")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(100 * 1024 * 1024)
    });

    let keep_count = keep.unwrap_or_else(|| {
        std::env::var("ADR_LOG_ROTATE_KEEP")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(5)
    });

    crate::sink::RotationConfig {
        max_size_bytes,
        keep: keep_count,
    }
}

fn resolve_install_inventory_interval_seconds(
    interval_seconds: Option<u64>,
    disabled: bool,
) -> Option<u64> {
    if disabled {
        return None;
    }
    Some(interval_seconds.unwrap_or_else(|| {
        std::env::var("ADR_INSTALL_INVENTORY_INTERVAL_SECONDS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(scan::DEFAULT_INSTALL_INVENTORY_INTERVAL_SECONDS)
    }))
}

pub fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    match args.command {
        Command::Scan {
            once,
            interval_seconds,
            iterations,
            root,
            path_profile,
            log_path,
            splunk_hec_endpoint,
            splunk_hec_token,
            state_path,
            dry_run,
            emit_activity,
            emit_session_risk_summary,
            allow_fixtures,
            backfill,
            rebuild_baselines,
            rule_paths,
            local_config,
            no_default_rules,
            policy,
            allowlist,
            baseline_deviation_scoring,
            clients,
            max_sources,
            project_config_paths,
            log_rotate_max_size,
            log_rotate_keep,
            log_rotate_disabled,
            install_inventory_interval_seconds,
            install_inventory_disabled,
        } => {
            let path_profile = path_profile.into();
            let log_path = paths::resolve_log_path(path_profile, log_path);
            let state_path = paths::resolve_state_path(path_profile, state_path);
            let rotation =
                resolve_rotation_config(log_rotate_max_size, log_rotate_keep, log_rotate_disabled);
            let install_inventory_interval_seconds = resolve_install_inventory_interval_seconds(
                install_inventory_interval_seconds,
                install_inventory_disabled,
            );
            let mut project_paths = project_config_paths.clone();
            if project_paths.is_empty() {
                project_paths = crate::projects::project_config_paths_from_env();
            }
            let resolved_config = resolve_scan_config(
                &local_config,
                &rule_paths,
                policy.as_deref(),
                allowlist.as_deref(),
            )?;
            let scan_args = scan::ScanCommandArgs {
                root: &root,
                log_path: &log_path,
                splunk_hec_endpoint: splunk_hec_endpoint.as_deref(),
                splunk_hec_token: splunk_hec_token.as_deref(),
                state_path: &state_path,
                rotation,
                dry_run,
                emit_activity,
                emit_session_risk_summary,
                allow_fixtures,
                backfill,
                rebuild_baselines,
                rule_paths: &resolved_config.rule_paths,
                override_paths: &resolved_config.override_paths,
                rule_load_mode: rule_load_mode(no_default_rules),
                policy_path: resolved_config.policy_path.as_deref(),
                allowlist_path: resolved_config.allowlist_path.as_deref(),
                baseline_deviation_scoring,
                clients: &clients,
                max_sources,
                project_config_paths: &project_paths,
                install_inventory_interval_seconds,
            };
            if once {
                scan::run_scan_once(scan::scan_config(&scan_args))?;
            } else {
                let interval =
                    interval_seconds.ok_or("scan requires --once or --interval-seconds")?;
                scan::run_scan_loop(
                    &scan_args,
                    iterations,
                    std::time::Duration::from_secs(interval),
                )?;
            }
        }
        Command::Rules { command } => match command {
            RulesCommand::List {
                rule_paths,
                local_config,
                no_default_rules,
                policy,
            } => {
                let resolved_config =
                    resolve_rule_config(&local_config, &rule_paths, policy.as_deref())?;
                let rule_set = load_rule_set_from_paths_with_mode_and_override_paths(
                    &resolved_config.rule_paths,
                    resolved_config.policy_path.as_deref(),
                    rule_load_mode(no_default_rules),
                    &resolved_config.override_paths,
                )?;
                for rule in rule_set.summaries() {
                    println!(
                        "{}\t{}\t{}\t{}\t{}",
                        rule.id, rule.category, rule.severity, rule.score, rule.enabled
                    );
                }
            }
            RulesCommand::Validate {
                rule_paths,
                local_config,
                no_default_rules,
                policy,
            } => {
                let resolved_config =
                    resolve_rule_config(&local_config, &rule_paths, policy.as_deref())?;
                let rule_set = load_rule_set_from_paths_with_mode_and_override_paths(
                    &resolved_config.rule_paths,
                    resolved_config.policy_path.as_deref(),
                    rule_load_mode(no_default_rules),
                    &resolved_config.override_paths,
                )?;
                println!(
                    "{}",
                    serde_json::to_string(&serde_json::json!({
                        "status": "ok",
                        "rule_count": rule_set.rule_count(),
                        "policy": rule_set.policy_name(),
                    }))?
                );
            }
            RulesCommand::Test {
                fixture,
                rule_paths,
                local_config,
                no_default_rules,
                policy,
            } => {
                let resolved_config =
                    resolve_rule_config(&local_config, &rule_paths, policy.as_deref())?;
                let rule_set = load_rule_set_from_paths_with_mode_and_override_paths(
                    &resolved_config.rule_paths,
                    resolved_config.policy_path.as_deref(),
                    rule_load_mode(no_default_rules),
                    &resolved_config.override_paths,
                )?;
                let source = Source {
                    client: ClientId::Codex,
                    kind: SourceKind::Jsonl,
                    source_id: "rules.test".to_string(),
                    path: fixture,
                };
                let detections = detect_sources_with_rules(&[source], &rule_set);
                let matches = detections
                    .iter()
                    .filter(|(_, event)| event.event_type == "detection")
                    .map(|(_, event)| {
                        serde_json::json!({
                            "session_id": event.session_id,
                            "severity": event.severity,
                            "risk_score": event.risk_score,
                            "rule_ids": event.rule_ids,
                            "categories": event.categories,
                        })
                    })
                    .collect::<Vec<_>>();
                println!(
                    "{}",
                    serde_json::to_string(&serde_json::json!({
                        "match_count": matches.len(),
                        "matches": matches,
                    }))?
                );
            }
            RulesCommand::Serve {
                addr,
                rule_paths,
                local_config,
                no_default_rules,
                policy,
                once,
            } => {
                let resolved_config =
                    resolve_rule_config(&local_config, &rule_paths, policy.as_deref())?;
                rules_server::run_rules_server(
                    addr,
                    &resolved_config.rule_paths,
                    &resolved_config.editable_rule_paths,
                    &resolved_config.override_paths,
                    resolved_config.policy_path.as_deref(),
                    rule_load_mode(no_default_rules),
                    once,
                )?;
            }
            RulesCommand::Coverage {
                root,
                rule_paths,
                local_config,
                no_default_rules,
                policy,
            } => {
                let resolved_config =
                    resolve_rule_config(&local_config, &rule_paths, policy.as_deref())?;
                coverage::run_rules_coverage(
                    &root,
                    &resolved_config.rule_paths,
                    &resolved_config.override_paths,
                    resolved_config.policy_path.as_deref(),
                    rule_load_mode(no_default_rules),
                )?;
            }
            RulesCommand::ExportDefault { output, force } => {
                run_rules_export_default(output.as_deref(), force)?;
            }
        },
        Command::Config { command } => match command {
            ConfigCommand::Validate {
                rule_paths,
                local_config,
                no_default_rules,
                policy,
                allowlist,
            } => run_config_validate(
                &local_config,
                &rule_paths,
                no_default_rules,
                policy.as_deref(),
                allowlist.as_deref(),
            )?,
        },
        Command::Watch {
            root,
            path_profile,
            log_path,
            state_path,
            dry_run,
            emit_activity,
            emit_session_risk_summary,
            allow_fixtures,
            iterations,
            debounce_ms,
            rule_paths,
            local_config,
            no_default_rules,
            policy,
            allowlist,
            baseline_deviation_scoring,
            clients,
            project_config_paths,
            log_rotate_max_size,
            log_rotate_keep,
            log_rotate_disabled,
            install_inventory_interval_seconds,
            install_inventory_disabled,
        } => {
            let path_profile = path_profile.into();
            let log_path = paths::resolve_log_path(path_profile, log_path);
            let state_path = paths::resolve_state_path(path_profile, state_path);
            let rotation =
                resolve_rotation_config(log_rotate_max_size, log_rotate_keep, log_rotate_disabled);
            let install_inventory_interval_seconds = resolve_install_inventory_interval_seconds(
                install_inventory_interval_seconds,
                install_inventory_disabled,
            );
            let mut project_paths = project_config_paths.clone();
            if project_paths.is_empty() {
                project_paths = crate::projects::project_config_paths_from_env();
            }
            let resolved_config = resolve_scan_config(
                &local_config,
                &rule_paths,
                policy.as_deref(),
                allowlist.as_deref(),
            )?;
            let watch_args = scan::WatchCommandArgs {
                root: &root,
                log_path: &log_path,
                state_path: &state_path,
                rotation,
                dry_run,
                emit_activity,
                emit_session_risk_summary,
                allow_fixtures,
                iterations,
                debounce: std::time::Duration::from_millis(debounce_ms),
                rule_paths: &resolved_config.rule_paths,
                override_paths: &resolved_config.override_paths,
                rule_load_mode: rule_load_mode(no_default_rules),
                policy_path: resolved_config.policy_path.as_deref(),
                allowlist_path: resolved_config.allowlist_path.as_deref(),
                baseline_deviation_scoring,
                clients: &clients,
                project_config_paths: &project_paths,
                install_inventory_interval_seconds,
            };
            scan::run_watch(scan::watch_config(&watch_args))?;
        }
        Command::Status {
            path_profile,
            log_path,
            state_path,
        } => {
            let path_profile = path_profile.into();
            let log_path = paths::resolve_log_path(path_profile, log_path);
            let state_path = paths::resolve_state_path(path_profile, state_path);
            scan::run_status(&log_path, &state_path)?;
        }
        Command::Export {
            path_profile,
            log_path,
            severities,
            clients,
            session_ids,
            rule_ids,
            since,
            until,
            format,
            correlate,
            timeline,
            source_root,
        } => {
            let log_path = paths::resolve_log_path(path_profile.into(), log_path);
            export::run_export(export::ExportConfig {
                log_path: &log_path,
                severities: &severities,
                clients: &clients,
                session_ids: &session_ids,
                rule_ids: &rule_ids,
                since: since.as_deref(),
                until: until.as_deref(),
                format,
                correlate,
                timeline,
                source_root: source_root.as_deref(),
            })?;
        }
    }

    Ok(())
}
