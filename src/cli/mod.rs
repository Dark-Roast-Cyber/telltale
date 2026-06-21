use std::fs;
use std::path::{Path, PathBuf};

use crate::clients::{ClientId, SourceKind, supported_clients};
use crate::detection::detect_sources_with_rules;
use crate::discovery::Source;
use crate::paths::{self, PathProfile};
use crate::rules::load_rule_set_from_paths;
use clap::{Parser, Subcommand, ValueEnum};

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

        /// YAML rule file to load. Repeat to load multiple files. Defaults to bundled rules.
        #[arg(long = "rules")]
        rule_paths: Vec<PathBuf>,

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

        /// YAML rule file to load. Repeat to load multiple files. Defaults to bundled rules.
        #[arg(long = "rules")]
        rule_paths: Vec<PathBuf>,

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
    },

    /// Inspect and validate Telltale detection rules.
    Rules {
        #[command(subcommand)]
        command: RulesCommand,
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
enum RulesCommand {
    /// List loaded rules.
    List {
        /// YAML rule file to load. Repeat to load multiple files. Defaults to bundled rules.
        #[arg(long = "rules")]
        rule_paths: Vec<PathBuf>,

        /// YAML policy file that selects active rule categories and rule ids.
        #[arg(long)]
        policy: Option<PathBuf>,
    },

    /// Validate rule and policy YAML.
    Validate {
        /// YAML rule file to load. Repeat to load multiple files. Defaults to bundled rules.
        #[arg(long = "rules")]
        rule_paths: Vec<PathBuf>,

        /// YAML policy file that selects active rule categories and rule ids.
        #[arg(long)]
        policy: Option<PathBuf>,
    },

    /// Evaluate one Codex-shaped JSONL fixture with the loaded rules.
    Test {
        /// Fixture file to evaluate.
        fixture: PathBuf,

        /// YAML rule file to load. Repeat to load multiple files. Defaults to bundled rules.
        #[arg(long = "rules")]
        rule_paths: Vec<PathBuf>,

        /// YAML policy file that selects active rule categories and rule ids.
        #[arg(long)]
        policy: Option<PathBuf>,
    },

    /// Serve a read-only local rule editor shell.
    Serve {
        /// Loopback address for the read-only rule editor server.
        #[arg(long, default_value = "127.0.0.1:8787")]
        addr: std::net::SocketAddr,

        /// YAML rule file to load. Repeat to load multiple files. Defaults to bundled rules.
        #[arg(long = "rules")]
        rule_paths: Vec<PathBuf>,

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

        /// YAML rule file to load. Repeat to load multiple files. Defaults to bundled rules.
        #[arg(long = "rules")]
        rule_paths: Vec<PathBuf>,

        /// YAML policy file that selects active rule categories and rule ids.
        #[arg(long)]
        policy: Option<PathBuf>,
    },
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
            policy,
            allowlist,
            baseline_deviation_scoring,
            clients,
            max_sources,
            project_config_paths,
        } => {
            let path_profile = path_profile.into();
            let log_path = paths::resolve_log_path(path_profile, log_path);
            let state_path = paths::resolve_state_path(path_profile, state_path);
            let mut project_paths = project_config_paths.clone();
            if project_paths.is_empty() {
                project_paths = crate::projects::project_config_paths_from_env();
            }
            let scan_args = scan::ScanCommandArgs {
                root: &root,
                log_path: &log_path,
                splunk_hec_endpoint: splunk_hec_endpoint.as_deref(),
                splunk_hec_token: splunk_hec_token.as_deref(),
                state_path: &state_path,
                dry_run,
                emit_activity,
                emit_session_risk_summary,
                allow_fixtures,
                backfill,
                rebuild_baselines,
                rule_paths: &rule_paths,
                policy_path: policy.as_deref(),
                allowlist_path: allowlist.as_deref(),
                baseline_deviation_scoring,
                clients: &clients,
                max_sources,
                project_config_paths: &project_paths,
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
            RulesCommand::List { rule_paths, policy } => {
                let rule_set = load_rule_set_from_paths(&rule_paths, policy.as_deref())?;
                for rule in rule_set.summaries() {
                    println!(
                        "{}\t{}\t{}\t{}\t{}",
                        rule.id, rule.category, rule.severity, rule.score, rule.enabled
                    );
                }
            }
            RulesCommand::Validate { rule_paths, policy } => {
                let rule_set = load_rule_set_from_paths(&rule_paths, policy.as_deref())?;
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
                policy,
            } => {
                let rule_set = load_rule_set_from_paths(&rule_paths, policy.as_deref())?;
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
                policy,
                once,
            } => {
                rules_server::run_rules_server(addr, &rule_paths, policy.as_deref(), once)?;
            }
            RulesCommand::Coverage {
                root,
                rule_paths,
                policy,
            } => {
                coverage::run_rules_coverage(&root, &rule_paths, policy.as_deref())?;
            }
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
            policy,
            allowlist,
            baseline_deviation_scoring,
            clients,
            project_config_paths,
        } => {
            let path_profile = path_profile.into();
            let log_path = paths::resolve_log_path(path_profile, log_path);
            let state_path = paths::resolve_state_path(path_profile, state_path);
            let mut project_paths = project_config_paths.clone();
            if project_paths.is_empty() {
                project_paths = crate::projects::project_config_paths_from_env();
            }
            let watch_args = scan::WatchCommandArgs {
                root: &root,
                log_path: &log_path,
                state_path: &state_path,
                dry_run,
                emit_activity,
                emit_session_risk_summary,
                allow_fixtures,
                iterations,
                debounce: std::time::Duration::from_millis(debounce_ms),
                rule_paths: &rule_paths,
                policy_path: policy.as_deref(),
                allowlist_path: allowlist.as_deref(),
                baseline_deviation_scoring,
                clients: &clients,
                project_config_paths: &project_paths,
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
