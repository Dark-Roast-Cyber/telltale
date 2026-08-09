use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use crate::detection::detect_sources_with_rules;
use crate::paths::{self, PathProfile};
use crate::rules::{
    RuleLoadMode, RulePackPaths, RuleResolutionDiagnostics,
    resolve_rule_set_from_pack_paths_with_mode_override_paths_and_replacements,
};
use crate::sink::config as sink_config;
use clap::{
    ArgAction, Args as ClapArgs, CommandFactory, FromArgMatches, Parser, Subcommand, ValueEnum,
};
use sha2::Digest;
use telltale_schema::clients::{ClientId, SourceKind};
use telltale_schema::event::path_hash;
use telltale_schema::source::Source;
use telltale_sources::clients::supported_clients;

mod coverage;
mod export;
#[allow(dead_code)]
pub mod historical;
mod migrate;
mod rules_server;
mod scan;

#[derive(Parser)]
#[command(
    name = "adr",
    about = "Telltale detection layer for AI coding agent sessions",
    version = concat!(env!("CARGO_PKG_VERSION"), " (", env!("ADR_GIT_HASH"), ")")
)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
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

        /// Do not load bundled defaults. Managed packs remain active; --rules files stay additive.
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

        /// Minimum milliseconds between watch-triggered scans. Events arriving
        /// sooner are coalesced into the next scan.
        #[arg(long, default_value_t = 10_000)]
        min_scan_interval_ms: u64,

        /// YAML rule file to add. Repeat to load multiple files in addition to bundled rules.
        #[arg(long = "rules")]
        rule_paths: Vec<PathBuf>,

        #[command(flatten)]
        local_config: LocalConfigCliArgs,

        /// Do not load bundled defaults. Managed packs remain active; --rules files stay additive.
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

    /// Explicitly migrate state, historical event JSONL, or environment files.
    Migrate {
        #[command(subcommand)]
        command: MigrateCommand,
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
        /// Outputs a structured timeline with detection anchors and historical triage context.
        #[arg(long)]
        timeline: bool,

        /// Read session stores from this root for --timeline instead of building from JSONL events.
        #[arg(long)]
        source_root: Option<PathBuf>,
    },
}

#[derive(Debug, Subcommand)]
enum MigrateCommand {
    /// Convert legacy unversioned state or relocate native 1.0 state.
    State {
        /// Existing legacy or native state file.
        #[arg(long = "from")]
        from: PathBuf,

        /// Destination native state file.
        #[arg(long = "to")]
        to: PathBuf,
    },

    /// Validate and relocate explicit historical event-set files without rewriting bytes.
    /// Repeated destinations are joined only across LF boundaries; the first
    /// pair owns the recovery manifest.
    Events {
        /// Explicit source and destination pair. Repeat for multiple mappings.
        /// At most 64 pairs and 32 unique destinations are accepted.
        #[arg(
            long = "pair",
            value_names = ["OLD", "NEW"],
            num_args = 2,
            action = ArgAction::Append
        )]
        pairs: Vec<PathBuf>,
    },

    /// Map an explicit legacy environment file to a canonical environment file
    /// using the audited ADR product-key inventory.
    Env {
        /// Existing legacy environment file.
        #[arg(long = "from")]
        from: PathBuf,

        /// Destination canonical environment file.
        #[arg(long = "to")]
        to: PathBuf,
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

        /// Do not load bundled defaults. Managed packs remain active; --rules files stay additive.
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
        /// Include winner and replaced-source provenance columns.
        #[arg(long)]
        verbose: bool,

        /// YAML rule file to add. Repeat to load multiple files in addition to bundled rules.
        #[arg(long = "rules")]
        rule_paths: Vec<PathBuf>,

        #[command(flatten)]
        local_config: LocalConfigCliArgs,

        /// Do not load bundled defaults. Managed packs remain active; --rules files stay additive.
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

        /// Do not load bundled defaults. Managed packs remain active; --rules files stay additive.
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

        /// Do not load bundled defaults. Managed packs remain active; --rules files stay additive.
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

        /// Do not load bundled defaults. Managed packs remain active; --rules files stay additive.
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

        /// Do not load bundled defaults. Managed packs remain active; --rules files stay additive.
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

    /// Disable local config discovery from organization-rules.d, rules.d, ui-rules.d,
    /// overrides.d, policies.d, allowlists.d, and outputs.d.
    #[arg(long)]
    no_local_config: bool,
}

struct ResolvedRuleConfig {
    explicit_rule_paths: Vec<PathBuf>,
    rule_pack_paths: RulePackPaths,
    editable_rule_paths: Vec<PathBuf>,
    override_paths: Vec<PathBuf>,
    policy_path: Option<PathBuf>,
}

struct ResolvedScanConfig {
    rule_paths: Vec<PathBuf>,
    explicit_rule_paths: Vec<PathBuf>,
    rule_pack_paths: RulePackPaths,
    override_paths: Vec<PathBuf>,
    policy_path: Option<PathBuf>,
    policy_origin: Option<&'static str>,
    allowlist_path: Option<PathBuf>,
    allowlist_origin: Option<&'static str>,
    discovered: crate::config::LocalConfigFiles,
}

#[derive(Debug, Clone)]
struct RuntimeSnapshot {
    value: serde_json::Value,
    executable_path: Option<PathBuf>,
}

fn observe_runtime() -> RuntimeSnapshot {
    let current_exe = std::env::current_exe();
    let executable_path = current_exe.as_ref().ok().cloned();
    let observation = observe_executable(current_exe, |path| {
        File::open(path).map(|file| Box::new(file) as Box<dyn Read>)
    });
    RuntimeSnapshot {
        value: serde_json::json!({
            "package_version": env!("CARGO_PKG_VERSION"),
            "build_git_hash": env!("ADR_GIT_HASH"),
            "executable": {
                "observation_status": observation.status,
                "path_hash": observation.path_hash,
                "sha256": observation.sha256,
            },
        }),
        executable_path,
    }
}

#[derive(Debug, PartialEq, Eq)]
struct ExecutableObservation {
    status: &'static str,
    path_hash: Option<String>,
    sha256: Option<String>,
}

fn observe_executable<F>(current_exe: io::Result<PathBuf>, open: F) -> ExecutableObservation
where
    F: FnOnce(&Path) -> io::Result<Box<dyn Read>>,
{
    let Ok(path) = current_exe else {
        return ExecutableObservation {
            status: "current_exe_unavailable",
            path_hash: None,
            sha256: None,
        };
    };
    let hash = path_hash(&path);
    let Ok(mut reader) = open(&path) else {
        return ExecutableObservation {
            status: "executable_read_failed",
            path_hash: Some(hash),
            sha256: None,
        };
    };
    let mut hasher = sha2::Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => hasher.update(&buffer[..read]),
            Err(_) => {
                return ExecutableObservation {
                    status: "executable_read_failed",
                    path_hash: Some(hash),
                    sha256: None,
                };
            }
        }
    }
    ExecutableObservation {
        status: "complete",
        path_hash: Some(hash),
        sha256: Some(format!("{:x}", hasher.finalize())),
    }
}

fn path_hashes(paths: &[PathBuf]) -> Vec<String> {
    paths.iter().map(|path| path_hash(path)).collect()
}

fn path_origin(explicit: Option<&Path>, environment_name: &str) -> &'static str {
    if explicit.is_some() {
        "cli"
    } else if std::env::var_os(environment_name).is_some_and(|value| !value.is_empty()) {
        "environment"
    } else {
        "path_profile"
    }
}

fn path_profile_name(profile: PathProfile) -> &'static str {
    match profile {
        PathProfile::User => "user",
        PathProfile::System => "system",
        PathProfile::Project => "project",
    }
}

fn config_path_value(path: Option<&Path>, origin: &'static str) -> serde_json::Value {
    serde_json::json!({
        "origin": origin,
        "path_hash": path.map(path_hash),
    })
}

fn source_identity_hash(source: &str) -> String {
    telltale_schema::event::evidence_hash(source)
}

fn rule_diagnostics_value(diagnostics: &RuleResolutionDiagnostics) -> serde_json::Value {
    serde_json::json!({
        "sources": diagnostics
            .sources
            .iter()
            .map(|source| source_identity_hash(source))
            .collect::<Vec<_>>(),
        "provenance": diagnostics
            .provenance
            .iter()
            .map(|entry| serde_json::json!({
                "id": entry.id,
                "kind": entry.kind,
                "winner": source_identity_hash(&entry.winner),
                "replaced_sources": entry
                    .replaced_sources
                    .iter()
                    .map(|source| source_identity_hash(source))
                    .collect::<Vec<_>>(),
            }))
            .collect::<Vec<_>>(),
    })
}

fn output_snapshot_value(
    specs: &[sink_config::SinkSpec],
    output_paths: &[PathBuf],
    outputs_config_present: bool,
    log_path: &Path,
    splunk_hec_endpoint: Option<&str>,
    splunk_hec_token: Option<&str>,
    sink_set: &crate::sink::SinkSet,
) -> serde_json::Value {
    let cli_hec = splunk_hec_endpoint.is_some() && splunk_hec_token.is_some();
    let mut sinks = Vec::new();
    if !outputs_config_present {
        sinks.push(serde_json::json!({
            "name": "jsonl",
            "type": "jsonl",
            "enabled": true,
            "selection": "selected",
            "origin_kind": "legacy_default",
            "winning_path_hash": serde_json::Value::Null,
            "resolved_destination_path_hash": path_hash(log_path),
            "has_inline_secret": false,
            "insecure_skip_verify": false,
        }));
    } else {
        for spec in specs {
            let replaced_by_cli =
                cli_hec && spec.enabled && spec.name == sink_config::CLI_SPLUNK_HEC_SINK_NAME;
            let resolved_destination_path_hash = match &spec.kind {
                sink_config::SinkKind::Jsonl(jsonl) => {
                    Some(path_hash(jsonl.path.as_deref().unwrap_or(log_path)))
                }
                _ => None,
            };
            sinks.push(serde_json::json!({
                "name": spec.name,
                "type": spec.kind.type_name(),
                "enabled": spec.enabled,
                "selection": if replaced_by_cli { "replaced_by_cli" } else if spec.enabled { "selected" } else { "disabled" },
                "origin_kind": "outputs_document",
                "winning_path_hash": spec.origin_path.as_deref().map(path_hash),
                "resolved_destination_path_hash": resolved_destination_path_hash,
                "has_inline_secret": spec.has_inline_secret(),
                "insecure_skip_verify": spec.has_insecure_tls(),
            }));
        }
    }
    if cli_hec {
        sinks.push(serde_json::json!({
            "name": sink_config::CLI_SPLUNK_HEC_SINK_NAME,
            "type": "splunk_hec",
            "enabled": true,
            "selection": "selected",
            "origin_kind": "cli_overlay",
            "winning_path_hash": serde_json::Value::Null,
            "resolved_destination_path_hash": serde_json::Value::Null,
            "has_inline_secret": true,
            "insecure_skip_verify": false,
        }));
    }
    let selected = sinks
        .iter()
        .filter(|sink| sink["selection"] == "selected")
        .collect::<Vec<_>>();
    let durable_sink_count = selected
        .iter()
        .filter(|sink| sink["type"] == "jsonl")
        .count();
    let enabled_sink_count = selected.len();
    serde_json::json!({
        "mode": if outputs_config_present { "outputs_config" } else { "legacy_default" },
        "document_path_hashes": path_hashes(output_paths),
        "sinks": sinks,
        "delivery": {
            "posture": sink_set.delivery_posture().as_str(),
            "durable_first_write": sink_set.delivery_posture().has_durable_first_write(),
            "built_in_persistent_replay": false,
            "enabled_sink_count": enabled_sink_count,
            "durable_sink_count": durable_sink_count,
            "remote_sink_count": enabled_sink_count.saturating_sub(durable_sink_count),
            "source": if outputs_config_present { "outputs_config" } else { "legacy_default" },
        },
    })
}

struct EffectiveConfigurationPaths<'a> {
    profile: PathProfile,
    log_path: &'a Path,
    state_path: &'a Path,
    log_origin: &'static str,
    state_origin: &'static str,
}

fn effective_configuration_base(
    local_config: &LocalConfigCliArgs,
    paths: EffectiveConfigurationPaths<'_>,
    resolved_config: &ResolvedScanConfig,
    no_default_rules: bool,
    project_config_paths: &[PathBuf],
    outputs: serde_json::Value,
) -> serde_json::Value {
    serde_json::json!({
        "local_config": {
            "mode": if local_config.no_local_config { "disabled" } else if local_config.config_dirs.is_empty() { "default_roots" } else { "explicit_roots" },
            "explicit_root_path_hashes": if local_config.no_local_config { Vec::<String>::new() } else { path_hashes(&local_config.config_dirs) },
        },
        "paths": {
            "profile": path_profile_name(paths.profile),
            "log": config_path_value(Some(paths.log_path), paths.log_origin),
            "state": config_path_value(Some(paths.state_path), paths.state_origin),
        },
        "rules": {
            "default_enabled": !no_default_rules,
            "path_hashes": path_hashes(&resolved_config.rule_paths),
            "sources": Vec::<String>::new(),
            "provenance": Vec::<serde_json::Value>::new(),
        },
        "overrides": {
            "path_hashes": path_hashes(&resolved_config.override_paths),
        },
        "policy": {
            "configured": resolved_config.policy_path.is_some(),
            "origin": resolved_config.policy_origin,
            "path_hash": resolved_config.policy_path.as_deref().map(path_hash),
        },
        "allowlist": {
            "configured": resolved_config.allowlist_path.is_some(),
            "origin": resolved_config.allowlist_origin,
            "path_hash": resolved_config.allowlist_path.as_deref().map(path_hash),
        },
        "project_config_path_hashes": path_hashes(project_config_paths),
        "outputs": outputs,
    })
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
    let rule_pack_paths = RulePackPaths {
        organization: discovered.organization_rule_paths.clone(),
        deployment: discovered.deployment_rule_paths.clone(),
        local: discovered.local_rule_paths.clone(),
    };
    Ok(ResolvedRuleConfig {
        explicit_rule_paths: rule_paths.to_vec(),
        rule_pack_paths,
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
    let rule_pack_paths = RulePackPaths {
        organization: discovered.organization_rule_paths.clone(),
        deployment: discovered.deployment_rule_paths.clone(),
        local: discovered.local_rule_paths.clone(),
    };
    let policy_path = crate::config::resolve_policy_path(policy, &discovered.policy_paths)?;
    let allowlist_path =
        crate::config::resolve_allowlist_path(allowlist, &discovered.allowlist_paths)?;
    let policy_origin = policy.map(|_| "cli").or_else(|| {
        policy_path
            .as_ref()
            .filter(|path| {
                discovered
                    .policy_paths
                    .iter()
                    .any(|candidate| candidate == *path)
            })
            .map(|_| "local_config")
    });
    let allowlist_origin = allowlist.map(|_| "cli").or_else(|| {
        allowlist_path
            .as_ref()
            .filter(|path| {
                discovered
                    .allowlist_paths
                    .iter()
                    .any(|candidate| candidate == *path)
            })
            .map(|_| "local_config")
    });

    Ok(ResolvedScanConfig {
        rule_paths: effective_rule_paths,
        explicit_rule_paths: rule_paths.to_vec(),
        rule_pack_paths,
        override_paths: discovered.override_paths.clone(),
        policy_path,
        policy_origin,
        allowlist_path,
        allowlist_origin,
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
    let resolution = resolve_rule_set_from_pack_paths_with_mode_override_paths_and_replacements(
        &resolved_config.rule_pack_paths,
        &resolved_config.explicit_rule_paths,
        resolved_config.policy_path.as_deref(),
        rule_load_mode(no_default_rules),
        &resolved_config.override_paths,
        &[],
    )?;
    let rule_set = &resolution.rule_set;
    crate::allowlist::load_allowlist(resolved_config.allowlist_path.as_deref())?;
    let output_specs = sink_config::load_outputs_config(&resolved_config.discovered.output_paths)?;
    let outputs_config_present = !resolved_config.discovered.output_paths.is_empty();
    sink_config::build_sink_set_with_presence(
        &output_specs,
        outputs_config_present,
        &sink_config::CliSinkOverrides {
            log_path: Path::new("adr-events.jsonl"),
            rotation: crate::sink::RotationConfig::default(),
            splunk_hec_endpoint: None,
            splunk_hec_token: None,
        },
        false,
    )?;
    let delivery_posture =
        sink_config::effective_delivery_posture(&output_specs, outputs_config_present);
    let (enabled_sink_count, durable_sink_count, remote_sink_count, delivery_source) =
        if !outputs_config_present {
            (1, 1, 0, "legacy_default")
        } else {
            let enabled = output_specs.iter().filter(|spec| spec.enabled);
            let enabled_specs = enabled.collect::<Vec<_>>();
            (
                enabled_specs.len(),
                enabled_specs
                    .iter()
                    .filter(|spec| matches!(spec.kind, sink_config::SinkKind::Jsonl(_)))
                    .count(),
                enabled_specs
                    .iter()
                    .filter(|spec| !matches!(spec.kind, sink_config::SinkKind::Jsonl(_)))
                    .count(),
                "outputs_config",
            )
        };
    let mut output_warnings: Vec<String> = output_specs
        .iter()
        .filter(|spec| spec.has_inline_secret())
        .map(|spec| {
            format!(
                "sink '{}' has an inline secret; prefer {{env: NAME}} or {{file: PATH}} references",
                spec.name
            )
        })
        .collect();
    output_warnings.extend(
        output_specs
            .iter()
            .filter(|spec| spec.has_insecure_tls())
            .map(|spec| {
                format!(
                    "sink '{}' disables TLS certificate verification (insecure_skip_verify)",
                    spec.name
                )
            }),
    );
    match delivery_posture {
        crate::sink::DeliveryPosture::BestEffortNoReplay => output_warnings.push(
            "remote-only delivery is best-effort with no persistent replay; events may be lost after retry exhaustion, process exit, or restart"
                .to_string(),
        ),
        crate::sink::DeliveryPosture::NoEnabledSinks => output_warnings.push(
            "no enabled sinks are configured; events will not be delivered".to_string(),
        ),
        crate::sink::DeliveryPosture::DurableFirstWrite => {}
    }
    let output_sinks: Vec<serde_json::Value> = output_specs
        .iter()
        .map(|spec| {
            serde_json::json!({
                "name": spec.name,
                "type": spec.kind.type_name(),
                "enabled": spec.enabled,
            })
        })
        .collect();

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
                "discovered_output_count": resolved_config.discovered.output_paths.len(),
            },
            "outputs": {
                "paths": display_paths(&resolved_config.discovered.output_paths),
                "sinks": output_sinks,
                "delivery": {
                    "posture": delivery_posture.as_str(),
                    "durable_first_write": delivery_posture.has_durable_first_write(),
                    "built_in_persistent_replay": false,
                    "enabled_sink_count": enabled_sink_count,
                    "durable_sink_count": durable_sink_count,
                    "remote_sink_count": remote_sink_count,
                    "source": delivery_source,
                },
                "warnings": output_warnings,
            },
            "rules": {
                "paths": display_paths(&resolved_config.rule_paths),
                "explicit_count": rule_paths.len(),
                "discovered_count": resolved_config.discovered.rule_paths.len(),
                "provenance": resolution.diagnostics.provenance,
                "sources": resolution.diagnostics.sources,
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
    Ok(historical::read_jsonl_records(log_path)?
        .into_iter()
        .map(|record| record.value)
        .collect())
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
    let runtime = observe_runtime();
    let is_adr_alias = runtime
        .executable_path
        .as_deref()
        .and_then(|path| path.file_stem())
        .and_then(|name| name.to_str().map(|name| name == "adr"))
        .unwrap_or(false);
    let binary_name = if is_adr_alias { "adr" } else { "telltale" };
    let command = Args::command().name(binary_name);
    let args = Args::from_arg_matches(&command.get_matches())?;

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
            let log_origin = path_origin(log_path.as_deref(), paths::LOG_PATH_ENV);
            let state_origin = path_origin(state_path.as_deref(), paths::STATE_PATH_ENV);
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
            let output_specs =
                sink_config::load_outputs_config(&resolved_config.discovered.output_paths)?;
            let sink_set = sink_config::build_sink_set_with_presence(
                &output_specs,
                !resolved_config.discovered.output_paths.is_empty(),
                &sink_config::CliSinkOverrides {
                    log_path: &log_path,
                    rotation,
                    splunk_hec_endpoint: splunk_hec_endpoint.as_deref(),
                    splunk_hec_token: splunk_hec_token.as_deref(),
                },
                true,
            )?;
            let outputs = output_snapshot_value(
                &output_specs,
                &resolved_config.discovered.output_paths,
                !resolved_config.discovered.output_paths.is_empty(),
                &log_path,
                splunk_hec_endpoint.as_deref(),
                splunk_hec_token.as_deref(),
                &sink_set,
            );
            let effective_configuration = effective_configuration_base(
                &local_config,
                EffectiveConfigurationPaths {
                    profile: path_profile,
                    log_path: &log_path,
                    state_path: &state_path,
                    log_origin,
                    state_origin,
                },
                &resolved_config,
                no_default_rules,
                &project_paths,
                outputs,
            );
            let scan_config = scan::ScanConfig {
                execution: scan::ScanExecutionConfig {
                    root: &root,
                    log_path: &log_path,
                    sinks: &sink_set,
                    state_path: &state_path,
                    dry_run,
                    emit_activity,
                    emit_session_risk_summary,
                    allow_fixtures,
                    rule_pack_paths: &resolved_config.rule_pack_paths,
                    rule_paths: &resolved_config.explicit_rule_paths,
                    override_paths: &resolved_config.override_paths,
                    rule_load_mode: rule_load_mode(no_default_rules),
                    policy_path: resolved_config.policy_path.as_deref(),
                    allowlist_path: resolved_config.allowlist_path.as_deref(),
                    baseline_deviation_scoring,
                    clients: &clients,
                    project_config_paths: &project_paths,
                    install_inventory_interval_seconds,
                    runtime: &runtime.value,
                    effective_configuration: &effective_configuration,
                },
                backfill,
                rebuild_baselines,
                max_sources,
            };
            if once {
                scan::run_scan_once(scan_config)?;
            } else {
                let interval =
                    interval_seconds.ok_or("scan requires --once or --interval-seconds")?;
                scan::run_scan_loop(
                    scan_config,
                    iterations,
                    std::time::Duration::from_secs(interval),
                )?;
            }
        }
        Command::Migrate { command } => match command {
            MigrateCommand::State { from, to } => migrate::run_state_migration(&from, &to)?,
            MigrateCommand::Events { pairs } => {
                if pairs.len() % 2 != 0 {
                    return Err("event migration requires OLD and NEW for every --pair".into());
                }
                let pairs = pairs
                    .chunks_exact(2)
                    .map(|pair| (pair[0].clone(), pair[1].clone()))
                    .collect::<Vec<_>>();
                migrate::run_event_migration(&pairs)?;
            }
            MigrateCommand::Env { from, to } => migrate::run_env_migration(&from, &to)?,
        },
        Command::Rules { command } => match command {
            RulesCommand::List {
                verbose,
                rule_paths,
                local_config,
                no_default_rules,
                policy,
            } => {
                let resolved_config =
                    resolve_rule_config(&local_config, &rule_paths, policy.as_deref())?;
                let resolution =
                    resolve_rule_set_from_pack_paths_with_mode_override_paths_and_replacements(
                        &resolved_config.rule_pack_paths,
                        &resolved_config.explicit_rule_paths,
                        resolved_config.policy_path.as_deref(),
                        rule_load_mode(no_default_rules),
                        &resolved_config.override_paths,
                        &[],
                    )?;
                let provenance = resolution
                    .diagnostics
                    .provenance
                    .iter()
                    .map(|entry| (entry.id.as_str(), entry))
                    .collect::<std::collections::BTreeMap<_, _>>();
                for rule in resolution.rule_set.summaries() {
                    let source = provenance
                        .get(rule.id.as_str())
                        .map(|entry| entry.winner.as_str())
                        .unwrap_or("-");
                    let replaced = provenance
                        .get(rule.id.as_str())
                        .map(|entry| entry.replaced_sources.join(","))
                        .unwrap_or_default();
                    if verbose {
                        println!(
                            "{}\t{}\t{}\t{}\t{}\t{}\t{}",
                            rule.id,
                            rule.category,
                            rule.severity,
                            rule.score,
                            rule.enabled,
                            source,
                            replaced
                        );
                    } else {
                        println!(
                            "{}\t{}\t{}\t{}\t{}",
                            rule.id, rule.category, rule.severity, rule.score, rule.enabled
                        );
                    }
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
                let resolution =
                    resolve_rule_set_from_pack_paths_with_mode_override_paths_and_replacements(
                        &resolved_config.rule_pack_paths,
                        &resolved_config.explicit_rule_paths,
                        resolved_config.policy_path.as_deref(),
                        rule_load_mode(no_default_rules),
                        &resolved_config.override_paths,
                        &[],
                    )?;
                println!(
                    "{}",
                    serde_json::to_string(&serde_json::json!({
                        "status": "ok",
                        "rule_count": resolution.rule_set.rule_count(),
                        "policy": resolution.rule_set.policy_name(),
                        "sources": resolution.diagnostics.sources,
                        "provenance": resolution.diagnostics.provenance,
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
                let resolution =
                    resolve_rule_set_from_pack_paths_with_mode_override_paths_and_replacements(
                        &resolved_config.rule_pack_paths,
                        &resolved_config.explicit_rule_paths,
                        resolved_config.policy_path.as_deref(),
                        rule_load_mode(no_default_rules),
                        &resolved_config.override_paths,
                        &[],
                    )?;
                let source = Source {
                    client: ClientId::Codex,
                    kind: SourceKind::Jsonl,
                    source_id: "codex.sessions".to_string(),
                    path: fixture,
                };
                let detections = detect_sources_with_rules(&[source], &resolution.rule_set);
                if let Some((_, error_event)) = detections
                    .iter()
                    .find(|(_, event)| event.event_type == "scanner_error")
                {
                    let detail = error_event
                        .evidence
                        .iter()
                        .find(|evidence| evidence.field == "error")
                        .map(|evidence| evidence.redacted_value.as_str())
                        .unwrap_or("rule evaluation failed");
                    return Err(format!("rules test failed: {detail}").into());
                }
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
                    rules_server::RuleServerConfig {
                        rule_pack_paths: &resolved_config.rule_pack_paths,
                        explicit_rule_paths: &resolved_config.explicit_rule_paths,
                        editable_rule_paths: &resolved_config.editable_rule_paths,
                        override_paths: &resolved_config.override_paths,
                        policy_path: resolved_config.policy_path.as_deref(),
                        rule_load_mode: rule_load_mode(no_default_rules),
                    },
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
                    &resolved_config.rule_pack_paths,
                    &resolved_config.explicit_rule_paths,
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
            min_scan_interval_ms,
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
            let log_origin = path_origin(log_path.as_deref(), paths::LOG_PATH_ENV);
            let state_origin = path_origin(state_path.as_deref(), paths::STATE_PATH_ENV);
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
            let output_specs =
                sink_config::load_outputs_config(&resolved_config.discovered.output_paths)?;
            let sink_set = sink_config::build_sink_set_with_presence(
                &output_specs,
                !resolved_config.discovered.output_paths.is_empty(),
                &sink_config::CliSinkOverrides {
                    log_path: &log_path,
                    rotation,
                    splunk_hec_endpoint: None,
                    splunk_hec_token: None,
                },
                true,
            )?;
            let outputs = output_snapshot_value(
                &output_specs,
                &resolved_config.discovered.output_paths,
                !resolved_config.discovered.output_paths.is_empty(),
                &log_path,
                None,
                None,
                &sink_set,
            );
            let effective_configuration = effective_configuration_base(
                &local_config,
                EffectiveConfigurationPaths {
                    profile: path_profile,
                    log_path: &log_path,
                    state_path: &state_path,
                    log_origin,
                    state_origin,
                },
                &resolved_config,
                no_default_rules,
                &project_paths,
                outputs,
            );
            let watch_config = scan::WatchConfig {
                execution: scan::ScanExecutionConfig {
                    root: &root,
                    log_path: &log_path,
                    sinks: &sink_set,
                    state_path: &state_path,
                    dry_run,
                    emit_activity,
                    emit_session_risk_summary,
                    allow_fixtures,
                    rule_pack_paths: &resolved_config.rule_pack_paths,
                    rule_paths: &resolved_config.explicit_rule_paths,
                    override_paths: &resolved_config.override_paths,
                    rule_load_mode: rule_load_mode(no_default_rules),
                    policy_path: resolved_config.policy_path.as_deref(),
                    allowlist_path: resolved_config.allowlist_path.as_deref(),
                    baseline_deviation_scoring,
                    clients: &clients,
                    project_config_paths: &project_paths,
                    install_inventory_interval_seconds,
                    runtime: &runtime.value,
                    effective_configuration: &effective_configuration,
                },
                trigger: scan::WatchTriggerConfig {
                    iterations,
                    debounce: std::time::Duration::from_millis(debounce_ms),
                    min_scan_interval: std::time::Duration::from_millis(min_scan_interval_ms),
                },
            };
            scan::run_watch(watch_config)?;
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

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::observe_executable;

    #[test]
    fn executable_observation_streams_a_sha256_digest() {
        let observation = observe_executable(Ok(std::path::PathBuf::from("/tmp/telltale")), |_| {
            Ok(Box::new(Cursor::new(b"telltale-test".to_vec())))
        });

        assert_eq!(observation.status, "complete");
        assert_eq!(observation.path_hash.as_deref().unwrap().len(), 64);
        assert_eq!(
            observation.sha256.as_deref(),
            Some("95b5d3baf14cb332b2b1c62ca30438787685666fd1be1817bd469a845f4425c7")
        );
    }

    #[test]
    fn executable_observation_degrades_without_error_text() {
        let unavailable = observe_executable(
            Err(std::io::Error::other("private failure detail")),
            |_| unreachable!(),
        );
        assert_eq!(unavailable.status, "current_exe_unavailable");
        assert_eq!(unavailable.path_hash, None);
        assert_eq!(unavailable.sha256, None);

        let unreadable = observe_executable(Ok(std::path::PathBuf::from("/tmp/telltale")), |_| {
            Err(std::io::Error::other("private failure detail"))
        });
        assert_eq!(unreadable.status, "executable_read_failed");
        assert_eq!(unreadable.sha256, None);
    }
}
