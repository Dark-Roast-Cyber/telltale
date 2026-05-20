use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{Duration, Instant};

use clap::{Parser, Subcommand, ValueEnum};
use notify::{
    Config as NotifyConfig, Event as NotifyEvent, EventKind, RecommendedWatcher, RecursiveMode,
    Watcher,
};
use serde::Deserialize;
use time::OffsetDateTime;

use crate::allowlist::{load_allowlist, suppress_detection};
use crate::baseline::{BaselineDeviationConfig, build_baseline_summaries};
use crate::clients::{ClientId, SourceKind, supported_clients};
use crate::correlation::{CorrelationConfig, correlation_events_from_detections};
use crate::detection::{
    detect_sources_with_rules, evaluate_session_matches, summarize_source_activities_with_baselines,
};
use crate::discovery::{Source, discover_sources, discover_watch_roots, is_fixture_root};
use crate::event::{
    Event, HealthEventInput, OperationalAlertInput, evidence_hash, health_event_with_metadata,
    load_operational_alert_config, operational_alert_event, parse_event_timestamp,
};
use crate::parser::parse_source_records;
use crate::rules::{
    CompiledRuleSet, RuleSet, load_default_rule_set, load_rule_set_from_documents,
    load_rule_set_from_paths,
};
use crate::schema::{NormalizedRecordV1, Provenance};
use crate::scoring::load_thresholds;
use crate::sink::{LocalJsonlSink, SplunkHecConfig, SplunkHecHttpSink, emit_events};
use crate::state::{ScanState, source_fingerprint};
use crate::timeline::build_exported_session_timeline;
use crate::triage::maybe_triage;

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

        /// Append-only JSONL event path.
        #[arg(long, default_value = "logs/adr-events.jsonl")]
        log_path: PathBuf,

        /// Optional Splunk HEC collector URL. Requires --splunk-hec-token.
        #[arg(long)]
        splunk_hec_endpoint: Option<String>,

        /// Optional Splunk HEC token. Requires --splunk-hec-endpoint.
        #[arg(long)]
        splunk_hec_token: Option<String>,

        /// JSON state path for duplicate suppression.
        #[arg(long, default_value = "state/adr-state.json")]
        state_path: PathBuf,

        /// Print the event summary without writing JSONL.
        #[arg(long)]
        dry_run: bool,

        /// Emit per-session activity summary events in addition to detections.
        #[arg(long)]
        emit_activity: bool,

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
    },

    /// Watch local session stores and scan when files change.
    Watch {
        /// Root containing codex/ and opencode/ session stores.
        #[arg(long, default_value = ".")]
        root: PathBuf,

        /// Append-only JSONL event path.
        #[arg(long, default_value = "logs/adr-events.jsonl")]
        log_path: PathBuf,

        /// JSON state path for duplicate suppression.
        #[arg(long, default_value = "state/adr-state.json")]
        state_path: PathBuf,

        /// Print event summaries without writing JSONL.
        #[arg(long)]
        dry_run: bool,

        /// Emit per-session activity summary events in addition to detections.
        #[arg(long)]
        emit_activity: bool,

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
    },

    /// Inspect and validate Telltale detection rules.
    Rules {
        #[command(subcommand)]
        command: RulesCommand,
    },

    /// Show scanner status from the most recent health event.
    Status {
        /// Append-only JSONL event path.
        #[arg(long, default_value = "logs/adr-events.jsonl")]
        log_path: PathBuf,

        /// JSON state path for duplicate suppression.
        #[arg(long, default_value = "state/adr-state.json")]
        state_path: PathBuf,
    },

    /// Export filtered events from a Telltale JSONL log.
    Export {
        /// Append-only JSONL event path.
        #[arg(long, default_value = "logs/adr-events.jsonl")]
        log_path: PathBuf,

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
enum ExportFormat {
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
        addr: SocketAddr,

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

pub fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    match args.command {
        Command::Scan {
            once,
            interval_seconds,
            iterations,
            root,
            log_path,
            splunk_hec_endpoint,
            splunk_hec_token,
            state_path,
            dry_run,
            emit_activity,
            allow_fixtures,
            backfill,
            rebuild_baselines,
            rule_paths,
            policy,
            allowlist,
            baseline_deviation_scoring,
            clients,
            max_sources,
        } => {
            let scan_args = ScanCommandArgs {
                root: &root,
                log_path: &log_path,
                splunk_hec_endpoint: splunk_hec_endpoint.as_deref(),
                splunk_hec_token: splunk_hec_token.as_deref(),
                state_path: &state_path,
                dry_run,
                emit_activity,
                allow_fixtures,
                backfill,
                rebuild_baselines,
                rule_paths: &rule_paths,
                policy_path: policy.as_deref(),
                allowlist_path: allowlist.as_deref(),
                baseline_deviation_scoring,
                clients: &clients,
                max_sources,
            };
            if once {
                run_scan_once(scan_config(&scan_args))?;
            } else {
                let interval =
                    interval_seconds.ok_or("scan requires --once or --interval-seconds")?;
                run_scan_loop(&scan_args, iterations, Duration::from_secs(interval))?;
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
                run_rules_server(addr, &rule_paths, policy.as_deref(), once)?;
            }
            RulesCommand::Coverage {
                root,
                rule_paths,
                policy,
            } => {
                run_rules_coverage(&root, &rule_paths, policy.as_deref())?;
            }
        },
        Command::Watch {
            root,
            log_path,
            state_path,
            dry_run,
            emit_activity,
            allow_fixtures,
            iterations,
            debounce_ms,
            rule_paths,
            policy,
            allowlist,
            baseline_deviation_scoring,
        } => {
            let watch_args = WatchCommandArgs {
                root: &root,
                log_path: &log_path,
                state_path: &state_path,
                dry_run,
                emit_activity,
                allow_fixtures,
                iterations,
                debounce: Duration::from_millis(debounce_ms),
                rule_paths: &rule_paths,
                policy_path: policy.as_deref(),
                allowlist_path: allowlist.as_deref(),
                baseline_deviation_scoring,
            };
            run_watch(watch_config(&watch_args))?;
        }
        Command::Status {
            log_path,
            state_path,
        } => {
            run_status(&log_path, &state_path)?;
        }
        Command::Export {
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
            run_export(ExportConfig {
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

fn run_rules_server(
    addr: SocketAddr,
    rule_paths: &[PathBuf],
    policy_path: Option<&Path>,
    once: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if !addr.ip().is_loopback() {
        return Err("rules serve only binds to loopback addresses".into());
    }
    let rule_set = load_rule_set_from_paths(rule_paths, policy_path)?;
    let mut state = RuleServerState::new(rule_set);
    let listener = TcpListener::bind(addr)?;
    println!(
        "{}",
        serde_json::to_string(&serde_json::json!({
            "status": "listening",
            "addr": listener.local_addr()?.to_string(),
            "endpoints": [
                "/",
                "/api/rules",
                "/api/rules/validate",
                "/api/rules/preview",
                "/api/rules/save",
            ],
        }))?
    );
    std::io::stdout().flush()?;
    if once {
        let (stream, _) = listener.accept()?;
        handle_rules_request(stream, &mut state, rule_paths, policy_path)?;
        return Ok(());
    }
    for stream in listener.incoming() {
        handle_rules_request(stream?, &mut state, rule_paths, policy_path)?;
    }
    Ok(())
}

struct RuleServerState {
    rule_set: CompiledRuleSet,
    rule_summary: serde_json::Value,
}

impl RuleServerState {
    fn new(rule_set: CompiledRuleSet) -> Self {
        let rule_summary = rule_summary_json(&rule_set);
        Self {
            rule_set,
            rule_summary,
        }
    }

    fn reload(&mut self, rule_set: CompiledRuleSet) {
        *self = Self::new(rule_set);
    }
}

fn rule_summary_json(rule_set: &CompiledRuleSet) -> serde_json::Value {
    serde_json::json!({
        "status": "ok",
        "rule_count": rule_set.rule_count(),
        "policy": rule_set.policy_name(),
        "rules": rule_set.summaries(),
    })
}

#[derive(Clone, Copy)]
enum RuleServerRoute {
    Editor,
    Summary,
    Validate,
    Preview,
    Save,
    NotFound,
}

struct HttpRequest {
    method: String,
    path: String,
    body: Vec<u8>,
}

fn handle_rules_request(
    mut stream: TcpStream,
    state: &mut RuleServerState,
    rule_paths: &[PathBuf],
    policy_path: Option<&Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    let peer_ip = stream.peer_addr()?.ip();
    if !peer_ip.is_loopback() {
        write_http_response(
            &mut stream,
            403,
            "Forbidden",
            "text/plain; charset=utf-8",
            "loopback clients only",
        )?;
        return Ok(());
    }
    let request = read_http_request(&stream)?;
    write_rules_route_response(
        &mut stream,
        rule_server_route(&request),
        &request.body,
        state,
        rule_paths,
        policy_path,
    )?;
    Ok(())
}

fn read_http_request(stream: &TcpStream) -> Result<HttpRequest, Box<dyn std::error::Error>> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;

    let mut content_length = 0_usize;
    loop {
        let mut header = String::new();
        reader.read_line(&mut header)?;
        let trimmed = header.trim_end();
        if trimmed.is_empty() {
            break;
        }
        if let Some(value) = trimmed.strip_prefix("Content-Length: ") {
            content_length = value.parse::<usize>()?;
        }
    }

    let mut body = vec![0_u8; content_length];
    if content_length > 0 {
        reader.read_exact(&mut body)?;
    }

    let mut parts = request_line.split_whitespace();
    Ok(HttpRequest {
        method: parts.next().unwrap_or_default().to_string(),
        path: parts.next().unwrap_or_default().to_string(),
        body,
    })
}

fn rule_server_route(request: &HttpRequest) -> RuleServerRoute {
    match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/") | ("HEAD", "/") => RuleServerRoute::Editor,
        ("GET", "/api/rules") | ("HEAD", "/api/rules") => RuleServerRoute::Summary,
        ("POST", "/api/rules/validate") => RuleServerRoute::Validate,
        ("POST", "/api/rules/preview") => RuleServerRoute::Preview,
        ("POST", "/api/rules/save") => RuleServerRoute::Save,
        _ => RuleServerRoute::NotFound,
    }
}

fn write_rules_route_response(
    stream: &mut TcpStream,
    route: RuleServerRoute,
    body: &[u8],
    state: &mut RuleServerState,
    rule_paths: &[PathBuf],
    policy_path: Option<&Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    match route {
        RuleServerRoute::Editor => write_http_response(
            stream,
            200,
            "OK",
            "text/html; charset=utf-8",
            RULE_EDITOR_HTML,
        ),
        RuleServerRoute::Summary => write_json_response(stream, 200, "OK", &state.rule_summary),
        RuleServerRoute::Validate => write_json_api_response(stream, validate_rules_request(body)?),
        RuleServerRoute::Preview => {
            write_json_api_response(stream, preview_rules_request(body, &state.rule_set)?)
        }
        RuleServerRoute::Save => {
            let response = save_rules_request(body, rule_paths)?;
            if response.status_code == 200 {
                state.reload(load_rule_set_from_paths(rule_paths, policy_path)?);
            }
            write_json_api_response(stream, response)
        }
        RuleServerRoute::NotFound => write_http_response(
            stream,
            404,
            "Not Found",
            "text/plain; charset=utf-8",
            "not found",
        ),
    }
}

#[derive(Debug, Deserialize)]
struct RuleValidationRequest {
    rules_yaml: String,
    #[serde(default)]
    policy_yaml: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RulePreviewRequest {
    fixture_path: PathBuf,
    #[serde(default)]
    rules_yaml: Option<String>,
    #[serde(default)]
    policy_yaml: Option<String>,
}

struct ApiResponse {
    status_code: u16,
    reason: &'static str,
    body: serde_json::Value,
}

impl ApiResponse {
    fn ok(body: serde_json::Value) -> Self {
        Self {
            status_code: 200,
            reason: "OK",
            body,
        }
    }

    fn bad_request(error: impl Into<String>) -> Self {
        Self {
            status_code: 400,
            reason: "Bad Request",
            body: serde_json::json!({
                "status": "error",
                "error": error.into(),
            }),
        }
    }
}

fn validate_rules_request(body: &[u8]) -> Result<ApiResponse, Box<dyn std::error::Error>> {
    let request: RuleValidationRequest = serde_json::from_slice(body)?;
    match compile_rule_yaml(&request.rules_yaml, request.policy_yaml.as_deref()) {
        Ok(rule_set) => Ok(ApiResponse::ok(rule_summary_json(&rule_set))),
        Err(error) => Ok(ApiResponse::bad_request(error.to_string())),
    }
}

fn preview_rules_request(
    body: &[u8],
    default_rule_set: &CompiledRuleSet,
) -> Result<ApiResponse, Box<dyn std::error::Error>> {
    let request: RulePreviewRequest = serde_json::from_slice(body)?;
    let fixture_path = match canonical_fixture_path(&request.fixture_path) {
        Ok(path) => path,
        Err(error) => return Ok(ApiResponse::bad_request(error.to_string())),
    };
    let rule_set = if let Some(rules_yaml) = request.rules_yaml.as_deref() {
        match compile_rule_yaml(rules_yaml, request.policy_yaml.as_deref()) {
            Ok(rule_set) => rule_set,
            Err(error) => return Ok(ApiResponse::bad_request(error.to_string())),
        }
    } else {
        default_rule_set.clone()
    };
    let source = Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "rules.serve.preview".to_string(),
        path: fixture_path.clone(),
    };
    let detections = detect_sources_with_rules(&[source], &rule_set);
    if let Some((_, event)) = detections
        .iter()
        .find(|(_, event)| event.event_type == "scanner_error")
    {
        return Ok(ApiResponse::bad_request(format!(
            "fixture parse failed for {}",
            event.session_id
        )));
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

    Ok(ApiResponse::ok(serde_json::json!({
        "status": "ok",
        "fixture_path": display_fixture_path(&fixture_path),
        "match_count": matches.len(),
        "matches": matches,
    })))
}

#[derive(Debug, Deserialize)]
struct RuleSaveRequest {
    rules_yaml: String,
    #[serde(default)]
    policy_yaml: Option<String>,
    /// Target rule file path. Must be one of the loaded rule_paths.
    /// Defaults to the first rule_path if omitted.
    #[serde(default)]
    path: Option<PathBuf>,
}

fn save_rules_request(
    body: &[u8],
    rule_paths: &[PathBuf],
) -> Result<ApiResponse, Box<dyn std::error::Error>> {
    let request: RuleSaveRequest = serde_json::from_slice(body)?;

    // Validate rules compile before writing.
    if let Err(error) = compile_rule_yaml(&request.rules_yaml, request.policy_yaml.as_deref()) {
        return Ok(ApiResponse::bad_request(error.to_string()));
    }

    // Resolve target path: must be one of the loaded rule_paths.
    let target = if let Some(ref requested) = request.path {
        let canonical_requested = requested.canonicalize().map_err(|e| {
            format!(
                "cannot resolve requested path '{}': {e}",
                requested.display()
            )
        })?;
        let allowed = rule_paths.iter().any(|rp| {
            rp.canonicalize()
                .map(|c| c == canonical_requested)
                .unwrap_or(false)
        });
        if !allowed {
            return Ok(ApiResponse::bad_request(format!(
                "requested path '{}' is not one of the loaded rule files",
                requested.display()
            )));
        }
        canonical_requested
    } else {
        rule_paths
            .first()
            .ok_or("no rule paths configured")?
            .canonicalize()?
    };

    // Backup existing file.
    let backup = target.with_extension("yaml.bak");
    if target.exists() {
        std::fs::copy(&target, &backup)?;
    }

    // Atomic write: temp file in same directory, then rename.
    let dir = target.parent().ok_or("rule file has no parent directory")?;
    let tmp = dir.join(".adr-rules-save.tmp");
    std::fs::write(&tmp, &request.rules_yaml)?;
    std::fs::rename(&tmp, &target)?;

    Ok(ApiResponse::ok(serde_json::json!({
        "status": "ok",
        "saved": target.display().to_string(),
        "backup": backup.display().to_string(),
        "rule_count": request.rules_yaml.lines().filter(|l| l.contains("id:")).count(),
    })))
}

fn compile_rule_yaml(
    rules_yaml: &str,
    policy_yaml: Option<&str>,
) -> Result<CompiledRuleSet, Box<dyn std::error::Error>> {
    load_rule_set_from_documents(&[rules_yaml], policy_yaml)
}

fn canonical_fixture_path(path: &Path) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let requested = if path.is_absolute() {
        path.to_path_buf()
    } else {
        manifest_dir.join(path)
    };
    let canonical = requested.canonicalize()?;
    let fixture_root = manifest_dir.join("tests/fixtures").canonicalize()?;
    if !canonical.starts_with(&fixture_root) {
        return Err("preview fixture must be under tests/fixtures".into());
    }
    Ok(canonical)
}

fn display_fixture_path(path: &Path) -> String {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    path.strip_prefix(manifest_dir)
        .unwrap_or(path)
        .display()
        .to_string()
}

fn write_json_api_response(
    stream: &mut TcpStream,
    response: ApiResponse,
) -> Result<(), Box<dyn std::error::Error>> {
    write_json_response(
        stream,
        response.status_code,
        response.reason,
        &response.body,
    )
}

fn write_json_response(
    stream: &mut TcpStream,
    status_code: u16,
    reason: &str,
    body: &serde_json::Value,
) -> Result<(), Box<dyn std::error::Error>> {
    write_http_response(
        stream,
        status_code,
        reason,
        "application/json",
        &serde_json::to_string(body)?,
    )
}

fn write_http_response(
    stream: &mut TcpStream,
    status_code: u16,
    reason: &str,
    content_type: &str,
    body: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    write!(
        stream,
        "HTTP/1.1 {status_code} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )?;
    Ok(())
}

const RULE_EDITOR_HTML: &str = r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Telltale Rules</title>
<style>
:root { color-scheme: light dark; font-family: system-ui, sans-serif; }
body { margin: 0; padding: 24px; }
main { max-width: 960px; margin: 0 auto; }
section { margin-top: 24px; }
table { width: 100%; border-collapse: collapse; }
th, td { padding: 8px; border-bottom: 1px solid #8885; text-align: left; }
label { display: block; margin: 12px 0 4px; font-weight: 600; }
textarea, input { box-sizing: border-box; width: 100%; font: inherit; }
textarea { min-height: 160px; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
button { margin-top: 12px; padding: 6px 10px; font: inherit; }
pre { white-space: pre-wrap; overflow-wrap: anywhere; }
code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
</style>
</head>
<body>
<main>
<h1>Telltale Rules</h1>
<table>
<thead><tr><th>ID</th><th>Category</th><th>Severity</th><th>Score</th></tr></thead>
<tbody id="rules"></tbody>
</table>
<section>
<h2>Validate</h2>
<label for="rules-yaml">Rule YAML</label>
<textarea id="rules-yaml"></textarea>
<button id="validate-rules">Validate</button>
<pre id="validation-result"></pre>
</section>
<section>
<h2>Fixture Preview</h2>
<label for="fixture-path">Fixture path</label>
<input id="fixture-path" value="tests/fixtures/rule_samples/tool-injection-shape.jsonl">
<button id="preview-rules">Preview</button>
<pre id="preview-result"></pre>
</section>
</main>
<script>
fetch('/api/rules').then(response => response.json()).then(data => {
  const body = document.getElementById('rules');
  body.textContent = '';
  for (const rule of data.rules) {
    const row = document.createElement('tr');
    for (const key of ['id', 'category', 'severity', 'score']) {
      const cell = document.createElement('td');
      cell.textContent = rule[key];
      row.appendChild(cell);
    }
    body.appendChild(row);
  }
});

function postJson(path, payload, target) {
  fetch(path, {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(payload)
  }).then(async response => {
    const data = await response.json();
    target.textContent = JSON.stringify(data, null, 2);
  }).catch(error => {
    target.textContent = String(error);
  });
}

document.getElementById('validate-rules').addEventListener('click', () => {
  postJson('/api/rules/validate', {
    rules_yaml: document.getElementById('rules-yaml').value
  }, document.getElementById('validation-result'));
});

document.getElementById('preview-rules').addEventListener('click', () => {
  postJson('/api/rules/preview', {
    rules_yaml: document.getElementById('rules-yaml').value || undefined,
    fixture_path: document.getElementById('fixture-path').value
  }, document.getElementById('preview-result'));
});
</script>
</body>
</html>"#;

fn run_rules_coverage(
    root: &Path,
    rule_paths: &[PathBuf],
    policy_path: Option<&Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    let rule_set = load_rule_set_from_paths(rule_paths, policy_path)?;

    // Load raw YAML to get false-positive notes.
    let paths = if rule_paths.is_empty() {
        vec![crate::rules::default_rule_path()]
    } else {
        rule_paths.to_vec()
    };
    let mut all_falsepositives: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut all_rule_categories: BTreeMap<String, String> = BTreeMap::new();
    for path in &paths {
        let raw = fs::read_to_string(path)?;
        let parsed: RuleSet = serde_yaml::from_str(&raw)?;
        for rule in &parsed.rules {
            all_rule_categories.insert(rule.id.clone(), rule.category.clone());
            if !rule.falsepositives.is_empty() {
                all_falsepositives.insert(rule.id.clone(), rule.falsepositives.clone());
            }
        }
        for modifier in &parsed.modifiers {
            if !modifier.when_all_categories.is_empty() {
                all_rule_categories
                    .insert(modifier.id.clone(), modifier.when_all_categories.join("+"));
            } else if !modifier.when_all_rule_ids.is_empty() {
                all_rule_categories
                    .insert(modifier.id.clone(), modifier.when_all_rule_ids.join("+"));
            }
            if !modifier.falsepositives.is_empty() {
                all_falsepositives.insert(modifier.id.clone(), modifier.falsepositives.clone());
            }
        }
    }

    let sources = discover_sources(root);
    if sources.is_empty() {
        println!("No fixture sources found under {}", root.display());
        return Ok(());
    }

    let detections = detect_sources_with_rules(&sources, &rule_set);

    // Build coverage map: rule_id -> (positive session_ids, clients).
    let mut positive_sessions: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut rule_clients: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut all_rule_ids: BTreeSet<String> = BTreeSet::new();
    let mut detected_source_paths: BTreeSet<String> = BTreeSet::new();

    for rule_summary in rule_set.summaries() {
        all_rule_ids.insert(rule_summary.id);
    }

    for (source, event) in &detections {
        detected_source_paths.insert(source.path.to_string_lossy().to_string());
        for rule_id in &event.rule_ids {
            all_rule_ids.insert(rule_id.clone());
            positive_sessions
                .entry(rule_id.clone())
                .or_default()
                .insert(event.session_id.clone());
            rule_clients
                .entry(rule_id.clone())
                .or_default()
                .insert(source.client.as_str().to_string());
        }
    }

    // Count benign fixtures (sources with no detections).
    let total_fixture_sources = sources.len();
    let sources_with_detections = sources
        .iter()
        .filter(|s| detected_source_paths.contains(&s.path.to_string_lossy().to_string()))
        .count();
    let benign_count = total_fixture_sources - sources_with_detections;

    println!(
        "RULE COVERAGE REPORT ({} rules, {} fixture sources, {} benign)\n",
        all_rule_ids.len(),
        total_fixture_sources,
        benign_count
    );

    println!(
        "{:<45} {:<10} {:<10} {:<20} FALSE_POSITIVES",
        "RULE_ID", "POSITIVE", "CLIENTS", "CATEGORIES"
    );
    println!("{}", "-".repeat(120));

    for rule_id in &all_rule_ids {
        let pos_count = positive_sessions.get(rule_id).map_or(0, |s| s.len());
        let client_count = rule_clients.get(rule_id).map_or(0, |s| s.len());
        let fps = all_falsepositives
            .get(rule_id)
            .map_or(String::new(), |v| v.join("; "));

        // Find category from rule set summaries.
        let category = all_rule_categories
            .get(rule_id)
            .cloned()
            .unwrap_or_else(|| {
                rule_set
                    .summaries()
                    .iter()
                    .find(|s| s.id == *rule_id)
                    .map_or(String::new(), |s| s.category.clone())
            });

        println!(
            "{:<45} {:<10} {:<10} {:<20} {}",
            rule_id, pos_count, client_count, category, fps
        );
    }

    // Summary of gaps.
    let zero_coverage: Vec<&String> = all_rule_ids
        .iter()
        .filter(|id| !positive_sessions.contains_key(*id))
        .collect();
    if !zero_coverage.is_empty() {
        println!(
            "\nCOVERAGE GAPS ({} rules with no positive fixtures):",
            zero_coverage.len()
        );
        for id in zero_coverage {
            println!("  - {}", id);
        }
    }

    Ok(())
}

fn json_field_or_null(value: &serde_json::Value, key: &str) -> serde_json::Value {
    value.get(key).cloned().unwrap_or(serde_json::Value::Null)
}

fn json_field_or_empty_object(value: &serde_json::Value, key: &str) -> serde_json::Value {
    value
        .get(key)
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}))
}

struct ScanSummaryInput<'a> {
    emitted_events: &'a [Event],
    activity_count: usize,
    detection_count: usize,
    suppressed_count: usize,
    rule_count: usize,
    active_policy_name: Option<&'a str>,
    dry_run: bool,
    log_path: &'a Path,
}

fn scan_summary_json(summary: ScanSummaryInput<'_>) -> serde_json::Value {
    serde_json::json!({
        "client": summary.emitted_events[0].client,
        "event_type": summary.emitted_events[0].event_type,
        "activity_count": summary.activity_count,
        "detection_count": summary.detection_count,
        "suppressed_count": summary.suppressed_count,
        "emitted_count": summary.emitted_events.len().saturating_sub(1),
        "rule_count": summary.rule_count,
        "policy": summary.active_policy_name,
        "log_path": if summary.dry_run { None } else { Some(summary.log_path.display().to_string()) },
        "source_counts": summary.emitted_events[0].source_counts.clone().unwrap_or_default(),
    })
}

fn status_json(
    health: &serde_json::Value,
    detection_count: usize,
    log_path: &Path,
    state_path: &Path,
) -> serde_json::Value {
    serde_json::json!({
        "status": "ok",
        "last_scan_time": json_field_or_null(health, "timestamp"),
        "log_path": log_path.display().to_string(),
        "state_path": state_path.display().to_string(),
        "active_policy_name": json_field_or_null(health, "active_policy_name"),
        "rule_count": json_field_or_null(health, "rule_count"),
        "detection_count": detection_count,
        "threshold_config": json_field_or_null(health, "threshold_config"),
        "source_counts": json_field_or_empty_object(health, "source_counts"),
    })
}

struct ScanConfig<'a> {
    root: &'a std::path::Path,
    log_path: &'a std::path::Path,
    splunk_hec_endpoint: Option<&'a str>,
    splunk_hec_token: Option<&'a str>,
    state_path: &'a std::path::Path,
    dry_run: bool,
    emit_activity: bool,
    allow_fixtures: bool,
    backfill: bool,
    rebuild_baselines: bool,
    rule_paths: &'a [PathBuf],
    policy_path: Option<&'a std::path::Path>,
    allowlist_path: Option<&'a std::path::Path>,
    baseline_deviation_scoring: bool,
    clients: &'a [ClientId],
    max_sources: Option<usize>,
}

struct ScanCommandArgs<'a> {
    root: &'a std::path::Path,
    log_path: &'a std::path::Path,
    splunk_hec_endpoint: Option<&'a str>,
    splunk_hec_token: Option<&'a str>,
    state_path: &'a std::path::Path,
    dry_run: bool,
    emit_activity: bool,
    allow_fixtures: bool,
    backfill: bool,
    rebuild_baselines: bool,
    rule_paths: &'a [PathBuf],
    policy_path: Option<&'a std::path::Path>,
    allowlist_path: Option<&'a std::path::Path>,
    baseline_deviation_scoring: bool,
    clients: &'a [ClientId],
    max_sources: Option<usize>,
}

struct WatchConfig<'a> {
    root: &'a std::path::Path,
    log_path: &'a std::path::Path,
    state_path: &'a std::path::Path,
    dry_run: bool,
    emit_activity: bool,
    allow_fixtures: bool,
    iterations: Option<u32>,
    debounce: Duration,
    rule_paths: &'a [PathBuf],
    policy_path: Option<&'a std::path::Path>,
    allowlist_path: Option<&'a std::path::Path>,
    baseline_deviation_scoring: bool,
}

struct WatchCommandArgs<'a> {
    root: &'a std::path::Path,
    log_path: &'a std::path::Path,
    state_path: &'a std::path::Path,
    dry_run: bool,
    emit_activity: bool,
    allow_fixtures: bool,
    iterations: Option<u32>,
    debounce: Duration,
    rule_paths: &'a [PathBuf],
    policy_path: Option<&'a std::path::Path>,
    allowlist_path: Option<&'a std::path::Path>,
    baseline_deviation_scoring: bool,
}

fn scan_config<'a>(args: &'a ScanCommandArgs<'a>) -> ScanConfig<'a> {
    ScanConfig {
        root: args.root,
        log_path: args.log_path,
        splunk_hec_endpoint: args.splunk_hec_endpoint,
        splunk_hec_token: args.splunk_hec_token,
        state_path: args.state_path,
        dry_run: args.dry_run,
        emit_activity: args.emit_activity,
        allow_fixtures: args.allow_fixtures,
        backfill: args.backfill,
        rebuild_baselines: args.rebuild_baselines,
        rule_paths: args.rule_paths,
        policy_path: args.policy_path,
        allowlist_path: args.allowlist_path,
        baseline_deviation_scoring: args.baseline_deviation_scoring,
        clients: args.clients,
        max_sources: args.max_sources,
    }
}

fn watch_config<'a>(args: &'a WatchCommandArgs<'a>) -> WatchConfig<'a> {
    WatchConfig {
        root: args.root,
        log_path: args.log_path,
        state_path: args.state_path,
        dry_run: args.dry_run,
        emit_activity: args.emit_activity,
        allow_fixtures: args.allow_fixtures,
        iterations: args.iterations,
        debounce: args.debounce,
        rule_paths: args.rule_paths,
        policy_path: args.policy_path,
        allowlist_path: args.allowlist_path,
        baseline_deviation_scoring: args.baseline_deviation_scoring,
    }
}

fn watch_scan_config<'a>(config: &'a WatchConfig<'a>) -> ScanConfig<'a> {
    ScanConfig {
        root: config.root,
        log_path: config.log_path,
        splunk_hec_endpoint: None,
        splunk_hec_token: None,
        state_path: config.state_path,
        dry_run: config.dry_run,
        emit_activity: config.emit_activity,
        allow_fixtures: config.allow_fixtures,
        backfill: false,
        rebuild_baselines: false,
        rule_paths: config.rule_paths,
        policy_path: config.policy_path,
        allowlist_path: config.allowlist_path,
        baseline_deviation_scoring: config.baseline_deviation_scoring,
        clients: &[],
        max_sources: None,
    }
}

fn run_scan_loop(
    scan_args: &ScanCommandArgs<'_>,
    iterations: Option<u32>,
    interval: Duration,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut remaining = iterations;
    loop {
        run_scan_once(scan_config(scan_args))?;
        if let Some(value) = remaining.as_mut() {
            if *value == 1 {
                break;
            }
            *value -= 1;
        }
        thread::sleep(interval);
    }
    Ok(())
}

fn run_watch(config: WatchConfig<'_>) -> Result<(), Box<dyn std::error::Error>> {
    if !config.dry_run && !config.allow_fixtures && is_fixture_root(config.root) {
        return Err(
            "refusing to write fixture/demo data to log path; use --dry-run or --allow-fixtures"
                .into(),
        );
    }

    let watch_roots = discover_watch_roots(config.root);
    if watch_roots.is_empty() {
        return Err(format!(
            "no existing Telltale session-store roots found under {}",
            config.root.display()
        )
        .into());
    }

    let (tx, rx) = mpsc::channel();
    let mut watcher = RecommendedWatcher::new(
        move |result| {
            let _ = tx.send(result);
        },
        NotifyConfig::default(),
    )?;
    for root in &watch_roots {
        watcher.watch(root, RecursiveMode::Recursive)?;
    }

    let mut remaining = config.iterations;
    loop {
        let event = receive_watch_event(&rx)?;
        if !watch_event_should_scan(&event) {
            continue;
        }
        thread::sleep(config.debounce);
        drain_watch_events(&rx);

        run_scan_once(watch_scan_config(&config))?;

        if let Some(value) = remaining.as_mut() {
            if *value == 1 {
                break;
            }
            *value -= 1;
        }
    }
    Ok(())
}

fn receive_watch_event(
    rx: &Receiver<notify::Result<NotifyEvent>>,
) -> Result<NotifyEvent, Box<dyn std::error::Error>> {
    match rx.recv()? {
        Ok(event) => Ok(event),
        Err(e) => Err(Box::new(e)),
    }
}

fn drain_watch_events(rx: &Receiver<notify::Result<NotifyEvent>>) {
    while rx.try_recv().is_ok() {}
}

fn watch_event_should_scan(event: &NotifyEvent) -> bool {
    matches!(
        event.kind,
        EventKind::Create(_) | EventKind::Modify(_) | EventKind::Remove(_)
    )
}

fn run_scan_once(config: ScanConfig<'_>) -> Result<(), Box<dyn std::error::Error>> {
    let scan_started = Instant::now();
    if !config.dry_run && !config.allow_fixtures && is_fixture_root(config.root) {
        return Err(
            "refusing to write fixture/demo data to log path; use --dry-run or --allow-fixtures"
                .into(),
        );
    }
    let splunk_hec_sink = splunk_hec_sink(config.splunk_hec_endpoint, config.splunk_hec_token)?;
    let mut sources = discover_sources(config.root);
    if !config.clients.is_empty() {
        let allowed_clients = config.clients.iter().copied().collect::<BTreeSet<_>>();
        sources.retain(|source| allowed_clients.contains(&source.client));
    }
    if let Some(max_sources) = config.max_sources {
        sources.truncate(max_sources);
    }
    let rule_set = load_rule_set_from_paths(config.rule_paths, config.policy_path)?;
    let rule_count = rule_set.rule_count();
    let active_policy_name = rule_set.policy_name().map(str::to_string);
    let allowlist = load_allowlist(config.allowlist_path)?;
    let mut state = ScanState::load(config.state_path)?;
    let baseline_snapshots = state.baseline_snapshots.clone();
    update_baseline_snapshots(&mut state, &sources, config.rebuild_baselines);
    let activities = if config.emit_activity {
        summarize_source_activities_with_baselines(
            &sources,
            &baseline_snapshots,
            BaselineDeviationConfig {
                enabled: config.baseline_deviation_scoring,
                ..BaselineDeviationConfig::default()
            },
        )
    } else {
        Vec::new()
    };
    let mut detections = detect_sources_with_rules(&sources, &rule_set);
    let mut suppressed_count = 0_usize;
    for (source, detection) in &mut detections {
        if let Some(suppression_match) = allowlist.suppression_for(source, detection) {
            suppress_detection(detection, &suppression_match);
            suppressed_count += 1;
        }
    }
    for (_, detection) in &mut detections {
        if let Some(triage_value) = &detection.triage
            && triage_value
                .get("required")
                .and_then(|v| v.as_bool())
                .is_some_and(|v| v)
        {
            match maybe_triage(detection)? {
                Some(outcome) => {
                    detection.triage = Some(serde_json::json!({
                        "required": true,
                        "verdict": outcome.verdict,
                        "confidence": outcome.confidence,
                        "reason": outcome.reason,
                    }));
                }
                None => {
                    detection.triage = Some(serde_json::json!({
                        "required": true,
                        "verdict": "config_missing"
                    }));
                }
            }
        }
    }
    let activity_count = activities.len();
    let detection_count = detections.len();
    let scan_duration_ms = scan_started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
    let observed_at_unix_ms = OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000;
    let observed_at_unix_ms = u64::try_from(observed_at_unix_ms).unwrap_or_default();
    let health = health_event_with_metadata(HealthEventInput {
        sources: &sources,
        scan_duration_ms,
        rule_count,
        threshold_config: load_thresholds(),
        active_policy_name: active_policy_name.as_deref(),
    });

    // Operational alerting: emit alerts when scanner health thresholds are exceeded.
    let op_config = load_operational_alert_config();
    let scanner_error_count = detections
        .iter()
        .filter(|(_, event)| event.event_type == "scanner_error")
        .count() as u32;
    let mut operational_alerts = Vec::new();
    if scanner_error_count > op_config.max_scanner_errors {
        operational_alerts.push(operational_alert_event(OperationalAlertInput {
            alert_type: "scanner_error_threshold_exceeded".to_string(),
            threshold: format!("max_scanner_errors={}", op_config.max_scanner_errors),
            actual_value: format!("scanner_error_count={scanner_error_count}"),
            scan_duration_ms: Some(scan_duration_ms),
            scanner_error_count: Some(scanner_error_count),
        }));
    }
    if scan_duration_ms > op_config.max_scan_duration_ms {
        operational_alerts.push(operational_alert_event(OperationalAlertInput {
            alert_type: "scan_duration_threshold_exceeded".to_string(),
            threshold: format!("max_scan_duration_ms={}", op_config.max_scan_duration_ms),
            actual_value: format!("scan_duration_ms={scan_duration_ms}"),
            scan_duration_ms: Some(scan_duration_ms),
            scanner_error_count: Some(scanner_error_count),
        }));
    }
    for observation in state.silent_source_observations(
        &sources,
        observed_at_unix_ms,
        op_config.max_source_silence_ms,
    ) {
        let source_label = if observation.source_instance_id.is_empty() {
            observation.source_id.clone()
        } else {
            format!(
                "{}/{}",
                observation.source_id, observation.source_instance_id
            )
        };
        operational_alerts.push(operational_alert_event(OperationalAlertInput {
            alert_type: "source_silence_threshold_exceeded".to_string(),
            threshold: format!("max_source_silence_ms={}", op_config.max_source_silence_ms),
            actual_value: format!(
                "missing_source={}/{};last_seen_unix_ms={}",
                observation.client, source_label, observation.last_seen_unix_ms
            ),
            scan_duration_ms: Some(scan_duration_ms),
            scanner_error_count: Some(scanner_error_count),
        }));
    }
    state.observe_sources(&sources, observed_at_unix_ms);

    let mut emitted_events =
        Vec::with_capacity(activities.len() + detections.len() + operational_alerts.len() + 1);
    emitted_events.push(health);
    for alert in operational_alerts {
        emitted_events.push(alert);
    }
    for (source, activity) in activities {
        if config.backfill || state.should_emit(&source, &activity) {
            emitted_events.push(activity);
        }
    }
    for (source, detection) in detections {
        if config.backfill || state.should_emit(&source, &detection) {
            emitted_events.push(detection);
        }
    }

    if !config.dry_run {
        let sink = LocalJsonlSink::new(config.log_path);
        emit_events(&sink, &emitted_events)?;
        if let Some(sink) = splunk_hec_sink {
            emit_events(&sink, &emitted_events)?;
        }
        state.save(config.state_path)?;
    }

    let summary = scan_summary_json(ScanSummaryInput {
        emitted_events: &emitted_events,
        activity_count,
        detection_count,
        suppressed_count,
        rule_count,
        active_policy_name: active_policy_name.as_deref(),
        dry_run: config.dry_run,
        log_path: config.log_path,
    });
    println!("{}", serde_json::to_string(&summary)?);
    Ok(())
}

fn splunk_hec_sink(
    endpoint: Option<&str>,
    token: Option<&str>,
) -> Result<Option<SplunkHecHttpSink>, Box<dyn std::error::Error>> {
    match (endpoint, token) {
        (None, None) => Ok(None),
        (Some(endpoint), Some(token)) => Ok(Some(SplunkHecHttpSink::new(
            endpoint.to_string(),
            token.to_string(),
            SplunkHecConfig::default(),
        ))),
        _ => Err("--splunk-hec-endpoint and --splunk-hec-token must be set together".into()),
    }
}

fn update_baseline_snapshots(state: &mut ScanState, sources: &[Source], force_rebuild: bool) {
    if state.has_legacy_source_identity_state() {
        state.drop_legacy_source_identity_state();
        state.rebuild_baseline_snapshots_from_source_contributions();
    }
    for source in sources {
        let fingerprint = source_fingerprint(source);
        if !force_rebuild && state.seen_source_fingerprints.contains(&fingerprint) {
            continue;
        }
        let Ok(records) = parse_source_records(source) else {
            continue;
        };
        let summaries = build_baseline_summaries(&records);
        state.record_baseline_source_contribution(source, fingerprint.clone(), summaries);
        state.rebuild_baseline_snapshots_from_source_contributions();
        state.seen_source_fingerprints.insert(fingerprint);
    }
}

fn run_status(log_path: &Path, state_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let contents = fs::read_to_string(log_path)?;
    let events = contents
        .lines()
        .filter(|line| !line.trim().is_empty())
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .collect::<Vec<_>>();
    let health_index = events
        .iter()
        .rposition(|event| {
            event.get("event_type").and_then(|value| value.as_str()) == Some("health")
        })
        .ok_or_else(|| format!("no health event found in {}", log_path.display()))?;
    let health = &events[health_index];
    let detection_count = events[health_index + 1..]
        .iter()
        .filter(|event| {
            event.get("event_type").and_then(|value| value.as_str()) == Some("detection")
        })
        .count();

    let status = status_json(health, detection_count, log_path, state_path);
    println!("{}", serde_json::to_string(&status)?);
    Ok(())
}

struct ExportConfig<'a> {
    log_path: &'a Path,
    severities: &'a [String],
    clients: &'a [String],
    session_ids: &'a [String],
    rule_ids: &'a [String],
    since: Option<&'a str>,
    until: Option<&'a str>,
    format: ExportFormat,
    correlate: bool,
    timeline: bool,
    source_root: Option<&'a Path>,
}

struct ParsedExportRange {
    since: Option<OffsetDateTime>,
    until: Option<OffsetDateTime>,
}

fn run_export(config: ExportConfig<'_>) -> Result<(), Box<dyn std::error::Error>> {
    validate_export_config(&config)?;
    let range = parse_export_range(&config)?;

    if let Some(source_root) = config.source_root.filter(|_| config.timeline) {
        return run_source_backed_timeline_export(&config, source_root);
    }

    let events = read_jsonl_events(config.log_path)?;
    let filtered = filtered_export_events(&events, &config, &range);

    if config.timeline {
        let timeline_events = build_session_timelines(&filtered);
        return print_single_session_timeline(
            &timeline_events,
            config.session_ids[0].as_str(),
            config.format,
        );
    }

    let correlation_events = config
        .correlate
        .then(|| correlation_events_from_filtered(&filtered));
    let output_events = correlation_events
        .as_ref()
        .map(|events| events.iter().collect::<Vec<_>>())
        .unwrap_or(filtered);
    print_export_events(&output_events, config.format)
}

fn validate_export_config(config: &ExportConfig<'_>) -> Result<(), Box<dyn std::error::Error>> {
    if config.timeline && config.session_ids.is_empty() {
        return Err("--timeline requires --session-id to select a session".into());
    }
    if config.timeline && config.session_ids.len() > 1 {
        return Err("--timeline requires exactly one --session-id".into());
    }
    if config.timeline && config.correlate {
        return Err("--correlate does not support --timeline".into());
    }
    if config.source_root.is_some() && !config.timeline {
        return Err("--source-root requires --timeline".into());
    }
    if !config.timeline && config.format == ExportFormat::TimelineText {
        return Err("--format timeline-text requires --timeline".into());
    }
    if config.timeline && config.format == ExportFormat::Summary {
        return Err("--format summary does not support --timeline".into());
    }
    if config.timeline && config.format == ExportFormat::ElasticBulk {
        return Err("--format elastic-bulk does not support --timeline".into());
    }
    if config.source_root.is_some() {
        if !config.severities.is_empty() {
            return Err("--source-root does not support --severity filters".into());
        }
        if !config.rule_ids.is_empty() {
            return Err("--source-root does not support --rule-id filters".into());
        }
        if config.since.is_some() || config.until.is_some() {
            return Err("--source-root does not support --since/--until filters".into());
        }
    }
    Ok(())
}

fn parse_export_range(
    config: &ExportConfig<'_>,
) -> Result<ParsedExportRange, Box<dyn std::error::Error>> {
    let since = parse_export_filter_timestamp(config.since, "--since")?;
    let until = parse_export_filter_timestamp(config.until, "--until")?;
    if let (Some(since), Some(until)) = (since, until)
        && since > until
    {
        return Err("--since must be less than or equal to --until".into());
    }
    Ok(ParsedExportRange { since, until })
}

fn run_source_backed_timeline_export(
    config: &ExportConfig<'_>,
    source_root: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let client_filters = string_set(config.clients);
    let session_filters = string_set(config.session_ids);
    let timeline_events =
        build_source_backed_session_timelines(source_root, &session_filters, &client_filters);
    print_single_session_timeline(
        &timeline_events,
        config.session_ids[0].as_str(),
        config.format,
    )
}

fn filtered_export_events<'a>(
    events: &'a [serde_json::Value],
    config: &ExportConfig<'_>,
    range: &ParsedExportRange,
) -> Vec<&'a serde_json::Value> {
    let severity_filters = lowercase_set(config.severities);
    let client_filters = string_set(config.clients);
    let session_filters = string_set(config.session_ids);
    let rule_filters = string_set(config.rule_ids);

    events
        .iter()
        .filter(|event| {
            event_matches_export_filters(
                event,
                &severity_filters,
                &client_filters,
                &session_filters,
                &rule_filters,
                range.since,
                range.until,
            )
        })
        .collect()
}

fn print_single_session_timeline(
    timeline_events: &[serde_json::Value],
    requested_session_id: &str,
    format: ExportFormat,
) -> Result<(), Box<dyn std::error::Error>> {
    ensure_single_timeline_match(timeline_events, requested_session_id)?;
    print_timeline_events(timeline_events, format)
}

fn correlation_events_from_filtered(filtered: &[&serde_json::Value]) -> Vec<serde_json::Value> {
    let detection_events = filtered
        .iter()
        .filter_map(|event| event_from_json_value(event))
        .collect::<Vec<_>>();

    correlation_events_from_detections(&detection_events, &CorrelationConfig::default())
        .into_iter()
        .map(|event| serde_json::to_value(event).expect("event serializes"))
        .collect()
}

fn print_export_events(
    events: &[&serde_json::Value],
    format: ExportFormat,
) -> Result<(), Box<dyn std::error::Error>> {
    match format {
        ExportFormat::Jsonl => {
            for event in events {
                println!("{}", serde_json::to_string(event)?);
            }
            Ok(())
        }
        ExportFormat::Summary => {
            print_export_summary(events);
            Ok(())
        }
        ExportFormat::ElasticBulk => print_elastic_bulk(events),
        ExportFormat::TimelineText => Err("--format timeline-text requires --timeline".into()),
    }
}

fn print_timeline_events(
    timeline_events: &[serde_json::Value],
    format: ExportFormat,
) -> Result<(), Box<dyn std::error::Error>> {
    match format {
        ExportFormat::TimelineText => {
            for (index, event) in timeline_events.iter().enumerate() {
                if index > 0 {
                    println!();
                }
                print!("{}", format_timeline_text(event));
            }
        }
        ExportFormat::Jsonl | ExportFormat::Summary | ExportFormat::ElasticBulk => {
            for event in timeline_events {
                println!("{}", serde_json::to_string(event)?);
            }
        }
    }

    Ok(())
}

fn ensure_single_timeline_match(
    timeline_events: &[serde_json::Value],
    requested_session_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    match timeline_events.len() {
        0 => Err(format!("no timeline found for session_id '{requested_session_id}'").into()),
        1 => Ok(()),
        count => Err(format!(
            "--timeline resolved {count} sessions for session_id '{requested_session_id}'; add --client to disambiguate"
        )
        .into()),
    }
}

fn print_elastic_bulk(events: &[&serde_json::Value]) -> Result<(), Box<dyn std::error::Error>> {
    for event in events {
        let mut metadata = serde_json::Map::new();
        metadata.insert(
            "_index".to_string(),
            serde_json::Value::String("adr-events".to_string()),
        );
        if let Some(event_id) = event.get("event_id").and_then(|value| value.as_str()) {
            metadata.insert(
                "_id".to_string(),
                serde_json::Value::String(event_id.to_string()),
            );
        }
        println!(
            "{}",
            serde_json::to_string(&serde_json::json!({ "index": metadata }))?
        );
        println!("{}", serde_json::to_string(event)?);
    }
    Ok(())
}

fn format_timeline_text(timeline: &serde_json::Value) -> String {
    let session_id = json_str(timeline, "session_id").unwrap_or("unknown");
    let client = json_str(timeline, "client").unwrap_or("unknown");
    let agent = json_str(timeline, "agent").unwrap_or("unknown");
    let model = json_str(timeline, "model").unwrap_or("unknown");
    let provider = json_str(timeline, "provider").unwrap_or("unknown");
    let entry_count = timeline
        .get("entry_count")
        .and_then(|value| value.as_u64())
        .unwrap_or(0);
    let detection_count = timeline
        .get("detection_count")
        .and_then(|value| value.as_u64())
        .unwrap_or(0);
    let max_severity = json_str(timeline, "max_severity").unwrap_or("informational");
    let has_triage = timeline
        .get("has_triage")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);

    let mut output = String::new();
    output.push_str(&format!("Timeline {session_id} ({client})\n"));
    output.push_str(&format!(
        "Agent: {agent} | Model: {model} | Provider: {provider}\n"
    ));
    output.push_str(&format!(
        "Entries: {entry_count} | Detections: {detection_count} | Max severity: {max_severity} | Triage: {}\n",
        if has_triage { "yes" } else { "no" }
    ));

    if let Some(risk_summary) = timeline.get("risk_summary") {
        output.push_str(&format_risk_summary_text(risk_summary));
    }

    if let Some(entries) = timeline.get("entries").and_then(|value| value.as_array()) {
        for entry in entries {
            output.push_str(&format_timeline_entry_text(entry));
        }
    }

    output
}

fn format_risk_summary_text(summary: &serde_json::Value) -> String {
    let tool_calls = summary
        .get("tool_call_count")
        .and_then(|value| value.as_u64())
        .map(|value| value.to_string())
        .unwrap_or_else(|| "unavailable".to_string());
    let risky_actions = summary
        .get("risky_action_count")
        .and_then(|value| value.as_u64())
        .map(|value| value.to_string())
        .unwrap_or_else(|| "0".to_string());
    let max_severity = json_str(summary, "max_severity").unwrap_or("informational");
    let triage_ran = summary
        .get("triage_ran")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    let top_rules = json_string_array(summary, "top_rule_ids").join(", ");
    let top_categories = json_string_array(summary, "top_categories").join(", ");
    let top_rules = if top_rules.is_empty() {
        "none".to_string()
    } else {
        top_rules
    };
    let top_categories = if top_categories.is_empty() {
        "none".to_string()
    } else {
        top_categories
    };

    format!(
        "Risk: tool_calls={tool_calls} risky_actions={risky_actions} max_severity={max_severity} triage_ran={} top_rules={top_rules} top_categories={top_categories}\n",
        if triage_ran { "yes" } else { "no" }
    )
}

fn format_timeline_entry_text(entry: &serde_json::Value) -> String {
    let index = entry
        .get("index")
        .and_then(|value| value.as_u64())
        .unwrap_or(0);
    let timestamp = json_str(entry, "timestamp").unwrap_or("unknown");
    let event_type = json_str(entry, "event_type").unwrap_or("unknown");
    let severity = json_str(entry, "severity").unwrap_or("informational");
    let mut line = format!("[{index}] {timestamp} {severity} {event_type}");
    if let Some(tool_name) = json_str(entry, "tool_name") {
        line.push_str(&format!(" tool={tool_name}"));
    }
    if let Some(call_id) = json_str(entry, "call_id") {
        line.push_str(&format!(" call_id={call_id}"));
    }
    if let Some(linked_index) = entry
        .get("linked_entry_index")
        .and_then(|value| value.as_u64())
    {
        line.push_str(&format!(" linked_entry={linked_index}"));
    }
    line.push('\n');

    let mut output = line;
    let rule_ids = json_string_array(entry, "rule_ids");
    if !rule_ids.is_empty() {
        output.push_str(&format!("  Rules: {}\n", rule_ids.join(", ")));
    }
    let categories = json_string_array(entry, "categories");
    if !categories.is_empty() {
        output.push_str(&format!("  Categories: {}\n", categories.join(", ")));
    }
    if let Some(evidence) = entry.get("evidence").and_then(|value| value.as_array()) {
        for item in evidence {
            let field = json_str(item, "field").unwrap_or("unknown");
            let hash = json_str(item, "hash").unwrap_or("unavailable");
            if let Some(redacted_value) = json_str(item, "redacted_value") {
                output.push_str(&format!(
                    "  Evidence: {field} hash={hash} value={redacted_value}\n"
                ));
            } else {
                output.push_str(&format!("  Evidence: {field} hash={hash}\n"));
            }
        }
    }
    if let Some(triage) = entry.get("triage") {
        let verdict = json_str(triage, "verdict").unwrap_or("unknown");
        let confidence = triage
            .get("confidence")
            .and_then(|value| value.as_f64())
            .map(|value| value.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        let reason = json_str(triage, "reason").unwrap_or("unavailable");
        output.push_str(&format!(
            "  Triage: {verdict} confidence={confidence} reason={reason}\n"
        ));
    }
    if let Some(response) = entry.get("response") {
        if let Some(action) = json_str(response, "recommended_action") {
            output.push_str(&format!("  Recommended action: {action}\n"));
        }
        if let Some(playbook) = json_str(response, "response_playbook") {
            output.push_str(&format!("  Playbook: {playbook}\n"));
        }
        if let Some(summary) = json_str(response, "investigation_summary") {
            output.push_str(&format!("  Summary: {summary}\n"));
        }
    }

    output
}

fn json_str<'a>(value: &'a serde_json::Value, field: &str) -> Option<&'a str> {
    value.get(field).and_then(|value| value.as_str())
}

fn json_string_array(value: &serde_json::Value, field: &str) -> Vec<String> {
    value
        .get(field)
        .and_then(|value| value.as_array())
        .map(|values| {
            values
                .iter()
                .filter_map(|value| value.as_str())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// Build redacted session timelines from filtered JSONL events.
///
/// Groups events by `(session_id, client)`, sorts by timestamp, and produces
/// one timeline JSON object per session identity containing ordered entries
/// with detection anchors and triage context.
fn build_session_timelines(events: &[&serde_json::Value]) -> Vec<serde_json::Value> {
    use std::collections::BTreeMap;

    // Group events by `(session_id, client)` so client-local session ids do not collide.
    let mut by_session: BTreeMap<(String, String), Vec<&serde_json::Value>> = BTreeMap::new();
    for event in events {
        let session_id = event
            .get("session_id")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();
        let client = event
            .get("client")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();
        by_session
            .entry((session_id, client))
            .or_default()
            .push(event);
    }

    let mut timelines = Vec::new();

    for ((session_id, client), mut session_events) in by_session {
        // Sort by timestamp.
        session_events.sort_by(|a, b| {
            let ts_a = a.get("timestamp").and_then(|v| v.as_str()).unwrap_or("");
            let ts_b = b.get("timestamp").and_then(|v| v.as_str()).unwrap_or("");
            ts_a.cmp(ts_b)
        });

        // Extract session metadata from the first event.
        let first = session_events.first();
        let agent = first.and_then(|e| e.get("agent").and_then(|v| v.as_str()));
        let model = first.and_then(|e| e.get("model").and_then(|v| v.as_str()));
        let provider = first.and_then(|e| e.get("provider").and_then(|v| v.as_str()));

        // Build timeline entries.
        let entries: Vec<serde_json::Value> = session_events
            .iter()
            .enumerate()
            .map(|(index, event)| {
                let event_type = event
                    .get("event_type")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                let severity = event
                    .get("severity")
                    .and_then(|v| v.as_str())
                    .unwrap_or("informational");
                let timestamp = event
                    .get("timestamp")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let tool_name = event.get("tool_name").and_then(|v| v.as_str());
                let rule_ids = event
                    .get("rule_ids")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str())
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                let categories = event
                    .get("categories")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str())
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();

                // Redacted evidence summary: field names and hashes only.
                let evidence_summary: Vec<serde_json::Value> = event
                    .get("evidence")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|item| {
                                let field = item.get("field")?.as_str()?;
                                let hash = item.get("hash").and_then(|v| v.as_str());
                                Some(serde_json::json!({
                                    "field": field,
                                    "hash": hash,
                                }))
                            })
                            .collect()
                    })
                    .unwrap_or_default();

                // Triage summary (redacted).
                let triage = event.get("triage").map(|t| {
                    serde_json::json!({
                        "verdict": t.get("verdict").and_then(|v| v.as_str()),
                        "confidence": t.get("confidence").and_then(|v| v.as_f64()),
                        "reason": t.get("reason").and_then(|v| v.as_str()),
                    })
                });

                // Response summary.
                let response = event.get("response").map(|r| {
                    serde_json::json!({
                        "recommended_action": r.get("recommended_action").and_then(|v| v.as_str()),
                        "response_playbook": r.get("response_playbook").and_then(|v| v.as_str()),
                        "investigation_summary": r.get("investigation_summary").and_then(|v| v.as_str()),
                    })
                });

                let mut entry = serde_json::json!({
                    "index": index,
                    "timestamp": timestamp,
                    "event_type": event_type,
                    "severity": severity,
                });

                if let Some(tool) = tool_name {
                    entry["tool_name"] = serde_json::Value::String(tool.to_string());
                }
                if !rule_ids.is_empty() {
                    entry["rule_ids"] = serde_json::json!(rule_ids);
                }
                if !categories.is_empty() {
                    entry["categories"] = serde_json::json!(categories);
                }
                if !evidence_summary.is_empty() {
                    entry["evidence"] = serde_json::json!(evidence_summary);
                }
                if let Some(t) = triage {
                    entry["triage"] = t;
                }
                if let Some(r) = response {
                    entry["response"] = r;
                }

                entry
            })
            .collect();

        // Compute session summary.
        let detection_count = session_events
            .iter()
            .filter(|e| {
                e.get("event_type")
                    .and_then(|v| v.as_str())
                    .is_some_and(|t| t == "detection")
            })
            .count();
        let max_severity = session_events
            .iter()
            .filter_map(|e| e.get("severity").and_then(|v| v.as_str()))
            .max_by_key(|s| severity_rank(s))
            .unwrap_or("informational");
        let has_triage = session_events.iter().any(|e| e.get("triage").is_some());
        let risk_summary = build_session_risk_summary(&session_events);

        let timeline = serde_json::json!({
            "event_type": "timeline",
            "session_id": session_id,
            "client": client,
            "agent": agent,
            "model": model,
            "provider": provider,
            "entry_count": entries.len(),
            "detection_count": detection_count,
            "max_severity": max_severity,
            "has_triage": has_triage,
            "risk_summary": risk_summary,
            "entries": entries,
        });

        timelines.push(timeline);
    }

    timelines
}

fn build_source_backed_session_timelines(
    source_root: &Path,
    session_filters: &BTreeSet<String>,
    client_filters: &BTreeSet<String>,
) -> Vec<serde_json::Value> {
    type SessionKey = (String, String);
    type CanonicalSessionRecord = (String, usize, NormalizedRecordV1);
    type LegacySessionRecord = (String, usize, crate::parser::NormalizedRecord);

    let rule_set = load_default_rule_set().expect("rule set");
    let mut by_session: BTreeMap<SessionKey, Vec<CanonicalSessionRecord>> = BTreeMap::new();
    let mut legacy_by_session: BTreeMap<SessionKey, Vec<LegacySessionRecord>> = BTreeMap::new();
    let mut sources = discover_sources(source_root);
    if !client_filters.is_empty() {
        sources.retain(|source| client_filters.contains(source.client.as_str()));
    }

    for source in &sources {
        let Ok(records) = parse_source_records(source) else {
            continue;
        };
        let client = source.client.as_str().to_string();
        let source_path = source.path.to_string_lossy();
        let source_path_hash = evidence_hash(&source_path);
        for (index, record) in records.into_iter().enumerate() {
            if !session_filters.contains(&record.session_id) {
                continue;
            }
            let session_id = record.session_id.clone();
            let timestamp = record.timestamp.clone().unwrap_or_default();
            legacy_by_session
                .entry((session_id.clone(), client.clone()))
                .or_default()
                .push((timestamp.clone(), index, record.clone()));
            let canonical = NormalizedRecordV1::from_legacy(
                record,
                Provenance {
                    source_path_hash: source_path_hash.clone(),
                    source_event_id: None,
                    offset: Some(index.to_string()),
                },
            );
            by_session
                .entry((session_id, client.clone()))
                .or_default()
                .push((timestamp, index, canonical));
        }
    }

    by_session
        .into_iter()
        .filter_map(|(session_key, mut records)| {
            records.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));
            let mut legacy_records = legacy_by_session.remove(&session_key).unwrap_or_default();
            legacy_records
                .sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));
            let canonical_records = records
                .into_iter()
                .map(|(_, _, record)| record)
                .collect::<Vec<_>>();
            let parsed_records = legacy_records
                .into_iter()
                .map(|(_, _, record)| record)
                .collect::<Vec<_>>();
            build_source_backed_timeline_value(&canonical_records, &parsed_records, &rule_set)
        })
        .collect()
}

fn build_source_backed_timeline_value(
    canonical_records: &[NormalizedRecordV1],
    parsed_records: &[crate::parser::NormalizedRecord],
    rule_set: &CompiledRuleSet,
) -> Option<serde_json::Value> {
    let mut timeline =
        serde_json::to_value(build_exported_session_timeline(canonical_records)?).ok()?;
    let summary = build_source_backed_risk_summary(parsed_records, rule_set);
    let max_severity = summary
        .get("max_severity")
        .and_then(|value| value.as_str())
        .unwrap_or("informational");
    let has_triage = summary
        .get("triage_ran")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    let detection_count = summary
        .get("risky_action_count")
        .and_then(|value| value.as_u64())
        .unwrap_or(0);

    timeline["detection_count"] = serde_json::Value::from(detection_count);
    timeline["max_severity"] = serde_json::Value::String(max_severity.to_string());
    timeline["has_triage"] = serde_json::Value::Bool(has_triage);
    timeline["risk_summary"] = summary;
    Some(timeline)
}

fn build_source_backed_risk_summary(
    parsed_records: &[crate::parser::NormalizedRecord],
    rule_set: &CompiledRuleSet,
) -> serde_json::Value {
    let tool_call_count = parsed_records
        .iter()
        .filter(|record| matches!(record.kind, crate::parser::RecordKind::ToolCall))
        .count() as u64;
    let matches = evaluate_session_matches(rule_set, parsed_records);
    let risk_score = matches.as_ref().map(|matches| matches.score).unwrap_or(0);
    let max_severity = if risk_score == 0 {
        "informational"
    } else {
        crate::scoring::assess_risk_with_thresholds(risk_score, crate::scoring::load_thresholds())
            .severity
            .as_str()
    };
    let risky_action_count = u64::from(matches.is_some());

    serde_json::json!({
        "tool_call_count": tool_call_count,
        "risky_action_count": risky_action_count,
        "top_rule_ids": matches
            .as_ref()
            .map(|matches| serde_json::json!(matches.rule_ids))
            .unwrap_or(serde_json::Value::Null),
        "top_categories": matches
            .as_ref()
            .map(|matches| serde_json::json!(matches.categories))
            .unwrap_or(serde_json::Value::Null),
        "max_severity": max_severity,
        "triage_ran": false,
    })
}

fn build_session_risk_summary(session_events: &[&serde_json::Value]) -> serde_json::Value {
    let mut tool_call_count = None;
    let mut detection_count = 0_usize;
    let mut max_severity = "informational";
    let mut triage_ran = false;
    let mut rule_counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut category_counts: BTreeMap<String, usize> = BTreeMap::new();

    for event in session_events {
        if let Some(severity) = event.get("severity").and_then(|value| value.as_str())
            && severity_rank(severity) > severity_rank(max_severity)
        {
            max_severity = severity;
        }

        match event.get("event_type").and_then(|value| value.as_str()) {
            Some("activity") if tool_call_count.is_none() => {
                tool_call_count = extract_tool_call_count(event);
            }
            Some("detection") => {
                detection_count += 1;
                triage_ran |= triage_ran_from_event(event);

                if let Some(values) = event.get("rule_ids").and_then(|value| value.as_array()) {
                    for value in values.iter().filter_map(|value| value.as_str()) {
                        *rule_counts.entry(value.to_string()).or_insert(0) += 1;
                    }
                }
                if let Some(values) = event.get("categories").and_then(|value| value.as_array()) {
                    for value in values.iter().filter_map(|value| value.as_str()) {
                        *category_counts.entry(value.to_string()).or_insert(0) += 1;
                    }
                }
            }
            _ => {}
        }
    }

    serde_json::json!({
        "tool_call_count": tool_call_count,
        "risky_action_count": detection_count,
        "top_rule_ids": ranked_summary_values(rule_counts),
        "top_categories": ranked_summary_values(category_counts),
        "max_severity": max_severity,
        "triage_ran": triage_ran,
    })
}

fn ranked_summary_values(counts: BTreeMap<String, usize>) -> serde_json::Value {
    let mut values = counts.into_iter().collect::<Vec<_>>();
    values.sort_by(|(left_value, left_count), (right_value, right_count)| {
        right_count
            .cmp(left_count)
            .then_with(|| left_value.cmp(right_value))
    });
    if values.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::Value::Array(
            values
                .into_iter()
                .take(3)
                .map(|(value, _)| serde_json::Value::String(value))
                .collect(),
        )
    }
}

fn extract_tool_call_count(event: &serde_json::Value) -> Option<u64> {
    let evidence = event.get("evidence")?.as_array()?;
    let record_counts = evidence
        .iter()
        .find(|item| item.get("field").and_then(|value| value.as_str()) == Some("record_counts"))?;
    let counts = record_counts
        .get("redacted_value")
        .and_then(|value| value.as_str())
        .and_then(|value| serde_json::from_str::<serde_json::Value>(value).ok())?;
    counts.get("tool_call").and_then(|value| value.as_u64())
}

fn triage_ran_from_event(event: &serde_json::Value) -> bool {
    event
        .get("triage")
        .and_then(|value| value.get("verdict"))
        .and_then(|value| value.as_str())
        .is_some_and(|verdict| !matches!(verdict, "pending" | "not_required" | "config_missing"))
}

fn severity_rank(severity: &str) -> u8 {
    match severity {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

fn event_from_json_value(event: &serde_json::Value) -> Option<Event> {
    Some(Event {
        timestamp: event.get("timestamp")?.as_str()?.to_string(),
        event_time: optional_string(event, "event_time"),
        observed_at: event
            .get("observed_at")
            .and_then(|value| value.as_str())
            .unwrap_or_else(|| {
                event
                    .get("timestamp")
                    .and_then(|value| value.as_str())
                    .unwrap_or("")
            })
            .to_string(),
        ingested_at: event
            .get("ingested_at")
            .and_then(|value| value.as_str())
            .unwrap_or_else(|| {
                event
                    .get("timestamp")
                    .and_then(|value| value.as_str())
                    .unwrap_or("")
            })
            .to_string(),
        time_source: event
            .get("time_source")
            .and_then(|value| value.as_str())
            .unwrap_or("source")
            .to_string(),
        time_confidence: event
            .get("time_confidence")
            .and_then(|value| value.as_str())
            .unwrap_or("high")
            .to_string(),
        time_override_reason: optional_string(event, "time_override_reason"),
        schema_version: event
            .get("schema_version")
            .and_then(|value| value.as_str())
            .unwrap_or("1.0")
            .to_string(),
        event_id: event.get("event_id")?.as_str()?.to_string(),
        event_type: event.get("event_type")?.as_str()?.to_string(),
        severity: event.get("severity")?.as_str()?.to_string(),
        risk_score: event.get("risk_score")?.as_u64()? as u32,
        client: event.get("client")?.as_str()?.to_string(),
        agent: optional_string(event, "agent"),
        model: optional_string(event, "model"),
        provider: optional_string(event, "provider"),
        session_id: event.get("session_id")?.as_str()?.to_string(),
        workspace: optional_string(event, "workspace"),
        source_path_hash: optional_string(event, "source_path_hash"),
        tool_name: optional_string(event, "tool_name"),
        rule_ids: string_array(event, "rule_ids"),
        categories: string_array(event, "categories"),
        detection_classes: string_array(event, "detection_classes"),
        signal_types: string_array(event, "signal_types"),
        analytic_intents: string_array(event, "analytic_intents"),
        atlas_tags: string_array(event, "atlas_tags"),
        tags: string_array(event, "tags"),
        evidence: Vec::new(),
        triage: event.get("triage").cloned(),
        response: None,
        source_counts: None,
        adr_version: optional_string(event, "adr_version"),
        scan_duration_ms: event
            .get("scan_duration_ms")
            .and_then(|value| value.as_u64()),
        rule_count: event
            .get("rule_count")
            .and_then(|value| value.as_u64())
            .map(|value| value as usize),
        threshold_config: None,
        active_policy_name: optional_string(event, "active_policy_name"),
    })
}

fn optional_string(event: &serde_json::Value, key: &str) -> Option<String> {
    event
        .get(key)
        .and_then(|value| value.as_str())
        .map(str::to_string)
}

fn string_array(event: &serde_json::Value, key: &str) -> Vec<String> {
    event
        .get(key)
        .and_then(|value| value.as_array())
        .map(|values| {
            values
                .iter()
                .filter_map(|value| value.as_str())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn read_jsonl_events(
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

fn lowercase_set(values: &[String]) -> BTreeSet<String> {
    values
        .iter()
        .map(|value| value.to_ascii_lowercase())
        .collect()
}

fn string_set(values: &[String]) -> BTreeSet<String> {
    values.iter().cloned().collect()
}

fn event_matches_export_filters(
    event: &serde_json::Value,
    severity_filters: &BTreeSet<String>,
    client_filters: &BTreeSet<String>,
    session_filters: &BTreeSet<String>,
    rule_filters: &BTreeSet<String>,
    since: Option<OffsetDateTime>,
    until: Option<OffsetDateTime>,
) -> bool {
    if !severity_filters.is_empty()
        && !event
            .get("severity")
            .and_then(|value| value.as_str())
            .map(|value| severity_filters.contains(&value.to_ascii_lowercase()))
            .unwrap_or(false)
    {
        return false;
    }
    if !client_filters.is_empty()
        && !event
            .get("client")
            .and_then(|value| value.as_str())
            .map(|value| client_filters.contains(value))
            .unwrap_or(false)
    {
        return false;
    }
    if !session_filters.is_empty()
        && !event
            .get("session_id")
            .and_then(|value| value.as_str())
            .map(|value| session_filters.contains(value))
            .unwrap_or(false)
    {
        return false;
    }
    if !rule_filters.is_empty()
        && !event
            .get("rule_ids")
            .and_then(|value| value.as_array())
            .map(|rule_ids| {
                rule_ids
                    .iter()
                    .filter_map(|value| value.as_str())
                    .any(|rule_id| rule_filters.contains(rule_id))
            })
            .unwrap_or(false)
    {
        return false;
    }
    if since.is_some() || until.is_some() {
        let Some(event_timestamp) = event
            .get("timestamp")
            .and_then(|value| value.as_str())
            .and_then(parse_event_timestamp)
        else {
            return false;
        };

        if since.is_some_and(|since| event_timestamp < since) {
            return false;
        }
        if until.is_some_and(|until| event_timestamp > until) {
            return false;
        }
    }
    true
}

fn parse_export_filter_timestamp(
    value: Option<&str>,
    flag: &str,
) -> Result<Option<OffsetDateTime>, Box<dyn std::error::Error>> {
    let Some(value) = value else {
        return Ok(None);
    };

    parse_event_timestamp(value)
        .ok_or_else(|| format!("{flag} requires a valid RFC3339 timestamp").into())
        .map(Some)
}

fn print_export_summary(events: &[&serde_json::Value]) {
    let mut event_types = BTreeMap::new();
    let mut severities = BTreeMap::new();
    let mut clients = BTreeMap::new();
    let mut rule_ids = BTreeMap::new();

    for event in events {
        increment_field(event, "event_type", &mut event_types);
        increment_field(event, "severity", &mut severities);
        increment_field(event, "client", &mut clients);
        if let Some(values) = event.get("rule_ids").and_then(|value| value.as_array()) {
            for value in values.iter().filter_map(|value| value.as_str()) {
                *rule_ids.entry(value.to_string()).or_insert(0_usize) += 1;
            }
        }
    }

    println!("events: {}", events.len());
    print_count_section("event_types", &event_types);
    print_count_section("severities", &severities);
    print_count_section("clients", &clients);
    print_count_section("rule_ids", &rule_ids);
}

fn increment_field(event: &serde_json::Value, field: &str, counts: &mut BTreeMap<String, usize>) {
    if let Some(value) = event.get(field).and_then(|value| value.as_str()) {
        *counts.entry(value.to_string()).or_insert(0) += 1;
    }
}

fn print_count_section(label: &str, counts: &BTreeMap<String, usize>) {
    println!("{label}:");
    if counts.is_empty() {
        println!("  none: 0");
        return;
    }
    for (value, count) in counts {
        println!("  {value}: {count}");
    }
}
