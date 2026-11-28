//! Scan execution: selects new or changed sources from scanner state, runs each
//! through the shared canonical source runtime, applies allowlists, health and
//! summaries, writes events to the sinks, and then installs the new state.
//!
//! State is installed only after required durable output succeeds. Source
//! processing semantics belong in `telltale-core::canonical_runtime`, not here.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use time::OffsetDateTime;

use crate::allowlist::{load_allowlist, suppress_detection};
use crate::baseline::BaselineDeviationConfig;
use crate::cli::historical::{JsonlEventRecord, visit_jsonl_records};
use crate::discovery::is_fixture_root;
use crate::event::{
    Event, Evidence, HealthEventInput, OperationalAlertConfig, OperationalAlertInput,
    PrivacySanitizer, SanitizationContext, SessionRiskSummaryEventInput, evidence_hash,
    health_event_with_metadata, opaque_identifier, operational_alert_event,
    sanitize_serialized_event, session_risk_summary_event, terminal_identifier,
};
use crate::file_lock::validate_runtime_paths;
use crate::install_inventory::{
    collect_install_inventory, install_inventory_due, snapshot_to_event,
};
use crate::process_chain::ProcessChainConfig;
use crate::rules::{
    CompiledRuleSet, RuleLoadMode, RulePackPaths,
    resolve_rule_set_from_pack_paths_with_mode_override_paths_and_replacements,
};
use crate::scoring::load_thresholds;
use crate::scoring::{RiskAccountingError, RiskContribution, canonicalize_contributions};
use crate::sink::{DeliveryErrorClass, SinkFailure, SinkSet};
use crate::state::{ScanState, SqliteIngestionCursor, StateLock, source_fingerprint};
use telltale_core::inventory::discover_mcp_scan_with_workspaces;
use telltale_detect::v2::PolicyMatchAccounting;
use telltale_detect::v2::activity::BaselineReplacement;
use telltale_schema::clients::{ClientId, SourceKind};
use telltale_schema::observation::ObservedAt;
use telltale_schema::source::Source;
use telltale_sources::acquisition::OpenCodeSqliteReadOptions;

const OPENCODE_SQLITE_PART_TABLE: &str = "part";
/// OpenCode v2 progress uses its own cursor key, so a legacy part watermark
/// never resumes, regress-checks or skips `session_message` history.
const OPENCODE_SQLITE_SESSION_MESSAGE_TABLE: &str = "session_message";

#[cfg(test)]
mod activation_tests;
mod canonical;
mod diagnostics;
mod discovery;
mod processing;
pub(super) mod watch;

pub(crate) use diagnostics::{ScanCommand, ScanDiagnosticsOptions};
use diagnostics::{ScanCounts, ScanPhase, ScanRecorder};

use processing::{
    SourceProcessingStatus, should_stage_sqlite_ingestion_cursors, sqlite_progress_candidate,
};

use discovery::{
    SourceDiscoveryAccounting, discover_operational_sources, load_project_configuration,
};

/// Options that resolve identically for `scan` and `watch`.
///
/// Both commands run the same scan through `run_scan`, so rules, policies,
/// allowlists, outputs, paths, client filters, project roots, and inventory
/// cadence resolve here once rather than being copied between two structs.
#[derive(Clone, Copy)]
pub(crate) struct ScanExecutionConfig<'a> {
    pub(crate) root: &'a Path,
    pub(crate) log_path: &'a Path,
    pub(crate) sinks: &'a SinkSet,
    pub(crate) state_path: &'a Path,
    pub(crate) dry_run: bool,
    pub(crate) emit_activity: bool,
    pub(crate) emit_session_risk_summary: bool,
    pub(crate) allow_fixtures: bool,
    pub(crate) rule_pack_paths: &'a RulePackPaths,
    pub(crate) rule_paths: &'a [PathBuf],
    pub(crate) override_paths: &'a [PathBuf],
    pub(crate) rule_load_mode: RuleLoadMode,
    pub(crate) policy_path: Option<&'a Path>,
    pub(crate) allowlist_path: Option<&'a Path>,
    pub(crate) baseline_deviation_scoring: bool,
    pub(crate) clients: &'a [ClientId],
    pub(crate) project_config_paths: &'a [PathBuf],
    pub(crate) install_inventory_interval_seconds: Option<u64>,
    /// Opt-in liveness heartbeat; `None` is off.
    pub(crate) health_heartbeat_interval_seconds: Option<u64>,
    pub(crate) process_chain: bool,
    pub(crate) operational_alerts: OperationalAlertConfig,
    pub(crate) runtime: &'a serde_json::Value,
    pub(crate) effective_configuration: &'a serde_json::Value,
}

/// A shared scan plus the options only `scan` accepts.
#[derive(Clone, Copy)]
pub(crate) struct ScanConfig<'a> {
    pub(crate) execution: ScanExecutionConfig<'a>,
    pub(crate) backfill: bool,
    /// Forensic history pass: every OpenCode v2 message from the earliest,
    /// deduplicated within this run only. Scan state is never read or written.
    pub(crate) history: bool,
    pub(crate) rebuild_baselines: bool,
    pub(crate) max_sources: Option<usize>,
    /// Opt-in diagnostics records; `None` when every category is off.
    pub(crate) diagnostics: Option<ScanDiagnosticsOptions<'a>>,
}

pub(crate) fn run_scan_loop(
    config: ScanConfig<'_>,
    iterations: Option<u32>,
    interval: Duration,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut remaining = iterations;
    let mut first_scan = true;
    loop {
        run_recorded_scan(config, first_scan)?;
        first_scan = false;
        if iteration_budget_exhausted(&mut remaining) {
            break;
        }
        thread::sleep(interval);
    }
    Ok(())
}

/// Counts one completed scan against an optional `--iterations` budget and
/// reports whether the budget is now spent. The CLI rejects zero, and a zero
/// budget still counts as spent here, so the counter can never wrap.
pub(super) fn iteration_budget_exhausted(remaining: &mut Option<u32>) -> bool {
    match remaining {
        None => false,
        Some(value) if *value <= 1 => true,
        Some(value) => {
            *value -= 1;
            false
        }
    }
}

/// Which sources a scan should parse and detect against.
enum ScanTargets {
    /// Discover and scan every source under the configured root.
    Full,
    /// Scan only the given pre-discovered sources (watch-mode targeted scan).
    Targeted {
        sources: Vec<Source>,
        discovery: SourceDiscoveryAccounting,
    },
}

/// When to persist scanner state after a scan.
#[derive(Clone, Copy, Eq, PartialEq)]
enum StateSavePolicy {
    /// Save on every scan (batch mode behavior).
    Always,
    /// Save only when the scan emitted events or advanced durable state
    /// (fingerprints, SQLite cursors, source inventory). Watch mode uses this
    /// to avoid rewriting the state file on every no-op scan.
    OnChange,
}

fn ensure_durable_scan_platform(
    sinks: &SinkSet,
    is_windows: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if sinks.has_persistent_replay() {
        crate::sink::outbox::ensure_durable_storage_supported_for_platform(is_windows)?;
    }
    Ok(())
}

fn validate_scan_execution_paths(
    execution: ScanExecutionConfig<'_>,
    is_windows: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    ensure_durable_scan_platform(execution.sinks, is_windows)?;
    validate_runtime_paths(
        execution.state_path,
        &execution.sinks.local_persistence_paths(),
        &execution.sinks.local_rotation_namespaces(),
    )?;
    if !execution.dry_run && !execution.allow_fixtures && is_fixture_root(execution.root) {
        return Err(
            "refusing to write fixture/demo data to log path; use --dry-run or --allow-fixtures"
                .into(),
        );
    }
    Ok(())
}

pub(super) fn validate_scan_execution(
    execution: ScanExecutionConfig<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    validate_scan_execution_paths(
        execution,
        crate::sink::outbox::current_platform_is_windows(),
    )?;
    let resolution = resolve_rule_set_from_pack_paths_with_mode_override_paths_and_replacements(
        execution.rule_pack_paths,
        execution.rule_paths,
        execution.policy_path,
        execution.rule_load_mode,
        execution.override_paths,
        &[],
    )?;
    cached_rule_plan(&resolution.rule_set.compatibility_export())?;
    load_allowlist(execution.allowlist_path)?;
    Ok(())
}

/// Compiles a resolved rule set, reusing the plan of an identical one.
///
/// Watch mode resolves the rules on every cycle so that an edited rule file
/// takes effect on the next scan, and most cycles resolve the same rules. The
/// key is the whole compile input, so a hit is always the plan a fresh compile
/// would build. Two entries cover the active rules and their pre-policy peer.
fn cached_rule_plan(
    export: &telltale_rules::RuleV1CompatibilityExport,
) -> Result<
    std::sync::Arc<telltale_detect::v2::RuleV1CompatibilityPlan>,
    telltale_detect::v2::RuleCompileError,
> {
    type Entry = (
        String,
        std::sync::Arc<telltale_detect::v2::RuleV1CompatibilityPlan>,
    );
    static PLANS: std::sync::Mutex<Vec<Entry>> = std::sync::Mutex::new(Vec::new());
    let key = format!("{export:?}");
    let mut plans = PLANS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some((_, plan)) = plans.iter().find(|(cached, _)| *cached == key) {
        return Ok(plan.clone());
    }
    let plan = std::sync::Arc::new(telltale_detect::v2::compile_rule_v1(export)?);
    if plans.len() == 2 {
        plans.remove(0);
    }
    plans.push((key, plan.clone()));
    Ok(plan)
}

/// Runs one full scan and returns the codes of its `observed_failure`
/// diagnostic warnings, which `--fail-on-source-errors` turns into an exit
/// status after output and state are written.
pub(crate) fn run_scan_once(
    config: ScanConfig<'_>,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    run_recorded_scan(config, true)
}

/// One full `scan`, followed by its diagnostics record when a category is
/// enabled, whether or not the scan succeeded. The record never changes the
/// result.
fn run_recorded_scan(
    config: ScanConfig<'_>,
    first_scan: bool,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let mut recorder = ScanRecorder::new(config.diagnostics, first_scan);
    let result = run_scan_for_platform(
        config,
        ScanTargets::Full,
        StateSavePolicy::Always,
        crate::sink::outbox::current_platform_is_windows(),
        &mut recorder,
    );
    recorder.finish(&config, result.is_ok());
    result.map(|result| result.source_failures)
}

/// A completed scan saw source failures and the operator asked to fail on them.
#[derive(Debug)]
pub(crate) struct SourceFailures(pub(crate) Vec<String>);

impl std::fmt::Display for SourceFailures {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "scan completed with source failures: {}",
            self.0.join(", ")
        )
    }
}

impl std::error::Error for SourceFailures {}

fn run_scan(
    config: ScanConfig<'_>,
    targets: ScanTargets,
    save_policy: StateSavePolicy,
) -> Result<ScanRunResult, Box<dyn std::error::Error>> {
    run_scan_for_platform(
        config,
        targets,
        save_policy,
        crate::sink::outbox::current_platform_is_windows(),
        &mut ScanRecorder::disabled(),
    )
}

fn run_scan_for_platform(
    config: ScanConfig<'_>,
    targets: ScanTargets,
    save_policy: StateSavePolicy,
    is_windows: bool,
    recorder: &mut ScanRecorder<'_>,
) -> Result<ScanRunResult, Box<dyn std::error::Error>> {
    validate_scan_execution_paths(config.execution, is_windows)?;
    let scan_started = Instant::now();
    recorder.start(scan_started);
    let (mut sources, targeted, source_discovery, workspace_roots) = match targets {
        ScanTargets::Targeted { sources, discovery } => (sources, true, discovery, Vec::new()),
        ScanTargets::Full => {
            let (project_configs, project_configuration) = load_project_configuration(
                config.execution.root,
                config.execution.project_config_paths,
            );
            let (sources, discovery) = discover_operational_sources(
                config.execution.root,
                config.execution.clients,
                config.max_sources,
                &project_configs,
                &project_configuration,
            );
            let workspace_roots = project_configs
                .into_iter()
                .map(|project| project.path)
                .collect::<Vec<_>>();
            (sources, false, discovery, workspace_roots)
        }
    };
    if targeted && let Some(max_sources) = config.max_sources {
        sources.truncate(max_sources);
    }
    let full_scan_discovery = if targeted {
        None
    } else {
        Some((sources.clone(), source_discovery.clone()))
    };
    recorder.enter(ScanPhase::Preparation);
    // A history pass never touches scan state, so it needs no lock and can
    // run beside a routine scanner.
    let state_lock = if config.execution.dry_run || config.history {
        None
    } else {
        Some(StateLock::acquire(config.execution.state_path)?)
    };
    let resolution = resolve_rule_set_from_pack_paths_with_mode_override_paths_and_replacements(
        config.execution.rule_pack_paths,
        config.execution.rule_paths,
        config.execution.policy_path,
        config.execution.rule_load_mode,
        config.execution.override_paths,
        &[],
    )?;
    let diagnostics = super::rule_diagnostics_value(&resolution.diagnostics);
    let policy_active = config.execution.policy_path.is_some();
    let rule_set = resolution.rule_set;
    let content = resolution.content;
    let mut effective_configuration = config.execution.effective_configuration.clone();
    effective_configuration["rules"] = {
        let mut rules = effective_configuration["rules"].clone();
        rules["sources"] = diagnostics["sources"].clone();
        rules["provenance"] = diagnostics["provenance"].clone();
        rules["packages"] = diagnostics["packages"].clone();
        rules
    };
    let rule_count = rule_set.rule_count();
    let active_policy_name = rule_set.policy_name().map(str::to_string);
    let allowlist = load_allowlist(config.execution.allowlist_path)?;
    let mut state = if config.history {
        ScanState::default()
    } else {
        ScanState::load_snapshot(config.execution.state_path)?
    };
    let state_probe = match save_policy {
        StateSavePolicy::Always => None,
        StateSavePolicy::OnChange => Some(StateChangeProbe::capture(&state)),
    };
    let install_inventory_interval_seconds = config.execution.install_inventory_interval_seconds;
    let observed_at_unix_ms = unix_ms_now();
    let mut install_inventory_event = None;
    if config.execution.clients.is_empty()
        && !config.history
        && let Some(interval_seconds) = install_inventory_interval_seconds
        && install_inventory_due(
            state.install_inventory.as_ref(),
            observed_at_unix_ms,
            interval_seconds,
        )
    {
        let snapshot = collect_install_inventory(observed_at_unix_ms);
        install_inventory_event = Some((snapshot_to_event(&snapshot)?, snapshot));
    }
    let rules = cached_rule_plan(&rule_set.compatibility_export())?;
    let pre_policy_rules = policy_active.then(|| {
        let compiled = content.compile(None)?;
        cached_rule_plan(&compiled.compatibility_export())
            .map_err(|error| Box::new(error) as Box<dyn std::error::Error>)
    });
    let observed_at = ObservedAt::new(
        OffsetDateTime::now_utc().format(&time::format_description::well_known::Rfc3339)?,
    )?;
    let process_chain_rules = load_process_chain_rules_if_enabled(config.execution.process_chain);
    let process_config = ProcessChainConfig::default();
    let mcp_scan = if config.execution.emit_activity && !targeted {
        discover_mcp_scan_with_workspaces(config.execution.root, &workspace_roots)
    } else {
        Default::default()
    };
    recorder.enter(ScanPhase::SourceProcessing);
    let processed_sources = sources
        .iter()
        .map(|source| {
            canonical::process_canonical_source(
                source,
                &state,
                canonical::CanonicalProcessingOptions {
                    mcp_servers: &mcp_scan.servers,
                    dry_run: config.execution.dry_run,
                    backfill: config.backfill,
                    history: config.history,
                    baseline_deviation: BaselineDeviationConfig {
                        enabled: config.execution.emit_activity
                            && config.execution.baseline_deviation_scoring,
                        ..BaselineDeviationConfig::default()
                    },
                    pre_policy_rules: pre_policy_rules
                        .as_ref()
                        .and_then(|rules| rules.as_ref().ok())
                        .map(std::sync::Arc::as_ref),
                },
                observed_at.clone(),
                &rules,
                process_chain_rules
                    .as_ref()
                    .map(|rules| (rules, &process_config)),
            )
        })
        .collect::<Vec<_>>();
    recorder.enter(ScanPhase::DetectionAssembly);
    let source_processing = source_processing_accounting(&processed_sources)?;
    // Targeted scans see only changed sources, so only a full scan can say a
    // client lost every source.
    let parse_outcomes = if targeted {
        Vec::new()
    } else {
        client_parse_outcomes(
            sources
                .iter()
                .zip(&processed_sources)
                .map(|(source, result)| (source.client, result.accounting.is_empty())),
        )
    };
    let policy_accounting = compute_policy_match_accounting(
        policy_active,
        pre_policy_rules.as_ref().is_some_and(Result::is_ok),
        &processed_sources,
    );
    let mut activities = Vec::new();
    let mut detections = Vec::new();
    let mut rebuild = config.rebuild_baselines;
    for (source, result) in sources.iter().zip(processed_sources) {
        match result.sqlite_progress_cursor(
            config.execution.dry_run,
            config.backfill,
            state.sqlite_ingestion_cursor_time_updated(
                source,
                OPENCODE_SQLITE_SESSION_MESSAGE_TABLE,
            ),
        ) {
            Some((table, last_time_updated, true)) => state.observe_sqlite_ingestion_drain(
                source,
                table,
                last_time_updated,
                observed_at_unix_ms,
            ),
            Some((table, last_time_updated, false)) => state.observe_sqlite_ingestion_cursor(
                source,
                table,
                last_time_updated,
                observed_at_unix_ms,
            ),
            None => {}
        }
        if let BaselineReplacement::Replace(summaries) = result.baseline_replacement {
            state.record_baseline_source_contribution(
                source,
                source_fingerprint(source),
                summaries,
            )?;
            rebuild = true;
        }
        for event in result.events {
            if event.event_type == "activity" {
                if config.execution.emit_activity {
                    activities.push((source.clone(), event));
                }
            } else {
                detections.push((source.clone(), event));
            }
        }
    }
    if rebuild && !config.execution.dry_run && !config.backfill {
        state.rebuild_baseline_snapshots_from_source_contributions()?;
    }
    // MCP discovery walks host-wide config directories; targeted scans only
    // re-examine changed session sources, so leave it to full scans.
    activities.extend(mcp_scan.events);
    let mut detection_flow = detection_flow_accounting(&detections);
    let mut suppressed_count = 0_usize;
    for (source, detection) in &mut detections {
        let is_detection = detection.event_type == "detection";
        if is_detection
            && let Some(suppression_match) = allowlist.suppression_for(source, detection)
        {
            suppress_detection(detection, &suppression_match);
            suppressed_count += 1;
            detection_flow.allowlist_marked_detection_count += 1;
        }
    }
    let activity_count = activities.len();
    let detection_count = detections.len();
    let session_risk_summaries = session_risk_summaries_for_scan(
        config.execution.emit_session_risk_summary,
        &activities,
        &detections,
    )?;
    let session_risk_summary_count = session_risk_summaries.len();
    let assembled = Instant::now();
    let scan_duration_ms = assembled
        .saturating_duration_since(scan_started)
        .as_millis()
        .min(u128::from(u64::MAX)) as u64;
    recorder.enter_at(ScanPhase::EventSelection, assembled);
    recorder.observe_scan_duration(scan_duration_ms);
    // Targeted scans see only a slice of the source inventory; comparing that
    // slice against prior observations would misreport every unscanned source
    // as removed, so inventory-change tracking is left to full scans. A
    // history scan has no prior state and would report a baseline every run.
    let source_inventory_change = if targeted || config.history {
        None
    } else {
        Some(state.source_inventory_change_summary(&sources))
    };

    let op_config = config.execution.operational_alerts;
    let scanner_error_count = detections
        .iter()
        .filter(|(_, event)| event.event_type == "scanner_error")
        .count() as u64;
    // Durable full scans alert only on the first crossing and stay quiet while
    // the pre-dedup count remains above, including when it rises. History,
    // dry-run, and backfill do not record that suppression; targeted scans
    // neither alert nor touch the latch. Their count is a slice, not the inventory.
    let emit_scanner_error_threshold = scanner_error_threshold_should_alert(
        &mut state,
        scanner_error_count,
        op_config.max_scanner_errors,
        targeted,
        !config.history && !config.execution.dry_run && !config.backfill,
    );
    let operational_alerts = scanner_health_alerts(
        &op_config,
        scanner_error_count,
        scan_duration_ms,
        emit_scanner_error_threshold,
    );
    // A suppressed threshold repeat is omitted, so it does not force health.
    let has_operational_alerts = !operational_alerts.is_empty();

    detection_flow.policy_match_accounting = policy_accounting;

    let inventory_health_change = source_inventory_change
        .as_ref()
        .is_some_and(|change| change.baseline || change.added > 0 || change.removed > 0);
    // Build the non-health emitted events first so the health event can report
    // an accurate emitted_count. The health event itself is excluded from this
    // count to match the scan summary's definition of emitted_count.
    let mut emitted_events = Vec::with_capacity(
        activities.len()
            + detections.len()
            + session_risk_summaries.len()
            + operational_alerts.len()
            + usize::from(install_inventory_event.is_some()),
    );
    for alert in operational_alerts {
        emitted_events.push(alert);
    }
    if let Some((event, snapshot)) = install_inventory_event {
        emitted_events.push(event);
        if !config.execution.dry_run {
            state.install_inventory = Some(snapshot);
        }
    }
    let routine_evidence_rules = routine_evidence_rule_ids(&rule_set);
    let selected = select_source_events(
        &mut state,
        config.backfill,
        activities,
        detections,
        session_risk_summaries,
        &routine_evidence_rules,
    );
    detection_flow.emitted_detection_count += selected.emitted_detection_count;
    detection_flow.state_deduplicated_detection_count += selected.deduplicated_detection_count;
    // An outage alerts when it starts, stays quiet while unchanged, and alerts
    // again if it recurs after a full scan saw one of the client's sources
    // process successfully.
    let mut outage_alerts = Vec::new();
    for &(client, selected_sources, all_failed) in &parse_outcomes {
        if !all_failed {
            state.clear_source_outage(client.as_str());
        } else if state.enter_source_outage(client.as_str()) || config.backfill {
            outage_alerts.push(source_parse_outage_alert(client, selected_sources));
        }
    }
    let outage_alert_emitted = !outage_alerts.is_empty();
    emitted_events.extend(outage_alerts);
    emitted_events.extend(selected.events);

    // The opt-in liveness heartbeat: a full scan emits health when none was
    // emitted for the interval. A history pass has no routine state, and a
    // targeted scan sees only a slice of the inventory.
    let heartbeat_interval_seconds = config
        .execution
        .health_heartbeat_interval_seconds
        .filter(|_| !config.history);
    let last_health_heartbeat =
        heartbeat_interval_seconds.and_then(|_| state.last_health_heartbeat_unix_ms());
    let heartbeat_due = !targeted
        && heartbeat_interval_seconds.is_some_and(|interval| {
            health_heartbeat_wait(last_health_heartbeat, observed_at_unix_ms, interval).is_zero()
        });
    // Dry-run, backfill, inventory change, a newly emitted scanner_error, an
    // outage that fires, a duration alert, this threshold alert when it fires,
    // and a due heartbeat. A suppressed threshold repeat is not among those
    // triggers.
    let health_emitted = config.execution.dry_run
        || config.backfill
        || inventory_health_change
        || selected.scanner_error_emitted
        || outage_alert_emitted
        || has_operational_alerts
        || heartbeat_due;
    let emitted_count = emitted_events.len() as u64;
    let health = health_event_with_metadata(HealthEventInput {
        sources: &sources,
        source_inventory_change: source_inventory_change.as_ref(),
        scan_duration_ms,
        rule_count,
        threshold_config: load_thresholds(),
        active_policy_name: active_policy_name.as_deref(),
        emitted_count,
        suppressed_count: suppressed_count as u64,
        scanner_error_count,
    });
    if health_emitted {
        emitted_events.insert(0, health.clone());
        // While enabled, any health event restarts the interval. The marker is
        // saved with the state after the event's required durable write.
        if heartbeat_interval_seconds.is_some() && !config.execution.dry_run {
            state.record_health_heartbeat(observed_at_unix_ms);
        }
    }

    if targeted {
        state.observe_sources(&sources, observed_at_unix_ms);
    } else {
        state.replace_source_observations(&sources, observed_at_unix_ms);
    }

    let mut sink_failures: Vec<SinkFailure> = Vec::new();
    let mut alert_persistence_error = None;
    let delivery_posture = config.execution.sinks.delivery_posture();
    let should_save = if config.execution.dry_run || config.history {
        false
    } else {
        match &state_probe {
            None => true,
            Some(probe) => !emitted_events.is_empty() || probe.changed(&state),
        }
    };
    let prepared_state = if should_save {
        recorder.enter(ScanPhase::StateSave);
        Some(state.prepare_atomic_save(config.execution.state_path)?)
    } else {
        None
    };
    // Episode suppression is decided after delivery. Dry-run and history do not
    // write or clear the durable latch. The latch save follows the alert so a
    // failed save cannot hide the failure, skip the attempt, or move the
    // JSONL-before-first-state-commit order.
    let persist_episode_latch = !config.execution.dry_run && !config.history;
    if !config.execution.dry_run {
        let verify_lock = || match &state_lock {
            Some(lock) => lock.verify(),
            None if config.history => Ok(()),
            None => Err("state lock missing before durable delivery".into()),
        };
        let persistent_replay = config.execution.sinks.has_persistent_replay();
        recorder.enter(if persistent_replay {
            ScanPhase::DurableAdmission
        } else {
            ScanPhase::CanonicalWrite
        });
        verify_lock()?;
        if persistent_replay {
            sink_failures = config
                .execution
                .sinks
                .persist_for_durable_replay_with_failures(&emitted_events)?;
            if let Some(prepared_state) = prepared_state {
                recorder.enter(ScanPhase::StateSave);
                verify_lock()?;
                prepared_state.install_replace(config.execution.state_path)?;
            }
            recorder.enter(ScanPhase::RemoteDelivery);
            sink_failures.extend(config.execution.sinks.deliver_durable()?);
            sink_failures.extend(
                config
                    .execution
                    .sinks
                    .deliver_best_effort(&emitted_events)?,
            );
        } else {
            // The same order as `SinkSet::deliver`, timed in two parts.
            config
                .execution
                .sinks
                .write_canonical_best_effort(&emitted_events)?;
            recorder.enter(ScanPhase::RemoteDelivery);
            sink_failures = config
                .execution
                .sinks
                .deliver_remote_best_effort(&emitted_events)?;
            if let Some(prepared_state) = prepared_state {
                recorder.enter(ScanPhase::StateSave);
                verify_lock()?;
                prepared_state.install_replace(config.execution.state_path)?;
                recorder.enter(ScanPhase::RemoteDelivery);
            }
        }
        let observation = if persist_episode_latch {
            observe_sink_failure_episode_success(
                &mut state,
                config.execution.sinks,
                &sink_failures,
                !emitted_events.is_empty(),
            )
        } else {
            EpisodeObservation {
                honor_open_episode: false,
                cleared: false,
                durable_success: BTreeMap::new(),
            }
        };
        if !sink_failures.is_empty() {
            if config.execution.sinks.has_canonical_first_write() {
                eprintln!(
                    "warning: remote delivery failed (retries exhausted or not applicable); local JSONL retains the event record"
                );
            } else {
                eprintln!(
                    "warning: remote-only delivery failed (retries exhausted or not applicable); the failed batch is not persisted and is not recoverable for replay"
                );
            }
        }
        let selection =
            select_sink_failure_alerts(&state, &sink_failures, observation.honor_open_episode);
        let mut alerts_accepted = selection.alerts.is_empty();
        if !selection.alerts.is_empty() {
            let failed_names: Vec<&str> = sink_failures.iter().map(|f| f.name.as_str()).collect();
            let delivered = (|| {
                if config.execution.sinks.has_persistent_replay() {
                    config
                        .execution
                        .sinks
                        .persist_for_durable_replay(&selection.alerts)?;
                }
                config
                    .execution
                    .sinks
                    .deliver_alerts(&selection.alerts, &failed_names)
            })();
            match delivered {
                Ok(accepted) => alerts_accepted = accepted,
                Err(error) => {
                    let rendered =
                        format!("warning: could not persist sink-delivery alert: {error}");
                    let rendered =
                        PrivacySanitizer::sanitize(SanitizationContext::Diagnostic, &rendered);
                    eprintln!("{}", rendered.chars().take(200).collect::<String>());
                    // Retain the original failure in stdout, then fail the
                    // command for the required canonical write.
                    alert_persistence_error = Some(error);
                }
            }
        }
        if persist_episode_latch {
            let mut latch_changed = observation.cleared;
            for (sink, identity) in &selection.episode_keys {
                let identity = if alerts_accepted {
                    identity.as_deref()
                } else {
                    None
                };
                latch_changed |= record_sink_failure_episode(
                    &mut state,
                    sink,
                    identity,
                    observation.durable_success.get(sink).copied().flatten(),
                );
            }
            if latch_changed {
                save_sink_failure_episode_latch(
                    &state,
                    config.execution.state_path,
                    state_lock.as_ref(),
                );
            }
        }
    }

    recorder.enter(ScanPhase::Report);
    let mut warnings = diagnostic_warnings(
        &source_discovery,
        &source_processing,
        &detection_flow,
        rule_count,
    );
    if session_store_environment_ignored(config.execution.root, config.execution.clients, &|name| {
        std::env::var_os(name)
    }) {
        warnings.push(diagnostic_warning(
            "session_store_environment_ignored",
            "coverage_limitation",
            "source_discovery",
        ));
    }
    let source_failures = warnings
        .iter()
        .filter(|warning| warning["classification"] == "observed_failure")
        .filter_map(|warning| warning["code"].as_str().map(str::to_string))
        .collect();
    let summary = scan_summary_json(ScanSummaryInput {
        health_event: &health,
        emitted_count,
        activity_count,
        detection_count,
        session_risk_summary_count,
        suppressed_count,
        rule_count,
        active_policy_name: active_policy_name.as_deref(),
        dry_run: config.execution.dry_run,
        log_path: config.execution.log_path,
        delivery_posture,
        sink_failures: &sink_failures,
        source_processing: &source_processing,
        detection_flow: &detection_flow,
        source_discovery: &source_discovery,
        diagnostic_warnings: &warnings,
        targeted,
        runtime: config.execution.runtime,
        effective_configuration: &effective_configuration,
        durable_health: config.execution.sinks.durable_health_json(),
    });
    let mut summary = summary;
    if config.history {
        summary["history"] = "all".into();
    }
    recorder.observe_counts(ScanCounts {
        selected_source_count: source_processing.selected_source_count as u64,
        parsed_record_count: source_processing.parsed_record_count,
        evaluated_window_count: source_processing.evaluated_window_count as u64,
        emitted_count,
    });
    println!("{}", serde_json::to_string(&summary)?);
    if let Some(error) = alert_persistence_error {
        // The sink-failure alert could not be written where events are
        // written first; its time counts toward remote delivery.
        recorder.fail_in(if config.execution.sinks.has_persistent_replay() {
            ScanPhase::DurableAdmission
        } else {
            ScanPhase::CanonicalWrite
        });
        return Err(error);
    }
    Ok(ScanRunResult {
        full_scan_discovery,
        source_failures,
        last_health_unix_ms: if health_emitted {
            Some(observed_at_unix_ms)
        } else {
            last_health_heartbeat
        },
    })
}

pub(super) fn unix_ms_now() -> u64 {
    u64::try_from(OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000).unwrap_or_default()
}

/// How long until the liveness heartbeat is due; zero when it is due now.
/// It is due when no health time is recorded, when the interval has elapsed,
/// or when the recorded time is in the future (the clock moved back), so a
/// clock change emits early rather than going silent until it catches up.
pub(super) fn health_heartbeat_wait(
    last_health_unix_ms: Option<u64>,
    now_unix_ms: u64,
    interval_seconds: u64,
) -> Duration {
    match last_health_unix_ms {
        Some(last) if last <= now_unix_ms => Duration::from_millis(
            interval_seconds
                .saturating_mul(1000)
                .saturating_sub(now_unix_ms - last),
        ),
        _ => Duration::ZERO,
    }
}

/// Session-store variables that only the default `--root .` reads. Another
/// root is searched as a home directory, so a variable that names a relocated
/// store leaves that store unscanned. Values are never inspected beyond the
/// ones discovery itself treats as unset.
fn session_store_environment_ignored(
    root: &Path,
    clients: &[ClientId],
    env: &dyn Fn(&str) -> Option<std::ffi::OsString>,
) -> bool {
    if root == Path::new(".") {
        return false;
    }
    let selected = |client| clients.is_empty() || clients.contains(&client);
    let set = |name| env(name).filter(|value| !value.is_empty());
    (selected(ClientId::Codex) && set("CODEX_HOME").is_some())
        || (selected(ClientId::OpenCode)
            && set("OPENCODE_DB").is_some_and(|value| value != ":memory:"))
}

/// Whether this scan should emit `scanner_error_threshold_exceeded`.
///
/// A durable full scan emits only when the pre-dedup count first goes above
/// the threshold, and clears that latch only when a later full scan is at or
/// below it. Targeted scans see a slice, so they neither emit nor touch the
/// latch. History, dry-run, and backfill do not persist suppression: history
/// and dry-run still emit when above, and backfill repeats while above.
fn scanner_error_threshold_should_alert(
    state: &mut ScanState,
    scanner_error_count: u64,
    max_scanner_errors: u32,
    targeted: bool,
    persist_latch: bool,
) -> bool {
    if targeted {
        return false;
    }
    let above = scanner_error_count > u64::from(max_scanner_errors);
    if !persist_latch {
        return above;
    }
    if above {
        state.enter_scanner_error_threshold()
    } else {
        state.clear_scanner_error_threshold();
        false
    }
}

fn scanner_health_alerts(
    config: &OperationalAlertConfig,
    scanner_error_count: u64,
    scan_duration_ms: u64,
    emit_scanner_error_threshold: bool,
) -> Vec<Event> {
    let mut alerts = Vec::new();
    if emit_scanner_error_threshold && scanner_error_count > u64::from(config.max_scanner_errors) {
        alerts.push(operational_alert_event(OperationalAlertInput {
            alert_type: "scanner_error_threshold_exceeded".to_string(),
            threshold: format!("max_scanner_errors={}", config.max_scanner_errors),
            actual_value: format!("scanner_error_count={scanner_error_count}"),
            scan_duration_ms: Some(scan_duration_ms),
            scanner_error_count: Some(scanner_error_count as u32),
        }));
    }
    if scan_duration_ms > config.max_scan_duration_ms {
        alerts.push(operational_alert_event(OperationalAlertInput {
            alert_type: "scan_duration_threshold_exceeded".to_string(),
            threshold: format!("max_scan_duration_ms={}", config.max_scan_duration_ms),
            actual_value: format!("scan_duration_ms={scan_duration_ms}"),
            scan_duration_ms: Some(scan_duration_ms),
            scanner_error_count: Some(scanner_error_count as u32),
        }));
    }
    alerts
}

/// Per client: the selected source count and whether every selected source
/// failed processing. Per-source `scanner_error` stays `informational` under
/// the frozen Event 3.0 contract; losing every source of a client is a
/// monitoring outage and is raised per client as a `warning` operational alert.
fn client_parse_outcomes(
    results: impl IntoIterator<Item = (ClientId, bool)>,
) -> Vec<(ClientId, usize, bool)> {
    let mut per_client = BTreeMap::<&'static str, (ClientId, usize, bool)>::new();
    for (client, failed) in results {
        let entry = per_client
            .entry(client.as_str())
            .or_insert((client, 0, true));
        entry.1 += 1;
        entry.2 &= failed;
    }
    per_client.into_values().collect()
}

fn source_parse_outage_alert(client: ClientId, selected: usize) -> Event {
    operational_alert_event(OperationalAlertInput {
        alert_type: "source_parse_outage".to_string(),
        threshold: "min_processed_sources_per_client=1".to_string(),
        actual_value: format!(
            "client={}; selected_sources={selected}; processed_sources=0",
            client.as_str()
        ),
        scan_duration_ms: None,
        scanner_error_count: None,
    })
}

struct SelectedSourceEvents {
    events: Vec<Event>,
    emitted_detection_count: usize,
    deduplicated_detection_count: usize,
    scanner_error_emitted: bool,
}

/// Suppress evidence growth only for rules with a known routine severity.
/// Unknown/native rules are not assumed low-risk. Download evidence always emits.
fn routine_evidence_rule_ids(rule_set: &CompiledRuleSet) -> BTreeSet<String> {
    rule_set
        .summaries()
        .into_iter()
        .filter(|rule| {
            matches!(rule.severity.as_str(), "informational" | "low")
                && rule.id != "network.download"
        })
        .map(|rule| rule.id)
        .collect()
}

/// Select in emission order, recording fingerprints only in the in-memory state.
/// Backfill bypasses both deduplication and fingerprint recording.
fn select_source_events(
    state: &mut ScanState,
    backfill: bool,
    activities: Vec<(Source, Event)>,
    detections: Vec<(Source, Event)>,
    session_risk_summaries: Vec<(Source, Event)>,
    routine_evidence_rules: &BTreeSet<String>,
) -> SelectedSourceEvents {
    let mut selected = SelectedSourceEvents {
        events: Vec::with_capacity(
            activities.len() + detections.len() + session_risk_summaries.len(),
        ),
        emitted_detection_count: 0,
        deduplicated_detection_count: 0,
        scanner_error_emitted: false,
    };
    for (source, activity) in activities {
        if backfill || state.should_emit(&source, &activity, routine_evidence_rules) {
            selected.events.push(activity);
        }
    }
    for (source, detection) in detections {
        let is_detection = detection.event_type == "detection";
        let should_emit =
            backfill || state.should_emit(&source, &detection, routine_evidence_rules);
        if is_detection {
            if should_emit {
                selected.emitted_detection_count += 1;
            } else {
                selected.deduplicated_detection_count += 1;
            }
        }
        if should_emit {
            selected.scanner_error_emitted |= detection.event_type == "scanner_error";
            selected.events.push(detection);
        }
    }
    for (source, summary) in session_risk_summaries {
        if backfill || state.should_emit_session_risk_summary(&source, &summary) {
            selected.events.push(summary);
        }
    }
    selected
}

fn sink_failure_alert_event(failure: &SinkFailure) -> Event {
    operational_alert_event(OperationalAlertInput {
        alert_type: "sink_delivery_failure".to_string(),
        threshold: format!("attempts_made={}", failure.attempts),
        actual_value: format!(
            "sink={} type={} class={} error={}",
            terminal_identifier("sink", &failure.name),
            failure.kind,
            failure.class.as_str(),
            failure.error
        ),
        scan_duration_ms: None,
        scanner_error_count: None,
    })
}

struct SinkFailureAlertSelection {
    alerts: Vec<Event>,
    episode_keys: BTreeMap<String, Option<String>>,
}

struct EpisodeObservation {
    honor_open_episode: bool,
    cleared: bool,
    durable_success: BTreeMap<String, Option<i64>>,
}

#[derive(Default)]
struct DurableSuccessSnapshot {
    success: BTreeMap<String, Option<i64>>,
    unordered: BTreeSet<String>,
}

/// Identity is `authentication_blocked` plus status, or `sink_response_blocked`
/// with no status. Other classes are not episode-suppressed.
fn sink_failure_episode_identity(class: DeliveryErrorClass) -> Option<String> {
    match class {
        DeliveryErrorClass::AuthenticationBlocked { status } => {
            Some(format!("authentication_blocked:{status}"))
        }
        DeliveryErrorClass::SinkResponseBlocked => Some("sink_response_blocked".to_string()),
        _ => None,
    }
}

fn is_sink_failure_episode_identity(identity: &str) -> bool {
    identity == "sink_response_blocked"
        || identity
            .strip_prefix("authentication_blocked:")
            .is_some_and(|status| {
                !status.is_empty() && status.bytes().all(|byte| byte.is_ascii_digit())
            })
}

fn sink_failure_episode_latch(sink: &str, identity: &str) -> String {
    format!(
        "telltale:sink_failure_episode_v2:{}:{identity}",
        evidence_hash(sink)
    )
}

fn sink_failure_episode_open(state: &ScanState, sink: &str, identity: &str) -> bool {
    let prefix = format!("{}@", sink_failure_episode_latch(sink, identity));
    state
        .seen_detection_fingerprints
        .range(prefix.clone()..)
        .next()
        .is_some_and(|key| key.starts_with(&prefix))
}

fn clear_sink_failure_episodes(state: &mut ScanState, sink: &str) -> bool {
    record_sink_failure_episode(state, sink, None, None)
}

fn record_sink_failure_episode(
    state: &mut ScanState,
    sink: &str,
    identity: Option<&str>,
    last_success: Option<i64>,
) -> bool {
    let prefix = format!("telltale:sink_failure_episode_v2:{}:", evidence_hash(sink));
    // Remove the pre-hashed markers too, without interpreting delimiters in an
    // operator-supplied name as part of another sink's identity.
    let legacy_prefix = format!("telltale:sink_failure_episode:{sink}:");
    let current = identity.map(|identity| {
        format!(
            "{}@{}",
            sink_failure_episode_latch(sink, identity),
            success_reference(last_success)
        )
    });
    let before = state.seen_detection_fingerprints.len();
    state.seen_detection_fingerprints.retain(|fingerprint| {
        current.as_ref() == Some(fingerprint)
            || ![&prefix, &legacy_prefix].into_iter().any(|prefix| {
                fingerprint
                    .strip_prefix(prefix.as_str())
                    .is_some_and(|suffix| {
                        is_sink_failure_episode_identity(suffix.split('@').next().unwrap_or(suffix))
                    })
            })
    });
    let removed = state.seen_detection_fingerprints.len() != before;
    removed | current.is_some_and(|key| state.seen_detection_fingerprints.insert(key))
}

/// A blocked row released by `release_blocked_for_sink` keeps its attempt count
/// and last structured error, then fails again. That is not a new row in an
/// open episode.
fn released_blocked_row_failed_again(failure: &SinkFailure) -> bool {
    failure.prior_attempts > 0
        && matches!(
            failure.prior_error_class,
            Some(
                DeliveryErrorClass::AuthenticationBlocked { .. }
                    | DeliveryErrorClass::SinkResponseBlocked
            )
        )
}

fn select_sink_failure_alerts(
    state: &ScanState,
    failures: &[SinkFailure],
    honor_open_episode: bool,
) -> SinkFailureAlertSelection {
    let mut alerts = Vec::new();
    let mut episode_keys = BTreeMap::new();
    let mut selected_episodes = BTreeSet::new();
    for failure in failures {
        if let Some(identity) = sink_failure_episode_identity(failure.class) {
            let already_open = episode_keys.get(&failure.name).map_or_else(
                || honor_open_episode && sink_failure_episode_open(state, &failure.name, &identity),
                |current: &Option<String>| current.as_deref() == Some(identity.as_str()),
            );
            episode_keys.insert(failure.name.clone(), Some(identity.clone()));
            let released = failures.iter().any(|other| {
                other.name == failure.name
                    && sink_failure_episode_identity(other.class).as_deref()
                        == Some(identity.as_str())
                    && released_blocked_row_failed_again(other)
            });
            if !released && already_open {
                continue;
            }
            if !selected_episodes.insert((failure.name.clone(), identity)) {
                continue;
            }
        } else {
            episode_keys.insert(failure.name.clone(), None);
        }
        alerts.push(sink_failure_alert_event(failure));
    }
    SinkFailureAlertSelection {
        alerts,
        episode_keys,
    }
}

fn snapshot_durable_sink_success(path: Option<&Path>) -> Result<DurableSuccessSnapshot, ()> {
    let Some(path) = path else {
        return Ok(DurableSuccessSnapshot::default());
    };
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(DurableSuccessSnapshot::default());
        }
        Err(_) => return Err(()),
        Ok(_) => {}
    }
    let outbox = crate::sink::outbox::Outbox::open_read_only(path).map_err(|_| ())?;
    let health = outbox
        .health(&[], crate::sink::outbox::unix_seconds())
        .map_err(|_| ())?;
    let mut snapshot = DurableSuccessSnapshot::default();
    for sink in health.sinks {
        // Equal millisecond timestamps cannot establish success/error order.
        // Fail open for this sink only rather than missing a rapid recovery.
        if sink.last_success_at.is_some() && sink.last_success_at == sink.last_error_at {
            snapshot.unordered.insert(sink.sink_id.clone());
        }
        snapshot.success.insert(sink.sink_id, sink.last_success_at);
    }
    Ok(snapshot)
}

fn clear_sinks_with_new_success(
    state: &mut ScanState,
    after: &BTreeMap<String, Option<i64>>,
) -> bool {
    let mut changed = false;
    for (sink, after_success) in after {
        // Watch may ack while idle. Compare with the success known when the
        // episode was latched, not merely with the beginning of this scan.
        let prefix = format!("telltale:sink_failure_episode_v2:{}:", evidence_hash(sink));
        let expected = format!("@{}", success_reference(*after_success));
        let stale = state
            .seen_detection_fingerprints
            .range(prefix.clone()..)
            .take_while(|key| key.starts_with(&prefix))
            .any(|key| !key.ends_with(&expected));
        if stale {
            changed |= clear_sink_failure_episodes(state, sink);
        }
    }
    changed
}

fn success_reference(success: Option<i64>) -> String {
    success.map_or_else(|| "none".to_string(), |value| value.to_string())
}

fn clear_successful_best_effort_episodes(
    state: &mut ScanState,
    sinks: &SinkSet,
    failures: &[SinkFailure],
    attempted: bool,
) -> bool {
    if !attempted {
        return false;
    }
    let failed = failures
        .iter()
        .map(|failure| failure.name.as_str())
        .collect::<BTreeSet<_>>();
    let durable = sinks
        .durable_sink_ids()
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let mut changed = false;
    for name in sinks.delivery_sink_ids() {
        let best_effort = !sinks.has_persistent_replay() || !durable.contains(name.as_str());
        if best_effort && !failed.contains(name.as_str()) {
            changed |= clear_sink_failure_episodes(state, &name);
        }
    }
    changed
}

fn observe_sink_failure_episode_success(
    state: &mut ScanState,
    sinks: &SinkSet,
    failures: &[SinkFailure],
    attempted_events: bool,
) -> EpisodeObservation {
    let mut cleared = false;
    let (honor_open_episode, durable_success) =
        match snapshot_durable_sink_success(sinks.durable_outbox_path()) {
            Ok(after) => {
                cleared |= clear_sinks_with_new_success(state, &after.success);
                for sink in after.unordered {
                    cleared |= clear_sink_failure_episodes(state, &sink);
                }
                (true, after.success)
            }
            Err(()) => (false, BTreeMap::new()),
        };
    cleared |= clear_successful_best_effort_episodes(state, sinks, failures, attempted_events);
    EpisodeObservation {
        honor_open_episode,
        cleared,
        durable_success,
    }
}

fn save_sink_failure_episode_latch(state: &ScanState, path: &Path, state_lock: Option<&StateLock>) {
    let saved = (|| {
        let Some(lock) = state_lock else {
            return Err("state lock missing before sink-failure episode latch save".into());
        };
        lock.verify_lock()?;
        state.prepare_atomic_save(path)?.install_replace(path)
    })();
    if let Err(error) = saved {
        let rendered =
            format!("warning: could not persist sink-failure alert episode latch: {error}");
        let rendered = PrivacySanitizer::sanitize(SanitizationContext::Diagnostic, &rendered);
        eprintln!("{}", rendered.chars().take(200).collect::<String>());
    }
}

/// Snapshot of the durable parts of scanner state, captured before a scan
/// mutates it, so `StateSavePolicy::OnChange` can skip the state-file write
/// when a scan changed nothing but observation timestamps.
struct StateChangeProbe {
    baseline_snapshots: crate::baseline::BaselineSnapshotStore,
    baseline_source_contributions: BTreeMap<String, crate::state::BaselineSourceContribution>,
    seen_source_fingerprints: usize,
    seen_detection_fingerprints: usize,
    sqlite_ingestion_cursors: BTreeMap<String, SqliteIngestionCursor>,
    source_observation_keys: BTreeSet<String>,
    install_inventory: Option<(u64, String)>,
}

impl StateChangeProbe {
    fn capture(state: &ScanState) -> Self {
        Self {
            baseline_snapshots: state.baseline_snapshots.clone(),
            baseline_source_contributions: state.baseline_source_contributions.clone(),
            seen_source_fingerprints: state.seen_source_fingerprints.len(),
            seen_detection_fingerprints: state.seen_detection_fingerprints.len(),
            sqlite_ingestion_cursors: state.sqlite_ingestion_cursors.clone(),
            source_observation_keys: state.source_observations.keys().cloned().collect(),
            install_inventory: state
                .install_inventory
                .as_ref()
                .map(|snap| (snap.observed_at_unix_ms, snap.hash.clone())),
        }
    }

    fn changed(&self, state: &ScanState) -> bool {
        self.baseline_snapshots != state.baseline_snapshots
            || self.baseline_source_contributions != state.baseline_source_contributions
            || self.seen_source_fingerprints != state.seen_source_fingerprints.len()
            || self.seen_detection_fingerprints != state.seen_detection_fingerprints.len()
            || self.sqlite_ingestion_cursors != state.sqlite_ingestion_cursors
            || self.source_observation_keys
                != state
                    .source_observations
                    .keys()
                    .cloned()
                    .collect::<BTreeSet<_>>()
            || self.install_inventory
                != state
                    .install_inventory
                    .as_ref()
                    .map(|snap| (snap.observed_at_unix_ms, snap.hash.clone()))
    }
}

#[derive(Default)]
struct SourceProcessingAccounting {
    selected_source_count: usize,
    parse_success_source_count: usize,
    empty_source_count: usize,
    parse_error_source_count: usize,
    parsed_record_count: u64,
    record_kind_counts: BTreeMap<String, u64>,
    evaluation_complete_source_count: usize,
    visibility_limited_source_count: usize,
    accounting_complete_source_count: usize,
    accounting_partial_source_count: usize,
    failures: BTreeMap<SourceFailureCategory, usize>,
    quarantined_unit_count: usize,
    /// Tool requests whose name no source tool table lists and that are not
    /// MCP-shaped, and declared requests that lack an operand their table row
    /// names. Counts only, never a name or an argument.
    unclassified_tool_calls: u64,
    tool_operand_drift: u64,
    /// Sources whose last evaluated window was still cut when the scan
    /// stopped draining, at the per-scan window limit or a failed window;
    /// the next scan continues from the advanced cursor.
    incomplete_window_source_count: usize,
    /// Windows evaluated across all sources; above the parsed source count
    /// when a backlog was drained in several windows.
    evaluated_window_count: usize,
    /// Coordinates only, never content; listed up to a fixed bound.
    quarantined_units: Vec<serde_json::Value>,
    /// Distinct native units evaluated with over-bound tool values replaced.
    bounded_value_unit_count: usize,
    /// One entry per unit, field and bound: coordinates only, never content;
    /// every entry of up to the same number of units as quarantined units.
    bounded_value_units: Vec<serde_json::Value>,
}

/// Quarantined units listed in one summary; the count is always complete.
const MAX_REPORTED_QUARANTINED_UNITS: usize = 1_000;

#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct SourceFailureCategory {
    stage: String,
    acquisition_code: Option<&'static str>,
    processing_code: Option<String>,
    bound_category: Option<String>,
    bound_dimension: Option<String>,
}

/// Counts each bounded unit once, however many fields, bounds or drain windows
/// report it, and lists every entry of the first `max_units` units, so a count
/// above the distinct units listed shows the list was cut.
fn bounded_value_units<'a>(
    entries: impl IntoIterator<Item = &'a (String, telltale_sources::acquisition::BoundedUnit)>,
    max_units: usize,
) -> (usize, Vec<serde_json::Value>) {
    let mut units = BTreeSet::new();
    let mut listed = BTreeSet::new();
    let mut reported = Vec::new();
    for (source_id, unit) in entries {
        let key = (
            source_id.as_str(),
            unit.session_id.as_deref(),
            unit.native_id.as_str(),
            unit.source_sequence,
        );
        units.insert(key);
        if listed.contains(&key) || (listed.len() < max_units && listed.insert(key)) {
            reported.push(serde_json::json!({
                "source": source_id,
                "session_id": unit.session_id,
                "native_id": unit.native_id,
                "source_sequence": unit.source_sequence,
                "target": unit.target.as_str(),
                "dimension": unit.dimension.as_str(),
            }));
        }
    }
    (units.len(), reported)
}

fn source_processing_accounting(
    results: &[canonical::CanonicalProcessingResult],
) -> Result<SourceProcessingAccounting, RiskAccountingError> {
    let mut accounting = SourceProcessingAccounting {
        selected_source_count: results.len(),
        parse_success_source_count: 0,
        empty_source_count: 0,
        parse_error_source_count: 0,
        parsed_record_count: 0,
        record_kind_counts: [
            "user_message",
            "assistant_message",
            "tool_call",
            "tool_result",
            "session_meta",
            "other",
        ]
        .into_iter()
        .map(|kind| (kind.to_string(), 0))
        .collect(),
        ..Default::default()
    };

    (
        accounting.bounded_value_unit_count,
        accounting.bounded_value_units,
    ) = bounded_value_units(
        results.iter().flat_map(|result| &result.bounded),
        MAX_REPORTED_QUARANTINED_UNITS,
    );
    for result in results {
        use telltale_detect::v2::EvaluationCompletion;
        use telltale_sources::acquisition::AccountingCoverage;
        match result.completion {
            Some(EvaluationCompletion::Complete) => {
                accounting.evaluation_complete_source_count += 1
            }
            Some(EvaluationCompletion::VisibilityLimited) => {
                accounting.visibility_limited_source_count += 1
            }
            None => {}
        }
        if matches!(
            result.progress,
            telltale_sources::acquisition::AcquisitionProgress::OpenCodeSessionMessages {
                window_complete: false,
                ..
            }
        ) {
            accounting.incomplete_window_source_count += 1;
        }
        for (source_id, unit) in &result.quarantined {
            accounting.quarantined_unit_count += 1;
            if accounting.quarantined_units.len() < MAX_REPORTED_QUARANTINED_UNITS {
                accounting.quarantined_units.push(serde_json::json!({
                    "source": source_id,
                    "session_id": unit.session_id,
                    "native_id": unit.native_id,
                    "source_sequence": unit.source_sequence,
                    "code": unit.code,
                    "bound_category": unit.bound.map(|bound| format!("{:?}", bound.category)),
                    "bound_dimension": unit.bound.map(|bound| format!("{:?}", bound.dimension)),
                }));
            }
        }
        if let Some(failure) = &result.failure {
            let context = failure.acquisition.and_then(|error| error.bound_context());
            let key = SourceFailureCategory {
                stage: format!("{:?}", failure.stage),
                acquisition_code: failure.acquisition.map(|error| error.code()),
                processing_code: failure.processing.map(|error| error.to_string()),
                bound_category: context.map(|context| format!("{:?}", context.category)),
                bound_dimension: context.map(|context| format!("{:?}", context.dimension)),
            };
            *accounting.failures.entry(key).or_default() += 1;
        }
        for source in &result.accounting {
            accounting.unclassified_tool_calls = accounting
                .unclassified_tool_calls
                .checked_add(source.tool_table.unclassified_tool_calls)
                .ok_or(RiskAccountingError::Overflow)?;
            accounting.tool_operand_drift = accounting
                .tool_operand_drift
                .checked_add(source.tool_table.tool_operand_drift)
                .ok_or(RiskAccountingError::Overflow)?;
        }
        accounting.evaluated_window_count += result.accounting.len();
        if result.accounting.is_empty() {
            accounting.parse_error_source_count += 1;
            continue;
        }
        // A drained source is one source however many windows it took; any
        // partial window makes its coverage partial.
        if result
            .accounting
            .iter()
            .all(|source| matches!(source.coverage, AccountingCoverage::CompleteSource))
        {
            accounting.accounting_complete_source_count += 1;
        } else {
            accounting.accounting_partial_source_count += 1;
        }
        accounting.parse_success_source_count += 1;
        let prior_record_count = accounting.parsed_record_count;
        for source in &result.accounting {
            for counts in source
                .sessions
                .iter()
                .map(|session| &session.counts)
                .chain(std::iter::once(&source.unscoped))
            {
                let counts = &counts.record_counts;
                for (kind, count) in [
                    ("user_message", counts.user_message),
                    ("assistant_message", counts.assistant_message),
                    ("tool_call", counts.tool_call),
                    ("tool_result", counts.tool_result),
                    ("session_meta", counts.session_meta),
                    ("other", counts.other),
                ] {
                    accounting.parsed_record_count = accounting
                        .parsed_record_count
                        .checked_add(count)
                        .ok_or(RiskAccountingError::Overflow)?;
                    let total = accounting
                        .record_kind_counts
                        .get_mut(kind)
                        .expect("record kind accounting key");
                    *total = total
                        .checked_add(count)
                        .ok_or(RiskAccountingError::Overflow)?;
                }
            }
        }
        if accounting.parsed_record_count == prior_record_count {
            accounting.empty_source_count += 1;
        }
    }

    Ok(accounting)
}

fn opencode_read_options_for_scan_source(
    source: &Source,
    state: &ScanState,
    backfill: bool,
    dry_run: bool,
) -> OpenCodeSqliteReadOptions {
    let mut options = OpenCodeSqliteReadOptions::default();
    if backfill || dry_run || !is_opencode_sqlite_source(source) {
        return options;
    }

    if let Some(last_seen) =
        state.sqlite_ingestion_cursor_time_updated(source, OPENCODE_SQLITE_PART_TABLE)
    {
        options = OpenCodeSqliteReadOptions::resume_after(last_seen);
    }
    // The store's schema is selected in the read snapshot; each cursor applies
    // only to its own schema, and a missing one means a bootstrap read.
    if let Some(last_seen) =
        state.sqlite_ingestion_cursor_time_updated(source, OPENCODE_SQLITE_SESSION_MESSAGE_TABLE)
    {
        options = options.resume_session_messages_after(last_seen);
        if let Some(cut) =
            state.sqlite_ingestion_continue_after(source, OPENCODE_SQLITE_SESSION_MESSAGE_TABLE)
        {
            options = options.continue_session_messages_after(cut);
        }
    }
    options
}

fn is_opencode_sqlite_source(source: &Source) -> bool {
    source.client == ClientId::OpenCode
        && source.kind == SourceKind::Sqlite
        && source.source_id == "opencode.sqlite"
}

#[derive(Debug)]
struct SessionRiskSummaryAccumulator<'a> {
    source: &'a Source,
    first_event: &'a Event,
    contributions:
        BTreeMap<(telltale_schema::scoring::RiskContributionType, String), RiskContribution>,
    event_time: Option<String>,
    event_counts: BTreeMap<String, u32>,
    tool_call_count: Option<u64>,
    detection_count: u32,
    rule_ids: BTreeSet<String>,
    categories: BTreeSet<String>,
    detection_classes: BTreeSet<String>,
    signal_types: BTreeSet<String>,
    analytic_intents: BTreeSet<String>,
    atlas_tags: BTreeSet<String>,
}

fn session_risk_summaries_for_scan(
    emit_session_risk_summary: bool,
    activities: &[(Source, Event)],
    detections: &[(Source, Event)],
) -> Result<Vec<(Source, Event)>, RiskAccountingError> {
    if emit_session_risk_summary {
        summarize_session_risk_events(activities, detections)
    } else {
        Ok(Vec::new())
    }
}

fn summarize_session_risk_events(
    activities: &[(Source, Event)],
    detections: &[(Source, Event)],
) -> Result<Vec<(Source, Event)>, RiskAccountingError> {
    let mut summaries: BTreeMap<(&str, &str, &str), SessionRiskSummaryAccumulator<'_>> =
        BTreeMap::new();

    for (source, event) in activities.iter().chain(detections.iter()) {
        if !matches!(event.event_type.as_str(), "activity" | "detection")
            || event.session_id == "scanner"
        {
            continue;
        }
        let contribution_score =
            telltale_schema::scoring::checked_risk_sum(&event.risk_contributions)?;
        if (!event.risk_contributions.is_empty() || event.schema_version == "2.0")
            && event.risk_score != contribution_score
        {
            return Err(RiskAccountingError::ScoreMismatch {
                declared: event.risk_score,
                computed: contribution_score,
            });
        }
        let key = (
            event.client.as_str(),
            source.source_id.as_str(),
            event.session_id.as_str(),
        );
        let summary = summaries
            .entry(key)
            .or_insert_with(|| SessionRiskSummaryAccumulator {
                source,
                first_event: event,
                contributions: BTreeMap::new(),
                event_time: None,
                event_counts: BTreeMap::new(),
                tool_call_count: None,
                detection_count: 0,
                rule_ids: BTreeSet::new(),
                categories: BTreeSet::new(),
                detection_classes: BTreeSet::new(),
                signal_types: BTreeSet::new(),
                analytic_intents: BTreeSet::new(),
                atlas_tags: BTreeSet::new(),
            });

        for contribution in &event.risk_contributions {
            let key = (
                contribution.contribution_type(),
                contribution.id().to_string(),
            );
            if let Some(existing) = summary.contributions.get(&key) {
                if existing != contribution {
                    return Err(RiskAccountingError::ConflictingContribution(
                        contribution.id().to_string(),
                    ));
                }
            } else {
                summary.contributions.insert(key, contribution.clone());
            }
        }
        if summary
            .event_time
            .as_deref()
            .is_none_or(|current| event.timestamp.as_str() > current)
        {
            summary.event_time = Some(event.timestamp.clone());
        }
        *summary
            .event_counts
            .entry(event.event_type.clone())
            .or_insert(0) += 1;
        if event.event_type == "activity" && summary.tool_call_count.is_none() {
            summary.tool_call_count = extract_tool_call_count_from_evidence(&event.evidence);
        }
        if event.event_type == "detection" {
            summary.detection_count += 1;
            extend_set(&mut summary.rule_ids, &event.rule_ids);
            extend_set(&mut summary.categories, &event.categories);
            extend_set(&mut summary.detection_classes, &event.detection_classes);
            extend_set(&mut summary.signal_types, &event.signal_types);
            extend_set(&mut summary.analytic_intents, &event.analytic_intents);
            extend_set(&mut summary.atlas_tags, &event.atlas_tags);
        }
    }

    summaries
        .into_values()
        .map(|summary| {
            let source = summary.source.clone();
            let tags = session_risk_summary_tags(&summary);
            let evidence = session_risk_summary_evidence(&summary);
            let risk_contributions = canonicalize_contributions(
                summary.contributions.into_values().collect::<Vec<_>>(),
            )?;
            let event = session_risk_summary_event(SessionRiskSummaryEventInput {
                client: summary.first_event.client.clone(),
                agent: summary.first_event.agent.clone(),
                model: summary.first_event.model.clone(),
                provider: summary.first_event.provider.clone(),
                session_id: summary.first_event.session_id.clone(),
                source_path_hash: summary.first_event.source_path_hash.clone(),
                rule_ids: summary.rule_ids.into_iter().collect(),
                categories: summary.categories.into_iter().collect(),
                detection_classes: summary.detection_classes.into_iter().collect(),
                signal_types: summary.signal_types.into_iter().collect(),
                analytic_intents: summary.analytic_intents.into_iter().collect(),
                atlas_tags: summary.atlas_tags.into_iter().collect(),
                tags,
                evidence,
                risk_contributions,
                event_time: summary.event_time,
            })?;
            Ok((source, event))
        })
        .collect()
}

fn extend_set(target: &mut BTreeSet<String>, values: &[String]) {
    target.extend(values.iter().cloned());
}

fn extract_tool_call_count_from_evidence(evidence: &[Evidence]) -> Option<u64> {
    let record_counts = evidence
        .iter()
        .find(|item| item.field == "record_counts")?
        .redacted_value
        .as_str();
    let counts = serde_json::from_str::<serde_json::Value>(record_counts).ok()?;
    counts.get("tool_call").and_then(|value| value.as_u64())
}

fn session_risk_summary_tags(summary: &SessionRiskSummaryAccumulator<'_>) -> Vec<String> {
    let mut tags = vec!["risk_summary".to_string(), "session".to_string()];
    if summary.detection_count > 0 {
        tags.push("risky_action".to_string());
    }
    if summary.event_counts.contains_key("activity") {
        tags.push("activity".to_string());
    }
    tags.sort();
    tags.dedup();
    tags
}

fn session_risk_summary_evidence(summary: &SessionRiskSummaryAccumulator<'_>) -> Vec<Evidence> {
    let mut evidence = Vec::new();
    let event_counts = serde_json::to_string(&summary.event_counts).unwrap_or_default();
    evidence.push(Evidence {
        field: "event_counts".to_string(),
        redacted_value: event_counts.clone(),
        hash: Some(evidence_hash(&event_counts)),
        rule_id: None,
    });
    evidence.push(Evidence {
        field: "risky_action_count".to_string(),
        redacted_value: summary.detection_count.to_string(),
        hash: None,
        rule_id: None,
    });
    if let Some(count) = summary.tool_call_count {
        evidence.push(Evidence {
            field: "tool_call_count".to_string(),
            redacted_value: count.to_string(),
            hash: None,
            rule_id: None,
        });
    }
    evidence
}

pub(crate) fn run_status(
    log_path: &Path,
    state_path: &Path,
    durable_health: serde_json::Value,
) -> Result<(), Box<dyn std::error::Error>> {
    let status = match journal_status_json(log_path, state_path, durable_health.clone()) {
        Ok(status) => status,
        Err((reason, _)) if durable_health["mode"] == "durable" => {
            let mut status =
                status_json("unavailable", None, 0, log_path, state_path, durable_health);
            status["detection_count"] = serde_json::Value::Null;
            status["journal_status"] = serde_json::json!({
                "availability": "unavailable",
                "reason": reason,
            });
            status
        }
        Err((_, error)) => return Err(error),
    };
    println!("{}", serde_json::to_string(&status)?);
    Ok(())
}

fn journal_status_json(
    log_path: &Path,
    state_path: &Path,
    durable_health: serde_json::Value,
) -> Result<serde_json::Value, (&'static str, Box<dyn std::error::Error>)> {
    if !log_path.exists() {
        return Err(("no_native_health", "no_native_health".into()));
    }
    let mut native_health = None;
    let mut native_detections = 0;
    let mut native_alert_reasons = BTreeSet::new();
    visit_jsonl_records(log_path, |record, _| {
        if event_record_has_type(&record, "health") {
            native_health = Some(record.value);
            native_detections = 0;
            native_alert_reasons.clear();
        } else if event_record_has_type(&record, "detection") {
            native_detections += 1;
        } else if event_record_has_type(&record, "operational_alert") {
            native_alert_reasons.insert(operational_alert_reason(&record.value));
        }
        Ok(())
    })
    .map_err(|error| ("journal_read_failed", error))?;
    let Some(health) = native_health else {
        return Err(("no_native_health", "no_native_health".into()));
    };
    let mut status = status_json(
        "ok",
        Some(&health),
        native_detections,
        log_path,
        state_path,
        durable_health,
    );
    let scanner_errors = scanner_errors_recorded(&health);
    if scanner_errors == Some(true) {
        native_alert_reasons.insert("scanner_errors");
    }
    status["attention_required"] = if !native_alert_reasons.is_empty() {
        true.into()
    } else if scanner_errors.is_none() {
        serde_json::Value::Null
    } else {
        false.into()
    };
    status["attention_reasons"] = native_alert_reasons.into_iter().collect();
    Ok(status)
}

/// Whether a health record counted any scanner errors, or `None` when the
/// count cannot be read. The schema accepts any non-negative integer, and a
/// count above `u64::MAX` reaches serde as a float, so positivity is checked on
/// whichever representation it has instead of treating it as zero.
fn scanner_errors_recorded(health: &serde_json::Value) -> Option<bool> {
    let count = health.get("scanner_error_count")?;
    count
        .as_u64()
        .map(|count| count > 0)
        .or_else(|| count.as_i64().map(|count| count > 0))
        .or_else(|| count.as_f64().map(|count| count > 0.0))
}

/// The closed status reason for one operational alert. The journal is local
/// input, so an unrecognized alert type is reported generically, never echoed.
fn operational_alert_reason(alert: &serde_json::Value) -> &'static str {
    let alert_type = alert
        .get("evidence")
        .and_then(serde_json::Value::as_array)
        .and_then(|evidence| {
            evidence.iter().find(|item| {
                item.get("field").and_then(serde_json::Value::as_str) == Some("alert_type")
            })
        })
        .and_then(|item| item.get("redacted_value"))
        .and_then(serde_json::Value::as_str);
    match alert_type {
        Some("scanner_error_threshold_exceeded") => "scanner_error_threshold_exceeded",
        Some("scan_duration_threshold_exceeded") => "scan_duration_threshold_exceeded",
        Some("source_parse_outage") => "source_parse_outage",
        Some("sink_delivery_failure") => "sink_delivery_failure",
        _ => "operational_alert",
    }
}

fn event_record_has_type(record: &JsonlEventRecord, expected: &str) -> bool {
    record
        .value
        .get("event_type")
        .and_then(|value| value.as_str())
        == Some(expected)
}

struct ScanSummaryInput<'a> {
    health_event: &'a Event,
    emitted_count: u64,
    activity_count: usize,
    detection_count: usize,
    session_risk_summary_count: usize,
    suppressed_count: usize,
    rule_count: usize,
    active_policy_name: Option<&'a str>,
    dry_run: bool,
    log_path: &'a Path,
    delivery_posture: crate::sink::DeliveryPosture,
    sink_failures: &'a [SinkFailure],
    source_processing: &'a SourceProcessingAccounting,
    detection_flow: &'a DetectionFlowAccounting,
    source_discovery: &'a SourceDiscoveryAccounting,
    diagnostic_warnings: &'a [serde_json::Value],
    targeted: bool,
    runtime: &'a serde_json::Value,
    effective_configuration: &'a serde_json::Value,
    durable_health: serde_json::Value,
}

struct ScanRunResult {
    full_scan_discovery: Option<(Vec<Source>, SourceDiscoveryAccounting)>,
    source_failures: Vec<String>,
    /// This scan's time when it emitted health, else the recorded heartbeat
    /// time (none while the heartbeat is off). Watch schedules from it.
    last_health_unix_ms: Option<u64>,
}

struct DetectionFlowAccounting {
    effective_detection_candidate_count: usize,
    matched_rule_id_count: usize,
    allowlist_marked_detection_count: usize,
    state_deduplicated_detection_count: usize,
    emitted_detection_count: usize,
    policy_match_accounting: PolicyMatchAccountingState,
}

enum PolicyMatchAccountingState {
    NotApplicable,
    Available(PolicyMatchAccounting),
    Unavailable,
}

/// Compiles the bundled process-chain pack unless the operator disabled it.
///
/// Process-chain detections emit their own `process_chain` events and never
/// alter the session `detection` event, so this stays a load-or-skip decision
/// rather than another axis on the scan config. The
/// `detections.process_chain` setting turns them off.
fn load_process_chain_rules_if_enabled(
    enabled: bool,
) -> Option<telltale_rules::process_chain::CompiledProcessChainRules> {
    if !enabled {
        return None;
    }
    telltale_rules::process_chain::load_default_process_chain_rules().ok()
}

fn detection_flow_accounting(detections: &[(Source, Event)]) -> DetectionFlowAccounting {
    let mut accounting = DetectionFlowAccounting {
        effective_detection_candidate_count: 0,
        matched_rule_id_count: 0,
        allowlist_marked_detection_count: 0,
        state_deduplicated_detection_count: 0,
        emitted_detection_count: 0,
        policy_match_accounting: PolicyMatchAccountingState::NotApplicable,
    };
    for (_, event) in detections {
        if event.event_type == "detection" {
            accounting.effective_detection_candidate_count += 1;
            accounting.matched_rule_id_count += event.rule_ids.len();
        }
    }
    accounting
}

fn checked_add_policy_match_accounting(
    total: &mut PolicyMatchAccounting,
    accounting: PolicyMatchAccounting,
) -> Option<()> {
    total.pre_policy_detection_candidate_count = total
        .pre_policy_detection_candidate_count
        .checked_add(accounting.pre_policy_detection_candidate_count)?;
    total.fully_filtered_detection_candidate_count = total
        .fully_filtered_detection_candidate_count
        .checked_add(accounting.fully_filtered_detection_candidate_count)?;
    total.filtered_rule_id_count = total
        .filtered_rule_id_count
        .checked_add(accounting.filtered_rule_id_count)?;
    Some(())
}

fn compute_policy_match_accounting(
    policy_active: bool,
    pre_policy_available: bool,
    results: &[canonical::CanonicalProcessingResult],
) -> PolicyMatchAccountingState {
    if !policy_active {
        return PolicyMatchAccountingState::NotApplicable;
    }
    if !pre_policy_available {
        return PolicyMatchAccountingState::Unavailable;
    }

    let mut total = PolicyMatchAccounting {
        pre_policy_detection_candidate_count: 0,
        fully_filtered_detection_candidate_count: 0,
        filtered_rule_id_count: 0,
    };
    for result in results {
        let Some(Ok(accounting)) = result.policy_accounting else {
            return PolicyMatchAccountingState::Unavailable;
        };
        if checked_add_policy_match_accounting(&mut total, accounting).is_none() {
            return PolicyMatchAccountingState::Unavailable;
        }
    }
    PolicyMatchAccountingState::Available(total)
}

impl SourceProcessingAccounting {
    fn selected_source_coverage(&self) -> &'static str {
        if self.selected_source_count == 0 {
            "no_sources"
        } else if self.parse_error_source_count > 0
            || self.quarantined_unit_count > 0
            || self.bounded_value_unit_count > 0
            || self.incomplete_window_source_count > 0
            || self.visibility_limited_source_count > 0
            || self.accounting_partial_source_count > 0
        {
            "partial"
        } else {
            "complete"
        }
    }

    fn json(&self) -> serde_json::Value {
        let failures: Vec<_> = self
            .failures
            .iter()
            .map(|(category, count)| {
                serde_json::json!({
                    "stage": category.stage,
                    "acquisition_code": category.acquisition_code,
                    "processing_code": category.processing_code,
                    "bound_category": category.bound_category,
                    "bound_dimension": category.bound_dimension,
                    "source_count": count,
                })
            })
            .collect();
        serde_json::json!({
            "selected_source_count": self.selected_source_count,
            "parse_success_source_count": self.parse_success_source_count,
            "empty_source_count": self.empty_source_count,
            "parse_error_source_count": self.parse_error_source_count,
            "parsed_record_count": self.parsed_record_count,
            "record_kind_counts": self.record_kind_counts,
            "evaluation_complete_source_count": self.evaluation_complete_source_count,
            "visibility_limited_source_count": self.visibility_limited_source_count,
            "accounting_complete_source_count": self.accounting_complete_source_count,
            "accounting_partial_source_count": self.accounting_partial_source_count,
            "selected_source_coverage": self.selected_source_coverage(),
            "failures": failures,
            "incomplete_window_source_count": self.incomplete_window_source_count,
            "evaluated_window_count": self.evaluated_window_count,
            "quarantined_unit_count": self.quarantined_unit_count,
            "quarantined_units": self.quarantined_units,
            "bounded_value_unit_count": self.bounded_value_unit_count,
            "bounded_value_units": self.bounded_value_units,
            "unclassified_tool_calls": self.unclassified_tool_calls,
            "tool_operand_drift": self.tool_operand_drift,
        })
    }
}

impl DetectionFlowAccounting {
    fn json(&self) -> serde_json::Value {
        let (status, accounting) = match &self.policy_match_accounting {
            PolicyMatchAccountingState::NotApplicable => ("not_applicable", None),
            PolicyMatchAccountingState::Available(accounting) => ("available", Some(accounting)),
            PolicyMatchAccountingState::Unavailable => ("unavailable", None),
        };
        serde_json::json!({
            "effective_detection_candidate_count": self.effective_detection_candidate_count,
            "matched_rule_id_count": self.matched_rule_id_count,
            "allowlist_marked_detection_count": self.allowlist_marked_detection_count,
            "state_deduplicated_detection_count": self.state_deduplicated_detection_count,
            "emitted_detection_count": self.emitted_detection_count,
            "policy_match_accounting": {
                "status": status,
                "pre_policy_detection_candidate_count": accounting.map(|value| value.pre_policy_detection_candidate_count),
                "fully_filtered_detection_candidate_count": accounting.map(|value| value.fully_filtered_detection_candidate_count),
                "filtered_rule_id_count": accounting.map(|value| value.filtered_rule_id_count),
            },
        })
    }
}

fn diagnostic_warnings(
    source_discovery: &SourceDiscoveryAccounting,
    source_processing: &SourceProcessingAccounting,
    detection_flow: &DetectionFlowAccounting,
    rule_count: usize,
) -> Vec<serde_json::Value> {
    let mut warnings = Vec::new();
    if source_discovery
        .project_configuration
        .document_failure_count
        > 0
    {
        warnings.push(diagnostic_warning(
            "project_config_load_failed",
            "observed_failure",
            "project_configuration",
        ));
    }
    if source_discovery.best_effort_fallback_used {
        warnings.push(diagnostic_warning(
            "source_discovery_degraded",
            "observed_failure",
            "source_discovery",
        ));
    }
    if source_processing.parse_error_source_count > 0 {
        warnings.push(diagnostic_warning(
            "source_parse_error_observed",
            "observed_failure",
            "source_processing",
        ));
    }
    if source_processing.selected_source_coverage() == "partial" {
        warnings.push(diagnostic_warning(
            "source_coverage_partial",
            "coverage_limitation",
            "source_processing",
        ));
    }

    let selected = source_processing.selected_source_count;
    let records = source_processing.parsed_record_count;
    if selected == 0 {
        warnings.push(diagnostic_warning(
            "no_sources_selected",
            "suspicious_zero",
            "source_selection",
        ));
    }
    if selected > 0 && records == 0 {
        warnings.push(diagnostic_warning(
            "selected_sources_produced_no_records",
            "suspicious_zero",
            "source_processing",
        ));
    }
    if selected > 0 && source_processing.parse_success_source_count == 0 {
        warnings.push(diagnostic_warning(
            "all_selected_sources_parse_failed_or_empty",
            "suspicious_zero",
            "source_processing",
        ));
    }
    let tool_call_count = source_processing
        .record_kind_counts
        .get("tool_call")
        .copied()
        .unwrap_or_default();
    let tool_result_count = source_processing
        .record_kind_counts
        .get("tool_result")
        .copied()
        .unwrap_or_default();
    if records > 0 && tool_call_count == 0 && tool_result_count == 0 {
        warnings.push(diagnostic_warning(
            "no_tool_records_observed",
            "suspicious_zero",
            "source_processing",
        ));
    }
    if records > 0 && rule_count > 0 && detection_flow.effective_detection_candidate_count == 0 {
        warnings.push(diagnostic_warning(
            "no_effective_detection_candidates",
            "suspicious_zero",
            "detection_flow",
        ));
    }
    warnings
}

fn diagnostic_warning(
    code: &'static str,
    classification: &'static str,
    basis: &'static str,
) -> serde_json::Value {
    serde_json::json!({
        "code": code,
        "classification": classification,
        "basis": basis,
    })
}

fn scan_summary_json(summary: ScanSummaryInput<'_>) -> serde_json::Value {
    let delivery_status = if summary.dry_run {
        "not_attempted"
    } else if summary.delivery_posture == crate::sink::DeliveryPosture::NoEnabledSinks {
        "not_delivered"
    } else if summary.sink_failures.is_empty() {
        "delivered"
    } else {
        "failed"
    };
    let sink_failures: Vec<serde_json::Value> = summary
        .sink_failures
        .iter()
        .map(|failure| {
            serde_json::json!({
                "name": terminal_identifier("sink", &failure.name),
                "type": failure.kind,
                "class": failure.class.as_str(),
                "attempts": failure.attempts,
                "error": PrivacySanitizer::sanitize(SanitizationContext::Diagnostic, &failure.error),
            })
        })
        .collect();
    let built_in_persistent_replay = summary
        .durable_health
        .get("mode")
        .and_then(serde_json::Value::as_str)
        == Some("durable");
    serde_json::json!({
        "client": summary.health_event.client,
        "event_type": summary.health_event.event_type,
        "activity_count": summary.activity_count,
        "detection_count": summary.detection_count,
        "session_risk_summary_count": summary.session_risk_summary_count,
        "suppressed_count": summary.suppressed_count,
        "emitted_count": summary.emitted_count,
        "rule_count": summary.rule_count,
        "policy": summary.active_policy_name.map(|value| opaque_identifier("policy", value)),
        "log_path": if summary.dry_run {
            None
        } else {
            Some(PrivacySanitizer::sanitize(
                SanitizationContext::Path,
                &summary.log_path.to_string_lossy(),
            ))
        },
        "delivery": {
            "posture": summary.delivery_posture.as_str(),
            "status": delivery_status,
            "durable_first_write": summary.delivery_posture.has_durable_first_write(),
            "built_in_persistent_replay": built_in_persistent_replay,
            "durable_health": summary.durable_health,
        },
        "source_counts": summary.health_event.source_counts.clone().unwrap_or_default(),
        "sink_failures": sink_failures,
        "source_discovery": summary.source_discovery.json(
            if summary.targeted {
                "watch_source_index_snapshot"
            } else {
                "current_full_scan"
            },
            !summary.targeted,
        ),
        "source_processing": summary.source_processing.json(),
        "detection_flow": summary.detection_flow.json(),
        "diagnostic_warnings": summary.diagnostic_warnings,
        "runtime": summary.runtime,
        "effective_configuration": summary.effective_configuration,
    })
}

fn status_json(
    status: &str,
    health: Option<&serde_json::Value>,
    detection_count: usize,
    log_path: &Path,
    state_path: &Path,
    durable_health: serde_json::Value,
) -> serde_json::Value {
    let mut health_fields = health
        .map(|health| {
            let mut terminal = health.clone();
            sanitize_serialized_event(&mut terminal);
            terminal
        })
        .and_then(|value| match value {
            serde_json::Value::Object(fields) => Some(fields),
            _ => None,
        })
        .unwrap_or_default();
    serde_json::json!({
        "status": status,
        "last_scan_time": health_fields.remove("timestamp"),
        "log_path": PrivacySanitizer::sanitize(SanitizationContext::Path, &log_path.to_string_lossy()),
        "state_path": PrivacySanitizer::sanitize(SanitizationContext::Path, &state_path.to_string_lossy()),
        "health_component": health_fields.remove("component"),
        "health_check_name": health_fields.remove("check_name"),
        "health_check_status": health_fields.remove("status"),
        "active_policy_name": health_fields.remove("active_policy_name"),
        "rule_count": health_fields.remove("rule_count"),
        "detection_count": detection_count,
        "threshold_config": health_fields.remove("threshold_config"),
        "source_counts": health_fields.remove("source_counts").unwrap_or_else(|| serde_json::json!({})),
        "emitted_count": health_fields.remove("emitted_count"),
        "suppressed_count": health_fields.remove("suppressed_count"),
        "scanner_error_count": health_fields.remove("scanner_error_count"),
        "durable_queue_health": durable_health,
        // Only native health can be assessed; anything else is unknown.
        "attention_required": serde_json::Value::Null,
        "attention_reasons": [],
    })
}

#[cfg(test)]
mod tests;
