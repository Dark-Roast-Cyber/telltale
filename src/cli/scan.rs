use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use time::OffsetDateTime;

use crate::allowlist::{load_allowlist, suppress_detection};
use crate::baseline::{BaselineDeviationConfig, build_baseline_summaries};
use crate::cli::historical::{EventRecordKind, JsonlEventRecord, read_jsonl_records};
use crate::detection::{
    EffectiveMatchSnapshot, ParsedSourceActivityAttempt, ParsedSourceDetectionAttempt,
    PolicyMatchAccounting, account_policy_matches, detect_parsed_source_attempt,
    summarize_parsed_source_activity_attempt,
};
use crate::discovery::is_fixture_root;
use crate::event::{
    Event, Evidence, HealthEventInput, OperationalAlertConfig, OperationalAlertInput,
    PrivacySanitizer, SanitizationContext, SessionRiskSummaryEventInput, evidence_hash,
    health_event_with_metadata, load_operational_alert_config, opaque_identifier,
    operational_alert_event, sanitize_serialized_event, scanner_error_event,
    session_risk_summary_event, terminal_identifier,
};
use crate::file_lock::validate_runtime_paths;
use crate::install_inventory::{
    collect_install_inventory, install_inventory_due, snapshot_to_event,
};
use crate::mcp::{discover_mcp_inventory, discover_mcp_usage};
use crate::parser::{ParseError, ParseOptions, parse_source_records_with_options};
use crate::process_chain::{ProcessChainConfig, detect_process_chains};
use crate::rules::{
    RuleLoadMode, RulePackPaths,
    resolve_rule_set_from_pack_paths_with_mode_override_paths_and_replacements,
};
use crate::scoring::load_thresholds;
use crate::scoring::{RiskAccountingError, RiskContribution, canonicalize_contributions};
use crate::sink::{SinkFailure, SinkSet};
use crate::state::{ScanState, SqliteIngestionCursor, StateLock, source_fingerprint};
use telltale_schema::clients::{ClientId, SourceKind};
use telltale_schema::record::{NormalizedRecord, RecordKind};
use telltale_schema::source::Source;

const OPENCODE_SQLITE_PART_TABLE: &str = "part";
const OPENCODE_SQLITE_CURSOR_OVERLAP_MS: i64 = 10 * 60 * 1_000;

mod canonical;
mod discovery;
mod processing;
pub(super) mod watch;

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
    pub(crate) runtime: &'a serde_json::Value,
    pub(crate) effective_configuration: &'a serde_json::Value,
}

/// A shared scan plus the options only `scan` accepts.
#[derive(Clone, Copy)]
pub(crate) struct ScanConfig<'a> {
    pub(crate) execution: ScanExecutionConfig<'a>,
    pub(crate) backfill: bool,
    pub(crate) rebuild_baselines: bool,
    pub(crate) max_sources: Option<usize>,
}

pub(crate) fn run_scan_loop(
    config: ScanConfig<'_>,
    iterations: Option<u32>,
    interval: Duration,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut remaining = iterations;
    loop {
        run_scan_once(config)?;
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

pub(crate) fn run_scan_once(config: ScanConfig<'_>) -> Result<(), Box<dyn std::error::Error>> {
    run_scan(config, ScanTargets::Full, StateSavePolicy::Always).map(|_| ())
}

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
    )
}

fn run_scan_for_platform(
    config: ScanConfig<'_>,
    targets: ScanTargets,
    save_policy: StateSavePolicy,
    is_windows: bool,
) -> Result<ScanRunResult, Box<dyn std::error::Error>> {
    ensure_durable_scan_platform(config.execution.sinks, is_windows)?;
    let scan_started = Instant::now();
    validate_runtime_paths(
        config.execution.state_path,
        &config.execution.sinks.local_persistence_paths(),
        &config.execution.sinks.local_rotation_namespaces(),
    )?;
    let fixture_root = is_fixture_root(config.execution.root);
    if !config.execution.dry_run && !config.execution.allow_fixtures && fixture_root {
        return Err(
            "refusing to write fixture/demo data to log path; use --dry-run or --allow-fixtures"
                .into(),
        );
    }
    let (mut sources, targeted, source_discovery) = match targets {
        ScanTargets::Targeted { sources, discovery } => (sources, true, discovery),
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
            (sources, false, discovery)
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
    let state_lock = if config.execution.dry_run {
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
    let merged_rule_set = resolution.merged_rule_set;
    let mut effective_configuration = config.execution.effective_configuration.clone();
    effective_configuration["rules"] = {
        let mut rules = effective_configuration["rules"].clone();
        rules["sources"] = diagnostics["sources"].clone();
        rules["provenance"] = diagnostics["provenance"].clone();
        rules
    };
    let rule_count = rule_set.rule_count();
    let active_policy_name = rule_set.policy_name().map(str::to_string);
    let allowlist = load_allowlist(config.execution.allowlist_path)?;
    let mut state = if config.execution.dry_run {
        ScanState::load_snapshot(config.execution.state_path)?
    } else {
        ScanState::load_unlocked(config.execution.state_path)?
    };
    let state_probe = match save_policy {
        StateSavePolicy::Always => None,
        StateSavePolicy::OnChange => Some(StateChangeProbe::capture(&state)),
    };
    let baseline_snapshots = state.baseline_snapshots.clone();
    let install_inventory_interval_seconds = config.execution.install_inventory_interval_seconds;
    let observed_at_unix_ms = OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000;
    let observed_at_unix_ms = u64::try_from(observed_at_unix_ms).unwrap_or_default();
    let parsed_sources =
        parse_scan_sources(&sources, &state, config.backfill, config.execution.dry_run);
    let source_processing = source_processing_accounting(&sources, &parsed_sources);
    update_baseline_snapshots(&mut state, &parsed_sources, config.rebuild_baselines);
    let mut install_inventory_event = None;
    if config.execution.clients.is_empty()
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
    let activity_config = config
        .execution
        .emit_activity
        .then(|| BaselineDeviationConfig {
            enabled: config.execution.baseline_deviation_scoring,
            ..BaselineDeviationConfig::default()
        });
    let mut activities = Vec::new();
    let mut effective_match_snapshots = Vec::new();
    let mut detections = Vec::new();
    let mut processing_statuses = Vec::with_capacity(parsed_sources.len());
    let process_chain_rules = load_process_chain_rules_if_enabled();
    for parsed_source in &parsed_sources {
        let activity_attempt = activity_config.and_then(|baseline_deviation_config| {
            let records = parsed_source.records.as_ref().ok()?;
            Some(summarize_parsed_source_activity_attempt(
                &parsed_source.source,
                records,
                &baseline_snapshots,
                baseline_deviation_config,
            ))
        });
        let analyzed = analyze_parsed_source(
            parsed_source,
            &rule_set,
            policy_active,
            process_chain_rules.as_ref(),
            activity_attempt.as_ref(),
        );
        processing_statuses.push(analyzed.status);
        if let Some(activity_attempt) = activity_attempt {
            activities.extend(
                activity_attempt
                    .events
                    .into_iter()
                    .map(|event| (parsed_source.source.clone(), event)),
            );
        }
        detections.extend(
            analyzed
                .events
                .into_iter()
                .map(|event| (parsed_source.source.clone(), event)),
        );
        effective_match_snapshots.extend(analyzed.snapshot);
    }
    // MCP discovery walks host-wide config directories; targeted scans only
    // re-examine changed session sources, so leave it to full scans.
    if config.execution.emit_activity && !targeted {
        activities.extend(discover_mcp_inventory(config.execution.root));
        activities.extend(discover_mcp_usage(config.execution.root, &sources));
    }
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
    let session_risk_summaries = if config.execution.emit_session_risk_summary {
        summarize_session_risk_events(&activities, &detections)?
    } else {
        Vec::new()
    };
    let session_risk_summary_count = session_risk_summaries.len();
    let scan_duration_ms = scan_started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
    // Targeted scans see only a slice of the source inventory; comparing that
    // slice against prior observations would misreport every unscanned source
    // as removed, so inventory-change tracking is left to full scans.
    let source_inventory_change = if targeted {
        None
    } else {
        Some(state.source_inventory_change_summary(&sources))
    };

    let op_config = load_operational_alert_config();
    let scanner_error_count = detections
        .iter()
        .filter(|(_, event)| event.event_type == "scanner_error")
        .count() as u64;
    let operational_alerts =
        scanner_health_alerts(&op_config, scanner_error_count, scan_duration_ms);
    let has_operational_alerts = !operational_alerts.is_empty();

    let pre_policy_rule_set = if policy_active {
        Some(merged_rule_set.compile(None))
    } else {
        None
    };
    detection_flow.policy_match_accounting = compute_policy_match_accounting(
        policy_active,
        pre_policy_rule_set.as_ref(),
        &effective_match_snapshots,
    );

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
    let selected = select_source_events(
        &mut state,
        config.backfill,
        activities,
        detections,
        session_risk_summaries,
    );
    detection_flow.emitted_detection_count += selected.emitted_detection_count;
    detection_flow.state_deduplicated_detection_count += selected.deduplicated_detection_count;
    emitted_events.extend(selected.events);

    let health_emitted = config.execution.dry_run
        || config.backfill
        || inventory_health_change
        || selected.scanner_error_emitted
        || has_operational_alerts;
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
    }

    if targeted {
        state.observe_sources(&sources, observed_at_unix_ms);
    } else {
        state.replace_source_observations(&sources, observed_at_unix_ms);
    }
    if should_stage_sqlite_ingestion_cursors(config.execution.dry_run, config.backfill) {
        observe_sqlite_ingestion_cursors(
            &mut state,
            &parsed_sources,
            &processing_statuses,
            observed_at_unix_ms,
        );
    }

    let mut sink_failures: Vec<SinkFailure> = Vec::new();
    let delivery_posture = config.execution.sinks.delivery_posture();
    let should_save = if config.execution.dry_run {
        false
    } else {
        match &state_probe {
            None => true,
            Some(probe) => !emitted_events.is_empty() || probe.changed(&state),
        }
    };
    let prepared_state = if should_save {
        Some(state.prepare_atomic_save(config.execution.state_path)?)
    } else {
        None
    };
    if !config.execution.dry_run {
        let state_lock = state_lock
            .as_ref()
            .ok_or("state lock missing before durable delivery")?;
        state_lock.verify()?;
        if config.execution.sinks.has_persistent_replay() {
            sink_failures = config
                .execution
                .sinks
                .persist_for_durable_replay_with_failures(&emitted_events)?;
            if let Some(prepared_state) = prepared_state {
                state_lock.verify()?;
                prepared_state.install_replace(config.execution.state_path)?;
            }
            sink_failures.extend(config.execution.sinks.deliver_durable()?);
            sink_failures.extend(
                config
                    .execution
                    .sinks
                    .deliver_best_effort(&emitted_events)?,
            );
        } else {
            sink_failures = config.execution.sinks.deliver(&emitted_events)?;
            if let Some(prepared_state) = prepared_state {
                state_lock.verify()?;
                prepared_state.install_replace(config.execution.state_path)?;
            }
        }
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
            let alerts: Vec<Event> = sink_failures.iter().map(sink_failure_alert_event).collect();
            let failed_names: Vec<&str> = sink_failures.iter().map(|f| f.name.as_str()).collect();
            if config.execution.sinks.has_persistent_replay()
                && let Err(error) = config.execution.sinks.persist_for_durable_replay(&alerts)
            {
                let rendered = format!(
                    "warning: could not persist sink-delivery alert for durable replay: {error}"
                );
                let rendered =
                    PrivacySanitizer::sanitize(SanitizationContext::Diagnostic, &rendered);
                eprintln!("{}", rendered.chars().take(200).collect::<String>());
            }
            config
                .execution
                .sinks
                .deliver_alerts(&alerts, &failed_names);
        }
    }

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
        diagnostic_warnings: &diagnostic_warnings(
            &source_discovery,
            &source_processing,
            &detection_flow,
            rule_count,
        ),
        targeted,
        runtime: config.execution.runtime,
        effective_configuration: &effective_configuration,
        durable_health: config.execution.sinks.durable_health_json(),
    });
    println!("{}", serde_json::to_string(&summary)?);
    Ok(ScanRunResult {
        full_scan_discovery,
    })
}

struct AnalyzedScanSource {
    events: Vec<Event>,
    snapshot: Option<EffectiveMatchSnapshot>,
    status: SourceProcessingStatus,
}

fn analyze_parsed_source(
    parsed_source: &ParsedScanSource,
    rule_set: &telltale_rules::CompiledRuleSet,
    policy_active: bool,
    process_chain_rules: Option<&telltale_rules::process_chain::CompiledProcessChainRules>,
    activity_attempt: Option<&ParsedSourceActivityAttempt>,
) -> AnalyzedScanSource {
    let source = &parsed_source.source;
    let records = match &parsed_source.records {
        Ok(records) => records,
        Err(ParseError::Empty) => {
            return AnalyzedScanSource {
                events: Vec::new(),
                snapshot: None,
                status: SourceProcessingStatus::Failed,
            };
        }
        Err(error) => {
            return AnalyzedScanSource {
                events: vec![scanner_error_event(source, error)],
                snapshot: None,
                status: SourceProcessingStatus::Failed,
            };
        }
    };
    let process_chain = process_chain_rules
        .map(|rules| detect_process_chains(source, rules, records, &ProcessChainConfig::default()));
    let attempt = detect_parsed_source_attempt(source, rule_set, records, policy_active);
    finish_analyzed_source(source, process_chain, attempt, activity_attempt)
}

/// Combines parse-success downstream results into one processing status.
/// Activity, process-chain, and detection Event3 values may describe a failure;
/// status remains the operational owner.
fn finish_analyzed_source(
    source: &Source,
    process_chain: Option<Result<Vec<Event>, RiskAccountingError>>,
    attempt: ParsedSourceDetectionAttempt,
    activity_attempt: Option<&ParsedSourceActivityAttempt>,
) -> AnalyzedScanSource {
    let mut events = Vec::new();
    let mut status = SourceProcessingStatus::Succeeded;
    if let Some(result) = process_chain {
        match result {
            Ok(chain_events) => events.extend(chain_events),
            Err(error) => {
                status = SourceProcessingStatus::Failed;
                events.push(scanner_error_event(source, &error));
            }
        }
    }
    // Chain output (or its scanner error) precedes the ordinary detection pass.
    if !attempt.completed_operationally {
        status = SourceProcessingStatus::Failed;
    }
    if activity_attempt.is_some_and(|attempt| !attempt.completed_operationally) {
        status = SourceProcessingStatus::Failed;
    }
    events.extend(attempt.events);
    AnalyzedScanSource {
        events,
        snapshot: attempt.snapshot,
        status,
    }
}

fn scanner_health_alerts(
    config: &OperationalAlertConfig,
    scanner_error_count: u64,
    scan_duration_ms: u64,
) -> Vec<Event> {
    let mut alerts = Vec::new();
    if scanner_error_count > u64::from(config.max_scanner_errors) {
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

struct SelectedSourceEvents {
    events: Vec<Event>,
    emitted_detection_count: usize,
    deduplicated_detection_count: usize,
    scanner_error_emitted: bool,
}

/// Select in emission order, recording fingerprints only in the in-memory state.
/// Backfill bypasses both deduplication and fingerprint recording.
fn select_source_events(
    state: &mut ScanState,
    backfill: bool,
    activities: Vec<(Source, Event)>,
    detections: Vec<(Source, Event)>,
    session_risk_summaries: Vec<(Source, Event)>,
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
        if backfill || state.should_emit(&source, &activity) {
            selected.events.push(activity);
        }
    }
    for (source, detection) in detections {
        let is_detection = detection.event_type == "detection";
        let should_emit = backfill || state.should_emit(&source, &detection);
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
        if backfill || state.should_emit(&source, &summary) {
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

/// Snapshot of the durable parts of scanner state, captured before a scan
/// mutates it, so `StateSavePolicy::OnChange` can skip the state-file write
/// when a scan changed nothing but observation timestamps.
struct StateChangeProbe {
    seen_source_fingerprints: usize,
    seen_detection_fingerprints: usize,
    sqlite_ingestion_cursors: BTreeMap<String, SqliteIngestionCursor>,
    source_observation_keys: BTreeSet<String>,
    install_inventory: Option<(u64, String)>,
}

impl StateChangeProbe {
    fn capture(state: &ScanState) -> Self {
        Self {
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
        self.seen_source_fingerprints != state.seen_source_fingerprints.len()
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

struct ParsedScanSource {
    source: Source,
    records: Result<Vec<NormalizedRecord>, ParseError>,
    sqlite_part_max_time_updated: Option<i64>,
}

struct SourceProcessingAccounting {
    selected_source_count: usize,
    parse_success_source_count: usize,
    empty_source_count: usize,
    parse_error_source_count: usize,
    parsed_record_count: usize,
    record_kind_counts: BTreeMap<String, usize>,
}

fn source_processing_accounting(
    sources: &[Source],
    parsed_sources: &[ParsedScanSource],
) -> SourceProcessingAccounting {
    let mut accounting = SourceProcessingAccounting {
        selected_source_count: sources.len(),
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
    };

    for parsed_source in parsed_sources {
        match &parsed_source.records {
            Ok(records) => {
                accounting.parse_success_source_count += 1;
                accounting.parsed_record_count += records.len();
                for record in records {
                    let kind = match record.kind {
                        RecordKind::UserMessage => "user_message",
                        RecordKind::AssistantMessage => "assistant_message",
                        RecordKind::ToolCall => "tool_call",
                        RecordKind::ToolResult => "tool_result",
                        RecordKind::SessionMeta => "session_meta",
                        RecordKind::Other => "other",
                        _ => "other",
                    };
                    *accounting
                        .record_kind_counts
                        .get_mut(kind)
                        .expect("record kind accounting key") += 1;
                }
            }
            Err(ParseError::Empty) => accounting.empty_source_count += 1,
            Err(_) => accounting.parse_error_source_count += 1,
        }
    }

    accounting
}

fn parse_scan_sources(
    sources: &[Source],
    state: &ScanState,
    backfill: bool,
    dry_run: bool,
) -> Vec<ParsedScanSource> {
    sources
        .iter()
        .map(|source| {
            let options = parse_options_for_scan_source(source, state, backfill, dry_run);
            match parse_source_records_with_options(source, options) {
                Ok(parsed) => ParsedScanSource {
                    source: source.clone(),
                    records: Ok(parsed.records),
                    sqlite_part_max_time_updated: parsed.sqlite_part_max_time_updated,
                },
                Err(error) => ParsedScanSource {
                    source: source.clone(),
                    records: Err(error),
                    sqlite_part_max_time_updated: None,
                },
            }
        })
        .collect()
}

fn parse_options_for_scan_source(
    source: &Source,
    state: &ScanState,
    backfill: bool,
    dry_run: bool,
) -> ParseOptions {
    let mut options = ParseOptions::default();
    if backfill || dry_run || !is_opencode_sqlite_source(source) {
        return options;
    }

    options.sqlite_part_min_time_updated = state
        .sqlite_ingestion_cursor_time_updated(source, OPENCODE_SQLITE_PART_TABLE)
        .map(|last_seen| last_seen.saturating_sub(OPENCODE_SQLITE_CURSOR_OVERLAP_MS));
    options
}

fn observe_sqlite_ingestion_cursors(
    state: &mut ScanState,
    parsed_sources: &[ParsedScanSource],
    processing_statuses: &[SourceProcessingStatus],
    observed_at_unix_ms: u64,
) {
    debug_assert_eq!(parsed_sources.len(), processing_statuses.len());
    for (parsed_source, status) in parsed_sources.iter().zip(processing_statuses) {
        let Some(last_time_updated) = sqlite_progress_candidate(
            is_opencode_sqlite_source(&parsed_source.source),
            parsed_source.sqlite_part_max_time_updated,
            *status,
        ) else {
            continue;
        };
        state.observe_sqlite_ingestion_cursor(
            &parsed_source.source,
            OPENCODE_SQLITE_PART_TABLE,
            last_time_updated,
            observed_at_unix_ms,
        );
    }
}

fn is_opencode_sqlite_source(source: &Source) -> bool {
    source.client == ClientId::OpenCode && source.kind == SourceKind::Sqlite
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

fn update_baseline_snapshots(
    state: &mut ScanState,
    parsed_sources: &[ParsedScanSource],
    force_rebuild: bool,
) {
    if state.has_legacy_source_identity_state() {
        state.drop_legacy_source_identity_state();
        state.rebuild_baseline_snapshots_from_source_contributions();
    }
    for parsed_source in parsed_sources {
        let source = &parsed_source.source;
        let fingerprint = source_fingerprint(source);
        if !force_rebuild && state.seen_source_fingerprints.contains(&fingerprint) {
            continue;
        }
        let Ok(records) = &parsed_source.records else {
            continue;
        };
        let summaries = build_baseline_summaries(records);
        state.record_baseline_source_contribution(source, fingerprint.clone(), summaries);
        state.rebuild_baseline_snapshots_from_source_contributions();
        state.seen_source_fingerprints.insert(fingerprint);
    }
}

pub(crate) fn run_status(
    log_path: &Path,
    state_path: &Path,
    durable_health: serde_json::Value,
) -> Result<(), Box<dyn std::error::Error>> {
    if !log_path.exists() {
        return Err("no_native_health".into());
    }
    let records = read_jsonl_records(log_path)?;
    if records.is_empty() {
        return Err("no_native_health".into());
    }
    let native_health_index = records.iter().rposition(|record| {
        record.kind == EventRecordKind::Native && event_record_has_type(record, "health")
    });
    let status = if let Some(health_index) = native_health_index {
        let detection_count = records[health_index + 1..]
            .iter()
            .filter(|record| {
                record.kind == EventRecordKind::Native && event_record_has_type(record, "detection")
            })
            .count();
        status_json(
            "ok",
            Some(&records[health_index].value),
            detection_count,
            log_path,
            state_path,
            durable_health,
        )
    } else if records
        .iter()
        .all(|record| record.kind == EventRecordKind::Historical)
    {
        let health = records
            .iter()
            .rev()
            .find(|record| event_record_has_type(record, "health"));
        let detection_count = records
            .iter()
            .filter(|record| event_record_has_type(record, "detection"))
            .count();
        status_json(
            "historical_only",
            health.map(|record| &record.value),
            detection_count,
            log_path,
            state_path,
            durable_health,
        )
    } else {
        return Err("no_native_health".into());
    };
    println!("{}", serde_json::to_string(&status)?);
    Ok(())
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
/// rather than another axis on the scan config. Set
/// `TELLTALE_PROCESS_CHAIN_DETECTIONS=0` to turn them off.
fn load_process_chain_rules_if_enabled()
-> Option<telltale_rules::process_chain::CompiledProcessChainRules> {
    if !crate::config::process_chain_detections_enabled() {
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
    pre_policy_rule_set: Option<
        &Result<telltale_rules::CompiledRuleSet, Box<dyn std::error::Error>>,
    >,
    snapshots: &[EffectiveMatchSnapshot],
) -> PolicyMatchAccountingState {
    if !policy_active {
        return PolicyMatchAccountingState::NotApplicable;
    }
    let Some(Ok(pre_policy_rule_set)) = pre_policy_rule_set else {
        return PolicyMatchAccountingState::Unavailable;
    };

    let mut total = PolicyMatchAccounting {
        pre_policy_detection_candidate_count: 0,
        fully_filtered_detection_candidate_count: 0,
        filtered_rule_id_count: 0,
    };
    for snapshot in snapshots {
        let Ok(accounting) = account_policy_matches(snapshot, pre_policy_rule_set) else {
            return PolicyMatchAccountingState::Unavailable;
        };
        if checked_add_policy_match_accounting(&mut total, accounting).is_none() {
            return PolicyMatchAccountingState::Unavailable;
        }
    }
    PolicyMatchAccountingState::Available(total)
}

impl SourceProcessingAccounting {
    fn json(&self) -> serde_json::Value {
        serde_json::json!({
            "selected_source_count": self.selected_source_count,
            "parse_success_source_count": self.parse_success_source_count,
            "empty_source_count": self.empty_source_count,
            "parse_error_source_count": self.parse_error_source_count,
            "parsed_record_count": self.parsed_record_count,
            "record_kind_counts": self.record_kind_counts,
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
    })
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::discovery::ProjectConfigurationAccounting;
    use super::*;
    use crate::baseline::BaselineSnapshotStore;
    use crate::install_inventory::InstallInventorySnapshot;
    use crate::sink::{
        DeliveryError, DeliveryErrorClass, EventSink, LocalJsonlSink, RotationConfig,
    };

    #[test]
    fn scanner_health_alert_thresholds_are_strict_and_error_alert_precedes_duration_alert() {
        let config = OperationalAlertConfig {
            max_scanner_errors: 3,
            max_scan_duration_ms: 100,
        };
        for (errors, duration, expected) in [
            (2, 99, vec![]),
            (3, 100, vec![]),
            (4, 100, vec!["scanner_error_threshold"]),
            (3, 101, vec!["scan_duration_threshold"]),
            (
                4,
                101,
                vec!["scanner_error_threshold", "scan_duration_threshold"],
            ),
        ] {
            let alerts = scanner_health_alerts(&config, errors, duration);
            assert_eq!(
                alerts
                    .iter()
                    .map(|event| event.check_name.as_deref().unwrap())
                    .collect::<Vec<_>>(),
                expected,
                "errors={errors}, duration={duration}",
            );
        }
    }

    #[test]
    fn source_event_selection_preserves_order_accounting_and_backfill_state() {
        let source = Source {
            client: ClientId::OpenCode,
            kind: SourceKind::Sqlite,
            source_id: "synthetic-selection".to_string(),
            path: PathBuf::from("synthetic-selection.db"),
        };
        let error = scanner_error_event(&source, &ParseError::Empty);
        let event = |kind: &str| {
            let mut event = error.clone();
            event.event_type = kind.to_string();
            (source.clone(), event)
        };
        let activities = vec![event("activity")];
        let detections = vec![
            event("detection"),
            event("detection"),
            event("scanner_error"),
            event("process_chain"),
        ];
        let summaries = vec![event("session_risk_summary")];
        let mut state = ScanState::default();
        let first = select_source_events(
            &mut state,
            false,
            activities.clone(),
            detections.clone(),
            summaries.clone(),
        );
        assert_eq!(
            first
                .events
                .iter()
                .map(|event| event.event_type.as_str())
                .collect::<Vec<_>>(),
            [
                "activity",
                "detection",
                "scanner_error",
                "process_chain",
                "session_risk_summary"
            ],
        );
        assert_eq!(first.emitted_detection_count, 1);
        assert_eq!(first.deduplicated_detection_count, 1);
        assert!(first.scanner_error_emitted);
        let recorded_state = state.canonical_bytes().unwrap();
        let repeated = select_source_events(
            &mut state,
            false,
            activities.clone(),
            detections.clone(),
            summaries.clone(),
        );
        assert!(repeated.events.is_empty());
        assert_eq!(repeated.emitted_detection_count, 0);
        assert_eq!(repeated.deduplicated_detection_count, 2);
        assert!(!repeated.scanner_error_emitted);
        assert_eq!(state.canonical_bytes().unwrap(), recorded_state);

        for mut state in [state, ScanState::default()] {
            let before = state.canonical_bytes().unwrap();
            let backfill = select_source_events(
                &mut state,
                true,
                activities.clone(),
                detections.clone(),
                summaries.clone(),
            );
            assert_eq!(backfill.events.len(), 6);
            assert_eq!(backfill.emitted_detection_count, 2);
            assert_eq!(backfill.deduplicated_detection_count, 0);
            assert!(backfill.scanner_error_emitted);
            assert_eq!(state.canonical_bytes().unwrap(), before);
        }
    }

    #[test]
    fn opencode_sqlite_scan_options_use_cursor_overlap_for_live_scans() {
        let source = Source {
            client: ClientId::OpenCode,
            kind: SourceKind::Sqlite,
            source_id: "opencode.sqlite".to_string(),
            path: PathBuf::from("/home/user/.local/share/opencode/opencode.db"),
        };
        let mut state = ScanState::default();
        state.observe_sqlite_ingestion_cursor(&source, OPENCODE_SQLITE_PART_TABLE, 1_000_000, 42);

        let live_options = parse_options_for_scan_source(&source, &state, false, false);
        assert_eq!(
            live_options.sqlite_part_min_time_updated,
            Some(1_000_000 - OPENCODE_SQLITE_CURSOR_OVERLAP_MS)
        );

        let dry_run_options = parse_options_for_scan_source(&source, &state, false, true);
        assert_eq!(dry_run_options.sqlite_part_min_time_updated, None);

        let backfill_options = parse_options_for_scan_source(&source, &state, true, false);
        assert_eq!(backfill_options.sqlite_part_min_time_updated, None);
    }

    #[test]
    fn sqlite_parse_failure_does_not_advance_ingestion_cursor() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("failed-opencode.db");
        fs::write(&path, b"not a SQLite database").expect("invalid SQLite fixture");
        let source = Source {
            client: ClientId::OpenCode,
            kind: SourceKind::Sqlite,
            source_id: "opencode.sqlite".to_string(),
            path,
        };
        let mut state = ScanState::default();
        state.observe_sqlite_ingestion_cursor(&source, OPENCODE_SQLITE_PART_TABLE, 5_000, 1_000);

        let parsed = parse_scan_sources(std::slice::from_ref(&source), &state, false, false);
        assert!(parsed[0].records.is_err());
        let analyzed = analyze_parsed_source(&parsed[0], &test_rule_set(), false, None, None);
        assert_eq!(analyzed.status, SourceProcessingStatus::Failed);
        assert_eq!(analyzed.events[0].event_type, "scanner_error");
        observe_sqlite_ingestion_cursors(&mut state, &parsed, &[analyzed.status], 2_000);

        assert_eq!(
            state.sqlite_ingestion_cursor_time_updated(&source, OPENCODE_SQLITE_PART_TABLE),
            Some(5_000)
        );
    }

    #[test]
    fn opencode_successful_no_match_keeps_cursor_eligible() {
        let parsed = opencode_parsed(Ok(Vec::new()), Some(9_000));
        let analyzed = analyze_parsed_source(&parsed, &test_rule_set(), false, None, None);
        assert_eq!(analyzed.status, SourceProcessingStatus::Succeeded);
        assert!(analyzed.events.is_empty());
        let mut state = ScanState::default();
        observe_sqlite_ingestion_cursors(&mut state, &[parsed], &[analyzed.status], 2_000);
        assert_eq!(
            state.sqlite_ingestion_cursor_time_updated(
                &opencode_test_source(),
                OPENCODE_SQLITE_PART_TABLE
            ),
            Some(9_000)
        );
    }

    #[test]
    fn opencode_activity_failure_emits_error_and_does_not_advance_cursor() {
        let parsed = opencode_parsed(Ok(vec![activity_record(Some(String::new()))]), Some(9_000));
        let source = parsed.source.clone();
        let activity_attempt = summarize_parsed_source_activity_attempt(
            &source,
            parsed.records.as_ref().expect("parsed records"),
            &BaselineSnapshotStore::default(),
            BaselineDeviationConfig::default(),
        );
        assert!(!activity_attempt.completed_operationally);
        assert_eq!(activity_attempt.events.len(), 1);
        assert_eq!(activity_attempt.events[0].event_type, "scanner_error");

        let detection_attempt = detect_parsed_source_attempt(
            &source,
            &test_rule_set(),
            parsed.records.as_ref().expect("parsed records"),
            false,
        );
        assert!(detection_attempt.completed_operationally);
        assert!(detection_attempt.events.is_empty());
        let analyzed = finish_analyzed_source(
            &source,
            Some(Ok(Vec::new())),
            detection_attempt,
            Some(&activity_attempt),
        );
        assert_eq!(analyzed.status, SourceProcessingStatus::Failed);
        assert!(
            analyzed.events.is_empty(),
            "ordinary detection is a no-match"
        );
        assert_eq!(
            sqlite_progress_candidate(true, Some(9_000), analyzed.status),
            None
        );

        let mut state = ScanState::default();
        state.observe_sqlite_ingestion_cursor(&source, OPENCODE_SQLITE_PART_TABLE, 5_000, 1_000);
        observe_sqlite_ingestion_cursors(&mut state, &[parsed], &[analyzed.status], 2_000);
        assert_eq!(
            state.sqlite_ingestion_cursor_time_updated(&source, OPENCODE_SQLITE_PART_TABLE),
            Some(5_000)
        );
    }

    #[test]
    fn opencode_successful_enabled_activity_no_match_keeps_cursor_eligible() {
        let parsed = opencode_parsed(
            Ok(vec![activity_record(Some("synthetic-model".to_string()))]),
            Some(9_000),
        );
        let source = parsed.source.clone();
        let activity_attempt = summarize_parsed_source_activity_attempt(
            &source,
            parsed.records.as_ref().expect("parsed records"),
            &BaselineSnapshotStore::default(),
            BaselineDeviationConfig::default(),
        );
        assert!(activity_attempt.completed_operationally);
        assert_eq!(activity_attempt.events.len(), 1);
        assert_eq!(activity_attempt.events[0].event_type, "activity");

        let detection_attempt = detect_parsed_source_attempt(
            &source,
            &test_rule_set(),
            parsed.records.as_ref().expect("parsed records"),
            false,
        );
        assert!(detection_attempt.completed_operationally);
        assert!(detection_attempt.events.is_empty());
        let analyzed = finish_analyzed_source(
            &source,
            Some(Ok(Vec::new())),
            detection_attempt,
            Some(&activity_attempt),
        );
        assert_eq!(analyzed.status, SourceProcessingStatus::Succeeded);
        assert!(
            analyzed.events.is_empty(),
            "ordinary detection is a no-match"
        );
        assert_eq!(
            sqlite_progress_candidate(true, Some(9_000), analyzed.status),
            Some(9_000)
        );

        let mut state = ScanState::default();
        observe_sqlite_ingestion_cursors(&mut state, &[parsed], &[analyzed.status], 2_000);
        assert_eq!(
            state.sqlite_ingestion_cursor_time_updated(&source, OPENCODE_SQLITE_PART_TABLE),
            Some(9_000)
        );
    }

    #[test]
    fn opencode_successful_findings_keep_cursor_eligible() {
        let parsed = opencode_parsed(Ok(Vec::new()), Some(9_000));
        let source = parsed.source.clone();
        let mut finding = scanner_error_event(&source, &ParseError::Empty);
        finding.event_type = "detection".to_string();
        let analyzed = finish_analyzed_source(
            &source,
            Some(Ok(Vec::new())),
            ParsedSourceDetectionAttempt {
                events: vec![finding],
                snapshot: None,
                completed_operationally: true,
            },
            None,
        );
        assert_eq!(analyzed.status, SourceProcessingStatus::Succeeded);
        assert_eq!(analyzed.events[0].event_type, "detection");
        let mut state = ScanState::default();
        observe_sqlite_ingestion_cursors(&mut state, &[parsed], &[analyzed.status], 2_000);
        assert_eq!(
            state.sqlite_ingestion_cursor_time_updated(&source, OPENCODE_SQLITE_PART_TABLE),
            Some(9_000)
        );
    }

    #[test]
    fn opencode_scanner_error_event_does_not_make_progress_eligible() {
        let parsed = opencode_parsed(Ok(Vec::new()), Some(9_000));
        let source = parsed.source.clone();
        let analyzed = finish_analyzed_source(
            &source,
            None,
            ParsedSourceDetectionAttempt {
                events: vec![scanner_error_event(&source, &RiskAccountingError::Overflow)],
                snapshot: None,
                completed_operationally: false,
            },
            None,
        );
        assert_eq!(analyzed.status, SourceProcessingStatus::Failed);
        assert_eq!(analyzed.events[0].event_type, "scanner_error");
        let mut state = ScanState::default();
        state.observe_sqlite_ingestion_cursor(&source, OPENCODE_SQLITE_PART_TABLE, 5_000, 1_000);
        observe_sqlite_ingestion_cursors(&mut state, &[parsed], &[analyzed.status], 2_000);
        assert_eq!(
            state.sqlite_ingestion_cursor_time_updated(&source, OPENCODE_SQLITE_PART_TABLE),
            Some(5_000)
        );
    }

    #[test]
    fn opencode_detection_operational_failure_does_not_advance_cursor() {
        let parsed = opencode_parsed(Ok(Vec::new()), Some(9_000));
        let source = parsed.source.clone();
        let analyzed = finish_analyzed_source(
            &source,
            Some(Ok(Vec::new())),
            ParsedSourceDetectionAttempt {
                events: vec![scanner_error_event(&source, &RiskAccountingError::Overflow)],
                snapshot: None,
                completed_operationally: false,
            },
            None,
        );
        assert_eq!(analyzed.status, SourceProcessingStatus::Failed);
        assert!(
            analyzed
                .events
                .iter()
                .any(|event| event.event_type == "scanner_error")
        );
        let mut state = ScanState::default();
        state.observe_sqlite_ingestion_cursor(&source, OPENCODE_SQLITE_PART_TABLE, 5_000, 1_000);
        observe_sqlite_ingestion_cursors(&mut state, &[parsed], &[analyzed.status], 2_000);
        assert_eq!(
            state.sqlite_ingestion_cursor_time_updated(&source, OPENCODE_SQLITE_PART_TABLE),
            Some(5_000)
        );
    }

    #[test]
    fn opencode_process_chain_operational_failure_does_not_advance_cursor() {
        let parsed = opencode_parsed(Ok(Vec::new()), Some(9_000));
        let source = parsed.source.clone();
        let analyzed = finish_analyzed_source(
            &source,
            Some(Err(RiskAccountingError::Overflow)),
            ParsedSourceDetectionAttempt {
                events: Vec::new(),
                snapshot: None,
                completed_operationally: true,
            },
            None,
        );
        assert_eq!(analyzed.status, SourceProcessingStatus::Failed);
        assert_eq!(analyzed.events[0].event_type, "scanner_error");
        let mut state = ScanState::default();
        state.observe_sqlite_ingestion_cursor(&source, OPENCODE_SQLITE_PART_TABLE, 5_000, 1_000);
        observe_sqlite_ingestion_cursors(&mut state, &[parsed], &[analyzed.status], 2_000);
        assert_eq!(
            state.sqlite_ingestion_cursor_time_updated(&source, OPENCODE_SQLITE_PART_TABLE),
            Some(5_000)
        );
    }

    #[test]
    fn watch_shared_path_failed_processing_is_not_a_durable_cursor_change() {
        let parsed = opencode_parsed(Ok(Vec::new()), Some(9_000));
        let mut state = ScanState::default();
        state.observe_sqlite_ingestion_cursor(
            &parsed.source,
            OPENCODE_SQLITE_PART_TABLE,
            5_000,
            1_000,
        );
        let probe = StateChangeProbe::capture(&state);
        observe_sqlite_ingestion_cursors(
            &mut state,
            &[parsed],
            &[SourceProcessingStatus::Failed],
            2_000,
        );
        assert!(!probe.changed(&state));
    }

    fn opencode_test_source() -> Source {
        Source {
            client: ClientId::OpenCode,
            kind: SourceKind::Sqlite,
            source_id: "opencode.sqlite".to_string(),
            path: PathBuf::from("/synthetic/opencode.db"),
        }
    }

    fn opencode_parsed(
        records: Result<Vec<NormalizedRecord>, ParseError>,
        high_water: Option<i64>,
    ) -> ParsedScanSource {
        ParsedScanSource {
            source: opencode_test_source(),
            records,
            sqlite_part_max_time_updated: high_water,
        }
    }

    fn activity_record(model: Option<String>) -> NormalizedRecord {
        NormalizedRecord {
            session_id: "session-a".to_string(),
            client: "opencode".to_string(),
            agent: None,
            model,
            provider: None,
            timestamp: None,
            kind: telltale_schema::record::RecordKind::Other,
            tool_name: None,
            arguments: None,
            content: "synthetic benign activity".to_string(),
        }
    }

    fn test_rule_set() -> telltale_rules::CompiledRuleSet {
        telltale_rules::load_default_rule_set().expect("default rule set")
    }

    #[test]
    fn simulated_windows_durable_scan_rejects_before_state_progress_or_best_effort_fallback() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().join("synthetic-root");
        fs::create_dir_all(&root).expect("synthetic root");
        let log_path = temp.path().join("events.jsonl");
        let state_path = temp.path().join("state.json");
        let outbox_path = temp.path().join("private").join("outbox.sqlite");

        let mut initial_state = ScanState::default();
        initial_state
            .seen_source_fingerprints
            .insert("synthetic-existing-fingerprint".to_string());
        initial_state.save(&state_path).expect("save initial state");
        let state_before = fs::read(&state_path).expect("read initial state");

        let delivery_calls = Arc::new(AtomicUsize::new(0));
        let mut sinks = SinkSet::new();
        sinks.add_canonical_first_write_path_with_rotation(
            "jsonl",
            Box::new(LocalJsonlSink::with_rotation(
                &log_path,
                RotationConfig::disabled(),
            )),
            log_path.clone(),
            None,
        );
        sinks.add_best_effort(
            "synthetic",
            Box::new(CountingSink {
                calls: Arc::clone(&delivery_calls),
            }),
        );
        sinks.enable_persistent_replay_with_capacity(
            outbox_path.clone(),
            vec!["synthetic".to_string()],
            crate::sink::outbox::CapacityLimits::default(),
        );

        let rule_pack_paths = RulePackPaths::default();
        let rule_paths = Vec::new();
        let override_paths = Vec::new();
        let project_config_paths = Vec::new();
        let clients = Vec::new();
        let runtime = serde_json::json!({});
        let effective_configuration = serde_json::json!({});
        let config = ScanConfig {
            execution: ScanExecutionConfig {
                root: &root,
                log_path: &log_path,
                sinks: &sinks,
                state_path: &state_path,
                dry_run: false,
                emit_activity: false,
                emit_session_risk_summary: false,
                allow_fixtures: true,
                rule_pack_paths: &rule_pack_paths,
                rule_paths: &rule_paths,
                override_paths: &override_paths,
                rule_load_mode: RuleLoadMode::IncludeDefault,
                policy_path: None,
                allowlist_path: None,
                baseline_deviation_scoring: false,
                clients: &clients,
                project_config_paths: &project_config_paths,
                install_inventory_interval_seconds: None,
                runtime: &runtime,
                effective_configuration: &effective_configuration,
            },
            backfill: false,
            rebuild_baselines: false,
            max_sources: None,
        };

        let error =
            match run_scan_for_platform(config, ScanTargets::Full, StateSavePolicy::Always, true) {
                Ok(_) => panic!("Windows durable scan must be rejected"),
                Err(error) => error,
            };
        let delivery = error
            .downcast_ref::<DeliveryError>()
            .expect("platform rejection must be structured");
        assert_eq!(delivery.class, DeliveryErrorClass::DurableStorage);
        assert_eq!(delivery.attempts, 0);
        assert_eq!(
            delivery.message,
            crate::sink::outbox::WINDOWS_DURABLE_STORAGE_UNSUPPORTED
        );

        assert_eq!(
            fs::read(&state_path).expect("read state after rejection"),
            state_before
        );
        assert!(!log_path.exists());
        assert!(!outbox_path.parent().expect("outbox parent").exists());
        assert!(!outbox_path.exists());
        assert_eq!(delivery_calls.load(Ordering::SeqCst), 0);
    }

    struct CountingSink {
        calls: Arc<AtomicUsize>,
    }

    impl EventSink for CountingSink {
        fn name(&self) -> &str {
            "synthetic"
        }

        fn emit(&self, _events: &[Event]) -> Result<(), Box<dyn std::error::Error>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        fn emit_canonical_once(&self, _payload: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    fn test_source(path: &str) -> Source {
        Source {
            client: ClientId::Codex,
            kind: SourceKind::Jsonl,
            source_id: "codex.sessions".to_string(),
            path: PathBuf::from(path),
        }
    }

    #[test]
    fn state_change_probe_detects_durable_changes_only() {
        let source = Source {
            client: ClientId::OpenCode,
            kind: SourceKind::Sqlite,
            source_id: "opencode.sqlite".to_string(),
            path: PathBuf::from("/watch-test/opencode/opencode.db"),
        };
        let mut state = ScanState::default();
        state.observe_sources(std::slice::from_ref(&source), 1_000);
        state.observe_sqlite_ingestion_cursor(&source, OPENCODE_SQLITE_PART_TABLE, 5_000, 1_000);

        let probe = StateChangeProbe::capture(&state);
        assert!(!probe.changed(&state));

        // Refreshing the observation timestamp for a known source is not durable.
        state.observe_sources(std::slice::from_ref(&source), 2_000);
        assert!(!probe.changed(&state));

        // Advancing a SQLite ingestion cursor is durable.
        state.observe_sqlite_ingestion_cursor(&source, OPENCODE_SQLITE_PART_TABLE, 6_000, 2_000);
        assert!(probe.changed(&state));

        // A newly observed source is durable.
        let probe = StateChangeProbe::capture(&state);
        let new_source = test_source("/watch-test/codex/sessions/session-b.jsonl");
        state.observe_sources(std::slice::from_ref(&new_source), 3_000);
        assert!(probe.changed(&state));

        // New fingerprints (emitted events / baseline contributions) are durable.
        let probe = StateChangeProbe::capture(&state);
        state
            .seen_source_fingerprints
            .insert("fingerprint".to_string());
        assert!(probe.changed(&state));

        // A new or changed install inventory snapshot is durable.
        let probe = StateChangeProbe::capture(&state);
        state.install_inventory = Some(InstallInventorySnapshot {
            observed_at_unix_ms: 4_000,
            hash: "hash-a".to_string(),
            agents: vec![],
        });
        assert!(probe.changed(&state));

        // An unchanged install inventory snapshot is not durable.
        let probe = StateChangeProbe::capture(&state);
        state.install_inventory = Some(InstallInventorySnapshot {
            observed_at_unix_ms: 4_000,
            hash: "hash-a".to_string(),
            agents: vec![],
        });
        assert!(!probe.changed(&state));

        // Changing the install inventory hash is durable.
        let probe = StateChangeProbe::capture(&state);
        state.install_inventory = Some(InstallInventorySnapshot {
            observed_at_unix_ms: 6_000,
            hash: "hash-b".to_string(),
            agents: vec![],
        });
        assert!(probe.changed(&state));
    }

    fn test_discovery_accounting() -> SourceDiscoveryAccounting {
        SourceDiscoveryAccounting {
            checked_status: "succeeded",
            first_error_category: None,
            best_effort_fallback_used: false,
            returned_source_count: 0,
            operational_source_count: 0,
            project_configuration: ProjectConfigurationAccounting::none(),
        }
    }

    fn warning_codes(warnings: &[serde_json::Value]) -> Vec<&str> {
        warnings
            .iter()
            .map(|warning| warning["code"].as_str().expect("warning code"))
            .collect()
    }

    #[test]
    fn policy_accounting_compile_failure_is_bounded_and_private() {
        let failed: Result<telltale_rules::CompiledRuleSet, Box<dyn std::error::Error>> =
            Err("synthetic diagnostic compile failure".into());
        let state = compute_policy_match_accounting(true, Some(&failed), &[]);
        let flow = DetectionFlowAccounting {
            effective_detection_candidate_count: 0,
            matched_rule_id_count: 0,
            allowlist_marked_detection_count: 0,
            state_deduplicated_detection_count: 0,
            emitted_detection_count: 0,
            policy_match_accounting: state,
        };
        let accounting = flow.json()["policy_match_accounting"].clone();
        assert_eq!(accounting["status"], "unavailable");
        assert!(accounting["pre_policy_detection_candidate_count"].is_null());
        assert!(accounting["fully_filtered_detection_candidate_count"].is_null());
        assert!(accounting["filtered_rule_id_count"].is_null());
        assert!(!accounting.to_string().contains("synthetic"));
    }

    #[test]
    fn suspicious_zero_warning_predicates_keep_empty_and_dedup_cases_distinct() {
        let discovery = test_discovery_accounting();
        let flow = DetectionFlowAccounting {
            effective_detection_candidate_count: 0,
            matched_rule_id_count: 0,
            allowlist_marked_detection_count: 0,
            state_deduplicated_detection_count: 0,
            emitted_detection_count: 0,
            policy_match_accounting: PolicyMatchAccountingState::NotApplicable,
        };
        let no_sources = SourceProcessingAccounting {
            selected_source_count: 0,
            parse_success_source_count: 0,
            empty_source_count: 0,
            parse_error_source_count: 0,
            parsed_record_count: 0,
            record_kind_counts: BTreeMap::new(),
        };
        assert_eq!(
            warning_codes(&diagnostic_warnings(&discovery, &no_sources, &flow, 18)),
            vec!["no_sources_selected"]
        );

        let empty_sources = SourceProcessingAccounting {
            selected_source_count: 2,
            parse_success_source_count: 0,
            empty_source_count: 2,
            parse_error_source_count: 0,
            parsed_record_count: 0,
            record_kind_counts: BTreeMap::new(),
        };
        assert_eq!(
            warning_codes(&diagnostic_warnings(&discovery, &empty_sources, &flow, 18)),
            vec![
                "selected_sources_produced_no_records",
                "all_selected_sources_parse_failed_or_empty"
            ]
        );

        let productive_sources = SourceProcessingAccounting {
            selected_source_count: 2,
            parse_success_source_count: 2,
            empty_source_count: 1,
            parse_error_source_count: 0,
            parsed_record_count: 1,
            record_kind_counts: BTreeMap::from([("user_message".to_string(), 1)]),
        };
        assert_eq!(
            warning_codes(&diagnostic_warnings(
                &discovery,
                &productive_sources,
                &flow,
                18
            )),
            vec![
                "no_tool_records_observed",
                "no_effective_detection_candidates"
            ]
        );
        assert!(
            !warning_codes(&diagnostic_warnings(
                &discovery,
                &productive_sources,
                &flow,
                0,
            ))
            .contains(&"no_effective_detection_candidates")
        );

        let repeated_positive = DetectionFlowAccounting {
            effective_detection_candidate_count: 1,
            state_deduplicated_detection_count: 1,
            ..flow
        };
        assert!(
            !warning_codes(&diagnostic_warnings(
                &discovery,
                &SourceProcessingAccounting {
                    selected_source_count: 1,
                    parse_success_source_count: 1,
                    empty_source_count: 0,
                    parse_error_source_count: 0,
                    parsed_record_count: 1,
                    record_kind_counts: BTreeMap::from([("tool_call".to_string(), 1)]),
                },
                &repeated_positive,
                18,
            ))
            .contains(&"no_effective_detection_candidates")
        );
    }

    #[test]
    fn parsed_empty_result_is_a_parse_success() {
        let source = test_source("empty-success.jsonl");
        let parsed = ParsedScanSource {
            source: source.clone(),
            records: Ok(Vec::new()),
            sqlite_part_max_time_updated: None,
        };
        let accounting = source_processing_accounting(&[source], &[parsed]);
        assert_eq!(accounting.selected_source_count, 1);
        assert_eq!(accounting.parse_success_source_count, 1);
        assert_eq!(accounting.empty_source_count, 0);
        assert_eq!(accounting.parse_error_source_count, 0);
        assert_eq!(accounting.parsed_record_count, 0);
    }

    #[test]
    fn session_summary_unions_exact_contributions_by_source_identity() {
        use crate::event::{ActivityEventInput, activity_event};
        use crate::scoring::{RiskContribution, RiskContributionType};

        let contribution = || {
            RiskContribution::new(
                "baseline.synthetic",
                RiskContributionType::BaselineDeviation,
                30,
                "synthetic rule match",
            )
            .expect("contribution")
        };
        let event = || {
            activity_event(ActivityEventInput {
                client: ClientId::Codex,
                agent: None,
                model: None,
                provider: None,
                session_id: "session-union".to_string(),
                source_path_hash: "path".to_string(),
                tool_name: Some("shell".to_string()),
                tags: vec!["activity".to_string()],
                evidence: Vec::new(),
                risk_contributions: vec![contribution()],
                event_time: None,
            })
            .expect("build activity event")
        };
        let source_a = Source {
            client: ClientId::Codex,
            kind: SourceKind::Jsonl,
            source_id: "source-a".to_string(),
            path: PathBuf::from("a.jsonl"),
        };
        let source_b = Source {
            source_id: "source-b".to_string(),
            path: PathBuf::from("b.jsonl"),
            ..source_a.clone()
        };
        let source_alias = Source {
            path: PathBuf::from("alias.jsonl"),
            ..source_a.clone()
        };
        let mut first_event = event();
        first_event.agent = Some("first-agent".to_string());
        first_event.timestamp = "2026-05-01T00:00:00Z".to_string();
        let mut later_event = event();
        later_event.agent = Some("later-agent".to_string());
        later_event.timestamp = "2026-05-02T00:00:00Z".to_string();

        let summaries = summarize_session_risk_events(
            &[
                (source_b, event()),
                (source_a.clone(), first_event),
                (source_alias, later_event),
            ],
            &[],
        )
        .expect("summary");
        assert_eq!(summaries.len(), 2);
        assert_eq!(summaries[0].0, source_a);
        assert_eq!(summaries[1].0.source_id, "source-b");
        assert_eq!(summaries[0].1.agent.as_deref(), Some("first-agent"));
        assert_eq!(summaries[0].1.timestamp, "2026-05-02T00:00:00.000Z");
        assert!(
            summaries
                .iter()
                .all(|(_, summary)| summary.risk_score == 30)
        );
        assert!(
            summaries
                .iter()
                .all(|(_, summary)| summary.risk_contributions.len() == 1)
        );
        let serialized = serde_json::to_value(&summaries[0].1).expect("serialize summary");
        assert_eq!(serialized["risk_score"], 30);
        assert_eq!(
            serialized["risk_contributions"][0]["id"],
            "baseline.synthetic"
        );
    }

    #[test]
    fn session_summary_rejects_conflicting_contribution_metadata() {
        use crate::event::{ActivityEventInput, activity_event};
        use crate::scoring::{RiskContribution, RiskContributionType};

        let source = Source {
            client: ClientId::Codex,
            kind: SourceKind::Jsonl,
            source_id: "source-conflict".to_string(),
            path: PathBuf::from("conflict.jsonl"),
        };
        let make_event = |points| {
            activity_event(ActivityEventInput {
                client: ClientId::Codex,
                agent: None,
                model: None,
                provider: None,
                session_id: "session-conflict".to_string(),
                source_path_hash: "path".to_string(),
                tool_name: None,
                tags: Vec::new(),
                evidence: Vec::new(),
                risk_contributions: vec![
                    RiskContribution::new(
                        "baseline.synthetic",
                        RiskContributionType::BaselineDeviation,
                        points,
                        "synthetic rule match",
                    )
                    .expect("contribution"),
                ],
                event_time: None,
            })
            .expect("build activity event")
        };

        let result = summarize_session_risk_events(
            &[(source.clone(), make_event(30)), (source, make_event(31))],
            &[],
        );
        assert!(matches!(
            result,
            Err(RiskAccountingError::ConflictingContribution(id)) if id == "baseline.synthetic"
        ));
    }

    #[test]
    fn operational_json_omits_hostile_sink_names() {
        let sink_name = "https://sink-owner.example.invalid/private";
        let alert = sink_failure_alert_event(&SinkFailure {
            name: sink_name.to_string(),
            kind: "splunk_hec".to_string(),
            class: crate::sink::DeliveryErrorClass::UnknownInternal,
            attempts: 1,
            error: "connection refused".to_string(),
        });
        let alert_bytes = serde_json::to_vec(&alert).expect("serialize sink alert");
        assert!(
            !String::from_utf8_lossy(&alert_bytes).contains(sink_name),
            "operational alert exposed a hostile sink name"
        );
    }

    #[test]
    fn status_json_omits_hostile_historical_health_fields() {
        let marker = "sk-abcdefgh";
        let historical_health = serde_json::json!({
            "schema_version": "2.0",
            "event_type": "health",
            "timestamp": "2026-05-01T00:00:00Z",
            "component": marker,
            "check_name": marker,
            "status": marker,
            "active_policy_name": marker,
            "source_counts": { marker: 1 },
        });
        let status = status_json(
            "historical_only",
            Some(&historical_health),
            0,
            std::path::Path::new("/tmp/telltale-events.jsonl"),
            std::path::Path::new("/tmp/telltale-state.json"),
            serde_json::json!({"mode": "not_configured", "sinks": {}}),
        );
        let status_bytes = serde_json::to_vec(&status).expect("serialize status");
        assert!(
            !String::from_utf8_lossy(&status_bytes).contains(marker),
            "status output exposed hostile historical health metadata"
        );
        assert_eq!(
            status["durable_queue_health"],
            serde_json::json!({"mode": "not_configured", "sinks": {}})
        );
    }
}
