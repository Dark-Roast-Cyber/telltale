use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::thread;
use std::time::{Duration, Instant};

use notify::{
    Config as NotifyConfig, Event as NotifyEvent, EventKind, RecommendedWatcher, RecursiveMode,
    Watcher,
};
use time::OffsetDateTime;

use crate::allowlist::{load_allowlist, suppress_detection};
use crate::baseline::{BaselineDeviationConfig, build_baseline_summaries};
use crate::detection::{detect_parsed_source_records, summarize_parsed_source_activity};
use crate::discovery::{
    discover_sources_with_projects_best_effort, discover_watch_roots_with_projects, is_fixture_root,
};
use crate::event::{
    Event, Evidence, HealthEventInput, OperationalAlertInput, SessionRiskSummaryEventInput,
    evidence_hash, health_event_with_metadata, load_operational_alert_config,
    operational_alert_event, scanner_error_event, session_risk_summary_event,
};
use crate::install_inventory::{
    collect_install_inventory, install_inventory_due, snapshot_to_event,
};
use crate::mcp::{discover_mcp_inventory, discover_mcp_usage};
use crate::parser::{ParseError, ParseOptions, parse_source_records_with_options};
use crate::rules::{
    RuleLoadMode, RulePackPaths,
    resolve_rule_set_from_pack_paths_with_mode_override_paths_and_replacements,
};
use crate::scoring::load_thresholds;
use crate::scoring::{RiskAccountingError, RiskContribution, canonicalize_contributions};
use crate::sink::{SinkFailure, SinkSet};
use crate::state::{ScanState, SqliteIngestionCursor, source_fingerprint};
use crate::triage::maybe_triage;
use telltale_schema::clients::{ClientId, SourceKind};
use telltale_schema::record::{NormalizedRecord, RecordKind};
use telltale_schema::source::Source;

const OPENCODE_SQLITE_PART_TABLE: &str = "part";
const OPENCODE_SQLITE_CURSOR_OVERLAP_MS: i64 = 10 * 60 * 1_000;
pub(crate) const DEFAULT_INSTALL_INVENTORY_INTERVAL_SECONDS: u64 = 24 * 60 * 60;

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

/// When `watch` decides to run a scan. Watch never backfills, rebuilds
/// baselines, or caps sources, so those options are absent by construction
/// rather than pinned to a default at conversion time.
#[derive(Clone, Copy)]
pub(crate) struct WatchTriggerConfig {
    pub(crate) iterations: Option<u32>,
    pub(crate) debounce: Duration,
    pub(crate) min_scan_interval: Duration,
}

/// A shared scan plus the triggering behavior only `watch` accepts.
#[derive(Clone, Copy)]
pub(crate) struct WatchConfig<'a> {
    pub(crate) execution: ScanExecutionConfig<'a>,
    pub(crate) trigger: WatchTriggerConfig,
}

fn watch_scan_config<'a>(config: &WatchConfig<'a>) -> ScanConfig<'a> {
    ScanConfig {
        execution: config.execution,
        backfill: false,
        rebuild_baselines: false,
        max_sources: None,
    }
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

const WATCH_SHUTDOWN_POLL: Duration = Duration::from_millis(200);

pub(crate) fn run_watch(config: WatchConfig<'_>) -> Result<(), Box<dyn std::error::Error>> {
    if !config.execution.dry_run
        && !config.execution.allow_fixtures
        && is_fixture_root(config.execution.root)
    {
        return Err(
            "refusing to write fixture/demo data to log path; use --dry-run or --allow-fixtures"
                .into(),
        );
    }
    let _rule_set = resolve_rule_set_from_pack_paths_with_mode_override_paths_and_replacements(
        config.execution.rule_pack_paths,
        config.execution.rule_paths,
        config.execution.policy_path,
        config.execution.rule_load_mode,
        config.execution.override_paths,
        &[],
    )?;

    // Note: structural changes to project YAML (new projects, new roots) require a process
    // restart; the notify watcher is not rebuilt at runtime.
    let project_configs = if config.execution.project_config_paths.is_empty()
        && config.execution.root == Path::new(".")
    {
        // Use default project paths only when root is the sentinel for home-relative discovery
        crate::projects::load_default_projects()
    } else {
        crate::projects::load_project_configs(config.execution.project_config_paths)
    };
    let watch_roots = discover_watch_roots_with_projects(
        config.execution.root,
        config.execution.clients,
        &project_configs,
    );
    if watch_roots.is_empty() {
        return Err(format!(
            "no existing Telltale session-store roots found under {}",
            config.execution.root.display()
        )
        .into());
    }

    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_handler = Arc::clone(&shutdown);
    ctrlc::set_handler(move || shutdown_handler.store(true, Ordering::SeqCst))?;

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

    let mut source_index = build_watch_source_index(&config, &project_configs);
    let mut remaining = config.trigger.iterations;
    let mut last_scan_completed: Option<Instant> = None;

    'watch: loop {
        // Block until the first relevant change, waking periodically to honor shutdown.
        let mut pending = PendingWatchChanges::default();
        while pending.is_empty() {
            if shutdown.load(Ordering::SeqCst) {
                break 'watch;
            }
            match rx.recv_timeout(WATCH_SHUTDOWN_POLL) {
                Ok(Ok(event)) => pending.absorb(&event),
                Ok(Err(error)) => return Err(Box::new(error)),
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => break 'watch,
            }
        }

        // Debounce window: coalesce rapid writes into one scan.
        collect_watch_events_for(&rx, &mut pending, config.trigger.debounce, &shutdown)?;
        // Rate limit: keep coalescing until the minimum scan interval has passed.
        if let Some(completed) = last_scan_completed {
            let elapsed = completed.elapsed();
            if elapsed < config.trigger.min_scan_interval {
                collect_watch_events_for(
                    &rx,
                    &mut pending,
                    config.trigger.min_scan_interval - elapsed,
                    &shutdown,
                )?;
            }
        }
        if shutdown.load(Ordering::SeqCst) {
            break;
        }

        match pending.scan_action(&source_index) {
            WatchScanAction::Skip => continue,
            WatchScanAction::Targeted(targets) => {
                run_scan(
                    watch_scan_config(&config),
                    ScanTargets::Targeted(targets),
                    StateSavePolicy::OnChange,
                )?;
            }
            WatchScanAction::Full => {
                run_scan(
                    watch_scan_config(&config),
                    ScanTargets::Full,
                    StateSavePolicy::OnChange,
                )?;
                source_index = build_watch_source_index(&config, &project_configs);
            }
        }
        last_scan_completed = Some(Instant::now());

        if let Some(value) = remaining.as_mut() {
            if *value == 1 {
                break;
            }
            *value -= 1;
        }
    }
    Ok(())
}

fn collect_watch_events_for(
    rx: &Receiver<notify::Result<NotifyEvent>>,
    pending: &mut PendingWatchChanges,
    window: Duration,
    shutdown: &AtomicBool,
) -> Result<(), Box<dyn std::error::Error>> {
    let deadline = Instant::now() + window;
    loop {
        if shutdown.load(Ordering::SeqCst) {
            return Ok(());
        }
        let now = Instant::now();
        if now >= deadline {
            return Ok(());
        }
        let timeout = (deadline - now).min(WATCH_SHUTDOWN_POLL);
        match rx.recv_timeout(timeout) {
            Ok(Ok(event)) => pending.absorb(&event),
            Ok(Err(error)) => return Err(Box::new(error)),
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return Ok(()),
        }
    }
}

enum WatchScanAction {
    /// No watched source is affected; do not scan.
    Skip,
    /// Every changed path maps to a known source; scan only those sources.
    Targeted(Vec<Source>),
    /// A path was removed or does not map to a known source; rediscover and scan everything.
    Full,
}

#[derive(Default)]
struct PendingWatchChanges {
    paths: BTreeSet<PathBuf>,
    saw_remove: bool,
}

impl PendingWatchChanges {
    fn absorb(&mut self, event: &NotifyEvent) {
        if !watch_event_should_scan(event) {
            return;
        }
        if matches!(event.kind, EventKind::Remove(_)) {
            self.saw_remove = true;
        }
        for path in &event.paths {
            if let Some(path) = normalize_watch_event_path(path) {
                self.paths.insert(path);
            }
        }
    }

    fn is_empty(&self) -> bool {
        self.paths.is_empty() && !self.saw_remove
    }

    fn scan_action(&self, source_index: &BTreeMap<PathBuf, Source>) -> WatchScanAction {
        if self.saw_remove {
            return WatchScanAction::Full;
        }
        let mut targets = Vec::new();
        let mut seen_paths = BTreeSet::new();
        for path in &self.paths {
            let lookup = path.canonicalize().unwrap_or_else(|_| path.clone());
            let Some(source) = source_index.get(&lookup) else {
                return WatchScanAction::Full;
            };
            if seen_paths.insert(source.path.clone()) {
                targets.push(source.clone());
            }
        }
        if targets.is_empty() {
            WatchScanAction::Skip
        } else {
            WatchScanAction::Targeted(targets)
        }
    }
}

/// Map SQLite WAL sidecar events onto the main database file and drop `-shm` /
/// `-journal` sidecar events, which fire on reader activity without new
/// persisted data.
fn normalize_watch_event_path(path: &Path) -> Option<PathBuf> {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return Some(path.to_path_buf());
    };
    if let Some(base) = name.strip_suffix("-wal")
        && base.ends_with(".db")
    {
        return Some(path.with_file_name(base));
    }
    for suffix in ["-shm", "-journal"] {
        if let Some(base) = name.strip_suffix(suffix)
            && base.ends_with(".db")
        {
            return None;
        }
    }
    Some(path.to_path_buf())
}

/// Index discovered sources by canonical path so notify event paths can be
/// mapped back to the source that changed. Mirrors the discovery filtering
/// applied by full scans.
fn build_watch_source_index(
    config: &WatchConfig<'_>,
    project_configs: &[crate::projects::ProjectDef],
) -> BTreeMap<PathBuf, Source> {
    let mut sources =
        discover_sources_with_projects_best_effort(config.execution.root, project_configs);
    if !config.execution.clients.is_empty() {
        let allowed_clients = config
            .execution
            .clients
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        sources.retain(|source| allowed_clients.contains(&source.client));
    }
    if !is_fixture_root(config.execution.root) {
        prefer_opencode_sqlite_over_legacy_json(&mut sources);
    }
    sources
        .into_iter()
        .map(|source| {
            let key = source
                .path
                .canonicalize()
                .unwrap_or_else(|_| source.path.clone());
            (key, source)
        })
        .collect()
}

fn watch_event_should_scan(event: &NotifyEvent) -> bool {
    matches!(
        event.kind,
        EventKind::Create(_) | EventKind::Modify(_) | EventKind::Remove(_)
    )
}

/// Which sources a scan should parse and detect against.
pub(crate) enum ScanTargets {
    /// Discover and scan every source under the configured root.
    Full,
    /// Scan only the given pre-discovered sources (watch-mode targeted scan).
    Targeted(Vec<Source>),
}

/// When to persist scanner state after a scan.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum StateSavePolicy {
    /// Save on every scan (batch mode behavior).
    Always,
    /// Save only when the scan emitted events or advanced durable state
    /// (fingerprints, SQLite cursors, source inventory). Watch mode uses this
    /// to avoid rewriting the state file on every no-op scan.
    OnChange,
}

pub(crate) fn run_scan_once(config: ScanConfig<'_>) -> Result<(), Box<dyn std::error::Error>> {
    run_scan(config, ScanTargets::Full, StateSavePolicy::Always)
}

fn run_scan(
    config: ScanConfig<'_>,
    targets: ScanTargets,
    save_policy: StateSavePolicy,
) -> Result<(), Box<dyn std::error::Error>> {
    let scan_started = Instant::now();
    let fixture_root = is_fixture_root(config.execution.root);
    if !config.execution.dry_run && !config.execution.allow_fixtures && fixture_root {
        return Err(
            "refusing to write fixture/demo data to log path; use --dry-run or --allow-fixtures"
                .into(),
        );
    }
    let (mut sources, targeted) = match targets {
        ScanTargets::Targeted(sources) => (sources, true),
        ScanTargets::Full => {
            let project_configs = if config.execution.project_config_paths.is_empty()
                && config.execution.root == Path::new(".")
            {
                // Use default project paths only when root is the sentinel for home-relative discovery
                crate::projects::load_default_projects()
            } else {
                crate::projects::load_project_configs(config.execution.project_config_paths)
            };
            let mut sources =
                discover_sources_with_projects_best_effort(config.execution.root, &project_configs);
            if !config.execution.clients.is_empty() {
                let allowed_clients = config
                    .execution
                    .clients
                    .iter()
                    .copied()
                    .collect::<BTreeSet<_>>();
                sources.retain(|source| allowed_clients.contains(&source.client));
            }
            if !fixture_root {
                prefer_opencode_sqlite_over_legacy_json(&mut sources);
            }
            (sources, false)
        }
    };
    if let Some(max_sources) = config.max_sources {
        sources.truncate(max_sources);
    }
    let resolution = resolve_rule_set_from_pack_paths_with_mode_override_paths_and_replacements(
        config.execution.rule_pack_paths,
        config.execution.rule_paths,
        config.execution.policy_path,
        config.execution.rule_load_mode,
        config.execution.override_paths,
        &[],
    )?;
    let diagnostics = super::rule_diagnostics_value(&resolution.diagnostics);
    let rule_set = resolution.rule_set;
    let mut effective_configuration = config.execution.effective_configuration.clone();
    effective_configuration["rules"] = {
        let mut rules = effective_configuration["rules"].clone();
        rules["sources"] = diagnostics["sources"].clone();
        rules["provenance"] = diagnostics["provenance"].clone();
        rules
    };
    let rule_count = rule_set.rule_count();
    let active_policy_name = rule_set.policy_name().map(str::to_string);
    let policy_active = config.execution.policy_path.is_some();
    let allowlist = load_allowlist(config.execution.allowlist_path)?;
    let mut state = ScanState::load(config.execution.state_path)?;
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
        install_inventory_event = Some((snapshot_to_event(&snapshot), snapshot));
    }
    let activities = if config.execution.emit_activity {
        let baseline_deviation_config = BaselineDeviationConfig {
            enabled: config.execution.baseline_deviation_scoring,
            ..BaselineDeviationConfig::default()
        };
        let mut activities = parsed_sources
            .iter()
            .filter_map(|parsed_source| {
                parsed_source
                    .records
                    .as_ref()
                    .ok()
                    .map(|records| (parsed_source, records))
            })
            .flat_map(|(parsed_source, records)| {
                summarize_parsed_source_activity(
                    &parsed_source.source,
                    records,
                    &baseline_snapshots,
                    baseline_deviation_config,
                )
                .into_iter()
                .map(|event| (parsed_source.source.clone(), event))
            })
            .collect::<Vec<_>>();
        // MCP discovery walks host-wide config directories; targeted scans only
        // re-examine changed session sources, so leave it to full scans.
        if !targeted {
            activities.extend(discover_mcp_inventory(config.execution.root));
            activities.extend(discover_mcp_usage(config.execution.root, &sources));
        }
        activities
    } else {
        Vec::new()
    };
    let mut detections = parsed_sources
        .iter()
        .flat_map(|parsed_source| match &parsed_source.records {
            Ok(records) => detect_parsed_source_records(&parsed_source.source, &rule_set, records)
                .into_iter()
                .map(|event| (parsed_source.source.clone(), event))
                .collect::<Vec<_>>(),
            Err(ParseError::Empty) => Vec::new(),
            Err(error) => vec![(
                parsed_source.source.clone(),
                scanner_error_event(&parsed_source.source, error),
            )],
        })
        .collect::<Vec<_>>();
    let mut detection_flow = detection_flow_accounting(&detections);
    let mut suppressed_count = 0_usize;
    for (source, detection) in &mut detections {
        let is_detection = detection.event_type == "detection";
        if let Some(suppression_match) = allowlist.suppression_for(source, detection) {
            suppress_detection(detection, &suppression_match);
            suppressed_count += 1;
            if is_detection {
                detection_flow.allowlist_marked_detection_count += 1;
            }
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

    // Operational alerting: emit alerts when scanner health thresholds are exceeded.
    let op_config = load_operational_alert_config();
    let scanner_error_count = detections
        .iter()
        .filter(|(_, event)| event.event_type == "scanner_error")
        .count() as u64;
    let mut operational_alerts = Vec::new();
    if scanner_error_count > u64::from(op_config.max_scanner_errors) {
        operational_alerts.push(operational_alert_event(OperationalAlertInput {
            alert_type: "scanner_error_threshold_exceeded".to_string(),
            threshold: format!("max_scanner_errors={}", op_config.max_scanner_errors),
            actual_value: format!("scanner_error_count={scanner_error_count}"),
            scan_duration_ms: Some(scan_duration_ms),
            scanner_error_count: Some(scanner_error_count as u32),
        }));
    }
    if scan_duration_ms > op_config.max_scan_duration_ms {
        operational_alerts.push(operational_alert_event(OperationalAlertInput {
            alert_type: "scan_duration_threshold_exceeded".to_string(),
            threshold: format!("max_scan_duration_ms={}", op_config.max_scan_duration_ms),
            actual_value: format!("scan_duration_ms={scan_duration_ms}"),
            scan_duration_ms: Some(scan_duration_ms),
            scanner_error_count: Some(scanner_error_count as u32),
        }));
    }
    let has_operational_alerts = !operational_alerts.is_empty();

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
    for (source, activity) in activities {
        if config.backfill || state.should_emit(&source, &activity) {
            emitted_events.push(activity);
        }
    }
    let mut scanner_error_emitted = false;
    for (source, detection) in detections {
        let is_detection = detection.event_type == "detection";
        let should_emit = config.backfill || state.should_emit(&source, &detection);
        if is_detection {
            if should_emit {
                detection_flow.emitted_detection_count += 1;
            } else {
                detection_flow.state_deduplicated_detection_count += 1;
            }
        }
        if should_emit {
            scanner_error_emitted |= detection.event_type == "scanner_error";
            emitted_events.push(detection);
        }
    }
    for (source, summary) in session_risk_summaries {
        if config.backfill || state.should_emit(&source, &summary) {
            emitted_events.push(summary);
        }
    }

    let health_emitted = config.execution.dry_run
        || config.backfill
        || inventory_health_change
        || scanner_error_emitted
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
    if !config.execution.dry_run && !config.backfill {
        observe_sqlite_ingestion_cursors(&mut state, &parsed_sources, observed_at_unix_ms);
    }

    let mut sink_failures: Vec<SinkFailure> = Vec::new();
    let delivery_posture = config.execution.sinks.delivery_posture();
    if !config.execution.dry_run {
        sink_failures = config.execution.sinks.deliver(&emitted_events)?;
        if !sink_failures.is_empty() {
            if config.execution.sinks.has_durable() {
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
            config
                .execution
                .sinks
                .deliver_alerts(&alerts, &failed_names);
        }
        let should_save = match &state_probe {
            None => true,
            Some(probe) => !emitted_events.is_empty() || probe.changed(&state),
        };
        if should_save {
            state.save(config.execution.state_path)?;
        }
    }

    let summary = scan_summary_json(ScanSummaryInput {
        health_event: &health,
        emitted_events: &emitted_events,
        health_emitted,
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
        policy_active,
        runtime: config.execution.runtime,
        effective_configuration: &effective_configuration,
    });
    println!("{}", serde_json::to_string(&summary)?);
    Ok(())
}

/// Truncation cap for delivery error text embedded in alert evidence.
const SINK_FAILURE_ERROR_MAX_CHARS: usize = 500;

fn sink_failure_alert_event(failure: &SinkFailure) -> Event {
    let mut error = failure.error.clone();
    if error.chars().count() > SINK_FAILURE_ERROR_MAX_CHARS {
        error = error.chars().take(SINK_FAILURE_ERROR_MAX_CHARS).collect();
        error.push('…');
    }
    operational_alert_event(OperationalAlertInput {
        alert_type: "sink_delivery_failure".to_string(),
        threshold: format!("attempts_made={}", failure.attempts),
        actual_value: format!(
            "sink={} type={} error={}",
            failure.name, failure.kind, error
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
    observed_at_unix_ms: u64,
) {
    for parsed_source in parsed_sources {
        if !is_opencode_sqlite_source(&parsed_source.source) || parsed_source.records.is_err() {
            continue;
        }
        if let Some(last_time_updated) = parsed_source.sqlite_part_max_time_updated {
            state.observe_sqlite_ingestion_cursor(
                &parsed_source.source,
                OPENCODE_SQLITE_PART_TABLE,
                last_time_updated,
                observed_at_unix_ms,
            );
        }
    }
}

fn is_opencode_sqlite_source(source: &Source) -> bool {
    source.client == ClientId::OpenCode && source.kind == SourceKind::Sqlite
}

fn prefer_opencode_sqlite_over_legacy_json(sources: &mut Vec<Source>) {
    let has_opencode_sqlite = sources.iter().any(is_opencode_sqlite_source);
    if !has_opencode_sqlite {
        return;
    }
    sources.retain(|source| {
        !(source.client == ClientId::OpenCode
            && source.kind == SourceKind::LegacyJson
            && source.source_id == "opencode.legacy_json")
    });
}

#[derive(Debug)]
struct SessionRiskSummaryAccumulator {
    source: Source,
    client: String,
    agent: Option<String>,
    model: Option<String>,
    provider: Option<String>,
    session_id: String,
    source_path_hash: Option<String>,
    contributions:
        BTreeMap<(telltale_schema::scoring::RiskContributionType, String), RiskContribution>,
    event_time: Option<String>,
    event_counts: BTreeMap<String, u32>,
    tool_call_count: Option<u64>,
    detection_count: u32,
    triage_ran: bool,
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
    let mut summaries: BTreeMap<(String, String, String), SessionRiskSummaryAccumulator> =
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
            event.client.clone(),
            source.source_id.clone(),
            event.session_id.clone(),
        );
        let summary = summaries
            .entry(key)
            .or_insert_with(|| SessionRiskSummaryAccumulator {
                source: source.clone(),
                client: event.client.clone(),
                agent: event.agent.clone(),
                model: event.model.clone(),
                provider: event.provider.clone(),
                session_id: event.session_id.clone(),
                source_path_hash: event.source_path_hash.clone(),
                contributions: BTreeMap::new(),
                event_time: None,
                event_counts: BTreeMap::new(),
                tool_call_count: None,
                detection_count: 0,
                triage_ran: false,
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
            summary.triage_ran |= triage_ran_from_typed_event(event);
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
                client: summary.client,
                agent: summary.agent,
                model: summary.model,
                provider: summary.provider,
                session_id: summary.session_id,
                source_path_hash: summary.source_path_hash,
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

fn triage_ran_from_typed_event(event: &Event) -> bool {
    event
        .triage
        .as_ref()
        .and_then(|value| value.get("verdict"))
        .and_then(|value| value.as_str())
        .is_some_and(|verdict| !matches!(verdict, "pending" | "not_required" | "config_missing"))
}

fn session_risk_summary_tags(summary: &SessionRiskSummaryAccumulator) -> Vec<String> {
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

fn session_risk_summary_evidence(summary: &SessionRiskSummaryAccumulator) -> Vec<Evidence> {
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
    evidence.push(Evidence {
        field: "triage_ran".to_string(),
        redacted_value: summary.triage_ran.to_string(),
        hash: None,
        rule_id: None,
    });
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
) -> Result<(), Box<dyn std::error::Error>> {
    let events = super::read_jsonl_events(log_path)?;
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

struct ScanSummaryInput<'a> {
    health_event: &'a Event,
    emitted_events: &'a [Event],
    health_emitted: bool,
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
    policy_active: bool,
    runtime: &'a serde_json::Value,
    effective_configuration: &'a serde_json::Value,
}

struct DetectionFlowAccounting {
    effective_detection_candidate_count: usize,
    matched_rule_id_count: usize,
    allowlist_marked_detection_count: usize,
    state_deduplicated_detection_count: usize,
    emitted_detection_count: usize,
}

fn detection_flow_accounting(detections: &[(Source, Event)]) -> DetectionFlowAccounting {
    let mut accounting = DetectionFlowAccounting {
        effective_detection_candidate_count: 0,
        matched_rule_id_count: 0,
        allowlist_marked_detection_count: 0,
        state_deduplicated_detection_count: 0,
        emitted_detection_count: 0,
    };
    for (_, event) in detections {
        if event.event_type == "detection" {
            accounting.effective_detection_candidate_count += 1;
            accounting.matched_rule_id_count += event.rule_ids.len();
        }
    }
    accounting
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
    fn json(&self, policy_active: bool) -> serde_json::Value {
        let policy_match_accounting = if policy_active {
            serde_json::json!({
                "status": "unavailable_effective_rules_only",
                "pre_policy_detection_candidate_count": null,
                "fully_filtered_detection_candidate_count": null,
                "filtered_rule_id_count": null,
            })
        } else {
            serde_json::json!({
                "status": "not_applicable",
                "pre_policy_detection_candidate_count": null,
                "fully_filtered_detection_candidate_count": null,
                "filtered_rule_id_count": null,
            })
        };
        serde_json::json!({
            "effective_detection_candidate_count": self.effective_detection_candidate_count,
            "matched_rule_id_count": self.matched_rule_id_count,
            "allowlist_marked_detection_count": self.allowlist_marked_detection_count,
            "state_deduplicated_detection_count": self.state_deduplicated_detection_count,
            "emitted_detection_count": self.emitted_detection_count,
            "policy_match_accounting": policy_match_accounting,
        })
    }
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
                "name": failure.name,
                "type": failure.kind,
                "attempts": failure.attempts,
                "error": failure.error,
            })
        })
        .collect();
    serde_json::json!({
        "client": summary.health_event.client,
        "event_type": summary.health_event.event_type,
        "activity_count": summary.activity_count,
        "detection_count": summary.detection_count,
        "session_risk_summary_count": summary.session_risk_summary_count,
        "suppressed_count": summary.suppressed_count,
        "emitted_count": summary.emitted_events.len().saturating_sub(usize::from(summary.health_emitted)),
        "rule_count": summary.rule_count,
        "policy": summary.active_policy_name,
        "log_path": if summary.dry_run { None } else { Some(summary.log_path.display().to_string()) },
        "delivery": {
            "posture": summary.delivery_posture.as_str(),
            "status": delivery_status,
            "durable_first_write": summary.delivery_posture.has_durable_first_write(),
            "built_in_persistent_replay": false,
        },
        "source_counts": summary.health_event.source_counts.clone().unwrap_or_default(),
        "sink_failures": sink_failures,
        "source_processing": summary.source_processing.json(),
        "detection_flow": summary.detection_flow.json(summary.policy_active),
        "runtime": summary.runtime,
        "effective_configuration": summary.effective_configuration,
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
        "health_component": json_field_or_null(health, "component"),
        "health_check_name": json_field_or_null(health, "check_name"),
        "health_check_status": json_field_or_null(health, "status"),
        "active_policy_name": json_field_or_null(health, "active_policy_name"),
        "rule_count": json_field_or_null(health, "rule_count"),
        "detection_count": detection_count,
        "threshold_config": json_field_or_null(health, "threshold_config"),
        "source_counts": json_field_or_empty_object(health, "source_counts"),
        "emitted_count": json_field_or_null(health, "emitted_count"),
        "suppressed_count": json_field_or_null(health, "suppressed_count"),
        "scanner_error_count": json_field_or_null(health, "scanner_error_count"),
    })
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

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;
    use crate::install_inventory::InstallInventorySnapshot;

    fn assert_same_execution_config(
        left: &ScanExecutionConfig<'_>,
        right: &ScanExecutionConfig<'_>,
    ) {
        assert!(std::ptr::eq(left.root, right.root), "root");
        assert!(std::ptr::eq(left.log_path, right.log_path), "log_path");
        assert!(std::ptr::eq(left.sinks, right.sinks), "sinks");
        assert!(
            std::ptr::eq(left.state_path, right.state_path),
            "state_path"
        );
        assert_eq!(left.dry_run, right.dry_run, "dry_run");
        assert_eq!(left.emit_activity, right.emit_activity, "emit_activity");
        assert_eq!(
            left.emit_session_risk_summary, right.emit_session_risk_summary,
            "emit_session_risk_summary"
        );
        assert_eq!(left.allow_fixtures, right.allow_fixtures, "allow_fixtures");
        assert!(
            std::ptr::eq(left.rule_pack_paths, right.rule_pack_paths),
            "rule_pack_paths"
        );
        assert_eq!(left.rule_paths, right.rule_paths, "rule_paths");
        assert_eq!(left.override_paths, right.override_paths, "override_paths");
        assert_eq!(left.rule_load_mode, right.rule_load_mode, "rule_load_mode");
        assert_eq!(left.policy_path, right.policy_path, "policy_path");
        assert_eq!(left.allowlist_path, right.allowlist_path, "allowlist_path");
        assert_eq!(
            left.baseline_deviation_scoring, right.baseline_deviation_scoring,
            "baseline_deviation_scoring"
        );
        assert_eq!(left.clients, right.clients, "clients");
        assert_eq!(
            left.project_config_paths, right.project_config_paths,
            "project_config_paths"
        );
        assert_eq!(
            left.install_inventory_interval_seconds, right.install_inventory_interval_seconds,
            "install_inventory_interval_seconds"
        );
        assert!(std::ptr::eq(left.runtime, right.runtime), "runtime");
        assert!(
            std::ptr::eq(left.effective_configuration, right.effective_configuration),
            "effective_configuration"
        );
    }

    /// Equivalent options must resolve identically whether they arrive through
    /// `scan` or through `watch`. Watch runs the same scan, so the only
    /// permitted differences are the scan-only options watch does not accept.
    #[test]
    fn scan_and_watch_resolve_equivalent_options_identically() {
        let root = PathBuf::from("/tmp/telltale-root");
        let log_path = PathBuf::from("/tmp/telltale.jsonl");
        let state_path = PathBuf::from("/tmp/telltale-state.json");
        let policy_path = PathBuf::from("/tmp/policy.yaml");
        let allowlist_path = PathBuf::from("/tmp/allowlist.yaml");
        let sinks = SinkSet::default();
        let rule_pack_paths = RulePackPaths::default();
        let rule_paths = vec![PathBuf::from("/tmp/rules.yaml")];
        let override_paths = vec![PathBuf::from("/tmp/overrides.d")];
        let clients = vec![ClientId::Claude, ClientId::OpenCode];
        let project_config_paths = vec![PathBuf::from("/tmp/projects.yaml")];
        let runtime = serde_json::json!({});
        let effective_configuration = serde_json::json!({});

        let execution = ScanExecutionConfig {
            root: &root,
            log_path: &log_path,
            sinks: &sinks,
            state_path: &state_path,
            dry_run: true,
            emit_activity: true,
            emit_session_risk_summary: true,
            allow_fixtures: true,
            rule_pack_paths: &rule_pack_paths,
            rule_paths: &rule_paths,
            override_paths: &override_paths,
            rule_load_mode: RuleLoadMode::IncludeDefault,
            policy_path: Some(&policy_path),
            allowlist_path: Some(&allowlist_path),
            baseline_deviation_scoring: true,
            clients: &clients,
            project_config_paths: &project_config_paths,
            install_inventory_interval_seconds: Some(3_600),
            runtime: &runtime,
            effective_configuration: &effective_configuration,
        };

        let scan = ScanConfig {
            execution,
            backfill: false,
            rebuild_baselines: false,
            max_sources: None,
        };
        let watch = WatchConfig {
            execution,
            trigger: WatchTriggerConfig {
                iterations: Some(3),
                debounce: Duration::from_millis(250),
                min_scan_interval: Duration::from_millis(1_000),
            },
        };

        let watch_derived_scan = watch_scan_config(&watch);

        assert_same_execution_config(&scan.execution, &watch_derived_scan.execution);
        assert_same_execution_config(&watch.execution, &watch_derived_scan.execution);

        // Watch never backfills, rebuilds baselines, or caps sources.
        assert!(!watch_derived_scan.backfill);
        assert!(!watch_derived_scan.rebuild_baselines);
        assert_eq!(watch_derived_scan.max_sources, None);
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
        observe_sqlite_ingestion_cursors(&mut state, &parsed, 2_000);

        assert_eq!(
            state.sqlite_ingestion_cursor_time_updated(&source, OPENCODE_SQLITE_PART_TABLE),
            Some(5_000)
        );
    }

    #[test]
    fn normalize_watch_event_path_handles_sqlite_sidecars() {
        let wal = Path::new("/data/opencode/opencode.db-wal");
        assert_eq!(
            normalize_watch_event_path(wal),
            Some(PathBuf::from("/data/opencode/opencode.db"))
        );

        assert_eq!(
            normalize_watch_event_path(Path::new("/data/opencode/opencode.db-shm")),
            None
        );
        assert_eq!(
            normalize_watch_event_path(Path::new("/data/opencode/opencode.db-journal")),
            None
        );

        let jsonl = Path::new("/home/user/.codex/sessions/session-a.jsonl");
        assert_eq!(normalize_watch_event_path(jsonl), Some(jsonl.to_path_buf()));

        // Non-SQLite names that merely end in a sidecar-like suffix are kept.
        let lookalike = Path::new("/home/user/.codex/sessions/notes-wal");
        assert_eq!(
            normalize_watch_event_path(lookalike),
            Some(lookalike.to_path_buf())
        );
    }

    fn watch_test_source(path: &str) -> Source {
        Source {
            client: ClientId::Codex,
            kind: SourceKind::Jsonl,
            source_id: "codex.sessions".to_string(),
            path: PathBuf::from(path),
        }
    }

    #[test]
    fn pending_changes_map_known_paths_to_targeted_scan() {
        let source = watch_test_source("/watch-test/codex/sessions/session-a.jsonl");
        let index = BTreeMap::from([(source.path.clone(), source.clone())]);

        let mut pending = PendingWatchChanges::default();
        pending
            .paths
            .insert(PathBuf::from("/watch-test/codex/sessions/session-a.jsonl"));

        match pending.scan_action(&index) {
            WatchScanAction::Targeted(targets) => assert_eq!(targets, vec![source]),
            _ => panic!("expected targeted scan"),
        }
    }

    #[test]
    fn pending_changes_dedupe_sqlite_db_and_wal_to_one_target() {
        let db_source = Source {
            client: ClientId::OpenCode,
            kind: SourceKind::Sqlite,
            source_id: "opencode.sqlite".to_string(),
            path: PathBuf::from("/watch-test/opencode/opencode.db"),
        };
        let index = BTreeMap::from([(db_source.path.clone(), db_source.clone())]);

        let mut pending = PendingWatchChanges::default();
        let event = NotifyEvent {
            kind: EventKind::Modify(notify::event::ModifyKind::Any),
            paths: vec![
                PathBuf::from("/watch-test/opencode/opencode.db"),
                PathBuf::from("/watch-test/opencode/opencode.db-wal"),
                PathBuf::from("/watch-test/opencode/opencode.db-shm"),
            ],
            attrs: Default::default(),
        };
        pending.absorb(&event);

        match pending.scan_action(&index) {
            WatchScanAction::Targeted(targets) => assert_eq!(targets, vec![db_source]),
            _ => panic!("expected targeted scan"),
        }
    }

    #[test]
    fn pending_changes_fall_back_to_full_scan_for_unknown_paths_and_removes() {
        let source = watch_test_source("/watch-test/codex/sessions/session-a.jsonl");
        let index = BTreeMap::from([(source.path.clone(), source)]);

        let mut unknown = PendingWatchChanges::default();
        unknown
            .paths
            .insert(PathBuf::from("/watch-test/codex/sessions/new-file.jsonl"));
        assert!(matches!(unknown.scan_action(&index), WatchScanAction::Full));

        let removed = PendingWatchChanges {
            saw_remove: true,
            ..Default::default()
        };
        assert!(matches!(removed.scan_action(&index), WatchScanAction::Full));

        let idle = PendingWatchChanges::default();
        assert!(matches!(idle.scan_action(&index), WatchScanAction::Skip));
    }

    #[test]
    fn pending_changes_ignore_access_events_and_sidecar_only_writes() {
        let mut pending = PendingWatchChanges::default();
        pending.absorb(&NotifyEvent {
            kind: EventKind::Access(notify::event::AccessKind::Any),
            paths: vec![PathBuf::from("/watch-test/codex/sessions/session-a.jsonl")],
            attrs: Default::default(),
        });
        pending.absorb(&NotifyEvent {
            kind: EventKind::Modify(notify::event::ModifyKind::Any),
            paths: vec![PathBuf::from("/watch-test/opencode/opencode.db-shm")],
            attrs: Default::default(),
        });
        assert!(pending.is_empty());
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
        let new_source = watch_test_source("/watch-test/codex/sessions/session-b.jsonl");
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

    #[test]
    fn collect_watch_events_coalesces_within_min_interval() {
        // Pre-queue two modify events for the same source path, then drop the
        // sender so the channel disconnects. `collect_watch_events_for`
        // absorbs both into `pending` and returns on disconnect. Because both
        // events map to the same normalized path, `pending.paths` holds
        // exactly one entry — proving rapid events within the coalescing
        // window are merged into a single targeted scan rather than two.
        let (tx, rx) = mpsc::channel();
        let mut pending = PendingWatchChanges::default();
        let shutdown = AtomicBool::new(false);

        let event = NotifyEvent {
            kind: EventKind::Modify(notify::event::ModifyKind::Any),
            paths: vec![PathBuf::from("/watch-test/codex/sessions/session-a.jsonl")],
            attrs: Default::default(),
        };
        tx.send(Ok(event.clone())).expect("send first event");
        tx.send(Ok(event)).expect("send second event");
        drop(tx);

        collect_watch_events_for(&rx, &mut pending, Duration::from_secs(5), &shutdown)
            .expect("collect should succeed");

        assert_eq!(pending.paths.len(), 1);
        assert!(
            pending
                .paths
                .contains(Path::new("/watch-test/codex/sessions/session-a.jsonl"))
        );
        assert!(!pending.saw_remove);
    }

    #[test]
    fn prefers_opencode_sqlite_over_host_legacy_json() {
        let data_root = PathBuf::from("home")
            .join("user")
            .join(".local")
            .join("share");
        let sqlite = Source {
            client: ClientId::OpenCode,
            kind: SourceKind::Sqlite,
            source_id: "opencode.sqlite".to_string(),
            path: data_root.join("opencode").join("opencode.db"),
        };
        let legacy = Source {
            client: ClientId::OpenCode,
            kind: SourceKind::LegacyJson,
            source_id: "opencode.legacy_json".to_string(),
            path: data_root
                .join("opencode")
                .join("storage")
                .join("message")
                .join("session")
                .join("message.json"),
        };
        let codex = Source {
            client: ClientId::Codex,
            kind: SourceKind::Jsonl,
            source_id: "codex.sessions".to_string(),
            path: PathBuf::from("home")
                .join("user")
                .join(".codex")
                .join("sessions")
                .join("session.jsonl"),
        };
        let mut sources = vec![legacy.clone(), sqlite.clone(), codex.clone()];

        prefer_opencode_sqlite_over_legacy_json(&mut sources);

        assert_eq!(sources, vec![sqlite, codex]);
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

        let summaries = summarize_session_risk_events(
            &[
                (source_a.clone(), event()),
                (source_alias, event()),
                (source_b, event()),
            ],
            &[],
        )
        .expect("summary");
        assert_eq!(summaries.len(), 2);
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
}
