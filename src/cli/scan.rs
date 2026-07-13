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
use crate::clients::{ClientId, SourceKind};
use crate::detection::{detect_parsed_source_records, summarize_parsed_source_activity};
use crate::discovery::{
    Source, discover_sources_with_projects, discover_watch_roots_with_projects, is_fixture_root,
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
use crate::parser::{
    NormalizedRecord, ParseError, ParseOptions, parse_source_records_with_options,
};
use crate::rules::{RuleLoadMode, load_rule_set_from_paths_with_mode_and_override_paths};
use crate::scoring::load_thresholds;
use crate::sink::{
    LocalJsonlSink, RotationConfig, SplunkHecConfig, SplunkHecHttpSink, emit_events,
};
use crate::state::{ScanState, SqliteIngestionCursor, source_fingerprint};
use crate::triage::maybe_triage;

const OPENCODE_SQLITE_PART_TABLE: &str = "part";
const OPENCODE_SQLITE_CURSOR_OVERLAP_MS: i64 = 10 * 60 * 1_000;
pub(crate) const DEFAULT_INSTALL_INVENTORY_INTERVAL_SECONDS: u64 = 24 * 60 * 60;

pub(crate) struct ScanConfig<'a> {
    pub(crate) root: &'a Path,
    pub(crate) log_path: &'a Path,
    pub(crate) splunk_hec_endpoint: Option<&'a str>,
    pub(crate) splunk_hec_token: Option<&'a str>,
    pub(crate) state_path: &'a Path,
    pub(crate) rotation: RotationConfig,
    pub(crate) dry_run: bool,
    pub(crate) emit_activity: bool,
    pub(crate) emit_session_risk_summary: bool,
    pub(crate) allow_fixtures: bool,
    pub(crate) backfill: bool,
    pub(crate) rebuild_baselines: bool,
    pub(crate) rule_paths: &'a [PathBuf],
    pub(crate) override_paths: &'a [PathBuf],
    pub(crate) rule_load_mode: RuleLoadMode,
    pub(crate) policy_path: Option<&'a Path>,
    pub(crate) allowlist_path: Option<&'a Path>,
    pub(crate) baseline_deviation_scoring: bool,
    pub(crate) clients: &'a [ClientId],
    pub(crate) max_sources: Option<usize>,
    pub(crate) project_config_paths: &'a [PathBuf],
    pub(crate) install_inventory_interval_seconds: Option<u64>,
}

pub(crate) struct ScanCommandArgs<'a> {
    pub(crate) root: &'a Path,
    pub(crate) log_path: &'a Path,
    pub(crate) splunk_hec_endpoint: Option<&'a str>,
    pub(crate) splunk_hec_token: Option<&'a str>,
    pub(crate) state_path: &'a Path,
    pub(crate) rotation: RotationConfig,
    pub(crate) dry_run: bool,
    pub(crate) emit_activity: bool,
    pub(crate) emit_session_risk_summary: bool,
    pub(crate) allow_fixtures: bool,
    pub(crate) backfill: bool,
    pub(crate) rebuild_baselines: bool,
    pub(crate) rule_paths: &'a [PathBuf],
    pub(crate) override_paths: &'a [PathBuf],
    pub(crate) rule_load_mode: RuleLoadMode,
    pub(crate) policy_path: Option<&'a Path>,
    pub(crate) allowlist_path: Option<&'a Path>,
    pub(crate) baseline_deviation_scoring: bool,
    pub(crate) clients: &'a [ClientId],
    pub(crate) max_sources: Option<usize>,
    pub(crate) project_config_paths: &'a [PathBuf],
    pub(crate) install_inventory_interval_seconds: Option<u64>,
}

pub(crate) struct WatchConfig<'a> {
    pub(crate) root: &'a Path,
    pub(crate) log_path: &'a Path,
    pub(crate) state_path: &'a Path,
    pub(crate) rotation: RotationConfig,
    pub(crate) dry_run: bool,
    pub(crate) emit_activity: bool,
    pub(crate) emit_session_risk_summary: bool,
    pub(crate) allow_fixtures: bool,
    pub(crate) iterations: Option<u32>,
    pub(crate) debounce: Duration,
    pub(crate) min_scan_interval: Duration,
    pub(crate) rule_paths: &'a [PathBuf],
    pub(crate) override_paths: &'a [PathBuf],
    pub(crate) rule_load_mode: RuleLoadMode,
    pub(crate) policy_path: Option<&'a Path>,
    pub(crate) allowlist_path: Option<&'a Path>,
    pub(crate) baseline_deviation_scoring: bool,
    pub(crate) clients: &'a [ClientId],
    pub(crate) project_config_paths: &'a [PathBuf],
    pub(crate) install_inventory_interval_seconds: Option<u64>,
}

pub(crate) struct WatchCommandArgs<'a> {
    pub(crate) root: &'a Path,
    pub(crate) log_path: &'a Path,
    pub(crate) state_path: &'a Path,
    pub(crate) rotation: RotationConfig,
    pub(crate) dry_run: bool,
    pub(crate) emit_activity: bool,
    pub(crate) emit_session_risk_summary: bool,
    pub(crate) allow_fixtures: bool,
    pub(crate) iterations: Option<u32>,
    pub(crate) debounce: Duration,
    pub(crate) min_scan_interval: Duration,
    pub(crate) rule_paths: &'a [PathBuf],
    pub(crate) override_paths: &'a [PathBuf],
    pub(crate) rule_load_mode: RuleLoadMode,
    pub(crate) policy_path: Option<&'a Path>,
    pub(crate) allowlist_path: Option<&'a Path>,
    pub(crate) baseline_deviation_scoring: bool,
    pub(crate) clients: &'a [ClientId],
    pub(crate) project_config_paths: &'a [PathBuf],
    pub(crate) install_inventory_interval_seconds: Option<u64>,
}

pub(crate) fn scan_config<'a>(args: &'a ScanCommandArgs<'a>) -> ScanConfig<'a> {
    ScanConfig {
        root: args.root,
        log_path: args.log_path,
        splunk_hec_endpoint: args.splunk_hec_endpoint,
        splunk_hec_token: args.splunk_hec_token,
        state_path: args.state_path,
        rotation: args.rotation.clone(),
        dry_run: args.dry_run,
        emit_activity: args.emit_activity,
        emit_session_risk_summary: args.emit_session_risk_summary,
        allow_fixtures: args.allow_fixtures,
        backfill: args.backfill,
        rebuild_baselines: args.rebuild_baselines,
        rule_paths: args.rule_paths,
        override_paths: args.override_paths,
        rule_load_mode: args.rule_load_mode,
        policy_path: args.policy_path,
        allowlist_path: args.allowlist_path,
        baseline_deviation_scoring: args.baseline_deviation_scoring,
        clients: args.clients,
        max_sources: args.max_sources,
        project_config_paths: args.project_config_paths,
        install_inventory_interval_seconds: args.install_inventory_interval_seconds,
    }
}

pub(crate) fn watch_config<'a>(args: &'a WatchCommandArgs<'a>) -> WatchConfig<'a> {
    WatchConfig {
        root: args.root,
        log_path: args.log_path,
        state_path: args.state_path,
        rotation: args.rotation.clone(),
        dry_run: args.dry_run,
        emit_activity: args.emit_activity,
        emit_session_risk_summary: args.emit_session_risk_summary,
        allow_fixtures: args.allow_fixtures,
        iterations: args.iterations,
        debounce: args.debounce,
        min_scan_interval: args.min_scan_interval,
        rule_paths: args.rule_paths,
        override_paths: args.override_paths,
        rule_load_mode: args.rule_load_mode,
        policy_path: args.policy_path,
        allowlist_path: args.allowlist_path,
        baseline_deviation_scoring: args.baseline_deviation_scoring,
        clients: args.clients,
        project_config_paths: args.project_config_paths,
        install_inventory_interval_seconds: args.install_inventory_interval_seconds,
    }
}

fn watch_scan_config<'a>(config: &'a WatchConfig<'a>) -> ScanConfig<'a> {
    ScanConfig {
        root: config.root,
        log_path: config.log_path,
        splunk_hec_endpoint: None,
        splunk_hec_token: None,
        state_path: config.state_path,
        rotation: config.rotation.clone(),
        dry_run: config.dry_run,
        emit_activity: config.emit_activity,
        emit_session_risk_summary: config.emit_session_risk_summary,
        allow_fixtures: config.allow_fixtures,
        backfill: false,
        rebuild_baselines: false,
        rule_paths: config.rule_paths,
        override_paths: config.override_paths,
        rule_load_mode: config.rule_load_mode,
        policy_path: config.policy_path,
        allowlist_path: config.allowlist_path,
        baseline_deviation_scoring: config.baseline_deviation_scoring,
        clients: config.clients,
        max_sources: None,
        project_config_paths: config.project_config_paths,
        install_inventory_interval_seconds: config.install_inventory_interval_seconds,
    }
}

pub(crate) fn run_scan_loop(
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

const WATCH_SHUTDOWN_POLL: Duration = Duration::from_millis(200);

pub(crate) fn run_watch(config: WatchConfig<'_>) -> Result<(), Box<dyn std::error::Error>> {
    if !config.dry_run && !config.allow_fixtures && is_fixture_root(config.root) {
        return Err(
            "refusing to write fixture/demo data to log path; use --dry-run or --allow-fixtures"
                .into(),
        );
    }
    let _rule_set = load_rule_set_from_paths_with_mode_and_override_paths(
        config.rule_paths,
        config.policy_path,
        config.rule_load_mode,
        config.override_paths,
    )?;

    // Note: structural changes to project YAML (new projects, new roots) require a process
    // restart; the notify watcher is not rebuilt at runtime.
    let project_configs = if config.project_config_paths.is_empty() && config.root == Path::new(".")
    {
        // Use default project paths only when root is the sentinel for home-relative discovery
        crate::projects::load_default_projects()
    } else {
        crate::projects::load_project_configs(config.project_config_paths)
    };
    let watch_roots =
        discover_watch_roots_with_projects(config.root, config.clients, &project_configs);
    if watch_roots.is_empty() {
        return Err(format!(
            "no existing Telltale session-store roots found under {}",
            config.root.display()
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
    let mut remaining = config.iterations;
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
        collect_watch_events_for(&rx, &mut pending, config.debounce, &shutdown)?;
        // Rate limit: keep coalescing until the minimum scan interval has passed.
        if let Some(completed) = last_scan_completed {
            let elapsed = completed.elapsed();
            if elapsed < config.min_scan_interval {
                collect_watch_events_for(
                    &rx,
                    &mut pending,
                    config.min_scan_interval - elapsed,
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
    let mut sources = discover_sources_with_projects(config.root, project_configs);
    if !config.clients.is_empty() {
        let allowed_clients = config.clients.iter().copied().collect::<BTreeSet<_>>();
        sources.retain(|source| allowed_clients.contains(&source.client));
    }
    if !is_fixture_root(config.root) {
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
    let fixture_root = is_fixture_root(config.root);
    if !config.dry_run && !config.allow_fixtures && fixture_root {
        return Err(
            "refusing to write fixture/demo data to log path; use --dry-run or --allow-fixtures"
                .into(),
        );
    }
    let splunk_hec_sink = splunk_hec_sink(config.splunk_hec_endpoint, config.splunk_hec_token)?;
    let (mut sources, targeted) = match targets {
        ScanTargets::Targeted(sources) => (sources, true),
        ScanTargets::Full => {
            let project_configs =
                if config.project_config_paths.is_empty() && config.root == Path::new(".") {
                    // Use default project paths only when root is the sentinel for home-relative discovery
                    crate::projects::load_default_projects()
                } else {
                    crate::projects::load_project_configs(config.project_config_paths)
                };
            let mut sources = discover_sources_with_projects(config.root, &project_configs);
            if !config.clients.is_empty() {
                let allowed_clients = config.clients.iter().copied().collect::<BTreeSet<_>>();
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
    let rule_set = load_rule_set_from_paths_with_mode_and_override_paths(
        config.rule_paths,
        config.policy_path,
        config.rule_load_mode,
        config.override_paths,
    )?;
    let rule_count = rule_set.rule_count();
    let active_policy_name = rule_set.policy_name().map(str::to_string);
    let allowlist = load_allowlist(config.allowlist_path)?;
    let mut state = ScanState::load(config.state_path)?;
    let state_probe = match save_policy {
        StateSavePolicy::Always => None,
        StateSavePolicy::OnChange => Some(StateChangeProbe::capture(&state)),
    };
    let baseline_snapshots = state.baseline_snapshots.clone();
    let install_inventory_interval_seconds = config.install_inventory_interval_seconds;
    let observed_at_unix_ms = OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000;
    let observed_at_unix_ms = u64::try_from(observed_at_unix_ms).unwrap_or_default();
    let parsed_sources = parse_scan_sources(&sources, &state, config.backfill, config.dry_run);
    update_baseline_snapshots(&mut state, &parsed_sources, config.rebuild_baselines);
    let mut install_inventory_event = None;
    if config.clients.is_empty()
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
    let activities = if config.emit_activity {
        let baseline_deviation_config = BaselineDeviationConfig {
            enabled: config.baseline_deviation_scoring,
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
            activities.extend(discover_mcp_inventory(config.root));
            activities.extend(discover_mcp_usage(config.root, &sources));
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
    let session_risk_summaries = if config.emit_session_risk_summary {
        summarize_session_risk_events(&activities, &detections)
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

    let inventory_health_change = source_inventory_change
        .as_ref()
        .is_some_and(|change| change.baseline || change.added > 0 || change.removed > 0);
    let health_emitted = config.dry_run
        || config.backfill
        || inventory_health_change
        || scanner_error_count > 0
        || !operational_alerts.is_empty();

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
        if !config.dry_run {
            state.install_inventory = Some(snapshot);
        }
    }
    for (source, activity) in activities {
        if config.backfill || state.should_emit(&source, &activity) {
            emitted_events.push(activity);
        }
    }
    for (source, detection) in detections {
        if detection.event_type == "scanner_error" {
            // Scanner errors bypass dedup: recurring operational failures
            // (locked SQLite, malformed sources) should be visible every scan.
            emitted_events.push(detection);
        } else if config.backfill || state.should_emit(&source, &detection) {
            emitted_events.push(detection);
        }
    }
    for (source, summary) in session_risk_summaries {
        if config.backfill || state.should_emit(&source, &summary) {
            emitted_events.push(summary);
        }
    }

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
    if !config.dry_run && !config.backfill {
        observe_sqlite_ingestion_cursors(&mut state, &parsed_sources, observed_at_unix_ms);
    }

    if !config.dry_run {
        let sink = LocalJsonlSink::with_rotation(config.log_path, config.rotation.clone());
        emit_events(&sink, &emitted_events)?;
        if let Some(sink) = splunk_hec_sink {
            emit_events(&sink, &emitted_events)?;
        }
        let should_save = match &state_probe {
            None => true,
            Some(probe) => !emitted_events.is_empty() || probe.changed(&state),
        };
        if should_save {
            state.save(config.state_path)?;
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
        dry_run: config.dry_run,
        log_path: config.log_path,
    });
    println!("{}", serde_json::to_string(&summary)?);
    Ok(())
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
    risk_score: u32,
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
) -> Vec<(Source, Event)> {
    let mut summaries: BTreeMap<(String, String, Option<String>), SessionRiskSummaryAccumulator> =
        BTreeMap::new();

    for (source, event) in activities.iter().chain(detections.iter()) {
        if !matches!(event.event_type.as_str(), "activity" | "detection")
            || event.session_id == "scanner"
        {
            continue;
        }
        let key = (
            event.client.clone(),
            event.session_id.clone(),
            event.source_path_hash.clone(),
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
                risk_score: 0,
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

        summary.risk_score = summary.risk_score.max(event.risk_score);
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
                risk_score: summary.risk_score,
                event_time: summary.event_time,
            });
            (source, event)
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
}

fn scan_summary_json(summary: ScanSummaryInput<'_>) -> serde_json::Value {
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
        "source_counts": summary.health_event.source_counts.clone().unwrap_or_default(),
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
    use super::*;
    use crate::install_inventory::InstallInventorySnapshot;

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
        let sqlite = Source {
            client: ClientId::OpenCode,
            kind: SourceKind::Sqlite,
            source_id: "opencode.sqlite".to_string(),
            path: PathBuf::from("/home/user/.local/share/opencode/opencode.db"),
        };
        let legacy = Source {
            client: ClientId::OpenCode,
            kind: SourceKind::LegacyJson,
            source_id: "opencode.legacy_json".to_string(),
            path: PathBuf::from(
                "/home/user/.local/share/opencode/storage/message/session/message.json",
            ),
        };
        let codex = Source {
            client: ClientId::Codex,
            kind: SourceKind::Jsonl,
            source_id: "codex.sessions".to_string(),
            path: PathBuf::from("/home/user/.codex/sessions/session.jsonl"),
        };
        let mut sources = vec![legacy.clone(), sqlite.clone(), codex.clone()];

        prefer_opencode_sqlite_over_legacy_json(&mut sources);

        assert_eq!(sources, vec![sqlite, codex]);
    }
}
