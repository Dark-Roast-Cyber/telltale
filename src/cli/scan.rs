use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{Duration, Instant};

use notify::{
    Config as NotifyConfig, Event as NotifyEvent, EventKind, RecommendedWatcher, RecursiveMode,
    Watcher,
};
use time::OffsetDateTime;

use crate::allowlist::{load_allowlist, suppress_detection};
use crate::baseline::{BaselineDeviationConfig, build_baseline_summaries};
use crate::clients::ClientId;
use crate::detection::{detect_sources_with_rules, summarize_source_activities_with_baselines};
use crate::discovery::{
    Source, discover_sources_with_projects, discover_watch_roots_with_projects, is_fixture_root,
};
use crate::event::{
    Event, Evidence, HealthEventInput, OperationalAlertInput, SessionRiskSummaryEventInput,
    evidence_hash, health_event_with_metadata, load_operational_alert_config,
    operational_alert_event, session_risk_summary_event,
};
use crate::mcp::{discover_mcp_inventory, discover_mcp_usage};
use crate::parser::parse_source_records;
use crate::rules::load_rule_set_from_paths;
use crate::scoring::load_thresholds;
use crate::sink::{LocalJsonlSink, SplunkHecConfig, SplunkHecHttpSink, emit_events};
use crate::state::{ScanState, source_fingerprint};
use crate::triage::maybe_triage;

pub(crate) struct ScanConfig<'a> {
    pub(crate) root: &'a Path,
    pub(crate) log_path: &'a Path,
    pub(crate) splunk_hec_endpoint: Option<&'a str>,
    pub(crate) splunk_hec_token: Option<&'a str>,
    pub(crate) state_path: &'a Path,
    pub(crate) dry_run: bool,
    pub(crate) emit_activity: bool,
    pub(crate) emit_session_risk_summary: bool,
    pub(crate) allow_fixtures: bool,
    pub(crate) backfill: bool,
    pub(crate) rebuild_baselines: bool,
    pub(crate) rule_paths: &'a [PathBuf],
    pub(crate) policy_path: Option<&'a Path>,
    pub(crate) allowlist_path: Option<&'a Path>,
    pub(crate) baseline_deviation_scoring: bool,
    pub(crate) clients: &'a [ClientId],
    pub(crate) max_sources: Option<usize>,
    pub(crate) project_config_paths: &'a [PathBuf],
}

pub(crate) struct ScanCommandArgs<'a> {
    pub(crate) root: &'a Path,
    pub(crate) log_path: &'a Path,
    pub(crate) splunk_hec_endpoint: Option<&'a str>,
    pub(crate) splunk_hec_token: Option<&'a str>,
    pub(crate) state_path: &'a Path,
    pub(crate) dry_run: bool,
    pub(crate) emit_activity: bool,
    pub(crate) emit_session_risk_summary: bool,
    pub(crate) allow_fixtures: bool,
    pub(crate) backfill: bool,
    pub(crate) rebuild_baselines: bool,
    pub(crate) rule_paths: &'a [PathBuf],
    pub(crate) policy_path: Option<&'a Path>,
    pub(crate) allowlist_path: Option<&'a Path>,
    pub(crate) baseline_deviation_scoring: bool,
    pub(crate) clients: &'a [ClientId],
    pub(crate) max_sources: Option<usize>,
    pub(crate) project_config_paths: &'a [PathBuf],
}

pub(crate) struct WatchConfig<'a> {
    pub(crate) root: &'a Path,
    pub(crate) log_path: &'a Path,
    pub(crate) state_path: &'a Path,
    pub(crate) dry_run: bool,
    pub(crate) emit_activity: bool,
    pub(crate) emit_session_risk_summary: bool,
    pub(crate) allow_fixtures: bool,
    pub(crate) iterations: Option<u32>,
    pub(crate) debounce: Duration,
    pub(crate) rule_paths: &'a [PathBuf],
    pub(crate) policy_path: Option<&'a Path>,
    pub(crate) allowlist_path: Option<&'a Path>,
    pub(crate) baseline_deviation_scoring: bool,
    pub(crate) clients: &'a [ClientId],
    pub(crate) project_config_paths: &'a [PathBuf],
}

pub(crate) struct WatchCommandArgs<'a> {
    pub(crate) root: &'a Path,
    pub(crate) log_path: &'a Path,
    pub(crate) state_path: &'a Path,
    pub(crate) dry_run: bool,
    pub(crate) emit_activity: bool,
    pub(crate) emit_session_risk_summary: bool,
    pub(crate) allow_fixtures: bool,
    pub(crate) iterations: Option<u32>,
    pub(crate) debounce: Duration,
    pub(crate) rule_paths: &'a [PathBuf],
    pub(crate) policy_path: Option<&'a Path>,
    pub(crate) allowlist_path: Option<&'a Path>,
    pub(crate) baseline_deviation_scoring: bool,
    pub(crate) clients: &'a [ClientId],
    pub(crate) project_config_paths: &'a [PathBuf],
}

pub(crate) fn scan_config<'a>(args: &'a ScanCommandArgs<'a>) -> ScanConfig<'a> {
    ScanConfig {
        root: args.root,
        log_path: args.log_path,
        splunk_hec_endpoint: args.splunk_hec_endpoint,
        splunk_hec_token: args.splunk_hec_token,
        state_path: args.state_path,
        dry_run: args.dry_run,
        emit_activity: args.emit_activity,
        emit_session_risk_summary: args.emit_session_risk_summary,
        allow_fixtures: args.allow_fixtures,
        backfill: args.backfill,
        rebuild_baselines: args.rebuild_baselines,
        rule_paths: args.rule_paths,
        policy_path: args.policy_path,
        allowlist_path: args.allowlist_path,
        baseline_deviation_scoring: args.baseline_deviation_scoring,
        clients: args.clients,
        max_sources: args.max_sources,
        project_config_paths: args.project_config_paths,
    }
}

pub(crate) fn watch_config<'a>(args: &'a WatchCommandArgs<'a>) -> WatchConfig<'a> {
    WatchConfig {
        root: args.root,
        log_path: args.log_path,
        state_path: args.state_path,
        dry_run: args.dry_run,
        emit_activity: args.emit_activity,
        emit_session_risk_summary: args.emit_session_risk_summary,
        allow_fixtures: args.allow_fixtures,
        iterations: args.iterations,
        debounce: args.debounce,
        rule_paths: args.rule_paths,
        policy_path: args.policy_path,
        allowlist_path: args.allowlist_path,
        baseline_deviation_scoring: args.baseline_deviation_scoring,
        clients: args.clients,
        project_config_paths: args.project_config_paths,
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
        emit_session_risk_summary: config.emit_session_risk_summary,
        allow_fixtures: config.allow_fixtures,
        backfill: false,
        rebuild_baselines: false,
        rule_paths: config.rule_paths,
        policy_path: config.policy_path,
        allowlist_path: config.allowlist_path,
        baseline_deviation_scoring: config.baseline_deviation_scoring,
        clients: config.clients,
        max_sources: None,
        project_config_paths: config.project_config_paths,
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

pub(crate) fn run_watch(config: WatchConfig<'_>) -> Result<(), Box<dyn std::error::Error>> {
    if !config.dry_run && !config.allow_fixtures && is_fixture_root(config.root) {
        return Err(
            "refusing to write fixture/demo data to log path; use --dry-run or --allow-fixtures"
                .into(),
        );
    }

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

pub(crate) fn run_scan_once(config: ScanConfig<'_>) -> Result<(), Box<dyn std::error::Error>> {
    let scan_started = Instant::now();
    if !config.dry_run && !config.allow_fixtures && is_fixture_root(config.root) {
        return Err(
            "refusing to write fixture/demo data to log path; use --dry-run or --allow-fixtures"
                .into(),
        );
    }
    let splunk_hec_sink = splunk_hec_sink(config.splunk_hec_endpoint, config.splunk_hec_token)?;
    let project_configs = if config.project_config_paths.is_empty() && config.root == Path::new(".")
    {
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
        let mut activities = summarize_source_activities_with_baselines(
            &sources,
            &baseline_snapshots,
            BaselineDeviationConfig {
                enabled: config.baseline_deviation_scoring,
                ..BaselineDeviationConfig::default()
            },
        );
        activities.extend(discover_mcp_inventory(config.root));
        activities.extend(discover_mcp_usage(config.root, &sources));
        activities
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
    let session_risk_summaries = if config.emit_session_risk_summary {
        summarize_session_risk_events(&activities, &detections)
    } else {
        Vec::new()
    };
    let session_risk_summary_count = session_risk_summaries.len();
    let scan_duration_ms = scan_started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
    let observed_at_unix_ms = OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000;
    let observed_at_unix_ms = u64::try_from(observed_at_unix_ms).unwrap_or_default();
    let source_inventory_change = state.source_inventory_change_summary(&sources);
    let health = health_event_with_metadata(HealthEventInput {
        sources: &sources,
        source_inventory_change: Some(&source_inventory_change),
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
    state.observe_sources(&sources, observed_at_unix_ms);

    let health_emitted = config.dry_run
        || config.backfill
        || source_inventory_change.baseline
        || source_inventory_change.added > 0
        || source_inventory_change.removed > 0
        || scanner_error_count > 0
        || !operational_alerts.is_empty();
    let mut emitted_events = Vec::with_capacity(
        activities.len()
            + detections.len()
            + session_risk_summaries.len()
            + operational_alerts.len()
            + usize::from(health_emitted),
    );
    if health_emitted {
        emitted_events.push(health.clone());
    }
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
    for (source, summary) in session_risk_summaries {
        if config.backfill || state.should_emit(&source, &summary) {
            emitted_events.push(summary);
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
