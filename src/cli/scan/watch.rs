use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

use notify::{
    Config as NotifyConfig, Event as NotifyEvent, EventKind, RecommendedWatcher, RecursiveMode,
    Watcher,
};

use crate::discovery::{discover_watch_roots_with_projects, is_fixture_root};
use crate::rules::resolve_rule_set_from_pack_paths_with_mode_override_paths_and_replacements;
use telltale_schema::source::Source;

use super::discovery::{
    SourceDiscoveryAccounting, discover_operational_sources, load_project_configuration,
};
use super::{
    ScanConfig, ScanExecutionConfig, ScanTargets, StateSavePolicy, ensure_durable_scan_platform,
    run_scan,
};

/// When `watch` decides to run a scan.
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

const WATCH_SHUTDOWN_POLL: Duration = Duration::from_millis(200);

pub(crate) fn run_watch(config: WatchConfig<'_>) -> Result<(), Box<dyn std::error::Error>> {
    ensure_durable_scan_platform(
        config.execution.sinks,
        crate::sink::outbox::current_platform_is_windows(),
    )?;
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
    let (project_configs, project_configuration) =
        load_project_configuration(config.execution.root, config.execution.project_config_paths);
    let watch_roots = discover_watch_roots_with_projects(
        config.execution.root,
        config.execution.clients,
        &project_configs,
    );
    if watch_roots.is_empty() {
        return Err("no existing Telltale session-store roots found".into());
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

    let (sources, discovery) = discover_operational_sources(
        config.execution.root,
        config.execution.clients,
        None,
        &project_configs,
        &project_configuration,
    );
    let (mut source_index, mut watch_discovery) = watch_index_from_sources(sources, discovery);
    let scan_config = ScanConfig {
        execution: config.execution,
        backfill: false,
        rebuild_baselines: false,
        max_sources: None,
    };
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

        let targets = match pending.scan_action(&source_index) {
            WatchScanAction::Skip => continue,
            WatchScanAction::Targeted(sources) => ScanTargets::Targeted {
                sources,
                discovery: watch_discovery.clone(),
            },
            WatchScanAction::Full => ScanTargets::Full,
        };
        let result = run_scan(scan_config, targets, StateSavePolicy::OnChange)?;
        if let Some((sources, discovery)) = result.full_scan_discovery {
            (source_index, watch_discovery) = watch_index_from_sources(sources, discovery);
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
        if !matches!(
            event.kind,
            EventKind::Create(_) | EventKind::Modify(_) | EventKind::Remove(_)
        ) {
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

/// Index already-selected sources by canonical path and account for duplicate paths.
fn watch_index_from_sources(
    sources: Vec<Source>,
    mut discovery: SourceDiscoveryAccounting,
) -> (BTreeMap<PathBuf, Source>, SourceDiscoveryAccounting) {
    let index: BTreeMap<_, _> = sources
        .into_iter()
        .map(|source| {
            let key = source
                .path
                .canonicalize()
                .unwrap_or_else(|_| source.path.clone());
            (key, source)
        })
        .collect();
    discovery.operational_source_count = index.len();
    (index, discovery)
}

#[cfg(test)]
mod tests {
    use super::super::discovery::ProjectConfigurationAccounting;
    use super::*;
    use telltale_schema::clients::{ClientId, SourceKind};

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
        let source = Source {
            client: ClientId::Codex,
            kind: SourceKind::Jsonl,
            source_id: "codex.sessions".to_string(),
            path: PathBuf::from("/watch-test/codex/sessions/session-a.jsonl"),
        };
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
    fn watch_snapshot_count_matches_canonical_path_index_for_duplicate_projects() {
        let path = PathBuf::from("duplicate-project/.codex-worktree/session.jsonl");
        let first = Source {
            client: ClientId::Codex,
            kind: SourceKind::Jsonl,
            source_id: "project-one".to_string(),
            path: path.clone(),
        };
        let second = Source {
            source_id: "project-two".to_string(),
            ..first.clone()
        };
        let discovery = SourceDiscoveryAccounting {
            checked_status: "succeeded",
            first_error_category: None,
            best_effort_fallback_used: false,
            returned_source_count: 2,
            operational_source_count: 2,
            project_configuration: ProjectConfigurationAccounting::none(),
        };
        let (index, snapshot) = watch_index_from_sources(vec![first, second], discovery);
        assert_eq!(index.len(), 1);
        assert_eq!(snapshot.operational_source_count, index.len());
    }

    #[test]
    fn collect_watch_events_coalesces_queued_changes_before_disconnect() {
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
}
