use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::time::{Duration, Instant};

use notify::{
    Config as NotifyConfig, Event as NotifyEvent, EventKind, RecommendedWatcher, RecursiveMode,
    Watcher,
};

use crate::discovery::discover_watch_roots_with_projects;
use crate::event::{PrivacySanitizer, SanitizationContext};
use crate::file_lock::normalized_path;
use telltale_schema::source::Source;

use super::discovery::{
    ProjectConfigurationAccounting, SourceDiscoveryAccounting, discover_operational_sources,
    load_project_configuration,
};
use super::{ScanConfig, ScanExecutionConfig, ScanTargets, StateSavePolicy, run_scan};

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
const WATCH_DELIVERY_INTERVAL: Duration = Duration::from_secs(1);
const WATCH_NOTIFICATION_CAPACITY: usize = 256;
const WATCH_EVENT_PATH_CAPACITY: usize = 64;
const WATCH_PENDING_PATH_CAPACITY: usize = 4096;

struct WatchInbox {
    rx: Receiver<NotifyEvent>,
    errors: Receiver<notify::Error>,
    overflow: Arc<AtomicBool>,
}

impl WatchInbox {
    fn check_error(&self) -> Result<(), Box<dyn std::error::Error>> {
        if let Ok(error) = self.errors.try_recv() {
            return Err(Box::new(error));
        }
        Ok(())
    }

    fn take_signals(
        &self,
        pending: &mut PendingWatchChanges,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.check_error()?;
        // A concurrent store after this swap remains set for the next pass.
        if self.overflow.swap(false, Ordering::SeqCst) {
            pending.require_full_scan();
        }
        Ok(())
    }
}

fn admit_watch_event(
    tx: &SyncSender<NotifyEvent>,
    errors: &SyncSender<notify::Error>,
    overflow: &AtomicBool,
    result: notify::Result<NotifyEvent>,
) {
    let mut event = match result {
        Ok(event) => event,
        Err(error) => {
            // Retain the first real error independently of notification saturation.
            let _ = errors.try_send(error);
            return;
        }
    };
    if !watch_event_is_relevant(&event) {
        return;
    }
    event
        .paths
        .retain(|path| watch_event_path_is_relevant(path));
    if event.paths.len() > WATCH_EVENT_PATH_CAPACITY
        || matches!(tx.try_send(event), Err(TrySendError::Full(_)))
    {
        overflow.store(true, Ordering::SeqCst);
    }
}

pub(crate) struct WatchRoots {
    roots: Vec<PathBuf>,
    projects: Vec<crate::projects::ProjectDef>,
    accounting: ProjectConfigurationAccounting,
}

pub(crate) fn validate_watch_roots(
    execution: ScanExecutionConfig<'_>,
) -> Result<WatchRoots, Box<dyn std::error::Error>> {
    let (project_configs, project_configuration) =
        load_project_configuration(execution.root, execution.project_config_paths);
    let watch_roots =
        discover_watch_roots_with_projects(execution.root, execution.clients, &project_configs);
    if watch_roots.is_empty() {
        return Err("no existing Telltale session-store roots found".into());
    }
    let roots = watch_roots
        .iter()
        .map(|path| normalized_path(path))
        .collect::<Result<Vec<_>, _>>()?;
    let mut storage = execution.sinks.local_persistence_paths();
    storage.push(execution.state_path.to_path_buf());
    if let Some(outbox) = execution.sinks.durable_outbox_path() {
        storage.push(outbox.to_path_buf());
    }
    for path in storage {
        // Sidecars, temporary files and rotations share the target's parent.
        // Reject placement rather than suppressing potentially real source events.
        let path = normalized_path(&path)?;
        if roots.iter().any(|root| path.starts_with(root)) {
            return Err("runtime storage must be outside watched session-store roots; relocate state, JSONL, and durable outbox paths".into());
        }
    }
    Ok(WatchRoots {
        roots: watch_roots,
        projects: project_configs,
        accounting: project_configuration,
    })
}

pub(crate) fn run_watch(
    config: WatchConfig<'_>,
    watch_roots: WatchRoots,
) -> Result<(), Box<dyn std::error::Error>> {
    // Structural project changes require a restart; registered roots stay fixed.
    let WatchRoots {
        roots: watch_roots,
        projects: project_configs,
        accounting: project_configuration,
    } = watch_roots;

    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_handler = Arc::clone(&shutdown);
    ctrlc::set_handler(move || shutdown_handler.store(true, Ordering::SeqCst))?;

    let (tx, rx) = mpsc::sync_channel(WATCH_NOTIFICATION_CAPACITY);
    let (error_tx, errors) = mpsc::sync_channel(1);
    let overflow = Arc::new(AtomicBool::new(false));
    let inbox = WatchInbox {
        rx,
        errors,
        overflow: Arc::clone(&overflow),
    };
    let mut watcher = RecommendedWatcher::new(
        move |result| {
            admit_watch_event(&tx, &error_tx, &overflow, result);
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
    let idle_delivery = !config.execution.dry_run && config.execution.sinks.has_persistent_replay();
    if idle_delivery {
        report_idle_delivery_failures(
            config
                .execution
                .sinks
                .persist_for_durable_replay_with_failures(&[])?,
        );
    }
    let mut last_delivery_completed = Instant::now();

    'watch: loop {
        // Delivery wakeups do not scan sources, save scanner state, or consume iterations.
        let mut pending = PendingWatchChanges::default();
        while pending.is_empty() {
            inbox.take_signals(&mut pending)?;
            if shutdown.load(Ordering::SeqCst) {
                break 'watch;
            }
            if !pending.is_empty() {
                break;
            }
            if idle_delivery && last_delivery_completed.elapsed() >= WATCH_DELIVERY_INTERVAL {
                report_idle_delivery_failures(config.execution.sinks.deliver_durable()?);
                last_delivery_completed = Instant::now();
                continue;
            }
            match inbox.rx.recv_timeout(WATCH_SHUTDOWN_POLL) {
                Ok(event) => pending.absorb(&event),
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => {
                    inbox.take_signals(&mut pending)?;
                    if pending.is_empty() {
                        break 'watch;
                    }
                }
            }
        }

        // Debounce window: coalesce rapid writes into one scan.
        collect_watch_events_for(&inbox, &mut pending, config.trigger.debounce, &shutdown)?;
        // Rate limit: keep coalescing until the minimum scan interval has passed.
        if let Some(completed) = last_scan_completed {
            let elapsed = completed.elapsed();
            if elapsed < config.trigger.min_scan_interval {
                collect_watch_events_for(
                    &inbox,
                    &mut pending,
                    config.trigger.min_scan_interval - elapsed,
                    &shutdown,
                )?;
            }
        }
        if shutdown.load(Ordering::SeqCst) {
            break;
        }
        inbox.take_signals(&mut pending)?;

        let targets = match pending.scan_action(&source_index) {
            WatchScanAction::Skip => continue,
            WatchScanAction::Targeted(sources) => ScanTargets::Targeted {
                sources,
                discovery: watch_discovery.clone(),
            },
            WatchScanAction::Full => ScanTargets::Full,
        };
        let result = run_scan(scan_config, targets, StateSavePolicy::OnChange)?;
        inbox.check_error()?;
        last_delivery_completed = Instant::now();
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

fn report_idle_delivery_failures(failures: Vec<crate::sink::SinkFailure>) {
    for failure in failures {
        eprintln!(
            "warning: idle durable delivery: {}",
            PrivacySanitizer::sanitize(SanitizationContext::Diagnostic, &failure.error)
        );
    }
}

fn collect_watch_events_for(
    inbox: &WatchInbox,
    pending: &mut PendingWatchChanges,
    window: Duration,
    shutdown: &AtomicBool,
) -> Result<(), Box<dyn std::error::Error>> {
    let deadline = Instant::now() + window;
    loop {
        inbox.take_signals(pending)?;
        if shutdown.load(Ordering::SeqCst) {
            return Ok(());
        }
        let now = Instant::now();
        if now >= deadline {
            return Ok(());
        }
        let timeout = (deadline - now).min(WATCH_SHUTDOWN_POLL);
        match inbox.rx.recv_timeout(timeout) {
            Ok(event) => pending.absorb(&event),
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => {
                inbox.take_signals(pending)?;
                return Ok(());
            }
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
    saw_rescan: bool,
}

impl PendingWatchChanges {
    fn require_full_scan(&mut self) {
        self.saw_rescan = true;
        self.paths.clear();
    }

    fn absorb(&mut self, event: &NotifyEvent) {
        if !watch_event_is_relevant(event) {
            return;
        }
        if event.need_rescan() {
            self.require_full_scan();
        }
        if self.saw_rescan {
            return;
        }
        if matches!(event.kind, EventKind::Remove(_)) {
            self.saw_remove = true;
        }
        for path in &event.paths {
            if let Some(path) = normalize_watch_event_path(path) {
                if self.paths.len() == WATCH_PENDING_PATH_CAPACITY && !self.paths.contains(&path) {
                    self.require_full_scan();
                    return;
                }
                self.paths.insert(path);
            }
        }
    }

    fn is_empty(&self) -> bool {
        self.paths.is_empty() && !self.saw_remove && !self.saw_rescan
    }

    fn scan_action(&self, source_index: &BTreeMap<PathBuf, Source>) -> WatchScanAction {
        if self.saw_remove || self.saw_rescan {
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

fn watch_event_is_relevant(event: &NotifyEvent) -> bool {
    event.need_rescan()
        || matches!(event.kind, EventKind::Remove(_))
        || (matches!(event.kind, EventKind::Create(_) | EventKind::Modify(_))
            && event
                .paths
                .iter()
                .any(|path| watch_event_path_is_relevant(path)))
}

fn watch_event_path_is_relevant(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return true;
    };
    !["-shm", "-journal"].iter().any(|suffix| {
        name.strip_suffix(suffix)
            .is_some_and(|base| base.ends_with(".db"))
    })
}

/// Map SQLite WAL sidecar events onto the main database file and drop `-shm` /
/// `-journal` sidecar events, which fire on reader activity without new
/// persisted data.
fn normalize_watch_event_path(path: &Path) -> Option<PathBuf> {
    if !watch_event_path_is_relevant(path) {
        return None;
    }
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return Some(path.to_path_buf());
    };
    if let Some(base) = name.strip_suffix("-wal")
        && base.ends_with(".db")
    {
        return Some(path.with_file_name(base));
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

    fn change(path: PathBuf) -> NotifyEvent {
        NotifyEvent::new(EventKind::Modify(notify::event::ModifyKind::Any)).add_path(path)
    }

    #[test]
    fn watch_admission_flood_retains_overflow_outside_stalled_queue() {
        let (tx, rx) = mpsc::sync_channel(WATCH_NOTIFICATION_CAPACITY);
        let (error_tx, errors) = mpsc::sync_channel(1);
        let overflow = Arc::new(AtomicBool::new(false));
        for i in 0..WATCH_NOTIFICATION_CAPACITY * 10 {
            admit_watch_event(
                &tx,
                &error_tx,
                &overflow,
                Ok(change(format!("/watch-test/{i}").into())),
            );
        }
        assert_eq!(rx.try_iter().count(), WATCH_NOTIFICATION_CAPACITY);
        let inbox = WatchInbox {
            rx,
            errors,
            overflow,
        };
        let mut pending = PendingWatchChanges::default();
        inbox.take_signals(&mut pending).unwrap();
        assert!(matches!(
            pending.scan_action(&BTreeMap::new()),
            WatchScanAction::Full
        ));
        let mut next = PendingWatchChanges::default();
        inbox.take_signals(&mut next).unwrap();
        assert!(next.is_empty(), "quiescence must not repeatedly reconcile");
        // Overflow after the consumer's swap belongs to the next reconciliation.
        inbox.overflow.store(true, Ordering::SeqCst);
        inbox.take_signals(&mut next).unwrap();
        assert!(matches!(
            next.scan_action(&BTreeMap::new()),
            WatchScanAction::Full
        ));
    }

    #[test]
    fn watch_admission_ignored_event_flood_does_not_queue_or_reconcile() {
        let (tx, rx) = mpsc::sync_channel(WATCH_NOTIFICATION_CAPACITY);
        let (error_tx, errors) = mpsc::sync_channel(1);
        let overflow = Arc::new(AtomicBool::new(false));
        for kind in [
            EventKind::Access(notify::event::AccessKind::Open(
                notify::event::AccessMode::Read,
            )),
            EventKind::Modify(notify::event::ModifyKind::Any),
        ] {
            for path_count in [1, WATCH_EVENT_PATH_CAPACITY + 1] {
                for _ in 0..WATCH_NOTIFICATION_CAPACITY * 2 {
                    let mut event = NotifyEvent::new(kind);
                    event.paths = (0..path_count)
                        .map(|i| match kind {
                            EventKind::Access(_) => format!("/watch-test/{i}.jsonl").into(),
                            _ => format!("/watch-test/{i}.db-shm").into(),
                        })
                        .collect();
                    admit_watch_event(&tx, &error_tx, &overflow, Ok(event));
                }
            }
            assert!(
                rx.try_recv().is_err(),
                "irrelevant events must not occupy the queue"
            );
            assert!(
                !overflow.load(Ordering::SeqCst),
                "irrelevant floods must not request reconciliation"
            );
        }
        let inbox = WatchInbox {
            rx,
            errors,
            overflow,
        };
        let mut pending = PendingWatchChanges::default();
        inbox.take_signals(&mut pending).unwrap();
        assert!(matches!(
            pending.scan_action(&BTreeMap::new()),
            WatchScanAction::Skip
        ));
    }

    #[test]
    fn watch_admission_relevance_preserves_rescan_remove_and_mixed_paths() {
        let (tx, rx) = mpsc::sync_channel(WATCH_NOTIFICATION_CAPACITY);
        let (error_tx, _errors) = mpsc::sync_channel(1);
        let overflow = AtomicBool::new(false);
        for event in [
            NotifyEvent::new(EventKind::Access(notify::event::AccessKind::Any))
                .set_flag(notify::event::Flag::Rescan),
            NotifyEvent::new(EventKind::Remove(notify::event::RemoveKind::Any))
                .add_path("/watch-test/database.db-shm".into()),
        ] {
            admit_watch_event(&tx, &error_tx, &overflow, Ok(event));
            let mut pending = PendingWatchChanges::default();
            pending.absorb(&rx.try_recv().unwrap());
            assert!(matches!(
                pending.scan_action(&BTreeMap::new()),
                WatchScanAction::Full
            ));
        }
        let mut mixed = change("/watch-test/real.jsonl".into());
        mixed.paths.extend(
            (0..=WATCH_EVENT_PATH_CAPACITY)
                .map(|i| PathBuf::from(format!("/watch-test/{i}.db-journal"))),
        );
        admit_watch_event(&tx, &error_tx, &overflow, Ok(mixed));
        let admitted = rx.try_recv().unwrap();
        assert_eq!(
            admitted.paths,
            vec![PathBuf::from("/watch-test/real.jsonl")]
        );
        assert!(!overflow.load(Ordering::SeqCst));
        let mut large_mixed = change("/watch-test/ignored.db-shm".into());
        large_mixed.paths.extend(
            (0..=WATCH_EVENT_PATH_CAPACITY)
                .map(|i| PathBuf::from(format!("/watch-test/{i}.jsonl"))),
        );
        admit_watch_event(&tx, &error_tx, &overflow, Ok(large_mixed));
        assert!(rx.try_recv().is_err());
        assert!(
            overflow.load(Ordering::SeqCst),
            "too many relevant paths must still reconcile"
        );
    }

    #[test]
    fn watch_admission_oversized_event_and_errors_bypass_full_queue() {
        let (tx, rx) = mpsc::sync_channel(1);
        let (error_tx, errors) = mpsc::sync_channel(1);
        let overflow = Arc::new(AtomicBool::new(false));
        let mut large = change("/watch-test/0".into());
        large.paths = (0..=WATCH_EVENT_PATH_CAPACITY)
            .map(|i| format!("/watch-test/{i}").into())
            .collect();
        admit_watch_event(&tx, &error_tx, &overflow, Ok(large));
        assert!(rx.try_recv().is_err(), "large events must not be retained");
        assert!(overflow.load(Ordering::SeqCst));
        admit_watch_event(
            &tx,
            &error_tx,
            &overflow,
            Ok(change("/watch-test/queued".into())),
        );
        for _ in 0..10 {
            admit_watch_event(
                &tx,
                &error_tx,
                &overflow,
                Err(notify::Error::generic("synthetic watcher failure")),
            );
        }
        let inbox = WatchInbox {
            rx,
            errors,
            overflow,
        };
        assert!(
            inbox
                .take_signals(&mut PendingWatchChanges::default())
                .unwrap_err()
                .to_string()
                .contains("synthetic watcher failure")
        );
    }

    #[test]
    fn pending_path_budget_counts_distinct_normalized_paths() {
        let mut pending = PendingWatchChanges::default();
        for i in 0..WATCH_PENDING_PATH_CAPACITY {
            let event = change(format!("/watch-test/{i}.db-wal").into());
            pending.absorb(&event);
            pending.absorb(&event);
        }
        assert_eq!(pending.paths.len(), WATCH_PENDING_PATH_CAPACITY);
        assert!(!pending.saw_rescan);
        pending.absorb(&change("/watch-test/over-budget".into()));
        assert!(
            pending.paths.is_empty(),
            "full reconciliation no longer needs paths"
        );
        assert!(matches!(
            pending.scan_action(&BTreeMap::new()),
            WatchScanAction::Full
        ));
        pending.absorb(&change("/watch-test/later".into()));
        assert!(pending.paths.is_empty());
    }

    #[test]
    fn collect_watch_overflow_without_queued_events_survives_zero_window_and_disconnect() {
        let (tx, rx) = mpsc::sync_channel(WATCH_NOTIFICATION_CAPACITY);
        let (_error_tx, errors) = mpsc::sync_channel(1);
        let inbox = WatchInbox {
            rx,
            errors,
            overflow: Arc::new(AtomicBool::new(true)),
        };
        drop(tx);
        let mut pending = PendingWatchChanges::default();
        collect_watch_events_for(
            &inbox,
            &mut pending,
            Duration::ZERO,
            &AtomicBool::new(false),
        )
        .unwrap();
        assert!(matches!(
            pending.scan_action(&BTreeMap::new()),
            WatchScanAction::Full
        ));
        let mut next = PendingWatchChanges::default();
        collect_watch_events_for(
            &inbox,
            &mut next,
            Duration::from_secs(5),
            &AtomicBool::new(false),
        )
        .unwrap();
        assert!(next.is_empty());
    }

    #[test]
    fn collect_watch_saturated_error_is_not_hidden_by_shutdown_or_zero_window() {
        let (tx, rx) = mpsc::sync_channel(1);
        let (error_tx, errors) = mpsc::sync_channel(1);
        let overflow = Arc::new(AtomicBool::new(false));
        admit_watch_event(
            &tx,
            &error_tx,
            &overflow,
            Ok(change("/watch-test/queued".into())),
        );
        admit_watch_event(
            &tx,
            &error_tx,
            &overflow,
            Err(notify::Error::generic("synthetic failure")),
        );
        let inbox = WatchInbox {
            rx,
            errors,
            overflow,
        };
        assert!(
            collect_watch_events_for(
                &inbox,
                &mut PendingWatchChanges::default(),
                Duration::ZERO,
                &AtomicBool::new(true)
            )
            .is_err()
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

        assert!(!pending.is_empty());
        match pending.scan_action(&index) {
            WatchScanAction::Targeted(targets) => assert_eq!(targets, vec![db_source]),
            _ => panic!("expected targeted scan"),
        }
    }

    #[test]
    fn pending_rescan_without_paths_requires_full_scan_even_when_coalesced() {
        let source = Source {
            client: ClientId::Codex,
            kind: SourceKind::Jsonl,
            source_id: "codex.sessions".to_string(),
            path: PathBuf::from("/watch-test/codex/sessions/session-a.jsonl"),
        };
        let index = BTreeMap::from([(source.path.clone(), source.clone())]);
        let mut pending = PendingWatchChanges::default();
        pending.absorb(&NotifyEvent::new(EventKind::Other).set_flag(notify::event::Flag::Rescan));
        assert!(!pending.is_empty(), "rescan must wake the pending loop");
        assert!(matches!(pending.scan_action(&index), WatchScanAction::Full));

        pending.absorb(
            &NotifyEvent::new(EventKind::Modify(notify::event::ModifyKind::Any))
                .add_path(source.path),
        );
        assert!(matches!(pending.scan_action(&index), WatchScanAction::Full));
    }

    #[test]
    fn pending_rescan_flag_precedes_kind_filter_but_plain_other_is_ignored() {
        let index = BTreeMap::new();
        let mut pending = PendingWatchChanges::default();
        pending.absorb(
            &NotifyEvent::new(EventKind::Other)
                .add_path(PathBuf::from("/watch-test/ignored.jsonl")),
        );
        assert!(pending.is_empty());
        assert!(matches!(pending.scan_action(&index), WatchScanAction::Skip));

        pending.absorb(
            &NotifyEvent::new(EventKind::Access(notify::event::AccessKind::Any))
                .set_flag(notify::event::Flag::Rescan),
        );
        assert!(!pending.is_empty());
        assert!(matches!(pending.scan_action(&index), WatchScanAction::Full));
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
        let path = PathBuf::from("duplicate-project/session.jsonl");
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
        let (tx, rx) = mpsc::sync_channel(WATCH_NOTIFICATION_CAPACITY);
        let (_error_tx, errors) = mpsc::sync_channel(1);
        let inbox = WatchInbox {
            rx,
            errors,
            overflow: Arc::new(AtomicBool::new(false)),
        };
        let mut pending = PendingWatchChanges::default();
        let shutdown = AtomicBool::new(false);

        let event = NotifyEvent {
            kind: EventKind::Modify(notify::event::ModifyKind::Any),
            paths: vec![PathBuf::from("/watch-test/codex/sessions/session-a.jsonl")],
            attrs: Default::default(),
        };
        tx.send(event.clone()).expect("send first event");
        tx.send(event).expect("send second event");
        drop(tx);

        collect_watch_events_for(&inbox, &mut pending, Duration::from_secs(5), &shutdown)
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
