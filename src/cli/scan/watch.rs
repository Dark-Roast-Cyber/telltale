//! `telltale watch`: filesystem notifications, bounded change coalescing and
//! scan scheduling on top of the one-shot scan path. Overflowing the pending
//! set forces a full reconciliation rather than dropping changes. Watch starts
//! idle unless `--initial-scan` asks for one uncounted full scan after every
//! watch is registered; either way it reports readiness once on stderr.
//!
//! With the opt-in liveness heartbeat, a due heartbeat makes the next scan a
//! full scan, idle or not. That scan emits health and, except in dry-run, saves
//! state through the ordinary scan path; idle delivery wakeups still never scan
//! or save state. The initial scan stays uncounted even if a heartbeat is due.

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
use telltale_schema::clients::SourceKind;
use telltale_schema::source::Source;

use super::discovery::{
    ProjectConfigurationAccounting, SourceDiscoveryAccounting, discover_operational_sources,
    load_project_configuration,
};
use super::{
    ScanConfig, ScanExecutionConfig, ScanTargets, StateSavePolicy, health_heartbeat_wait,
    iteration_budget_exhausted, run_scan, unix_ms_now,
};
use crate::state::ScanState;

#[cfg(any(target_os = "macos", all(test, unix)))]
mod sqlite_metadata;

/// When `watch` decides to run a scan.
#[derive(Clone, Copy)]
pub(crate) struct WatchTriggerConfig {
    pub(crate) iterations: Option<u32>,
    /// Run one uncounted full scan once every watch is registered.
    pub(crate) initial_scan: bool,
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
/// Delays after a scan of a SQLite store at which its commit sample is re-read.
/// SQLite writes a commit's WAL frames, which notify, before it publishes the
/// commit to readers in `-shm`, which does not; a scan woken by the write can
/// still read the previous snapshot. A bounded window catches that late
/// publication without rescanning an unchanged store.
const SQLITE_COMMIT_RECHECK_DELAYS: [Duration; 4] = [
    Duration::from_millis(250),
    Duration::from_secs(1),
    Duration::from_secs(3),
    Duration::from_secs(10),
];
/// The leading bytes of `-shm`: both wal-index header copies, which every
/// published commit rewrites, compared as opaque bytes. The reader marks that
/// follow change whenever a reader, including the watcher's own scan, starts.
const SQLITE_COMMIT_SAMPLE_LEN: usize = 96;

/// The startup snapshot and subsequent scan results, never reread on idle wakeups.
struct WatchHeartbeat {
    interval_seconds: u64,
    last_health_unix_ms: Option<u64>,
    retry_started: Option<Instant>,
}

impl WatchHeartbeat {
    fn is_due(&self, now_unix_ms: u64, now: Instant) -> bool {
        // Only the anti-loop delay is monotonic. Recheck wall time so forward
        // jumps and a marker now in the future both schedule a full scan.
        self.retry_started.is_none_or(|started| {
            now.saturating_duration_since(started) >= Duration::from_secs(self.interval_seconds)
        }) && health_heartbeat_wait(self.last_health_unix_ms, now_unix_ms, self.interval_seconds)
            .is_zero()
    }

    fn after_scan(
        &mut self,
        last_health_unix_ms: Option<u64>,
        heartbeat_scan: bool,
        now_unix_ms: u64,
        now: Instant,
    ) {
        self.last_health_unix_ms = last_health_unix_ms;
        // A scan that leaves the heartbeat due must not cause a tight loop,
        // even if the wall clock changes again. Elapsed time avoids overflow
        // when the configured interval cannot fit in an Instant deadline.
        self.retry_started = (heartbeat_scan
            && health_heartbeat_wait(last_health_unix_ms, now_unix_ms, self.interval_seconds)
                .is_zero())
        .then_some(now);
    }
}

#[derive(Clone, Default)]
struct WatchPathFilter {
    sqlite_override: Option<PathBuf>,
    exclusive_parent: Option<PathBuf>,
}

impl WatchPathFilter {
    fn ignores(&self, path: &Path) -> bool {
        let database = self.sqlite_override.as_deref();
        if database.is_some_and(|database| watch_paths_equal(path, database)) {
            return false;
        }
        if configured_reader_sidecar(path, database) {
            return true;
        }
        self.exclusive_parent.as_deref().is_some_and(|parent| {
            path.parent()
                .is_some_and(|actual| watch_paths_equal(actual, parent))
                && database.is_none_or(|database| {
                    !watch_paths_equal(path, &sqlite_sidecar_path(database, "-wal"))
                })
        })
    }

    fn normalize(&self, path: &Path) -> Option<PathBuf> {
        if self.ignores(path) {
            return None;
        }
        normalize_watch_event_path_with_override(path, self.sqlite_override.as_deref())
    }
}

struct WatchInbox {
    rx: Receiver<NotifyEvent>,
    errors: Receiver<notify::Error>,
    overflow: Arc<AtomicBool>,
    filter: WatchPathFilter,
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

#[cfg(test)]
fn admit_watch_event(
    tx: &SyncSender<NotifyEvent>,
    errors: &SyncSender<notify::Error>,
    overflow: &AtomicBool,
    result: notify::Result<NotifyEvent>,
) {
    admit_watch_event_with_override(tx, errors, overflow, result, None);
}

#[cfg(test)]
fn admit_watch_event_with_override(
    tx: &SyncSender<NotifyEvent>,
    errors: &SyncSender<notify::Error>,
    overflow: &AtomicBool,
    result: notify::Result<NotifyEvent>,
    sqlite_override: Option<&Path>,
) {
    admit_filtered_watch_event(
        tx,
        errors,
        overflow,
        result,
        &WatchPathFilter {
            sqlite_override: sqlite_override.map(Path::to_path_buf),
            exclusive_parent: None,
        },
    );
}

fn admit_filtered_watch_event(
    tx: &SyncSender<NotifyEvent>,
    errors: &SyncSender<notify::Error>,
    overflow: &AtomicBool,
    result: notify::Result<NotifyEvent>,
    filter: &WatchPathFilter,
) {
    let mut event = match result {
        Ok(event) => event,
        Err(error) => {
            // Retain the first real error independently of notification saturation.
            let _ = errors.try_send(error);
            return;
        }
    };
    if !watch_event_is_relevant(&event, filter) {
        return;
    }
    event.paths.retain(|path| filter.normalize(path).is_some());
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
    non_recursive: BTreeSet<PathBuf>,
    filter: WatchPathFilter,
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
    let include_opencode = execution.clients.is_empty()
        || execution
            .clients
            .contains(&telltale_schema::clients::ClientId::OpenCode);
    let sqlite_override = if include_opencode {
        telltale_sources::discovery::opencode_database_override(execution.root)
            .map_err(|_| "invalid OpenCode database override")?
            .map(|path| normalized_path(&path))
            .transpose()?
    } else {
        None
    };
    let other_clients = telltale_sources::clients::supported_clients()
        .iter()
        .filter(|client| {
            client.id != telltale_schema::clients::ClientId::OpenCode
                && (execution.clients.is_empty() || execution.clients.contains(&client.id))
        })
        .map(|client| client.id)
        .collect::<Vec<_>>();
    let recursive_roots = if other_clients.is_empty() {
        Vec::new()
    } else {
        discover_watch_roots_with_projects(execution.root, &other_clients, &project_configs)
            .iter()
            .map(|path| normalized_path(path))
            .collect::<Result<Vec<_>, _>>()?
    };
    // SQLite candidates are direct children. In particular, an arbitrary override
    // authorizes its file and sidecars, not recursively watching its parent's tree.
    let mut roots = watch_roots
        .iter()
        .map(|path| normalized_path(path))
        .collect::<Result<Vec<_>, _>>()?;
    roots.sort_unstable();
    roots.dedup();
    let non_recursive = roots
        .iter()
        .filter(|path| !recursive_roots.contains(path))
        .cloned()
        .collect();
    let data_directories = if sqlite_override.is_some() {
        telltale_sources::discovery::opencode_data_directories(execution.root)
            .iter()
            .map(|path| normalized_path(path))
            .collect::<Result<Vec<_>, _>>()?
    } else {
        Vec::new()
    };
    let exclusive_parent = sqlite_override
        .as_ref()
        .and_then(|path| path.parent())
        .filter(|parent| {
            !data_directories.iter().any(|data| data == parent)
                && !recursive_roots.iter().any(|root| parent.starts_with(root))
        })
        .map(Path::to_path_buf);
    let filter = WatchPathFilter {
        sqlite_override,
        exclusive_parent,
    };
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
        roots,
        projects: project_configs,
        accounting: project_configuration,
        non_recursive,
        filter,
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
        non_recursive,
        filter,
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
        filter: filter.clone(),
    };
    let mut watcher = RecommendedWatcher::new(
        move |result| {
            admit_filtered_watch_event(&tx, &error_tx, &overflow, result, &filter);
        },
        NotifyConfig::default(),
    )?;
    for root in &watch_roots {
        watcher.watch(
            root,
            if non_recursive.contains(root) {
                RecursiveMode::NonRecursive
            } else {
                RecursiveMode::Recursive
            },
        )?;
    }

    let (sources, discovery) = discover_operational_sources(
        config.execution.root,
        config.execution.clients,
        None,
        &project_configs,
        &project_configuration,
    );
    let (mut source_index, mut watch_discovery) = watch_index_from_sources(sources, discovery);
    #[cfg(target_os = "macos")]
    let mut sqlite_metadata =
        sqlite_metadata::SqliteMetadataWatch::new(&source_index, Instant::now());
    let scan_config = ScanConfig {
        execution: config.execution,
        history: false,
        backfill: false,
        rebuild_baselines: false,
        max_sources: None,
        // Diagnostics records cover `scan` only.
        diagnostics: None,
    };
    let mut remaining = config.trigger.iterations;
    let mut last_scan_completed: Option<Instant> = None;
    let mut sqlite_rechecks = BTreeMap::new();
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
    // Read the recorded heartbeat once; later checks use this scan-owned cache.
    let heartbeat_interval = config.execution.health_heartbeat_interval_seconds;
    let mut heartbeat = match heartbeat_interval {
        Some(interval_seconds) => Some(WatchHeartbeat {
            interval_seconds,
            last_health_unix_ms: ScanState::load_snapshot(config.execution.state_path)?
                .last_health_heartbeat_unix_ms(),
            retry_started: None,
        }),
        None => None,
    };
    // Watches are registered before this scan reads anything, so a write
    // during it stays queued and triggers a later scan.
    let mut initial_scan = config.trigger.initial_scan;
    if !initial_scan {
        report_watch_ready(watch_roots.len(), false, heartbeat_interval.is_some());
    }

    'watch: loop {
        // Delivery wakeups do not scan sources, save scanner state, or consume iterations.
        let mut pending = PendingWatchChanges::default();
        if initial_scan {
            pending.require_full_scan();
        }
        while pending.is_empty() {
            inbox.take_signals(&mut pending)?;
            if shutdown.load(Ordering::SeqCst) {
                break 'watch;
            }
            if !pending.is_empty() {
                break;
            }
            #[cfg(target_os = "macos")]
            {
                pending.paths.extend(sqlite_metadata.poll(Instant::now()));
                if !pending.is_empty() {
                    break;
                }
            }
            if heartbeat
                .as_ref()
                .is_some_and(|heartbeat| heartbeat.is_due(unix_ms_now(), Instant::now()))
            {
                pending.require_full_scan();
                break;
            }
            if idle_delivery && last_delivery_completed.elapsed() >= WATCH_DELIVERY_INTERVAL {
                report_idle_delivery_failures(config.execution.sinks.deliver_durable()?);
                last_delivery_completed = Instant::now();
                continue;
            }
            let now = Instant::now();
            take_due_sqlite_rechecks(&mut sqlite_rechecks, &mut pending, now);
            if !pending.is_empty() {
                break;
            }
            let wait = next_sqlite_recheck(&sqlite_rechecks).map_or(WATCH_SHUTDOWN_POLL, |due| {
                due.saturating_duration_since(now).min(WATCH_SHUTDOWN_POLL)
            });
            match inbox.rx.recv_timeout(wait) {
                Ok(event) => pending.absorb_with_filter(&event, &inbox.filter),
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
        if !initial_scan {
            collect_watch_events_for(&inbox, &mut pending, config.trigger.debounce, &shutdown)?;
        }
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
        // A due heartbeat widens a targeted scan, so a busy host reports too.
        let heartbeat_scan = heartbeat
            .as_ref()
            .is_some_and(|heartbeat| heartbeat.is_due(unix_ms_now(), Instant::now()));
        // Sample before widening clears the changed paths.
        let samples = sample_sqlite_sources(
            &pending,
            heartbeat_scan,
            &source_index,
            &mut sqlite_rechecks,
        );
        if heartbeat_scan {
            pending.require_full_scan();
        }

        let targets = match pending.scan_action(&source_index) {
            WatchScanAction::Skip => continue,
            WatchScanAction::Targeted(sources) => ScanTargets::Targeted {
                sources,
                discovery: watch_discovery.clone(),
            },
            WatchScanAction::Full => ScanTargets::Full,
        };
        if inbox.filter.sqlite_override.is_some() {
            telltale_sources::discovery::opencode_database_override(config.execution.root)
                .map_err(|_| "invalid OpenCode database override")?;
        }
        // Capture before acquisition, never after: a later writer commit must
        // remain a change even if it arrives while this scan is finishing.
        #[cfg(target_os = "macos")]
        sqlite_metadata.before_scan(&targets);
        let result = run_scan(scan_config, targets, StateSavePolicy::OnChange)?;
        let scanned = Instant::now();
        sqlite_rechecks.extend(samples.into_iter().map(|(path, sample)| {
            (
                path,
                SqliteCommitRecheck {
                    sample,
                    scanned,
                    next: 0,
                },
            )
        }));
        inbox.check_error()?;
        last_delivery_completed = Instant::now();
        if let Some(heartbeat) = &mut heartbeat {
            heartbeat.after_scan(
                result.last_health_unix_ms,
                heartbeat_scan,
                unix_ms_now(),
                Instant::now(),
            );
        }
        if let Some((sources, discovery)) = result.full_scan_discovery {
            (source_index, watch_discovery) = watch_index_from_sources(sources, discovery);
            sqlite_rechecks.retain(|path, _| {
                source_index
                    .get(path)
                    .is_some_and(|source| source.kind == SourceKind::Sqlite)
            });
            #[cfg(target_os = "macos")]
            sqlite_metadata.reconcile(&source_index);
        }
        last_scan_completed = Some(Instant::now());
        if initial_scan {
            initial_scan = false;
            report_watch_ready(watch_roots.len(), true, heartbeat_interval.is_some());
            continue;
        }

        if iteration_budget_exhausted(&mut remaining) {
            break;
        }
    }
    Ok(())
}

/// One constant stderr line, without paths: every later change will be seen.
fn report_watch_ready(roots: usize, initial_scan: bool, heartbeat: bool) {
    if heartbeat {
        let initial = if initial_scan {
            ", initial scan complete"
        } else {
            ""
        };
        eprintln!(
            "telltale watch: ready{initial}; watching {roots} session-store root(s); changes and liveness heartbeats trigger scans"
        );
    } else if initial_scan {
        eprintln!(
            "telltale watch: ready, initial scan complete; watching {roots} session-store root(s); changes trigger scans"
        );
    } else {
        eprintln!(
            "telltale watch: ready; watching {roots} session-store root(s); existing sessions are scanned only after they change (use --initial-scan to scan them at startup)"
        );
    }
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
            Ok(event) => pending.absorb_with_filter(&event, &inbox.filter),
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => {
                inbox.take_signals(pending)?;
                return Ok(());
            }
        }
    }
}

/// A changed SQLite store's commit sample from before its last scan.
struct SqliteCommitRecheck {
    sample: [u8; SQLITE_COMMIT_SAMPLE_LEN],
    scanned: Instant,
    next: usize,
}

/// A plain read of the leading `-shm` bytes; never opens the database. A
/// missing or shorter file means there is nothing to compare.
fn sqlite_commit_sample(database: &Path) -> Option<[u8; SQLITE_COMMIT_SAMPLE_LEN]> {
    use std::io::Read;
    let mut sample = [0; SQLITE_COMMIT_SAMPLE_LEN];
    std::fs::File::open(sqlite_sidecar_path(database, "-shm"))
        .and_then(|mut file| file.read_exact(&mut sample))
        .ok()?;
    Some(sample)
}

/// Sample the SQLite stores a scan is about to read, ending their earlier
/// windows; the scan restarts them. A full scan, including one a heartbeat
/// widens, samples every indexed store, because rescans and overflow clear
/// the changed paths. A changed path not yet indexed is sampled when a `-shm`
/// sits beside it, so a new store's first commit is covered too.
fn sample_sqlite_sources(
    pending: &PendingWatchChanges,
    full_scan: bool,
    source_index: &BTreeMap<PathBuf, Source>,
    rechecks: &mut BTreeMap<PathBuf, SqliteCommitRecheck>,
) -> Vec<(PathBuf, [u8; SQLITE_COMMIT_SAMPLE_LEN])> {
    let full_scan = full_scan || pending.saw_rescan || pending.saw_remove;
    let indexed = source_index
        .iter()
        .filter(|(_, source)| full_scan && source.kind == SourceKind::Sqlite)
        .map(|(key, _)| key.clone());
    let changed = pending
        .paths
        .iter()
        .map(|path| path.canonicalize().unwrap_or_else(|_| path.clone()))
        .filter(|key| {
            source_index
                .get(key)
                .is_none_or(|source| source.kind == SourceKind::Sqlite)
        });
    let keys = indexed.chain(changed).collect::<BTreeSet<_>>();
    keys.into_iter()
        .filter_map(|key| {
            rechecks.remove(&key);
            // Re-checks read the same canonical path that the scan reads.
            let sample = sqlite_commit_sample(&key)?;
            Some((key, sample))
        })
        .collect()
}

/// Queue a scan of each store whose sample changed since its scan; drop a
/// window after its last delay.
fn take_due_sqlite_rechecks(
    rechecks: &mut BTreeMap<PathBuf, SqliteCommitRecheck>,
    pending: &mut PendingWatchChanges,
    now: Instant,
) {
    rechecks.retain(|path, recheck| {
        let Some(delay) = SQLITE_COMMIT_RECHECK_DELAYS.get(recheck.next) else {
            return false;
        };
        if now < recheck.scanned + *delay {
            return true;
        }
        recheck.next += 1;
        // SQLite truncates and rebuilds `-shm` when a first connection
        // reopens, so an unreadable sample waits for the next delay.
        match sqlite_commit_sample(path) {
            Some(sample) if sample != recheck.sample => {
                pending.paths.insert(path.clone());
                false
            }
            _ => recheck.next < SQLITE_COMMIT_RECHECK_DELAYS.len(),
        }
    });
}

fn next_sqlite_recheck(rechecks: &BTreeMap<PathBuf, SqliteCommitRecheck>) -> Option<Instant> {
    rechecks
        .values()
        .filter_map(|recheck| {
            SQLITE_COMMIT_RECHECK_DELAYS
                .get(recheck.next)
                .map(|delay| recheck.scanned + *delay)
        })
        .min()
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

    #[cfg(test)]
    fn absorb(&mut self, event: &NotifyEvent) {
        self.absorb_with_override(event, None);
    }

    #[cfg(test)]
    fn absorb_with_override(&mut self, event: &NotifyEvent, sqlite_override: Option<&Path>) {
        self.absorb_with_filter(
            event,
            &WatchPathFilter {
                sqlite_override: sqlite_override.map(Path::to_path_buf),
                exclusive_parent: None,
            },
        );
    }

    fn absorb_with_filter(&mut self, event: &NotifyEvent, filter: &WatchPathFilter) {
        if !watch_event_is_relevant(event, filter) {
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
            if let Some(path) = filter.normalize(path) {
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

fn watch_event_is_relevant(event: &NotifyEvent, filter: &WatchPathFilter) -> bool {
    event.need_rescan()
        || (matches!(event.kind, EventKind::Remove(_))
            && (event.paths.is_empty() || event.paths.iter().any(|path| !filter.ignores(path))))
        || (matches!(event.kind, EventKind::Create(_) | EventKind::Modify(_))
            && event
                .paths
                .iter()
                .any(|path| filter.normalize(path).is_some()))
}

fn sqlite_sidecar_path(database: &Path, suffix: &str) -> PathBuf {
    let mut path = database.as_os_str().to_os_string();
    path.push(suffix);
    path.into()
}

fn watch_paths_equal(left: &Path, right: &Path) -> bool {
    if left == right {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        let left = left.as_os_str().encode_wide().collect::<Vec<_>>();
        let right = right.as_os_str().encode_wide().collect::<Vec<_>>();
        let (Ok(left_len), Ok(right_len)) = (i32::try_from(left.len()), i32::try_from(right.len()))
        else {
            return false;
        };
        // SAFETY: both buffers remain live for the supplied UTF-16 unit lengths;
        // ordinal comparison reads only those buffers and performs no path I/O.
        let result = unsafe {
            windows_sys::Win32::Globalization::CompareStringOrdinal(
                left.as_ptr(),
                left_len,
                right.as_ptr(),
                right_len,
                1,
            )
        };
        result == 2
    }
    #[cfg(not(windows))]
    false
}

fn configured_reader_sidecar(path: &Path, database: Option<&Path>) -> bool {
    database.is_some_and(|database| {
        !watch_paths_equal(path, database)
            && ["-shm", "-journal"]
                .iter()
                .any(|suffix| watch_paths_equal(path, &sqlite_sidecar_path(database, suffix)))
    })
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
#[cfg(test)]
fn normalize_watch_event_path(path: &Path) -> Option<PathBuf> {
    normalize_watch_event_path_with_override(path, None)
}

fn normalize_watch_event_path_with_override(
    path: &Path,
    sqlite_override: Option<&Path>,
) -> Option<PathBuf> {
    if let Some(database) = sqlite_override {
        // An explicitly configured main file can itself have a sidecar-looking name.
        if watch_paths_equal(path, database)
            || watch_paths_equal(path, &sqlite_sidecar_path(database, "-wal"))
        {
            return Some(database.to_path_buf());
        }
        if configured_reader_sidecar(path, Some(database)) {
            return None;
        }
    }
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
mod tests;
