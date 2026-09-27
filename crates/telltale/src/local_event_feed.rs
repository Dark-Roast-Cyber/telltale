//! A bounded, read-only consumer for the local canonical Event 3.0 journal.
//!
//! `LocalEventFeed` owns no runtime, watcher, lock, cursor file, or delivery
//! state. An embedding host calls [`LocalEventFeed::poll`] on its own cadence.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::path::PathBuf;

use sha2::{Digest, Sha256};
use telltale_schema::event::{EVENT3_MAX_INPUT_BYTES, Event3ErrorCategory, Event3Record};
use telltale_sources::journal::{self, JournalDiscovery, JournalFile, JournalGeneration};
use telltale_sources::paths::{PathProfile, resolve_log_path};

const DEFAULT_MAX_EVENTS: usize = 256;
const DEFAULT_MAX_BYTES: usize = 1024 * 1024;
const DEFAULT_MAX_GENERATIONS: usize = 256;
const DEFAULT_MAX_DIRECTORY_ENTRIES: usize = 4096;
const DEFAULT_MAX_RECONCILIATIONS: usize = 16;
const DEFAULT_MAX_DEDUP_ENTRIES: usize = 256;
const DEFAULT_MAX_NOTICES: usize = 64;
const GENERATION_HEAD_BYTES: usize = 64;

/// Startup position for a feed.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum StartupMode {
    Beginning,
    End,
    Recent { max_events: usize, max_bytes: usize },
}

/// Resource bounds applied to every feed instance and poll.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct FeedLimits {
    pub max_events_per_poll: usize,
    pub max_bytes_per_poll: usize,
    pub max_frame_bytes: usize,
    pub max_generations: usize,
    pub max_directory_entries: usize,
    pub max_reconciliations_per_poll: usize,
    pub max_dedup_entries: usize,
    pub max_notices: usize,
}

impl Default for FeedLimits {
    fn default() -> Self {
        Self {
            max_events_per_poll: DEFAULT_MAX_EVENTS,
            max_bytes_per_poll: DEFAULT_MAX_BYTES,
            max_frame_bytes: EVENT3_MAX_INPUT_BYTES,
            max_generations: DEFAULT_MAX_GENERATIONS,
            max_directory_entries: DEFAULT_MAX_DIRECTORY_ENTRIES,
            max_reconciliations_per_poll: DEFAULT_MAX_RECONCILIATIONS,
            max_dedup_entries: DEFAULT_MAX_DEDUP_ENTRIES,
            max_notices: DEFAULT_MAX_NOTICES,
        }
    }
}

/// Immutable feed configuration. Constructing one does not access the
/// filesystem; missing journal paths are valid waiting states.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct LocalEventFeedConfig {
    pub path: PathBuf,
    pub startup: StartupMode,
    pub limits: FeedLimits,
}

impl LocalEventFeedConfig {
    pub fn new(path: impl Into<PathBuf>, startup: StartupMode) -> Self {
        Self {
            path: path.into(),
            startup,
            limits: FeedLimits::default(),
        }
    }

    pub fn for_profile(
        profile: PathProfile,
        explicit: Option<PathBuf>,
        startup: StartupMode,
    ) -> Self {
        Self::new(resolve_log_path(profile, explicit), startup)
    }

    pub fn from_profile(
        profile: PathProfile,
        explicit: Option<PathBuf>,
        startup: StartupMode,
    ) -> Self {
        Self::for_profile(profile, explicit, startup)
    }

    pub fn with_limits(mut self, limits: FeedLimits) -> Self {
        self.limits = limits;
        self
    }
}

/// Stable, privacy-safe configuration/error codes.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum LocalEventFeedErrorCode {
    InvalidLimit,
    InvalidRecentLimit,
}

/// Configuration error that never stores a path or input-derived text.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct LocalEventFeedError {
    code: LocalEventFeedErrorCode,
}

impl LocalEventFeedError {
    pub const fn code(self) -> LocalEventFeedErrorCode {
        self.code
    }
}

impl fmt::Display for LocalEventFeedError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let code = match self.code {
            LocalEventFeedErrorCode::InvalidLimit => "invalid_limit",
            LocalEventFeedErrorCode::InvalidRecentLimit => "invalid_recent_limit",
        };
        write!(formatter, "local event feed configuration error: {code}")
    }
}

impl std::error::Error for LocalEventFeedError {}

/// Stable recoverable notice codes. Notice values contain no path, OS error,
/// parser diagnostic, raw JSON, or event evidence.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum FeedNoticeCode {
    JournalUnavailable,
    UnsafeFile,
    DirectoryBound,
    GenerationBound,
    GenerationGap,
    ReplacedGeneration,
    TruncatedGeneration,
    ReadRace,
    StartupBoundaryUnavailable,
    ActivePartialFrame,
    NonActivePartialFrame,
    OversizedFrame,
    ParserMalformed,
    ParserVersion,
    ParserStructure,
    ParserIdentity,
    ParserSemantic,
    ParserFamily,
    ReplaySuppressed,
    EventIdCollision,
    DedupEvicted,
    NoticeBound,
}

/// A bounded static-code notice with an aggregated count.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct FeedNotice {
    pub code: FeedNoticeCode,
    pub count: u64,
}

impl fmt::Display for FeedNoticeCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let code = match self {
            Self::JournalUnavailable => "journal_unavailable",
            Self::UnsafeFile => "unsafe_file",
            Self::DirectoryBound => "directory_bound",
            Self::GenerationBound => "generation_bound",
            Self::GenerationGap => "generation_gap",
            Self::ReplacedGeneration => "replaced_generation",
            Self::TruncatedGeneration => "truncated_generation",
            Self::ReadRace => "read_race",
            Self::StartupBoundaryUnavailable => "startup_boundary_unavailable",
            Self::ActivePartialFrame => "active_partial_frame",
            Self::NonActivePartialFrame => "non_active_partial_frame",
            Self::OversizedFrame => "oversized_frame",
            Self::ParserMalformed => "parser_malformed",
            Self::ParserVersion => "parser_version",
            Self::ParserStructure => "parser_structure",
            Self::ParserIdentity => "parser_identity",
            Self::ParserSemantic => "parser_semantic",
            Self::ParserFamily => "parser_family",
            Self::ReplaySuppressed => "replay_suppressed",
            Self::EventIdCollision => "event_id_collision",
            Self::DedupEvicted => "dedup_evicted",
            Self::NoticeBound => "notice_bound",
        };
        formatter.write_str(code)
    }
}

impl fmt::Display for FeedNotice {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "local event feed notice: {} ({})",
            self.code, self.count
        )
    }
}

/// One bounded poll result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeedBatch {
    pub records: Vec<Event3Record>,
    pub notices: Vec<FeedNotice>,
    pub bytes_read: usize,
    pub caught_up: bool,
    pub suppressed_replays: u64,
    pub event_id_collisions: u64,
    pub dedup_evictions: u64,
}

#[derive(Debug)]
struct NoticeSink {
    notices: Vec<FeedNotice>,
    max: usize,
}

impl NoticeSink {
    fn new(max: usize) -> Self {
        Self {
            notices: Vec::new(),
            max,
        }
    }

    fn add(&mut self, code: FeedNoticeCode) {
        if let Some(notice) = self.notices.iter_mut().find(|notice| notice.code == code) {
            notice.count = notice.count.saturating_add(1);
            return;
        }
        if self.notices.len() < self.max {
            self.notices.push(FeedNotice { code, count: 1 });
        } else if let Some(notice) = self
            .notices
            .iter_mut()
            .find(|notice| notice.code == FeedNoticeCode::NoticeBound)
        {
            notice.count = notice.count.saturating_add(1);
        } else if self.max > 0 {
            self.notices[self.max - 1] = FeedNotice {
                code: FeedNoticeCode::NoticeBound,
                count: 1,
            };
        }
    }

    fn finish(self) -> Vec<FeedNotice> {
        self.notices
    }
}

struct Cursor {
    identity: String,
    path: PathBuf,
    head: Option<Vec<u8>>,
    is_active: bool,
    offset: u64,
    safe_offset: u64,
    frame_start: u64,
    frame: Vec<u8>,
    discarding: bool,
    skipping_until_lf: bool,
    initialized: bool,
    complete: bool,
    unresolved: bool,
    partial_reported: bool,
    missing_reported: bool,
}

impl fmt::Debug for Cursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Cursor")
            .field("identity", &self.identity)
            .field("path", &self.path)
            .field("head_len", &self.head.as_ref().map_or(0, |head| head.len()))
            .field("is_active", &self.is_active)
            .field("offset", &self.offset)
            .field("safe_offset", &self.safe_offset)
            .field("frame_start", &self.frame_start)
            .field("frame_len", &self.frame.len())
            .field("discarding", &self.discarding)
            .field("skipping_until_lf", &self.skipping_until_lf)
            .field("initialized", &self.initialized)
            .field("complete", &self.complete)
            .field("unresolved", &self.unresolved)
            .field("partial_reported", &self.partial_reported)
            .field("missing_reported", &self.missing_reported)
            .finish()
    }
}

impl Cursor {
    fn new(generation: &JournalGeneration) -> Self {
        Self {
            identity: generation.identity.clone(),
            path: generation.path.clone(),
            head: None,
            is_active: generation.is_active,
            offset: 0,
            safe_offset: 0,
            frame_start: 0,
            frame: Vec::new(),
            discarding: false,
            skipping_until_lf: false,
            initialized: false,
            complete: false,
            unresolved: false,
            partial_reported: false,
            missing_reported: false,
        }
    }

    fn set_generation(&mut self, generation: &JournalGeneration) {
        if self.is_active && !generation.is_active {
            self.partial_reported = false;
        }
        self.path.clone_from(&generation.path);
        self.is_active = generation.is_active;
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum RecentPhase {
    Scanning,
    Draining,
    Live,
}

#[derive(Debug)]
struct RecentState {
    floor_identity: String,
    floor_offset: u64,
    snapshot_identity: String,
    snapshot_offset: Option<u64>,
    excluded: HashSet<String>,
    scan_identities: HashSet<String>,
    live_seen: HashSet<String>,
    scan_targets: HashMap<String, Option<u64>>,
    scan_order: Vec<String>,
    selected: VecDeque<Event3Record>,
    phase: RecentPhase,
    max_events: usize,
    max_bytes: usize,
    boundary_established: bool,
    floor_seen_non_active: bool,
}

impl RecentState {
    fn authentic_floor_index(&self, generations: &[JournalGeneration]) -> Option<usize> {
        let floor_index = generations
            .iter()
            .position(|generation| generation.identity == self.floor_identity)?;
        if self.floor_seen_non_active && generations[floor_index].is_active {
            return None;
        }
        // A startup floor cannot sort after a generation already eligible for scan/live reads.
        // Such an identity now belongs to a later file, not the original startup floor.
        if generations[..floor_index].iter().any(|generation| {
            !self.excluded.contains(&generation.identity)
                && (self.live_seen.contains(&generation.identity)
                    || self.scan_identities.contains(&generation.identity))
        }) {
            None
        } else {
            Some(floor_index)
        }
    }
}

#[derive(Debug)]
struct PollContext {
    records: Vec<Event3Record>,
    notices: NoticeSink,
    bytes_read: usize,
    suppressed_replays: u64,
    event_id_collisions: u64,
    dedup_evictions: u64,
    max_events: usize,
    max_bytes: usize,
    max_frame: usize,
    reconciliations: usize,
    max_reconciliations: usize,
    budget_exhausted: bool,
    generation_bound_reached: bool,
    lifecycle_gap: bool,
}

impl PollContext {
    fn new(limits: FeedLimits) -> Self {
        Self {
            records: Vec::new(),
            notices: NoticeSink::new(limits.max_notices),
            bytes_read: 0,
            suppressed_replays: 0,
            event_id_collisions: 0,
            dedup_evictions: 0,
            max_events: limits.max_events_per_poll,
            max_bytes: limits.max_bytes_per_poll,
            max_frame: limits.max_frame_bytes,
            reconciliations: 0,
            max_reconciliations: limits.max_reconciliations_per_poll,
            budget_exhausted: false,
            generation_bound_reached: false,
            lifecycle_gap: false,
        }
    }

    fn can_read(&mut self) -> bool {
        if self.budget_exhausted
            || self.bytes_read >= self.max_bytes
            || self.records.len() >= self.max_events
        {
            self.budget_exhausted = true;
            false
        } else {
            true
        }
    }

    fn can_read_bytes(&mut self) -> bool {
        if self.budget_exhausted || self.bytes_read >= self.max_bytes {
            self.budget_exhausted = true;
            false
        } else {
            true
        }
    }

    fn reconcile(&mut self) -> bool {
        self.reconciliations += 1;
        if self.reconciliations > self.max_reconciliations {
            self.budget_exhausted = true;
            false
        } else {
            true
        }
    }

    fn generation_gap(&mut self) {
        self.lifecycle_gap = true;
        self.notices.add(FeedNoticeCode::GenerationGap);
    }
}

/// Runtime-neutral, in-memory local journal poller.
#[derive(Debug)]
pub struct LocalEventFeed {
    config: LocalEventFeedConfig,
    cursors: HashMap<String, Cursor>,
    dedup: HashMap<String, [u8; 32]>,
    dedup_order: VecDeque<String>,
    started: bool,
    active_identity: Option<String>,
    recent: Option<RecentState>,
    replacement_notice_pending: bool,
}

impl LocalEventFeed {
    pub fn from_path(
        path: impl Into<PathBuf>,
        startup: StartupMode,
    ) -> Result<Self, LocalEventFeedError> {
        Self::new(LocalEventFeedConfig::new(path, startup))
    }

    pub fn new(config: LocalEventFeedConfig) -> Result<Self, LocalEventFeedError> {
        validate_config(&config)?;
        Ok(Self {
            config,
            cursors: HashMap::new(),
            dedup: HashMap::new(),
            dedup_order: VecDeque::new(),
            started: false,
            active_identity: None,
            recent: None,
            replacement_notice_pending: false,
        })
    }

    pub fn config(&self) -> &LocalEventFeedConfig {
        &self.config
    }

    pub fn poll(&mut self) -> Result<FeedBatch, LocalEventFeedError> {
        let mut context = PollContext::new(self.config.limits);
        let discovery = match journal::discover_generations(
            &self.config.path,
            self.config.limits.max_directory_entries,
        ) {
            Ok(discovery) => discovery,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                context.notices.add(FeedNoticeCode::JournalUnavailable);
                self.reset_waiting_state();
                return Ok(self.finish(context, false));
            }
            Err(error) => {
                let code = if error.kind() == std::io::ErrorKind::Other {
                    FeedNoticeCode::UnsafeFile
                } else {
                    FeedNoticeCode::JournalUnavailable
                };
                context.notices.add(code);
                return Ok(self.finish(context, false));
            }
        };

        let directory_bound_reached = discovery.directory_bound_reached;
        let generations = self.limit_generations(discovery, &mut context);
        if generations.is_empty() {
            context.notices.add(FeedNoticeCode::JournalUnavailable);
            self.reset_waiting_state();
            return Ok(self.finish(context, false));
        }

        self.reconcile_missing(&generations, &mut context);
        if self.replacement_notice_pending {
            context.notices.add(FeedNoticeCode::ReplacedGeneration);
            self.replacement_notice_pending = false;
        }
        self.cursors.retain(|identity, _| {
            generations
                .iter()
                .any(|generation| generation.identity == *identity)
        });
        self.retain_recent_generations(&generations);
        for generation in &generations {
            self.cursors
                .entry(generation.identity.clone())
                .and_modify(|cursor| cursor.set_generation(generation))
                .or_insert_with(|| Cursor::new(generation));
        }

        let current_active = generations
            .last()
            .map(|generation| generation.identity.clone());
        if let (Some(previous), Some(current)) = (&self.active_identity, &current_active)
            && previous != current
            && !generations
                .iter()
                .any(|generation| &generation.identity == previous)
        {
            context.notices.add(FeedNoticeCode::ReplacedGeneration);
        }
        self.active_identity = current_active;

        if !self.started {
            if !self.initialize_startup(&generations, &mut context) {
                return Ok(self.finish(context, false));
            }
            self.started = true;
        }

        if self.recent.is_some() {
            self.poll_recent(&generations, &mut context);
        } else {
            for generation in &generations {
                if !context.can_read() {
                    break;
                }
                let Some(cursor) = self.cursors.get_mut(&generation.identity) else {
                    continue;
                };
                process_generation(
                    cursor,
                    &mut context,
                    &mut self.dedup,
                    &mut self.dedup_order,
                    self.config.limits.max_dedup_entries,
                    GenerationOptions {
                        scanning_recent: false,
                        stop_offset: None,
                        scan_target: None,
                        recent: None,
                        minimum_offset: None,
                    },
                );
            }
        }

        let mut caught_up = !context.budget_exhausted
            && !directory_bound_reached
            && !context.generation_bound_reached
            && !context.lifecycle_gap;
        if directory_bound_reached {
            context.notices.add(FeedNoticeCode::DirectoryBound);
        }
        for (index, generation) in generations.iter().enumerate() {
            if self.recent.is_some() && !self.recent_generation_allowed(&generations, index) {
                continue;
            }
            if let Some(cursor) = self.cursors.get(&generation.identity) {
                if cursor.unresolved
                    || !cursor.complete
                    || !cursor.frame.is_empty()
                    || cursor.discarding
                    || cursor.skipping_until_lf
                {
                    caught_up = false;
                }
            } else {
                caught_up = false;
            }
        }
        if self
            .recent
            .as_ref()
            .is_some_and(|recent| recent.phase != RecentPhase::Live)
        {
            caught_up = false;
        }
        Ok(self.finish(context, caught_up))
    }

    fn poll_recent(&mut self, generations: &[JournalGeneration], context: &mut PollContext) {
        if self
            .recent
            .as_ref()
            .is_some_and(|recent| recent.phase == RecentPhase::Scanning)
        {
            self.scan_recent(generations, context);
            if self.recent_scan_complete(generations)
                && let Some(recent) = self.recent.as_mut()
            {
                recent.phase = RecentPhase::Draining;
            }
        }

        if self
            .recent
            .as_ref()
            .is_some_and(|recent| recent.phase == RecentPhase::Draining)
        {
            self.drain_recent(context);
            if self
                .recent
                .as_ref()
                .is_some_and(|recent| recent.selected.is_empty())
                && let Some(recent) = self.recent.as_mut()
            {
                recent.phase = RecentPhase::Live;
            }
        }

        if !self
            .recent
            .as_ref()
            .is_some_and(|recent| recent.phase == RecentPhase::Live)
        {
            return;
        }

        for (index, generation) in generations.iter().enumerate() {
            if !self.recent_generation_allowed(generations, index) {
                continue;
            }
            if !context.can_read() {
                break;
            }
            let Some(cursor) = self.cursors.get_mut(&generation.identity) else {
                continue;
            };
            let minimum_offset = self.recent.as_ref().and_then(|recent| {
                (recent.authentic_floor_index(generations) == Some(index))
                    .then_some(recent.floor_offset)
            });
            process_generation(
                cursor,
                context,
                &mut self.dedup,
                &mut self.dedup_order,
                self.config.limits.max_dedup_entries,
                GenerationOptions {
                    scanning_recent: false,
                    stop_offset: None,
                    scan_target: None,
                    recent: None,
                    minimum_offset,
                },
            );
        }
    }

    fn recent_generation_allowed(
        &mut self,
        generations: &[JournalGeneration],
        index: usize,
    ) -> bool {
        let Some(recent) = self.recent.as_ref() else {
            return true;
        };
        let generation = &generations[index];
        if recent.excluded.contains(&generation.identity) {
            return false;
        }
        let allowed = if let Some(floor_index) = recent.authentic_floor_index(generations) {
            index >= floor_index
        } else if let Some(first_known) = generations.iter().position(|candidate| {
            (recent.scan_identities.contains(&candidate.identity)
                || recent.live_seen.contains(&candidate.identity))
                && !recent.excluded.contains(&candidate.identity)
        }) {
            index >= first_known
        } else {
            index + 1 == generations.len()
        };
        if allowed {
            let recent = self.recent.as_mut().expect("recent state");
            recent.live_seen.insert(generation.identity.clone());
            recent
                .live_seen
                .retain(|identity| !recent.excluded.contains(identity));
        }
        allowed
    }

    fn retain_recent_generations(&mut self, generations: &[JournalGeneration]) {
        let current = generations
            .iter()
            .map(|generation| generation.identity.as_str())
            .collect::<HashSet<_>>();
        let Some(recent) = self.recent.as_mut() else {
            return;
        };
        recent
            .scan_identities
            .retain(|identity| current.contains(identity.as_str()));
        recent
            .scan_targets
            .retain(|identity, _| current.contains(identity.as_str()));
        recent
            .scan_order
            .retain(|identity| current.contains(identity.as_str()));
        recent
            .live_seen
            .retain(|identity| current.contains(identity.as_str()));
        recent
            .excluded
            .retain(|identity| current.contains(identity.as_str()));
        recent.floor_seen_non_active |= generations.iter().any(|generation| {
            generation.identity == recent.floor_identity && !generation.is_active
        });
    }

    fn scan_recent(&mut self, generations: &[JournalGeneration], context: &mut PollContext) {
        self.refresh_recent_boundaries(generations, context);
        let Some(recent) = self.recent.as_mut() else {
            return;
        };
        if !recent.boundary_established {
            return;
        }
        let floor_index = recent.authentic_floor_index(generations);
        for (index, generation) in generations.iter().enumerate() {
            if !recent.scan_identities.contains(&generation.identity)
                || recent.excluded.contains(&generation.identity)
            {
                continue;
            }
            let Some(cursor) = self.cursors.get_mut(&generation.identity) else {
                continue;
            };
            let stop_offset = if recent.snapshot_identity == generation.identity {
                recent.snapshot_offset
            } else {
                None
            };
            let Some(_) = recent
                .scan_targets
                .get(&generation.identity)
                .and_then(|target| *target)
            else {
                continue;
            };
            recent.live_seen.insert(generation.identity.clone());
            if !context.can_read_bytes() {
                break;
            }
            let scan_target = recent
                .scan_targets
                .get_mut(&generation.identity)
                .and_then(|target| target.as_mut());
            let minimum_offset = (floor_index == Some(index)).then_some(recent.floor_offset);
            process_generation(
                cursor,
                context,
                &mut self.dedup,
                &mut self.dedup_order,
                self.config.limits.max_dedup_entries,
                GenerationOptions {
                    scanning_recent: true,
                    stop_offset,
                    scan_target,
                    recent: Some((&mut recent.selected, recent.max_events)),
                    minimum_offset,
                },
            );
        }
    }

    fn recent_scan_complete(&self, generations: &[JournalGeneration]) -> bool {
        let Some(recent) = self.recent.as_ref() else {
            return false;
        };
        if recent.scan_identities.is_empty() {
            return recent.boundary_established || recent.scan_order.is_empty();
        }
        if !recent.boundary_established || recent.snapshot_offset.is_none() {
            return false;
        }
        for identity in &recent.scan_identities {
            if !generations
                .iter()
                .any(|generation| generation.identity == *identity)
            {
                continue;
            }
            let Some(cursor) = self.cursors.get(identity) else {
                return false;
            };
            if cursor.unresolved {
                return false;
            }
            let Some(target) = recent.scan_targets.get(identity).and_then(|target| *target) else {
                return false;
            };
            if cursor.offset < target {
                return false;
            }
        }
        true
    }

    fn refresh_recent_boundaries(
        &mut self,
        generations: &[JournalGeneration],
        context: &mut PollContext,
    ) {
        let Some(recent) = self.recent.as_mut() else {
            return;
        };
        if recent.boundary_established {
            return;
        }
        let unknown = recent
            .scan_order
            .iter()
            .filter(|identity| {
                recent
                    .scan_targets
                    .get(*identity)
                    .is_none_or(Option::is_none)
            })
            .cloned()
            .collect::<Vec<_>>();
        for identity in unknown {
            let Some(generation) = generations
                .iter()
                .find(|generation| generation.identity == identity)
            else {
                context
                    .notices
                    .add(FeedNoticeCode::StartupBoundaryUnavailable);
                continue;
            };
            match JournalFile::open(&generation.path) {
                Ok(file) if file.identity() == generation.identity => {
                    let length = file.len();
                    if let Some(target) = recent.scan_targets.get_mut(&identity) {
                        *target = Some(length);
                    }
                    if recent.snapshot_identity == identity {
                        recent.snapshot_offset = Some(length);
                    }
                }
                Ok(_) => {
                    context.notices.add(FeedNoticeCode::ReplacedGeneration);
                    context
                        .notices
                        .add(FeedNoticeCode::StartupBoundaryUnavailable);
                }
                Err(_) => {
                    context.notices.add(FeedNoticeCode::JournalUnavailable);
                    context
                        .notices
                        .add(FeedNoticeCode::StartupBoundaryUnavailable);
                    if !context.reconcile() {
                        return;
                    }
                }
            }
        }
        if recent.snapshot_offset.is_none() {
            recent.snapshot_offset = recent
                .scan_targets
                .get(&recent.snapshot_identity)
                .and_then(|target| *target);
        }
        let ready = recent.scan_order.iter().all(|identity| {
            recent
                .scan_targets
                .get(identity)
                .is_some_and(Option::is_some)
        }) && recent.snapshot_offset.is_some();
        if ready {
            self.establish_recent_boundary(generations, context);
        }
    }

    fn establish_recent_boundary(
        &mut self,
        generations: &[JournalGeneration],
        context: &mut PollContext,
    ) {
        let Some(recent) = self.recent.as_mut() else {
            return;
        };
        if recent.boundary_established {
            return;
        }
        let lengths = recent
            .scan_order
            .iter()
            .map(|identity| recent.scan_targets.get(identity).and_then(|target| *target))
            .collect::<Option<Vec<_>>>();
        let Some(lengths) = lengths else {
            return;
        };
        let newest_index = lengths.len().saturating_sub(1);
        let mut floor_index = newest_index;
        let mut floor_offset = 0_u64;
        let mut remaining = recent.max_bytes as u64;
        for index in (0..lengths.len()).rev() {
            if remaining == 0 {
                break;
            }
            let length = lengths[index];
            let amount = length.min(remaining);
            if amount > 0 {
                floor_index = index;
                floor_offset = length - amount;
                remaining -= amount;
            }
        }

        recent.floor_identity = recent.scan_order[floor_index].clone();
        recent.floor_offset = floor_offset;
        recent.floor_seen_non_active |= generations.iter().any(|generation| {
            generation.identity == recent.floor_identity && !generation.is_active
        });
        recent.excluded = recent.scan_order[..floor_index].iter().cloned().collect();
        recent.scan_identities = recent.scan_order[floor_index..].iter().cloned().collect();
        recent.boundary_established = true;

        for (index, identity) in recent.scan_order.iter().enumerate() {
            let Some(cursor) = self.cursors.get_mut(identity) else {
                continue;
            };
            cursor.initialized = true;
            cursor.frame.clear();
            cursor.discarding = false;
            cursor.skipping_until_lf = false;
            cursor.safe_offset = 0;
            cursor.frame_start = 0;
            cursor.offset = 0;
            cursor.unresolved = false;
            cursor.partial_reported = false;
            if index < floor_index {
                cursor.complete = true;
                continue;
            }
            cursor.complete = false;
            if index == floor_index {
                cursor.offset = floor_offset;
                cursor.safe_offset = floor_offset;
                cursor.frame_start = floor_offset;
                if floor_offset > 0 {
                    let Some(generation) = generations
                        .iter()
                        .find(|generation| generation.identity == *identity)
                    else {
                        cursor.skipping_until_lf = true;
                        context
                            .notices
                            .add(FeedNoticeCode::StartupBoundaryUnavailable);
                        continue;
                    };
                    match JournalFile::open(&generation.path) {
                        Ok(mut file) if file.identity() == *identity => {
                            set_minimum_boundary(cursor, floor_offset, &mut file, context);
                        }
                        Ok(_) | Err(_) => {
                            cursor.skipping_until_lf = true;
                            context
                                .notices
                                .add(FeedNoticeCode::StartupBoundaryUnavailable);
                        }
                    }
                }
            }
        }
    }

    fn drain_recent(&mut self, context: &mut PollContext) {
        let Some(recent) = self.recent.as_mut() else {
            return;
        };
        while context.records.len() < context.max_events {
            let Some(record) = recent.selected.pop_front() else {
                break;
            };
            context.records.push(record);
        }
    }

    fn limit_generations(
        &self,
        discovery: JournalDiscovery,
        context: &mut PollContext,
    ) -> Vec<JournalGeneration> {
        if discovery.generations.len() <= self.config.limits.max_generations {
            return discovery.generations;
        }
        context.notices.add(FeedNoticeCode::GenerationBound);
        context.generation_bound_reached = true;
        let keep = self.config.limits.max_generations.max(1);
        let generations = discovery.generations;
        let first = generations.len().saturating_sub(keep);
        generations.into_iter().skip(first).collect()
    }

    fn reconcile_missing(&mut self, generations: &[JournalGeneration], context: &mut PollContext) {
        for (identity, cursor) in &mut self.cursors {
            if generations
                .iter()
                .any(|generation| &generation.identity == identity)
            {
                continue;
            }
            if (!cursor.complete || cursor.unresolved || !cursor.frame.is_empty())
                && !cursor.missing_reported
            {
                cursor.missing_reported = true;
                cursor.unresolved = true;
                context.generation_gap();
            }
        }
    }

    fn initialize_startup(
        &mut self,
        generations: &[JournalGeneration],
        context: &mut PollContext,
    ) -> bool {
        match self.config.startup {
            StartupMode::Beginning => {
                for generation in generations {
                    if let Some(cursor) = self.cursors.get_mut(&generation.identity) {
                        cursor.initialized = true;
                    }
                }
                true
            }
            StartupMode::End => {
                for generation in generations {
                    let Some(cursor) = self.cursors.get_mut(&generation.identity) else {
                        continue;
                    };
                    cursor.initialized = true;
                    if !generation.is_active {
                        match JournalFile::open(&generation.path) {
                            Ok(file) => {
                                cursor.offset = file.len();
                                cursor.safe_offset = cursor.offset;
                                cursor.frame_start = cursor.offset;
                                cursor.complete = true;
                                if cursor.offset > 0 {
                                    if !context.can_read_bytes() {
                                        cursor.complete = false;
                                        cursor.unresolved = true;
                                        context.notices.add(FeedNoticeCode::NonActivePartialFrame);
                                    } else {
                                        let mut file = file;
                                        match file.read_at(cursor.offset - 1, 1) {
                                            Ok(bytes) if bytes.len() == 1 => {
                                                context.bytes_read =
                                                    context.bytes_read.saturating_add(1);
                                                if bytes[0] != b'\n' {
                                                    cursor.complete = false;
                                                    cursor.unresolved = true;
                                                    context
                                                        .notices
                                                        .add(FeedNoticeCode::NonActivePartialFrame);
                                                }
                                            }
                                            _ => {
                                                cursor.complete = false;
                                                cursor.unresolved = true;
                                                context
                                                    .notices
                                                    .add(FeedNoticeCode::NonActivePartialFrame);
                                            }
                                        }
                                    }
                                }
                            }
                            Err(_) => {
                                cursor.unresolved = true;
                                context.generation_gap();
                                if !context.reconcile() {
                                    return false;
                                }
                            }
                        }
                    }
                }
                if let Some(active) = generations.last() {
                    self.initialize_end_active(active, context);
                }
                true
            }
            StartupMode::Recent {
                max_events,
                max_bytes,
            } => {
                self.initialize_recent(generations, max_events, max_bytes, context);
                true
            }
        }
    }

    fn initialize_end_active(&mut self, generation: &JournalGeneration, context: &mut PollContext) {
        let Some(cursor) = self.cursors.get_mut(&generation.identity) else {
            return;
        };
        let Ok(mut file) = JournalFile::open(&generation.path) else {
            cursor.unresolved = true;
            context.notices.add(FeedNoticeCode::JournalUnavailable);
            if !context.reconcile() {
                return;
            }
            return;
        };
        let length = file.len();
        let requested = self.config.limits.max_frame_bytes.min(context.max_bytes);
        let start = length.saturating_sub(requested as u64);
        let amount = (length - start) as usize;
        let bytes = match file.read_at(start, amount) {
            Ok(bytes) => bytes,
            Err(_) => {
                cursor.unresolved = true;
                context.notices.add(FeedNoticeCode::ReadRace);
                if !context.reconcile() {
                    return;
                }
                return;
            }
        };
        context.bytes_read = context.bytes_read.saturating_add(bytes.len());
        if bytes.len() < (length - start) as usize {
            context
                .notices
                .add(FeedNoticeCode::StartupBoundaryUnavailable);
        }
        if let Some(last_lf) = bytes.iter().rposition(|byte| *byte == b'\n') {
            let tail = &bytes[last_lf + 1..];
            cursor.offset = length;
            cursor.safe_offset = start + last_lf as u64 + 1;
            cursor.frame_start = start + last_lf as u64 + 1;
            cursor.frame.clear();
            cursor.frame.extend_from_slice(tail);
            cursor.complete = tail.is_empty();
            cursor.discarding = tail.len() > context.max_frame;
            cursor.partial_reported = false;
        } else {
            cursor.offset = length;
            cursor.safe_offset = 0;
            cursor.frame_start = start;
            if start == 0 && bytes.len() <= context.max_frame {
                cursor.frame = bytes;
                cursor.discarding = false;
            } else {
                cursor.frame.clear();
                cursor.discarding = true;
            }
            cursor.complete = false;
            context
                .notices
                .add(FeedNoticeCode::StartupBoundaryUnavailable);
        }
    }

    fn initialize_recent(
        &mut self,
        generations: &[JournalGeneration],
        max_events: usize,
        max_bytes: usize,
        context: &mut PollContext,
    ) {
        let newest_index = generations.len().saturating_sub(1);
        let snapshot_identity = generations[newest_index].identity.clone();
        let mut candidate = Vec::new();
        let mut accumulated = 0_u64;
        for generation in generations.iter().rev() {
            let length = match JournalFile::open(&generation.path) {
                Ok(file) if file.identity() == generation.identity => Some(file.len()),
                Ok(_) => {
                    context.notices.add(FeedNoticeCode::ReplacedGeneration);
                    context
                        .notices
                        .add(FeedNoticeCode::StartupBoundaryUnavailable);
                    None
                }
                Err(_) => {
                    context.notices.add(FeedNoticeCode::JournalUnavailable);
                    if !context.reconcile() {
                        break;
                    }
                    None
                }
            };
            candidate.push((generation.identity.clone(), length));
            match length {
                Some(length) => {
                    accumulated = accumulated.saturating_add(length);
                    if accumulated >= max_bytes as u64 {
                        break;
                    }
                }
                None => break,
            }
        }
        candidate.reverse();
        let scan_order = candidate
            .iter()
            .map(|(identity, _)| identity.clone())
            .collect::<Vec<_>>();
        let scan_targets = candidate.into_iter().collect::<HashMap<_, _>>();
        let snapshot_offset = scan_targets
            .get(&snapshot_identity)
            .and_then(|target| *target);
        let boundary_established = scan_targets.values().all(Option::is_some);

        for generation in generations {
            let Some(cursor) = self.cursors.get_mut(&generation.identity) else {
                continue;
            };
            cursor.initialized = true;
            cursor.frame.clear();
            cursor.discarding = false;
            cursor.skipping_until_lf = false;
            cursor.safe_offset = 0;
            cursor.frame_start = 0;
            cursor.offset = 0;
            cursor.unresolved = false;
            cursor.partial_reported = false;
            cursor.complete = false;
        }

        self.recent = Some(RecentState {
            floor_identity: snapshot_identity.clone(),
            floor_offset: 0,
            snapshot_identity,
            snapshot_offset,
            excluded: HashSet::new(),
            scan_identities: HashSet::new(),
            live_seen: HashSet::new(),
            scan_targets,
            scan_order,
            selected: VecDeque::new(),
            phase: RecentPhase::Scanning,
            max_events,
            max_bytes,
            boundary_established: false,
            floor_seen_non_active: false,
        });
        if !boundary_established {
            context
                .notices
                .add(FeedNoticeCode::StartupBoundaryUnavailable);
        }
        if boundary_established {
            self.establish_recent_boundary(generations, context);
        }
    }

    fn finish(&self, context: PollContext, caught_up: bool) -> FeedBatch {
        FeedBatch {
            records: context.records,
            notices: context.notices.finish(),
            bytes_read: context.bytes_read,
            caught_up,
            suppressed_replays: context.suppressed_replays,
            event_id_collisions: context.event_id_collisions,
            dedup_evictions: context.dedup_evictions,
        }
    }

    fn reset_waiting_state(&mut self) {
        self.replacement_notice_pending = self.started
            || self.active_identity.is_some()
            || self.recent.is_some()
            || !self.cursors.is_empty()
            || self.replacement_notice_pending;
        self.cursors.clear();
        self.active_identity = None;
        self.recent = None;
        self.started = false;
    }
}

fn validate_config(config: &LocalEventFeedConfig) -> Result<(), LocalEventFeedError> {
    let limits = config.limits;
    if limits.max_events_per_poll == 0
        || limits.max_bytes_per_poll == 0
        || limits.max_frame_bytes == 0
        || limits.max_frame_bytes > EVENT3_MAX_INPUT_BYTES
        || limits.max_generations == 0
        || limits.max_directory_entries == 0
        || limits.max_reconciliations_per_poll == 0
        || limits.max_dedup_entries == 0
        || limits.max_notices == 0
    {
        return Err(LocalEventFeedError {
            code: LocalEventFeedErrorCode::InvalidLimit,
        });
    }
    if let StartupMode::Recent {
        max_events,
        max_bytes,
    } = config.startup
        && (max_events == 0 || max_bytes == 0)
    {
        return Err(LocalEventFeedError {
            code: LocalEventFeedErrorCode::InvalidRecentLimit,
        });
    }
    Ok(())
}

struct GenerationOptions<'a> {
    scanning_recent: bool,
    stop_offset: Option<u64>,
    scan_target: Option<&'a mut u64>,
    recent: Option<(&'a mut VecDeque<Event3Record>, usize)>,
    minimum_offset: Option<u64>,
}

fn process_generation(
    cursor: &mut Cursor,
    context: &mut PollContext,
    dedup: &mut HashMap<String, [u8; 32]>,
    dedup_order: &mut VecDeque<String>,
    max_dedup_entries: usize,
    mut options: GenerationOptions<'_>,
) {
    let Ok(mut file) = JournalFile::open(&cursor.path) else {
        cursor.unresolved = true;
        context.notices.add(FeedNoticeCode::JournalUnavailable);
        if !context.reconcile() {
            return;
        }
        return;
    };
    if file.identity() != cursor.identity {
        cursor.unresolved = true;
        context.notices.add(FeedNoticeCode::ReplacedGeneration);
        return;
    }
    let length = file.len();
    let mut truncated = false;
    let mut floor_boundary_reset = false;
    if length < cursor.offset {
        truncated = true;
        context.notices.add(FeedNoticeCode::TruncatedGeneration);
        let reset = if cursor.safe_offset <= length {
            cursor.safe_offset
        } else {
            0
        };
        cursor.offset = options
            .minimum_offset
            .map_or(reset, |minimum| reset.max(minimum).min(length));
        cursor.safe_offset = cursor.offset;
        cursor.frame_start = cursor.offset;
        cursor.frame.clear();
        cursor.discarding = false;
        cursor.skipping_until_lf = false;
        cursor.complete = false;
        cursor.partial_reported = false;
    }
    if truncated
        && let Some(minimum) = options.minimum_offset
        && cursor.offset == minimum
        && length >= minimum
    {
        set_minimum_boundary(cursor, minimum, &mut file, context);
        floor_boundary_reset = true;
    }
    if let Some(minimum) = options.minimum_offset
        && cursor.offset < minimum
    {
        if length < minimum {
            if let Some(target) = options.scan_target.as_deref_mut() {
                *target = length;
            }
            cursor.offset = length;
            cursor.safe_offset = length;
            cursor.frame_start = length;
            cursor.frame.clear();
            cursor.discarding = false;
            cursor.skipping_until_lf = false;
            cursor.complete = false;
            return;
        }
        cursor.offset = minimum;
        cursor.safe_offset = minimum;
        cursor.frame_start = minimum;
        cursor.frame.clear();
        cursor.discarding = false;
        set_minimum_boundary(cursor, minimum, &mut file, context);
        cursor.complete = false;
        floor_boundary_reset = true;
    }
    let mut stop_offset = options.stop_offset;
    let mut scan_target_shrunk = false;
    if let Some(target) = options.scan_target.as_deref_mut() {
        if length < *target {
            if !truncated {
                context.notices.add(FeedNoticeCode::TruncatedGeneration);
            }
            *target = length;
            scan_target_shrunk = true;
        }
        if scan_target_shrunk && let Some(minimum) = options.minimum_offset {
            if length < minimum {
                cursor.offset = length;
                cursor.safe_offset = length;
                cursor.frame_start = length;
                cursor.frame.clear();
                cursor.discarding = false;
                cursor.skipping_until_lf = false;
                cursor.complete = false;
                return;
            }
            if cursor.offset == minimum && !floor_boundary_reset {
                set_minimum_boundary(cursor, minimum, &mut file, context);
            }
        }
        stop_offset = Some(*target);
    }
    let head_changed = match cursor.head.as_ref() {
        None => match read_generation_head(&mut file, length) {
            Ok(head) => {
                cursor.head = Some(head);
                false
            }
            Err(_) => {
                cursor.unresolved = true;
                context.notices.add(FeedNoticeCode::ReadRace);
                if !context.reconcile() {
                    return;
                }
                return;
            }
        },
        Some(head) if length >= head.len() as u64 => match file.read_at(0, head.len()) {
            Ok(current) => current.as_slice() != head.as_slice(),
            Err(_) => {
                cursor.unresolved = true;
                context.notices.add(FeedNoticeCode::ReadRace);
                if !context.reconcile() {
                    return;
                }
                return;
            }
        },
        Some(_) => false,
    };
    if head_changed {
        context.notices.add(FeedNoticeCode::ReplacedGeneration);
        let reset = options.minimum_offset.unwrap_or(0);
        cursor.offset = reset;
        cursor.safe_offset = reset;
        cursor.frame_start = reset;
        cursor.frame.clear();
        cursor.discarding = false;
        cursor.skipping_until_lf = false;
        cursor.complete = false;
        cursor.unresolved = false;
        cursor.partial_reported = false;
        cursor.missing_reported = false;
        match read_generation_head(&mut file, length) {
            Ok(head) => cursor.head = Some(head),
            Err(_) => {
                cursor.unresolved = true;
                context.notices.add(FeedNoticeCode::ReadRace);
                if !context.reconcile() {
                    return;
                }
                return;
            }
        }
        if reset > 0 {
            set_minimum_boundary(cursor, reset, &mut file, context);
        }
    }
    let snapshot_length = stop_offset.map_or(length, |stop| length.min(stop));
    while cursor.offset < snapshot_length
        && if options.scanning_recent {
            context.can_read_bytes()
        } else {
            context.can_read()
        }
    {
        let byte = match file.read_at(cursor.offset, 1) {
            Ok(bytes) => match bytes.first() {
                Some(byte) => *byte,
                None => break,
            },
            Err(_) => {
                cursor.unresolved = true;
                context.notices.add(FeedNoticeCode::ReadRace);
                if !context.reconcile() {
                    return;
                }
                break;
            }
        };
        context.bytes_read = context.bytes_read.saturating_add(1);
        let recent_for_byte = options
            .recent
            .as_mut()
            .map(|(records, max_events)| (&mut **records, *max_events));
        process_byte(
            cursor,
            byte,
            context,
            dedup,
            dedup_order,
            max_dedup_entries,
            recent_for_byte,
        );
    }
    if cursor.offset < snapshot_length {
        context.budget_exhausted = true;
        return;
    }
    if stop_offset.is_some() {
        update_partial_state(cursor, context);
        return;
    }
    let current_length = file.refresh_len().unwrap_or(snapshot_length);
    if current_length > snapshot_length {
        context.budget_exhausted = true;
    }
    update_partial_state(cursor, context);
}

fn read_generation_head(file: &mut JournalFile, length: u64) -> std::io::Result<Vec<u8>> {
    file.read_at(0, length.min(GENERATION_HEAD_BYTES as u64) as usize)
}

fn set_minimum_boundary(
    cursor: &mut Cursor,
    minimum: u64,
    file: &mut JournalFile,
    context: &mut PollContext,
) {
    if minimum == 0 {
        cursor.skipping_until_lf = false;
        return;
    }
    cursor.skipping_until_lf = match file.read_at(minimum - 1, 1) {
        Ok(bytes) => match bytes.first() {
            Some(b'\n') => {
                context.bytes_read = context.bytes_read.saturating_add(1);
                false
            }
            Some(_) => {
                context.bytes_read = context.bytes_read.saturating_add(1);
                true
            }
            None => {
                context
                    .notices
                    .add(FeedNoticeCode::StartupBoundaryUnavailable);
                true
            }
        },
        Err(_) => {
            context
                .notices
                .add(FeedNoticeCode::StartupBoundaryUnavailable);
            true
        }
    };
}

fn update_partial_state(cursor: &mut Cursor, context: &mut PollContext) {
    if cursor.discarding || !cursor.frame.is_empty() {
        cursor.complete = false;
        if cursor.is_active {
            if !cursor.partial_reported {
                context.notices.add(FeedNoticeCode::ActivePartialFrame);
                cursor.partial_reported = true;
            }
        } else if !cursor.partial_reported {
            context.notices.add(FeedNoticeCode::NonActivePartialFrame);
            cursor.partial_reported = true;
            cursor.unresolved = true;
        }
    } else {
        cursor.complete = !cursor.skipping_until_lf;
        cursor.partial_reported = false;
    }
}

fn process_byte(
    cursor: &mut Cursor,
    byte: u8,
    context: &mut PollContext,
    dedup: &mut HashMap<String, [u8; 32]>,
    dedup_order: &mut VecDeque<String>,
    max_dedup_entries: usize,
    recent: Option<(&mut VecDeque<Event3Record>, usize)>,
) {
    let byte_end = cursor.offset.saturating_add(1);
    if cursor.skipping_until_lf {
        cursor.offset = byte_end;
        if byte == b'\n' {
            cursor.skipping_until_lf = false;
            cursor.frame.clear();
            cursor.safe_offset = byte_end;
            cursor.frame_start = byte_end;
            cursor.complete = false;
        }
        return;
    }
    if cursor.discarding {
        cursor.offset = byte_end;
        if byte == b'\n' {
            cursor.discarding = false;
            cursor.frame.clear();
            cursor.frame_start = byte_end;
            cursor.complete = false;
            context.notices.add(FeedNoticeCode::OversizedFrame);
        }
        return;
    }
    if byte == b'\n' {
        let body = std::mem::take(&mut cursor.frame);
        cursor.offset = byte_end;
        cursor.safe_offset = byte_end;
        cursor.frame_start = byte_end;
        cursor.complete = false;
        emit_body(
            &body,
            context,
            dedup,
            dedup_order,
            max_dedup_entries,
            recent,
        );
        return;
    }
    if cursor.frame.len() >= context.max_frame {
        cursor.offset = byte_end;
        cursor.frame.clear();
        cursor.discarding = true;
        return;
    }
    cursor.offset = byte_end;
    cursor.frame.push(byte);
}

fn emit_body(
    body: &[u8],
    context: &mut PollContext,
    dedup: &mut HashMap<String, [u8; 32]>,
    dedup_order: &mut VecDeque<String>,
    max_dedup_entries: usize,
    recent: Option<(&mut VecDeque<Event3Record>, usize)>,
) {
    let record = match Event3Record::from_json(body) {
        Ok(record) => record,
        Err(error) => {
            let code = match error.category() {
                Event3ErrorCategory::Malformed => FeedNoticeCode::ParserMalformed,
                Event3ErrorCategory::Version => FeedNoticeCode::ParserVersion,
                Event3ErrorCategory::Structure => FeedNoticeCode::ParserStructure,
                Event3ErrorCategory::Identity => FeedNoticeCode::ParserIdentity,
                Event3ErrorCategory::Semantic => FeedNoticeCode::ParserSemantic,
                Event3ErrorCategory::Family => FeedNoticeCode::ParserFamily,
            };
            context.notices.add(code);
            return;
        }
    };
    let digest: [u8; 32] = Sha256::digest(body).into();
    let event_id = record.common().event_id.clone();
    if let Some(previous) = dedup.get(&event_id) {
        if previous == &digest {
            context.suppressed_replays = context.suppressed_replays.saturating_add(1);
            context.notices.add(FeedNoticeCode::ReplaySuppressed);
        } else {
            context.event_id_collisions = context.event_id_collisions.saturating_add(1);
            context.notices.add(FeedNoticeCode::EventIdCollision);
        }
        return;
    }
    if dedup.len() >= max_dedup_entries
        && let Some(oldest) = dedup_order.pop_front()
    {
        dedup.remove(&oldest);
        context.dedup_evictions = context.dedup_evictions.saturating_add(1);
        context.notices.add(FeedNoticeCode::DedupEvicted);
    }
    dedup.insert(event_id.clone(), digest);
    dedup_order.push_back(event_id);
    if let Some((recent, max_events)) = recent {
        recent.push_back(record.clone());
        while recent.len() > max_events {
            recent.pop_front();
        }
    } else if context.records.len() < context.max_events {
        context.records.push(record);
    } else {
        context.budget_exhausted = true;
    }
}

#[cfg(test)]
#[path = "local_event_feed_tests.rs"]
mod tests;
