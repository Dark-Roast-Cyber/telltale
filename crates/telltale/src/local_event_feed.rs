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
mod tests {
    use super::{
        Cursor, FeedLimits, FeedNotice, FeedNoticeCode, LocalEventFeed, LocalEventFeedConfig,
        LocalEventFeedErrorCode, PollContext, RecentPhase, StartupMode,
    };
    use std::collections::BTreeMap;
    use std::fs;
    use std::io::Write;
    use std::path::{Path, PathBuf};
    use telltale_schema::event::{Event3ErrorCategory, Event3Record};
    use telltale_sources::journal::{JournalFile, JournalGeneration};
    use telltale_sources::paths::{PathProfile, resolve_log_path};
    use tempfile::tempdir;

    fn valid_record(event_id: &str) -> Vec<u8> {
        format!(
            r#"{{"schema_version":"3.0","event_id":"{event_id}","telltale_version":"0.5.0","timestamp":"2026-01-01T00:00:00.000Z","observed_at":"2026-01-01T00:00:00.000Z","ingested_at":"2026-01-01T00:00:00.000Z","time_source":"observed","time_confidence":"high","time_override_reason":"synthetic","severity":"informational","risk_score":0,"risk_contributions":[],"client":"synthetic","session_id":"synthetic-session","tags":[],"evidence":[],"event_type":"activity","source_path_hash":"synthetic-hash"}}"#
        )
        .into_bytes()
    }

    fn line(event_id: &str) -> Vec<u8> {
        let mut value = valid_record(event_id);
        value.push(b'\n');
        value
    }

    fn append(path: &Path, bytes: &[u8]) {
        fs::OpenOptions::new()
            .append(true)
            .open(path)
            .expect("append")
            .write_all(bytes)
            .expect("append bytes");
    }

    fn event_ids(batch: &super::FeedBatch) -> Vec<String> {
        batch
            .records
            .iter()
            .map(|record| record.common().event_id.clone())
            .collect()
    }

    fn has_notice(batch: &super::FeedBatch, code: FeedNoticeCode) -> bool {
        batch.notices.iter().any(|notice| notice.code == code)
    }

    fn replace_once(bytes: Vec<u8>, from: &str, to: &str) -> Vec<u8> {
        String::from_utf8(bytes)
            .expect("synthetic UTF-8")
            .replacen(from, to, 1)
            .into_bytes()
    }

    fn parser_notice(body: &[u8]) -> FeedNoticeCode {
        let error = Event3Record::from_json(body).expect_err("synthetic parser failure");
        match error.category() {
            Event3ErrorCategory::Malformed => FeedNoticeCode::ParserMalformed,
            Event3ErrorCategory::Version => FeedNoticeCode::ParserVersion,
            Event3ErrorCategory::Structure => FeedNoticeCode::ParserStructure,
            Event3ErrorCategory::Identity => FeedNoticeCode::ParserIdentity,
            Event3ErrorCategory::Semantic => FeedNoticeCode::ParserSemantic,
            Event3ErrorCategory::Family => FeedNoticeCode::ParserFamily,
        }
    }

    fn snapshot(root: &Path) -> BTreeMap<PathBuf, (&'static str, u64)> {
        fn visit(root: &Path, path: &Path, result: &mut BTreeMap<PathBuf, (&'static str, u64)>) {
            let metadata = fs::symlink_metadata(path).expect("snapshot metadata");
            let kind = if metadata.file_type().is_symlink() {
                "symlink"
            } else if metadata.is_dir() {
                "directory"
            } else if metadata.is_file() {
                "file"
            } else {
                "other"
            };
            result.insert(
                path.strip_prefix(root)
                    .expect("snapshot path")
                    .to_path_buf(),
                (kind, metadata.len()),
            );
            if metadata.is_dir() {
                for entry in fs::read_dir(path).expect("snapshot directory") {
                    visit(root, &entry.expect("snapshot entry").path(), result);
                }
            }
        }

        let mut result = BTreeMap::new();
        visit(root, root, &mut result);
        result
    }

    #[test]
    fn missing_path_is_waiting_and_does_not_create_parent() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("missing/events.jsonl");
        let mut feed =
            LocalEventFeed::new(LocalEventFeedConfig::new(&path, StartupMode::Beginning))
                .expect("config");
        let batch = feed.poll().expect("poll");
        assert!(!batch.caught_up);
        assert!(batch.records.is_empty());
        assert!(
            batch
                .notices
                .iter()
                .any(|notice| notice.code == FeedNoticeCode::JournalUnavailable)
        );
        assert!(!path.exists());
        assert!(!path.parent().expect("parent").exists());
    }

    #[test]
    fn malformed_complete_lines_are_consumed_and_partial_waits() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("events.jsonl");
        fs::write(&path, b"not-json\npartial").expect("journal");
        let limits = FeedLimits {
            max_bytes_per_poll: 1024,
            ..FeedLimits::default()
        };
        let mut feed = LocalEventFeed::new(
            LocalEventFeedConfig::new(&path, StartupMode::Beginning).with_limits(limits),
        )
        .expect("config");
        let batch = feed.poll().expect("poll");
        assert!(batch.records.is_empty());
        assert!(
            batch
                .notices
                .iter()
                .any(|notice| notice.code == FeedNoticeCode::ParserMalformed)
        );
        assert!(
            batch
                .notices
                .iter()
                .any(|notice| notice.code == FeedNoticeCode::ActivePartialFrame)
        );
        fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("append")
            .write_all(b"\n")
            .expect("complete");
        let second = feed.poll().expect("poll");
        assert!(second.records.is_empty());
    }

    #[test]
    fn valid_records_are_typed_and_identical_replays_are_suppressed() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("events.jsonl");
        let record = br#"{"schema_version":"3.0","event_id":"telltale-12345678-1234-4123-8123-123456789abc","telltale_version":"0.5.0","timestamp":"2026-01-01T00:00:00.000Z","observed_at":"2026-01-01T00:00:00.000Z","ingested_at":"2026-01-01T00:00:00.000Z","time_source":"observed","time_confidence":"high","time_override_reason":"synthetic","severity":"informational","risk_score":0,"risk_contributions":[],"client":"synthetic","session_id":"synthetic-session","tags":[],"evidence":[],"event_type":"activity","source_path_hash":"synthetic-hash"}"#;
        let mut bytes = record.to_vec();
        bytes.push(b'\n');
        fs::write(&path, &bytes).expect("journal");
        let mut feed =
            LocalEventFeed::new(LocalEventFeedConfig::new(&path, StartupMode::Beginning))
                .expect("config");
        let first = feed.poll().expect("poll");
        assert_eq!(first.records.len(), 1);
        assert_eq!(
            first.records[0].common().event_id,
            "telltale-12345678-1234-4123-8123-123456789abc"
        );
        let second = feed.poll().expect("poll");
        assert!(second.records.is_empty());
        fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("append")
            .write_all(&bytes)
            .expect("replay");
        let replay = feed.poll().expect("poll");
        assert!(replay.records.is_empty());
        assert_eq!(replay.suppressed_replays, 1);
    }

    #[test]
    fn end_retains_partial_and_recent_returns_newest_records() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("events.jsonl");
        let first = valid_record("telltale-11111111-1111-4111-8111-111111111111");
        let second = valid_record("telltale-22222222-2222-4222-8222-222222222222");
        let third = valid_record("telltale-33333333-3333-4333-8333-333333333333");
        let mut history = first.clone();
        history.push(b'\n');
        history.extend_from_slice(&second);
        history.push(b'\n');
        history.extend_from_slice(&third);
        fs::write(&path, &history).expect("history");

        let mut end_feed = LocalEventFeed::new(LocalEventFeedConfig::new(&path, StartupMode::End))
            .expect("end config");
        let end_start = end_feed.poll().expect("end start");
        assert!(end_start.records.is_empty());
        fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("append")
            .write_all(b"\n")
            .expect("complete partial");
        let completed = end_feed.poll().expect("end completion");
        assert_eq!(completed.records.len(), 1);
        assert_eq!(
            completed.records[0].common().event_id,
            "telltale-33333333-3333-4333-8333-333333333333"
        );

        let mut recent_feed = LocalEventFeed::new(LocalEventFeedConfig::new(
            &path,
            StartupMode::Recent {
                max_events: 2,
                max_bytes: history.len() + 1,
            },
        ))
        .expect("recent config");
        let recent = recent_feed.poll().expect("recent start");
        assert_eq!(recent.records.len(), 2);
        assert_eq!(
            recent.records[0].common().event_id,
            "telltale-22222222-2222-4222-8222-222222222222"
        );
        assert_eq!(
            recent.records[1].common().event_id,
            "telltale-33333333-3333-4333-8333-333333333333"
        );
    }

    #[test]
    fn end_non_active_last_byte_peeks_are_bounded_and_counted() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("events.jsonl");
        fs::write(directory.path().join("events-2026-01-01.jsonl"), b"first\n")
            .expect("first rotated generation");
        fs::write(
            directory.path().join("events-2026-01-02.jsonl"),
            b"second\n",
        )
        .expect("second rotated generation");
        fs::write(&path, []).expect("empty active generation");
        let limits = FeedLimits {
            max_bytes_per_poll: 1,
            ..FeedLimits::default()
        };
        let mut feed = LocalEventFeed::new(
            LocalEventFeedConfig::new(&path, StartupMode::End).with_limits(limits),
        )
        .expect("config");

        let batch = feed.poll().expect("poll");

        assert_eq!(batch.bytes_read, 1);
        assert!(has_notice(&batch, FeedNoticeCode::NonActivePartialFrame));
        assert!(!batch.caught_up);
    }

    #[test]
    fn collision_eviction_rotation_and_truncation_are_explicit() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("events.jsonl");
        let first = valid_record("telltale-44444444-4444-4444-8444-444444444444");
        let second = valid_record("telltale-55555555-5555-4555-8555-555555555555");
        let mut first_line = first.clone();
        first_line.push(b'\n');
        fs::write(&path, &first_line).expect("journal");
        let limits = FeedLimits {
            max_dedup_entries: 1,
            ..FeedLimits::default()
        };
        let mut feed = LocalEventFeed::new(
            LocalEventFeedConfig::new(&path, StartupMode::Beginning).with_limits(limits),
        )
        .expect("config");
        assert_eq!(feed.poll().expect("first poll").records.len(), 1);

        let mut collision = first.clone();
        collision.extend_from_slice(b" ");
        let mut collision_line = collision;
        collision_line.push(b'\n');
        fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("append collision")
            .write_all(&collision_line)
            .expect("collision");
        let collision_batch = feed.poll().expect("collision poll");
        assert_eq!(collision_batch.event_id_collisions, 1);
        assert!(collision_batch.records.is_empty());

        let rotated = directory.path().join("events-2026-01-02.jsonl");
        fs::rename(&path, &rotated).expect("rotate");
        let mut active = second.clone();
        active.push(b'\n');
        fs::write(&path, &active).expect("new active");
        let rotated_batch = feed.poll().expect("rotation poll");
        assert_eq!(rotated_batch.records.len(), 1);

        fs::write(&path, []).expect("truncate");
        let truncated = feed.poll().expect("truncation poll");
        assert!(
            truncated
                .notices
                .iter()
                .any(|notice| notice.code == FeedNoticeCode::TruncatedGeneration)
        );
        fs::write(&path, &active).expect("rewrite");
        let replay = feed.poll().expect("replay after truncation");
        assert_eq!(replay.suppressed_replays, 1);
    }

    #[test]
    fn notices_are_static_and_do_not_echo_input_canaries() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("events.jsonl");
        let canary = "SYNTHETIC_FEED_PRIVACY_CANARY";
        fs::write(&path, format!("{{{canary}\n")).expect("journal");
        let mut feed = LocalEventFeed::from_path(&path, StartupMode::Beginning).expect("config");
        let batch = feed.poll().expect("poll");
        let display = batch
            .notices
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(" ");
        let debug = format!("{:?}", batch.notices);
        assert!(!display.contains(canary));
        assert!(!debug.contains(canary));
    }

    #[test]
    fn recent_exact_poll_byte_budget_emits_the_only_record() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("events.jsonl");
        let event_id = "telltale-66666666-6666-4666-8666-666666666666";
        let mut line = valid_record(event_id);
        line.push(b'\n');

        fs::write(&path, &line).expect("journal");
        let limits = FeedLimits {
            max_bytes_per_poll: line.len(),
            ..FeedLimits::default()
        };
        let mut feed = LocalEventFeed::new(
            LocalEventFeedConfig::new(
                &path,
                StartupMode::Recent {
                    max_events: 1,
                    max_bytes: line.len(),
                },
            )
            .with_limits(limits),
        )
        .expect("config");

        let first = feed.poll().expect("first poll");
        let second = feed.poll().expect("second poll");
        let third = feed.poll().expect("third poll");
        let emitted = first
            .records
            .into_iter()
            .chain(second.records)
            .chain(third.records)
            .collect::<Vec<_>>();

        assert_eq!(emitted.len(), 1);
        assert_eq!(emitted[0].common().event_id, event_id);
    }

    #[test]
    fn recent_debug_does_not_dump_a_partial_frame() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("events.jsonl");
        let canary = "SYNTHETIC_FEED_PRIVACY_CANARY";
        fs::write(&path, canary).expect("partial journal");
        let mut feed = LocalEventFeed::from_path(&path, StartupMode::Beginning).expect("config");

        feed.poll().expect("poll");

        assert!(!format!("{feed:?}").contains(canary));
    }

    #[test]
    fn recent_boundary_rejects_a_replaced_generation_identity() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("events.jsonl");
        fs::write(&path, b"not-json\n").expect("journal");
        let generation = JournalGeneration {
            path: path.clone(),
            identity: "stale-generation-identity".to_owned(),
            is_active: true,
        };
        let mut feed = LocalEventFeed::new(LocalEventFeedConfig::new(
            &path,
            StartupMode::Recent {
                max_events: 1,
                max_bytes: 8,
            },
        ))
        .expect("config");
        feed.cursors
            .insert(generation.identity.clone(), Cursor::new(&generation));
        let mut context = PollContext::new(feed.config.limits);

        feed.initialize_recent(std::slice::from_ref(&generation), 1, 8, &mut context);

        assert!(
            context
                .notices
                .notices
                .iter()
                .any(|notice| notice.code == FeedNoticeCode::ReplacedGeneration)
        );
        assert!(
            context
                .notices
                .notices
                .iter()
                .any(|notice| notice.code == FeedNoticeCode::StartupBoundaryUnavailable)
        );
        let recent = feed.recent.as_ref().expect("recent state");
        assert!(!recent.boundary_established);
        assert_eq!(recent.scan_targets.get(&generation.identity), Some(&None));
        assert!(!feed.recent_scan_complete(std::slice::from_ref(&generation)));

        let actual_identity = JournalFile::open(&path)
            .expect("journal open")
            .identity()
            .to_owned();
        assert_ne!(actual_identity, generation.identity);
    }

    #[test]
    fn recent_floor_peek_counts_against_the_poll_byte_budget() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("events.jsonl");
        let mut line = valid_record("telltale-66666666-6666-4666-8666-666666666666");
        line.push(b'\n');
        fs::write(&path, &line).expect("journal");
        let limits = FeedLimits {
            max_bytes_per_poll: 1,
            ..FeedLimits::default()
        };
        let mut feed = LocalEventFeed::new(
            LocalEventFeedConfig::new(
                &path,
                StartupMode::Recent {
                    max_events: 1,
                    max_bytes: line.len() / 2,
                },
            )
            .with_limits(limits),
        )
        .expect("config");

        let batch = feed.poll().expect("poll");

        assert_eq!(batch.bytes_read, 1);
        assert!(batch.records.is_empty());
    }

    #[test]
    fn recent_window_larger_than_poll_budget_drains_without_loss() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("events.jsonl");
        let event_ids = [
            "telltale-77777777-7777-4777-8777-777777777777",
            "telltale-88888888-8888-4888-8888-888888888888",
            "telltale-99999999-9999-4999-8999-999999999999",
        ];
        let mut history = Vec::new();
        for event_id in event_ids {
            history.extend_from_slice(&valid_record(event_id));
            history.push(b'\n');
        }
        let line_len = history.len() / event_ids.len();

        fs::write(&path, &history).expect("journal");
        let limits = FeedLimits {
            max_bytes_per_poll: line_len,
            ..FeedLimits::default()
        };
        let mut feed = LocalEventFeed::new(
            LocalEventFeedConfig::new(
                &path,
                StartupMode::Recent {
                    max_events: event_ids.len(),
                    max_bytes: history.len(),
                },
            )
            .with_limits(limits),
        )
        .expect("config");

        let mut emitted = Vec::new();
        for _ in 0..16 {
            let batch = feed.poll().expect("poll");
            emitted.extend(
                batch
                    .records
                    .into_iter()
                    .map(|record| record.common().event_id.clone()),
            );
            if batch.caught_up {
                break;
            }
        }

        let expected = event_ids
            .iter()
            .map(|event_id| (*event_id).to_owned())
            .collect::<Vec<_>>();
        assert_eq!(emitted, expected);
    }

    #[test]
    fn event_limit_exhaustion_does_not_forget_remaining_records() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("events.jsonl");
        let event_ids = [
            "telltale-aaaaaaa1-aaaa-4aaa-8aaa-aaaaaaaaaaa1",
            "telltale-bbbbbbb2-bbbb-4bbb-8bbb-bbbbbbbbbbb2",
            "telltale-ccccccc3-cccc-4ccc-8ccc-ccccccccccc3",
        ];
        let mut history = Vec::new();
        for event_id in event_ids {
            history.extend_from_slice(&valid_record(event_id));
            history.push(b'\n');
        }

        fs::write(&path, &history).expect("journal");
        let limits = FeedLimits {
            max_events_per_poll: 1,
            max_bytes_per_poll: history.len() + 1,
            ..FeedLimits::default()
        };
        let mut feed = LocalEventFeed::new(
            LocalEventFeedConfig::new(
                &path,
                StartupMode::Recent {
                    max_events: event_ids.len(),
                    max_bytes: history.len(),
                },
            )
            .with_limits(limits),
        )
        .expect("config");

        let mut emitted = Vec::new();
        for _ in 0..16 {
            let batch = feed.poll().expect("poll");
            emitted.extend(
                batch
                    .records
                    .into_iter()
                    .map(|record| record.common().event_id.clone()),
            );
            if batch.caught_up {
                break;
            }
        }

        let expected = event_ids
            .iter()
            .map(|event_id| (*event_id).to_owned())
            .collect::<Vec<_>>();
        assert_eq!(emitted, expected);
    }

    #[test]
    fn beginning_event_limit_drains_remaining_records() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("events.jsonl");
        let event_ids = [
            "telltale-ddddddd4-dddd-4ddd-8ddd-ddddddddddd4",
            "telltale-eeeeeee5-eeee-4eee-8eee-eeeeeeeeeee5",
            "telltale-fffffff6-ffff-4fff-8fff-fffffffffff6",
        ];
        let mut history = Vec::new();
        for event_id in event_ids {
            history.extend_from_slice(&valid_record(event_id));
            history.push(b'\n');
        }

        fs::write(&path, &history).expect("journal");
        let limits = FeedLimits {
            max_events_per_poll: 1,
            max_bytes_per_poll: history.len() + 1,
            ..FeedLimits::default()
        };
        let mut feed = LocalEventFeed::new(
            LocalEventFeedConfig::new(&path, StartupMode::Beginning).with_limits(limits),
        )
        .expect("config");

        let mut emitted = Vec::new();
        for _ in 0..16 {
            let batch = feed.poll().expect("poll");
            emitted.extend(
                batch
                    .records
                    .into_iter()
                    .map(|record| record.common().event_id.clone()),
            );
            if batch.caught_up {
                break;
            }
        }

        let expected = event_ids
            .iter()
            .map(|event_id| (*event_id).to_owned())
            .collect::<Vec<_>>();
        assert_eq!(emitted, expected);
    }

    #[test]
    fn recent_excluded_generation_never_reenters_polling() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("events.jsonl");
        let oldest_path = directory.path().join("events-2026-01-01.jsonl");
        let middle_path = directory.path().join("events-2026-01-02.jsonl");
        let oldest_id = "telltale-aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
        let middle_id = "telltale-bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
        let active_id = "telltale-cccccccc-cccc-4ccc-8ccc-cccccccccccc";
        let mut oldest = valid_record(oldest_id);
        oldest.push(b'\n');
        let mut middle = valid_record(middle_id);
        middle.push(b'\n');
        let mut active = valid_record(active_id);
        active.push(b'\n');

        fs::write(&oldest_path, &oldest).expect("oldest generation");
        fs::write(&middle_path, &middle).expect("middle generation");
        fs::write(&path, &active).expect("active generation");
        let limits = FeedLimits {
            max_events_per_poll: 16,
            max_bytes_per_poll: oldest.len() + middle.len() + active.len(),
            ..FeedLimits::default()
        };
        let mut feed = LocalEventFeed::new(
            LocalEventFeedConfig::new(
                &path,
                StartupMode::Recent {
                    max_events: 2,
                    max_bytes: middle.len() + active.len(),
                },
            )
            .with_limits(limits),
        )
        .expect("config");

        let mut emitted = Vec::new();
        for _ in 0..8 {
            let batch = feed.poll().expect("poll");
            emitted.extend(
                batch
                    .records
                    .into_iter()
                    .map(|record| record.common().event_id.clone()),
            );
            if batch.caught_up {
                break;
            }
        }
        let later = feed.poll().expect("later poll");
        emitted.extend(
            later
                .records
                .into_iter()
                .map(|record| record.common().event_id.clone()),
        );

        assert!(!emitted.iter().any(|event_id| event_id == oldest_id));
        assert_eq!(
            emitted
                .iter()
                .filter(|event_id| event_id.as_str() == middle_id || event_id.as_str() == active_id)
                .cloned()
                .collect::<Vec<_>>(),
            vec![middle_id.to_owned(), active_id.to_owned()]
        );
    }

    #[test]
    fn recent_live_rotated_generation_survives_floor_disappearance() {
        assert_recent_live_rotated_generation_survives_floor_disappearance(false);
    }

    #[test]
    fn recent_live_rotated_generation_survives_reused_floor_identity() {
        assert_recent_live_rotated_generation_survives_floor_disappearance(true);
    }

    fn assert_recent_live_rotated_generation_survives_floor_disappearance(
        inject_floor_identity_collision: bool,
    ) {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("events.jsonl");
        let first_rotated = directory.path().join("events-2026-01-01.jsonl");
        let second_rotated = directory.path().join("events-2026-01-02.jsonl");
        let first_id = "telltale-10101010-1010-4010-8010-101010101010";
        let second_id = "telltale-20202020-2020-4020-8020-202020202020";
        let third_id = "telltale-30303030-3030-4030-8030-303030303030";
        let fourth_id = "telltale-40404040-4040-4040-8040-404040404040";
        let mut first = valid_record(first_id);
        first.push(b'\n');
        if inject_floor_identity_collision {
            let mut initial_generation = first.clone();
            initial_generation.extend_from_slice(&first);
            fs::write(&path, initial_generation).expect("initial generation with startup prefix");
        } else {
            fs::write(&path, &first).expect("initial generation");
        }

        let limits = FeedLimits {
            max_events_per_poll: 1,
            max_bytes_per_poll: 4096,
            ..FeedLimits::default()
        };
        let mut feed = LocalEventFeed::new(
            LocalEventFeedConfig::new(
                &path,
                StartupMode::Recent {
                    max_events: 1,
                    max_bytes: first.len(),
                },
            )
            .with_limits(limits),
        )
        .expect("config");

        let initial = feed.poll().expect("initial poll");
        assert_eq!(
            initial
                .records
                .iter()
                .map(|record| record.common().event_id.as_str())
                .collect::<Vec<_>>(),
            vec![first_id]
        );

        fs::rename(&path, &first_rotated).expect("rotate first generation");
        let mut second = valid_record(second_id);
        second.push(b'\n');
        let mut third = valid_record(third_id);
        third.push(b'\n');
        let mut second_generation = second.clone();
        second_generation.extend_from_slice(&third);
        fs::write(&path, &second_generation).expect("second generation");

        let partial = feed.poll().expect("partial second generation poll");
        assert_eq!(
            partial
                .records
                .iter()
                .map(|record| record.common().event_id.as_str())
                .collect::<Vec<_>>(),
            vec![second_id]
        );

        fs::rename(&path, &second_rotated).expect("rotate second generation");
        fs::remove_file(&first_rotated).expect("remove floor generation");
        let mut fourth = valid_record(fourth_id);
        fourth.push(b'\n');
        fs::write(&path, &fourth).expect("third generation");

        if inject_floor_identity_collision {
            assert!(feed.recent.as_ref().expect("recent state").floor_offset > 0);
            feed.recent.as_mut().expect("recent state").floor_identity = JournalFile::open(&path)
                .expect("new active")
                .identity()
                .to_owned();
        }

        let mut emitted = Vec::new();
        for _ in 0..16 {
            let batch = feed.poll().expect("post-floor poll");
            emitted.extend(
                batch
                    .records
                    .into_iter()
                    .map(|record| record.common().event_id.clone()),
            );
            if batch.caught_up {
                break;
            }
        }

        assert_eq!(emitted, vec![third_id.to_owned(), fourth_id.to_owned()]);
        let recent = feed.recent.as_ref().expect("recent state");
        assert!(
            recent
                .live_seen
                .iter()
                .all(|identity| feed.cursors.contains_key(identity))
        );
    }

    #[test]
    fn recent_reused_floor_identity_does_not_clip_sole_new_active() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("events.jsonl");
        let rotated = directory.path().join("events-2026-01-01.jsonl");
        let first_id = "telltale-10101010-1010-4010-8010-101010101010";
        let second_id = "telltale-20202020-2020-4020-8020-202020202020";
        let fourth_id = "telltale-40404040-4040-4040-8040-404040404040";
        let first = line(first_id);
        fs::write(&path, [first.as_slice(), first.as_slice()].concat())
            .expect("initial generation");

        let limits = FeedLimits {
            max_events_per_poll: 1,
            max_bytes_per_poll: 4096,
            ..FeedLimits::default()
        };
        let mut feed = LocalEventFeed::new(
            LocalEventFeedConfig::new(
                &path,
                StartupMode::Recent {
                    max_events: 1,
                    max_bytes: first.len(),
                },
            )
            .with_limits(limits),
        )
        .expect("config");

        let mut initial_emitted = Vec::new();
        for _ in 0..16 {
            let batch = feed.poll().expect("initial poll");
            initial_emitted.extend(event_ids(&batch));
            if feed.recent.as_ref().expect("recent state").phase == RecentPhase::Live {
                break;
            }
        }
        assert_eq!(initial_emitted, vec![first_id.to_owned()]);
        assert!(feed.recent.as_ref().expect("recent state").floor_offset > 0);

        fs::rename(&path, &rotated).expect("rotate first generation");
        fs::write(&path, line(second_id)).expect("second generation");
        let _ = feed.poll().expect("second generation poll");
        assert!(
            feed.recent
                .as_ref()
                .expect("recent state")
                .floor_seen_non_active
        );

        fs::remove_file(&rotated).expect("remove floor generation");
        fs::remove_file(&path).expect("remove second generation");
        fs::write(&path, line(fourth_id)).expect("new active generation");
        feed.recent.as_mut().expect("recent state").floor_identity = JournalFile::open(&path)
            .expect("new active")
            .identity()
            .to_owned();

        let batch = feed.poll().expect("sole new active poll");
        assert_eq!(event_ids(&batch), vec![fourth_id.to_owned()]);
    }

    #[test]
    fn recent_scan_does_not_wedge_when_the_initial_generation_disappears() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("events.jsonl");
        let rotated = directory.path().join("events-2026-01-01.jsonl");
        let event_id = "telltale-50505050-5050-4050-8050-505050505050";
        fs::write(&path, b"initial\n").expect("initial generation");
        let limits = FeedLimits {
            max_bytes_per_poll: 1,
            ..FeedLimits::default()
        };
        let mut feed = LocalEventFeed::new(
            LocalEventFeedConfig::new(
                &path,
                StartupMode::Recent {
                    max_events: 1,
                    max_bytes: "initial\n".len(),
                },
            )
            .with_limits(limits),
        )
        .expect("config");

        let scanning = feed.poll().expect("initial scan");
        assert!(scanning.records.is_empty());
        assert_eq!(
            feed.recent.as_ref().expect("recent state").phase,
            RecentPhase::Scanning
        );

        fs::rename(&path, &rotated).expect("rotate initial generation");
        fs::remove_file(&rotated).expect("delete initial generation");
        fs::write(&path, line(event_id)).expect("new active generation");

        let mut emitted = Vec::new();
        for _ in 0..1024 {
            let batch = feed.poll().expect("follow-up poll");
            emitted.extend(event_ids(&batch));
            if emitted.iter().any(|id| id == event_id) {
                break;
            }
        }

        assert_eq!(emitted, vec![event_id.to_owned()]);
        assert_eq!(
            feed.recent.as_ref().expect("recent state").phase,
            RecentPhase::Live
        );
    }

    #[test]
    fn recent_later_discovered_older_generation_is_ignored() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("events.jsonl");
        let middle_path = directory.path().join("events-2026-01-02.jsonl");
        let middle_id = "telltale-bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
        let active_id = "telltale-cccccccc-cccc-4ccc-8ccc-cccccccccccc";
        let older_id = "telltale-20250101-2501-4250-8250-202501012501";
        let mut middle = valid_record(middle_id);
        middle.push(b'\n');
        let mut active = valid_record(active_id);
        active.push(b'\n');

        fs::write(&middle_path, &middle).expect("middle generation");
        fs::write(&path, &active).expect("active generation");
        let limits = FeedLimits {
            max_events_per_poll: 16,
            max_bytes_per_poll: middle.len() + active.len(),
            ..FeedLimits::default()
        };
        let mut feed = LocalEventFeed::new(
            LocalEventFeedConfig::new(
                &path,
                StartupMode::Recent {
                    max_events: 2,
                    max_bytes: middle.len() + active.len(),
                },
            )
            .with_limits(limits),
        )
        .expect("config");

        for _ in 0..8 {
            if feed.poll().expect("initial poll").caught_up {
                break;
            }
        }

        let older_path = directory.path().join("events-2025-01-01.jsonl");
        let mut older = valid_record(older_id);
        older.push(b'\n');
        fs::write(&older_path, &older).expect("older generation");
        let later = feed.poll().expect("later poll");

        assert!(
            !later
                .records
                .iter()
                .any(|record| record.common().event_id == older_id)
        );
    }

    #[test]
    fn recent_byte_floor_skips_clipped_prefix_without_malformed_notice() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("events.jsonl");
        let first_id = "telltale-12121212-1212-4121-8121-121212121212";
        let second_id = "telltale-34343434-3434-4343-8434-343434343434";
        let mut first = valid_record(first_id);
        first.push(b'\n');
        let mut second = valid_record(second_id);
        second.push(b'\n');
        let mut history = first.clone();
        history.extend_from_slice(&second);
        let recent_bytes = first.len() / 2 + second.len();

        fs::write(&path, &history).expect("journal");
        let limits = FeedLimits {
            max_bytes_per_poll: history.len() + 1,
            ..FeedLimits::default()
        };
        let mut feed = LocalEventFeed::new(
            LocalEventFeedConfig::new(
                &path,
                StartupMode::Recent {
                    max_events: 2,
                    max_bytes: recent_bytes,
                },
            )
            .with_limits(limits),
        )
        .expect("config");

        let batch = feed.poll().expect("poll");
        assert_eq!(batch.records.len(), 1);
        assert_eq!(batch.records[0].common().event_id, second_id);
        assert!(
            !batch
                .records
                .iter()
                .any(|record| record.common().event_id == first_id)
        );
        assert!(
            !batch
                .notices
                .iter()
                .any(|notice| notice.code == FeedNoticeCode::ParserMalformed)
        );
        assert!(
            !batch
                .notices
                .iter()
                .any(|notice| notice.code == FeedNoticeCode::OversizedFrame)
        );
    }

    #[test]
    fn recent_truncation_does_not_skip_record_starting_at_floor() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("events.jsonl");
        let first_id = "telltale-56565656-5656-4565-8565-565656565656";
        let second_id = "telltale-78787878-7878-4787-8787-787878787878";
        let replacement_id = "telltale-90909090-9090-4909-8909-909090909090";
        let mut first = valid_record(first_id);
        first.push(b'\n');
        let mut second = valid_record(second_id);
        second.push(b'\n');
        let mut history = first.clone();
        history.extend_from_slice(&second);
        let recent_bytes = first.len() / 2 + second.len();
        let floor_offset = history.len().saturating_sub(recent_bytes);

        fs::write(&path, &history).expect("history");
        let limits = FeedLimits {
            max_bytes_per_poll: history.len() + 1,
            ..FeedLimits::default()
        };
        let mut feed = LocalEventFeed::new(
            LocalEventFeedConfig::new(
                &path,
                StartupMode::Recent {
                    max_events: 2,
                    max_bytes: recent_bytes,
                },
            )
            .with_limits(limits),
        )
        .expect("config");

        let initial = feed.poll().expect("initial poll");
        assert_eq!(initial.records.len(), 1);
        assert_eq!(initial.records[0].common().event_id, second_id);

        fs::write(&path, []).expect("truncate");
        let truncated = feed.poll().expect("truncation poll");
        assert!(
            truncated
                .notices
                .iter()
                .any(|notice| notice.code == FeedNoticeCode::TruncatedGeneration)
        );

        let mut replacement = vec![b'x'; floor_offset];
        replacement[floor_offset - 1] = b'\n';
        replacement.extend_from_slice(&valid_record(replacement_id));
        replacement.push(b'\n');
        fs::write(&path, &replacement).expect("rewrite at floor");

        let mut emitted = Vec::new();
        for _ in 0..8 {
            let batch = feed.poll().expect("replacement poll");
            emitted.extend(
                batch
                    .records
                    .into_iter()
                    .map(|record| record.common().event_id.clone()),
            );
            if batch.caught_up {
                break;
            }
        }
        assert!(emitted.iter().any(|event_id| event_id == replacement_id));
    }

    #[test]
    fn recent_truncation_reestablishes_the_floor_clip() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("events.jsonl");
        let first_id = "telltale-11223344-1122-4122-8122-112233445566";
        let second_id = "telltale-22334455-2233-4233-8233-223344556677";
        let mut first = valid_record(first_id);
        first.push(b'\n');
        let mut second = valid_record(second_id);
        second.push(b'\n');
        let mut history = first.clone();
        history.extend_from_slice(&second);
        let recent_bytes = first.len() / 2 + second.len();
        let floor_offset = history.len() - recent_bytes;

        fs::write(&path, &history).expect("history");
        let limits = FeedLimits {
            max_bytes_per_poll: history.len() + 1,
            ..FeedLimits::default()
        };
        let mut feed = LocalEventFeed::new(
            LocalEventFeedConfig::new(
                &path,
                StartupMode::Recent {
                    max_events: 2,
                    max_bytes: recent_bytes,
                },
            )
            .with_limits(limits),
        )
        .expect("config");

        let initial = feed.poll().expect("initial poll");
        assert_eq!(
            initial
                .records
                .iter()
                .map(|record| record.common().event_id.as_str())
                .collect::<Vec<_>>(),
            vec![second_id]
        );

        let truncated_length = floor_offset + 4;
        fs::write(&path, vec![b'x'; truncated_length]).expect("truncate and rewrite");
        let truncated = feed.poll().expect("truncation poll");
        assert!(truncated.records.is_empty());
        assert!(
            !truncated
                .notices
                .iter()
                .any(|notice| notice.code == FeedNoticeCode::ParserMalformed)
        );

        fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("append newline")
            .write_all(b"\n")
            .expect("complete clipped prefix");
        let completed = feed.poll().expect("completion poll");
        assert!(completed.records.is_empty());
        assert!(
            !completed
                .notices
                .iter()
                .any(|notice| notice.code == FeedNoticeCode::ParserMalformed)
        );
    }

    #[test]
    fn recent_scan_target_shrink_reestablishes_the_floor_clip() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("events.jsonl");
        let first_id = "telltale-51515151-5151-4515-8515-515151515151";
        let second_id = "telltale-62626262-6262-4626-8626-626262626262";
        let replacement_id = "telltale-73737373-7373-4737-8737-737373737373";
        let mut first = valid_record(first_id);
        first.push(b'\n');
        let mut second = valid_record(second_id);
        second.push(b'\n');
        let mut history = first.clone();
        history.extend_from_slice(&second);
        let recent_bytes = first.len() / 2 + second.len();
        let floor_offset = history.len() - recent_bytes;

        fs::write(&path, &history).expect("history");
        let limits = FeedLimits {
            max_bytes_per_poll: 1,
            ..FeedLimits::default()
        };
        let mut feed = LocalEventFeed::new(
            LocalEventFeedConfig::new(
                &path,
                StartupMode::Recent {
                    max_events: 1,
                    max_bytes: recent_bytes,
                },
            )
            .with_limits(limits),
        )
        .expect("config");

        let initial = feed.poll().expect("initial poll");
        assert_eq!(initial.bytes_read, 1);
        assert!(initial.records.is_empty());

        let mut replacement = vec![b'x'; floor_offset];
        replacement[floor_offset - 1] = b'\n';
        replacement.extend_from_slice(&valid_record(replacement_id));
        replacement.push(b'\n');
        fs::write(&path, &replacement).expect("rewrite at floor");

        let mut emitted = Vec::new();
        for _ in 0..1024 {
            let batch = feed.poll().expect("replacement poll");
            emitted.extend(
                batch
                    .records
                    .into_iter()
                    .map(|record| record.common().event_id.clone()),
            );
            if batch.caught_up {
                break;
            }
        }

        assert_eq!(emitted, vec![replacement_id.to_owned()]);
    }

    #[test]
    fn cursor_state_is_pruned_to_the_current_generation_bound() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("events.jsonl");
        fs::write(&path, b"initial\n").expect("active generation");
        let limits = FeedLimits {
            max_generations: 2,
            max_bytes_per_poll: 4096,
            ..FeedLimits::default()
        };
        let mut feed = LocalEventFeed::new(
            LocalEventFeedConfig::new(&path, StartupMode::Beginning).with_limits(limits),
        )
        .expect("config");
        feed.poll().expect("initial poll");
        assert!(feed.cursors.len() <= 2);

        for day in 1..=8 {
            let rotated = directory
                .path()
                .join(format!("events-2026-01-{day:02}.jsonl"));
            fs::rename(&path, rotated).expect("rotate");
            fs::write(&path, format!("generation-{day}\n")).expect("new active generation");
            feed.poll().expect("rotation poll");
            assert!(feed.cursors.len() <= 2);
        }
    }

    #[test]
    fn generation_bound_keeps_newest_suffix_and_is_not_caught_up() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("events.jsonl");
        let ids = [
            "telltale-a1111111-1111-4111-8111-111111111111",
            "telltale-b2222222-2222-4222-8222-222222222222",
            "telltale-c3333333-3333-4333-8333-333333333333",
            "telltale-d4444444-4444-4444-8444-444444444444",
        ];
        for (index, event_id) in ids.iter().enumerate().take(3) {
            let path = directory
                .path()
                .join(format!("events-2026-01-0{}.jsonl", index + 1));
            let mut record = valid_record(event_id);
            record.push(b'\n');
            fs::write(path, record).expect("rotated generation");
        }
        let mut active = valid_record(ids[3]);
        active.push(b'\n');
        fs::write(&path, &active).expect("active generation");

        let limits = FeedLimits {
            max_generations: 2,
            max_bytes_per_poll: 4096,
            ..FeedLimits::default()
        };
        let mut feed = LocalEventFeed::new(
            LocalEventFeedConfig::new(&path, StartupMode::Beginning).with_limits(limits),
        )
        .expect("config");
        let batch = feed.poll().expect("poll");

        let emitted = batch
            .records
            .iter()
            .map(|record| record.common().event_id.as_str())
            .collect::<Vec<_>>();
        assert_eq!(emitted, vec![ids[2], ids[3]]);
        assert!(!batch.caught_up);
        assert!(
            batch
                .notices
                .iter()
                .any(|notice| notice.code == FeedNoticeCode::GenerationBound)
        );
    }

    #[test]
    fn startup_empty_beginning_file_is_caught_up_with_no_records() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("events.jsonl");
        fs::write(&path, []).expect("empty journal");
        let mut feed = LocalEventFeed::from_path(&path, StartupMode::Beginning).expect("config");

        let batch = feed.poll().expect("poll");

        assert!(batch.records.is_empty());
        assert!(batch.caught_up);
        assert_eq!(batch.bytes_read, 0);
    }

    #[test]
    fn startup_recent_restart_replays_the_same_latest_record() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("events.jsonl");
        let mut history = line("telltale-01010101-0101-4010-8010-010101010101");
        history.extend_from_slice(&line("telltale-02020202-0202-4020-8020-020202020202"));
        history.extend_from_slice(&line("telltale-03030303-0303-4030-8030-030303030303"));
        fs::write(&path, history).expect("journal");
        let startup = StartupMode::Recent {
            max_events: 1,
            max_bytes: 1024 * 1024,
        };
        let mut first = LocalEventFeed::from_path(&path, startup).expect("first config");
        let mut second = LocalEventFeed::from_path(&path, startup).expect("second config");

        let first_batch = first.poll().expect("first poll");
        let second_batch = second.poll().expect("second poll");

        assert_eq!(event_ids(&first_batch), event_ids(&second_batch));
        assert_eq!(
            event_ids(&first_batch),
            vec!["telltale-03030303-0303-4030-8030-030303030303"]
        );
    }

    #[test]
    fn startup_missing_path_appears_later_without_feed_creation() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("events.jsonl");
        let mut feed = LocalEventFeed::from_path(&path, StartupMode::Beginning).expect("config");

        let missing = feed.poll().expect("missing poll");
        assert!(missing.records.is_empty());
        assert!(has_notice(&missing, FeedNoticeCode::JournalUnavailable));
        assert!(!path.exists());

        fs::write(&path, line("telltale-04040404-0404-4040-8040-040404040404"))
            .expect("journal appears");
        let appeared = feed.poll().expect("appeared poll");

        assert_eq!(
            event_ids(&appeared),
            vec!["telltale-04040404-0404-4040-8040-040404040404"]
        );
    }

    #[test]
    fn startup_beginning_discovers_an_extensionless_active_path() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("events");
        let event_id = "telltale-41414141-4141-4041-8041-414141414141";
        fs::write(&path, line(event_id)).expect("extensionless journal");
        let mut feed = LocalEventFeed::from_path(&path, StartupMode::Beginning).expect("config");

        let batch = feed.poll().expect("poll");

        assert_eq!(event_ids(&batch), vec![event_id.to_owned()]);
        assert!(!has_notice(&batch, FeedNoticeCode::UnsafeFile));
    }

    #[test]
    fn startup_recent_large_journal_reads_only_the_bounded_suffix() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("events.jsonl");
        let mut history = Vec::new();
        let mut ids = Vec::new();
        for index in 0..40 {
            let event_id = format!("telltale-{index:08x}-0000-4000-8000-{index:012x}");
            ids.push(event_id.clone());
            history.extend_from_slice(&line(&event_id));
        }
        let recent_bytes = line(&ids[38]).len() + line(&ids[39]).len();
        fs::write(&path, &history).expect("large journal");
        let limits = FeedLimits {
            max_bytes_per_poll: recent_bytes + 1,
            ..FeedLimits::default()
        };
        let mut feed = LocalEventFeed::new(
            LocalEventFeedConfig::new(
                &path,
                StartupMode::Recent {
                    max_events: 2,
                    max_bytes: recent_bytes,
                },
            )
            .with_limits(limits),
        )
        .expect("config");

        let batch = feed.poll().expect("poll");

        assert_eq!(event_ids(&batch), vec![ids[38].clone(), ids[39].clone()]);
        assert!(batch.bytes_read <= recent_bytes + 1);
        assert!(batch.bytes_read < history.len());
        assert!(!event_ids(&batch).iter().any(|id| ids[..38].contains(id)));
    }

    #[test]
    fn startup_beginning_walks_rotated_generations_oldest_to_newest() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("events.jsonl");
        let ids = [
            "telltale-05050505-0505-4050-8050-050505050505",
            "telltale-06060606-0606-4060-8060-060606060606",
            "telltale-07070707-0707-4070-8070-070707070707",
        ];
        fs::write(
            directory.path().join("events-2026-01-01.jsonl"),
            line(ids[0]),
        )
        .expect("oldest generation");
        fs::write(
            directory.path().join("events-2026-01-02.jsonl"),
            line(ids[1]),
        )
        .expect("newest rotated generation");
        fs::write(&path, line(ids[2])).expect("active generation");
        let mut feed = LocalEventFeed::from_path(&path, StartupMode::Beginning).expect("config");

        let batch = feed.poll().expect("poll");

        assert_eq!(event_ids(&batch), ids.map(str::to_owned));
    }

    #[test]
    fn framing_split_record_across_bounded_reads_is_emitted_once() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("events.jsonl");
        let record = line("telltale-08080808-0808-4080-8080-080808080808");
        fs::write(&path, &record).expect("journal");
        let limits = FeedLimits {
            max_bytes_per_poll: record.len() / 2,
            ..FeedLimits::default()
        };
        let mut feed = LocalEventFeed::new(
            LocalEventFeedConfig::new(&path, StartupMode::Beginning).with_limits(limits),
        )
        .expect("config");

        let first = feed.poll().expect("first poll");
        let second = feed.poll().expect("second poll");
        let third = feed.poll().expect("third poll");

        assert!(first.records.is_empty());
        assert!(!first.caught_up);
        assert!(second.records.is_empty());
        assert_eq!(
            event_ids(&third),
            vec!["telltale-08080808-0808-4080-8080-080808080808"]
        );
        assert!(third.caught_up);
        assert!(feed.poll().expect("no duplicate poll").records.is_empty());
    }

    #[test]
    fn framing_malformed_line_between_valid_events_does_not_wedge_following_data() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("events.jsonl");
        let first_id = "telltale-09090909-0909-4090-8090-090909090909";
        let second_id = "telltale-0a0a0a0a-0a0a-40a0-80a0-0a0a0a0a0a0a";
        let mut contents = line(first_id);
        contents.extend_from_slice(b"{malformed-between-valid}\n");
        contents.extend_from_slice(&line(second_id));
        fs::write(&path, contents).expect("journal");
        let mut feed = LocalEventFeed::from_path(&path, StartupMode::Beginning).expect("config");

        let batch = feed.poll().expect("poll");

        assert_eq!(
            event_ids(&batch),
            vec![first_id.to_owned(), second_id.to_owned()]
        );
        assert!(has_notice(&batch, FeedNoticeCode::ParserMalformed));
    }

    #[test]
    fn framing_structural_parser_failure_consumes_line_and_preserves_following_event() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("events.jsonl");
        let body = replace_once(
            replace_once(
                valid_record("telltale-0b0b0b0b-0b0b-40b0-80b0-0b0b0b0b0b0b"),
                "\"client\":\"synthetic\",",
                "",
            ),
            "\"source_path_hash\":\"synthetic-hash\"",
            "\"source_path_hash\":\"SYNTHETIC_STRUCTURAL\"",
        );
        assert_eq!(parser_notice(&body), FeedNoticeCode::ParserStructure);
        let following_id = "telltale-0c0c0c0c-0c0c-40c0-80c0-0c0c0c0c0c0c";
        let mut contents = body;
        contents.push(b'\n');
        contents.extend_from_slice(&line(following_id));
        fs::write(&path, contents).expect("journal");
        let mut feed = LocalEventFeed::from_path(&path, StartupMode::Beginning).expect("config");

        let batch = feed.poll().expect("poll");

        assert!(
            batch.records.iter().all(|record| record.common().event_id
                != "telltale-0b0b0b0b-0b0b-40b0-80b0-0b0b0b0b0b0b")
        );
        assert_eq!(event_ids(&batch), vec![following_id.to_owned()]);
        assert!(has_notice(&batch, FeedNoticeCode::ParserStructure));
    }

    #[test]
    fn framing_unsupported_event3_version_is_classified_and_following_event_emits() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("events.jsonl");
        let body = replace_once(
            valid_record("telltale-0d0d0d0d-0d0d-40d0-80d0-0d0d0d0d0d0d"),
            "\"schema_version\":\"3.0\"",
            "\"schema_version\":\"2.0\"",
        );
        assert_eq!(parser_notice(&body), FeedNoticeCode::ParserVersion);
        let following_id = "telltale-0e0e0e0e-0e0e-40e0-80e0-0e0e0e0e0e0e";
        let mut contents = body;
        contents.push(b'\n');
        contents.extend_from_slice(&line(following_id));
        fs::write(&path, contents).expect("journal");
        let mut feed = LocalEventFeed::from_path(&path, StartupMode::Beginning).expect("config");

        let batch = feed.poll().expect("poll");

        assert_eq!(event_ids(&batch), vec![following_id.to_owned()]);
        assert!(has_notice(&batch, FeedNoticeCode::ParserVersion));
    }

    #[test]
    fn framing_unsupported_event_family_is_classified_and_following_event_emits() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("events.jsonl");
        let body = replace_once(
            valid_record("telltale-0f0f0f0f-0f0f-40f0-80f0-0f0f0f0f0f0f"),
            "\"event_type\":\"activity\"",
            "\"event_type\":\"unsupported_family\"",
        );
        assert_eq!(parser_notice(&body), FeedNoticeCode::ParserFamily);
        let following_id = "telltale-10111213-1415-4016-8017-181920212223";
        let mut contents = body;
        contents.push(b'\n');
        contents.extend_from_slice(&line(following_id));
        fs::write(&path, contents).expect("journal");
        let mut feed = LocalEventFeed::from_path(&path, StartupMode::Beginning).expect("config");

        let batch = feed.poll().expect("poll");

        assert_eq!(event_ids(&batch), vec![following_id.to_owned()]);
        assert!(has_notice(&batch, FeedNoticeCode::ParserFamily));
    }

    #[test]
    fn framing_identity_parser_failure_is_classified_and_following_event_emits() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("events.jsonl");
        let body = replace_once(
            valid_record("telltale-22232425-2627-4028-8029-303132333435"),
            "telltale-22232425-2627-4028-8029-303132333435",
            "bad-event-id",
        );
        assert_eq!(parser_notice(&body), FeedNoticeCode::ParserIdentity);
        let following_id = "telltale-36373839-4041-4042-8043-444546474849";
        let mut contents = body;
        contents.push(b'\n');
        contents.extend_from_slice(&line(following_id));
        fs::write(&path, contents).expect("journal");
        let mut feed = LocalEventFeed::from_path(&path, StartupMode::Beginning).expect("config");

        let batch = feed.poll().expect("poll");

        assert_eq!(event_ids(&batch), vec![following_id.to_owned()]);
        assert!(has_notice(&batch, FeedNoticeCode::ParserIdentity));
    }

    #[test]
    fn framing_oversized_complete_frame_is_discarded_before_following_event() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("events.jsonl");
        let following_id = "telltale-64656667-6869-4070-8071-727374757677";
        let max_frame = valid_record(following_id).len();
        let oversized = vec![b'x'; max_frame + 1];
        let mut contents = oversized;
        contents.push(b'\n');
        contents.extend_from_slice(&line(following_id));
        fs::write(&path, contents).expect("journal");
        let limits = FeedLimits {
            max_frame_bytes: max_frame,
            ..FeedLimits::default()
        };
        let mut feed = LocalEventFeed::new(
            LocalEventFeedConfig::new(&path, StartupMode::Beginning).with_limits(limits),
        )
        .expect("config");

        let batch = feed.poll().expect("poll");

        assert_eq!(event_ids(&batch), vec![following_id.to_owned()]);
        assert!(has_notice(&batch, FeedNoticeCode::OversizedFrame));
    }

    #[test]
    fn framing_oversized_partial_frame_stays_bounded_until_lf_then_recovers() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("events.jsonl");
        let following_id = "telltale-78798081-8283-4084-8085-868788899091";
        let max_frame = valid_record(following_id).len();
        let oversized = vec![b'x'; max_frame * 8];
        fs::write(&path, &oversized).expect("unterminated oversized frame");
        let limits = FeedLimits {
            max_frame_bytes: max_frame,
            max_bytes_per_poll: 32,
            ..FeedLimits::default()
        };
        let mut feed = LocalEventFeed::new(
            LocalEventFeedConfig::new(&path, StartupMode::Beginning).with_limits(limits),
        )
        .expect("config");

        for _ in 0..32 {
            let _ = feed.poll().expect("bounded partial poll");
            let cursor = feed.cursors.values().next().expect("active cursor");
            assert!(cursor.frame.len() <= max_frame);
        }

        let mut completion = vec![b'\n'];
        completion.extend_from_slice(&line(following_id));
        append(&path, &completion);
        let mut emitted = Vec::new();
        let mut saw_oversized = false;
        for _ in 0..128 {
            let batch = feed.poll().expect("recovery poll");
            emitted.extend(event_ids(&batch));
            saw_oversized |= has_notice(&batch, FeedNoticeCode::OversizedFrame);
            if emitted.iter().any(|id| id == following_id) {
                break;
            }
        }

        assert_eq!(emitted, vec![following_id.to_owned()]);
        assert!(saw_oversized);
    }

    #[test]
    fn framing_non_active_partial_never_joins_the_next_generation() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("events.jsonl");
        let rotated = directory.path().join("events-2026-02-01.jsonl");
        fs::write(&rotated, b"partial-old-generation").expect("partial rotated generation");
        let active_id = "telltale-92939495-9697-4098-8099-000102030405";
        fs::write(&path, line(active_id)).expect("active generation");
        let mut feed = LocalEventFeed::from_path(&path, StartupMode::Beginning).expect("config");

        let batch = feed.poll().expect("poll");

        assert_eq!(event_ids(&batch), vec![active_id.to_owned()]);
        assert!(has_notice(&batch, FeedNoticeCode::NonActivePartialFrame));
        assert!(!batch.caught_up);
    }

    #[test]
    fn lifecycle_append_after_caught_up_emits_new_record_once() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("events.jsonl");
        let first_id = "telltale-06070809-1011-4012-8013-141516171819";
        let second_id = "telltale-20212223-2425-4026-8027-282930313233";
        fs::write(&path, line(first_id)).expect("journal");
        let mut feed = LocalEventFeed::from_path(&path, StartupMode::Beginning).expect("config");

        let first = feed.poll().expect("initial poll");
        assert!(first.caught_up);
        append(&path, &line(second_id));
        let second = feed.poll().expect("append poll");
        let third = feed.poll().expect("no duplicate poll");

        assert!(third.records.is_empty());
        assert_eq!(event_ids(&second), vec![second_id.to_owned()]);
        assert!(second.caught_up);
    }

    #[test]
    fn lifecycle_multiple_rotations_walk_old_generations_before_new_active() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("events.jsonl");
        let first_id = "telltale-34353637-3839-4041-8042-434445464748";
        let second_id = "telltale-49505152-5354-4055-8056-575859606162";
        let third_id = "telltale-63646566-6768-4069-8070-717273747576";
        fs::write(&path, line(first_id)).expect("first active");
        let mut feed = LocalEventFeed::from_path(&path, StartupMode::Beginning).expect("config");
        assert_eq!(
            event_ids(&feed.poll().expect("first poll")),
            vec![first_id.to_owned()]
        );

        fs::rename(&path, directory.path().join("events-2026-02-02.jsonl"))
            .expect("first rotation");
        fs::write(&path, line(second_id)).expect("second active");
        let second = feed.poll().expect("second poll");

        fs::rename(&path, directory.path().join("events-2026-02-03.jsonl"))
            .expect("second rotation");
        fs::write(&path, line(third_id)).expect("third active");
        let third = feed.poll().expect("third poll");

        assert_eq!(event_ids(&second), vec![second_id.to_owned()]);
        assert_eq!(event_ids(&third), vec![third_id.to_owned()]);
    }

    #[test]
    fn lifecycle_replacing_active_identity_is_not_treated_as_append() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("events.jsonl");
        let first_id = "telltale-77787980-8182-4083-8084-858687888990";
        let replacement_id = "telltale-91929394-9596-4097-8098-990001020304";
        fs::write(&path, line(first_id)).expect("initial journal");
        let mut feed = LocalEventFeed::from_path(&path, StartupMode::Beginning).expect("config");
        feed.poll().expect("initial poll");
        fs::remove_file(&path).expect("remove old active");
        fs::write(&path, line(replacement_id)).expect("replacement active");

        let batch = feed.poll().expect("replacement poll");

        assert_eq!(event_ids(&batch), vec![replacement_id.to_owned()]);
        assert!(has_notice(&batch, FeedNoticeCode::ReplacedGeneration));
    }

    #[test]
    fn lifecycle_same_identity_same_size_rewrite_is_not_treated_as_append() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("events.jsonl");
        let first_id = "telltale-77787980-8182-4083-8084-858687888990";
        let replacement_id = "telltale-91929394-9596-4097-8098-990001020304";
        let first = line(first_id);
        let replacement = line(replacement_id);
        assert_eq!(first.len(), replacement.len());
        fs::write(&path, &first).expect("initial journal");
        let mut feed = LocalEventFeed::from_path(&path, StartupMode::Beginning).expect("config");
        assert_eq!(
            event_ids(&feed.poll().expect("initial poll")),
            vec![first_id.to_owned()]
        );

        fs::write(&path, &replacement).expect("same-identity replacement");

        let batch = feed.poll().expect("replacement poll");

        assert_eq!(event_ids(&batch), vec![replacement_id.to_owned()]);
        assert!(has_notice(&batch, FeedNoticeCode::ReplacedGeneration));
    }

    #[test]
    fn lifecycle_delete_then_recreate_reports_unavailable_then_reads_new_identity() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("events.jsonl");
        let first_id = "telltale-05060708-0910-4011-8012-131415161718";
        let replacement_id = "telltale-19202122-2324-4025-8026-272829303132";
        fs::write(&path, line(first_id)).expect("initial journal");
        let mut feed = LocalEventFeed::from_path(&path, StartupMode::Beginning).expect("config");
        feed.poll().expect("initial poll");
        fs::remove_file(&path).expect("delete active");

        let unavailable = feed.poll().expect("deleted poll");
        assert!(unavailable.records.is_empty());
        assert!(has_notice(&unavailable, FeedNoticeCode::JournalUnavailable));

        fs::write(&path, line(replacement_id)).expect("recreate active");
        let recreated = feed.poll().expect("recreated poll");

        assert_eq!(event_ids(&recreated), vec![replacement_id.to_owned()]);
        assert!(has_notice(&recreated, FeedNoticeCode::ReplacedGeneration));
    }

    #[test]
    fn lifecycle_unread_generation_disappearance_reports_gap_and_continues() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("events.jsonl");
        let rotated = directory.path().join("events-2026-02-04.jsonl");
        let first_id = "telltale-33343536-3738-4039-8040-414243444546";
        let unread_id = "telltale-47484950-5152-4053-8054-555657585960";
        let active_id = "telltale-61626364-6566-4067-8068-697071727374";
        let mut initial = line(first_id);
        initial.extend_from_slice(&line(unread_id));
        fs::write(&path, initial).expect("initial journal");
        let limits = FeedLimits {
            max_events_per_poll: 1,
            max_bytes_per_poll: 4096,
            ..FeedLimits::default()
        };
        let mut feed = LocalEventFeed::new(
            LocalEventFeedConfig::new(&path, StartupMode::Beginning).with_limits(limits),
        )
        .expect("config");
        assert_eq!(
            event_ids(&feed.poll().expect("first poll")),
            vec![first_id.to_owned()]
        );

        fs::rename(&path, &rotated).expect("rotate unread generation");
        fs::write(&path, line(active_id)).expect("new active");
        fs::remove_file(&rotated).expect("lose unread generation");
        let batch = feed.poll().expect("gap poll");

        assert_eq!(event_ids(&batch), vec![active_id.to_owned()]);
        assert!(has_notice(&batch, FeedNoticeCode::GenerationGap));
        assert!(!batch.caught_up);
    }

    #[test]
    fn lifecycle_directory_target_is_rejected_without_panic() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("events.jsonl");
        fs::create_dir(&path).expect("directory target");
        let mut feed = LocalEventFeed::from_path(&path, StartupMode::Beginning).expect("config");

        let batch = feed.poll().expect("poll");

        assert!(batch.records.is_empty());
        assert!(has_notice(&batch, FeedNoticeCode::UnsafeFile));
    }

    #[cfg(unix)]
    #[test]
    fn lifecycle_symlink_target_is_rejected_without_following() {
        use std::os::unix::fs::symlink;

        let directory = tempdir().expect("tempdir");
        let target = directory.path().join("real-events.jsonl");
        let path = directory.path().join("events.jsonl");
        fs::write(
            &target,
            line("telltale-75767778-7980-4081-8082-838485868788"),
        )
        .expect("real journal");
        symlink(&target, &path).expect("symlink journal");
        let mut feed = LocalEventFeed::from_path(&path, StartupMode::Beginning).expect("config");

        let batch = feed.poll().expect("poll");

        assert!(batch.records.is_empty());
        assert!(has_notice(&batch, FeedNoticeCode::UnsafeFile));
    }

    #[cfg(unix)]
    #[test]
    fn lifecycle_hardlink_target_is_rejected_as_ambiguous_identity() {
        let directory = tempdir().expect("tempdir");
        let source = directory.path().join("real-events.jsonl");
        let path = directory.path().join("events.jsonl");
        fs::write(
            &source,
            line("telltale-898a8b8c-8d8e-408f-8090-919293949596"),
        )
        .expect("real journal");
        fs::hard_link(&source, &path).expect("hard link journal");
        let mut feed = LocalEventFeed::from_path(&path, StartupMode::Beginning).expect("config");

        let batch = feed.poll().expect("poll");

        assert!(batch.records.is_empty());
        assert!(has_notice(&batch, FeedNoticeCode::UnsafeFile));
    }

    #[test]
    fn lifecycle_directory_bound_is_reported_and_not_caught_up() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("events.jsonl");
        fs::write(&path, line("telltale-97989900-0102-4003-8004-050607080910"))
            .expect("active journal");
        for index in 0..5 {
            fs::write(
                directory.path().join(format!("unrelated-{index}")),
                b"fixture",
            )
            .expect("unrelated fixture");
        }
        let limits = FeedLimits {
            max_directory_entries: 2,
            ..FeedLimits::default()
        };
        let mut feed = LocalEventFeed::new(
            LocalEventFeedConfig::new(&path, StartupMode::Beginning).with_limits(limits),
        )
        .expect("config");

        let batch = feed.poll().expect("poll");

        assert!(has_notice(&batch, FeedNoticeCode::DirectoryBound));
        assert!(!batch.caught_up);
    }

    #[test]
    fn dedup_evicted_identity_can_be_emitted_again() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("events.jsonl");
        let first_id = "telltale-a1a2a3a4-a5a6-40a7-80a8-a9aaabacadae";
        let second_id = "telltale-b1b2b3b4-b5b6-40b7-80b8-b9babcbdbebf";
        fs::write(&path, line(first_id)).expect("journal");
        let limits = FeedLimits {
            max_dedup_entries: 1,
            ..FeedLimits::default()
        };
        let mut feed = LocalEventFeed::new(
            LocalEventFeedConfig::new(&path, StartupMode::Beginning).with_limits(limits),
        )
        .expect("config");
        assert_eq!(
            event_ids(&feed.poll().expect("first poll")),
            vec![first_id.to_owned()]
        );
        append(&path, &line(second_id));
        let second = feed.poll().expect("second poll");
        append(&path, &line(first_id));
        let third = feed.poll().expect("evicted replay poll");

        assert_eq!(event_ids(&second), vec![second_id]);
        assert!(has_notice(&second, FeedNoticeCode::DedupEvicted));
        assert_eq!(event_ids(&third), vec![first_id.to_owned()]);
    }

    #[test]
    fn dedup_physical_order_wins_over_event_timestamp_order() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("events.jsonl");
        let first_id = "telltale-babbbcbc-dbde-40df-80e0-e1e2e3e4e5e6";
        let second_id = "telltale-fafbfcfd-feff-4010-8011-121314151617";
        let later = "2026-01-02T00:00:00.000Z";
        let earlier = "2026-01-01T00:00:00.000Z";
        let first = replace_once(
            replace_once(
                replace_once(valid_record(first_id), "2026-01-01T00:00:00.000Z", later),
                "2026-01-01T00:00:00.000Z",
                later,
            ),
            "2026-01-01T00:00:00.000Z",
            later,
        );
        let second = replace_once(
            replace_once(
                replace_once(valid_record(second_id), "2026-01-01T00:00:00.000Z", earlier),
                "2026-01-01T00:00:00.000Z",
                earlier,
            ),
            "2026-01-01T00:00:00.000Z",
            earlier,
        );
        let mut contents = first;
        contents.push(b'\n');
        contents.extend_from_slice(&second);
        contents.push(b'\n');
        fs::write(&path, contents).expect("journal");
        let mut feed = LocalEventFeed::from_path(&path, StartupMode::Beginning).expect("config");

        let batch = feed.poll().expect("poll");

        assert_eq!(
            event_ids(&batch),
            vec![first_id.to_owned(), second_id.to_owned()]
        );
    }

    #[test]
    fn dedup_identical_record_replayed_after_rotation_is_suppressed() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("events.jsonl");
        let record = line("telltale-18192021-2223-4024-8025-262728293031");
        fs::write(&path, &record).expect("initial journal");
        let mut feed = LocalEventFeed::from_path(&path, StartupMode::Beginning).expect("config");
        feed.poll().expect("initial poll");
        fs::rename(&path, directory.path().join("events-2026-02-05.jsonl")).expect("rotate");
        fs::write(&path, &record).expect("replayed active journal");

        let batch = feed.poll().expect("replay poll");

        assert!(batch.records.is_empty());
        assert_eq!(batch.suppressed_replays, 1);
        assert!(has_notice(&batch, FeedNoticeCode::ReplaySuppressed));
    }

    #[test]
    fn readonly_feed_operations_preserve_fixture_artifacts_across_lifecycle() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("events.jsonl");
        let before_missing = snapshot(directory.path());
        let mut feed = LocalEventFeed::from_path(&path, StartupMode::Beginning).expect("config");
        assert_eq!(snapshot(directory.path()), before_missing);

        let missing = feed.poll().expect("missing poll");
        assert!(has_notice(&missing, FeedNoticeCode::JournalUnavailable));
        assert_eq!(snapshot(directory.path()), before_missing);

        let first_id = "telltale-32333435-3637-4038-8039-404142434445";
        fs::write(&path, line(first_id)).expect("test-created journal");
        let before_append = snapshot(directory.path());
        let first = feed.poll().expect("append poll");
        assert_eq!(event_ids(&first), vec![first_id.to_owned()]);
        assert_eq!(snapshot(directory.path()), before_append);

        append(&path, b"malformed-readonly-fixture\n");
        let before_malformed = snapshot(directory.path());
        let malformed = feed.poll().expect("malformed poll");
        assert!(has_notice(&malformed, FeedNoticeCode::ParserMalformed));
        assert_eq!(snapshot(directory.path()), before_malformed);

        let rotated = directory.path().join("events-2026-02-06.jsonl");
        fs::rename(&path, &rotated).expect("test-created rotation");
        let second_id = "telltale-46474849-5051-4052-8053-545556575859";
        fs::write(&path, line(second_id)).expect("test-created active replacement");
        let before_rotation_poll = snapshot(directory.path());
        let rotated_batch = feed.poll().expect("rotation poll");
        assert_eq!(event_ids(&rotated_batch), vec![second_id.to_owned()]);
        assert_eq!(snapshot(directory.path()), before_rotation_poll);
    }

    #[test]
    fn privacy_notice_display_and_debug_are_static() {
        let notice = FeedNotice {
            code: FeedNoticeCode::ParserMalformed,
            count: 2,
        };

        assert_eq!(
            notice.to_string(),
            "local event feed notice: parser_malformed (2)"
        );
        let debug = format!("{notice:?}");
        assert!(debug.contains("ParserMalformed"));
        assert!(debug.contains('2'));
        assert!(!debug.contains("SYNTHETIC_FEED_PRIVACY_CANARY"));
    }

    #[test]
    fn privacy_invalid_limit_errors_display_and_debug_without_input_values() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("SYNTHETIC_FEED_PRIVACY_CANARY.jsonl");
        let invalid_limits = FeedLimits {
            max_events_per_poll: 0,
            ..FeedLimits::default()
        };
        let invalid_limit = LocalEventFeed::new(
            LocalEventFeedConfig::new(&path, StartupMode::Beginning).with_limits(invalid_limits),
        )
        .expect_err("invalid limit");
        let invalid_recent = LocalEventFeed::new(LocalEventFeedConfig::new(
            &path,
            StartupMode::Recent {
                max_events: 0,
                max_bytes: 1,
            },
        ))
        .expect_err("invalid recent limit");

        assert_eq!(invalid_limit.code(), LocalEventFeedErrorCode::InvalidLimit);
        assert_eq!(
            invalid_recent.code(),
            LocalEventFeedErrorCode::InvalidRecentLimit
        );
        assert_eq!(
            invalid_limit.to_string(),
            "local event feed configuration error: invalid_limit"
        );
        assert_eq!(
            invalid_recent.to_string(),
            "local event feed configuration error: invalid_recent_limit"
        );
        for error in [invalid_limit, invalid_recent] {
            let display = error.to_string();
            let debug = format!("{error:?}");
            assert!(!display.contains("SYNTHETIC_FEED_PRIVACY_CANARY"));
            assert!(!debug.contains("SYNTHETIC_FEED_PRIVACY_CANARY"));
            assert!(!display.contains(path.to_string_lossy().as_ref()));
            assert!(!debug.contains(path.to_string_lossy().as_ref()));
        }
    }

    #[test]
    fn privacy_parser_notice_mappings_redact_canary_body_and_path() {
        let directory = tempdir().expect("tempdir");
        let path = directory
            .path()
            .join("SYNTHETIC_FEED_PRIVACY_CANARY-events.jsonl");
        let canary = "SYNTHETIC_FEED_PRIVACY_CANARY";
        let cases = vec![
            (
                format!(r#"{{"body":"{canary}""#).into_bytes(),
                FeedNoticeCode::ParserMalformed,
            ),
            (
                replace_once(
                    valid_record("telltale-60616263-6465-4066-8067-686970717273"),
                    "\"schema_version\":\"3.0\"",
                    "\"schema_version\":\"2.0\"",
                ),
                FeedNoticeCode::ParserVersion,
            ),
            (
                replace_once(
                    replace_once(
                        valid_record("telltale-74757677-7879-4080-8081-828384858687"),
                        "\"client\":\"synthetic\",",
                        "",
                    ),
                    "\"source_path_hash\":\"synthetic-hash\"",
                    &format!("\"source_path_hash\":\"{canary}\""),
                ),
                FeedNoticeCode::ParserStructure,
            ),
            (
                replace_once(
                    replace_once(
                        valid_record("telltale-88898a8b-8c8d-408e-808f-909192939495"),
                        "telltale-88898a8b-8c8d-408e-808f-909192939495",
                        "bad-event-id",
                    ),
                    "\"client\":\"synthetic\"",
                    &format!("\"client\":\"{canary}\""),
                ),
                FeedNoticeCode::ParserIdentity,
            ),
            (
                replace_once(
                    replace_once(
                        valid_record("telltale-96979899-0001-4002-8003-040506070809"),
                        "\"time_source\":\"observed\"",
                        "\"time_source\":\"invalid\"",
                    ),
                    "\"client\":\"synthetic\"",
                    &format!("\"client\":\"{canary}\""),
                ),
                FeedNoticeCode::ParserSemantic,
            ),
            (
                replace_once(
                    replace_once(
                        valid_record("telltale-10111213-1415-4016-8017-181920212223"),
                        "\"event_type\":\"activity\"",
                        "\"event_type\":\"unknown_family\"",
                    ),
                    "\"client\":\"synthetic\"",
                    &format!("\"client\":\"{canary}\""),
                ),
                FeedNoticeCode::ParserFamily,
            ),
        ];
        let mut contents = Vec::new();
        for (body, expected) in &cases {
            assert_eq!(parser_notice(body), *expected);
            contents.extend_from_slice(body);
            contents.push(b'\n');
        }
        fs::write(&path, &contents).expect("privacy journal");
        let mut feed = LocalEventFeed::from_path(&path, StartupMode::Beginning).expect("config");

        let batch = feed.poll().expect("poll");
        let display = batch
            .notices
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(" ");
        let debug = format!("{:?}", batch.notices);
        let raw = String::from_utf8(contents).expect("synthetic UTF-8");
        let path_text = path.to_string_lossy();

        assert!(batch.records.is_empty());
        assert!(!display.contains(canary));
        assert!(!debug.contains(canary));
        assert!(!display.contains(&raw));
        assert!(!debug.contains(&raw));
        assert!(!display.contains(path_text.as_ref()));
        assert!(!debug.contains(path_text.as_ref()));
    }

    #[test]
    fn api_profile_path_matches_resolver_without_creating_override() {
        let user_path = resolve_log_path(PathProfile::User, None);
        let user_existed = user_path.exists();
        let user =
            LocalEventFeedConfig::for_profile(PathProfile::User, None, StartupMode::Beginning);
        assert_eq!(user.path, user_path);
        assert_eq!(user.path.exists(), user_existed);

        let directory = tempdir().expect("tempdir");
        let explicit = directory.path().join("missing/events.jsonl");
        let config = LocalEventFeedConfig::for_profile(
            PathProfile::User,
            Some(explicit.clone()),
            StartupMode::Beginning,
        );
        assert_eq!(
            config.path,
            resolve_log_path(PathProfile::User, Some(explicit.clone()))
        );
        assert!(!explicit.exists());
        assert!(!explicit.parent().expect("explicit parent").exists());
    }

    #[test]
    fn caught_up_recent_scanning_and_draining_states_are_false() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("events.jsonl");
        let first_id = "telltale-24252627-2829-4030-8031-323334353637";
        let second_id = "telltale-38394041-4243-4044-8045-464748495051";
        let mut history = line(first_id);
        history.extend_from_slice(&line(second_id));
        let line_len = line(first_id).len();
        fs::write(&path, &history).expect("journal");
        let scanning_limits = FeedLimits {
            max_bytes_per_poll: line_len,
            ..FeedLimits::default()
        };
        let mut scanning = LocalEventFeed::new(
            LocalEventFeedConfig::new(
                &path,
                StartupMode::Recent {
                    max_events: 2,
                    max_bytes: history.len(),
                },
            )
            .with_limits(scanning_limits),
        )
        .expect("scanning config");
        let scanning_batch = scanning.poll().expect("scanning poll");

        let draining_limits = FeedLimits {
            max_events_per_poll: 1,
            max_bytes_per_poll: history.len() + 1,
            ..FeedLimits::default()
        };
        let mut draining = LocalEventFeed::new(
            LocalEventFeedConfig::new(
                &path,
                StartupMode::Recent {
                    max_events: 2,
                    max_bytes: history.len(),
                },
            )
            .with_limits(draining_limits),
        )
        .expect("draining config");
        let draining_batch = draining.poll().expect("draining poll");

        assert!(scanning_batch.records.is_empty());
        assert!(!scanning_batch.caught_up);
        assert_eq!(
            scanning.recent.as_ref().expect("recent state").phase,
            RecentPhase::Scanning
        );
        assert_eq!(event_ids(&draining_batch), vec![first_id.to_owned()]);
        assert!(!draining_batch.caught_up);
        assert_eq!(
            draining.recent.as_ref().expect("recent state").phase,
            RecentPhase::Draining
        );
    }

    #[test]
    fn caught_up_is_false_for_budget_and_active_partial_frontiers() {
        let directory = tempdir().expect("tempdir");
        let budget_path = directory.path().join("budget-events.jsonl");
        let mut budget_contents = line("telltale-52535455-5657-4058-8059-606162636465");
        budget_contents.extend_from_slice(&line("telltale-66676869-7071-4072-8073-747576777879"));
        fs::write(&budget_path, budget_contents).expect("budget journal");
        let budget_limits = FeedLimits {
            max_events_per_poll: 1,
            ..FeedLimits::default()
        };
        let mut budget_feed = LocalEventFeed::new(
            LocalEventFeedConfig::new(&budget_path, StartupMode::Beginning)
                .with_limits(budget_limits),
        )
        .expect("budget config");
        let budget_batch = budget_feed.poll().expect("budget poll");

        let partial_path = directory.path().join("partial-events.jsonl");
        fs::write(&partial_path, b"partial-active-frame").expect("partial journal");
        let mut partial_feed =
            LocalEventFeed::from_path(&partial_path, StartupMode::Beginning).expect("config");
        let partial_batch = partial_feed.poll().expect("partial poll");

        assert!(!budget_batch.caught_up);
        assert!(!partial_batch.caught_up);
        assert!(has_notice(
            &partial_batch,
            FeedNoticeCode::ActivePartialFrame
        ));
    }

    #[test]
    fn caught_up_bytes_read_is_payload_only_and_noop_is_zero() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("events.jsonl");
        let first_id = "telltale-80818283-8485-4086-8087-888990919293";
        let second_id = "telltale-94959697-9899-4000-8001-020304050607";
        let first = line(first_id);
        let second = line(second_id);
        let mut contents = first.clone();
        contents.extend_from_slice(&second);
        fs::write(&path, contents).expect("journal");
        let limits = FeedLimits {
            max_bytes_per_poll: first.len(),
            ..FeedLimits::default()
        };
        let mut feed = LocalEventFeed::new(
            LocalEventFeedConfig::new(&path, StartupMode::Beginning).with_limits(limits),
        )
        .expect("config");

        let first_batch = feed.poll().expect("first poll");
        let second_batch = feed.poll().expect("second poll");
        let no_op = feed.poll().expect("no-op poll");

        assert_eq!(first_batch.bytes_read, first.len());
        assert_eq!(second_batch.bytes_read, second.len());
        assert!(!first_batch.caught_up);
        assert!(second_batch.caught_up);
        assert!(no_op.records.is_empty());
        assert_eq!(no_op.bytes_read, 0);
        assert!(no_op.caught_up);
    }

    #[test]
    fn reconciliation_budget_stops_subsequent_reads() {
        let context_limits = FeedLimits {
            max_reconciliations_per_poll: 1,
            ..FeedLimits::default()
        };
        let mut context = PollContext::new(context_limits);

        assert!(context.reconcile());
        assert!(!context.reconcile());
        assert!(!context.can_read());
        assert!(!context.can_read_bytes());
    }
}
