//! Authoritative Canonical Observation v2 acquisition from local sources.
//!
//! Source modules own canonical semantics. Progress is operational metadata, not
//! canonical evidence or persisted scanner state. Production runtime cutover is
//! separate from this API; acquisition performs no detection or event delivery.
//!
//! File reads come in three modes: `acquire_source` opens the path by name,
//! `acquire_resolved_source` walks an already-canonical path without following a
//! link (the shared scan runtime), and `acquire_source_bounded` opens under a
//! discovery root's trust anchors for investigation.

pub use crate::source_read::BoundedReadError;
use crate::source_read::SourceReadError;
use std::fmt;
use std::path::Path;

use telltale_schema::clients::{ClientId, SourceKind};
use telltale_schema::observation::{
    BoundDimension, BoundedTarget, CanonicalBoundContext, CanonicalObservationV2, CorrelationId,
    ObservedAt, SourceScale,
};

use crate::tool_operation::{BoundedRecord, bounded_records};
use telltale_schema::record::RecordKind;
use telltale_schema::source::Source;

use crate::sources::claude::canonical::{
    ClaudeCanonicalError, ClaudeCanonicalOptions, project_claude_native_records,
};
use crate::sources::claude::native::extract_claude_native_records_with_limits;
use crate::sources::codex::canonical::{
    CodexCanonicalError, CodexCanonicalOptions, project_codex_native_records,
};
use crate::sources::codex::native::extract_codex_native_records_with_limits;
use crate::sources::copilot::canonical::{
    CopilotCanonicalError, CopilotCanonicalOptions, project_copilot_native_events,
};
use crate::sources::copilot::native::extract_copilot_native_events_with;
use crate::sources::openclaw::canonical::{
    OpenClawCanonicalError, OpenClawCanonicalOptions, project_openclaw_native_records,
};
use crate::sources::openclaw::native::extract_openclaw_native_records_with_limits;
#[cfg(feature = "opencode-sqlite")]
use crate::sources::opencode::canonical::{
    OpenCodeCanonicalError, project_opencode_native_records,
};
#[cfg(feature = "opencode-sqlite")]
use crate::sources::opencode::native::{OpenCodeNativeExtraction, extract_opencode_native_source};
#[cfg(feature = "opencode-sqlite")]
use crate::sources::opencode::session_message_canonical::{RowProjection, SessionMessageProjector};
use crate::sources::pi::canonical::{
    PiCanonicalError, PiCanonicalOptions, project_pi_native_records,
};
use crate::sources::pi::native::extract_pi_native_records_with_limits;
use crate::sources::qwen::canonical::{
    QwenCanonicalError, QwenCanonicalOptions, project_qwen_native_records,
};
use crate::sources::qwen::native::extract_qwen_native_records_with_limits;

#[cfg(test)]
use crate::sources::{
    openclaw::native::extract_openclaw_native_records, qwen::native::extract_qwen_native_records,
};

mod accounting;
mod contributions;
pub(crate) mod transcript;
use accounting::AccountingBuilder;
pub(crate) use accounting::session_identity;
pub use accounting::{
    AccountingCoverage, AttestedValue, MAX_ATTESTED_SESSIONS, NativeCounts, RecordCounts,
    SessionAccounting, SessionMetadata, SourceAccounting, ToolTableCounts, ToolUsage,
};
pub use contributions::{ActivityContributions, MAX_CONTRIBUTION_KEYS};
pub use transcript::{
    MAX_TRANSCRIPT_SOURCE_BYTES, TranscriptBatch, TranscriptEntry, TranscriptReadOptions,
    acquire_transcript, message_text as transcript_message_text,
};

pub struct AcquisitionBatch {
    pub observations: Vec<CanonicalObservationV2>,
    pub progress: AcquisitionProgress,
    pub accounting: SourceAccounting,
    /// Native units excluded because their own values exceed a size bound.
    /// Every other unit was still mapped; progress still covers these units.
    pub quarantined: Vec<QuarantinedUnit>,
    /// Native units mapped with over-bound tool values replaced, one entry per
    /// replaced field and bound. They are evaluated without those values and
    /// take no part in contribution accounting.
    pub bounded: Vec<BoundedUnit>,
    /// For a cut OpenCode v2 window: the lowest `time_updated` a next window
    /// may re-read so that it repeats at most half of this window's retained
    /// bytes. Re-reading from there lets a next window extend back past this
    /// window's high-water and still make progress.
    pub message_overlap_from: Option<i64>,
    /// How far this source's bounds scale with the bytes read: a JSONL session
    /// source's whole read, otherwise the floor.
    pub source_scale: SourceScale,
}

/// Where a quarantined native unit is, and which bound it exceeded. It
/// carries coordinates only, never source content.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuarantinedUnit {
    pub session_id: Option<String>,
    pub native_id: String,
    pub source_sequence: u64,
    /// `unbounded_value` (a canonical value bound),
    /// `invalid_native_contribution` (a request-input contribution bound) or
    /// `oversized_native_cell` (a stored payload over the read cell limit,
    /// never loaded) or `evaluation_capacity_exceeded` (rows whose smallest
    /// window still exceeded evaluation work or projection capacity).
    pub code: &'static str,
    /// The canonical field category and dimension, when the bound reports one.
    pub bound: Option<CanonicalBoundContext>,
}

/// Where a native unit with replaced tool values is, which field and which
/// bound. It carries coordinates only, never source content or the place of
/// the replaced value inside the field.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct BoundedUnit {
    pub session_id: Option<String>,
    pub native_id: String,
    pub source_sequence: u64,
    pub target: BoundedTarget,
    pub dimension: BoundDimension,
}

impl BoundedUnit {
    fn new(session_id: Option<String>, native_id: String, record: BoundedRecord) -> Self {
        Self {
            session_id,
            native_id,
            source_sequence: record.source_sequence,
            target: record.target,
            dimension: record.dimension,
        }
    }
}

/// Bounded units of a source projected as a whole, by the coordinates of the
/// observations that carry replaced values.
fn bounded_units(observations: &[CanonicalObservationV2]) -> Vec<BoundedUnit> {
    let mut units: Vec<BoundedUnit> = Vec::new();
    for observation in observations {
        let source = observation.source();
        let sequence = source.source_sequence().unwrap_or_default();
        for record in bounded_records(sequence, std::slice::from_ref(observation)) {
            let unit = BoundedUnit::new(
                observation.session_id().map(|id| id.value().to_owned()),
                source.native_id().unwrap_or_default().to_owned(),
                record,
            );
            if !units.contains(&unit) {
                units.push(unit);
            }
        }
    }
    units
}

/// One source projection owns this collector; capacity is checked before each
/// canonical observation is retained, not after an adapter returns its batch.
pub(crate) struct CanonicalCollector {
    observations: Vec<CanonicalObservationV2>,
    retained_bytes: usize,
    limit: usize,
}

impl Default for CanonicalCollector {
    fn default() -> Self {
        Self {
            observations: Vec::new(),
            retained_bytes: 0,
            limit: telltale_schema::observation::MAX_CANONICAL_RETAINED_BYTES,
        }
    }
}

impl CanonicalCollector {
    /// A source-wide collector whose retention budget scales with the source.
    pub(crate) fn scaled(scale: telltale_schema::observation::SourceScale) -> Self {
        Self {
            limit: scale.apply(telltale_schema::observation::MAX_CANONICAL_RETAINED_BYTES),
            ..Self::default()
        }
    }

    pub(crate) fn push(
        &mut self,
        observation: CanonicalObservationV2,
    ) -> Result<(), telltale_schema::observation::ObservationError> {
        use telltale_schema::observation::{ObservationError, ValidationCode};
        let bytes = self
            .retained_bytes
            .checked_add(observation.retained_byte_len())
            .filter(|bytes| *bytes <= self.limit)
            .ok_or_else(|| {
                ObservationError::from_validation_code(ValidationCode::UnboundedValue)
            })?;
        self.observations.push(observation);
        self.retained_bytes = bytes;
        Ok(())
    }

    pub(crate) fn finish(self) -> Vec<CanonicalObservationV2> {
        self.observations
    }
}

#[cfg(test)]
#[path = "acquisition_accounting_tests.rs"]
mod accounting_tests;

#[cfg(test)]
#[path = "acquisition_bound_tests.rs"]
mod bound_tests;

/// Progress names its coordinate space. A legacy `part` high-water and an
/// OpenCode v2 `session_message` high-water are different cursors: neither may
/// resume, regress-check or skip the other schema's history.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum AcquisitionProgress {
    None,
    /// Legacy `message`/`part` store: selected part `time_updated` high-water.
    OpenCodeSqlite {
        part_max_time_updated: Option<i64>,
    },
    /// OpenCode v2 `session_v2`/`session_message` store: the `time_updated`
    /// high-water of the evaluated window. `window_complete` is false when the
    /// row limit or retained budget cut the selection. Continue strictly after
    /// this raw cut while keeping a higher evaluated checkpoint separate.
    OpenCodeSessionMessages {
        message_max_time_updated: Option<i64>,
        window_complete: bool,
    },
}

pub(crate) const SQLITE_PART_LIMIT: i64 = 5_000;
/// A resumed OpenCode read re-reads parts updated within this window before the
/// prior high-water, so late or same-millisecond updates are not missed.
pub const OPENCODE_SQLITE_RESUME_OVERLAP_MS: i64 = 10 * 60 * 1_000;
/// Parts a resumed OpenCode read may select before failing as `LimitExceeded`.
pub const OPENCODE_SQLITE_RESUME_PART_LIMIT: i64 = 25_000;

/// Read controls for both OpenCode schemas. The store's schema is selected in
/// the read snapshot, and only the controls for that schema apply: `part_*` and
/// `resume_high_water` to legacy stores, `message_*` to OpenCode v2 stores.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct OpenCodeSqliteReadOptions {
    pub part_min_time_updated: Option<i64>,
    pub part_limit: i64,
    /// When set, the store's newest part must still be updated at or after this
    /// high-water; otherwise the read fails as [`AcquisitionError::ResumeRegressed`]
    /// before selecting parts. Set by callers that hold a resume position.
    pub resume_high_water: Option<i64>,
    /// Inclusive `session_message.time_updated` lower bound for an incremental
    /// OpenCode v2 read; `None` selects the newest `message_limit` rows.
    pub message_min_time_updated: Option<i64>,
    pub message_limit: i64,
    /// The `session_message` counterpart of [`Self::resume_high_water`].
    pub message_resume_high_water: Option<i64>,
    /// Retained-semantics budget for one OpenCode v2 window, at most the
    /// source-wide budget; `None` uses the source-wide budget. Callers lower
    /// it when evaluating a full window would exceed their work budget. The
    /// first whole timestamp group may exceed this adaptive target, but never
    /// the source-wide budget: a cursor cannot continue inside that group.
    pub message_window_bytes: Option<usize>,
}

impl OpenCodeSqliteReadOptions {
    /// Resume after a recorded part `time_updated` high-water, applying the one
    /// shared overlap and incremental part limit. It also sets
    /// [`Self::resume_high_water`], so a store regressed below the high-water
    /// fails as [`AcquisitionError::ResumeRegressed`] instead of reading nothing.
    pub fn resume_after(high_water: i64) -> Self {
        Self {
            part_min_time_updated: Some(
                high_water.saturating_sub(OPENCODE_SQLITE_RESUME_OVERLAP_MS),
            ),
            part_limit: OPENCODE_SQLITE_RESUME_PART_LIMIT,
            resume_high_water: Some(high_water),
            ..Self::default()
        }
    }

    /// Continue a cut OpenCode v2 window strictly after its raw cut,
    /// without the overlap, so a backlog drains even when one window cannot
    /// hold the overlap. Retain any higher `message_resume_high_water` as the
    /// regression floor; the cut may be below that checkpoint. Resume with
    /// [`Self::resume_session_messages_after`] once a window reports itself complete.
    pub fn continue_session_messages_after(self, cut: i64) -> Self {
        Self {
            message_min_time_updated: Some(cut.saturating_add(1)),
            message_limit: OPENCODE_SQLITE_RESUME_PART_LIMIT,
            message_resume_high_water: Some(
                self.message_resume_high_water
                    .map_or(cut, |floor| floor.max(cut)),
            ),
            ..self
        }
    }

    /// Every OpenCode v2 message from the earliest, for a forensic history
    /// read; a cut selection is drained with
    /// [`Self::continue_session_messages_after`].
    pub fn session_message_history(self) -> Self {
        Self {
            message_min_time_updated: Some(i64::MIN),
            message_limit: OPENCODE_SQLITE_RESUME_PART_LIMIT,
            message_resume_high_water: None,
            ..self
        }
    }

    /// Resume an OpenCode v2 checkpoint with the shared ten-minute overlap,
    /// incremental row limit and regression check. Legacy controls are unchanged.
    pub fn resume_session_messages_after(self, high_water: i64) -> Self {
        Self {
            message_min_time_updated: Some(
                high_water.saturating_sub(OPENCODE_SQLITE_RESUME_OVERLAP_MS),
            ),
            message_limit: OPENCODE_SQLITE_RESUME_PART_LIMIT,
            message_resume_high_water: Some(high_water),
            ..self
        }
    }
}

impl Default for OpenCodeSqliteReadOptions {
    fn default() -> Self {
        Self {
            part_min_time_updated: None,
            part_limit: SQLITE_PART_LIMIT,
            resume_high_water: None,
            message_min_time_updated: None,
            message_limit: SQLITE_PART_LIMIT,
            message_resume_high_water: None,
            message_window_bytes: None,
        }
    }
}

#[derive(Clone)]
pub struct AcquisitionOptions {
    pub observed_at: ObservedAt,
}

impl AcquisitionOptions {
    pub fn new(observed_at: ObservedAt) -> Self {
        Self { observed_at }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
pub enum AcquisitionError {
    UnsupportedSourceIdentity,
    SourceKindMismatch,
    SourceRead,
    /// The source identity is supported, but its acquisition was not compiled into
    /// this build (OpenCode without `opencode-sqlite`, a hook journal without
    /// `hook-journal`). No source I/O is attempted.
    CapabilityNotCompiled,
    /// A resumed OpenCode read found the store older than the resume high-water
    /// (restored or replaced, or newest parts deleted, including by session
    /// deletion). Recover with
    /// a read that carries no resume position.
    ResumeRegressed,
    /// The store holds only part of a supported native schema, or lacks its
    /// required columns. No other schema is read in its place.
    UnsupportedSourceSchema,
    BoundedSourceRead(BoundedReadError),
    InvalidAttestation,
    ConflictingSessionOwnership,
    InvalidContribution,
    ContributionCapacity,
    AttestationCapacity,
    AccountingOverflow,
    CanonicalMapping {
        code: &'static str,
    },
    CanonicalValidation {
        code: &'static str,
    },
    CanonicalBoundValidation {
        context: CanonicalBoundContext,
    },
    /// A transcript of this store is read one session at a time, and no
    /// session was named.
    TranscriptSessionRequired,
    /// This store shape gives transcript records no order that stays stable
    /// while the store grows (the legacy OpenCode schema, or a session whose
    /// `seq` is missing or repeated).
    TranscriptOrderUnavailable,
}

impl AcquisitionError {
    pub fn code(self) -> &'static str {
        match self {
            Self::UnsupportedSourceIdentity => "unsupported_source_identity",
            Self::SourceKindMismatch => "source_kind_mismatch",
            Self::SourceRead => "source_read",
            Self::CapabilityNotCompiled => "capability_not_compiled",
            Self::ResumeRegressed => "resume_regressed",
            Self::UnsupportedSourceSchema => "unsupported_source_schema",
            Self::BoundedSourceRead(reason) => reason.code(),
            Self::InvalidAttestation => "invalid_session_attestation",
            Self::ConflictingSessionOwnership => "conflicting_session_ownership",
            Self::InvalidContribution => "invalid_native_contribution",
            Self::ContributionCapacity => "native_contribution_capacity",
            Self::AttestationCapacity => "session_attestation_capacity",
            Self::AccountingOverflow => "native_accounting_overflow",
            Self::CanonicalMapping { code } | Self::CanonicalValidation { code } => code,
            Self::CanonicalBoundValidation { .. } => "unbounded_value",
            Self::TranscriptSessionRequired => "transcript_session_required",
            Self::TranscriptOrderUnavailable => "transcript_order_unavailable",
        }
    }

    pub fn bound_context(self) -> Option<CanonicalBoundContext> {
        match self {
            Self::CanonicalBoundValidation { context } => Some(context),
            _ => None,
        }
    }
}

impl fmt::Display for AcquisitionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for AcquisitionError {}

/// Acquire a migrated identity with default source read controls.
pub fn acquire_source(
    source: &Source,
    options: AcquisitionOptions,
) -> Result<AcquisitionBatch, AcquisitionError> {
    acquire_source_impl(source, options, SourceAccess::ByName)
}

/// Acquire a source whose path is already resolved: a canonical path, as from
/// `std::fs::canonicalize`, which no link names. Same limits, semantics and
/// errors as [`acquire_source`], but the file is opened by walking that path
/// from the filesystem root through directory handles without following any
/// link, and without blocking. A link, FIFO or replacement that appears after
/// the path was resolved is an unreadable source (`source_read`) rather than
/// being followed, so the bytes read belong to the resolved file. A path that
/// still contains a link is refused the same way: resolve it first.
/// OpenCode SQLite is unchanged: SQLite resolves links and opens its journal
/// files by name.
pub fn acquire_resolved_source(
    source: &Source,
    options: AcquisitionOptions,
) -> Result<AcquisitionBatch, AcquisitionError> {
    acquire_source_impl(source, options, SourceAccess::Resolved)
}

/// Finite direct JSONL read controls for on-demand investigation. These do not
/// alter production scanning or enable retired source identities.
#[derive(Debug, Clone, Copy)]
pub struct DirectReadLimits {
    pub bytes: usize,
    pub records: usize,
    pub json_depth: usize,
}

impl Default for DirectReadLimits {
    fn default() -> Self {
        Self {
            bytes: 8 * 1024 * 1024,
            records: 8192,
            json_depth: 64,
        }
    }
}

impl DirectReadLimits {
    pub fn is_valid(self) -> bool {
        let max = Self::default();
        self.bytes > 0
            && self.bytes <= max.bytes
            && self.records > 0
            && self.records <= max.records
            && self.json_depth > 0
            && self.json_depth <= max.json_depth
    }
}

/// A bounded direct read of a source coordinate under its discovery root.
#[derive(Clone, Copy)]
pub(crate) struct DirectRead<'a> {
    pub(crate) root: &'a Path,
    pub(crate) limits: DirectReadLimits,
}

/// A transcript read: production bounds, except that the caller may lower the
/// source byte bound, and no link is followed.
#[derive(Clone, Copy)]
pub(crate) struct AnchoredRead<'a> {
    /// Open under this discovery root's trust anchors; `None` walks an
    /// already-resolved path from the filesystem root.
    pub(crate) root: Option<&'a Path>,
    pub(crate) max_bytes: usize,
}

/// How a JSONL or log source coordinate is opened.
#[derive(Clone, Copy)]
pub(crate) enum SourceAccess<'a> {
    /// Production read by name: links are followed, as for any `File::open`.
    ByName,
    /// Production read of an already-resolved path, walked without links.
    Resolved,
    /// Bounded investigation read under a discovery root.
    Direct(DirectRead<'a>),
    /// Transcript read (see `transcript::acquire_transcript`).
    Anchored(AnchoredRead<'a>),
}

impl SourceAccess<'_> {
    pub(crate) fn limits(self) -> Option<DirectReadLimits> {
        match self {
            Self::Direct(direct) => Some(direct.limits),
            Self::ByName | Self::Resolved | Self::Anchored(_) => None,
        }
    }

    /// Whether a read failure keeps its bounded reason code.
    fn reports_bounded_reason(self) -> bool {
        matches!(self, Self::Direct(_) | Self::Anchored(_))
    }
}

/// Same authoritative dispatcher and native mapping, with a bounded direct-file
/// reader. Non-JSONL identities fail before I/O; OpenCode investigation is deferred.
///
/// `root` is the discovery root the source belongs to, as passed to bounded
/// discovery (`.` for the environment). The file is opened under the same trust
/// anchors, whether the coordinate was discovered or supplied by the caller:
/// the approved root is resolved once (aliases at or above it are accepted),
/// and no link below it is followed, at the file or any ancestor. A coordinate
/// outside every approved root is walked strictly from the filesystem root, so
/// no link anywhere in its path is followed. A refused link is
/// `non_regular_source`. The source path itself is
/// never rewritten, so its identity is unchanged.
pub fn acquire_source_bounded(
    root: &Path,
    source: &Source,
    options: AcquisitionOptions,
    limits: DirectReadLimits,
) -> Result<AcquisitionBatch, AcquisitionError> {
    if !limits.is_valid() {
        return Err(AcquisitionError::BoundedSourceRead(
            BoundedReadError::LimitExceeded,
        ));
    }
    acquire_source_impl(
        source,
        options,
        SourceAccess::Direct(DirectRead { root, limits }),
    )
}

fn acquire_source_impl(
    source: &Source,
    options: AcquisitionOptions,
    access: SourceAccess<'_>,
) -> Result<AcquisitionBatch, AcquisitionError> {
    let limits = access.limits();
    // The hook-journal identity of a client (`ClientId::hook_journal_source_id`)
    // reads as the journal of any client does, under its own identity. Hooks
    // only ever read a window by name, never bounded.
    let hook_journal = source.client.owns_hook_journal(&source.source_id);
    if hook_journal {
        if limits.is_some() || matches!(access, SourceAccess::Anchored(_)) {
            return Err(AcquisitionError::UnsupportedSourceIdentity);
        }
        #[cfg(not(feature = "hook-journal"))]
        return Err(AcquisitionError::CapabilityNotCompiled);
    }
    let reader = if hook_journal {
        ClientId::Claude
    } else {
        source.client
    };
    let expected_kind = match (source.client, source.source_id.as_str()) {
        _ if hook_journal => SourceKind::Jsonl,
        (ClientId::Claude, "claude.projects")
        | (ClientId::Codex, "codex.sessions")
        | (ClientId::OpenClaw, "openclaw.agents")
        | (ClientId::Qwen, "qwen.projects")
        | (ClientId::Pi, "pi.sessions") => SourceKind::Jsonl,
        (ClientId::Codex, "codex.archived_sessions") => SourceKind::ArchivedJsonl,
        (ClientId::Codex, "codex.headless_sessions") => SourceKind::HeadlessJsonl,
        (ClientId::Copilot, "copilot.process_log") if limits.is_none() => {
            SourceKind::CopilotProcessLog
        }
        (ClientId::OpenCode, "opencode.sqlite") => {
            // Bounded and transcript reads of the store have their own paths.
            if limits.is_some() || matches!(access, SourceAccess::Anchored(_)) {
                return Err(AcquisitionError::UnsupportedSourceIdentity);
            }
            return acquire_opencode_sqlite(source, options, OpenCodeSqliteReadOptions::default());
        }
        _ => return Err(AcquisitionError::UnsupportedSourceIdentity),
    };
    if source.kind != expected_kind {
        return Err(AcquisitionError::SourceKindMismatch);
    }

    let mut accounting = AccountingBuilder::default();
    let mut quarantined = Vec::new();
    let mut bounded = Vec::new();
    let mut source_scale = SourceScale::FLOOR;
    let observations = match reader {
        ClientId::Claude => {
            let (records, bytes) = extract_claude_native_records_with_limits(source, access)
                .map_err(|error| map_source_read(error, access))?;
            source_scale = SourceScale::for_source_bytes(bytes);
            // Ownership and attestation are whole-source integrity: every
            // record is counted, and checked, before any is projected.
            for record in &records {
                accounting.record(
                    record.session_id.as_deref(),
                    &record.attestation,
                    &[record.accounting_kind()],
                )?;
            }
            let canonical =
                ClaudeCanonicalOptions::new(options.observed_at).with_scale(source_scale);
            let canonical = if hook_journal {
                canonical
                    .with_adapter(
                        ClientId::HOOK_JOURNAL_ADAPTER_TYPE,
                        source.client.hook_journal_source_id(),
                    )
                    .with_tool_table(source.client)
                    // Strict on purpose: the hooks runtime projects a call it
                    // cannot evaluate whole, so a journal call over a bound is
                    // quarantined and never read as evaluated with a value
                    // replaced.
                    .with_strict_values()
            } else {
                canonical
            };
            let projection =
                project_claude_native_records(&records, &canonical).map_err(map_claude_error)?;
            let replaced = replaced_by_sequence(projection.bounded);
            let mut excluded = projection
                .quarantined
                .iter()
                .map(|unit| (unit.source_sequence, (unit.code, unit.bound)))
                .collect::<std::collections::BTreeMap<_, _>>();
            for record in &records {
                // Check this record's contribution alone before shared
                // accounting changes, so a rejected token quarantines the
                // record instead of half-counting it. Accounting counts only
                // tool calls, so only they are checked.
                let mut keys = 0;
                if record.accounting_kind() == RecordKind::ToolCall
                    && !excluded.contains_key(&record.source_sequence)
                    && let Err(error) = ActivityContributions::default().observe(
                        record.accounting_tool_name(),
                        None,
                        // A unit with replaced values keeps its label check
                        // but contributes no text.
                        record
                            .contribution_strings()
                            .iter()
                            .map(String::as_str)
                            .filter(|_| !replaced.contains_key(&record.source_sequence)),
                        &mut keys,
                    )
                {
                    match error {
                        AcquisitionError::InvalidContribution => {
                            excluded.insert(
                                record.source_sequence,
                                ("invalid_native_contribution", None),
                            );
                        }
                        error => return Err(error),
                    }
                }
                if let Some((code, bound)) = excluded.get(&record.source_sequence) {
                    quarantined.push(QuarantinedUnit {
                        session_id: record.session_id.clone(),
                        native_id: record.native_id.clone().unwrap_or_default(),
                        source_sequence: record.source_sequence,
                        code,
                        bound: *bound,
                    });
                    continue;
                }
                if let Some(records) = replaced.get(&record.source_sequence) {
                    // Nothing is derived from a value the observation does
                    // not carry: like an excluded unit, a unit with replaced
                    // values takes no part in contribution accounting.
                    // Its call's name and time are still checked.
                    accounting.check_tool_usage(
                        record.session_id.as_deref(),
                        record.accounting_kind(),
                        record.accounting_tool_name(),
                        record.timestamp.as_deref(),
                    )?;
                    bounded.extend(records.iter().map(|replaced| {
                        BoundedUnit::new(
                            record.session_id.clone(),
                            record.native_id.clone().unwrap_or_default(),
                            replaced.clone(),
                        )
                    }));
                    continue;
                }
                let session = record.session_id.as_deref();
                let kind = record.accounting_kind();
                accounting.tool_usage(
                    session,
                    kind,
                    record.accounting_tool_name(),
                    record.timestamp.as_deref(),
                )?;
                accounting.contribute(
                    session,
                    kind,
                    record.accounting_tool_name(),
                    None,
                    record.contribution_strings().iter().map(String::as_str),
                )?;
            }
            projection
                .observations
                .into_iter()
                .filter(|observation| {
                    observation
                        .source()
                        .source_sequence()
                        .is_none_or(|sequence| !excluded.contains_key(&sequence))
                })
                .collect()
        }
        ClientId::Codex => {
            let (records, bytes) = extract_codex_native_records_with_limits(source, access)
                .map_err(|error| map_source_read(error, access))?;
            source_scale = SourceScale::for_source_bytes(bytes);
            // Ownership and attestation are whole-source integrity: every
            // record is counted, and checked, before any is projected.
            for record in &records {
                accounting.record(
                    record.effective_session_id.as_deref(),
                    &record.attestation,
                    &[record.accounting_kind()],
                )?;
            }
            let projection = project_codex_native_records(
                &records,
                &CodexCanonicalOptions::new(options.observed_at).with_scale(source_scale),
            )
            .map_err(map_codex_error)?;
            let replaced = replaced_by_sequence(projection.bounded);
            let mut excluded = projection
                .quarantined
                .iter()
                .map(|unit| (unit.source_sequence, (unit.code, unit.bound)))
                .collect::<std::collections::BTreeMap<_, _>>();
            for record in &records {
                // Check this record's contribution alone before shared
                // accounting changes, so a rejected token quarantines the
                // record instead of half-counting it. Accounting counts only
                // tool calls, so only they are checked.
                let mut keys = 0;
                if record.accounting_kind() == RecordKind::ToolCall
                    && !excluded.contains_key(&record.source_sequence)
                    && let Err(error) = ActivityContributions::default().observe(
                        record.accounting_tool_name(),
                        None,
                        // A unit with replaced values keeps its label check
                        // but contributes no text.
                        record
                            .contribution_strings()
                            .iter()
                            .map(String::as_str)
                            .filter(|_| !replaced.contains_key(&record.source_sequence)),
                        &mut keys,
                    )
                {
                    match error {
                        AcquisitionError::InvalidContribution => {
                            excluded.insert(
                                record.source_sequence,
                                ("invalid_native_contribution", None),
                            );
                        }
                        error => return Err(error),
                    }
                }
                if let Some((code, bound)) = excluded.get(&record.source_sequence) {
                    quarantined.push(QuarantinedUnit {
                        session_id: record.effective_session_id.clone(),
                        native_id: record.quarantine_native_id(),
                        source_sequence: record.source_sequence,
                        code,
                        bound: *bound,
                    });
                    continue;
                }
                if let Some(records) = replaced.get(&record.source_sequence) {
                    // Nothing is derived from a value the observation does
                    // not carry: like an excluded unit, a unit with replaced
                    // values takes no part in contribution accounting.
                    // Its call's name and time are still checked.
                    accounting.check_tool_usage(
                        record.effective_session_id.as_deref(),
                        record.accounting_kind(),
                        record.accounting_tool_name(),
                        record.timestamp.as_deref(),
                    )?;
                    bounded.extend(records.iter().map(|replaced| {
                        BoundedUnit::new(
                            record.effective_session_id.clone(),
                            record.quarantine_native_id(),
                            replaced.clone(),
                        )
                    }));
                    continue;
                }
                let session = record.effective_session_id.as_deref();
                let kind = record.accounting_kind();
                accounting.tool_usage(
                    session,
                    kind,
                    record.accounting_tool_name(),
                    record.timestamp.as_deref(),
                )?;
                accounting.contribute(
                    session,
                    kind,
                    record.accounting_tool_name(),
                    None,
                    record.contribution_strings().iter().map(String::as_str),
                )?;
            }
            projection
                .observations
                .into_iter()
                .filter(|observation| {
                    observation
                        .source()
                        .source_sequence()
                        .is_none_or(|sequence| !excluded.contains_key(&sequence))
                })
                .collect()
        }
        ClientId::OpenClaw => {
            let (records, bytes) = extract_openclaw_native_records_with_limits(source, access)
                .map_err(|error| map_source_read(error, access))?;
            source_scale = SourceScale::for_source_bytes(bytes);
            for record in &records {
                accounting.record(
                    record.session_id.as_deref(),
                    &record.attestation,
                    &[record.accounting_kind()],
                )?;
            }
            let observations = project_openclaw_native_records(
                &records,
                &OpenClawCanonicalOptions::new(options.observed_at).with_scale(source_scale),
            )
            .map_err(map_openclaw_error)?;
            bounded = bounded_units(&observations);
            for record in &records {
                account_activity(
                    &mut accounting,
                    bounded
                        .iter()
                        .any(|unit| unit.source_sequence == record.source_sequence),
                    record.session_id.as_deref(),
                    record.accounting_kind(),
                    record.accounting_tool_name(),
                    record.source_timestamp.as_deref(),
                    record.contribution_strings(),
                )?;
            }
            observations
        }
        ClientId::Qwen => {
            let (records, bytes) = extract_qwen_native_records_with_limits(source, access)
                .map_err(|error| map_source_read(error, access))?;
            source_scale = SourceScale::for_source_bytes(bytes);
            for record in &records {
                accounting.record(
                    record.session_id.as_deref(),
                    &record.attestation,
                    &[record.accounting_kind()],
                )?;
            }
            let observations = project_qwen_native_records(
                &records,
                &QwenCanonicalOptions::new(options.observed_at).with_scale(source_scale),
            )
            .map_err(map_qwen_error)?;
            bounded = bounded_units(&observations);
            for record in &records {
                account_activity(
                    &mut accounting,
                    bounded
                        .iter()
                        .any(|unit| unit.source_sequence == record.source_sequence),
                    record.session_id.as_deref(),
                    record.accounting_kind(),
                    record.accounting_tool_name(),
                    record.source_timestamp.as_deref(),
                    record.contribution_strings(),
                )?;
            }
            observations
        }
        ClientId::Pi => {
            let (records, bytes) = extract_pi_native_records_with_limits(source, access)
                .map_err(|error| map_source_read(error, access))?;
            source_scale = SourceScale::for_source_bytes(bytes);
            // Ownership and attestation are whole-source integrity: every
            // record is counted, and checked, before any is projected.
            for record in &records {
                accounting.record(
                    record.session_id.as_deref(),
                    &record.attestation,
                    &[record.accounting_kind()],
                )?;
            }
            let projection = project_pi_native_records(
                &records,
                &PiCanonicalOptions::new(options.observed_at).with_scale(source_scale),
            )
            .map_err(map_pi_error)?;
            let replaced = replaced_by_sequence(projection.bounded);
            let mut excluded = projection
                .quarantined
                .iter()
                .map(|unit| (unit.source_sequence, (unit.code, unit.bound)))
                .collect::<std::collections::BTreeMap<_, _>>();
            for record in &records {
                // Check this record's contribution alone before shared
                // accounting changes, so a rejected token quarantines the
                // record instead of half-counting it.
                let mut keys = 0;
                if record.accounting_kind() == RecordKind::ToolCall
                    && !excluded.contains_key(&record.source_sequence)
                    && let Err(error) = ActivityContributions::default().observe(
                        record.accounting_tool_name(),
                        None,
                        // A unit with replaced values keeps its label check
                        // but contributes no text.
                        record
                            .contribution_strings()
                            .iter()
                            .map(String::as_str)
                            .filter(|_| !replaced.contains_key(&record.source_sequence)),
                        &mut keys,
                    )
                {
                    match error {
                        AcquisitionError::InvalidContribution => {
                            excluded.insert(
                                record.source_sequence,
                                ("invalid_native_contribution", None),
                            );
                        }
                        error => return Err(error),
                    }
                }
                if let Some((code, bound)) = excluded.get(&record.source_sequence) {
                    quarantined.push(QuarantinedUnit {
                        session_id: record.session_id.clone(),
                        native_id: record.native_id.clone().unwrap_or_default(),
                        source_sequence: record.source_sequence,
                        code,
                        bound: *bound,
                    });
                    continue;
                }
                if let Some(records) = replaced.get(&record.source_sequence) {
                    // Nothing is derived from a value the observation does
                    // not carry: like an excluded unit, a unit with replaced
                    // values takes no part in contribution accounting.
                    // Its call's name and time are still checked.
                    accounting.check_tool_usage(
                        record.session_id.as_deref(),
                        record.accounting_kind(),
                        record.accounting_tool_name(),
                        record.timestamp.as_deref(),
                    )?;
                    bounded.extend(records.iter().map(|replaced| {
                        BoundedUnit::new(
                            record.session_id.clone(),
                            record.native_id.clone().unwrap_or_default(),
                            replaced.clone(),
                        )
                    }));
                    continue;
                }
                let session = record.session_id.as_deref();
                let kind = record.accounting_kind();
                accounting.tool_usage(
                    session,
                    kind,
                    record.accounting_tool_name(),
                    record.timestamp.as_deref(),
                )?;
                accounting.contribute(
                    session,
                    kind,
                    record.accounting_tool_name(),
                    None,
                    record.contribution_strings().iter().map(String::as_str),
                )?;
            }
            projection
                .observations
                .into_iter()
                .filter(|observation| {
                    observation
                        .source()
                        .source_sequence()
                        .is_none_or(|sequence| !excluded.contains_key(&sequence))
                })
                .collect()
        }
        ClientId::Copilot => {
            let events =
                extract_copilot_native_events_with(source, access).map_err(
                    |error| match error {
                        SourceReadError::Bounded(reason @ BoundedReadError::LimitExceeded) => {
                            AcquisitionError::BoundedSourceRead(reason)
                        }
                        // Scans keep the plain read failure; only a transcript
                        // read reports its bounded reason. Bounded
                        // investigation reads never reach here.
                        error if matches!(access, SourceAccess::Anchored(_)) => {
                            map_source_read(error, access)
                        }
                        _ => AcquisitionError::SourceRead,
                    },
                )?;
            use crate::sources::copilot::native::CopilotNativeEvent;
            use telltale_schema::record::RecordKind;
            for event in &events {
                match event {
                    CopilotNativeEvent::WorkspaceInitialized {
                        source_session_id, ..
                    } => {
                        accounting.record(
                            source_session_id.as_deref(),
                            &Ok(SessionMetadata::default()),
                            &[RecordKind::SessionMeta],
                        )?;
                    }
                    CopilotNativeEvent::AccumulatedOutputItem {
                        canonical_session_id,
                        item,
                        ..
                    } => {
                        accounting.record(
                            canonical_session_id.as_deref(),
                            &item.attestation,
                            item.record_kinds(),
                        )?;
                    }
                    CopilotNativeEvent::SessionCompleted
                    | CopilotNativeEvent::MalformedStructuredOutput { .. } => {}
                }
            }
            let observations = project_copilot_native_events(
                &events,
                &CopilotCanonicalOptions::new(options.observed_at),
            )
            .map_err(map_copilot_error)?;
            bounded = bounded_units(&observations);
            for event in &events {
                let CopilotNativeEvent::AccumulatedOutputItem {
                    canonical_session_id,
                    ordinal,
                    timestamp,
                    item,
                } = event
                else {
                    continue;
                };
                // Ordinals number the items of one session. The observation
                // carries the session id as projection normalized it.
                let session = canonical_session_id
                    .as_deref()
                    .and_then(|id| CorrelationId::source_reported(id).ok());
                let replaced = bounded.iter().any(|unit| {
                    unit.session_id.as_deref() == session.as_ref().map(CorrelationId::value)
                        && Some(unit.source_sequence) == *ordinal
                });
                if item.item_type.as_deref() != Some("function_call") {
                    continue;
                }
                if replaced {
                    // Its labels are still checked; nothing is counted.
                    accounting.check_tool_usage(
                        canonical_session_id.as_deref(),
                        RecordKind::ToolCall,
                        item.name.as_deref(),
                        timestamp.as_deref(),
                    )?;
                    contributions::check_name(item.name.as_deref())?;
                    continue;
                }
                accounting.tool_usage(
                    canonical_session_id.as_deref(),
                    RecordKind::ToolCall,
                    item.name.as_deref(),
                    timestamp.as_deref(),
                )?;
                accounting.contribute(
                    canonical_session_id.as_deref(),
                    RecordKind::ToolCall,
                    item.name.as_deref(),
                    item.arguments.as_deref(),
                    // punctuation carries no path or host facts.
                    [
                        item.name.as_deref().unwrap_or("unknown"),
                        item.call_id.as_deref().unwrap_or_default(),
                    ],
                )?;
            }
            observations
        }
        _ => unreachable!("exact acquisition identity was validated"),
    };
    if limits.is_some_and(|limits| observations.len() > limits.records) {
        return Err(AcquisitionError::BoundedSourceRead(
            BoundedReadError::LimitExceeded,
        ));
    }
    // A unit evaluated without some of its values leaves evidence
    // unevaluated, as a quarantined unit does.
    let mut accounting = accounting.finish(if quarantined.is_empty() && bounded.is_empty() {
        AccountingCoverage::CompleteSource
    } else {
        AccountingCoverage::PartialSource
    });
    accounting.tool_table = crate::tool_operation::count(source.client, &observations);
    Ok(AcquisitionBatch {
        observations,
        progress: AcquisitionProgress::None,
        // Quarantined units were counted as records but not as activity.
        accounting,
        quarantined,
        bounded,
        message_overlap_from: None,
        source_scale,
    })
}

/// Replaced (field, bound) pairs of a per-record projection, by record.
fn replaced_by_sequence(
    bounded: Vec<BoundedRecord>,
) -> std::collections::BTreeMap<u64, Vec<BoundedRecord>> {
    let mut replaced = std::collections::BTreeMap::<_, Vec<_>>::new();
    for record in bounded {
        replaced
            .entry(record.source_sequence)
            .or_default()
            .push(record);
    }
    replaced
}

fn map_source_read(error: SourceReadError, access: SourceAccess<'_>) -> AcquisitionError {
    if !access.reports_bounded_reason() {
        return AcquisitionError::SourceRead;
    }
    AcquisitionError::BoundedSourceRead(match error {
        SourceReadError::Bounded(reason) => reason,
        SourceReadError::Json(_) | SourceReadError::SchemaDrift { .. } => {
            BoundedReadError::MalformedSource
        }
        _ => BoundedReadError::Unreadable,
    })
}

/// OpenCode-only bounded reads; these controls are not shared acquisition options.
pub fn acquire_opencode_sqlite(
    source: &Source,
    options: AcquisitionOptions,
    read: OpenCodeSqliteReadOptions,
) -> Result<AcquisitionBatch, AcquisitionError> {
    if source.client != ClientId::OpenCode || source.source_id != "opencode.sqlite" {
        return Err(AcquisitionError::UnsupportedSourceIdentity);
    }
    if source.kind != SourceKind::Sqlite {
        return Err(AcquisitionError::SourceKindMismatch);
    }

    #[cfg(not(feature = "opencode-sqlite"))]
    {
        let _ = (options, read);
        Err(AcquisitionError::CapabilityNotCompiled)
    }
    #[cfg(feature = "opencode-sqlite")]
    {
        use telltale_schema::observation::MAX_CANONICAL_RETAINED_BYTES;
        let extraction =
            extract_opencode_native_source(source, read).map_err(|error| match error {
                // A resumed read that selected more rows than its limit: recoverable
                // by a fresh bootstrap read, unlike an unreadable source.
                SourceReadError::Bounded(BoundedReadError::LimitExceeded) => {
                    AcquisitionError::BoundedSourceRead(BoundedReadError::LimitExceeded)
                }
                SourceReadError::ResumeRegressed => AcquisitionError::ResumeRegressed,
                SourceReadError::UnsupportedSchema => AcquisitionError::UnsupportedSourceSchema,
                _ => AcquisitionError::SourceRead,
            })?;
        let mut accounting = AccountingBuilder::default();
        let mut quarantined = Vec::new();
        let mut bounded = Vec::new();
        let mut message_overlap_from = None;
        let (observations, progress) = match extraction {
            OpenCodeNativeExtraction::Legacy(extraction) => {
                for record in &extraction.records {
                    let facts = record.accounting();
                    accounting.record(facts.session_id, facts.attestation, &[facts.kind])?;
                }
                let observations =
                    project_opencode_native_records(&extraction.records, &options.observed_at)
                        .map_err(map_canonical_error)?;
                bounded = bounded_units(&observations);
                for record in &extraction.records {
                    let (sequence, native_id) = record.coordinates();
                    let replaced = bounded.iter().any(|unit| {
                        unit.source_sequence == sequence
                            && unit.native_id == native_id.unwrap_or_default()
                    });
                    let facts = record.accounting();
                    account_activity(
                        &mut accounting,
                        replaced,
                        facts.session_id,
                        facts.kind,
                        facts.tool_name,
                        facts.timestamp,
                        &facts.contribution_strings,
                    )?;
                }
                (
                    observations,
                    AcquisitionProgress::OpenCodeSqlite {
                        part_max_time_updated: extraction.sqlite_part_max_time_updated,
                    },
                )
            }
            OpenCodeNativeExtraction::SessionMessages(extraction) => {
                // Map rows in update order and end the window on the row
                // boundary where retained semantics would exceed the
                // source-wide budget. Later rows roll to the next window.
                let window_bytes = read
                    .message_window_bytes
                    .map_or(MAX_CANONICAL_RETAINED_BYTES, |bytes| {
                        bytes.min(MAX_CANONICAL_RETAINED_BYTES)
                    });
                let mut projector = SessionMessageProjector::new(&options.observed_at);
                let mut window = Vec::new();
                let mut retained = 0usize;
                let mut cut = false;
                for record in &extraction.records {
                    let tools = record.tool_accounting();
                    let mut outcome = match projector.row(record).map_err(map_canonical_error)? {
                        RowProjection::Mapped(observations) => {
                            // A row with replaced values takes no part in
                            // contribution accounting.
                            let replaced = bounded_records(record.seq, &observations);
                            // Check this row's request input alone before any
                            // shared accounting changes, so a rejected token
                            // quarantines the row instead of half-counting it.
                            let mut keys = 0;
                            // A row with replaced values keeps its label
                            // checks but contributes no text.
                            match tools.iter().try_for_each(|tool| {
                                ActivityContributions::default().observe(
                                    tool.name,
                                    None,
                                    tool.contribution_strings
                                        .iter()
                                        .map(String::as_str)
                                        .filter(|_| replaced.is_empty()),
                                    &mut keys,
                                )
                            }) {
                                Ok(()) => Ok((observations, replaced)),
                                Err(AcquisitionError::InvalidContribution) => {
                                    Err(("invalid_native_contribution", None))
                                }
                                Err(error) => return Err(error),
                            }
                        }
                        RowProjection::Quarantined(error) => {
                            Err((error.code(), error.bound_context()))
                        }
                        RowProjection::OversizedCell => Err(("oversized_native_cell", None)),
                    };
                    if let Ok((observations, _)) = &outcome {
                        let bytes = observations
                            .iter()
                            .map(CanonicalObservationV2::retained_byte_len)
                            .fold(0usize, usize::saturating_add);
                        if retained.saturating_add(bytes) > window_bytes {
                            let first_group = extraction
                                .records
                                .first()
                                .is_some_and(|first| first.time_updated == record.time_updated);
                            if !window.is_empty()
                                && (!first_group
                                    || retained.saturating_add(bytes)
                                        > MAX_CANONICAL_RETAINED_BYTES)
                            {
                                cut = true;
                                break;
                            }
                            if bytes > MAX_CANONICAL_RETAINED_BYTES {
                                // A single row larger than any window.
                                outcome = Err(("unbounded_value", None));
                            } else {
                                // The first cursor-safe timestamp group fits a
                                // reduced target, subject to the hard budget.
                                retained += bytes;
                            }
                        } else {
                            retained += bytes;
                        }
                    }
                    window.push((record, tools, outcome));
                }
                let window_complete = !cut && !extraction.truncated;
                // The first row this window left out.
                let next = if cut {
                    extraction
                        .records
                        .get(window.len())
                        .map(|record| record.time_updated)
                } else {
                    extraction.next_time_updated
                };
                let last = window.last().map(|(record, ..)| record.time_updated);
                if !window_complete && next.is_none_or(|next| Some(next) == last) {
                    // A cut window ends on a whole `time_updated` group, so
                    // continuing strictly after its high-water skips nothing.
                    while window.len() > 1
                        && window.last().map(|(record, ..)| record.time_updated) == last
                    {
                        window.pop();
                    }
                    if window.last().map(|(record, ..)| record.time_updated) == last {
                        // One timestamp holds more rows than a whole window.
                        return Err(AcquisitionError::BoundedSourceRead(
                            BoundedReadError::LimitExceeded,
                        ));
                    }
                }
                let high_water = window.last().map(|(record, ..)| record.time_updated);
                if !window_complete {
                    // Whole `time_updated` groups from the end, while they
                    // hold at most half of this window's rows and of what it
                    // retained.
                    let bytes = |outcome: &Result<(Vec<CanonicalObservationV2>, _), _>| {
                        outcome.as_ref().map_or(0, |(observations, _)| {
                            observations
                                .iter()
                                .map(CanonicalObservationV2::retained_byte_len)
                                .fold(0usize, usize::saturating_add)
                        })
                    };
                    let half = window
                        .iter()
                        .map(|(_, _, outcome)| bytes(outcome))
                        .fold(0usize, usize::saturating_add)
                        / 2;
                    let mut tail = 0usize;
                    let mut group = 0usize;
                    let mut index = window.len();
                    while index > 0 {
                        let (record, _, outcome) = &window[index - 1];
                        group = group.saturating_add(bytes(outcome));
                        let starts_group =
                            index == 1 || window[index - 2].0.time_updated != record.time_updated;
                        if starts_group {
                            if tail.saturating_add(group) > half
                                || window.len() - (index - 1) > window.len() / 2
                            {
                                break;
                            }
                            tail += group;
                            group = 0;
                            message_overlap_from = Some(record.time_updated);
                        }
                        index -= 1;
                    }
                }
                // Evaluation and accounting follow source order.
                window.sort_by(|(left, ..), (right, ..)| {
                    (left.session_id.as_deref(), left.seq)
                        .cmp(&(right.session_id.as_deref(), right.seq))
                });
                let mut collector = CanonicalCollector::default();
                for (record, tools, outcome) in window {
                    let session = record.session_id.as_deref();
                    accounting.record(session, &record.attestation, &record.accounting_kinds())?;
                    match outcome {
                        Ok((observations, replaced)) => {
                            let activity = if replaced.is_empty() { &tools[..] } else { &[] };
                            for tool in tools.iter().filter(|_| !replaced.is_empty()) {
                                accounting.check_tool_usage(
                                    session,
                                    RecordKind::ToolCall,
                                    tool.name,
                                    tool.timestamp,
                                )?;
                            }
                            bounded.extend(replaced.into_iter().map(|replaced| {
                                BoundedUnit::new(
                                    record.session_id.clone(),
                                    record.source_id.clone().unwrap_or_default(),
                                    replaced,
                                )
                            }));
                            for tool in activity {
                                accounting.tool_usage(
                                    session,
                                    RecordKind::ToolCall,
                                    tool.name,
                                    tool.timestamp,
                                )?;
                                accounting.contribute(
                                    session,
                                    RecordKind::ToolCall,
                                    tool.name,
                                    None,
                                    tool.contribution_strings.iter().map(String::as_str),
                                )?;
                            }
                            for observation in observations {
                                collector
                                    .push(observation)
                                    .map_err(|error| map_canonical_error(error.into()))?;
                            }
                        }
                        Err((code, bound)) => quarantined.push(QuarantinedUnit {
                            session_id: record.session_id.clone(),
                            native_id: record.source_id.clone().unwrap_or_default(),
                            source_sequence: record.seq,
                            code,
                            bound,
                        }),
                    }
                }
                (
                    collector.finish(),
                    AcquisitionProgress::OpenCodeSessionMessages {
                        message_max_time_updated: high_water,
                        window_complete,
                    },
                )
            }
        };

        // A coherent selected snapshot is still not whole-database
        // replacement coverage, even without a lower bound.
        let mut accounting = accounting.finish(AccountingCoverage::PartialSource);
        accounting.tool_table = crate::tool_operation::count(ClientId::OpenCode, &observations);
        Ok(AcquisitionBatch {
            observations,
            progress,
            quarantined,
            bounded,
            message_overlap_from,
            // OpenCode reads bounded windows; its bounds stay at the floor.
            source_scale: SourceScale::FLOOR,
            accounting,
        })
    }
}

/// Tool usage and request-input contributions of one unit of a source
/// projected as a whole, after every unit was counted and projection passed.
/// A unit with replaced values is not counted, but its labels are checked
/// exactly as when it is.
fn account_activity(
    accounting: &mut AccountingBuilder,
    replaced: bool,
    session: Option<&str>,
    kind: RecordKind,
    tool_name: Option<&str>,
    timestamp: Option<&str>,
    texts: &[String],
) -> Result<(), AcquisitionError> {
    if replaced {
        accounting.check_tool_usage(session, kind, tool_name, timestamp)?;
        if kind == RecordKind::ToolCall {
            contributions::check_name(tool_name)?;
        }
        return Ok(());
    }
    accounting.tool_usage(session, kind, tool_name, timestamp)?;
    accounting.contribute(
        session,
        kind,
        tool_name,
        None,
        texts.iter().map(String::as_str),
    )
}

fn map_observation_error(
    error: telltale_schema::observation::ObservationError,
) -> AcquisitionError {
    match error.bound_context() {
        Some(context) => AcquisitionError::CanonicalBoundValidation { context },
        None => AcquisitionError::CanonicalValidation { code: error.code() },
    }
}

#[cfg(feature = "opencode-sqlite")]
fn map_canonical_error(error: OpenCodeCanonicalError) -> AcquisitionError {
    match error {
        OpenCodeCanonicalError::Mapping { code, .. } => AcquisitionError::CanonicalMapping { code },
        OpenCodeCanonicalError::Observation(error) => map_observation_error(error),
    }
}

fn map_claude_error(error: ClaudeCanonicalError) -> AcquisitionError {
    match error {
        ClaudeCanonicalError::Mapping { code, .. } => AcquisitionError::CanonicalMapping { code },
        ClaudeCanonicalError::Observation(error) => map_observation_error(error),
    }
}

fn map_pi_error(error: PiCanonicalError) -> AcquisitionError {
    match error {
        PiCanonicalError::Mapping { code, .. } => AcquisitionError::CanonicalMapping { code },
        PiCanonicalError::Observation(error) => map_observation_error(error),
    }
}

fn map_codex_error(error: CodexCanonicalError) -> AcquisitionError {
    match error {
        CodexCanonicalError::Mapping { code, .. } => AcquisitionError::CanonicalMapping { code },
        CodexCanonicalError::Observation(error) => map_observation_error(error),
    }
}

fn map_openclaw_error(error: OpenClawCanonicalError) -> AcquisitionError {
    match error {
        OpenClawCanonicalError::Mapping { code, .. } => AcquisitionError::CanonicalMapping { code },
        OpenClawCanonicalError::Observation(error) => map_observation_error(error),
    }
}

fn map_qwen_error(error: QwenCanonicalError) -> AcquisitionError {
    match error {
        QwenCanonicalError::Mapping { code, .. } => AcquisitionError::CanonicalMapping { code },
        QwenCanonicalError::Observation(error) => map_observation_error(error),
    }
}

fn map_copilot_error(error: CopilotCanonicalError) -> AcquisitionError {
    match error {
        CopilotCanonicalError::Mapping { code, .. } => AcquisitionError::CanonicalMapping { code },
        CopilotCanonicalError::Observation(error) => map_observation_error(error),
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use rusqlite::Connection;
    use telltale_schema::clients::{ClientId, SourceKind};
    use telltale_schema::observation::{ObservationBody, ObservedAt};
    use telltale_schema::source::Source;
    use tempfile::tempdir;

    use super::{
        AcquisitionError, AcquisitionOptions, AcquisitionProgress, BoundedReadError,
        OpenCodeSqliteReadOptions, acquire_opencode_sqlite,
    };

    const OBSERVED_AT: &str = "2026-09-18T12:00:00Z";

    /// A call's declared operation spends no retention: the observations of a
    /// source that fit its limit exactly, as acquired with their declarations,
    /// still fit it and one byte less does not.
    #[test]
    fn declared_operations_leave_the_retention_limit_where_it_was() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("limit.jsonl");
        let content = serde_json::json!({"type":"assistant","sessionId":"limit","message":{
            "role":"assistant","content":[{"type":"tool_use","id":"call-0","name":"Write",
            "input":{"file_path":"/synthetic/w.txt","content":"synthetic"}}]}});
        std::fs::write(&path, content.to_string()).unwrap();
        let batch = super::acquire_source(
            &Source {
                client: ClientId::Claude,
                kind: SourceKind::Jsonl,
                source_id: "claude.projects".to_owned(),
                path,
            },
            options(),
        )
        .unwrap();
        let declared = batch
            .observations
            .iter()
            .filter(|observation| match observation.body() {
                ObservationBody::Tool(tool) => tool.operation().is_some(),
                _ => false,
            })
            .count();
        assert_eq!(declared, 1);
        let total: usize = batch
            .observations
            .iter()
            .map(telltale_schema::observation::CanonicalObservationV2::retained_byte_len)
            .sum();
        let mut exact = super::CanonicalCollector {
            limit: total,
            ..super::CanonicalCollector::default()
        };
        let mut short = super::CanonicalCollector {
            limit: total - 1,
            ..super::CanonicalCollector::default()
        };
        let mut fits = true;
        let mut overflows = false;
        for observation in batch.observations {
            fits &= exact.push(observation.clone()).is_ok();
            overflows |= short.push(observation).is_err();
        }
        assert!(fits && overflows);
    }

    fn options() -> AcquisitionOptions {
        AcquisitionOptions::new(ObservedAt::new(OBSERVED_AT).unwrap())
    }

    const JSONL_IDENTITIES: &[(ClientId, &str, SourceKind)] = &[
        (ClientId::Claude, "claude.projects", SourceKind::Jsonl),
        (ClientId::OpenClaw, "openclaw.agents", SourceKind::Jsonl),
        (ClientId::Qwen, "qwen.projects", SourceKind::Jsonl),
        (ClientId::Pi, "pi.sessions", SourceKind::Jsonl),
        (ClientId::Codex, "codex.sessions", SourceKind::Jsonl),
        (
            ClientId::Codex,
            "codex.archived_sessions",
            SourceKind::ArchivedJsonl,
        ),
        (
            ClientId::Codex,
            "codex.headless_sessions",
            SourceKind::HeadlessJsonl,
        ),
    ];

    #[test]
    fn bounded_source_errors_do_not_change_production_classification() {
        for reason in [
            BoundedReadError::Missing,
            BoundedReadError::PermissionDenied,
            BoundedReadError::Unreadable,
            BoundedReadError::NonRegularSource,
            BoundedReadError::LimitExceeded,
            BoundedReadError::MalformedSource,
        ] {
            for production in [super::SourceAccess::ByName, super::SourceAccess::Resolved] {
                assert_eq!(
                    super::map_source_read(super::SourceReadError::Bounded(reason), production),
                    AcquisitionError::SourceRead
                );
            }
            let root = std::path::Path::new("synthetic-root");
            for bounded in [
                super::SourceAccess::Direct(super::DirectRead {
                    root,
                    limits: super::DirectReadLimits::default(),
                }),
                super::SourceAccess::Anchored(super::AnchoredRead {
                    root: Some(root),
                    max_bytes: 1,
                }),
            ] {
                assert_eq!(
                    super::map_source_read(super::SourceReadError::Bounded(reason), bounded),
                    AcquisitionError::BoundedSourceRead(reason)
                );
            }
        }
    }

    #[test]
    fn acquisition_denominator_matches_builtin_sources() {
        let expected = JSONL_IDENTITIES
            .iter()
            .copied()
            .chain([
                (ClientId::OpenCode, "opencode.sqlite", SourceKind::Sqlite),
                (
                    ClientId::Copilot,
                    "copilot.process_log",
                    SourceKind::CopilotProcessLog,
                ),
            ])
            .collect::<std::collections::BTreeSet<_>>();
        let registered = crate::clients::supported_clients()
            .iter()
            .flat_map(|client| {
                client
                    .sources
                    .iter()
                    .map(move |source| (client.id, source.id, source.kind))
            })
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(expected.len(), 9);
        assert_eq!(expected, registered);
        // Hook-journal identities are host-fed: no registered source is one.
        for client in ClientId::ALL {
            assert!(
                registered
                    .iter()
                    .all(|(_, source_id, _)| *source_id != client.hook_journal_source_id())
            );
        }
        let directory = tempdir().unwrap();
        for (client, source_id, kind) in registered {
            // An existing directory is unreadable as any supported source format.
            let source = Source {
                client,
                source_id: source_id.to_owned(),
                kind,
                path: directory.path().to_owned(),
            };
            let expected = if client == ClientId::OpenCode && !cfg!(feature = "opencode-sqlite") {
                AcquisitionError::CapabilityNotCompiled
            } else {
                AcquisitionError::SourceRead
            };
            assert_eq!(
                acquisition_error(super::acquire_source(&source, options())),
                expected
            );
        }
    }

    const JOURNAL_WINDOW: &str = concat!(
        r#"{"type":"user","sessionId":"synthetic-window","uuid":"u1","timestamp":"2026-11-04T00:00:00.001Z","message":{"role":"user","content":"synthetic prompt"}}"#,
        "\n",
        r#"{"type":"assistant","sessionId":"synthetic-window","uuid":"a1","timestamp":"2026-11-04T00:00:00.002Z","message":{"role":"assistant","content":[{"type":"tool_use","id":"call_1","name":"Bash","input":{"command":"ls"}}]}}"#,
        "\n",
    );

    fn journal_source(client: ClientId, source_id: &str, path: &std::path::Path) -> Source {
        Source {
            client,
            kind: SourceKind::Jsonl,
            source_id: source_id.to_owned(),
            path: path.to_owned(),
        }
    }

    /// The rule covers every client, including one with no registered source.
    #[test]
    fn every_clients_hook_journal_is_outside_the_registry() {
        let registered = crate::clients::supported_clients();
        for client in ClientId::ALL {
            let id = client.hook_journal_source_id();
            assert!(id.ends_with(".hooks"));
            assert!(
                registered
                    .iter()
                    .flat_map(|client| client.sources)
                    .all(|source| source.id != id)
            );
        }
    }

    #[test]
    #[cfg(feature = "hook-journal")]
    fn hook_journal_pairs_acquire_and_carry_their_own_identity() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("window.jsonl");
        std::fs::write(&path, JOURNAL_WINDOW).unwrap();
        let session = super::acquire_source(
            &journal_source(ClientId::Claude, "claude.projects", &path),
            options(),
        )
        .unwrap();
        assert!(!session.observations.is_empty());
        for &client in ClientId::ALL {
            let source_id = client.hook_journal_source_id();
            let source = journal_source(client, source_id, &path);
            let acquired = super::acquire_source(&source, options()).unwrap();
            assert_eq!(acquired.observations.len(), session.observations.len());
            for observation in &acquired.observations {
                assert_eq!(observation.source().adapter_id(), source_id);
                assert_eq!(
                    observation.source().adapter_type(),
                    ClientId::HOOK_JOURNAL_ADAPTER_TYPE
                );
            }
            // Only identity differs from the session reading of the same window.
            for (hook, reference) in acquired.observations.iter().zip(&session.observations) {
                // A tool call is declared by its own client's table, not Claude's.
                match reference.body() {
                    ObservationBody::Tool(tool) if tool.operation().is_some() => {
                        let mut undeclared = telltale_schema::observation::ToolObservation::new();
                        if let Some(name) = tool.name() {
                            undeclared = undeclared.with_name(name).unwrap();
                        }
                        if let Some(arguments) = tool.arguments() {
                            undeclared = undeclared.with_arguments(arguments.clone());
                        }
                        // A name's argument text holds whichever table reads it.
                        undeclared = undeclared.with_argument_text(tool.argument_text().clone());
                        let expected = crate::tool_operation::declare(
                            crate::tool_operation::table(client).unwrap_or(&[]),
                            undeclared,
                        );
                        assert_eq!(hook.body(), &ObservationBody::Tool(expected));
                    }
                    body => assert_eq!(hook.body(), body),
                }
                assert_eq!(hook.kind(), reference.kind());
                assert_eq!(hook.stage(), reference.stage());
                assert_eq!(hook.occurred_at(), reference.occurred_at());
                assert_eq!(hook.sequence(), reference.sequence());
                assert_eq!(hook.session_id(), reference.session_id());
                assert_eq!(hook.correlation(), reference.correlation());
                assert_eq!(hook.facets(), reference.facets());
                assert_eq!(hook.fact_metadata(), reference.fact_metadata());
                assert_eq!(hook.retained_byte_len(), reference.retained_byte_len());
            }
            // The same window under another identity is another source: no
            // observation is shared.
            for other in &session.observations {
                assert!(
                    acquired
                        .observations
                        .iter()
                        .all(|o| o.observation_id() != other.observation_id())
                );
            }
        }
    }

    /// A hook journal converts strictly: a call over a value bound is
    /// quarantined, never admitted with the value replaced, while the session
    /// reading of the same window admits it.
    #[test]
    #[cfg(feature = "hook-journal")]
    fn hook_journal_quarantines_a_call_over_a_value_bound() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("window.jsonl");
        let call = serde_json::json!({"type":"assistant","sessionId":"synthetic-window","uuid":"a1","timestamp":"2026-11-04T00:00:00.002Z","message":{"role":"assistant","content":[{"type":"tool_use","id":"call_1","name":"mcp__synthetic__run","input":{"query":"z ".repeat(2_500),"file_path":"/synthetic/project/notes.txt"}}]}});
        std::fs::write(&path, format!("{call}\n")).unwrap();
        let tool_calls = |batch: &super::AcquisitionBatch| {
            batch
                .observations
                .iter()
                .filter(|observation| matches!(observation.body(), ObservationBody::Tool(_)))
                .count()
        };
        let session = super::acquire_source(
            &journal_source(ClientId::Claude, "claude.projects", &path),
            options(),
        )
        .unwrap();
        assert_eq!((session.bounded.len(), session.quarantined.len()), (1, 0));
        assert_eq!(tool_calls(&session), 1);
        for &client in ClientId::ALL {
            let source = journal_source(client, client.hook_journal_source_id(), &path);
            let journal = super::acquire_source(&source, options()).unwrap();
            assert_eq!(
                (journal.bounded.len(), journal.quarantined.len()),
                (0, 1),
                "{client:?}"
            );
            assert_eq!(tool_calls(&journal), 0, "{client:?}");
        }
    }

    #[test]
    fn hook_journal_pairs_refuse_other_clients_kinds_and_bounded_reads() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("window.jsonl");
        std::fs::write(&path, JOURNAL_WINDOW).unwrap();
        let compiled = cfg!(feature = "hook-journal");
        for &client in ClientId::ALL {
            let source_id = client.hook_journal_source_id();
            for &other in ClientId::ALL.iter().filter(|other| **other != client) {
                let cross = journal_source(other, source_id, &path);
                assert_eq!(
                    acquisition_error(super::acquire_source(&cross, options())),
                    AcquisitionError::UnsupportedSourceIdentity
                );
            }
            let mut source = journal_source(client, source_id, &path);
            let bounded = super::acquire_source_bounded(
                directory.path(),
                &source,
                options(),
                super::DirectReadLimits::default(),
            );
            assert_eq!(
                acquisition_error(bounded),
                AcquisitionError::UnsupportedSourceIdentity
            );
            if !compiled {
                // An uncompiled capability: refused before any source I/O.
                assert_eq!(
                    acquisition_error(super::acquire_source(&source, options())),
                    AcquisitionError::CapabilityNotCompiled
                );
                continue;
            }
            for kind in [
                SourceKind::Json,
                SourceKind::ArchivedJsonl,
                SourceKind::HeadlessJsonl,
                SourceKind::Sqlite,
                SourceKind::CopilotProcessLog,
            ] {
                source.kind = kind;
                assert_eq!(
                    acquisition_error(super::acquire_source(&source, options())),
                    AcquisitionError::SourceKindMismatch
                );
            }
        }
    }

    #[test]
    fn jsonl_acquisition_preserves_semantics_and_replay() {
        let directory = tempdir().unwrap();
        let codex_path = directory.path().join("synthetic-codex.jsonl");
        std::fs::write(&codex_path, concat!(
            "{\"type\":\"session_meta\",\"payload\":{\"session_id\":\"acquisition-session\"}}\n",
            "{\"timestamp\":\"2026-04-27T12:10:00Z\",\"type\":\"response_item\",\"payload\":{\"type\":\"function_call\",\"name\":\"exec\",\"call_id\":\"acquisition-call\",\"arguments\":{\"command\":\"printf synthetic\"}}}\n",
            "{\"type\":\"response_item\",\"payload\":{\"type\":\"function_call_output\",\"call_id\":\"acquisition-call\",\"output\":{\"text\":\"synthetic\"}}}\n"
        )).unwrap();
        let mut codex_ids = std::collections::BTreeSet::new();
        for &(client, source_id, kind) in JSONL_IDENTITIES {
            let source = Source {
                client,
                kind,
                source_id: source_id.to_owned(),
                path: match client {
                    ClientId::Claude => crate::test_fixture_path(
                        "session_stores/claude/projects/project-b/session-tool-use.jsonl",
                    ),
                    ClientId::OpenClaw => crate::test_fixture_path(
                        "session_stores/openclaw/agents/project-b/uc001-openclaw-tool-result.jsonl",
                    ),
                    ClientId::Qwen => crate::test_fixture_path(
                        "session_stores/qwen/projects/project-b/chats/uc001-qwen-tool-result.jsonl",
                    ),
                    ClientId::Pi => crate::test_fixture_path(
                        "session_stores/pi/sessions/--synthetic-project-b--/2026-04-27T12-40-00-000Z_pi-uc001-tool-result.jsonl",
                    ),
                    _ => codex_path.clone(),
                },
            };
            let acquired = super::acquire_source(&source, options()).unwrap();
            let replay = super::acquire_source(&source, options()).unwrap();
            assert_eq!(acquired.progress, AcquisitionProgress::None);
            assert!(!acquired.observations.is_empty());
            assert_eq!(acquired.observations.len(), replay.observations.len());
            for (actual, expected) in acquired.observations.iter().zip(&replay.observations) {
                assert_eq!(actual.observation_id(), expected.observation_id());
                assert_eq!(actual.observed_at().as_str(), OBSERVED_AT);
                assert_eq!(actual.occurred_at(), expected.occurred_at());
                assert_eq!(actual.session_id(), expected.session_id());
                assert_eq!(actual.source(), expected.source());
                assert_eq!(actual.source().adapter_id(), source_id);
                assert_eq!(actual.body(), expected.body());
                assert_eq!(actual.stage(), expected.stage());
                assert_eq!(actual.correlation(), expected.correlation());
                assert_eq!(actual.fact_metadata(), expected.fact_metadata());
                assert_eq!(actual.facets(), expected.facets());
                assert_eq!(actual.capability_context(), expected.capability_context());
            }
            assert_eq!(
                acquired.observations[0].occurred_at().unwrap().as_str(),
                match client {
                    ClientId::OpenClaw => "2026-04-27T19:10:00Z",
                    ClientId::Qwen => "2026-04-27T12:40:00Z",
                    ClientId::Pi => "2026-04-27T12:40:00.200Z",
                    _ => "2026-04-27T12:10:00Z",
                }
            );
            if client == ClientId::Codex {
                assert!(codex_ids.insert(acquired.observations[0].observation_id().to_string()));
                assert!(acquired.observations[1].occurred_at().is_none());
                assert_eq!(
                    acquired.observations[0].stage(),
                    telltale_schema::observation::ObservationStage::ToolRequested
                );
            }
        }
        assert_eq!(codex_ids.len(), 3);
    }

    #[test]
    fn dispatcher_rejects_identity_and_kind_before_io() {
        let directory = tempdir().unwrap();
        let missing = directory.path().join("private-missing-source");
        let clients = crate::clients::supported_clients();
        for (client, definition) in clients
            .iter()
            .flat_map(|client| client.sources.iter().map(move |source| (client.id, source)))
        {
            let source_id = definition.id;
            let kind = definition.kind;
            let mut source = Source {
                client,
                source_id: source_id.to_owned(),
                kind,
                path: missing.clone(),
            };
            for wrong_kind in [
                SourceKind::Json,
                SourceKind::Jsonl,
                SourceKind::ArchivedJsonl,
                SourceKind::HeadlessJsonl,
                SourceKind::Sqlite,
                SourceKind::CopilotProcessLog,
            ] {
                if wrong_kind == kind {
                    continue;
                }
                source.kind = wrong_kind;
                assert_eq!(
                    acquisition_error(super::acquire_source(&source, options())),
                    AcquisitionError::SourceKindMismatch
                );
            }
            source.kind = kind;
            if client != ClientId::OpenCode {
                assert_eq!(
                    acquisition_error(acquire_opencode_sqlite(
                        &source,
                        options(),
                        OpenCodeSqliteReadOptions::default()
                    )),
                    AcquisitionError::UnsupportedSourceIdentity
                );
            }
            for wrong_client in clients.iter().map(|client| client.id) {
                if wrong_client == client {
                    continue;
                }
                source.client = wrong_client;
                assert_eq!(
                    acquisition_error(super::acquire_source(&source, options())),
                    AcquisitionError::UnsupportedSourceIdentity
                );
            }
        }
        for (client, source_id) in [
            (ClientId::OpenCode, "opencode.legacy_json"),
            (ClientId::OpenCode, "opencode.project_json"),
            (ClientId::Codex, "codex.project_sessions"),
            (ClientId::Claude, "Claude.projects"),
            (ClientId::Claude, "gemini.tmp"),
            (ClientId::Claude, "roocode.tasks"),
            (ClientId::Claude, "kilocode.tasks"),
            (ClientId::Qwen, "openclaw.agents"),
            (ClientId::OpenClaw, "qwen.projects"),
            (ClientId::OpenClaw, "OpenClaw.agents"),
            (ClientId::Qwen, "Qwen.projects"),
            (ClientId::Claude, "copilot.process_log"),
            (ClientId::Copilot, "Copilot.process_log"),
        ] {
            let source = Source {
                client,
                source_id: source_id.to_owned(),
                kind: SourceKind::Jsonl,
                path: missing.clone(),
            };
            assert_eq!(
                acquisition_error(super::acquire_source(&source, options())),
                AcquisitionError::UnsupportedSourceIdentity
            );
        }
        assert!(!missing.exists());
    }

    #[test]
    fn copilot_scan_read_failures_stay_plain_source_read_failures() {
        let directory = tempdir().unwrap();
        let source = Source {
            client: ClientId::Copilot,
            source_id: "copilot.process_log".to_owned(),
            kind: SourceKind::CopilotProcessLog,
            path: directory.path().join("missing-process.log"),
        };
        assert_eq!(
            acquisition_error(super::acquire_source(&source, options())),
            AcquisitionError::SourceRead
        );
        assert_eq!(
            acquisition_error(super::acquire_resolved_source(&source, options())),
            AcquisitionError::SourceRead
        );
    }

    #[test]
    fn bounded_acquisition_keeps_its_jsonl_only_subset() {
        let directory = tempdir().unwrap();
        let missing = directory.path().join("missing-source");
        for client in crate::clients::supported_clients() {
            for definition in client.sources {
                let source = Source {
                    client: client.id,
                    source_id: definition.id.to_owned(),
                    kind: definition.kind,
                    path: missing.clone(),
                };
                let expected = if matches!(
                    definition.kind,
                    SourceKind::Jsonl | SourceKind::ArchivedJsonl | SourceKind::HeadlessJsonl
                ) {
                    AcquisitionError::BoundedSourceRead(BoundedReadError::Missing)
                } else {
                    AcquisitionError::UnsupportedSourceIdentity
                };
                assert_eq!(
                    acquisition_error(super::acquire_source_bounded(
                        directory.path(),
                        &source,
                        options(),
                        super::DirectReadLimits::default()
                    )),
                    expected,
                    "{}",
                    definition.id
                );
            }
        }
        assert!(!missing.exists());
    }

    #[test]
    #[cfg(feature = "opencode-sqlite")]
    fn empty_opencode_progress_is_not_no_progress() {
        let (_directory, connection, source) = database();
        connection.execute("delete from part", []).unwrap();
        drop(connection);
        let batch = super::acquire_source(&source, options()).unwrap();
        assert_eq!(
            batch.progress,
            AcquisitionProgress::OpenCodeSqlite {
                part_max_time_updated: None
            }
        );
        assert_ne!(batch.progress, AcquisitionProgress::None);
    }

    #[test]
    fn openclaw_qwen_acquisition_preserves_coordinates_and_evidence_strength() {
        use telltale_schema::observation::{
            CapabilityAvailability, CapabilityId, JsonValue, ObservationStage,
        };
        let directory = tempdir().unwrap();
        let path = directory.path().join("synthetic-evidence.jsonl");
        let moved_path = directory.path().join("renamed-evidence.jsonl");
        let input = concat!(
            "{\"type\":\"user\",\"id\":\"native-message\",\"sessionId\":\"source-session\",\"content\":\"synthetic native message\"}\n",
            "{\"type\":\"user\",\"sessionId\":\"source-session\",\"content\":\"synthetic scoped message\"}\n",
            "{\"type\":\"tool_call\",\"sessionId\":\"source-session\",\"callID\":\"source-call\",\"name\":\"shell\",\"input\":{\"command\":\"printf synthetic\",\"path\":\"README.md\"}}\n",
            "{\"type\":\"tool_result\",\"sessionId\":\"source-session\",\"callID\":\"source-call\",\"tool\":\"shell\",\"output\":{\"text\":\"synthetic result\"},\"timestamp\":\"invalid-source-time\"}\n"
        );
        std::fs::write(&path, input).unwrap();
        std::fs::write(&moved_path, input).unwrap();
        for (client, source_id) in [
            (ClientId::OpenClaw, "openclaw.agents"),
            (ClientId::Qwen, "qwen.projects"),
        ] {
            let source = Source {
                client,
                source_id: source_id.to_owned(),
                kind: SourceKind::Jsonl,
                path: path.clone(),
            };
            let batch = super::acquire_source(&source, options()).unwrap();
            let relocated = super::acquire_source(
                &Source {
                    path: moved_path.clone(),
                    ..source.clone()
                },
                options(),
            )
            .unwrap();
            let reference = if client == ClientId::OpenClaw {
                super::project_openclaw_native_records(
                    &super::extract_openclaw_native_records(&source).unwrap(),
                    &super::OpenClawCanonicalOptions::new(options().observed_at),
                )
                .unwrap()
            } else {
                super::project_qwen_native_records(
                    &super::extract_qwen_native_records(&source).unwrap(),
                    &super::QwenCanonicalOptions::new(options().observed_at),
                )
                .unwrap()
            };
            assert_eq!(batch.progress, AcquisitionProgress::None);
            assert_eq!(batch.observations.len(), 4);
            assert_eq!(
                batch.observations[0].source().native_id(),
                Some("native-message")
            );
            assert!(batch.observations[1].source().native_id().is_none());
            for ((actual, moved), expected) in batch
                .observations
                .iter()
                .zip(&relocated.observations)
                .zip(&reference)
            {
                assert_eq!(actual.observation_id(), moved.observation_id());
                assert_eq!(actual.session_id(), moved.session_id());
                assert_eq!(actual.session_id().unwrap().value(), "source-session");
                assert_eq!(actual.observed_at().as_str(), OBSERVED_AT);
                assert!(actual.occurred_at().is_none());
                assert_eq!(actual.body(), expected.body());
                assert_eq!(actual.correlation(), expected.correlation());
                assert_eq!(actual.capability_context(), expected.capability_context());
                for (capability, availability) in [
                    (CapabilityId::ToolCall, CapabilityAvailability::Supported),
                    (CapabilityId::UserContext, CapabilityAvailability::Supported),
                    (CapabilityId::ToolExecution, CapabilityAvailability::Unknown),
                ] {
                    assert_eq!(
                        actual.capability_context().unwrap().resolve(capability),
                        availability
                    );
                }
                assert!(matches!(
                    actual.body(),
                    ObservationBody::Message(_) | ObservationBody::Tool(_)
                ));
                assert!(matches!(
                    actual.stage(),
                    ObservationStage::MessageObserved
                        | ObservationStage::ToolRequested
                        | ObservationStage::ToolResultReturned
                ));
            }
            for observation in &batch.observations[2..] {
                assert_eq!(
                    observation.correlation().call_id().unwrap().value(),
                    "source-call"
                );
            }
            let ObservationBody::Tool(request) = batch.observations[2].body() else {
                panic!("expected tool request")
            };
            assert_eq!(
                request.arguments(),
                Some(
                    &JsonValue::try_from_source_value(
                        &serde_json::json!({"command":"printf synthetic", "path":"README.md"})
                    )
                    .unwrap()
                )
            );
            let ObservationBody::Tool(result) = batch.observations[3].body() else {
                panic!("expected tool result")
            };
            assert_eq!(
                result.result(),
                Some(
                    &JsonValue::try_from_source_value(
                        &serde_json::json!({"text":"synthetic result"})
                    )
                    .unwrap()
                )
            );

            std::fs::write(
                &moved_path,
                format!("{{\"type\":\"session_meta\"}}\n{input}"),
            )
            .unwrap();
            let shifted = super::acquire_source(
                &Source {
                    path: moved_path.clone(),
                    ..source
                },
                options(),
            )
            .unwrap();
            assert_eq!(
                batch.observations[0].observation_id(),
                shifted.observations[0].observation_id()
            );
            assert_ne!(
                batch.observations[1].observation_id(),
                shifted.observations[1].observation_id()
            );
            std::fs::write(&moved_path, input).unwrap();
        }
    }

    #[test]
    fn codex_bound_diagnostic_quarantines_the_late_record() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("synthetic-bound.jsonl");
        let oversized = "x".repeat(65_537);
        let input = format!(
            "{}\n{}\n",
            serde_json::json!({"type":"user", "session_id":"synthetic", "content":"ok"}),
            serde_json::json!({"type":"user", "session_id":"synthetic", "content":oversized})
        );
        std::fs::write(&path, input).unwrap();
        for (source_id, kind) in [
            ("codex.sessions", SourceKind::Jsonl),
            ("codex.archived_sessions", SourceKind::ArchivedJsonl),
            ("codex.headless_sessions", SourceKind::HeadlessJsonl),
        ] {
            let source = Source {
                client: ClientId::Codex,
                source_id: source_id.into(),
                kind,
                path: path.clone(),
            };
            let batch = super::acquire_source(&source, options()).unwrap();
            assert_eq!(batch.observations.len(), 1);
            assert_eq!(batch.quarantined.len(), 1);
            assert_eq!(batch.quarantined[0].code, "unbounded_value");
            assert_eq!(
                batch.quarantined[0].session_id.as_deref(),
                Some("synthetic")
            );
            let diagnostic = format!("{:?}", batch.quarantined);
            assert!(
                diagnostic.contains("MessageContent"),
                "missing canonical category"
            );
            assert!(
                diagnostic.contains("StringBytes"),
                "missing bound dimension"
            );
            assert!(!diagnostic.contains(&oversized), "content leaked");
        }
    }

    #[test]
    fn jsonl_errors_are_bounded_and_do_not_restore_legacy_identity() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("private-path-marker.jsonl");
        for &(client, source_id, kind) in JSONL_IDENTITIES {
            let source = Source {
                client,
                source_id: source_id.to_owned(),
                kind,
                path: path.clone(),
            };
            for (payload, expected) in [
                ("{private-payload-marker", AcquisitionError::SourceRead),
                (
                    r#"{"type":"private-discriminator-marker","content":"private-payload-marker"}"#,
                    AcquisitionError::CanonicalMapping {
                        code: "unknown_discriminator",
                    },
                ),
                (
                    r#"{"type":"user","content":"private-payload-marker"}"#,
                    AcquisitionError::CanonicalValidation {
                        code: "replay_unverifiable",
                    },
                ),
            ] {
                std::fs::write(&path, payload).unwrap();
                let unknown_discriminator = expected
                    == (AcquisitionError::CanonicalMapping {
                        code: "unknown_discriminator",
                    });
                // Pi has no `user` entry type: both payloads are unknown entries.
                let pi_unknown = client == ClientId::Pi && expected != AcquisitionError::SourceRead;
                if matches!(client, ClientId::Claude | ClientId::Codex) && unknown_discriminator
                    || pi_unknown
                {
                    // Claude, Codex and Pi quarantine an unknown record by itself.
                    let batch = super::acquire_source(&source, options()).unwrap();
                    assert_eq!(batch.quarantined[0].code, "unknown_discriminator");
                    assert!(!format!("{:?}", batch.quarantined).contains("private-"));
                    continue;
                }
                let error = acquisition_error(super::acquire_source(&source, options()));
                assert_eq!(error, expected);
                let rendered = format!("{error} {error:?}");
                assert!(!rendered.contains("private-"));
            }
        }
    }

    #[test]
    fn copilot_acquisition_preserves_reference_lifecycle_and_evidence() {
        use telltale_schema::observation::{
            CapabilityAvailability, CapabilityId, ObservationStage,
        };
        let directory = tempdir().unwrap();
        let reactivated = directory.path().join("reactivated.log");
        std::fs::write(&reactivated, concat!(
            "Workspace initialized: session-a (checkpoints: 0)\n",
            "Accumulated output items (2): [{\"type\":\"reasoning\"},{\"type\":\"function_call\",\"name\":\"view\",\"call_id\":\"call-a\"}]\n",
            "Session completed.\nWorkspace initialized: session-b (checkpoints: 0)\n",
            "Accumulated output items (1): [{\"type\":\"function_call\",\"name\":\"view\"}]\n",
            "Session completed.\nWorkspace initialized: session-a (checkpoints: 0)\n",
            "Accumulated output items (1): [{\"type\":\"function_call\",\"name\":\"view\"}]\nSession completed.\n"
        )).unwrap();
        for (path, sequences) in [
            (
                crate::test_fixture_path("session_stores/copilot/process-mixed-format.log"),
                vec![1, 2, 3, 3],
            ),
            (
                crate::test_fixture_path("session_stores/copilot/process-multi-session.log"),
                vec![0, 0],
            ),
            (reactivated, vec![1, 0, 2]),
        ] {
            let source = Source {
                client: ClientId::Copilot,
                source_id: "copilot.process_log".to_owned(),
                kind: SourceKind::CopilotProcessLog,
                path,
            };
            let acquired = super::acquire_source(&source, options()).unwrap();
            let replay = super::acquire_source(&source, options()).unwrap();
            let reference = super::project_copilot_native_events(
                &crate::sources::copilot::native::extract_copilot_native_events(&source).unwrap(),
                &super::CopilotCanonicalOptions::new(options().observed_at),
            )
            .unwrap();
            assert_eq!(acquired.progress, AcquisitionProgress::None);
            assert_eq!(acquired.observations.len(), reference.len());
            assert_eq!(acquired.observations.len(), replay.observations.len());
            assert_eq!(
                acquired
                    .observations
                    .iter()
                    .map(|o| o.sequence().unwrap())
                    .collect::<Vec<_>>(),
                sequences
            );
            for ((actual, expected), repeated) in acquired
                .observations
                .iter()
                .zip(&reference)
                .zip(&replay.observations)
            {
                assert_eq!(actual.observation_id(), expected.observation_id());
                assert_eq!(actual.observation_id(), repeated.observation_id());
                assert_eq!(actual.session_id(), expected.session_id());
                assert_eq!(actual.source(), expected.source());
                assert!(actual.source().native_id().is_none());
                assert_eq!(actual.observed_at().as_str(), OBSERVED_AT);
                assert_eq!(actual.occurred_at(), expected.occurred_at());
                assert_eq!(actual.body(), expected.body());
                assert_eq!(actual.correlation(), expected.correlation());
                assert_eq!(actual.facets(), expected.facets());
                assert_eq!(actual.fact_metadata(), expected.fact_metadata());
                assert_eq!(actual.capability_context(), expected.capability_context());
                for (id, availability) in [
                    (CapabilityId::ToolCall, CapabilityAvailability::Supported),
                    (CapabilityId::ToolExecution, CapabilityAvailability::Unknown),
                    (
                        CapabilityId::UserContext,
                        CapabilityAvailability::Unsupported,
                    ),
                ] {
                    assert_eq!(
                        actual.capability_context().unwrap().resolve(id),
                        availability
                    );
                }
                assert!(matches!(
                    actual.body(),
                    ObservationBody::Message(_) | ObservationBody::Tool(_)
                ));
                assert!(matches!(
                    actual.stage(),
                    ObservationStage::MessageObserved
                        | ObservationStage::ToolRequested
                        | ObservationStage::ToolResultReturned
                ));
            }
            if sequences == [1, 2, 3, 3] {
                assert!(matches!(
                    acquired.observations[0].body(),
                    ObservationBody::Message(_)
                ));
                assert_eq!(
                    acquired.observations[0].occurred_at().unwrap().as_str(),
                    "2026-04-27T16:17:17.990Z"
                );
                assert_eq!(
                    acquired.observations[1]
                        .correlation()
                        .call_id()
                        .unwrap()
                        .value(),
                    "call_mixed_001"
                );
            }
        }
    }

    #[test]
    fn copilot_acquisition_failures_preserve_strict_reference_behavior() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("private-path-marker.log");
        let source = Source {
            client: ClientId::Copilot,
            source_id: "copilot.process_log".to_owned(),
            kind: SourceKind::CopilotProcessLog,
            path: path.clone(),
        };
        let init = "Workspace initialized: private-session-marker (checkpoints: 0)\n";
        let item = "Accumulated output items (1): [{\"type\":\"function_call\",\"name\":\"private-tool-marker\",\"call_id\":\"private-call-marker\",\"arguments\":\"private-argument-marker\",\"message\":\"private-result-marker\"}]\n";
        for (input, expected) in [
            (
                item.to_owned(),
                AcquisitionError::CanonicalMapping {
                    code: "replay_unverifiable",
                },
            ),
            (
                format!("{init}{item}Session completed.\n{item}"),
                AcquisitionError::CanonicalMapping {
                    code: "replay_unverifiable",
                },
            ),
            (
                format!("{init}{item}Accumulated output items (1): [{{private-malformed-marker"),
                AcquisitionError::CanonicalMapping {
                    code: "malformed_structured_output",
                },
            ),
            (
                "Accumulated output items (1): [private-malformed-marker".to_owned(),
                AcquisitionError::CanonicalMapping {
                    code: "replay_unverifiable",
                },
            ),
            (
                format!("{init}Accumulated output items (1): [42]"),
                AcquisitionError::SourceRead,
            ),
        ] {
            std::fs::write(&path, input).unwrap();
            let error = acquisition_error(super::acquire_source(&source, options()));
            assert_eq!(error, expected);
            assert!(!format!("{error} {error:?}").contains("private-"));
        }
        // Each invocation starts fresh, even after a previous initialized stream.
        std::fs::write(&path, format!("{init}{item}")).unwrap();
        assert!(super::acquire_source(&source, options()).is_ok());
        std::fs::write(&path, item).unwrap();
        assert_eq!(
            acquisition_error(super::acquire_source(&source, options())).code(),
            "replay_unverifiable"
        );
    }

    fn acquisition_error(
        result: Result<super::AcquisitionBatch, AcquisitionError>,
    ) -> AcquisitionError {
        match result {
            Ok(_) => panic!("expected acquisition error"),
            Err(error) => error,
        }
    }

    fn source(path: PathBuf) -> Source {
        Source {
            client: ClientId::OpenCode,
            kind: SourceKind::Sqlite,
            source_id: "opencode.sqlite".to_owned(),
            path,
        }
    }

    fn database() -> (tempfile::TempDir, Connection, Source) {
        let directory = tempdir().unwrap();
        let path = directory.path().join("synthetic-opencode.db");
        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch(
                "create table message (
                    id text, session_id text, time_created integer,
                    time_updated integer, data text
                 );
                 create table part (
                    id text, message_id text, session_id text,
                    time_created integer, time_updated integer, data text
                 );",
            )
            .unwrap();
        connection
            .execute(
                "insert into message values (?1, ?2, ?3, ?4, ?5)",
                (
                    "message-acquisition",
                    "session-acquisition",
                    1_000_i64,
                    1_000_i64,
                    r#"{"role":"assistant","modelID":"fixture-model"}"#,
                ),
            )
            .unwrap();
        for (id, updated, text) in [
            ("part-first", 1_000_i64, "first"),
            ("part-second", 2_000_i64, "second"),
            ("part-third", 3_000_i64, "third"),
        ] {
            connection
                .execute(
                    "insert into part values (?1, ?2, ?3, ?4, ?5, ?6)",
                    (
                        id,
                        "message-acquisition",
                        "session-acquisition",
                        updated,
                        updated,
                        serde_json::json!({"type":"text","text":text}).to_string(),
                    ),
                )
                .unwrap();
        }
        let source = source(path);
        (directory, connection, source)
    }

    #[test]
    #[cfg(feature = "opencode-sqlite")]
    fn long_message_sqlite_acquisition_keeps_full_suffix_and_rejects_atomically() {
        use telltale_schema::observation::{JsonValue, ObservationBody};
        let (_directory, connection, source) = database();
        for (bytes, accepted) in [(9_000, true), (65_537, false)] {
            let text = format!("{}suffix", "x".repeat(bytes - 6));
            connection
                .execute(
                    "update part set data = ?1 where id = 'part-third'",
                    [serde_json::json!({"type":"text", "text":text}).to_string()],
                )
                .unwrap();
            let result = super::acquire_source(&source, options());
            if accepted {
                let batch = result.unwrap();
                assert!(batch.observations.iter().any(|observation| matches!(observation.body(), ObservationBody::Message(message) if message.content() == Some(&JsonValue::string(&text)))));
            } else {
                assert_eq!(acquisition_error(result).code(), "unbounded_value");
            }
        }
    }

    #[test]
    fn validates_exact_identity_and_kind_before_source_io() {
        let directory = tempdir().unwrap();
        let missing = directory.path().join("must-not-be-created.db");
        for invalid in [
            Source {
                client: ClientId::Claude,
                kind: SourceKind::Sqlite,
                source_id: "opencode.sqlite".to_owned(),
                path: missing.clone(),
            },
            Source {
                client: ClientId::OpenCode,
                kind: SourceKind::Sqlite,
                source_id: "OpenCode.sqlite".to_owned(),
                path: missing.clone(),
            },
        ] {
            assert_eq!(
                acquisition_error(acquire_opencode_sqlite(
                    &invalid,
                    options(),
                    OpenCodeSqliteReadOptions::default()
                )),
                AcquisitionError::UnsupportedSourceIdentity
            );
            assert!(!missing.exists());
        }

        let wrong_kind = Source {
            client: ClientId::OpenCode,
            kind: SourceKind::Json,
            source_id: "opencode.sqlite".to_owned(),
            path: missing.clone(),
        };
        assert_eq!(
            acquisition_error(acquire_opencode_sqlite(
                &wrong_kind,
                options(),
                OpenCodeSqliteReadOptions::default()
            )),
            AcquisitionError::SourceKindMismatch
        );
        assert!(!missing.exists());
    }

    #[test]
    fn missing_opencode_database_is_not_created_by_either_acquisition_entry() {
        let directory = tempdir().unwrap();
        let source = source(directory.path().join("missing.db"));
        for error in [
            acquisition_error(super::acquire_source(&source, options())),
            acquisition_error(acquire_opencode_sqlite(
                &source,
                options(),
                OpenCodeSqliteReadOptions::default(),
            )),
        ] {
            let expected = if cfg!(feature = "opencode-sqlite") {
                AcquisitionError::SourceRead
            } else {
                AcquisitionError::CapabilityNotCompiled
            };
            assert_eq!(error, expected);
            assert!(!source.path.exists());
        }
    }

    #[cfg(not(feature = "opencode-sqlite"))]
    #[test]
    fn disabled_opencode_acquisition_does_not_touch_present_database() {
        let (directory, connection, source) = database();
        drop(connection);
        let bytes = std::fs::read(&source.path).unwrap();
        let modified = std::fs::metadata(&source.path).unwrap().modified().unwrap();
        for result in [
            super::acquire_source(&source, options()),
            acquire_opencode_sqlite(&source, options(), OpenCodeSqliteReadOptions::default()),
        ] {
            assert_eq!(
                acquisition_error(result),
                AcquisitionError::CapabilityNotCompiled
            );
        }
        assert_eq!(std::fs::read(&source.path).unwrap(), bytes);
        assert_eq!(
            std::fs::metadata(&source.path).unwrap().modified().unwrap(),
            modified
        );
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
    }

    #[test]
    #[cfg(feature = "opencode-sqlite")]
    fn malformed_serialized_message_data_fails_atomically_but_metadata_only_succeeds() {
        let (_directory, connection, source) = database();
        connection.execute("delete from part", []).unwrap();
        connection.execute("delete from message", []).unwrap();
        connection
            .execute(
                "insert into message values ('metadata', 'session', 1, 1, '{}')",
                [],
            )
            .unwrap();
        let valid = super::acquire_source(&source, options()).unwrap();
        assert_eq!(valid.accounting.sessions[0].counts.native_units, 1);
        for invalid in ["not-json", "null", "[]", "42", "\"text\""] {
            connection
                .execute(
                    "insert into message values ('malformed', 'session', 2, 2, ?1)",
                    [invalid],
                )
                .unwrap();
            assert_eq!(
                acquisition_error(super::acquire_source(&source, options())),
                AcquisitionError::SourceRead,
            );
            connection
                .execute("delete from message where id = 'malformed'", [])
                .unwrap();
        }
        connection
            .execute(
                "insert into message values ('malformed', 'session', 2, 2, NULL)",
                [],
            )
            .unwrap();
        assert_eq!(
            acquisition_error(super::acquire_source(&source, options())),
            AcquisitionError::SourceRead,
        );
    }

    #[test]
    #[cfg(feature = "opencode-sqlite")]
    fn sqlite_admission_failure_is_source_read_without_partial_acquisition() {
        let (_directory, connection, source) = database();
        let before = super::acquire_source(&source, options()).unwrap();
        connection.execute_batch("alter table message add column unknown blob; alter table part add column unknown blob;").unwrap();
        let under = super::acquire_source(&source, options()).unwrap();
        assert_eq!(
            format!("{:?}", under.observations),
            format!("{:?}", before.observations)
        );
        assert_eq!(under.accounting, before.accounting);
        assert_eq!(under.progress, before.progress);
        connection.execute_batch("insert into part values('unselected','message-acquisition','session-acquisition',4,4,'{\"type\":\"metadata\"}',zeroblob(8388609));").unwrap();
        let unselected = super::acquire_source(&source, options()).unwrap();
        assert_eq!(
            format!("{:?}", unselected.observations),
            format!("{:?}", before.observations)
        );
        assert_eq!(unselected.accounting, before.accounting);
        assert_eq!(unselected.progress, before.progress);
        connection
            .execute("delete from part where id='unselected'", [])
            .unwrap();
        for table in ["message", "part"] {
            connection
                .execute_batch(&format!("update {table} set unknown=zeroblob(8388609)"))
                .unwrap();
            let error = acquisition_error(super::acquire_source(&source, options()));
            assert_eq!(error, AcquisitionError::SourceRead);
            assert!(!format!("{error:?} {error}").contains("unknown"));
            connection
                .execute_batch(&format!("update {table} set unknown=null"))
                .unwrap();
            let repaired = super::acquire_source(&source, options()).unwrap();
            assert_eq!(
                format!("{:?}", repaired.observations),
                format!("{:?}", before.observations)
            );
            assert_eq!(repaired.accounting, before.accounting);
            assert_eq!(repaired.progress, before.progress);
        }
        connection.execute_batch("insert into message values('metadata-only','another-session',4,4,'{}',zeroblob(8388609));").unwrap();
        assert_eq!(
            acquisition_error(super::acquire_source(&source, options())),
            AcquisitionError::SourceRead
        );
    }

    #[test]
    #[cfg(feature = "opencode-sqlite")]
    fn incremental_parts_must_fit_the_effective_limit_or_fail_atomically() {
        let (_directory, connection, source) = database();
        connection.execute("delete from part", []).unwrap();
        for i in 0..7 {
            connection.execute(
                "insert into part values (?1, 'message-acquisition', 'session-acquisition', 1, ?2, '{\"type\":\"text\",\"text\":\"synthetic\"}')",
                (format!("part-{i}"), if i < 5 { 100 } else { 100 + i }),
            ).unwrap();
        }
        let read = |min, limit| {
            acquire_opencode_sqlite(
                &source,
                options(),
                OpenCodeSqliteReadOptions {
                    part_min_time_updated: min,
                    part_limit: limit,
                    resume_high_water: None,
                    ..Default::default()
                },
            )
        };
        for (limit, expected) in [(8, 7), (7, 7), (6, 6)] {
            let batch = read(Some(i64::MIN), limit);
            if limit == 6 {
                assert_eq!(
                    acquisition_error(batch),
                    AcquisitionError::BoundedSourceRead(BoundedReadError::LimitExceeded)
                );
            } else {
                assert_eq!(batch.unwrap().observations.len(), expected);
            }
        }
        // Selecting more parts than the (at least one) limit is a typed overflow.
        for limit in [0, -1, 1, 2, 3, 4, 5] {
            assert_eq!(
                acquisition_error(read(Some(100), limit)),
                AcquisitionError::BoundedSourceRead(BoundedReadError::LimitExceeded),
            );
        }
        // An unrepresentable page limit is rejected before reading.
        assert_eq!(
            acquisition_error(read(Some(100), i64::MAX)),
            AcquisitionError::SourceRead,
        );
        for limit in [0, -1, 1] {
            let one = read(Some(106), limit).unwrap();
            assert_eq!(one.observations.len(), 1);
            assert_eq!(
                one.progress,
                AcquisitionProgress::OpenCodeSqlite {
                    part_max_time_updated: Some(106)
                }
            );
        }
        assert_eq!(read(Some(105), 2).unwrap().observations.len(), 2);
        // Bootstrap still selects the newest bounded rows without overflow.
        assert_eq!(read(None, 2).unwrap().observations.len(), 2);
        let empty = read(Some(i64::MAX), 1).unwrap();
        assert!(empty.observations.is_empty());
        assert_eq!(
            empty.progress,
            AcquisitionProgress::OpenCodeSqlite {
                part_max_time_updated: None
            }
        );
        connection.execute("delete from part", []).unwrap();
        assert!(read(Some(i64::MIN), 1).unwrap().observations.is_empty());
    }

    #[test]
    #[cfg(feature = "opencode-sqlite")]
    fn dense_distinct_incremental_timestamps_fail_instead_of_truncating() {
        let (_directory, connection, source) = database();
        connection.execute("delete from part", []).unwrap();
        for i in 0..7_i64 {
            connection.execute(
                "insert into part values (?1, 'message-acquisition', 'session-acquisition', 1, ?2, '{\"type\":\"text\",\"text\":\"synthetic\"}')",
                (format!("part-{i}"), 1_000 + i),
            ).unwrap();
        }
        assert_eq!(
            acquisition_error(acquire_opencode_sqlite(
                &source,
                options(),
                OpenCodeSqliteReadOptions {
                    part_min_time_updated: Some(1_000),
                    part_limit: 5,
                    resume_high_water: None,
                    ..Default::default()
                },
            )),
            AcquisitionError::BoundedSourceRead(BoundedReadError::LimitExceeded),
        );
    }

    #[test]
    #[cfg(feature = "opencode-sqlite")]
    fn default_acquisition_preserves_canonical_semantics_and_observed_time() {
        let (_directory, connection, source) = database();
        drop(connection);

        let acquired = super::acquire_source(&source, options()).unwrap();
        assert_eq!(acquired.observations.len(), 3);
        for (observation, (id, text)) in acquired.observations.iter().zip([
            ("part-first", "first"),
            ("part-second", "second"),
            ("part-third", "third"),
        ]) {
            assert_eq!(observation.source().native_id(), Some(id));
            assert_eq!(observation.observed_at().as_str(), OBSERVED_AT);
            let ObservationBody::Message(message) = observation.body() else {
                panic!("expected text part message")
            };
            assert_eq!(
                message.content(),
                Some(&telltale_schema::observation::JsonValue::string(text))
            );
        }
        assert_eq!(
            acquired.progress,
            AcquisitionProgress::OpenCodeSqlite {
                part_max_time_updated: Some(3_000)
            }
        );
    }

    #[test]
    #[cfg(feature = "opencode-sqlite")]
    fn bounded_read_options_return_selected_progress() {
        let (_directory, connection, source) = database();
        drop(connection);
        let read = OpenCodeSqliteReadOptions {
            part_min_time_updated: Some(3_000),
            part_limit: 1,
            resume_high_water: None,
            ..Default::default()
        };

        let acquired = acquire_opencode_sqlite(&source, options(), read).unwrap();
        assert_eq!(acquired.observations.len(), 1);
        let ObservationBody::Message(message) = acquired.observations[0].body() else {
            panic!("expected selected message part")
        };
        assert_eq!(
            message.content(),
            Some(&telltale_schema::observation::JsonValue::string("third"))
        );
        assert_eq!(
            acquired.progress,
            AcquisitionProgress::OpenCodeSqlite {
                part_max_time_updated: Some(3_000)
            }
        );
    }

    #[test]
    #[cfg(feature = "opencode-sqlite")]
    fn repeated_equivalent_acquisition_is_identity_stable() {
        let (_directory, connection, source) = database();
        drop(connection);
        let first = super::acquire_source(&source, options()).unwrap();
        let second = super::acquire_source(&source, options()).unwrap();

        assert_eq!(first.progress, second.progress);
        assert_eq!(
            first
                .observations
                .iter()
                .map(|observation| observation.observation_id())
                .collect::<Vec<_>>(),
            second
                .observations
                .iter()
                .map(|observation| observation.observation_id())
                .collect::<Vec<_>>()
        );
    }

    #[test]
    #[cfg(feature = "opencode-sqlite")]
    fn acquisition_errors_do_not_expose_source_details() {
        let private_directory = tempdir().unwrap();
        let private_path = private_directory
            .path()
            .join("private-source-path-marker.db");
        std::fs::create_dir(&private_path).unwrap();
        let unreadable = source(private_path.clone());
        let error = acquisition_error(super::acquire_source(&unreadable, options()));
        assert_eq!(error, AcquisitionError::SourceRead);
        assert_eq!(error.to_string(), "source_read");
        assert!(!format!("{error:?}").contains(private_path.to_string_lossy().as_ref()));

        let (directory, connection, source) = database();
        connection
            .execute(
                "insert into part values (?1, ?2, ?3, ?4, ?5, ?6)",
                (
                    "private-part-id-marker",
                    "private-message-id-marker",
                    "private-session-id-marker",
                    4_000_i64,
                    4_000_i64,
                    r#"{"type":"tool","tool":"private-tool-marker","callID":"private-call-marker","state":{"status":"private-status-marker","input":{"command":"private-argument-marker"},"output":"private-result-marker"}}"#,
                ),
            )
            .unwrap();
        drop(connection);
        let error = acquisition_error(super::acquire_source(&source, options()));
        assert_eq!(error.code(), "unknown_tool_status");
        let rendered = format!("{error:?} {error}");
        let directory_marker = directory.path().to_string_lossy().into_owned();
        for marker in [
            directory_marker.as_str(),
            "private-part-id-marker",
            "private-message-id-marker",
            "private-session-id-marker",
            "private-tool-marker",
            "private-call-marker",
            "private-status-marker",
            "private-argument-marker",
            "private-result-marker",
        ] {
            assert!(!rendered.contains(marker));
        }
    }
}
