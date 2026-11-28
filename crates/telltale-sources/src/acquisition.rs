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
mod tests;
