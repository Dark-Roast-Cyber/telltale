//! Embedding facade for Telltale: one dependency that exposes the full
//! discover → acquire → detect pipeline to a host Rust application (an EDR
//! agent, a security tool, an inference proxy).
//!
//! Results come back as values; the host decides where they go. Nothing here
//! writes JSONL, talks to a SIEM, or exits the process.
//!
//! [`Pipeline::scan_sources_detailed`] and [`Pipeline::scan_root_detailed`] are
//! the action API: canonical [`ActionFinding`]s, typed per-source outcomes
//! ([`SourceScan::failure`], [`SourceScan::coverage`],
//! [`SourceScan::visibility_limits`]), and opt-in same-pass context beside
//! unchanged session-scoped Event 3 events. Scans are stateless; the host owns
//! delivery, persistence, and retry. Replay identity is conditional, so retain
//! coordinate fallbacks bound to exact source identity. The contract and surface
//! classification live in `docs/embedding.md`; re-exports are not a lower-level
//! plugin ABI.
//!
//! The default `hooks` feature adds [`hooks`], the pre-execution enforcement
//! runtime behind `telltale hooks`. It is the one part of this crate that
//! writes files (per-session journals and a telemetry JSONL) and runs a
//! long-lived local evaluator; a host that only reads sessions builds with
//! `default-features = false` and gets none of it.
//!
//! ```no_run
//! use telltale_core::{Pipeline, PipelineError};
//!
//! let pipeline = Pipeline::builder().build()?;
//! for (source, event) in pipeline.scan_root(std::path::Path::new("tests/fixtures/session_stores"))? {
//!     println!("{}: {} {:?}", source.source_id, event.event_type, event.rule_ids);
//! }
//! # Ok::<(), PipelineError>(())
//! ```

use rule_resolution::{
    ContentFailure, InputName, NoRuleDocuments, RuleContent, RuleTier, resolve_rule_content,
};
pub use rule_resolution::{RuleContentError, RuleContentErrorCode, SkippedOverride};
use telltale_rules::package::CommunityRules;
pub use telltale_rules::package::{COMMUNITY_PACKAGE_ID, RulePackageSummary};
use telltale_rules::{CompiledRuleSet, LoadedRules, RuleLoadMode};

#[cfg(feature = "protected-assignment")]
pub mod assignment;
/// Unstable cross-crate migration seam, not a supported embedding API.
#[doc(hidden)]
pub mod canonical_runtime;
#[cfg(feature = "hooks")]
pub mod hooks;
pub mod inventory;
pub mod investigation;
pub mod local_event_feed;
pub mod provenance;
pub mod rule_resolution;

pub use local_event_feed::{
    FeedBatch, FeedLimits, FeedNotice, FeedNoticeCode, LocalEventFeed, LocalEventFeedConfig,
    LocalEventFeedError, LocalEventFeedErrorCode, StartupMode,
};

pub use canonical_runtime::FailureStage as SourceFailureStage;
pub use provenance::{
    DEFAULT_INSTALL_INVENTORY_INTERVAL_SECONDS, ProducerProvenanceOptions,
    assemble_producer_provenance_manifest,
};
pub use telltale_detect::v2::RuleCompileError;
pub use telltale_schema::clients::{ClientId, SourceKind};
pub use telltale_schema::event::Event;
pub use telltale_schema::event::Event3Record;
pub use telltale_schema::observation::ObservationError;
pub use telltale_schema::observation::{
    CanonicalBoundContext, ObservationFamily, ObservationStage,
};
pub use telltale_schema::provenance::{
    Event3ContractIdentity, ProducerFeatureSwitches, ProducerOperationalAlertThresholds,
    ProducerProvenanceError, ProducerProvenanceManifestV1, ProducerRiskThresholds,
    ProducerRuleProvenance, ProducerSuppressionProvenance, ProducerSuppressionState,
};
pub use telltale_schema::scoring::{RiskContribution, RiskContributionType};
pub use telltale_schema::source::Source;
pub use telltale_sources::acquisition::{
    AcquisitionError, BoundedReadError, BoundedUnit, QuarantinedUnit,
};
pub use telltale_sources::discovery::{
    DiscoveryError, discover_sources, discover_sources_best_effort,
    discover_watch_roots_for_clients,
};
pub use telltale_sources::paths::PathProfile;

use sha2::{Digest, Sha256};
use std::path::Path;

type BoxError = Box<dyn std::error::Error>;

pub use telltale_detect::v2::{
    ActionContextEntry, ActionContextKind, ActionContribution, ActionCoordinate, ActionEvidence,
    ActionFinding, ActionFindingKind, CanonicalActionFinding, ContextOptions,
    DEFAULT_ACTION_DOWNLOAD_LINK_SCORE, DetailedEvaluationOptions, EvaluationCompletion,
    ReplayIdentity, SemanticProvenance, Severity, VisibilityLimit,
};
mod action_record;
mod rule_catalog;
pub use rule_catalog::{
    RuleCatalogEntry, RuleCatalogKind, bundled_rule_catalog, rule_catalog_document,
};
pub use telltale_schema::action_record::{
    ACTION_RECORD_MAX_INPUT_BYTES, ACTION_RECORD_V1_ID, ACTION_RECORD_V1_SCHEMA,
    ActionRecordContext, ActionRecordContribution, ActionRecordError, ActionRecordErrorCategory,
    ActionRecordEvidence, ActionRecordFinding, ActionRecordHighlight, ActionRecordV1,
};
pub use telltale_schema::action_record_v2::{
    ACTION_RECORD_V2_ID, ACTION_RECORD_V2_SCHEMA, ActionRecordV2,
};
pub use telltale_schema::destination_facts::DestinationFacts;
pub use telltale_schema::effective_configuration::{
    AppliedOverrideV1, DefinitionKindV1, DisabledByV1, DocumentKindV1,
    EFFECTIVE_CONFIGURATION_MAX_INPUT_BYTES, EFFECTIVE_CONFIGURATION_V1_ID,
    EFFECTIVE_CONFIGURATION_V1_SCHEMA, EffectiveConfigurationError, EffectiveConfigurationV1,
    EffectiveDefinitionV1, EffectiveDocumentV1, EffectivePackageV1, PackageOriginV1, RuleTierV1,
};
pub use telltale_schema::rule_catalog::{
    RULE_CATALOG_V2_ID, RULE_CATALOG_V2_SCHEMA, RuleCatalogEntryV2, RuleCatalogError,
    RuleCatalogLogSourceV2, RuleCatalogRelatedV2, RuleCatalogV2,
};

type SourceOutcome = Result<canonical_runtime::SourceResult, canonical_runtime::SourceFailure>;

fn current_rfc3339() -> Result<String, time::error::Format> {
    time::OffsetDateTime::now_utc().format(&time::format_description::well_known::Rfc3339)
}

/// Returned failures of pipeline construction and batch scanning.
///
/// Display and Debug render closed codes and never include paths, configuration,
/// or source text. `Error::source()` retains the original cause for inspection.
/// Source-processing failures instead become per-source `scanner_error` events.
#[non_exhaustive]
pub enum PipelineError {
    /// Checked discovery could not complete; no partial listing is scanned.
    Discovery(DiscoveryError),
    /// The batch UTC clock could not be formatted as an observation time.
    Clock(BoxError),
    /// The batch observation time failed canonical validation, not a source failure.
    Observation(ObservationError),
    /// Rule documents, policy, or canonical compilation were rejected.
    /// The boxed source is diagnostic only; its concrete type is not a supported
    /// error taxonomy.
    Compilation(BoxError),
    /// No rule documents were supplied after disabling bundled defaults.
    InvalidConfiguration,
    /// Accepted rule content and policy left no effective rule, so the
    /// pipeline would detect nothing. Never built as an empty rule set.
    EmptyRuleSet,
    /// Detailed-scan options failed their closed bounds.
    InvalidOptions,
    /// A resume token does not belong to the supplied source, or the source is
    /// not resumable. Rejected before any source I/O.
    InvalidResumeToken,
}

impl std::fmt::Display for PipelineError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Discovery(_) => "pipeline_discovery_failed",
            Self::Clock(_) => "pipeline_clock_failed",
            Self::Observation(_) => "pipeline_observation_failed",
            Self::Compilation(_) => "pipeline_compilation_failed",
            Self::InvalidConfiguration => "pipeline_no_rule_documents",
            Self::EmptyRuleSet => "pipeline_empty_rule_set",
            Self::InvalidOptions => "pipeline_invalid_options",
            Self::InvalidResumeToken => "pipeline_invalid_resume_token",
        })
    }
}

impl std::fmt::Debug for PipelineError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, formatter)
    }
}

impl std::error::Error for PipelineError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Discovery(error) => Some(error),
            Self::Clock(error) | Self::Compilation(error) => Some(error.as_ref()),
            Self::Observation(error) => Some(error),
            Self::InvalidConfiguration
            | Self::EmptyRuleSet
            | Self::InvalidOptions
            | Self::InvalidResumeToken => None,
        }
    }
}

impl From<DiscoveryError> for PipelineError {
    fn from(source: DiscoveryError) -> Self {
        Self::Discovery(source)
    }
}

impl From<ObservationError> for PipelineError {
    fn from(source: ObservationError) -> Self {
        Self::Observation(source)
    }
}

impl From<time::error::Format> for PipelineError {
    fn from(source: time::error::Format) -> Self {
        Self::Clock(Box::new(source))
    }
}

impl From<RuleCompileError> for PipelineError {
    fn from(source: RuleCompileError) -> Self {
        Self::Compilation(Box::new(source))
    }
}

/// One source's session-scoped events and their precise detection occurrences.
#[non_exhaustive]
pub struct SourceScan {
    pub source: Source,
    pub events: Vec<Event>,
    pub occurrences: Vec<DetectionOccurrence>,
    pub action_findings: Vec<ActionFinding>,
    pub semantic_provenance: Option<SemanticProvenance>,
    pub completion: Option<EvaluationCompletion>,
    coverage: Option<SourceCoverage>,
    failure: Option<SourceScanFailure>,
    visibility_limits: Vec<VisibilityLimit>,
    quarantined: Vec<QuarantinedUnit>,
    bounded: Vec<BoundedUnit>,
    resume_token: Option<ResumeToken>,
}

const RESUME_TOKEN_PREFIX: &str = "resume:v1:opencode.sqlite:";
/// Marks an OpenCode v2 `session_message` position inside the v1 token family.
const SESSION_MESSAGE_COORDINATE: &str = "session_message:";
/// Older cut tokens lack the raw cut; replay their overlap on upgrade.
const SESSION_MESSAGE_DRAIN_COORDINATE: &str = "session_message_drain:";
/// Cut tokens carry both the monotone checkpoint and the raw continuation.
/// Older readers reject this coordinate rather than skip unfinished overlap.
const SESSION_MESSAGE_WINDOW_COORDINATE: &str = "session_message_window:";

/// The progress coordinate a token resumes. A legacy `part` position never
/// resumes an OpenCode v2 `session_message` store, or the reverse.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ResumeCoordinate {
    Part,
    SessionMessage,
    SessionMessageDrain,
    SessionMessageWindow(i64),
}

impl ResumeCoordinate {
    /// Positions in the same progress space, whatever the read mode.
    fn same_schema(self, other: Self) -> bool {
        matches!(
            (self, other),
            (Self::Part, Self::Part)
                | (
                    Self::SessionMessage
                        | Self::SessionMessageDrain
                        | Self::SessionMessageWindow(_),
                    Self::SessionMessage
                        | Self::SessionMessageDrain
                        | Self::SessionMessageWindow(_)
                )
        )
    }
}

/// Opaque, versioned position after a successful scan of a resumable source
/// (`opencode.sqlite` today). It is bound to one source, carries a monotone
/// checkpoint and (for unfinished v2 windows) a separate raw cut, and contains
/// no path or content. Persist [`ResumeToken::as_str`] only after durably
/// accepting that scan's findings, and pass the parsed token to
/// [`Pipeline::scan_source_detailed_resuming`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResumeToken {
    text: String,
    binding: String,
    coordinate: ResumeCoordinate,
    high_water: i64,
}

impl ResumeToken {
    fn new(binding: String, coordinate: ResumeCoordinate, high_water: i64) -> Self {
        let position = match coordinate {
            ResumeCoordinate::Part => high_water.to_string(),
            ResumeCoordinate::SessionMessage => format!("{SESSION_MESSAGE_COORDINATE}{high_water}"),
            ResumeCoordinate::SessionMessageDrain => {
                format!("{SESSION_MESSAGE_DRAIN_COORDINATE}{high_water}")
            }
            ResumeCoordinate::SessionMessageWindow(cut) => {
                format!("{SESSION_MESSAGE_WINDOW_COORDINATE}{high_water}:{cut}")
            }
        };
        Self {
            text: format!("{RESUME_TOKEN_PREFIX}{position}:{binding}"),
            binding,
            coordinate,
            high_water,
        }
    }

    /// The stable text form for host persistence.
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// Parse a persisted token. Unknown versions and malformed text are errors.
    pub fn parse(text: &str) -> Result<Self, ResumeTokenError> {
        let rest = text
            .strip_prefix(RESUME_TOKEN_PREFIX)
            .ok_or(ResumeTokenError)?;
        let window = rest.starts_with(SESSION_MESSAGE_WINDOW_COORDINATE);
        let (mut coordinate, rest) =
            if let Some(rest) = rest.strip_prefix(SESSION_MESSAGE_WINDOW_COORDINATE) {
                (ResumeCoordinate::SessionMessageWindow(0), rest)
            } else if let Some(rest) = rest.strip_prefix(SESSION_MESSAGE_COORDINATE) {
                (ResumeCoordinate::SessionMessage, rest)
            } else if let Some(rest) = rest.strip_prefix(SESSION_MESSAGE_DRAIN_COORDINATE) {
                (ResumeCoordinate::SessionMessageDrain, rest)
            } else {
                (ResumeCoordinate::Part, rest)
            };
        let (high_water, binding) = rest.split_once(':').ok_or(ResumeTokenError)?;
        let high_water = high_water
            .parse::<i64>()
            .ok()
            .filter(|value| *value >= 0 && high_water == value.to_string())
            .ok_or(ResumeTokenError)?;
        let binding = if window {
            let (cut_text, binding) = binding.split_once(':').ok_or(ResumeTokenError)?;
            let cut = cut_text
                .parse::<i64>()
                .ok()
                .filter(|cut| *cut <= high_water && cut_text == cut.to_string())
                .ok_or(ResumeTokenError)?;
            coordinate = ResumeCoordinate::SessionMessageWindow(cut);
            binding
        } else {
            binding
        };
        if binding.len() != 64
            || !binding
                .bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        {
            return Err(ResumeTokenError);
        }
        Ok(Self::new(binding.to_owned(), coordinate, high_water))
    }
}

impl std::fmt::Display for ResumeToken {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.text)
    }
}

/// A persisted resume token could not be parsed. Renders a closed code only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct ResumeTokenError;

impl std::fmt::Display for ResumeTokenError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("invalid_resume_token")
    }
}

impl std::error::Error for ResumeTokenError {}

/// The selected schema's high-water, never earlier than a token of the same
/// coordinate. A token for the other schema does not bound the new one; when the
/// selected schema reported nothing yet, the resumed token is returned unchanged.
fn resume_token(
    source: &Source,
    progress: telltale_sources::acquisition::AcquisitionProgress,
    resumed_from: Option<(ResumeCoordinate, i64)>,
) -> Option<ResumeToken> {
    use telltale_sources::acquisition::AcquisitionProgress;
    if !is_resumable(source) {
        return None;
    }
    let (coordinate, high_water) = match progress {
        AcquisitionProgress::OpenCodeSqlite {
            part_max_time_updated,
        } => (ResumeCoordinate::Part, part_max_time_updated),
        AcquisitionProgress::OpenCodeSessionMessages {
            message_max_time_updated,
            window_complete,
        } => (
            if window_complete {
                ResumeCoordinate::SessionMessage
            } else {
                ResumeCoordinate::SessionMessageWindow(message_max_time_updated?)
            },
            message_max_time_updated,
        ),
        AcquisitionProgress::None => return None,
    };
    // Only the checkpoint is clamped. A cut's raw continuation remains in its
    // coordinate, including when it falls inside unfinished overlap below it.
    let prior = resumed_from
        .filter(|(resumed, _)| resumed.same_schema(coordinate))
        .map(|(_, high_water)| high_water);
    match high_water.max(prior) {
        Some(high_water) => Some(ResumeToken::new(
            resume_binding(source),
            coordinate,
            high_water,
        )),
        None => resumed_from.map(|(resumed, high_water)| {
            ResumeToken::new(resume_binding(source), resumed, high_water)
        }),
    }
}

fn is_resumable(source: &Source) -> bool {
    source.client == ClientId::OpenCode
        && source.kind == SourceKind::Sqlite
        && source.source_id == "opencode.sqlite"
}

/// Source binding for resume tokens: length-framed client, source identity, and
/// the exact platform-native path. Distinct paths never share a binding, even
/// when their lossy UTF-8 renderings collide. No raw path is retained.
fn resume_binding(source: &Source) -> String {
    use sha2::{Digest, Sha256};
    let path = native_path_bytes(&source.path);
    let mut hasher = Sha256::new();
    for part in [
        b"telltale.resume.v1".as_slice(),
        source.client.as_str().as_bytes(),
        source.source_id.as_bytes(),
        path.0.as_bytes(),
        &path.1,
    ] {
        hasher.update((part.len() as u64).to_le_bytes());
        hasher.update(part);
    }
    hex::encode(hasher.finalize())
}

/// Path encoding tag and exact bytes: Unix bytes, or Windows UTF-16LE units.
fn native_path_bytes(path: &std::path::Path) -> (&'static str, Vec<u8>) {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        ("unix-bytes", path.as_os_str().as_bytes().to_vec())
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        (
            "windows-utf16le",
            path.as_os_str()
                .encode_wide()
                .flat_map(u16::to_le_bytes)
                .collect(),
        )
    }
    #[cfg(not(any(unix, windows)))]
    {
        ("utf8", path.to_string_lossy().into_owned().into_bytes())
    }
}

/// How much of one successfully scanned source was evaluated.
///
/// This is acquisition scope, not rule visibility: `completion` separately
/// reports whether enabled rules could observe their targets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SourceCoverage {
    /// Every countable native unit of the acquired read was evaluated. File
    /// reads cover the acquired byte stream, not an atomic filesystem revision.
    WholeSource,
    /// A bounded selection or quarantined native units left evidence unevaluated.
    /// No finding is not evidence about excluded units or unselected history;
    /// a later bounded scan may no longer select an earlier action.
    Partial,
}

/// Typed, content-free reason one source produced a `scanner_error` and no
/// successful findings. Debug renders closed codes only, never paths or content.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct SourceScanFailure {
    stage: SourceFailureStage,
    acquisition: Option<AcquisitionError>,
}

impl SourceScanFailure {
    pub fn stage(&self) -> SourceFailureStage {
        self.stage
    }
    /// Present only for acquisition failures.
    pub fn acquisition_error(&self) -> Option<AcquisitionError> {
        self.acquisition
    }
    /// The closed code carried by the source's Event 3 `scanner_error`.
    pub fn code(&self) -> &'static str {
        self.stage.code()
    }
}

/// A canonical observation associated with a finding, without content or paths.
#[non_exhaustive]
pub struct DetectionOccurrence {
    pub identity: OccurrenceId,
    /// Index into the containing [`SourceScan::events`], not an Event3 identity.
    pub finding_index: usize,
    pub session_id: String,
    /// Ordered session observation index, matching detection timeline anchors.
    pub timeline_index: Option<usize>,
    /// Source-reported time only; absence is never filled with a scan clock.
    pub occurred_at: Option<String>,
    pub rule_ids: Vec<String>,
    pub categories: Vec<String>,
    /// Selector-derived names; empty for process/correlation findings.
    pub evidence_fields: Vec<String>,
}

/// Validated, opaque Canonical Observation v2 identity, not a content hash.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct OccurrenceId(String);

impl OccurrenceId {
    /// Coordinate identity for an action finding; distinct from its optional
    /// replay identity. This never hashes or reparses evidence.
    pub fn from_action_finding(finding: &ActionFinding) -> Self {
        Self(finding.observation_id().to_owned())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl SourceScan {
    /// Evaluated acquisition scope; `None` exactly when the source failed.
    pub fn coverage(&self) -> Option<SourceCoverage> {
        self.coverage
    }

    /// Closed reasons for `VisibilityLimited` completion, in stable order. Empty
    /// for `Complete` and for failed sources.
    pub fn visibility_limits(&self) -> &[VisibilityLimit] {
        &self.visibility_limits
    }

    /// Native units this successful scan excluded because their own values
    /// exceed a size bound, by coordinates only. Every other unit was
    /// evaluated; progress covers these units, so rescanning will not retry
    /// them. Empty for failed sources.
    pub fn quarantined(&self) -> &[QuarantinedUnit] {
        &self.quarantined
    }

    /// Native units this successful scan evaluated with over-bound tool
    /// values replaced: one entry per unit, field and bound, by coordinates
    /// only. Their other values were evaluated; coverage is `Partial`.
    /// Empty for failed sources.
    pub fn bounded_units(&self) -> &[BoundedUnit] {
        &self.bounded
    }

    /// Typed failure; `Some` exactly when the source failed. Prefer this over
    /// matching Event 3 `event_type` strings or inferring from `completion`.
    pub fn failure(&self) -> Option<&SourceScanFailure> {
        self.failure.as_ref()
    }

    /// Position to resume this source from, after a successful scan of a
    /// resumable source; `None` for other sources, on failure, or when nothing
    /// has been read yet. Never earlier than the token the scan resumed from.
    pub fn resume_token(&self) -> Option<&ResumeToken> {
        self.resume_token.as_ref()
    }

    fn from_result(
        source: Source,
        result: SourceOutcome,
        resumed_from: Option<(ResumeCoordinate, i64)>,
    ) -> Self {
        let success = result.and_then(|mut result| {
            let occurrences = std::mem::take(&mut result.occurrences)
                .into_iter()
                .map(|occurrence| {
                    if !telltale_schema::observation::valid_observation_id(
                        &occurrence.observation_id,
                    ) {
                        return Err(canonical_runtime::SourceFailure {
                            stage: canonical_runtime::FailureStage::Projection,
                            progress: result.progress,
                            acquisition: None,
                            processing: Some(telltale_detect::v2::ProcessingError::Projection),
                        });
                    }
                    Ok(DetectionOccurrence {
                        identity: OccurrenceId(occurrence.observation_id),
                        finding_index: occurrence.finding_index,
                        session_id: occurrence.session_id,
                        timeline_index: occurrence.timeline_index,
                        occurred_at: occurrence.occurred_at,
                        rule_ids: occurrence.rule_ids,
                        categories: occurrence.categories,
                        evidence_fields: occurrence.evidence_fields,
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok((result, occurrences))
        });
        match success {
            Ok((result, occurrences)) => Self {
                events: result.events,
                occurrences,
                action_findings: result.action_findings,
                semantic_provenance: Some(result.semantic_provenance),
                completion: Some(result.completion),
                coverage: Some(match result.accounting.coverage {
                    telltale_sources::acquisition::AccountingCoverage::CompleteSource => {
                        SourceCoverage::WholeSource
                    }
                    telltale_sources::acquisition::AccountingCoverage::PartialSource => {
                        SourceCoverage::Partial
                    }
                }),
                failure: None,
                visibility_limits: result.visibility_limits,
                quarantined: result.quarantined,
                bounded: result.bounded,
                resume_token: resume_token(&source, result.progress, resumed_from),
                source,
            },
            Err(error) => Self {
                events: vec![error.event(&source)],
                source,
                occurrences: Vec::new(),
                action_findings: Vec::new(),
                semantic_provenance: None,
                completion: None,
                coverage: None,
                failure: Some(SourceScanFailure {
                    stage: error.stage,
                    acquisition: error.acquisition,
                }),
                visibility_limits: Vec::new(),
                quarantined: Vec::new(),
                bounded: Vec::new(),
                resume_token: None,
            },
        }
    }
}

/// A compiled detection pipeline: bundled (and optional custom) rules, ready
/// to evaluate supported session stores through canonical acquisition.
pub struct Pipeline {
    /// Every loaded definition before policy, for the rule catalog.
    content: LoadedRules,
    rule_set: CompiledRuleSet,
    /// Canonical semantics compiled once in `build`; content they reject never
    /// becomes a `Pipeline`.
    canonical: telltale_detect::v2::RuleV1CompatibilityPlan,
    /// The bundled process pack, loaded on first opt-in use and then reused.
    process_rules: std::sync::OnceLock<telltale_rules::process_chain::CompiledProcessChainRules>,
    /// Identity of every rule package in `rule_set`, in load order.
    rule_packages: Vec<RulePackageSummary>,
    /// The tier and source of every definition in `content`.
    provenance: Vec<rule_resolution::RuleProvenance>,
    /// The builder's text inputs, for the effective configuration; empty for
    /// a pipeline over rule files.
    documents: Vec<EffectiveDocumentV1>,
    /// Override entries skipped because `skip_unknown_override_rules(true)`
    /// was set and no loaded rule or chain modifier matched their `rule_id`.
    skipped_overrides: Vec<SkippedOverride>,
}

/// Builder for [`Pipeline`]. It includes bundled core rules and the embedded
/// community package, and makes supplied packages and rule documents
/// additive. Organization rule documents may replace a same-ID definition and
/// override documents tune rules, as the CLI's `organization-rules.d` and
/// `overrides.d` do, through the CLI's own tier resolution. Every input is
/// text; the builder reads no configuration directory.
#[derive(Default)]
pub struct PipelineBuilder {
    extra_rule_documents: Vec<String>,
    /// (label, text) in call order.
    organization_documents: Vec<(Option<String>, String)>,
    override_documents: Vec<(Option<String>, String)>,
    rule_packages: Vec<String>,
    policy_document: Option<String>,
    custom_only: bool,
    without_community: bool,
    skip_unknown_overrides: bool,
}

impl Pipeline {
    pub fn builder() -> PipelineBuilder {
        PipelineBuilder::default()
    }

    /// Number of enabled, compiled rules in this pipeline.
    pub fn rule_count(&self) -> usize {
        self.rule_set.rule_count()
    }

    /// Identity of each rule package compiled into this pipeline, embedded
    /// community content first, for provenance and inventory reporting.
    pub fn rule_packages(&self) -> &[RulePackageSummary] {
        &self.rule_packages
    }

    /// Override entries skipped during [`PipelineBuilder::build`] when
    /// [`PipelineBuilder::skip_unknown_override_rules`] was enabled, in input
    /// order. Always empty when unknown overrides are rejected (the default).
    pub fn skipped_overrides(&self) -> &[SkippedOverride] {
        &self.skipped_overrides
    }

    /// Resolve the exact detailed-scan semantic identity before acquisition.
    /// Compiles in-memory content and validates switches; performs no source I/O.
    /// Part of the detailed action contract; session-scoped Event 3 is unchanged.
    pub fn semantic_provenance(
        &self,
        options: &DetailedEvaluationOptions,
    ) -> Result<SemanticProvenance, PipelineError> {
        let (rules, _) = self.compile_semantics(Some(options))?;
        Ok(rules.semantic_provenance_with_options(options))
    }

    fn compile_semantics(
        &self,
        options: Option<&DetailedEvaluationOptions>,
    ) -> Result<
        (
            &telltale_detect::v2::RuleV1CompatibilityPlan,
            Option<&telltale_rules::process_chain::CompiledProcessChainRules>,
        ),
        PipelineError,
    > {
        if let Some(options) = options {
            options
                .validate()
                .map_err(|_| PipelineError::InvalidOptions)?;
        }
        let rules = &self.canonical;
        let process = match options {
            Some(options) if options.process_chain => Some(self.process_rules()?),
            _ => None,
        };
        Ok((rules, process))
    }

    fn process_rules(
        &self,
    ) -> Result<&telltale_rules::process_chain::CompiledProcessChainRules, PipelineError> {
        if let Some(rules) = self.process_rules.get() {
            return Ok(rules);
        }
        // A failed load is not cached; the bundled pack is static content.
        let rules = telltale_rules::process_chain::load_default_process_chain_rules()
            .map_err(|error| PipelineError::Compilation(Box::new(error)))?;
        Ok(self.process_rules.get_or_init(|| rules))
    }

    /// Discover session stores under `root` and run canonical detection and activity.
    /// Source processing failures surface as `scanner_error` events; discovery
    /// and batch clock/observation-time or rule compilation failures return
    /// [`PipelineError`]. No baseline or cursor is persisted.
    pub fn scan_root(&self, root: &Path) -> Result<Vec<(Source, Event)>, PipelineError> {
        let sources = telltale_sources::discovery::discover_sources(root)?;
        self.scan_sources(&sources)
    }

    /// Run canonical detection and activity over exactly the supplied sources.
    /// Uses one UTC observation time per call and the same session-scoped Event 3
    /// projection (including timeline anchors) as [`Self::scan_root`]. Source
    /// processing failures surface as `scanner_error` events. No discovery,
    /// baseline, cursor, or output persistence is performed. Batch clock,
    /// observation-time validation, and rule compilation failures return [`PipelineError`].
    pub fn scan_sources(&self, sources: &[Source]) -> Result<Vec<(Source, Event)>, PipelineError> {
        Ok(self
            .scan_sources_with_occurrences(sources)?
            .into_iter()
            .flat_map(|scan| {
                scan.events
                    .into_iter()
                    .map(move |event| (scan.source.clone(), event))
            })
            .collect())
    }

    /// Discover stores and return the same events with precise occurrence linkage.
    /// Returned failures match [`Self::scan_root`], including checked discovery.
    pub fn scan_root_with_occurrences(
        &self,
        root: &Path,
    ) -> Result<Vec<SourceScan>, PipelineError> {
        let sources = telltale_sources::discovery::discover_sources(root)?;
        self.scan_sources_with_occurrences(&sources)
    }

    /// Scan supplied sources once, returning session events and observation identities.
    /// Occurrences are ordered by finding index, timeline index (unknown last), then
    /// identity. Source failures return only `scanner_error` with no occurrences;
    /// batch clock, observation-time validation, and compilation failures return
    /// [`PipelineError`]. No state or output is persisted.
    pub fn scan_sources_with_occurrences(
        &self,
        sources: &[Source],
    ) -> Result<Vec<SourceScan>, PipelineError> {
        self.scan_sources_timed(sources, None, current_rfc3339)
    }

    /// The action contract for exactly the supplied sources: canonical findings,
    /// replay comparison aids, and opt-in same-pass context from one acquired batch.
    /// Session-scoped Event 3 and existing occurrence meanings are unchanged.
    pub fn scan_sources_detailed(
        &self,
        sources: &[Source],
        options: &DetailedEvaluationOptions,
    ) -> Result<Vec<SourceScan>, PipelineError> {
        self.scan_sources_timed(sources, Some(options), current_rfc3339)
    }

    /// Discover stores under `root` and apply the detailed action contract.
    /// Returns canonical action findings beside unchanged session-scoped Event 3;
    /// context is opt-in and same-pass, not an investigation reread.
    pub fn scan_root_detailed(
        &self,
        root: &Path,
        options: &DetailedEvaluationOptions,
    ) -> Result<Vec<SourceScan>, PipelineError> {
        let sources = telltale_sources::discovery::discover_sources(root)?;
        self.scan_sources_detailed(&sources, options)
    }

    /// Detailed scan of one source, resuming a resumable source
    /// (`opencode.sqlite`) after a prior [`ResumeToken`]. Without a token it is
    /// the bounded bootstrap read of [`Self::scan_sources_detailed`]. A resumed
    /// read re-reads a fixed overlap before the token's high-water, so expect
    /// repeated actions (dedup with replay identity or coordinates). A resumed
    /// unfinished v2 window instead continues after its raw cut, even below the
    /// checkpoint; older cut tokens without that coordinate replay the overlap.
    /// Regression detection always uses the checkpoint. A resumed
    /// read that exceeds its part limit fails with
    /// `AcquisitionError::BoundedSourceRead(LimitExceeded)`: drop the token and
    /// scan again from bootstrap, treating the gap as unevaluated history.
    /// A store with no part at or after the token's high-water (restored,
    /// replaced, or newest parts deleted) fails with
    /// `AcquisitionError::ResumeRegressed` and the same bootstrap recovery.
    /// A token for another source or a non-resumable source returns
    /// [`PipelineError::InvalidResumeToken`] before any source I/O.
    pub fn scan_source_detailed_resuming(
        &self,
        source: &Source,
        resume: Option<&ResumeToken>,
        options: &DetailedEvaluationOptions,
    ) -> Result<SourceScan, PipelineError> {
        options
            .validate()
            .map_err(|_| PipelineError::InvalidOptions)?;
        let resumed_from = match resume {
            None => None,
            Some(token) if is_resumable(source) && token.binding == resume_binding(source) => {
                Some((token.coordinate, token.high_water))
            }
            Some(_) => return Err(PipelineError::InvalidResumeToken),
        };
        let observed_at = telltale_schema::observation::ObservedAt::new(current_rfc3339()?)?;
        let (rules, process_rules) = self.compile_semantics(Some(options))?;
        let result = Self::process_one(
            source,
            observed_at,
            Some(options),
            resumed_from.map(|(coordinate, high_water)| {
                use telltale_sources::acquisition::OpenCodeSqliteReadOptions;
                // A token resumes only its own schema; the other schema reads its
                // bounded bootstrap selection instead of inheriting this position.
                match coordinate {
                    ResumeCoordinate::Part => OpenCodeSqliteReadOptions::resume_after(high_water),
                    ResumeCoordinate::SessionMessage | ResumeCoordinate::SessionMessageDrain => {
                        OpenCodeSqliteReadOptions::default()
                            .resume_session_messages_after(high_water)
                    }
                    ResumeCoordinate::SessionMessageWindow(cut) => {
                        OpenCodeSqliteReadOptions::default()
                            .resume_session_messages_after(high_water)
                            .continue_session_messages_after(cut)
                    }
                }
            }),
            rules,
            process_rules,
        );
        Ok(SourceScan::from_result(
            source.clone(),
            result,
            resumed_from,
        ))
    }

    #[cfg(test)]
    fn scan_sources_with_time(
        &self,
        sources: &[Source],
        now: impl FnOnce() -> Result<String, time::error::Format>,
    ) -> Result<Vec<SourceScan>, PipelineError> {
        self.scan_sources_timed(sources, None, now)
    }

    fn scan_sources_timed(
        &self,
        sources: &[Source],
        detailed: Option<&DetailedEvaluationOptions>,
        now: impl FnOnce() -> Result<String, time::error::Format>,
    ) -> Result<Vec<SourceScan>, PipelineError> {
        if let Some(options) = detailed {
            options
                .validate()
                .map_err(|_| PipelineError::InvalidOptions)?;
        }
        let observed_at = telltale_schema::observation::ObservedAt::new(now()?)?;
        Ok(self
            .scan_canonical_sources_with_options(sources, observed_at, detailed)?
            .into_iter()
            .map(|(source, result)| SourceScan::from_result(source, result, None))
            .collect())
    }

    /// Stateless adapter. One observation time for the entire source batch.
    /// No prior baseline means no deviation history; replacement remains data.
    #[cfg(test)]
    fn scan_canonical_sources(
        &self,
        sources: &[Source],
        observed_at: telltale_schema::observation::ObservedAt,
    ) -> Result<Vec<(Source, SourceOutcome)>, PipelineError> {
        self.scan_canonical_sources_with_options(sources, observed_at, None)
    }

    fn scan_canonical_sources_with_options(
        &self,
        sources: &[Source],
        observed_at: telltale_schema::observation::ObservedAt,
        detailed: Option<&DetailedEvaluationOptions>,
    ) -> Result<Vec<(Source, SourceOutcome)>, PipelineError> {
        let (rules, process_rules) = self.compile_semantics(detailed)?;
        Ok(sources
            .iter()
            .map(|source| {
                let result = Self::process_one(
                    source,
                    observed_at.clone(),
                    detailed,
                    None,
                    rules,
                    process_rules,
                );
                (source.clone(), result)
            })
            .collect())
    }

    /// Stateless adapter for one source. `sqlite` selects a resumed OpenCode
    /// read; `None` keeps the bounded bootstrap selection. No prior baseline
    /// means no deviation history; replacement remains data.
    fn process_one(
        source: &Source,
        observed_at: telltale_schema::observation::ObservedAt,
        detailed: Option<&DetailedEvaluationOptions>,
        sqlite: Option<telltale_sources::acquisition::OpenCodeSqliteReadOptions>,
        rules: &telltale_detect::v2::RuleV1CompatibilityPlan,
        process_rules: Option<&telltale_rules::process_chain::CompiledProcessChainRules>,
    ) -> SourceOutcome {
        let prior = telltale_detect::baseline::BaselineSnapshotStore::default();
        let process_config = telltale_detect::process_chain::ProcessChainConfig::default();
        let context = canonical_runtime::SourceContext {
            mcp_servers: &[],
            rules,
            pre_policy_rules: None,
            process: process_rules.map(|rules| (rules, &process_config)),
            prior: &prior,
            baseline_deviation: telltale_detect::baseline::BaselineDeviationConfig::default(),
        };
        match detailed {
            Some(options) => canonical_runtime::process_source_detailed(
                source,
                observed_at,
                sqlite,
                context,
                options,
            ),
            None => canonical_runtime::process_source(source, observed_at, sqlite, context),
        }
    }

    /// Materialize a deterministic, privacy-safe identity for this pipeline's
    /// already effective producer configuration. This method does not resolve
    /// configuration paths or policy files; callers provide resolved values in
    /// `options`. It is not Event 3 telemetry or an attestation of any
    /// individual event.
    pub fn producer_provenance_manifest(
        &self,
        options: &ProducerProvenanceOptions,
    ) -> Result<ProducerProvenanceManifestV1, ProducerProvenanceError> {
        assemble_producer_provenance_manifest(&self.rule_set, options)
    }
}

impl PipelineBuilder {
    /// Add a YAML rule file: one or more Rule v2 rule and chain documents. A
    /// Rule v1 document fails at [`Self::build`]. Additive to the bundled defaults unless
    /// [`Self::without_bundled_defaults`] is set (mirrors `--rules`).
    pub fn rules_document(mut self, yaml: impl Into<String>) -> Self {
        self.extra_rule_documents.push(yaml.into());
        self
    }

    /// Apply a YAML rule policy (category/rule enablement, mirrors `--policy`).
    pub fn policy_document(mut self, yaml: impl Into<String>) -> Self {
        self.policy_document = Some(yaml.into());
        self
    }

    /// Add a rule package: the whole text of a `telltale-rule-package/v2` YAML
    /// stream. Package definitions are additive; a package with the community ID replaces the
    /// embedded community snapshot (mirrors an installed `rule-packages.d` file).
    pub fn rule_package(mut self, yaml: impl Into<String>) -> Self {
        self.rule_packages.push(yaml.into());
        self
    }

    /// Add a rule document at the organization tier, like a file in
    /// `organization-rules.d`. A rule or chain whose ID bundled core or a
    /// package already defines replaces that definition in place and must
    /// keep its Rule v2 `id`; other IDs are added. An ID repeated among
    /// organization documents fails. A replacing rule whose matchers differ
    /// from the bundled rule's uses its own matchers, not the bundled rule's
    /// native precision profile.
    pub fn organization_rules_document(mut self, yaml: impl Into<String>) -> Self {
        self.organization_documents.push((None, yaml.into()));
        self
    }

    /// [`Self::organization_rules_document`] with a caller-chosen label, which
    /// names the input in [`RuleContentError::document`] and is reported as
    /// the document's `label` in [`Pipeline::effective_configuration`], so
    /// treat it as visible to operators: 1 to 64 characters from
    /// `A-Z a-z 0-9 . _ -`. Do not pass a path. Another label, or a label two
    /// organization documents share, fails `build` with
    /// [`RuleContentErrorCode::InvalidLabel`]. An unlabelled document's label is
    /// its 1-based position among organization documents.
    pub fn labeled_organization_rules_document(
        mut self,
        label: impl Into<String>,
        yaml: impl Into<String>,
    ) -> Self {
        self.organization_documents
            .push((Some(label.into()), yaml.into()));
        self
    }

    /// Add an override v1 document, like a file in `overrides.d`. Documents
    /// apply in call order after all rule content is merged and before the
    /// policy. An entry's `rule_id` names a rule or a chain modifier; by
    /// default one that names neither fails `build` with
    /// [`RuleContentErrorCode::UnknownRuleId`] unless
    /// [`Self::skip_unknown_override_rules`] is enabled.
    pub fn override_document(mut self, yaml: impl Into<String>) -> Self {
        self.override_documents.push((None, yaml.into()));
        self
    }

    /// [`Self::override_document`] with a caller-chosen label, checked as for
    /// [`Self::labeled_organization_rules_document`]. An unlabelled document's
    /// label is its 1-based position among override documents.
    pub fn labeled_override_document(
        mut self,
        label: impl Into<String>,
        yaml: impl Into<String>,
    ) -> Self {
        self.override_documents
            .push((Some(label.into()), yaml.into()));
        self
    }

    /// Drop the bundled core rules and the embedded community package; use
    /// only supplied packages and documents (mirrors `--no-default-rules`).
    pub fn without_bundled_defaults(mut self) -> Self {
        self.custom_only = true;
        self
    }

    /// Omit community rules from every origin, embedded or supplied
    /// (mirrors `--no-community-rules`).
    pub fn without_community_rules(mut self) -> Self {
        self.without_community = true;
        self
    }

    /// When `true`, an override entry whose `rule_id` matches no loaded rule
    /// or chain modifier is skipped instead of failing [`Self::build`] with
    /// [`RuleContentErrorCode::UnknownRuleId`], and is recorded on
    /// [`Pipeline::skipped_overrides`]. Defaults to `false` (strict).
    ///
    /// Invalid override documents, unsupported versions, invalid entries,
    /// bound violations, and empty effective rule sets still fail `build()`.
    pub fn skip_unknown_override_rules(mut self, skip: bool) -> Self {
        self.skip_unknown_overrides = skip;
        self
    }

    /// Resolve bundled core rules, rule packages, organization and supplied
    /// rule documents by tier, apply override documents, and compile with the
    /// optional policy, as the CLI does.
    /// Missing documents return [`PipelineError::InvalidConfiguration`].
    /// Rejected labels, documents, packages and policies that do not parse,
    /// repeated IDs, override entries and content past a bound return
    /// [`PipelineError::Compilation`] with a [`RuleContentError`] source. Other
    /// rejected packages, and a rule that fails validation when the merged
    /// content compiles, keep an untyped source whose text can name rule IDs
    /// and quote document values.
    /// Canonical semantics are compiled once here and reused by every scan.
    /// Content that rule loading accepts but canonical compilation rejects
    /// returns [`PipelineError::Compilation`] here, not later from a scan.
    /// Content and policy that leave no effective rule return
    /// [`PipelineError::EmptyRuleSet`].
    pub fn build(self) -> Result<Pipeline, PipelineError> {
        let organization =
            labeled_sources(DocumentKindV1::Organization, self.organization_documents)?;
        let overrides = labeled_sources(DocumentKindV1::Override, self.override_documents)?;
        let explicit = self
            .extra_rule_documents
            .into_iter()
            .enumerate()
            .map(|(index, raw)| {
                (
                    input_name(DocumentKindV1::Explicit, (index + 1).to_string()),
                    raw,
                )
            })
            .collect::<Vec<_>>();
        let policy = self
            .policy_document
            .map(|raw| (input_name(DocumentKindV1::Policy, "1".to_owned()), raw));
        let supplied = organization
            .iter()
            .map(|(name, raw)| (DocumentKindV1::Organization, name, raw.as_str()))
            .chain(
                explicit
                    .iter()
                    .map(|(name, raw)| (DocumentKindV1::Explicit, name, raw.as_str())),
            )
            .chain(
                overrides
                    .iter()
                    .map(|(name, raw)| (DocumentKindV1::Override, name, raw.as_str())),
            )
            .chain(
                policy
                    .iter()
                    .map(|(name, raw)| (DocumentKindV1::Policy, name, raw.as_str())),
            )
            .collect::<Vec<_>>();
        // The effective configuration lists every supplied document.
        if let Some((_, name, _)) = supplied.get(MAX_SUPPLIED_DOCUMENTS) {
            return Err(PipelineError::Compilation(Box::new(RuleContentError::new(
                RuleContentErrorCode::ExceedsBounds,
                Some(name.source.clone()),
            ))));
        }
        let supplied_documents = supplied
            .into_iter()
            .map(|(kind, name, raw)| EffectiveDocumentV1 {
                kind,
                label: name.label.clone().unwrap_or_default(),
                content_sha256: hex::encode(Sha256::digest(raw.as_bytes())),
            })
            .collect::<Vec<_>>();
        let content = RuleContent {
            mode: if self.custom_only {
                RuleLoadMode::CustomOnly
            } else {
                RuleLoadMode::IncludeDefault
            },
            community: if self.without_community {
                CommunityRules::Disabled
            } else {
                CommunityRules::Embedded
            },
            packages: self
                .rule_packages
                .into_iter()
                .enumerate()
                .map(|(index, raw)| (format!("supplied:{}", index + 1), raw))
                .collect(),
            files: organization
                .into_iter()
                .map(|(name, raw)| (RuleTier::Organization, name, raw))
                .chain(
                    explicit
                        .into_iter()
                        .map(|(name, raw)| (RuleTier::Explicit, name, raw)),
                )
                .collect(),
            documents: Vec::new(),
            host_documents: Vec::new(),
            skip_unknown_overrides: self.skip_unknown_overrides,
            overrides,
            policy,
        };
        let (resolution, skipped_overrides) = resolve_rule_content(content).map_err(|error| {
            if error.is::<NoRuleDocuments>() {
                PipelineError::InvalidConfiguration
            } else if let Some(failure) = error.downcast_ref::<ContentFailure>() {
                PipelineError::Compilation(Box::new(failure.without_message()))
            } else {
                PipelineError::Compilation(error)
            }
        })?;
        resolution.into_pipeline().map(|pipeline| Pipeline {
            documents: supplied_documents,
            skipped_overrides: skipped_overrides
                .into_iter()
                .map(|entry| entry.into_diagnostic())
                .collect(),
            ..pipeline
        })
    }
}

/// Most documents a builder takes: the effective configuration lists each.
const MAX_SUPPLIED_DOCUMENTS: usize = 1024;

/// A builder input's name: `<kind>:<label>` as its source, which errors
/// report, and its label, which the effective configuration reports with the
/// same kind.
fn input_name(kind: DocumentKindV1, label: String) -> InputName {
    let kind_name = match kind {
        DocumentKindV1::Organization => "organization",
        DocumentKindV1::Explicit => "explicit",
        DocumentKindV1::Override => "override",
        DocumentKindV1::Policy => "policy",
    };
    InputName {
        source: format!("{kind_name}:{label}"),
        label: Some(label),
    }
}

/// Name each input of one kind with [`input_name`], an unlabelled one by its
/// 1-based position. A label outside the allowed form, or a name two inputs
/// share, fails, so a name in a diagnostic always means one input.
fn labeled_sources(
    kind: DocumentKindV1,
    inputs: Vec<(Option<String>, String)>,
) -> Result<Vec<(InputName, String)>, PipelineError> {
    let invalid = || {
        PipelineError::Compilation(Box::new(RuleContentError::new(
            RuleContentErrorCode::InvalidLabel,
            None,
        )))
    };
    let mut named = Vec::<(InputName, String)>::with_capacity(inputs.len());
    for (index, (label, raw)) in inputs.into_iter().enumerate() {
        let label = label.unwrap_or_else(|| (index + 1).to_string());
        if !(1..=64).contains(&label.len())
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        {
            return Err(invalid());
        }
        if named
            .iter()
            .any(|(existing, _)| existing.label.as_ref() == Some(&label))
        {
            return Err(invalid());
        }
        named.push((input_name(kind, label), raw));
    }
    Ok(named)
}

impl Pipeline {
    /// A pipeline over rule content that is already merged and compiled, such
    /// as a [`rule_resolution`] result.
    pub(crate) fn from_compiled(
        content: LoadedRules,
        rule_set: CompiledRuleSet,
        diagnostics: rule_resolution::RuleResolutionDiagnostics,
    ) -> Result<Self, PipelineError> {
        // Modifiers only combine rule matches, so no effective rule leaves no
        // rule detection. Fail closed instead of building an empty pipeline,
        // even though opt-in process-chain detection does not use this rule set:
        // building cannot know whether a later scan enables it.
        if rule_set.rule_count() == 0 {
            return Err(PipelineError::EmptyRuleSet);
        }
        let canonical = telltale_detect::v2::compile_rule_v1(&rule_set.compatibility_export())
            .map_err(|error| PipelineError::Compilation(Box::new(error)))?;
        Ok(Pipeline {
            content,
            rule_set,
            canonical,
            process_rules: std::sync::OnceLock::new(),
            rule_packages: diagnostics.packages,
            provenance: diagnostics.provenance,
            documents: Vec::new(),
            skipped_overrides: Vec::new(),
        })
    }
}

#[cfg(test)]
mod canonical_embedding_tests;
#[cfg(test)]
mod detailed_scan_tests;
#[cfg(test)]
mod rule_content_tests;

#[cfg(test)]
mod test_support;

#[cfg(test)]
mod investigation_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;
    use telltale_schema::clients::{ClientId, SourceKind};

    fn synthetic_source() -> Source {
        Source {
            client: ClientId::Codex,
            kind: SourceKind::Jsonl,
            source_id: "embedded.synthetic".to_string(),
            path: std::path::PathBuf::from("embedded://synthetic"),
        }
    }

    #[test]
    fn canonical_rejection_fails_build_and_batch_time_precedes_source_io() {
        let invalid_rules = r#"
title: Synthetic batch error precedence
id: 3f2504e0-4f89-41d3-9a0c-0305e82c3302
name: synthetic.invalid
taxonomy: telltale
logsource:
    product: ai_agent
    category: tool_activity
detection:
    selection:
        - tool.command|re: 'needle'
    condition: selection
level: low
telltale:
    category: synthetic
    score: 1
    explanation: synthetic
    detection_class: operational_health
"#;
        // Rule loading accepts the detection class; canonical compilation
        // rejects it at build time, so no pipeline exists that can only fail
        // scans.
        let error = Pipeline::builder()
            .without_bundled_defaults()
            .rules_document(invalid_rules)
            .build()
            .err()
            .expect("canonical rejection at build");
        assert!(matches!(error, PipelineError::Compilation(_)));
        assert!(matches!(
            error
                .source()
                .and_then(|cause| cause.downcast_ref::<RuleCompileError>()),
            Some(RuleCompileError::UnmappableDetectionClass)
        ));
        let valid = Pipeline::builder().build().unwrap();
        let sources = [synthetic_source()];
        for batch in [&[][..], &sources[..]] {
            let error = valid
                .scan_sources_with_time(batch, || {
                    time::Date::from_calendar_date(2026, time::Month::October, 4)
                        .unwrap()
                        .format(
                            &time::format_description::parse_borrowed::<1>("[offset_hour]")
                                .unwrap(),
                        )
                })
                .err()
                .expect("clock failure");
            assert!(matches!(error, PipelineError::Clock(_)));
            let error = valid
                .scan_sources_with_time(batch, || Ok("invalid-observed-at".into()))
                .err()
                .expect("observation failure");
            assert!(matches!(error, PipelineError::Observation(_)));
        }
        let scans = valid
            .scan_sources_with_time(&sources, || Ok("2026-10-04T00:00:00Z".into()))
            .unwrap();
        assert_eq!(scans.len(), 1);
        assert_eq!(scans[0].events.len(), 1);
        assert_eq!(scans[0].events[0].event_type, "scanner_error");
        assert!(scans[0].occurrences.is_empty());
    }

    #[test]
    fn custom_only_without_documents_is_an_error() {
        assert!(
            Pipeline::builder()
                .without_bundled_defaults()
                .build()
                .is_err()
        );
    }

    fn community_package(version: &str, rule_id: &str) -> String {
        format!(
            "format: telltale-rule-package/v2\nid: telltale.community\ntitle: Synthetic community\n\
             version: \"{version}\"\npublisher: Synthetic\nlicense: Apache-2.0\nrule_namespace: tdx\n\
             ---\ntitle: Synthetic community rule\nid: 5d0f6c4e-8a1b-4c2d-9e3f-0a1b2c3d4e5f\n\
             name: {rule_id}\ntaxonomy: telltale\nlogsource:\n    product: ai_agent\n    \
             category: tool_activity\ndetection:\n    selection:\n        - tool.command|re|i: marker\n    \
             condition: selection\nlevel: low\ntelltale:\n    category: persistence\n    score: 20\n    \
             explanation: Synthetic.\n    tags: [synthetic]\n"
        )
    }

    #[test]
    fn rule_v1_documents_and_packages_fail_as_invalid_documents() {
        // The CLI shows the pointer to Rule v2; the builder reports the code.
        let v1 = concat!(
            "version: 1\ndescription: synthetic\n",
            "defaults: {case_insensitive: true, enabled: true}\nrules: []\nmodifiers: []\n",
        );
        let content_error = |error: PipelineError| {
            let PipelineError::Compilation(cause) = error else {
                panic!("compilation error, got {error:?}");
            };
            cause.downcast_ref::<RuleContentError>().cloned().unwrap()
        };
        let document = content_error(
            Pipeline::builder()
                .rules_document(v1)
                .build()
                .err()
                .expect("Rule v1 document"),
        );
        assert_eq!(
            (document.code(), document.document()),
            (RuleContentErrorCode::InvalidDocument, Some("explicit:1"))
        );
        let package = format!(
            "format: telltale-rule-package/v1\nid: acme.rules\nversion: 1.0.0\npublisher: Acme\n\
             license: Apache-2.0\nrule_namespace: acme\ndocuments:\n  - {}",
            v1.replace('\n', "\n    ")
        );
        let package = content_error(
            Pipeline::builder()
                .rule_package(package)
                .build()
                .err()
                .expect("format v1 package"),
        );
        assert_eq!(
            (package.code(), package.document()),
            (RuleContentErrorCode::InvalidDocument, Some("package:1"))
        );
    }

    #[test]
    fn builder_accepts_rule_v2_documents_beside_bundled_rules() {
        let v2 = "title: Synthetic v2 marker\nid: 3f2504e0-4f89-41d3-9a0c-0305e82c3301\n\
                  name: synthetic.v2.marker\ntaxonomy: telltale\nstatus: test\n\
                  logsource:\n    product: ai_agent\n    category: tool_activity\n\
                  detection:\n    selection:\n        tool.command|contains: synthetic-v2-marker\n    condition: selection\n\
                  level: medium\ntelltale:\n    category: synthetic\n    score: 25\n    explanation: Synthetic v2 rule.\n";
        let pipeline = Pipeline::builder()
            .without_bundled_defaults()
            .rules_document(v2)
            .build()
            .unwrap();
        assert_eq!(pipeline.rule_count(), 1);
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("source.jsonl");
        let row = serde_json::json!({"sessionId":"v2-session","type":"assistant","uuid":"v2-call","timestamp":"2026-11-18T00:00:00Z","message":{"role":"assistant","content":[{"type":"tool_use","id":"v2-call","name":"Bash","input":{"command":"echo synthetic-v2-marker"}}]}});
        std::fs::write(&path, format!("{row}\n")).unwrap();
        let source = Source {
            client: ClientId::Claude,
            kind: SourceKind::Jsonl,
            source_id: "claude.projects".into(),
            path,
        };
        let events = pipeline.scan_sources(&[source]).unwrap();
        assert!(
            events
                .iter()
                .any(|(_, event)| event.rule_ids.iter().any(|id| id == "synthetic.v2.marker")),
            "{events:?}"
        );

        // Added beside the bundled content, a rule may not reuse a bundled id.
        assert_eq!(
            Pipeline::builder()
                .rules_document(v2)
                .build()
                .unwrap()
                .rule_count(),
            Pipeline::builder().build().unwrap().rule_count() + 1
        );
        let error = Pipeline::builder()
            .rules_document(v2.replace("synthetic.v2.marker", "network.download"))
            .build()
            .err()
            .unwrap();
        assert_eq!(
            error.source().unwrap().to_string(),
            "rule_content_duplicate_id"
        );
    }

    #[test]
    fn community_rules_are_default_and_opt_out_leaves_core_rules() {
        let embedded = telltale_rules::package::bundled_community_package().unwrap();
        let community_rules = embedded
            .documents()
            .iter()
            .flat_map(|document| document.definitions())
            .filter(|definition| definition.kind() == telltale_rules::DefinitionKind::Rule)
            .count();
        let default = Pipeline::builder().build().unwrap();
        let core = Pipeline::builder()
            .without_community_rules()
            .build()
            .unwrap();
        assert_eq!(default.rule_count(), core.rule_count() + community_rules);
        assert_eq!(
            default.rule_packages(),
            [RulePackageSummary {
                id: COMMUNITY_PACKAGE_ID.to_string(),
                version: embedded.version().to_string(),
                content_sha256: embedded.content_sha256().to_string(),
                embedded: true,
                replaced_embedded_version: None,
            }]
        );
        assert!(core.rule_packages().is_empty());
        assert_eq!(
            core.rule_count(),
            telltale_rules::load_default_rule_set()
                .unwrap()
                .rule_count()
        );
    }

    #[test]
    fn default_pipeline_detects_with_embedded_community_rules() {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join(".claude/projects/synthetic");
        std::fs::create_dir_all(&directory).unwrap();
        let call = serde_json::json!({"type": "assistant", "sessionId": "community-session",
            "message": {"role": "assistant", "content": [{"type": "tool_use", "id": "toolu_1",
            "name": "Bash", "input": {"command": "claude mcp add synthetic-server -- npx synthetic-mcp"}}]}});
        std::fs::write(directory.join("session.jsonl"), format!("{call}\n")).unwrap();
        let community_rule_ids = |pipeline: Pipeline| {
            pipeline
                .scan_root(root.path())
                .unwrap()
                .into_iter()
                .filter(|(_, event)| event.event_type == "detection")
                .flat_map(|(_, event)| event.rule_ids)
                .filter(|id| id.starts_with("tdx."))
                .collect::<Vec<_>>()
        };
        assert_eq!(
            community_rule_ids(Pipeline::builder().build().unwrap()),
            ["tdx.persistence.mcp_server_registration"]
        );
        assert!(
            community_rule_ids(
                Pipeline::builder()
                    .without_community_rules()
                    .build()
                    .unwrap()
            )
            .is_empty()
        );
    }

    #[test]
    fn supplied_community_package_replaces_embedded_and_stays_opt_out() {
        let supplied = community_package("99.0.0", "tdx.synthetic.newer");
        let replaced = Pipeline::builder().rule_package(&supplied).build().unwrap();
        let summary = &replaced.rule_packages()[0];
        assert_eq!(
            (summary.version.as_str(), summary.embedded),
            ("99.0.0", false)
        );
        assert!(summary.replaced_embedded_version.is_some());
        let core = Pipeline::builder()
            .without_community_rules()
            .build()
            .unwrap();
        assert_eq!(replaced.rule_count(), core.rule_count() + 1);

        let package_only = Pipeline::builder()
            .without_bundled_defaults()
            .rule_package(&supplied)
            .build()
            .unwrap();
        assert_eq!(package_only.rule_count(), 1);
        assert!(matches!(
            Pipeline::builder()
                .without_bundled_defaults()
                .without_community_rules()
                .rule_package(&supplied)
                .build(),
            Err(PipelineError::InvalidConfiguration)
        ));
        assert!(matches!(
            Pipeline::builder()
                .rule_package("format: unknown\n")
                .build(),
            Err(PipelineError::Compilation(_))
        ));
    }

    #[test]
    fn rule_catalog_attributes_community_entries_to_their_package() {
        let catalog = bundled_rule_catalog(&DetailedEvaluationOptions::default()).unwrap();
        let community = catalog
            .iter()
            .filter(|entry| entry.package_id() == Some(COMMUNITY_PACKAGE_ID))
            .collect::<Vec<_>>();
        assert!(!community.is_empty());
        assert!(
            community
                .iter()
                .all(|entry| entry.id().starts_with("tdx.") && entry.enabled())
        );
        assert!(
            catalog
                .iter()
                .any(|entry| entry.id() == "secret.env.read" && entry.package_id().is_none())
        );
    }
}
