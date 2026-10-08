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
//! ```no_run
//! use telltale_core::{Pipeline, PipelineError};
//!
//! let pipeline = Pipeline::builder().build()?;
//! for (source, event) in pipeline.scan_root(std::path::Path::new("/home/user"))? {
//!     println!("{}: {} {:?}", source.source_id, event.event_type, event.rule_ids);
//! }
//! # Ok::<(), PipelineError>(())
//! ```

use telltale_rules::CompiledRuleSet;

#[cfg(feature = "protected-assignment")]
pub mod assignment;
/// Unstable cross-crate migration seam, not a supported embedding API.
#[doc(hidden)]
pub mod canonical_runtime;
pub mod inventory;
pub mod investigation;
pub mod local_event_feed;
pub mod provenance;

pub use local_event_feed::{
    FeedBatch, FeedLimits, FeedNotice, FeedNoticeCode, LocalEventFeed, LocalEventFeedConfig,
    LocalEventFeedError, LocalEventFeedErrorCode, StartupMode,
};

pub use canonical_runtime::FailureStage as SourceFailureStage;
pub use provenance::{
    ProducerProvenanceOptions, assemble_producer_provenance_manifest,
    resolve_install_inventory_interval_seconds,
};
pub use telltale_detect::v2::RuleV1CompileError;
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
pub use telltale_sources::acquisition::{AcquisitionError, BoundedReadError};
pub use telltale_sources::discovery::{
    DiscoveryError, discover_sources, discover_sources_best_effort,
    discover_watch_roots_for_clients,
};
pub use telltale_sources::paths::PathProfile;

use std::path::Path;

type BoxError = Box<dyn std::error::Error>;

pub use telltale_detect::v2::{
    ActionContextEntry, ActionContextKind, ActionContribution, ActionCoordinate, ActionEvidence,
    ActionFinding, ActionFindingKind, CanonicalActionFinding, ContextOptions,
    DEFAULT_ACTION_DOWNLOAD_LINK_SCORE, DetailedEvaluationOptions, EvaluationCompletion,
    ReplayIdentity, SemanticProvenance, Severity, VisibilityLimit,
};
mod rule_catalog;
pub use rule_catalog::{RuleCatalogEntry, RuleCatalogKind, bundled_rule_catalog};

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
    /// Detailed-scan options failed their closed bounds.
    InvalidOptions,
}

impl std::fmt::Display for PipelineError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Discovery(_) => "pipeline_discovery_failed",
            Self::Clock(_) => "pipeline_clock_failed",
            Self::Observation(_) => "pipeline_observation_failed",
            Self::Compilation(_) => "pipeline_compilation_failed",
            Self::InvalidConfiguration => "pipeline_no_rule_documents",
            Self::InvalidOptions => "pipeline_invalid_options",
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
            Self::InvalidConfiguration | Self::InvalidOptions => None,
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

impl From<RuleV1CompileError> for PipelineError {
    fn from(source: RuleV1CompileError) -> Self {
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
    /// Only a selected part was evaluated (OpenCode's bounded recent window).
    /// No finding is not evidence about unselected history, and a later scan
    /// may no longer select an earlier action.
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

    /// Typed failure; `Some` exactly when the source failed. Prefer this over
    /// matching Event 3 `event_type` strings or inferring from `completion`.
    pub fn failure(&self) -> Option<&SourceScanFailure> {
        self.failure.as_ref()
    }

    fn from_result(source: Source, result: SourceOutcome) -> Self {
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
                source,
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
            },
        }
    }
}

/// A compiled detection pipeline: bundled (and optional custom) rules, ready
/// to evaluate discovered session stores or caller-supplied records.
pub struct Pipeline {
    rule_set: CompiledRuleSet,
    /// Canonical semantics compiled once in `build`. A rejection is retained,
    /// not raised there: the record APIs can still use legacy-accepted content,
    /// and scans keep their clock -> observation -> compilation error order.
    canonical: Result<telltale_detect::v2::RuleV1CompatibilityPlan, RuleV1CompileError>,
    /// The bundled process pack, loaded on first opt-in use and then reused.
    process_rules: std::sync::OnceLock<telltale_rules::process_chain::CompiledProcessChainRules>,
}

/// Builder for [`Pipeline`]. This in-memory convenience includes bundled default
/// rules and makes extra rule documents additive; it is not the CLI's path and
/// managed-tier configuration resolver.
#[derive(Default)]
pub struct PipelineBuilder {
    extra_rule_documents: Vec<String>,
    policy_document: Option<String>,
    custom_only: bool,
}

impl Pipeline {
    pub fn builder() -> PipelineBuilder {
        PipelineBuilder::default()
    }

    /// Number of enabled, compiled rules in this pipeline.
    pub fn rule_count(&self) -> usize {
        self.rule_set.rule_count()
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
        let rules = self
            .canonical
            .as_ref()
            .map_err(|error| PipelineError::Compilation(Box::new(*error)))?;
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
            .map(|(source, result)| SourceScan::from_result(source, result))
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
        let prior = telltale_detect::baseline::BaselineSnapshotStore::default();
        let process_config = telltale_detect::process_chain::ProcessChainConfig::default();
        Ok(sources
            .iter()
            .map(|source| {
                let context = canonical_runtime::SourceContext {
                    mcp_servers: &[],
                    rules,
                    pre_policy_rules: None,
                    process: process_rules.map(|rules| (rules, &process_config)),
                    prior: &prior,
                    baseline_deviation: telltale_detect::baseline::BaselineDeviationConfig::default(
                    ),
                };
                let result = match detailed {
                    Some(options) => canonical_runtime::process_source_detailed(
                        source,
                        observed_at.clone(),
                        None,
                        context,
                        options,
                    ),
                    None => canonical_runtime::process_source(
                        source,
                        observed_at.clone(),
                        None,
                        context,
                    ),
                };
                (source.clone(), result)
            })
            .collect())
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
    /// Add a YAML rule document. Additive to the bundled defaults unless
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

    /// Drop the bundled default rules and use only the supplied documents
    /// (mirrors `--no-default-rules`).
    pub fn without_bundled_defaults(mut self) -> Self {
        self.custom_only = true;
        self
    }

    /// Compile bundled and supplied Rule v1 documents with the optional policy.
    /// Missing documents or rejected rules/policy return [`PipelineError`].
    /// Canonical semantics are compiled once here and reused by every scan; a
    /// canonical rejection is reported by the scan and provenance methods.
    pub fn build(self) -> Result<Pipeline, PipelineError> {
        let mut documents: Vec<&str> = Vec::new();
        if !self.custom_only {
            documents.push(telltale_rules::bundled_default_rule_yaml());
        }
        documents.extend(self.extra_rule_documents.iter().map(String::as_str));
        if documents.is_empty() {
            return Err(PipelineError::InvalidConfiguration);
        }
        let rule_set = telltale_rules::load_rule_set_from_documents(
            &documents,
            self.policy_document.as_deref(),
        )
        .map_err(PipelineError::Compilation)?;
        let canonical = telltale_detect::v2::compile_rule_v1(&rule_set.compatibility_export());
        Ok(Pipeline {
            rule_set,
            canonical,
            process_rules: std::sync::OnceLock::new(),
        })
    }
}

#[cfg(test)]
mod canonical_embedding_tests;
#[cfg(test)]
mod detailed_scan_tests;

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
    fn batch_time_failures_precede_compilation_and_source_io() {
        let invalid_rules = r#"
version: 1
description: synthetic batch error precedence
defaults:
  case_insensitive: false
  enabled: true
rules:
  - id: synthetic.invalid
    category: synthetic
    severity: unknown
    score: 1
    targets: [command]
    regex: needle
    tags: []
    explanation: synthetic
modifiers: []
"#;
        let invalid = Pipeline::builder()
            .without_bundled_defaults()
            .rules_document(invalid_rules)
            .build()
            .expect("legacy rules accept severity");
        let valid = Pipeline::builder().build().unwrap();
        let sources = [synthetic_source()];
        for batch in [&[][..], &sources[..]] {
            for pipeline in [&valid, &invalid] {
                let error = pipeline
                    .scan_sources_with_time(batch, || {
                        time::Date::from_calendar_date(2026, time::Month::October, 4)
                            .unwrap()
                            .format(&time::format_description::parse("[offset_hour]").unwrap())
                    })
                    .err()
                    .expect("clock failure");
                assert!(matches!(error, PipelineError::Clock(_)));
                let error = pipeline
                    .scan_sources_with_time(batch, || Ok("invalid-observed-at".into()))
                    .err()
                    .expect("observation failure");
                assert!(matches!(error, PipelineError::Observation(_)));
            }
            let error = invalid
                .scan_sources_with_time(batch, || Ok("2026-10-04T00:00:00Z".into()))
                .err()
                .expect("compilation failure");
            assert!(matches!(error, PipelineError::Compilation(_)));
            assert!(matches!(
                error
                    .source()
                    .and_then(|cause| cause.downcast_ref::<RuleV1CompileError>()),
                Some(RuleV1CompileError::InvalidSeverity)
            ));
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
    fn builder_compiles_bundled_defaults() {
        let pipeline = Pipeline::builder().build().expect("pipeline");
        assert!(pipeline.rule_count() > 0);
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

    #[test]
    fn scan_root_propagates_checked_discovery_errors() {
        let pipeline = Pipeline::builder().build().expect("pipeline");
        let root =
            std::env::temp_dir().join(format!("telltale-core-missing-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);

        let error = pipeline.scan_root(&root).expect_err("missing root");

        assert!(matches!(error, PipelineError::Discovery(_)));
    }
}
