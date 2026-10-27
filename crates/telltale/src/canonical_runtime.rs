//! Shared source-semantic runtime for scan, watch, and embedding.
//! Scanner policy, state installation, event policy and delivery belong outside.

use crate::{Event, Source};
use sha2::{Digest, Sha256};
use telltale_detect::baseline::{BaselineDeviationConfig, BaselineSnapshotStore};
use telltale_detect::process_chain::ProcessChainConfig;
use telltale_detect::v2::activity::{BaselineReplacement, evaluate_activity};
use telltale_detect::v2::{
    CanonicalSourceInput, EvaluationCompletion, EvaluationWorkBudget, Event3CompatibilityContext,
    Event3SessionMetadata, PolicyMatchAccounting, PolicyMatchAccountingError, ProcessingError,
    RuleV1CompatibilityPlan, evaluate_source_with_work_budget, project_event3,
};
use telltale_rules::process_chain::CompiledProcessChainRules;
use telltale_schema::event::path_hash;
use telltale_schema::observation::{CorrelationId, CorrelationOrigin, ObservedAt};
use telltale_sources::acquisition::{
    AcquisitionBatch, AcquisitionError, AcquisitionOptions, AcquisitionProgress,
    OpenCodeSqliteReadOptions, QuarantinedUnit, SourceAccounting, acquire_opencode_sqlite,
    acquire_source,
};

pub struct SourceResult {
    pub events: Vec<Event>,
    pub occurrences: Vec<telltale_detect::v2::event3::ProjectedOccurrence>,
    pub action_findings: Vec<telltale_detect::v2::ActionFinding>,
    pub semantic_provenance: telltale_detect::v2::SemanticProvenance,
    pub progress: AcquisitionProgress,
    pub completion: EvaluationCompletion,
    pub visibility_limits: Vec<telltale_detect::v2::VisibilityLimit>,
    pub accounting: SourceAccounting,
    pub baseline_replacement: BaselineReplacement,
    pub policy_accounting: Option<Result<PolicyMatchAccounting, PolicyMatchAccountingError>>,
    /// Native units excluded for exceeding a size bound; the rest were evaluated.
    pub quarantined: Vec<QuarantinedUnit>,
    /// The OpenCode v2 window budget this result fit in, when the read set
    /// one or evaluation had to shrink it; a caller draining further windows
    /// starts from it.
    pub window_bytes: Option<usize>,
    /// Where a next OpenCode v2 window may start re-reading this cut window;
    /// see [`AcquisitionBatch::message_overlap_from`].
    pub message_overlap_from: Option<i64>,
}

/// Content-free `scanner_error` marking a source that was evaluated without
/// its quarantined units. Coordinates stay in the caller's local report.
pub fn quarantine_event(source: &Source) -> Event {
    let mut event =
        telltale_schema::event::scanner_error_event(source, &"canonical_units_quarantined");
    for evidence in &mut event.evidence {
        if evidence.field == "source_path" {
            evidence.redacted_value = "canonical source".into();
        }
    }
    event
}

/// Stage at which one source failed; re-exported as `SourceFailureStage`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FailureStage {
    SourceScope,
    Acquisition,
    Evaluation,
    Projection,
    Activity,
}

impl FailureStage {
    /// Closed, content-free code used by the Event 3 `scanner_error` adaptation.
    pub fn code(self) -> &'static str {
        match self {
            Self::SourceScope => "canonical_source_scope_failed",
            Self::Acquisition => "canonical_acquisition_failed",
            Self::Evaluation => "canonical_evaluation_failed",
            Self::Projection => "canonical_projection_failed",
            Self::Activity => "canonical_activity_failed",
        }
    }
}

#[derive(Debug)]
pub struct SourceFailure {
    pub stage: FailureStage,
    pub progress: AcquisitionProgress,
    pub acquisition: Option<AcquisitionError>,
    pub processing: Option<ProcessingError>,
}

impl std::fmt::Display for SourceFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "canonical source processing failed: {:?}", self.stage)?;
        if let Some(reason) = self.processing {
            write!(f, ": {reason}")?;
        }
        Ok(())
    }
}
impl std::error::Error for SourceFailure {}

impl SourceFailure {
    /// Adapt typed operational failure to the frozen source-scanning Event3 contract.
    pub fn event(&self, source: &Source) -> Event {
        let mut event = telltale_schema::event::scanner_error_event(source, &self.stage.code());
        for evidence in &mut event.evidence {
            if evidence.field == "source_path" {
                evidence.redacted_value = "canonical source".into();
            }
        }
        event
    }
}

/// One resolved regular-file coordinate; unchanged canonical correlation domain.
fn verified_source(source: &Source) -> Result<(Source, CorrelationId), ProcessingError> {
    let path = source
        .path
        .canonicalize()
        .map_err(|_| ProcessingError::InvalidSource)?;
    if !path.is_file() {
        return Err(ProcessingError::InvalidSource);
    }
    let mut hash = Sha256::new();
    hash.update(b"telltale:canonical-source-instance:v1\0");
    for value in [
        source.client.as_str().as_bytes(),
        source.source_id.as_bytes(),
        source.kind.as_str().as_bytes(),
        path.as_os_str().as_encoded_bytes(),
    ] {
        hash.update((value.len() as u64).to_le_bytes());
        hash.update(value);
    }
    let instance = CorrelationId::new(
        hex::encode(hash.finalize()),
        CorrelationOrigin::TelltaleOriginated,
    )
    .map_err(|_| ProcessingError::InvalidSource)?;
    let mut resolved = source.clone();
    resolved.path = path;
    Ok((resolved, instance))
}

#[derive(Clone, Copy)]
pub struct SourceContext<'a> {
    pub mcp_servers: &'a [crate::inventory::McpServerInventory],
    pub rules: &'a RuleV1CompatibilityPlan,
    pub pre_policy_rules: Option<&'a RuleV1CompatibilityPlan>,
    pub process: Option<(&'a CompiledProcessChainRules, &'a ProcessChainConfig)>,
    pub prior: &'a BaselineSnapshotStore,
    pub baseline_deviation: BaselineDeviationConfig,
}

/// The caller supplies exactly one observation time per acquisition operation.
/// Optional SQLite bounds are acquisition controls, not cursor policy.
pub fn process_source(
    source: &Source,
    observed_at: ObservedAt,
    sqlite: Option<OpenCodeSqliteReadOptions>,
    context: SourceContext<'_>,
) -> Result<SourceResult, SourceFailure> {
    process_source_inner(source, observed_at, sqlite, context, None)
}

pub fn process_source_detailed(
    source: &Source,
    observed_at: ObservedAt,
    sqlite: Option<OpenCodeSqliteReadOptions>,
    context: SourceContext<'_>,
    options: &telltale_detect::v2::DetailedEvaluationOptions,
) -> Result<SourceResult, SourceFailure> {
    process_source_inner(source, observed_at, sqlite, context, Some(options))
}

fn process_source_inner(
    source: &Source,
    observed_at: ObservedAt,
    sqlite: Option<OpenCodeSqliteReadOptions>,
    context: SourceContext<'_>,
    detailed: Option<&telltale_detect::v2::DetailedEvaluationOptions>,
) -> Result<SourceResult, SourceFailure> {
    let (resolved, instance) = verified_source(source).map_err(|error| SourceFailure {
        stage: FailureStage::SourceScope,
        progress: AcquisitionProgress::None,
        acquisition: None,
        processing: Some(error),
    })?;
    let mut sqlite = sqlite;
    let mut previous_window = None;
    loop {
        let options = AcquisitionOptions::new(observed_at.clone());
        let batch = match sqlite {
            Some(bounds) => acquire_opencode_sqlite(&resolved, options, bounds),
            None => acquire_source(&resolved, options),
        }
        .map_err(|error| SourceFailure {
            stage: FailureStage::Acquisition,
            progress: AcquisitionProgress::None,
            acquisition: Some(error),
            processing: None,
        })?;
        let window = matches!(
            batch.progress,
            AcquisitionProgress::OpenCodeSessionMessages { .. }
        )
        .then(|| {
            batch
                .observations
                .iter()
                .map(telltale_schema::observation::CanonicalObservationV2::retained_byte_len)
                .fold(0usize, usize::saturating_add)
        });
        // The rows of this window, should even its smallest size not fit.
        let units = window.map(|_| window_units(&batch.observations));
        let work = EvaluationWorkBudget::default();
        let capacity = std::cell::Cell::new(false);
        let result = finish_batch_with_work(
            source, &instance, batch, context, detailed, &work, &capacity,
        );
        let over_capacity = result.as_ref().is_err_and(|failure| {
            matches!(
                failure.stage,
                FailureStage::Evaluation | FailureStage::Projection
            )
        }) && (work.is_exhausted() || capacity.get());
        // An OpenCode v2 window is a selection, not the whole source: when
        // evaluating or projecting it exceeds the work budget or retained
        // capacity, evaluate a smaller one. Every attempt must shrink the
        // window, so this always ends.
        if let Some((bounds, bytes)) = sqlite.zip(window).filter(|&(_, bytes)| {
            over_capacity && bytes > 1 && previous_window.is_none_or(|previous| bytes < previous)
        }) {
            previous_window = Some(bytes);
            sqlite = Some(OpenCodeSqliteReadOptions {
                message_window_bytes: Some(bytes / 2),
                ..bounds
            });
        }
        // The smallest window still exceeds evaluation work or projection
        // capacity: quarantine its rows by coordinates, like rows over a
        // size bound, so one row cannot stop a forensic drain. The same
        // selection is re-read and evaluated without them.
        else if let (true, Some(bounds), Some(units)) = (over_capacity, sqlite, units) {
            let mut batch = acquire_opencode_sqlite(
                &resolved,
                AcquisitionOptions::new(observed_at.clone()),
                bounds,
            )
            .map_err(|error| SourceFailure {
                stage: FailureStage::Acquisition,
                progress: AcquisitionProgress::None,
                acquisition: Some(error),
                processing: None,
            })?;
            batch.observations.clear();
            batch.quarantined.extend(units);
            return finish_batch_with_work(
                source,
                &instance,
                batch,
                context,
                detailed,
                &EvaluationWorkBudget::default(),
                &std::cell::Cell::new(false),
            )
            .map(|mut result| {
                result.window_bytes = bounds.message_window_bytes;
                result
            });
        } else {
            return result.map(|mut result| {
                result.window_bytes = sqlite.and_then(|bounds| bounds.message_window_bytes);
                result
            });
        }
    }
}

/// Coordinates of each native unit with observations in a window.
fn window_units(
    observations: &[telltale_schema::observation::CanonicalObservationV2],
) -> Vec<QuarantinedUnit> {
    let mut seen = std::collections::BTreeSet::new();
    observations
        .iter()
        .filter_map(|observation| {
            let source = observation.source();
            let native_id = source.native_id()?;
            seen.insert(native_id).then(|| QuarantinedUnit {
                session_id: observation.session_id().map(|id| id.value().to_owned()),
                native_id: native_id.to_owned(),
                source_sequence: source.source_sequence().unwrap_or_default(),
                code: EVALUATION_CAPACITY_EXCEEDED,
                bound: None,
            })
        })
        .collect()
}

/// Quarantine code for rows whose smallest window still exceeds evaluation
/// work or retained projection capacity.
pub const EVALUATION_CAPACITY_EXCEEDED: &str = "evaluation_capacity_exceeded";

/// Source-atomic composition after acquisition by this module.
#[cfg(test)]
fn finish_batch(
    source: &Source,
    instance: &CorrelationId,
    batch: AcquisitionBatch,
    context: SourceContext<'_>,
) -> Result<SourceResult, SourceFailure> {
    finish_batch_with_work(
        source,
        instance,
        batch,
        context,
        None,
        &EvaluationWorkBudget::default(),
        &std::cell::Cell::new(false),
    )
}

fn finish_batch_with_work(
    source: &Source,
    instance: &CorrelationId,
    batch: AcquisitionBatch,
    context: SourceContext<'_>,
    detailed: Option<&telltale_detect::v2::DetailedEvaluationOptions>,
    work: &EvaluationWorkBudget,
    // Set when evaluation or projection failed on a capacity bound, which a
    // smaller selection can satisfy, rather than on invalid input.
    capacity: &std::cell::Cell<bool>,
) -> Result<SourceResult, SourceFailure> {
    let bounded = |error: ProcessingError, stage| {
        capacity.set(error == ProcessingError::Bounds);
        SourceFailure {
            stage,
            progress: batch.progress,
            acquisition: None,
            processing: Some(error),
        }
    };
    let fail = |stage| SourceFailure {
        stage,
        progress: batch.progress,
        acquisition: None,
        processing: None,
    };
    let input = CanonicalSourceInput {
        client: source.client,
        source_id: &source.source_id,
        source_instance: Some(instance),
        observations: &batch.observations,
    };
    let evaluation = match detailed {
        Some(options) => telltale_detect::v2::evaluate_source_with_options_and_work_budget(
            input,
            context.rules,
            context.process,
            options,
            work,
        ),
        None => evaluate_source_with_work_budget(input, context.rules, context.process, work),
    }
    .map_err(|error| bounded(error, FailureStage::Evaluation))?;
    let sessions = batch
        .accounting
        .sessions
        .iter()
        .filter(|attestation| {
            evaluation
                .sessions()
                .iter()
                .any(|session| session.session_id() == Some(&attestation.session_id))
        })
        .map(|session| Event3SessionMetadata {
            session_id: &session.session_id,
            agent: session.metadata.agent.known(),
            model: session.metadata.model.known(),
            provider: session.metadata.provider.known(),
        })
        .collect::<Vec<_>>();
    let hash = path_hash(&source.path);
    let mut projected = project_event3(
        &evaluation,
        &Event3CompatibilityContext {
            source_path_hash: &hash,
            sessions: &sessions,
        },
    )
    .map_err(|error| bounded(error, FailureStage::Projection))?;
    let activity = evaluate_activity(
        &evaluation,
        &batch.accounting,
        &hash,
        context.prior,
        context.baseline_deviation,
    )
    .map_err(|_| fail(FailureStage::Activity))?;
    // Diagnostic-only comparison over the same acquisition. No second source read,
    // no legacy record conversion. Work exhaustion still discards the source;
    // other comparison failures remain diagnostic-only.
    let before = context.pre_policy_rules.map(|rules| {
        evaluate_source_with_work_budget(
            CanonicalSourceInput {
                client: source.client,
                source_id: &source.source_id,
                source_instance: Some(instance),
                observations: &batch.observations,
            },
            rules,
            None,
            work,
        )
    });
    if work.is_exhausted() {
        return Err(bounded(ProcessingError::Bounds, FailureStage::Evaluation));
    }
    let policy_accounting = before.as_ref().map(|before| {
        let before = before.as_ref().map_err(|_| PolicyMatchAccountingError)?;
        let mut total = PolicyMatchAccounting {
            pre_policy_detection_candidate_count: 0,
            fully_filtered_detection_candidate_count: 0,
            filtered_rule_id_count: 0,
        };
        if before.sessions().len() != evaluation.sessions().len() {
            return Err(PolicyMatchAccountingError);
        }
        for (before, after) in before.sessions().iter().zip(evaluation.sessions()) {
            if before.session_id() != after.session_id()
                || after
                    .rule_ids()
                    .iter()
                    .any(|id| !before.rule_ids().contains(id))
            {
                return Err(PolicyMatchAccountingError);
            }
            if !before.rule_ids().is_empty() {
                total.pre_policy_detection_candidate_count = total
                    .pre_policy_detection_candidate_count
                    .checked_add(1)
                    .ok_or(PolicyMatchAccountingError)?;
                if after.rule_ids().is_empty() {
                    total.fully_filtered_detection_candidate_count = total
                        .fully_filtered_detection_candidate_count
                        .checked_add(1)
                        .ok_or(PolicyMatchAccountingError)?;
                }
                let filtered = u64::try_from(before.rule_ids().len() - after.rule_ids().len())
                    .map_err(|_| PolicyMatchAccountingError)?;
                total.filtered_rule_id_count = total
                    .filtered_rule_id_count
                    .checked_add(filtered)
                    .ok_or(PolicyMatchAccountingError)?;
            }
        }
        Ok(total)
    });
    let mcp =
        telltale_detect::mcp::project_mcp_usage(source, &batch.accounting, context.mcp_servers)
            .map_err(|_| fail(FailureStage::Activity))?;
    projected.events.extend(activity.events);
    projected.events.extend(mcp);
    Ok(SourceResult {
        action_findings: projected.action_findings,
        semantic_provenance: detailed.map_or_else(
            || context.rules.semantic_provenance(),
            |options| context.rules.semantic_provenance_with_options(options),
        ),
        events: projected.events,
        occurrences: projected.occurrences,
        completion: projected.completion,
        visibility_limits: evaluation.visibility_limits().iter().copied().collect(),
        progress: batch.progress,
        accounting: batch.accounting,
        baseline_replacement: activity.replacement,
        policy_accounting,
        quarantined: batch.quarantined,
        window_bytes: None,
        message_overlap_from: batch.message_overlap_from,
    })
}

#[cfg(test)]
#[path = "canonical_runtime_tests.rs"]
mod tests;
