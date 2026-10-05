//! Shared source-semantic runtime for scan, watch, and embedding.
//! Scanner policy, state installation, event policy and delivery belong outside.

use crate::{Event, Source};
use sha2::{Digest, Sha256};
use telltale_detect::baseline::{BaselineDeviationConfig, BaselineSnapshotStore};
use telltale_detect::process_chain::ProcessChainConfig;
use telltale_detect::v2::activity::{BaselineReplacement, evaluate_activity};
use telltale_detect::v2::{
    CanonicalSourceInput, EvaluationCompletion, Event3CompatibilityContext, Event3SessionMetadata,
    PolicyMatchAccounting, PolicyMatchAccountingError, ProcessingError, RuleV1CompatibilityPlan,
    evaluate_source, project_event3,
};
use telltale_rules::process_chain::CompiledProcessChainRules;
use telltale_schema::event::path_hash;
use telltale_schema::observation::{CorrelationId, CorrelationOrigin, ObservedAt};
use telltale_sources::acquisition::{
    AcquisitionBatch, AcquisitionError, AcquisitionOptions, AcquisitionProgress,
    OpenCodeSqliteReadOptions, SourceAccounting, acquire_opencode_sqlite, acquire_source,
};

pub struct SourceResult {
    pub events: Vec<Event>,
    pub occurrences: Vec<telltale_detect::v2::event3::ProjectedOccurrence>,
    pub action_findings: Vec<telltale_detect::v2::ActionFinding>,
    pub semantic_provenance: telltale_detect::v2::SemanticProvenance,
    pub progress: AcquisitionProgress,
    pub completion: EvaluationCompletion,
    pub accounting: SourceAccounting,
    pub baseline_replacement: BaselineReplacement,
    pub policy_accounting: Option<Result<PolicyMatchAccounting, PolicyMatchAccountingError>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureStage {
    SourceScope,
    Acquisition,
    Evaluation,
    Projection,
    Activity,
}

#[derive(Debug)]
pub struct SourceFailure {
    pub stage: FailureStage,
    pub progress: AcquisitionProgress,
    pub acquisition: Option<AcquisitionError>,
}

impl std::fmt::Display for SourceFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "canonical source processing failed: {:?}", self.stage)
    }
}
impl std::error::Error for SourceFailure {}

impl SourceFailure {
    /// Adapt typed operational failure to the frozen source-scanning Event3 contract.
    pub fn event(&self, source: &Source) -> Event {
        let code = match self.stage {
            FailureStage::SourceScope => "canonical_source_scope_failed",
            FailureStage::Acquisition => "canonical_acquisition_failed",
            FailureStage::Evaluation => "canonical_evaluation_failed",
            FailureStage::Projection => "canonical_projection_failed",
            FailureStage::Activity => "canonical_activity_failed",
        };
        let mut event = telltale_schema::event::scanner_error_event(source, &code);
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
        format!("{:x}", hash.finalize()),
        CorrelationOrigin::TelltaleOriginated,
    )
    .map_err(|_| ProcessingError::InvalidSource)?;
    let mut resolved = source.clone();
    resolved.path = path;
    Ok((resolved, instance))
}

pub struct SourceContext<'a> {
    pub mcp_servers: &'a [telltale_detect::mcp::McpServerInventory],
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
    let (resolved, instance) = verified_source(source).map_err(|_| SourceFailure {
        stage: FailureStage::SourceScope,
        progress: AcquisitionProgress::None,
        acquisition: None,
    })?;
    let options = AcquisitionOptions::new(observed_at);
    let batch = match sqlite {
        Some(bounds) => acquire_opencode_sqlite(&resolved, options, bounds),
        None => acquire_source(&resolved, options),
    }
    .map_err(|error| SourceFailure {
        stage: FailureStage::Acquisition,
        progress: AcquisitionProgress::None,
        acquisition: Some(error),
    })?;
    finish_batch_with_options(source, &instance, batch, context, detailed)
}

/// Source-atomic composition after acquisition by this module.
#[cfg(test)]
fn finish_batch(
    source: &Source,
    instance: &CorrelationId,
    batch: AcquisitionBatch,
    context: SourceContext<'_>,
) -> Result<SourceResult, SourceFailure> {
    finish_batch_with_options(source, instance, batch, context, None)
}

fn finish_batch_with_options(
    source: &Source,
    instance: &CorrelationId,
    batch: AcquisitionBatch,
    context: SourceContext<'_>,
    detailed: Option<&telltale_detect::v2::DetailedEvaluationOptions>,
) -> Result<SourceResult, SourceFailure> {
    let fail = |stage| SourceFailure {
        stage,
        progress: batch.progress,
        acquisition: None,
    };
    let input = CanonicalSourceInput {
        client: source.client,
        source_id: &source.source_id,
        source_instance: Some(instance),
        observations: &batch.observations,
    };
    let evaluation = match detailed {
        Some(options) => telltale_detect::v2::evaluate_source_with_options(
            input,
            context.rules,
            context.process,
            options,
        ),
        None => evaluate_source(input, context.rules, context.process),
    }
    .map_err(|_| fail(FailureStage::Evaluation))?;
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
    .map_err(|_| fail(FailureStage::Projection))?;
    let activity = evaluate_activity(
        &evaluation,
        &batch.accounting,
        &hash,
        context.prior,
        context.baseline_deviation,
    )
    .map_err(|_| fail(FailureStage::Activity))?;
    // Diagnostic-only comparison over the same acquisition. No second source read,
    // no legacy record conversion, and no effect on authoritative output/progress.
    let policy_accounting = context.pre_policy_rules.map(|rules| {
        let before = evaluate_source(
            CanonicalSourceInput {
                client: source.client,
                source_id: &source.source_id,
                source_instance: Some(instance),
                observations: &batch.observations,
            },
            rules,
            None,
        )
        .map_err(|_| PolicyMatchAccountingError)?;
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
        action_findings: evaluation
            .sessions()
            .iter()
            .flat_map(|s| s.action_findings().iter().cloned())
            .collect(),
        semantic_provenance: detailed.map_or_else(
            || context.rules.semantic_provenance(),
            |options| context.rules.semantic_provenance_with_options(options),
        ),
        events: projected.events,
        occurrences: projected.occurrences,
        completion: projected.completion,
        progress: batch.progress,
        accounting: batch.accounting,
        baseline_replacement: activity.replacement,
        policy_accounting,
    })
}

#[cfg(test)]
#[path = "canonical_runtime_tests.rs"]
mod tests;
