//! Unstable Issue #51 source-semantic runtime. Not selected by production callers.
//! Scanner policy, state installation, event policy and delivery belong outside.

use crate::{Event, Source};
use sha2::{Digest, Sha256};
use telltale_detect::baseline::{BaselineDeviationConfig, BaselineSnapshotStore};
use telltale_detect::process_chain::ProcessChainConfig;
use telltale_detect::v2::activity::{BaselineReplacement, evaluate_activity};
use telltale_detect::v2::{
    CanonicalSourceInput, EvaluationCompletion, Event3CompatibilityContext, Event3SessionMetadata,
    ProcessingError, RuleV1CompatibilityPlan, evaluate_source, project_event3,
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
    pub progress: AcquisitionProgress,
    pub completion: EvaluationCompletion,
    pub accounting: SourceAccounting,
    pub baseline_replacement: BaselineReplacement,
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
    pub rules: &'a RuleV1CompatibilityPlan,
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
    finish_batch(source, &instance, batch, context)
}

/// Source-atomic composition after acquisition by this module.
fn finish_batch(
    source: &Source,
    instance: &CorrelationId,
    batch: AcquisitionBatch,
    context: SourceContext<'_>,
) -> Result<SourceResult, SourceFailure> {
    let fail = |stage| SourceFailure {
        stage,
        progress: batch.progress,
        acquisition: None,
    };
    let evaluation = evaluate_source(
        CanonicalSourceInput {
            client: source.client,
            source_id: &source.source_id,
            source_instance: Some(instance),
            observations: &batch.observations,
        },
        context.rules,
        context.process,
    )
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
    projected.events.extend(activity.events);
    Ok(SourceResult {
        events: projected.events,
        completion: projected.completion,
        progress: batch.progress,
        accounting: batch.accounting,
        baseline_replacement: activity.replacement,
    })
}

#[cfg(test)]
#[path = "canonical_runtime_tests.rs"]
mod tests;
