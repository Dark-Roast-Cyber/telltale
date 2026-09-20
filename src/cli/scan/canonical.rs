//! Inactive Issue #51 composition: prove native acquisition -> evaluation ->
//! Event3 before coordinated scan/watch/embedding activation. Activity/baseline
//! staging is inactive. After validated
//! activation, converge here and delete legacy composition/temporary carriers.
#![allow(dead_code)] // Private migration seam; never selected by run_scan.

use sha2::{Digest, Sha256};
use telltale_detect::baseline::{BaselineDeviationConfig, BaselineSnapshotStore};
use telltale_detect::v2::activity::{BaselineReplacement, evaluate_activity};
use telltale_detect::v2::{
    CanonicalSourceInput, EvaluationCompletion, Event3CompatibilityContext, Event3SessionMetadata,
    ProcessingError, RuleV1CompatibilityPlan, evaluate_source, project_event3,
};
use telltale_rules::process_chain::CompiledProcessChainRules;
use telltale_schema::event::path_hash;
use telltale_schema::observation::{CorrelationId, CorrelationOrigin, ObservedAt};
use telltale_sources::acquisition::{
    AcquisitionBatch, AcquisitionOptions, AcquisitionProgress, OpenCodeSqliteReadOptions,
    SourceAccounting, acquire_opencode_sqlite, acquire_source,
};

use super::{
    Event, ProcessChainConfig, ScanState, Source, SourceProcessingStatus,
    is_opencode_sqlite_source, parse_options_for_scan_source, scanner_error_event,
    should_stage_sqlite_ingestion_cursors, sqlite_progress_candidate,
};

pub(super) struct CanonicalProcessingResult {
    pub events: Vec<Event>,
    pub status: SourceProcessingStatus,
    pub progress: AcquisitionProgress,
    pub completion: Option<EvaluationCompletion>,
    pub accounting: Option<SourceAccounting>,
    pub baseline_replacement: BaselineReplacement,
}

#[derive(Default)]
pub(super) struct CanonicalProcessingOptions {
    pub backfill: bool,
    pub dry_run: bool,
    pub baseline_deviation: BaselineDeviationConfig,
}

impl CanonicalProcessingResult {
    /// Eligible for staging only; this operation never mutates ScanState.
    pub(super) fn sqlite_progress_candidate(&self, dry_run: bool, backfill: bool) -> Option<i64> {
        if !should_stage_sqlite_ingestion_cursors(dry_run, backfill) {
            return None;
        }
        match self.progress {
            AcquisitionProgress::None => None,
            AcquisitionProgress::OpenCodeSqlite {
                part_max_time_updated,
            } => sqlite_progress_candidate(true, part_max_time_updated, self.status),
        }
    }
}

/// One resolved regular-file coordinate, never an adapter-wide or session scope.
/// The resolved path is also used for acquisition so aliases cannot change scope.
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

/// `observed_at` is supplied once by the scanner acquisition caller (its existing
/// UTC clock boundary), never inferred from records or used as occurred_at.
pub(super) fn process_canonical_source(
    source: &Source,
    state: &ScanState,
    processing: CanonicalProcessingOptions,
    observed_at: ObservedAt,
    rules: &RuleV1CompatibilityPlan,
    process: Option<(&CompiledProcessChainRules, &ProcessChainConfig)>,
) -> CanonicalProcessingResult {
    let (resolved, instance) = match verified_source(source) {
        Ok(scope) => scope,
        Err(_) => {
            return failed(
                source,
                AcquisitionProgress::None,
                "canonical_source_scope_failed",
            );
        }
    };
    let options = AcquisitionOptions::new(observed_at);
    let acquisition = if is_opencode_sqlite_source(source) {
        // Reuse scanner-owned cursor/overlap policy, including dry-run/backfill.
        let bounds =
            parse_options_for_scan_source(source, state, processing.backfill, processing.dry_run);
        acquire_opencode_sqlite(
            &resolved,
            options,
            OpenCodeSqliteReadOptions {
                part_min_time_updated: bounds.sqlite_part_min_time_updated,
                part_limit: bounds.sqlite_part_limit,
            },
        )
    } else {
        acquire_source(&resolved, options)
    };
    match acquisition {
        Ok(batch) => {
            let mut result = finish_batch(
                source,
                &instance,
                batch,
                rules,
                process,
                &state.baseline_snapshots,
                processing.baseline_deviation,
            );
            // Scanner mode owns staging eligibility; the semantic operation is
            // pure and does not know about dry-run/backfill or installation.
            if processing.dry_run || processing.backfill {
                result.baseline_replacement = BaselineReplacement::NoReplacement;
            }
            result
        }
        Err(_) => failed(
            source,
            AcquisitionProgress::None,
            "canonical_acquisition_failed",
        ),
    }
}

fn finish_batch(
    source: &Source,
    instance: &CorrelationId,
    batch: AcquisitionBatch,
    rules: &RuleV1CompatibilityPlan,
    process: Option<(&CompiledProcessChainRules, &ProcessChainConfig)>,
    prior: &BaselineSnapshotStore,
    baseline_deviation: BaselineDeviationConfig,
) -> CanonicalProcessingResult {
    let evaluation = match evaluate_source(
        CanonicalSourceInput {
            client: source.client,
            source_id: &source.source_id,
            source_instance: Some(instance),
            observations: &batch.observations,
        },
        rules,
        process,
    ) {
        Ok(evaluation) => evaluation,
        Err(_) => return failed(source, batch.progress, "canonical_evaluation_failed"),
    };
    // Metadata-only native sessions may emit no observations. Projection accepts
    // evaluated keys only; origin/visible-ID collision validation stays there.
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
    match project_event3(
        &evaluation,
        &Event3CompatibilityContext {
            source_path_hash: &path_hash(&source.path),
            sessions: &sessions,
        },
    ) {
        Ok(mut projected) => {
            let activity = match evaluate_activity(
                &evaluation,
                &batch.accounting,
                &path_hash(&source.path),
                prior,
                baseline_deviation,
            ) {
                Ok(activity) => activity,
                Err(_) => return failed(source, batch.progress, "canonical_activity_failed"),
            };
            projected.events.extend(activity.events);
            CanonicalProcessingResult {
                events: projected.events,
                status: SourceProcessingStatus::from_canonical(Ok(projected.completion)),
                progress: batch.progress,
                completion: Some(projected.completion),
                accounting: Some(batch.accounting),
                baseline_replacement: activity.replacement,
            }
        }
        Err(_) => failed(source, batch.progress, "canonical_projection_failed"),
    }
}

fn failed(
    source: &Source,
    progress: AcquisitionProgress,
    code: &'static str,
) -> CanonicalProcessingResult {
    let mut event = scanner_error_event(source, &code);
    // The shared legacy constructor includes a filename label. B2's public
    // diagnostic boundary retains its hash but never that source-controlled text.
    for evidence in &mut event.evidence {
        if evidence.field == "source_path" {
            evidence.redacted_value = "canonical source".into();
        }
    }
    CanonicalProcessingResult {
        events: vec![event],
        status: SourceProcessingStatus::Failed,
        progress,
        completion: None,
        accounting: None,
        baseline_replacement: BaselineReplacement::NoReplacement,
    }
}

#[cfg(test)]
#[path = "canonical_tests.rs"]
mod tests;
