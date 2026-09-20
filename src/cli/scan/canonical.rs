//! Inactive Issue #51 composition: prove native acquisition -> evaluation ->
//! Event3 before coordinated scan/watch/embedding activation. Activity/baseline
//! staging is inactive. Source semantics live in telltale_core::canonical_runtime;
//! this adapter retains scanner policy and compatibility error events only.
#![allow(dead_code)] // Private migration seam; never selected by run_scan.

use telltale_core::canonical_runtime::{FailureStage, SourceContext, SourceResult};
use telltale_detect::baseline::BaselineDeviationConfig;
use telltale_detect::v2::activity::BaselineReplacement;
use telltale_detect::v2::{EvaluationCompletion, RuleV1CompatibilityPlan};
use telltale_rules::process_chain::CompiledProcessChainRules;
#[cfg(test)]
use telltale_schema::event::path_hash;
use telltale_schema::observation::ObservedAt;
#[cfg(test)]
use telltale_sources::acquisition::{AcquisitionOptions, acquire_source};
use telltale_sources::acquisition::{
    AcquisitionProgress, OpenCodeSqliteReadOptions, SourceAccounting,
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
    let sqlite = if is_opencode_sqlite_source(source) {
        // Reuse scanner-owned cursor/overlap policy, including dry-run/backfill.
        let bounds =
            parse_options_for_scan_source(source, state, processing.backfill, processing.dry_run);
        Some(OpenCodeSqliteReadOptions {
            part_min_time_updated: bounds.sqlite_part_min_time_updated,
            part_limit: bounds.sqlite_part_limit,
        })
    } else {
        None
    };
    let mut result = adapt_result(
        source,
        telltale_core::canonical_runtime::process_source(
            source,
            observed_at,
            sqlite,
            SourceContext {
                rules,
                process,
                prior: &state.baseline_snapshots,
                baseline_deviation: processing.baseline_deviation,
            },
        ),
    );
    // Scanner mode owns staging eligibility; the semantic operation does not
    // know about dry-run/backfill or installation.
    if processing.dry_run || processing.backfill {
        result.baseline_replacement = BaselineReplacement::NoReplacement;
    }
    result
}

fn adapt_result(
    source: &Source,
    result: Result<SourceResult, telltale_core::canonical_runtime::SourceFailure>,
) -> CanonicalProcessingResult {
    match result {
        Ok(result) => CanonicalProcessingResult {
            events: result.events,
            status: SourceProcessingStatus::from_canonical(Ok(result.completion)),
            progress: result.progress,
            completion: Some(result.completion),
            accounting: Some(result.accounting),
            baseline_replacement: result.baseline_replacement,
        },
        Err(error) => {
            let code = match error.stage {
                FailureStage::SourceScope => "canonical_source_scope_failed",
                FailureStage::Acquisition => "canonical_acquisition_failed",
                FailureStage::Evaluation => "canonical_evaluation_failed",
                FailureStage::Projection => "canonical_projection_failed",
                FailureStage::Activity => "canonical_activity_failed",
            };
            failed(source, error.progress, code)
        }
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
