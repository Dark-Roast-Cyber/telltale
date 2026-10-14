//! Scanner adapter for native acquisition -> evaluation -> Event3.
//! Source semantics live in telltale_core::canonical_runtime;
//! this adapter retains scanner policy and compatibility error events only.

use telltale_core::canonical_runtime::{SourceContext, SourceFailure, SourceResult};
use telltale_detect::baseline::BaselineDeviationConfig;
use telltale_detect::v2::EvaluationCompletion;
use telltale_detect::v2::RuleV1CompatibilityPlan;
use telltale_detect::v2::activity::BaselineReplacement;
use telltale_rules::process_chain::CompiledProcessChainRules;
#[cfg(test)]
use telltale_schema::event::path_hash;
use telltale_schema::observation::ObservedAt;
#[cfg(test)]
use telltale_sources::acquisition::{AcquisitionOptions, acquire_source};
use telltale_sources::acquisition::{AcquisitionProgress, QuarantinedUnit, SourceAccounting};

use super::{
    Event, OPENCODE_SQLITE_PART_TABLE, OPENCODE_SQLITE_SESSION_MESSAGE_TABLE, ProcessChainConfig,
    ScanState, Source, SourceProcessingStatus, is_opencode_sqlite_source,
    opencode_read_options_for_scan_source, should_stage_sqlite_ingestion_cursors,
    sqlite_progress_candidate,
};

pub(super) struct CanonicalProcessingResult {
    pub events: Vec<Event>,
    pub status: SourceProcessingStatus,
    pub progress: AcquisitionProgress,
    pub completion: Option<EvaluationCompletion>,
    pub failure: Option<SourceFailure>,
    pub accounting: Option<SourceAccounting>,
    pub baseline_replacement: BaselineReplacement,
    pub policy_accounting: Option<
        Result<
            telltale_detect::v2::PolicyMatchAccounting,
            telltale_detect::v2::PolicyMatchAccountingError,
        >,
    >,
    /// Source ID and coordinates of units excluded for exceeding a size bound.
    pub quarantined: Vec<(String, QuarantinedUnit)>,
}

#[derive(Default)]
pub(super) struct CanonicalProcessingOptions<'a> {
    pub mcp_servers: &'a [telltale_detect::mcp::McpServerInventory],
    pub backfill: bool,
    pub dry_run: bool,
    pub baseline_deviation: BaselineDeviationConfig,
    pub pre_policy_rules: Option<&'a RuleV1CompatibilityPlan>,
}

impl CanonicalProcessingResult {
    /// The cursor table this result's progress belongs to, and its high-water.
    /// Eligible for staging only; this operation never mutates ScanState. Legacy
    /// `part` and OpenCode v2 `session_message` progress stage separate cursors.
    pub(super) fn sqlite_progress_cursor(
        &self,
        dry_run: bool,
        backfill: bool,
    ) -> Option<(&'static str, i64, bool)> {
        if !should_stage_sqlite_ingestion_cursors(dry_run, backfill) {
            return None;
        }
        let (table, high_water, draining) = match self.progress {
            AcquisitionProgress::None => return None,
            AcquisitionProgress::OpenCodeSqlite {
                part_max_time_updated,
            } => (OPENCODE_SQLITE_PART_TABLE, part_max_time_updated, false),
            AcquisitionProgress::OpenCodeSessionMessages {
                message_max_time_updated,
                window_complete,
            } => (
                OPENCODE_SQLITE_SESSION_MESSAGE_TABLE,
                message_max_time_updated,
                !window_complete,
            ),
        };
        sqlite_progress_candidate(true, high_water, self.status)
            .map(|value| (table, value, draining))
    }

    #[cfg(test)]
    pub(super) fn sqlite_progress_candidate(&self, dry_run: bool, backfill: bool) -> Option<i64> {
        self.sqlite_progress_cursor(dry_run, backfill)
            .map(|(_, high_water, _)| high_water)
    }
}

/// `observed_at` is supplied once by the scanner acquisition caller (its existing
/// UTC clock boundary), never inferred from records or used as occurred_at.
pub(super) fn process_canonical_source(
    source: &Source,
    state: &ScanState,
    processing: CanonicalProcessingOptions<'_>,
    observed_at: ObservedAt,
    rules: &RuleV1CompatibilityPlan,
    process: Option<(&CompiledProcessChainRules, &ProcessChainConfig)>,
) -> CanonicalProcessingResult {
    let sqlite = if is_opencode_sqlite_source(source) {
        // Reuse scanner-owned cursor/overlap policy, including dry-run/backfill.
        Some(opencode_read_options_for_scan_source(
            source,
            state,
            processing.backfill,
            processing.dry_run,
        ))
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
                mcp_servers: processing.mcp_servers,
                rules,
                pre_policy_rules: processing.pre_policy_rules,
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
            events: {
                let mut events = result.events;
                if !result.quarantined.is_empty() {
                    events.push(telltale_core::canonical_runtime::quarantine_event(source));
                }
                events
            },
            quarantined: result
                .quarantined
                .into_iter()
                .map(|unit| (source.source_id.clone(), unit))
                .collect(),
            status: SourceProcessingStatus::from_canonical(Ok(result.completion)),
            progress: result.progress,
            completion: Some(result.completion),
            failure: None,
            accounting: Some(result.accounting),
            baseline_replacement: result.baseline_replacement,
            policy_accounting: result.policy_accounting,
        },
        Err(error) => CanonicalProcessingResult {
            events: vec![error.event(source)],
            status: SourceProcessingStatus::Failed,
            progress: error.progress,
            completion: None,
            failure: Some(error),
            accounting: None,
            baseline_replacement: BaselineReplacement::NoReplacement,
            policy_accounting: None,
            quarantined: Vec::new(),
        },
    }
}

#[cfg(test)]
#[path = "canonical_tests.rs"]
mod tests;
