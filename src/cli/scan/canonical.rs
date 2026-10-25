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
use telltale_schema::observation::{MAX_CANONICAL_RETAINED_BYTES, ObservedAt};
#[cfg(test)]
use telltale_sources::acquisition::{AcquisitionOptions, acquire_source};
use telltale_sources::acquisition::{
    AcquisitionProgress, OpenCodeSqliteReadOptions, QuarantinedUnit, SourceAccounting,
};

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
    /// One accounting per evaluated window, oldest first; empty on failure
    /// before any window was evaluated.
    pub accounting: Vec<SourceAccounting>,
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
    pub mcp_servers: &'a [telltale_core::inventory::McpServerInventory],
    pub backfill: bool,
    /// Forensic history: read OpenCode v2 stores from their earliest message
    /// and drain without a window limit. Scan state is neither read nor kept.
    pub history: bool,
    pub dry_run: bool,
    pub baseline_deviation: BaselineDeviationConfig,
    pub pre_policy_rules: Option<&'a RuleV1CompatibilityPlan>,
}

impl CanonicalProcessingResult {
    /// The cursor table this result's progress belongs to, and its high-water.
    /// Eligible for staging only; this operation never mutates ScanState. Legacy
    /// `part` and OpenCode v2 `session_message` progress stage separate cursors.
    /// An empty completed drain retains its checkpoint but clears continuation.
    pub(super) fn sqlite_progress_cursor(
        &self,
        dry_run: bool,
        backfill: bool,
        prior_message_checkpoint: Option<i64>,
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
                message_max_time_updated.or(prior_message_checkpoint.filter(|_| window_complete)),
                !window_complete,
            ),
        };
        sqlite_progress_candidate(true, high_water, self.status)
            .map(|value| (table, value, draining))
    }

    #[cfg(test)]
    pub(super) fn sqlite_progress_candidate(&self, dry_run: bool, backfill: bool) -> Option<i64> {
        self.sqlite_progress_cursor(dry_run, backfill, None)
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
    let sqlite = if is_opencode_sqlite_source(source) && processing.history {
        Some(OpenCodeSqliteReadOptions::default().session_message_history())
    } else if is_opencode_sqlite_source(source) {
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
    let context = SourceContext {
        mcp_servers: processing.mcp_servers,
        rules,
        pre_policy_rules: processing.pre_policy_rules,
        process,
        prior: &state.baseline_snapshots,
        baseline_deviation: processing.baseline_deviation,
    };
    let process_window = |sqlite| {
        telltale_core::canonical_runtime::process_source(
            source,
            observed_at.clone(),
            sqlite,
            context,
        )
    };
    let first = process_window(sqlite);
    let mut window_bytes = first.as_ref().ok().and_then(|result| result.window_bytes);
    let mut overlap_from = first
        .as_ref()
        .ok()
        .and_then(|result| result.message_overlap_from);
    let mut result = adapt_result(source, first);
    // An OpenCode v2 backlog larger than one window is drained here, window
    // after window. Each next window re-reads the tail of the last one, at
    // most half of it and at most an hour before its high-water, so a
    // correlation straddling the cut is still evaluated whole; repeated
    // detections are deduplicated like those of the routine overlap. When
    // the tail alone would fill a window, the next window starts strictly
    // after the high-water instead, so draining always advances. A window
    // that fit after shrinking sets the size for the next ones, so the search
    // is not repeated for every window. Events of every window
    // are released together with the final position, so output gating is
    // unchanged; a later window that fails keeps the earlier windows and
    // their position, and reports the failure.
    let mut windows = 1;
    let mut fitted = 0;
    while let (
        Some(options),
        AcquisitionProgress::OpenCodeSessionMessages {
            message_max_time_updated: Some(high_water),
            window_complete: false,
        },
        None,
    ) = (sqlite, result.progress, &result.failure)
    {
        if !processing.history && windows >= MAX_DRAIN_WINDOWS_PER_SCAN {
            break;
        }
        windows += 1;
        // A history pass can take long; report progress, never content.
        if processing.history && windows % HISTORY_PROGRESS_WINDOWS == 0 {
            eprintln!("history: {windows} windows evaluated");
        }
        let strict = OpenCodeSqliteReadOptions {
            message_window_bytes: window_bytes,
            ..options.continue_session_messages_after(high_water)
        };
        let next = match overlap_from {
            Some(from) => {
                let overlapped = process_window(Some(OpenCodeSqliteReadOptions {
                    message_min_time_updated: Some(
                        from.max(high_water.saturating_sub(DRAIN_OVERLAP_MS)),
                    ),
                    ..strict
                }));
                if advances(&overlapped, high_water) {
                    overlapped
                } else {
                    process_window(Some(strict))
                }
            }
            None => process_window(Some(strict)),
        };
        if let Ok(next) = &next {
            // A shrunken size that keeps fitting doubles again, so a dense
            // stretch does not shrink the rest of the drain.
            if next.window_bytes == window_bytes {
                fitted += 1;
            } else {
                fitted = 0;
                window_bytes = next.window_bytes;
            }
            if fitted == WINDOW_GROWTH_AFTER {
                fitted = 0;
                window_bytes = window_bytes
                    .and_then(|bytes| bytes.checked_mul(2))
                    .filter(|bytes| *bytes < MAX_CANONICAL_RETAINED_BYTES);
            }
        }
        overlap_from = next
            .as_ref()
            .ok()
            .and_then(|result| result.message_overlap_from);
        // A quarantined row in the re-read tail is quarantined again; it is
        // still one excluded unit and needs no second scanner error.
        let next = next.map(|mut next| {
            next.quarantined
                .retain(|unit| !result.quarantined.iter().any(|(_, seen)| seen == unit));
            next
        });
        let next = adapt_result(source, next);
        result.events.extend(next.events);
        result.quarantined.extend(next.quarantined);
        result.accounting.extend(next.accounting);
        match next.failure {
            None => {
                result.progress = next.progress;
                result.completion = match (result.completion, next.completion) {
                    (
                        Some(EvaluationCompletion::Complete),
                        Some(EvaluationCompletion::Complete),
                    ) => Some(EvaluationCompletion::Complete),
                    _ => Some(EvaluationCompletion::VisibilityLimited),
                };
                // Each window replaces the source's contribution, exactly as
                // separate scans of the same windows would.
                result.baseline_replacement = next.baseline_replacement;
                result.policy_accounting = merge_policy_accounting(
                    result.policy_accounting.take(),
                    next.policy_accounting,
                );
            }
            Some(failure) => {
                result.failure = Some(failure);
                break;
            }
        }
    }
    // Scanner mode owns staging eligibility; the semantic operation does not
    // know about dry-run/backfill or installation.
    if processing.dry_run || processing.backfill || processing.history {
        result.baseline_replacement = BaselineReplacement::NoReplacement;
    }
    result
}

/// Cut OpenCode v2 windows drained by one routine scan; the rest continue
/// next scan. History mode drains without this limit.
const MAX_DRAIN_WINDOWS_PER_SCAN: usize = 64;

/// Windows between history progress lines on stderr.
const HISTORY_PROGRESS_WINDOWS: usize = 50;

/// Windows that fit at a shrunken size before the next one tries twice it.
const WINDOW_GROWTH_AFTER: usize = 4;

/// The most a drain window re-reads before the last high-water: the longest
/// bundled correlation window.
const DRAIN_OVERLAP_MS: i64 = 3_600_000;

/// Whether an overlapped window read after `high_water` moved past it on its
/// own. A failure, or rows quarantined because even the smallest window
/// exceeded capacity, could stem from re-read rows, so the window is then read
/// strictly after the high-water instead.
fn advances(window: &Result<SourceResult, SourceFailure>, high_water: i64) -> bool {
    match window {
        Ok(result)
            if result.quarantined.iter().any(|unit| {
                unit.code == telltale_core::canonical_runtime::EVALUATION_CAPACITY_EXCEEDED
            }) =>
        {
            false
        }
        Ok(result) => match result.progress {
            AcquisitionProgress::OpenCodeSessionMessages {
                message_max_time_updated,
                window_complete,
            } => window_complete || message_max_time_updated.is_some_and(|next| next > high_water),
            _ => true,
        },
        Err(_) => false,
    }
}

type PolicyAccounting = Option<
    Result<
        telltale_detect::v2::PolicyMatchAccounting,
        telltale_detect::v2::PolicyMatchAccountingError,
    >,
>;

fn merge_policy_accounting(left: PolicyAccounting, right: PolicyAccounting) -> PolicyAccounting {
    let (Some(left), Some(right)) = (left, right) else {
        return None;
    };
    let (Ok(left), Ok(right)) = (left, right) else {
        return Some(Err(telltale_detect::v2::PolicyMatchAccountingError));
    };
    let add = |left: u64, right: u64| {
        left.checked_add(right)
            .ok_or(telltale_detect::v2::PolicyMatchAccountingError)
    };
    Some((|| {
        Ok(telltale_detect::v2::PolicyMatchAccounting {
            pre_policy_detection_candidate_count: add(
                left.pre_policy_detection_candidate_count,
                right.pre_policy_detection_candidate_count,
            )?,
            fully_filtered_detection_candidate_count: add(
                left.fully_filtered_detection_candidate_count,
                right.fully_filtered_detection_candidate_count,
            )?,
            filtered_rule_id_count: add(left.filtered_rule_id_count, right.filtered_rule_id_count)?,
        })
    })())
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
            accounting: vec![result.accounting],
            baseline_replacement: result.baseline_replacement,
            policy_accounting: result.policy_accounting,
        },
        Err(error) => CanonicalProcessingResult {
            events: vec![error.event(source)],
            status: SourceProcessingStatus::Failed,
            progress: error.progress,
            completion: None,
            failure: Some(error),
            accounting: Vec::new(),
            baseline_replacement: BaselineReplacement::NoReplacement,
            policy_accounting: None,
            quarantined: Vec::new(),
        },
    }
}

#[cfg(test)]
#[path = "canonical_tests.rs"]
mod tests;
