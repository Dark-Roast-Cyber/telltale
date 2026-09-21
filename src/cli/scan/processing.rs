//! Scanner-owned processing success and progress eligibility.
//!
//! Observed source high-water is a progress candidate. Eligibility depends on
//! operational processing success, not parse success, Event3 contents, or
//! finding count. Required output persistence still gates state installation.
//!
//! This contract remains the scanner owner after canonical activation.
//! Do not duplicate `EvaluationCompletion` here.

use telltale_detect::v2::{EvaluationCompletion, ProcessingError};

/// Operational result of one source processing attempt.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(super) enum SourceProcessingStatus {
    /// Parse/read and downstream analysis completed operationally.
    /// Progress candidates from this attempt may be considered for staging.
    Succeeded,
    /// Parse/read or downstream analysis failed operationally.
    /// Progress candidates must not be staged.
    Failed,
}

impl SourceProcessingStatus {
    /// Projection failure must be passed as `Err`.
    pub(super) fn from_canonical(result: Result<EvaluationCompletion, ProcessingError>) -> Self {
        match result {
            Ok(EvaluationCompletion::Complete | EvaluationCompletion::VisibilityLimited) => {
                Self::Succeeded
            }
            Err(_) => Self::Failed,
        }
    }

    pub(super) fn is_progress_eligible(self) -> bool {
        matches!(self, Self::Succeeded)
    }
}

pub(super) fn should_stage_sqlite_ingestion_cursors(dry_run: bool, backfill: bool) -> bool {
    !dry_run && !backfill
}

/// Returns observed high-water only when it is eligible to be staged.
/// This is not a committed cursor.
pub(super) fn sqlite_progress_candidate(
    is_opencode_sqlite: bool,
    observed_high_water: Option<i64>,
    status: SourceProcessingStatus,
) -> Option<i64> {
    if !is_opencode_sqlite || !status.is_progress_eligible() {
        return None;
    }
    observed_high_water
}

#[cfg(test)]
mod tests {
    use super::{
        SourceProcessingStatus, should_stage_sqlite_ingestion_cursors, sqlite_progress_candidate,
    };
    use telltale_detect::v2::{EvaluationCompletion, ProcessingError};

    #[test]
    fn canonical_complete_and_visibility_limited_are_successful_processing() {
        assert_eq!(
            SourceProcessingStatus::from_canonical(Ok(EvaluationCompletion::Complete)),
            SourceProcessingStatus::Succeeded
        );
        assert_eq!(
            SourceProcessingStatus::from_canonical(Ok(EvaluationCompletion::VisibilityLimited)),
            SourceProcessingStatus::Succeeded
        );
        assert!(
            SourceProcessingStatus::from_canonical(Ok(EvaluationCompletion::VisibilityLimited))
                .is_progress_eligible()
        );
    }

    #[test]
    fn canonical_processing_error_is_operational_failure() {
        for error in [
            ProcessingError::InvalidSource,
            ProcessingError::DuplicateObservation,
            ProcessingError::Bounds,
            ProcessingError::Evaluation,
            ProcessingError::Projection,
        ] {
            assert_eq!(
                SourceProcessingStatus::from_canonical(Err(error)),
                SourceProcessingStatus::Failed,
                "{error}"
            );
            assert!(
                !SourceProcessingStatus::from_canonical(Err(error)).is_progress_eligible(),
                "{error}"
            );
        }
    }

    #[test]
    fn sqlite_progress_candidate_requires_success_and_opencode_high_water() {
        assert_eq!(
            sqlite_progress_candidate(true, Some(9_000), SourceProcessingStatus::Succeeded),
            Some(9_000)
        );
        assert_eq!(
            sqlite_progress_candidate(true, Some(9_000), SourceProcessingStatus::Failed),
            None
        );
        assert_eq!(
            sqlite_progress_candidate(false, Some(9_000), SourceProcessingStatus::Succeeded),
            None
        );
        assert_eq!(
            sqlite_progress_candidate(true, None, SourceProcessingStatus::Succeeded),
            None
        );
    }

    #[test]
    fn dry_run_and_backfill_cannot_stage_cursors() {
        assert!(should_stage_sqlite_ingestion_cursors(false, false));
        assert!(!should_stage_sqlite_ingestion_cursors(true, false));
        assert!(!should_stage_sqlite_ingestion_cursors(false, true));
        assert!(!should_stage_sqlite_ingestion_cursors(true, true));
    }
}
