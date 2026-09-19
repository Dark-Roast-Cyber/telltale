//! Experimental, local, non-production Detection v2 foundation.
//!
//! This module is intentionally not scanner-wired or connected to the
//! production scanner. It accepts only typed Canonical Observation v2 values
//! and emits local semantic results plus an explicit inactive Event3 compatibility
//! projection; source discovery, actions, persistence, and production routing
//! remain outside this boundary.

mod classification;
pub mod event3;
mod matcher;
mod observation_match;
#[allow(dead_code)]
pub(crate) mod process_chain;
pub(crate) mod rule_v1;
mod selector;
pub mod session;
mod types;

pub use event3::{
    Event3CompatibilityContext, Event3SessionMetadata, ProjectedSource, project_event3,
};
pub use matcher::{
    CompiledMatcher, MAX_MATCHER_BRANCHES, MAX_MATCHER_DEPTH, MAX_PATTERN_BYTES, MatchState,
    MatcherEvaluation, MatcherOperator, MatcherSpec,
};
pub use session::{
    CanonicalActivity, CanonicalSessionEvaluation, CanonicalSourceEvaluation, CanonicalSourceInput,
    EvaluationCompletion, ProcessingError, evaluate_source,
};
pub type Operator = MatcherOperator;
pub use observation_match::{
    CompiledObservationMatchDetector, MAX_REQUIRED_CAPABILITIES, MatchSurface,
    ObservationMatchContent, ObservationMatchSpec,
};
pub(crate) use rule_v1::{RuleV1CompatibilityMetadata, evaluate_rule_v1_session};
pub use rule_v1::{RuleV1CompatibilityPlan, RuleV1CompileError, compile_rule_v1};
pub use rule_v1::{RuleV1DetectorOutcome, RuleV1DetectorSessionEvaluation};
pub use selector::{
    SelectorBacking, SelectorId, SelectorPresence, SelectorRegistry, SelectorResolution,
};
pub use types::{
    Confidence, CorrelationScope, DeduplicationStatus, DetectionError, DetectorIdentity,
    DetectorKind, DetectorResult, Diagnostic, DiagnosticKind, EvaluationStatus, EvidenceRef,
    EvidenceReference, EvidenceRepresentation, FINDING_ID_PREFIX, Finding, FindingKind,
    FindingMetadata, MAX_CATEGORY_BYTES, MAX_EVIDENCE_REFS, MAX_ID_BYTES, MAX_OBSERVATION_IDS,
    MAX_SELECTOR_PATHS, MAX_TAGS, MAX_TECHNIQUES, NonEvaluationReason, NotEvaluationReason,
    SIGNAL_ID_PREFIX, Score, Severity, Signal, SuppressionStatus,
};

#[cfg(test)]
mod session_tests;
#[cfg(test)]
mod tests;
