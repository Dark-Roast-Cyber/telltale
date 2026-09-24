//! Detection v2 semantic evaluation used by the canonical source runtime.
//!
//! This module accepts typed Canonical Observation v2 and native accounting and
//! emits local semantic results plus an Event3 compatibility projection. Source
//! discovery, actions, persistence, and runtime routing remain outside this
//! boundary.

#[cfg(feature = "source-io")]
pub mod activity;
#[cfg(all(test, feature = "source-io"))]
mod activity_tests;
mod classification;
pub mod event3;
mod matcher;
mod observation_match;
pub mod policy_accounting;
#[allow(dead_code)]
pub(crate) mod process_chain;
#[cfg(test)]
mod process_chain_contract_tests;
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
pub use policy_accounting::{PolicyMatchAccounting, PolicyMatchAccountingError};
#[cfg(test)]
pub(crate) use rule_v1::RuleV1CompatibilityMetadata;
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
