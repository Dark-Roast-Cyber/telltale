//! Experimental, local, non-production Detection v2 foundation.
//!
//! This module is intentionally not scanner-wired or connected to the
//! production scanner. It accepts only typed Canonical Observation v2 values
//! and emits local semantic results; source discovery, policy, actions,
//! telemetry, and Event projection remain outside this boundary.

mod matcher;
mod observation_match;
mod rule_v1;
mod selector;
mod types;

pub use matcher::{
    CompiledMatcher, MAX_MATCHER_BRANCHES, MAX_MATCHER_DEPTH, MAX_PATTERN_BYTES, MatchState,
    MatcherEvaluation, MatcherOperator, MatcherSpec,
};
pub type Operator = MatcherOperator;
pub use observation_match::{
    CompiledObservationMatchDetector, MAX_REQUIRED_CAPABILITIES, MatchSurface,
    ObservationMatchContent, ObservationMatchSpec,
};
pub use rule_v1::{
    RuleV1CompatibilityPlan, RuleV1CompileError, RuleV1ModifierPlan, compile_rule_v1,
};
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
mod tests;
