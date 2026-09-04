//! Detector-neutral Detection v2 values.
//!
//! These types deliberately have no serde implementation.  They are local
//! semantic values, not an Event or telemetry representation.

use std::fmt;

use sha2::{Digest, Sha256};
use telltale_schema::observation::{
    CanonicalObservationV2, CapabilityContext, CorrelationId, JsonValue, LocalReference,
    ObservationId, canonical_identity_json, valid_observation_id,
};

use super::selector::SelectorId;

pub const MAX_ID_BYTES: usize = 96;
pub const MAX_CATEGORY_BYTES: usize = 128;
pub const MAX_TAGS: usize = 32;
pub const MAX_TECHNIQUES: usize = 32;
pub const MAX_EVIDENCE_REFS: usize = 16;
pub const MAX_OBSERVATION_IDS: usize = 64;
pub const MAX_SELECTOR_PATHS: usize = 64;
pub const MAX_DIAGNOSTIC_CODE_BYTES: usize = 96;
pub const SIGNAL_ID_PREFIX: &str = "sig:v2:sha256:";
pub const FINDING_ID_PREFIX: &str = "fnd:v2:sha256:";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectionError {
    InvalidId,
    InvalidText,
    InvalidStatus,
    InvalidReason,
    InvalidMetadata,
    InvalidBounds,
    InvalidSelector,
    InvalidOperator,
    InvalidValue,
    InvalidCapability,
    InvalidPattern,
    InvalidEvidenceReference,
    MissingObservationId,
    PatternTooLong,
    EmptyBooleanGroup,
    BooleanDepthExceeded,
    BooleanBranchLimit,
    UnsupportedDetectorKind,
    UnmappableRuleClass,
    ScoreOutOfRange,
    RuntimeEvaluation,
}

impl DetectionError {
    pub fn code(self) -> &'static str {
        match self {
            Self::InvalidId => "invalid_id",
            Self::InvalidText => "invalid_text",
            Self::InvalidStatus => "invalid_status",
            Self::InvalidReason => "invalid_reason",
            Self::InvalidMetadata => "invalid_metadata",
            Self::InvalidBounds => "invalid_bounds",
            Self::InvalidSelector => "invalid_selector",
            Self::InvalidOperator => "invalid_operator",
            Self::InvalidValue => "invalid_value",
            Self::InvalidCapability => "invalid_capability",
            Self::InvalidPattern => "invalid_pattern",
            Self::InvalidEvidenceReference => "invalid_evidence_reference",
            Self::MissingObservationId => "missing_observation_id",
            Self::PatternTooLong => "pattern_too_long",
            Self::EmptyBooleanGroup => "empty_boolean_group",
            Self::BooleanDepthExceeded => "boolean_depth_exceeded",
            Self::BooleanBranchLimit => "boolean_branch_limit",
            Self::UnsupportedDetectorKind => "unsupported_detector_kind",
            Self::UnmappableRuleClass => "unmappable_rule_class",
            Self::ScoreOutOfRange => "score_out_of_range",
            Self::RuntimeEvaluation => "runtime_evaluation",
        }
    }
}

impl fmt::Display for DetectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for DetectionError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DetectorKind {
    ObservationMatch,
    ProcessChain,
    Sequence,
    Correlation,
    Imported,
    Baseline,
    GuardModel,
}

impl DetectorKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ObservationMatch => "observation_match",
            Self::ProcessChain => "process_chain",
            Self::Sequence => "sequence",
            Self::Correlation => "correlation",
            Self::Imported => "imported",
            Self::Baseline => "baseline",
            Self::GuardModel => "guard_model",
        }
    }

    pub fn runtime_supported(self) -> bool {
        matches!(self, Self::ObservationMatch)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvaluationStatus {
    EvaluatedMatch,
    EvaluatedNoMatch,
    NotApplicable,
    NotEvaluated,
    DetectorError,
}

impl EvaluationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EvaluatedMatch => "evaluated_match",
            Self::EvaluatedNoMatch => "evaluated_no_match",
            Self::NotApplicable => "not_applicable",
            Self::NotEvaluated => "not_evaluated",
            Self::DetectorError => "detector_error",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum NonEvaluationReason {
    RequiredCapabilityUnsupported,
    RequiredCapabilityUnknown,
    InsufficientVisibility,
    MissingOrderingField,
    MissingCorrelationKey,
    TypeMismatch,
    IneligibleInput,
}

pub type NotEvaluationReason = NonEvaluationReason;

impl NonEvaluationReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InsufficientVisibility => "insufficient_visibility",
            Self::RequiredCapabilityUnsupported => "required_capability_unsupported",
            Self::RequiredCapabilityUnknown => "required_capability_unknown",
            Self::MissingOrderingField => "missing_ordering_field",
            Self::MissingCorrelationKey => "missing_correlation_key",
            Self::TypeMismatch => "type_mismatch",
            Self::IneligibleInput => "ineligible_input",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingKind {
    SecurityDetection,
    PolicyViolation,
    BehavioralDeviation,
    Guardrail,
    ComplianceObservation,
    ThreatHunt,
    Correlation,
    Informational,
}

impl FindingKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SecurityDetection => "security_detection",
            Self::PolicyViolation => "policy_violation",
            Self::BehavioralDeviation => "behavioral_deviation",
            Self::Guardrail => "guardrail",
            Self::ComplianceObservation => "compliance_observation",
            Self::ThreatHunt => "threat_hunt",
            Self::Correlation => "correlation",
            Self::Informational => "informational",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Informational => "informational",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Confidence {
    Low,
    Medium,
    High,
}

impl Confidence {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CorrelationScope {
    Observation,
    Session,
    Sequence,
    Workflow,
    Process,
}

impl CorrelationScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Observation => "observation",
            Self::Session => "session",
            Self::Sequence => "sequence",
            Self::Workflow => "workflow",
            Self::Process => "process",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceRepresentation {
    RedactedExcerpt,
    Hash,
    Classification,
    LocalStructuredValue,
    Correlation,
    Timeline,
}

impl EvidenceRepresentation {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RedactedExcerpt => "redacted_excerpt",
            Self::Hash => "hash",
            Self::Classification => "classification",
            Self::LocalStructuredValue => "local_structured_value",
            Self::Correlation => "correlation",
            Self::Timeline => "timeline",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiagnosticKind {
    CompileFailure,
    InvalidSelector,
    UnavailableCapability,
    RuntimeDetectorError,
    SequenceStateError,
    UnsupportedOperatorOrType,
    MalformedContentOrPackage,
}

impl DiagnosticKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CompileFailure => "compile_failure",
            Self::InvalidSelector => "invalid_selector",
            Self::UnavailableCapability => "unavailable_capability",
            Self::RuntimeDetectorError => "runtime_detector_error",
            Self::SequenceStateError => "sequence_state_error",
            Self::UnsupportedOperatorOrType => "unsupported_operator_or_type",
            Self::MalformedContentOrPackage => "malformed_content_or_package",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SuppressionStatus {
    NotSuppressed,
    Suppressed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeduplicationStatus {
    Unique,
    Duplicate,
    NotConfigured,
}

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub struct Score(f64);

impl Score {
    pub fn new(value: f64) -> Result<Self, DetectionError> {
        if value.is_finite() && (0.0..=1.0).contains(&value) {
            Ok(Self(value))
        } else {
            Err(DetectionError::ScoreOutOfRange)
        }
    }

    pub fn value(self) -> f64 {
        self.0
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct DetectorIdentity {
    kind: DetectorKind,
    id: String,
    version: Option<String>,
    engine: Option<String>,
    content_ref: Option<String>,
    rule_version: Option<u8>,
}

impl fmt::Debug for DetectorIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DetectorIdentity")
            .field("kind", &self.kind)
            .field("id", &"[redacted]")
            .field("version_present", &self.version.is_some())
            .field("engine_present", &self.engine.is_some())
            .field("content_ref_present", &self.content_ref.is_some())
            .field("rule_version", &self.rule_version)
            .finish()
    }
}

impl DetectorIdentity {
    pub fn new(kind: DetectorKind, id: impl AsRef<str>) -> Result<Self, DetectionError> {
        Ok(Self {
            kind,
            id: bounded_identifier(id.as_ref())?,
            version: None,
            engine: None,
            content_ref: None,
            rule_version: None,
        })
    }

    pub fn with_version(mut self, value: impl AsRef<str>) -> Result<Self, DetectionError> {
        self.version = Some(bounded_opaque(value.as_ref(), MAX_ID_BYTES)?);
        Ok(self)
    }

    pub fn with_engine(mut self, value: impl AsRef<str>) -> Result<Self, DetectionError> {
        self.engine = Some(bounded_opaque(value.as_ref(), MAX_ID_BYTES)?);
        Ok(self)
    }

    pub fn with_content_ref(mut self, value: impl AsRef<str>) -> Result<Self, DetectionError> {
        self.content_ref = Some(bounded_opaque(value.as_ref(), MAX_ID_BYTES)?);
        Ok(self)
    }

    pub fn with_rule_version(mut self, value: u8) -> Result<Self, DetectionError> {
        if value != 1 {
            return Err(DetectionError::InvalidMetadata);
        }
        self.rule_version = Some(value);
        Ok(self)
    }

    pub fn kind(&self) -> DetectorKind {
        self.kind
    }
    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn version(&self) -> Option<&str> {
        self.version.as_deref()
    }
    pub fn engine(&self) -> Option<&str> {
        self.engine.as_deref()
    }
    pub fn content_ref(&self) -> Option<&str> {
        self.content_ref.as_deref()
    }
    pub fn rule_version(&self) -> Option<u8> {
        self.rule_version
    }
}

/// A validated, non-content evidence handle accepted by [`EvidenceRef`].
///
/// The fields are private so callers must use a representation-specific
/// constructor; an arbitrary string cannot be smuggled in through this type.
#[derive(Clone, PartialEq, Eq)]
pub struct EvidenceReference {
    representation: EvidenceRepresentation,
    reference: String,
}

impl fmt::Debug for EvidenceReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EvidenceReference")
            .field("representation", &self.representation)
            .field("reference", &"[redacted]")
            .finish()
    }
}

impl EvidenceReference {
    pub fn redacted_excerpt(reference: impl AsRef<str>) -> Result<Self, DetectionError> {
        let reference = validate_evidence_reference(
            EvidenceRepresentation::RedactedExcerpt,
            reference.as_ref(),
        )?;
        Ok(Self {
            representation: EvidenceRepresentation::RedactedExcerpt,
            reference,
        })
    }

    pub fn hash(reference: impl AsRef<str>) -> Result<Self, DetectionError> {
        let reference =
            validate_evidence_reference(EvidenceRepresentation::Hash, reference.as_ref())?;
        Ok(Self {
            representation: EvidenceRepresentation::Hash,
            reference,
        })
    }

    pub fn classification(reference: impl AsRef<str>) -> Result<Self, DetectionError> {
        let reference = validate_evidence_reference(
            EvidenceRepresentation::Classification,
            reference.as_ref(),
        )?;
        Ok(Self {
            representation: EvidenceRepresentation::Classification,
            reference,
        })
    }

    pub fn local_structured(reference: &LocalReference) -> Result<Self, DetectionError> {
        let reference = format!("local:{}", reference.handle());
        let reference =
            validate_evidence_reference(EvidenceRepresentation::LocalStructuredValue, &reference)?;
        Ok(Self {
            representation: EvidenceRepresentation::LocalStructuredValue,
            reference,
        })
    }

    pub fn correlation(reference: &CorrelationId) -> Result<Self, DetectionError> {
        let reference = format!("correlation:{}", reference.value());
        let reference =
            validate_evidence_reference(EvidenceRepresentation::Correlation, &reference)?;
        Ok(Self {
            representation: EvidenceRepresentation::Correlation,
            reference,
        })
    }

    pub fn timeline(reference: impl AsRef<str>) -> Result<Self, DetectionError> {
        let reference =
            validate_evidence_reference(EvidenceRepresentation::Timeline, reference.as_ref())?;
        Ok(Self {
            representation: EvidenceRepresentation::Timeline,
            reference,
        })
    }

    pub fn representation(&self) -> EvidenceRepresentation {
        self.representation
    }

    pub fn reference(&self) -> &str {
        &self.reference
    }
}

/// A validated, privacy-safe reference to caller-owned evidence.
#[derive(Clone, PartialEq, Eq)]
pub struct EvidenceRef {
    observation_id: Option<String>,
    field: Option<String>,
    representation: EvidenceRepresentation,
    reference: String,
}

impl fmt::Debug for EvidenceRef {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EvidenceRef")
            .field("observation_id", &self.observation_id)
            .field("field", &self.field)
            .field("representation", &self.representation)
            .field("reference", &"[redacted]")
            .finish()
    }
}

impl EvidenceRef {
    /// Construct a reference after applying the representation-specific safe
    /// reference grammar.  Raw evidence text is rejected.
    pub fn new(
        representation: EvidenceRepresentation,
        reference: impl AsRef<str>,
    ) -> Result<Self, DetectionError> {
        let reference = validate_evidence_reference(representation, reference.as_ref())?;
        Ok(Self {
            observation_id: None,
            field: None,
            representation,
            reference,
        })
    }

    pub fn from_reference(reference: EvidenceReference) -> Result<Self, DetectionError> {
        Self::new(reference.representation, reference.reference)
    }

    pub fn hash(reference: impl AsRef<str>) -> Result<Self, DetectionError> {
        Self::new(EvidenceRepresentation::Hash, reference)
    }

    pub fn classification(reference: impl AsRef<str>) -> Result<Self, DetectionError> {
        Self::new(EvidenceRepresentation::Classification, reference)
    }

    pub fn redacted_excerpt(reference: impl AsRef<str>) -> Result<Self, DetectionError> {
        Self::new(EvidenceRepresentation::RedactedExcerpt, reference)
    }

    pub fn local_structured(reference: &LocalReference) -> Result<Self, DetectionError> {
        Self::from_reference(EvidenceReference::local_structured(reference)?)
    }

    pub fn correlation(reference: &CorrelationId) -> Result<Self, DetectionError> {
        Self::from_reference(EvidenceReference::correlation(reference)?)
    }

    pub fn timeline(reference: impl AsRef<str>) -> Result<Self, DetectionError> {
        Self::new(EvidenceRepresentation::Timeline, reference)
    }

    pub fn with_observation_id(
        mut self,
        observation_id: &ObservationId,
    ) -> Result<Self, DetectionError> {
        self.observation_id = Some(validated_observation_id(observation_id.as_str())?);
        Ok(self)
    }

    pub fn with_field(mut self, field: impl AsRef<str>) -> Result<Self, DetectionError> {
        SelectorId::parse(field.as_ref())?;
        self.field = Some(bounded_opaque(field.as_ref(), MAX_ID_BYTES)?);
        Ok(self)
    }

    pub fn observation_id(&self) -> Option<&str> {
        self.observation_id.as_deref()
    }
    pub fn field(&self) -> Option<&str> {
        self.field.as_deref()
    }
    pub fn representation(&self) -> EvidenceRepresentation {
        self.representation
    }
    pub fn reference(&self) -> &str {
        &self.reference
    }
}

fn validate_evidence_reference(
    representation: EvidenceRepresentation,
    reference: &str,
) -> Result<String, DetectionError> {
    match representation {
        EvidenceRepresentation::Hash => {
            if is_digest(reference) {
                Ok(reference.to_owned())
            } else {
                Err(DetectionError::InvalidEvidenceReference)
            }
        }
        EvidenceRepresentation::RedactedExcerpt => {
            let Some(digest) = reference.strip_prefix("redacted:") else {
                return Err(DetectionError::InvalidEvidenceReference);
            };
            if is_bare_digest(digest) {
                Ok(reference.to_owned())
            } else {
                Err(DetectionError::InvalidEvidenceReference)
            }
        }
        EvidenceRepresentation::Classification => {
            validate_prefixed_token(reference, "classification:")
        }
        EvidenceRepresentation::LocalStructuredValue => {
            validate_prefixed_token(reference, "local:")
        }
        EvidenceRepresentation::Correlation => validate_prefixed_token(reference, "correlation:"),
        EvidenceRepresentation::Timeline => validate_prefixed_token(reference, "timeline:"),
    }
}

fn validate_prefixed_token(reference: &str, prefix: &str) -> Result<String, DetectionError> {
    let Some(value) = reference.strip_prefix(prefix) else {
        return Err(DetectionError::InvalidEvidenceReference);
    };
    if reference.len() <= MAX_ID_BYTES && safe_token(value) {
        Ok(reference.to_owned())
    } else {
        Err(DetectionError::InvalidEvidenceReference)
    }
}

fn safe_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_ID_BYTES
        && !value.contains("..")
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'+' | b'-')
        })
}

fn is_digest(value: &str) -> bool {
    is_bare_digest(value)
        || value.strip_prefix("sha256:").is_some_and(is_bare_digest)
        || value
            .strip_prefix("hmac-sha256:v1:")
            .is_some_and(is_bare_digest)
        || value
            .strip_prefix("hmac-sha256:assignment-v1:")
            .is_some_and(is_bare_digest)
}

fn is_bare_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    kind: DiagnosticKind,
    code: String,
}

impl Diagnostic {
    pub fn new(kind: DiagnosticKind, code: impl AsRef<str>) -> Result<Self, DetectionError> {
        let code = bounded_text(code.as_ref(), MAX_DIAGNOSTIC_CODE_BYTES)?;
        if !code
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        {
            return Err(DetectionError::InvalidText);
        }
        Ok(Self { kind, code })
    }
    pub fn kind(&self) -> DiagnosticKind {
        self.kind
    }
    pub fn code(&self) -> &str {
        &self.code
    }
}

#[derive(Clone)]
pub struct FindingMetadata {
    finding_kind: FindingKind,
    category: String,
    severity: Severity,
    risk_points: Option<u8>,
    confidence: Option<Confidence>,
    confidence_score: Option<Score>,
    tags: Vec<String>,
    techniques: Vec<String>,
    evidence_refs: Vec<EvidenceRef>,
    correlation_scope: CorrelationScope,
    dedupe_key: Option<String>,
    session_id: Option<String>,
    semantic_identity: Option<String>,
}

impl fmt::Debug for FindingMetadata {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FindingMetadata")
            .field("finding_kind", &self.finding_kind)
            .field("category", &"[redacted]")
            .field("severity", &self.severity)
            .field("risk_points", &self.risk_points)
            .field("confidence", &self.confidence)
            .field("confidence_score", &self.confidence_score)
            .field("tag_count", &self.tags.len())
            .field("technique_count", &self.techniques.len())
            .field("evidence_ref_count", &self.evidence_refs.len())
            .field("correlation_scope", &self.correlation_scope)
            .field("dedupe_key_present", &self.dedupe_key.is_some())
            .field("session_id_present", &self.session_id.is_some())
            .field(
                "semantic_identity_present",
                &self.semantic_identity.is_some(),
            )
            .finish()
    }
}

impl FindingMetadata {
    pub fn new(
        finding_kind: FindingKind,
        category: impl AsRef<str>,
        severity: Severity,
    ) -> Result<Self, DetectionError> {
        Ok(Self {
            finding_kind,
            category: bounded_text(category.as_ref(), MAX_CATEGORY_BYTES)?,
            severity,
            risk_points: None,
            confidence: None,
            confidence_score: None,
            tags: Vec::new(),
            techniques: Vec::new(),
            evidence_refs: Vec::new(),
            correlation_scope: CorrelationScope::Observation,
            dedupe_key: None,
            session_id: None,
            semantic_identity: None,
        })
    }

    pub fn with_risk_points(mut self, value: u64) -> Result<Self, DetectionError> {
        if value > 100 {
            return Err(DetectionError::ScoreOutOfRange);
        }
        self.risk_points = Some(value as u8);
        Ok(self)
    }
    pub fn with_confidence(mut self, value: Confidence) -> Self {
        self.confidence = Some(value);
        self
    }
    pub fn with_confidence_score(mut self, value: Score) -> Self {
        self.confidence_score = Some(value);
        self
    }
    pub fn with_tags(
        mut self,
        values: impl IntoIterator<Item = impl AsRef<str>>,
    ) -> Result<Self, DetectionError> {
        self.tags = bounded_list(values, MAX_TAGS, MAX_ID_BYTES)?;
        Ok(self)
    }
    pub fn with_techniques(
        mut self,
        values: impl IntoIterator<Item = impl AsRef<str>>,
    ) -> Result<Self, DetectionError> {
        let values = bounded_list(values, MAX_TECHNIQUES, MAX_ID_BYTES)?;
        if values.iter().any(|value| {
            let valid_prefix = value
                .strip_prefix("attack:")
                .or_else(|| value.strip_prefix("atlas:"));
            valid_prefix.is_none_or(|suffix| {
                suffix.is_empty()
                    || !suffix.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')
                    })
            })
        }) {
            return Err(DetectionError::InvalidMetadata);
        }
        self.techniques = values;
        Ok(self)
    }
    pub fn with_evidence_refs(mut self, values: Vec<EvidenceRef>) -> Result<Self, DetectionError> {
        if values.len() > MAX_EVIDENCE_REFS {
            return Err(DetectionError::InvalidBounds);
        }
        self.evidence_refs = values;
        Ok(self)
    }
    pub fn with_correlation_scope(mut self, value: CorrelationScope) -> Self {
        self.correlation_scope = value;
        self
    }
    pub fn with_dedupe_key(mut self, value: impl AsRef<str>) -> Result<Self, DetectionError> {
        self.dedupe_key = Some(bounded_opaque(value.as_ref(), MAX_ID_BYTES)?);
        Ok(self)
    }
    pub fn with_session_id(mut self, value: impl AsRef<str>) -> Result<Self, DetectionError> {
        self.session_id = Some(bounded_opaque(value.as_ref(), MAX_ID_BYTES)?);
        Ok(self)
    }
    pub fn with_semantic_identity(
        mut self,
        value: impl AsRef<str>,
    ) -> Result<Self, DetectionError> {
        self.semantic_identity = Some(bounded_opaque(value.as_ref(), MAX_ID_BYTES)?);
        Ok(self)
    }
}

/// Experimental detector output; this is not a production scanner or Event
/// representation.
#[derive(Clone)]
pub struct DetectorResult {
    detector: DetectorIdentity,
    evaluation_status: EvaluationStatus,
    non_evaluation_reason: Option<NonEvaluationReason>,
    observation_ids: Vec<String>,
    finding_kind: FindingKind,
    category: String,
    severity: Severity,
    risk_points: Option<u8>,
    confidence: Option<Confidence>,
    confidence_score: Option<Score>,
    tags: Vec<String>,
    techniques: Vec<String>,
    evidence_refs: Vec<EvidenceRef>,
    capability_context: Option<CapabilityContext>,
    session_id: Option<String>,
    correlation_scope: CorrelationScope,
    dedupe_key: Option<String>,
    semantic_identity: Option<String>,
    match_surface: Option<String>,
    matched_selector_paths: Vec<String>,
    diagnostics: Option<Diagnostic>,
}

impl fmt::Debug for DetectorResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DetectorResult")
            .field("detector", &self.detector)
            .field("evaluation_status", &self.evaluation_status)
            .field("non_evaluation_reason", &self.non_evaluation_reason)
            .field("observation_id_count", &self.observation_ids.len())
            .field("finding_kind", &self.finding_kind)
            .field("category", &"[redacted]")
            .field("severity", &self.severity)
            .field("risk_points", &self.risk_points)
            .field("confidence", &self.confidence)
            .field("confidence_score", &self.confidence_score)
            .field("tag_count", &self.tags.len())
            .field("technique_count", &self.techniques.len())
            .field("evidence_ref_count", &self.evidence_refs.len())
            .field(
                "capability_context_present",
                &self.capability_context.is_some(),
            )
            .field("session_id_present", &self.session_id.is_some())
            .field("correlation_scope", &self.correlation_scope)
            .field("dedupe_key_present", &self.dedupe_key.is_some())
            .field(
                "semantic_identity_present",
                &self.semantic_identity.is_some(),
            )
            .field("match_surface", &self.match_surface)
            .field(
                "matched_selector_path_count",
                &self.matched_selector_paths.len(),
            )
            .field("diagnostics", &self.diagnostics)
            .finish()
    }
}

impl DetectorResult {
    pub fn new(
        detector: DetectorIdentity,
        evaluation_status: EvaluationStatus,
        metadata: FindingMetadata,
    ) -> Result<Self, DetectionError> {
        Self::from_parts(
            detector,
            evaluation_status,
            None,
            Vec::new(),
            metadata,
            None,
            Vec::new(),
            None,
        )
    }

    /// Construct an evaluated match only when it already has an observation
    /// identity. Other statuses may be constructed without observations, but a
    /// match cannot materialize a Signal without one.
    pub fn evaluated_match(
        detector: DetectorIdentity,
        observation_ids: &[ObservationId],
        metadata: FindingMetadata,
    ) -> Result<Self, DetectionError> {
        let observation_ids = normalize_observation_ids(observation_ids)?;
        if observation_ids.is_empty() {
            return Err(DetectionError::MissingObservationId);
        }
        Self::from_parts(
            detector,
            EvaluationStatus::EvaluatedMatch,
            None,
            observation_ids,
            metadata,
            None,
            Vec::new(),
            None,
        )
    }

    pub fn not_evaluated(
        detector: DetectorIdentity,
        reason: NonEvaluationReason,
        metadata: FindingMetadata,
    ) -> Result<Self, DetectionError> {
        Self::from_parts(
            detector,
            EvaluationStatus::NotEvaluated,
            Some(reason),
            Vec::new(),
            metadata,
            None,
            Vec::new(),
            None,
        )
    }

    pub fn with_observation_ids(
        mut self,
        values: &[ObservationId],
    ) -> Result<Self, DetectionError> {
        let observation_ids = normalize_observation_ids(values)?;
        if self.evaluation_status == EvaluationStatus::EvaluatedMatch && observation_ids.is_empty()
        {
            return Err(DetectionError::MissingObservationId);
        }
        self.observation_ids = observation_ids;
        Ok(self)
    }

    pub fn with_matched_selector_paths(
        mut self,
        values: Vec<String>,
    ) -> Result<Self, DetectionError> {
        for value in &values {
            SelectorId::parse(value)?;
        }
        self.matched_selector_paths = normalize_paths(&values)?;
        if self.evaluation_status != EvaluationStatus::EvaluatedMatch
            && !self.matched_selector_paths.is_empty()
        {
            return Err(DetectionError::InvalidStatus);
        }
        Ok(self)
    }

    pub fn with_match_surface(mut self, value: impl AsRef<str>) -> Result<Self, DetectionError> {
        let value = value.as_ref();
        if !matches!(value, "text" | "structured") {
            return Err(DetectionError::InvalidMetadata);
        }
        self.match_surface = Some(value.to_owned());
        Ok(self)
    }

    pub fn with_capability_context(mut self, value: CapabilityContext) -> Self {
        self.capability_context = Some(value);
        self
    }

    pub fn with_diagnostic(mut self, value: Diagnostic) -> Result<Self, DetectionError> {
        if self.evaluation_status != EvaluationStatus::DetectorError {
            return Err(DetectionError::InvalidStatus);
        }
        self.diagnostics = Some(value);
        Ok(self)
    }

    pub fn detector_error(
        detector: DetectorIdentity,
        metadata: FindingMetadata,
        diagnostic: Diagnostic,
    ) -> Result<Self, DetectionError> {
        Self::from_parts(
            detector,
            EvaluationStatus::DetectorError,
            None,
            Vec::new(),
            metadata,
            None,
            Vec::new(),
            Some(diagnostic),
        )
    }

    pub fn unsupported(
        detector: DetectorIdentity,
        metadata: FindingMetadata,
    ) -> Result<Self, DetectionError> {
        let diagnostic = Diagnostic::new(
            DiagnosticKind::MalformedContentOrPackage,
            "unsupported_detector_kind",
        )?;
        Self::detector_error(detector, metadata, diagnostic)
    }

    pub fn evaluation_status(&self) -> EvaluationStatus {
        self.evaluation_status
    }
    pub fn non_evaluation_reason(&self) -> Option<NonEvaluationReason> {
        self.non_evaluation_reason
    }
    pub fn detector(&self) -> &DetectorIdentity {
        &self.detector
    }
    pub fn observation_ids(&self) -> &[String] {
        &self.observation_ids
    }
    pub fn finding_kind(&self) -> FindingKind {
        self.finding_kind
    }
    pub fn category(&self) -> &str {
        &self.category
    }
    pub fn severity(&self) -> Severity {
        self.severity
    }
    pub fn risk_points(&self) -> Option<u8> {
        self.risk_points
    }
    pub fn confidence(&self) -> Option<Confidence> {
        self.confidence
    }
    pub fn confidence_score(&self) -> Option<Score> {
        self.confidence_score
    }
    pub fn tags(&self) -> &[String] {
        &self.tags
    }
    pub fn techniques(&self) -> &[String] {
        &self.techniques
    }
    pub fn evidence_refs(&self) -> &[EvidenceRef] {
        &self.evidence_refs
    }
    pub fn capability_context(&self) -> Option<&CapabilityContext> {
        self.capability_context.as_ref()
    }
    pub fn session_id(&self) -> Option<&str> {
        self.session_id.as_deref()
    }
    pub fn match_surface(&self) -> Option<&str> {
        self.match_surface.as_deref()
    }
    pub fn correlation_scope(&self) -> CorrelationScope {
        self.correlation_scope
    }
    pub fn dedupe_key(&self) -> Option<&str> {
        self.dedupe_key.as_deref()
    }
    pub fn semantic_identity(&self) -> Option<&str> {
        self.semantic_identity.as_deref()
    }
    pub fn matched_selector_paths(&self) -> &[String] {
        &self.matched_selector_paths
    }
    pub fn diagnostics(&self) -> Option<&Diagnostic> {
        self.diagnostics.as_ref()
    }

    pub fn signal(&self) -> Result<Option<Signal>, DetectionError> {
        if self.evaluation_status != EvaluationStatus::EvaluatedMatch {
            return Ok(None);
        }
        Ok(Some(Signal::from_result(self)?))
    }

    pub fn finding(&self) -> Result<Option<Finding>, DetectionError> {
        self.signal()?
            .map(|signal| Finding::from_signal(&signal))
            .transpose()
    }

    pub(crate) fn evaluated(
        detector: DetectorIdentity,
        status: EvaluationStatus,
        reason: Option<NonEvaluationReason>,
        observation: Option<&CanonicalObservationV2>,
        mut metadata: FindingMetadata,
        capability_context: Option<CapabilityContext>,
        matched_selector_paths: Vec<String>,
    ) -> Result<Self, DetectionError> {
        let observation_ids = match observation {
            Some(value) => vec![validated_observation_id(value.observation_id())?],
            None => Vec::new(),
        };
        if metadata.session_id.is_none() {
            metadata.session_id = observation
                .and_then(|value| value.session_id())
                .map(|value| value.value().to_owned());
        }
        Self::from_parts(
            detector,
            status,
            reason,
            observation_ids,
            metadata,
            capability_context,
            matched_selector_paths,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn from_parts(
        detector: DetectorIdentity,
        status: EvaluationStatus,
        reason: Option<NonEvaluationReason>,
        observation_ids: Vec<String>,
        metadata: FindingMetadata,
        capability_context: Option<CapabilityContext>,
        matched_selector_paths: Vec<String>,
        diagnostics: Option<Diagnostic>,
    ) -> Result<Self, DetectionError> {
        if (status == EvaluationStatus::NotEvaluated) != reason.is_some() {
            return Err(DetectionError::InvalidStatus);
        }
        if status == EvaluationStatus::EvaluatedMatch && observation_ids.is_empty() {
            return Err(DetectionError::MissingObservationId);
        }
        if !detector.kind().runtime_supported()
            && matches!(
                status,
                EvaluationStatus::EvaluatedMatch | EvaluationStatus::EvaluatedNoMatch
            )
        {
            return Err(DetectionError::UnsupportedDetectorKind);
        }
        if status != EvaluationStatus::DetectorError && diagnostics.is_some() {
            return Err(DetectionError::InvalidStatus);
        }
        if (status == EvaluationStatus::DetectorError) != diagnostics.is_some() {
            return Err(DetectionError::InvalidStatus);
        }
        let matched_selector_paths = normalize_paths(&matched_selector_paths)?;
        if status != EvaluationStatus::EvaluatedMatch && !matched_selector_paths.is_empty() {
            return Err(DetectionError::InvalidStatus);
        }
        Ok(Self {
            detector,
            evaluation_status: status,
            non_evaluation_reason: reason,
            observation_ids: normalize_string_ids(observation_ids)?,
            finding_kind: metadata.finding_kind,
            category: metadata.category,
            severity: metadata.severity,
            risk_points: metadata.risk_points,
            confidence: metadata.confidence,
            confidence_score: metadata.confidence_score,
            tags: metadata.tags,
            techniques: metadata.techniques,
            evidence_refs: metadata.evidence_refs,
            capability_context,
            session_id: metadata.session_id,
            correlation_scope: metadata.correlation_scope,
            dedupe_key: metadata.dedupe_key,
            semantic_identity: metadata.semantic_identity,
            match_surface: None,
            matched_selector_paths,
            diagnostics,
        })
    }
}

/// Experimental materialization of an evaluated Detection v2 result.
///
/// Its ID hashes `["telltale:detection-v2-signal", 2, kind, id,
/// version|null, engine|null, content_ref|null, rule_version|null,
/// match_surface|null, sorted_ids, token|null, status, selector_digest]`.
#[derive(Clone)]
pub struct Signal {
    signal_id: String,
    detector: DetectorIdentity,
    evaluation_status: EvaluationStatus,
    observation_ids: Vec<String>,
    session_id: Option<String>,
    finding_kind: FindingKind,
    category: String,
    severity: Severity,
    risk_points: Option<u8>,
    confidence: Option<Confidence>,
    confidence_score: Option<Score>,
    evidence_refs: Vec<EvidenceRef>,
    tags: Vec<String>,
    techniques: Vec<String>,
    dedupe_key: Option<String>,
    correlation_scope: CorrelationScope,
    match_surface: Option<String>,
    selector_digest: String,
    suppression_status: SuppressionStatus,
    deduplication_status: DeduplicationStatus,
}

impl fmt::Debug for Signal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Signal")
            .field("signal_id", &self.signal_id)
            .field("detector", &self.detector)
            .field("evaluation_status", &self.evaluation_status)
            .field("observation_id_count", &self.observation_ids.len())
            .field("finding_kind", &self.finding_kind)
            .field("category", &"[redacted]")
            .field("severity", &self.severity)
            .field("risk_points", &self.risk_points)
            .field("confidence", &self.confidence)
            .field("confidence_score", &self.confidence_score)
            .field("evidence_ref_count", &self.evidence_refs.len())
            .field("tag_count", &self.tags.len())
            .field("technique_count", &self.techniques.len())
            .field("dedupe_key_present", &self.dedupe_key.is_some())
            .field("correlation_scope", &self.correlation_scope)
            .field("match_surface", &self.match_surface)
            .field("selector_digest", &self.selector_digest)
            .field("suppression_status", &self.suppression_status)
            .field("deduplication_status", &self.deduplication_status)
            .finish()
    }
}

impl Signal {
    fn from_result(result: &DetectorResult) -> Result<Self, DetectionError> {
        if result.observation_ids.is_empty() {
            return Err(DetectionError::MissingObservationId);
        }
        let selector_digest = selector_path_digest(&result.matched_selector_paths)?;
        let tuple = signal_identity_tuple_for_digest(result, &selector_digest)?;
        let digest = Sha256::digest(
            canonical_identity_json(&tuple).map_err(|_| DetectionError::RuntimeEvaluation)?,
        );
        Ok(Self {
            signal_id: format!("{SIGNAL_ID_PREFIX}{digest:x}"),
            detector: result.detector.clone(),
            evaluation_status: result.evaluation_status,
            observation_ids: result.observation_ids.clone(),
            session_id: result.session_id.clone(),
            finding_kind: result.finding_kind,
            category: result.category.clone(),
            severity: result.severity,
            risk_points: result.risk_points,
            confidence: result.confidence,
            confidence_score: result.confidence_score,
            evidence_refs: result.evidence_refs.clone(),
            tags: result.tags.clone(),
            techniques: result.techniques.clone(),
            dedupe_key: result.dedupe_key.clone(),
            correlation_scope: result.correlation_scope,
            match_surface: result.match_surface.clone(),
            selector_digest,
            suppression_status: SuppressionStatus::NotSuppressed,
            deduplication_status: result
                .dedupe_key
                .as_ref()
                .map_or(DeduplicationStatus::NotConfigured, |_| {
                    DeduplicationStatus::Unique
                }),
        })
    }

    pub fn signal_id(&self) -> &str {
        &self.signal_id
    }
    pub fn detector(&self) -> &DetectorIdentity {
        &self.detector
    }
    pub fn evaluation_status(&self) -> EvaluationStatus {
        self.evaluation_status
    }
    pub fn observation_ids(&self) -> &[String] {
        &self.observation_ids
    }
    pub fn session_id(&self) -> Option<&str> {
        self.session_id.as_deref()
    }
    pub fn finding_kind(&self) -> FindingKind {
        self.finding_kind
    }
    pub fn category(&self) -> &str {
        &self.category
    }
    pub fn severity(&self) -> Severity {
        self.severity
    }
    pub fn risk_points(&self) -> Option<u8> {
        self.risk_points
    }
    pub fn confidence(&self) -> Option<Confidence> {
        self.confidence
    }
    pub fn confidence_score(&self) -> Option<Score> {
        self.confidence_score
    }
    pub fn evidence_refs(&self) -> &[EvidenceRef] {
        &self.evidence_refs
    }
    pub fn tags(&self) -> &[String] {
        &self.tags
    }
    pub fn techniques(&self) -> &[String] {
        &self.techniques
    }
    pub fn dedupe_key(&self) -> Option<&str> {
        self.dedupe_key.as_deref()
    }
    pub fn match_surface(&self) -> Option<&str> {
        self.match_surface.as_deref()
    }
    pub fn correlation_scope(&self) -> CorrelationScope {
        self.correlation_scope
    }
    pub fn selector_digest(&self) -> &str {
        &self.selector_digest
    }
    pub fn suppression_status(&self) -> SuppressionStatus {
        self.suppression_status
    }
    pub fn deduplication_status(&self) -> DeduplicationStatus {
        self.deduplication_status
    }

    pub fn finding(&self) -> Result<Finding, DetectionError> {
        Finding::from_signal(self)
    }
}

/// Build the internal Detection v2 Signal identity tuple for tests and review.
///
/// Its fixed shape is `[domain, 2, kind, id, version|null, engine|null,
/// content_ref|null, rule_version|null, match_surface|null, sorted_ids,
/// token|null, status, selector_path_digest]`. `match_surface` is a separate
/// semantic-context member, not part of the detector identity fields. The
/// returned tuple is hashed before becoming the public Signal ID.
#[cfg(test)]
pub(crate) fn signal_identity_tuple(result: &DetectorResult) -> Result<JsonValue, DetectionError> {
    let selector_digest = selector_path_digest(&result.matched_selector_paths)?;
    signal_identity_tuple_for_digest(result, &selector_digest)
}

fn signal_identity_tuple_for_digest(
    result: &DetectorResult,
    selector_digest: &str,
) -> Result<JsonValue, DetectionError> {
    let observation_ids = normalize_string_ids(result.observation_ids.clone())?;
    let token = result
        .semantic_identity
        .as_deref()
        .or(result.dedupe_key.as_deref())
        .map(JsonValue::string)
        .unwrap_or(JsonValue::Null);
    Ok(JsonValue::Array(vec![
        JsonValue::string("telltale:detection-v2-signal"),
        JsonValue::Unsigned(2),
        JsonValue::string(result.detector.kind().as_str()),
        JsonValue::string(result.detector.id()),
        result
            .detector
            .version()
            .map(JsonValue::string)
            .unwrap_or(JsonValue::Null),
        result
            .detector
            .engine()
            .map(JsonValue::string)
            .unwrap_or(JsonValue::Null),
        result
            .detector
            .content_ref()
            .map(JsonValue::string)
            .unwrap_or(JsonValue::Null),
        result
            .detector
            .rule_version()
            .map(|value| JsonValue::Unsigned(value as u64))
            .unwrap_or(JsonValue::Null),
        result
            .match_surface
            .as_deref()
            .map(JsonValue::string)
            .unwrap_or(JsonValue::Null),
        JsonValue::Array(observation_ids.iter().map(JsonValue::string).collect()),
        token,
        JsonValue::string(result.evaluation_status.as_str()),
        JsonValue::string(selector_digest),
    ]))
}

/// Experimental atomic Finding materialized from one Detection v2 Signal.
#[derive(Clone)]
pub struct Finding {
    finding_id: String,
    signal_ids: Vec<String>,
    observation_ids: Vec<String>,
    detectors: Vec<DetectorIdentity>,
    finding_kind: FindingKind,
    category: String,
    severity: Severity,
    confidence: Option<Confidence>,
    confidence_score: Option<Score>,
    risk_points: Option<u8>,
    evidence_refs: Vec<EvidenceRef>,
    correlation_scope: CorrelationScope,
    deduplication_status: DeduplicationStatus,
    suppression_status: SuppressionStatus,
}

impl fmt::Debug for Finding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Finding")
            .field("finding_id", &self.finding_id)
            .field("signal_id_count", &self.signal_ids.len())
            .field("observation_id_count", &self.observation_ids.len())
            .field("detector_count", &self.detectors.len())
            .field("finding_kind", &self.finding_kind)
            .field("category", &"[redacted]")
            .field("severity", &self.severity)
            .field("confidence", &self.confidence)
            .field("confidence_score", &self.confidence_score)
            .field("risk_points", &self.risk_points)
            .field("evidence_ref_count", &self.evidence_refs.len())
            .field("correlation_scope", &self.correlation_scope)
            .field("deduplication_status", &self.deduplication_status)
            .field("suppression_status", &self.suppression_status)
            .finish()
    }
}

impl Finding {
    fn from_signal(signal: &Signal) -> Result<Self, DetectionError> {
        let tuple = JsonValue::Array(vec![
            JsonValue::string("telltale:detection-v2-finding"),
            JsonValue::Unsigned(1),
            JsonValue::string("atomic"),
            JsonValue::string(&signal.signal_id),
        ]);
        let digest = Sha256::digest(
            canonical_identity_json(&tuple).map_err(|_| DetectionError::RuntimeEvaluation)?,
        );
        Ok(Self {
            finding_id: format!("{FINDING_ID_PREFIX}{digest:x}"),
            signal_ids: vec![signal.signal_id.clone()],
            observation_ids: signal.observation_ids.clone(),
            detectors: vec![signal.detector.clone()],
            finding_kind: signal.finding_kind,
            category: signal.category.clone(),
            severity: signal.severity,
            confidence: signal.confidence,
            confidence_score: signal.confidence_score,
            risk_points: signal.risk_points,
            evidence_refs: signal.evidence_refs.clone(),
            correlation_scope: signal.correlation_scope,
            deduplication_status: signal.deduplication_status,
            suppression_status: signal.suppression_status,
        })
    }

    pub fn finding_id(&self) -> &str {
        &self.finding_id
    }
    pub fn signal_ids(&self) -> &[String] {
        &self.signal_ids
    }
    pub fn observation_ids(&self) -> &[String] {
        &self.observation_ids
    }
    pub fn detectors(&self) -> &[DetectorIdentity] {
        &self.detectors
    }
    pub fn finding_kind(&self) -> FindingKind {
        self.finding_kind
    }
    pub fn category(&self) -> &str {
        &self.category
    }
    pub fn severity(&self) -> Severity {
        self.severity
    }
    pub fn confidence(&self) -> Option<Confidence> {
        self.confidence
    }
    pub fn confidence_score(&self) -> Option<Score> {
        self.confidence_score
    }
    pub fn risk_points(&self) -> Option<u8> {
        self.risk_points
    }
    pub fn evidence_refs(&self) -> &[EvidenceRef] {
        &self.evidence_refs
    }
    pub fn correlation_scope(&self) -> CorrelationScope {
        self.correlation_scope
    }
    pub fn deduplication_status(&self) -> DeduplicationStatus {
        self.deduplication_status
    }
    pub fn suppression_status(&self) -> SuppressionStatus {
        self.suppression_status
    }
}

pub(crate) fn bounded_text(value: &str, max: usize) -> Result<String, DetectionError> {
    if value.is_empty()
        || value.len() > max
        || value.chars().any(|character| character.is_control())
    {
        return Err(DetectionError::InvalidText);
    }
    Ok(value.to_owned())
}

pub(crate) fn bounded_identifier(value: &str) -> Result<String, DetectionError> {
    let value = bounded_text(value, MAX_ID_BYTES)?;
    if !value.bytes().all(|byte| {
        byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
    }) {
        return Err(DetectionError::InvalidId);
    }
    Ok(value)
}

pub(crate) fn bounded_opaque(value: &str, max: usize) -> Result<String, DetectionError> {
    let value = bounded_text(value, max)?;
    if value.contains('/')
        || value.contains('\\')
        || value.contains("..")
        || value.chars().any(char::is_whitespace)
    {
        return Err(DetectionError::InvalidText);
    }
    Ok(value)
}

fn bounded_list(
    values: impl IntoIterator<Item = impl AsRef<str>>,
    max_items: usize,
    max_bytes: usize,
) -> Result<Vec<String>, DetectionError> {
    let mut values = values
        .into_iter()
        .map(|value| bounded_text(value.as_ref(), max_bytes))
        .collect::<Result<Vec<_>, _>>()?;
    if values.len() > max_items {
        return Err(DetectionError::InvalidBounds);
    }
    values.sort();
    values.dedup();
    Ok(values)
}

fn validated_observation_id(value: &str) -> Result<String, DetectionError> {
    if valid_observation_id(value) {
        Ok(value.to_owned())
    } else {
        Err(DetectionError::InvalidId)
    }
}

fn normalize_observation_ids(values: &[ObservationId]) -> Result<Vec<String>, DetectionError> {
    values
        .iter()
        .map(|value| validated_observation_id(value.as_str()))
        .collect::<Result<Vec<_>, _>>()
        .and_then(normalize_string_ids)
}

fn normalize_string_ids(mut values: Vec<String>) -> Result<Vec<String>, DetectionError> {
    if values.len() > MAX_OBSERVATION_IDS {
        return Err(DetectionError::InvalidBounds);
    }
    values.sort();
    values.dedup();
    Ok(values)
}

pub(crate) fn normalize_paths(values: &[String]) -> Result<Vec<String>, DetectionError> {
    let mut paths = values
        .iter()
        .map(|value| bounded_text(value, MAX_ID_BYTES))
        .collect::<Result<Vec<_>, _>>()?;
    if paths.len() > MAX_SELECTOR_PATHS {
        return Err(DetectionError::InvalidBounds);
    }
    paths.sort();
    paths.dedup();
    Ok(paths)
}

pub(crate) fn selector_path_digest(paths: &[String]) -> Result<String, DetectionError> {
    let paths = normalize_paths(paths)?;
    let value = JsonValue::Array(paths.iter().map(JsonValue::string).collect());
    let bytes = canonical_identity_json(&value).map_err(|_| DetectionError::RuntimeEvaluation)?;
    let digest = Sha256::digest(bytes);
    Ok(format!("{digest:x}"))
}

pub(crate) fn metadata_for_path(
    observation: &CanonicalObservationV2,
    path: &str,
) -> Result<Option<telltale_schema::observation::FactMetadata>, DetectionError> {
    observation
        .fact_metadata()
        .get(path)
        .cloned()
        .map(Some)
        .ok_or(DetectionError::InvalidMetadata)
}
