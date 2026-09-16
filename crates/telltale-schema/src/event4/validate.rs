use std::collections::BTreeMap;
use std::fmt;
use std::sync::LazyLock;

use jsonschema::{Draft, Validator};
use regex::Regex;
use serde_json::Value;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use super::*;
use crate::observation::valid_observation_id;

pub const EVENT4_SCHEMA: &str = include_str!("../../data/event-4.0.schema.json");
pub const EVENT4_SERIALIZER_ID: &str = "event4-json-v1";
pub const EVENT4_MAX_BYTES: usize = 65_536;
pub const EVENT4_MAX_DEPTH: usize = 8;
pub const EXTENSIONS_MAX_BYTES: usize = 16_384;
pub const EXTENSIONS_MAX_SCALARS: usize = 512;

static EVENT4_VALIDATOR: LazyLock<Result<Validator, ()>> = LazyLock::new(|| {
    let schema: Value = serde_json::from_str(EVENT4_SCHEMA).map_err(|_| ())?;
    jsonschema::options()
        .with_draft(Draft::Draft202012)
        .should_validate_formats(true)
        .build(&schema)
        .map_err(|_| ())
});

static OPAQUE_REFERENCE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$").expect("constant Event4 identifier regex")
});

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event4ErrorCategory {
    Version,
    Structure,
    Identity,
    Time,
    Semantic,
    Reference,
    Extension,
    Resource,
    Encoding,
    Context,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event4ValidationCode {
    SchemaUnavailable,
    InvalidVersion,
    InvalidStructure,
    InvalidIdentity,
    IdentityNotDistinct,
    InvalidObservationId,
    InvalidTimestamp,
    MaterializationBeforeObservation,
    TypeBodyMismatch,
    ActionTypeMismatch,
    ActionSemanticMismatch,
    SessionIdentityMismatch,
    InvalidOutcomeRelationship,
    InvalidDegradation,
    InvalidApproval,
    InvalidEvidence,
    InvalidExtension,
    DuplicateNormalizedKey,
    NonFiniteNumber,
    EventTooLarge,
    ExtensionTooLarge,
    ExtensionScalarLimit,
    DepthLimit,
    MissingReference,
    ReferenceTypeMismatch,
    RequestedOutcomeMismatch,
    ApprovalTransition,
    ApprovalActionMismatch,
    IdentityCollision,
    ContextConflict,
    EncodingFailed,
}

impl Event4ValidationCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SchemaUnavailable => "schema_unavailable",
            Self::InvalidVersion => "invalid_version",
            Self::InvalidStructure => "invalid_structure",
            Self::InvalidIdentity => "invalid_identity",
            Self::IdentityNotDistinct => "identity_not_distinct",
            Self::InvalidObservationId => "invalid_observation_id",
            Self::InvalidTimestamp => "invalid_timestamp",
            Self::MaterializationBeforeObservation => "materialization_before_observation",
            Self::TypeBodyMismatch => "type_body_mismatch",
            Self::ActionTypeMismatch => "action_type_mismatch",
            Self::ActionSemanticMismatch => "action_semantic_mismatch",
            Self::SessionIdentityMismatch => "session_identity_mismatch",
            Self::InvalidOutcomeRelationship => "invalid_outcome_relationship",
            Self::InvalidDegradation => "invalid_degradation",
            Self::InvalidApproval => "invalid_approval",
            Self::InvalidEvidence => "invalid_evidence",
            Self::InvalidExtension => "invalid_extension",
            Self::DuplicateNormalizedKey => "duplicate_normalized_key",
            Self::NonFiniteNumber => "non_finite_number",
            Self::EventTooLarge => "event_too_large",
            Self::ExtensionTooLarge => "extension_too_large",
            Self::ExtensionScalarLimit => "extension_scalar_limit",
            Self::DepthLimit => "depth_limit",
            Self::MissingReference => "missing_reference",
            Self::ReferenceTypeMismatch => "reference_type_mismatch",
            Self::RequestedOutcomeMismatch => "requested_outcome_mismatch",
            Self::ApprovalTransition => "approval_transition",
            Self::ApprovalActionMismatch => "approval_action_mismatch",
            Self::IdentityCollision => "identity_collision",
            Self::ContextConflict => "context_conflict",
            Self::EncodingFailed => "encoding_failed",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Event4ValidationError {
    category: Event4ErrorCategory,
    code: Event4ValidationCode,
}

impl Event4ValidationError {
    const fn new(category: Event4ErrorCategory, code: Event4ValidationCode) -> Self {
        Self { category, code }
    }

    pub const fn category(self) -> Event4ErrorCategory {
        self.category
    }
    pub const fn code(self) -> Event4ValidationCode {
        self.code
    }
}

impl fmt::Display for Event4ValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "event4 validation error: {}", self.code.as_str())
    }
}

impl std::error::Error for Event4ValidationError {}

fn error(category: Event4ErrorCategory, code: Event4ValidationCode) -> Event4ValidationError {
    Event4ValidationError::new(category, code)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcceptanceDisposition {
    New,
    Idempotent,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event4DecisionFact {
    requested: Outcome,
    approval_id: Option<String>,
    approval_state: Option<ApprovalState>,
}

impl Event4DecisionFact {
    /// Reconstructs minimal facts from previously accepted durable state.
    pub fn restored(
        requested: Outcome,
        approval_id: Option<String>,
        approval_state: Option<ApprovalState>,
    ) -> Self {
        Self {
            requested,
            approval_id,
            approval_state,
        }
    }

    pub fn requested(&self) -> Outcome {
        self.requested
    }
    pub fn approval_id(&self) -> Option<&str> {
        self.approval_id.as_deref()
    }
    pub fn approval_state(&self) -> Option<ApprovalState> {
        self.approval_state
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event4AcceptedFact {
    content_hash: [u8; 32],
    event_type: EventType,
    decision: Option<Event4DecisionFact>,
}

impl Event4AcceptedFact {
    /// Reconstructs minimal facts from previously accepted durable state.
    pub fn restored(
        content_hash: [u8; 32],
        event_type: EventType,
        decision: Option<Event4DecisionFact>,
    ) -> Self {
        Self {
            content_hash,
            event_type,
            decision,
        }
    }

    pub fn content_hash(&self) -> &[u8; 32] {
        &self.content_hash
    }
    pub fn event_type(&self) -> EventType {
        self.event_type
    }
    pub fn decision(&self) -> Option<&Event4DecisionFact> {
        self.decision.as_ref()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event4ApprovalFact {
    state: ApprovalState,
    decision_event_id: String,
}

impl Event4ApprovalFact {
    /// Reconstructs minimal facts from previously accepted durable state.
    pub fn restored(state: ApprovalState, decision_event_id: String) -> Self {
        Self {
            state,
            decision_event_id,
        }
    }

    pub fn state(&self) -> ApprovalState {
        self.state
    }

    pub fn decision_event_id(&self) -> &str {
        &self.decision_event_id
    }
}

/// Minimal read-only facts needed by contextual Event4 validation.
pub trait Event4Context {
    fn event(&self, event_id: &str) -> Option<Event4AcceptedFact>;
    fn approval(&self, approval_id: &str) -> Option<(ApprovalState, String)>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event4AcceptanceEffect {
    event_id: String,
    event: Event4AcceptedFact,
    approval: Option<(String, Event4ApprovalFact)>,
    disposition: AcceptanceDisposition,
}

impl Event4AcceptanceEffect {
    pub fn event_id(&self) -> &str {
        &self.event_id
    }
    pub fn event(&self) -> &Event4AcceptedFact {
        &self.event
    }
    pub fn disposition(&self) -> AcceptanceDisposition {
        self.disposition
    }

    pub fn approval_update(&self) -> Option<(&str, &Event4ApprovalFact)> {
        self.approval
            .as_ref()
            .map(|(approval_id, fact)| (approval_id.as_str(), fact))
    }
}

#[derive(Default, Clone)]
pub struct Event4InMemoryContext {
    events: BTreeMap<String, Event4AcceptedFact>,
    approvals: BTreeMap<String, Event4ApprovalFact>,
}

impl fmt::Debug for Event4InMemoryContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Event4InMemoryContext")
            .field("event_count", &self.events.len())
            .field("approval_count", &self.approvals.len())
            .finish()
    }
}

impl Event4InMemoryContext {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn apply(&mut self, effect: &Event4AcceptanceEffect) -> Result<(), Event4ValidationError> {
        if let Some(existing) = self.events.get(&effect.event_id) {
            if existing.content_hash != effect.event.content_hash {
                return Err(error(
                    Event4ErrorCategory::Context,
                    Event4ValidationCode::ContextConflict,
                ));
            }
            return Ok(());
        }
        if effect.disposition == AcceptanceDisposition::Idempotent {
            return Err(error(
                Event4ErrorCategory::Context,
                Event4ValidationCode::ContextConflict,
            ));
        }
        if let Some((approval_id, fact)) = &effect.approval {
            let transition_is_valid = match fact.state {
                ApprovalState::Requested => !self.approvals.contains_key(approval_id),
                ApprovalState::Granted
                | ApprovalState::Denied
                | ApprovalState::Expired
                | ApprovalState::Cancelled => self
                    .approvals
                    .get(approval_id)
                    .is_some_and(|current| current.state == ApprovalState::Requested),
                ApprovalState::Required => false,
            };
            if !transition_is_valid {
                return Err(error(
                    Event4ErrorCategory::Context,
                    Event4ValidationCode::ContextConflict,
                ));
            }
        }
        self.events
            .insert(effect.event_id.clone(), effect.event.clone());
        if let Some((approval_id, fact)) = &effect.approval {
            self.approvals.insert(approval_id.clone(), fact.clone());
        }
        Ok(())
    }
}

impl Event4Context for Event4InMemoryContext {
    fn event(&self, event_id: &str) -> Option<Event4AcceptedFact> {
        self.events.get(event_id).cloned()
    }

    fn approval(&self, approval_id: &str) -> Option<(ApprovalState, String)> {
        self.approvals
            .get(approval_id)
            .map(|fact| (fact.state, fact.decision_event_id.clone()))
    }
}

pub struct AcceptedEvent4 {
    event_id: String,
    canonical_bytes: Vec<u8>,
    content_hash: [u8; 32],
    effect: Event4AcceptanceEffect,
}

impl fmt::Debug for AcceptedEvent4 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AcceptedEvent4")
            .field("event_id", &"[redacted]")
            .field("canonical_byte_len", &self.canonical_bytes.len())
            .field("serializer", &EVENT4_SERIALIZER_ID)
            .finish()
    }
}

impl AcceptedEvent4 {
    pub fn event_id(&self) -> &str {
        &self.event_id
    }
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }
    pub fn content_hash(&self) -> &[u8; 32] {
        &self.content_hash
    }
    pub fn serializer_id(&self) -> &'static str {
        EVENT4_SERIALIZER_ID
    }
    pub fn effect(&self) -> &Event4AcceptanceEffect {
        &self.effect
    }
    pub fn disposition(&self) -> AcceptanceDisposition {
        self.effect.disposition
    }
}

/// Runs only the pinned structural schema and format checks against a JSON value.
/// Diagnostics from `jsonschema` are deliberately discarded.
pub fn validate_event4_structure(value: &Value) -> Result<(), Event4ValidationError> {
    let Some(version) = value
        .as_object()
        .and_then(|object| object.get("schema_version"))
    else {
        return Err(error(
            Event4ErrorCategory::Version,
            Event4ValidationCode::InvalidVersion,
        ));
    };
    if version != EVENT4_SCHEMA_VERSION {
        return Err(error(
            Event4ErrorCategory::Version,
            Event4ValidationCode::InvalidVersion,
        ));
    }
    let validator = EVENT4_VALIDATOR.as_ref().map_err(|_| {
        error(
            Event4ErrorCategory::Structure,
            Event4ValidationCode::SchemaUnavailable,
        )
    })?;
    if !validator.is_valid(value) {
        return Err(error(
            Event4ErrorCategory::Structure,
            Event4ValidationCode::InvalidStructure,
        ));
    }
    Ok(())
}

/// Validates and canonically encodes a post-privacy, once-materialized Event4
/// candidate. The returned effect is not applied to context by this function.
pub fn validate_terminal(
    event: &MaterializedEvent4,
    context: &impl Event4Context,
) -> Result<AcceptedEvent4, Event4ValidationError> {
    let value = serde_json::to_value(event).map_err(|_| {
        error(
            Event4ErrorCategory::Encoding,
            Event4ValidationCode::DuplicateNormalizedKey,
        )
    })?;
    validate_event4_structure(&value)?;
    validate_local(event)?;

    let canonical_bytes = serde_json::to_vec(event).map_err(|_| {
        error(
            Event4ErrorCategory::Encoding,
            Event4ValidationCode::EncodingFailed,
        )
    })?;
    if canonical_bytes.len() > EVENT4_MAX_BYTES {
        return Err(error(
            Event4ErrorCategory::Resource,
            Event4ValidationCode::EventTooLarge,
        ));
    }
    if container_depth(&value, 1) > EVENT4_MAX_DEPTH {
        return Err(error(
            Event4ErrorCategory::Resource,
            Event4ValidationCode::DepthLimit,
        ));
    }

    let content_hash: [u8; 32] = Sha256::digest(&canonical_bytes).into();
    let effect = validate_context(event, content_hash, context)?;
    Ok(AcceptedEvent4 {
        event_id: event.event_id().to_owned(),
        canonical_bytes,
        content_hash,
        effect,
    })
}

fn validate_local(event: &MaterializedEvent4) -> Result<(), Event4ValidationError> {
    let candidate = event.candidate();
    if candidate.schema_version != EVENT4_SCHEMA_VERSION {
        return Err(error(
            Event4ErrorCategory::Version,
            Event4ValidationCode::InvalidVersion,
        ));
    }
    if !valid_opaque_reference(&candidate.event_id) {
        return Err(error(
            Event4ErrorCategory::Identity,
            Event4ValidationCode::InvalidIdentity,
        ));
    }
    if valid_observation_id(&candidate.event_id) {
        return Err(error(
            Event4ErrorCategory::Identity,
            Event4ValidationCode::IdentityNotDistinct,
        ));
    }
    if candidate.event_type != candidate.body.event_type() {
        return Err(error(
            Event4ErrorCategory::Semantic,
            Event4ValidationCode::TypeBodyMismatch,
        ));
    }
    if candidate.event_action.event_type() != candidate.event_type {
        return Err(error(
            Event4ErrorCategory::Semantic,
            Event4ValidationCode::ActionTypeMismatch,
        ));
    }

    let observed = parse_time(&candidate.observed_at)?;
    let materialized = parse_time(event.materialized_at())?;
    if let Some(occurred) = &candidate.occurred_at {
        parse_time(occurred)?;
    }
    if materialized < observed {
        return Err(error(
            Event4ErrorCategory::Time,
            Event4ValidationCode::MaterializationBeforeObservation,
        ));
    }

    validate_body(candidate)?;
    validate_finite(candidate)?;
    validate_extensions(candidate.extensions.as_ref())?;
    Ok(())
}

fn validate_body(candidate: &Event4Candidate) -> Result<(), Event4ValidationError> {
    match &candidate.body {
        EventBody::Session(body) => {
            if candidate.session_id.as_deref() != Some(body.session_id.as_str()) {
                return Err(error(
                    Event4ErrorCategory::Identity,
                    Event4ValidationCode::SessionIdentityMismatch,
                ));
            }
            let expected = match candidate.event_action {
                EventAction::SessionOpened => SessionLifecycle::Opened,
                EventAction::SessionUpdated => SessionLifecycle::Updated,
                EventAction::SessionClosed => SessionLifecycle::Closed,
                _ => return Err(action_semantic_error()),
            };
            if body.lifecycle != expected {
                return Err(action_semantic_error());
            }
        }
        EventBody::Observation(body) => {
            if !valid_observation_id(&body.observation_id) {
                return Err(error(
                    Event4ErrorCategory::Identity,
                    Event4ValidationCode::InvalidObservationId,
                ));
            }
            if candidate.event_id == body.observation_id {
                return Err(error(
                    Event4ErrorCategory::Identity,
                    Event4ValidationCode::IdentityNotDistinct,
                ));
            }
            if let Some(parent) = body
                .correlation
                .as_ref()
                .and_then(|item| item.parent_observation_id.as_deref())
            {
                require_observation_id(parent)?;
            }
            let expected =
                observation_pair(candidate.event_action).ok_or_else(action_semantic_error)?;
            if (body.kind, body.stage) != expected {
                return Err(action_semantic_error());
            }
        }
        EventBody::Finding(body) => {
            if candidate.session_id.is_none() {
                return Err(action_semantic_error());
            }
            if let Some(ids) = &body.related_observation_ids {
                for id in ids {
                    require_observation_id(id)?;
                }
            }
            if let Some(evidence) = &body.evidence {
                for item in evidence {
                    validate_evidence(item)?;
                }
            }
            let expected =
                finding_detector(candidate.event_action).ok_or_else(action_semantic_error)?;
            if body.detector.kind != expected {
                return Err(action_semantic_error());
            }
        }
        EventBody::Decision(body) => validate_decision(candidate.event_action, body)?,
        EventBody::Action(body) => {
            if body.action_id == candidate.event_id {
                return Err(error(
                    Event4ErrorCategory::Identity,
                    Event4ValidationCode::IdentityNotDistinct,
                ));
            }
            validate_action(candidate.event_action, body)?;
        }
        EventBody::State(body) => {
            let expected = state_kind(candidate.event_action).ok_or_else(action_semantic_error)?;
            if body.kind != expected {
                return Err(action_semantic_error());
            }
        }
        EventBody::Health(body) => {
            let expected = match candidate.event_action {
                EventAction::HealthDegraded => HealthStatus::Degraded,
                EventAction::HealthFailed => HealthStatus::Failed,
                _ => return Err(action_semantic_error()),
            };
            if body.status != expected {
                return Err(action_semantic_error());
            }
        }
        EventBody::Summary(_) => {
            if candidate.event_action != EventAction::SummaryEmitted {
                return Err(action_semantic_error());
            }
        }
    }
    Ok(())
}

fn observation_pair(action: EventAction) -> Option<(ObservationKind, ObservationStage)> {
    Some(match action {
        EventAction::MessageObserved => (ObservationKind::Message, ObservationStage::Observed),
        EventAction::InferenceRequested => {
            (ObservationKind::Inference, ObservationStage::Requested)
        }
        EventAction::InferenceCompleted => {
            (ObservationKind::Inference, ObservationStage::Completed)
        }
        EventAction::InferenceFailed => (ObservationKind::Inference, ObservationStage::Failed),
        EventAction::ToolProposed => (ObservationKind::Tool, ObservationStage::Proposed),
        EventAction::ToolRequested => (ObservationKind::Tool, ObservationStage::Requested),
        EventAction::ToolExecutionStarted => {
            (ObservationKind::Tool, ObservationStage::ExecutionStarted)
        }
        EventAction::ToolExecutionCompleted => {
            (ObservationKind::Tool, ObservationStage::ExecutionCompleted)
        }
        EventAction::ToolResultReturned => {
            (ObservationKind::Tool, ObservationStage::ResultReturned)
        }
        EventAction::ToolDefinitionChanged => {
            (ObservationKind::ToolDefinition, ObservationStage::Changed)
        }
        EventAction::McpInventoryChanged => {
            (ObservationKind::Mcp, ObservationStage::InventoryChanged)
        }
        EventAction::ProcessObserved => (ObservationKind::Process, ObservationStage::Observed),
        EventAction::FileObserved => (ObservationKind::File, ObservationStage::Observed),
        EventAction::NetworkObserved => (ObservationKind::Network, ObservationStage::Observed),
        EventAction::BrowserObserved => (ObservationKind::Browser, ObservationStage::Observed),
        EventAction::RuntimeObserved => (ObservationKind::Runtime, ObservationStage::Observed),
        _ => return None,
    })
}

fn finding_detector(action: EventAction) -> Option<DetectorKind> {
    Some(match action {
        EventAction::RuleMatched => DetectorKind::Rule,
        EventAction::SequenceMatched => DetectorKind::Sequence,
        EventAction::GuardModelMatched => DetectorKind::GuardModel,
        EventAction::ClassifierMatched => DetectorKind::Classifier,
        EventAction::BaselineDeviation => DetectorKind::Baseline,
        EventAction::CorrelationMatched => DetectorKind::Correlation,
        _ => return None,
    })
}

fn state_kind(action: EventAction) -> Option<StateKind> {
    Some(match action {
        EventAction::RuntimeChanged => StateKind::Runtime,
        EventAction::IsolationChanged => StateKind::Isolation,
        EventAction::CapabilitiesChanged => StateKind::Capabilities,
        EventAction::RulesetActivated => StateKind::Ruleset,
        EventAction::PolicyActivated => StateKind::Policy,
        EventAction::ToolsetChanged => StateKind::Toolset,
        EventAction::SensorHeartbeat => StateKind::Heartbeat,
        _ => return None,
    })
}

fn validate_decision(
    action: EventAction,
    body: &DecisionBody,
) -> Result<(), Event4ValidationError> {
    validate_outcomes(
        body.requested,
        body.effective,
        body.status == DecisionStatus::Degraded,
        body.capability.as_ref(),
        body.degradation_reason.as_deref(),
    )?;
    if body.approval_state.is_some() != body.approval_id.is_some() {
        return Err(error(
            Event4ErrorCategory::Semantic,
            Event4ValidationCode::InvalidApproval,
        ));
    }
    match action {
        EventAction::PolicyEvaluated => {
            if matches!(body.status, DecisionStatus::Pending)
                || !matches!(body.approval_state, None | Some(ApprovalState::Required))
            {
                return Err(action_semantic_error());
            }
        }
        EventAction::ApprovalRequested => {
            if body.status != DecisionStatus::Pending
                || body.requested != body.effective
                || body.approval_state != Some(ApprovalState::Requested)
                || body.approval_id.is_none()
            {
                return Err(error(
                    Event4ErrorCategory::Semantic,
                    Event4ValidationCode::InvalidApproval,
                ));
            }
        }
        EventAction::ApprovalResolved => {
            if body.status != DecisionStatus::Evaluated
                || !matches!(
                    body.approval_state,
                    Some(
                        ApprovalState::Granted
                            | ApprovalState::Denied
                            | ApprovalState::Expired
                            | ApprovalState::Cancelled
                    )
                )
                || body.approval_id.is_none()
            {
                return Err(error(
                    Event4ErrorCategory::Semantic,
                    Event4ValidationCode::InvalidApproval,
                ));
            }
        }
        _ => return Err(action_semantic_error()),
    }
    Ok(())
}

fn validate_action(action: EventAction, body: &ActionBody) -> Result<(), Event4ValidationError> {
    validate_outcomes(
        body.requested,
        body.effective,
        body.status == ActionStatus::Degraded,
        body.capability.as_ref(),
        body.degradation_reason.as_deref(),
    )?;
    if body.status == ActionStatus::Succeeded
        && body.enforcement_point.as_deref().is_none_or(str::is_empty)
    {
        return Err(action_semantic_error());
    }
    match action {
        EventAction::EnforcementDegraded if body.status == ActionStatus::Degraded => Ok(()),
        EventAction::EnforcementApplied if body.status != ActionStatus::Degraded => Ok(()),
        _ => Err(action_semantic_error()),
    }
}

fn validate_outcomes(
    requested: Outcome,
    effective: Outcome,
    degraded: bool,
    capability: Option<&CapabilityOutcome>,
    degradation_reason: Option<&str>,
) -> Result<(), Event4ValidationError> {
    if (requested != effective) != degraded {
        return Err(error(
            Event4ErrorCategory::Semantic,
            Event4ValidationCode::InvalidOutcomeRelationship,
        ));
    }
    if degraded {
        let Some(capability) = capability else {
            return Err(error(
                Event4ErrorCategory::Semantic,
                Event4ValidationCode::InvalidDegradation,
            ));
        };
        if !matches!(
            capability.availability,
            Availability::Unsupported | Availability::Unknown
        ) || capability.limitation.as_deref().is_none_or(str::is_empty)
            || degradation_reason.is_none_or(str::is_empty)
        {
            return Err(error(
                Event4ErrorCategory::Semantic,
                Event4ValidationCode::InvalidDegradation,
            ));
        }
    }
    Ok(())
}

fn validate_evidence(evidence: &Evidence) -> Result<(), Event4ValidationError> {
    if let Some(id) = &evidence.observation_id {
        require_observation_id(id)?;
    }
    if let Some(ExtensionScalar::Number(value)) = evidence.value.as_ref()
        && !value.is_finite()
    {
        return Err(error(
            Event4ErrorCategory::Semantic,
            Event4ValidationCode::NonFiniteNumber,
        ));
    }
    if evidence.representation == EvidenceRepresentation::RedactedExcerpt {
        let Some(ExtensionScalar::String(value)) = evidence.value.as_ref() else {
            return Err(error(
                Event4ErrorCategory::Semantic,
                Event4ValidationCode::InvalidEvidence,
            ));
        };
        if value.chars().count() > 512 {
            return Err(error(
                Event4ErrorCategory::Semantic,
                Event4ValidationCode::InvalidEvidence,
            ));
        }
    }
    Ok(())
}

fn validate_extensions(extensions: Option<&Extensions>) -> Result<(), Event4ValidationError> {
    let Some(extensions) = extensions else {
        return Ok(());
    };
    let bytes = serde_json::to_vec(extensions).map_err(|_| {
        error(
            Event4ErrorCategory::Extension,
            Event4ValidationCode::DuplicateNormalizedKey,
        )
    })?;
    if bytes.len() > EXTENSIONS_MAX_BYTES {
        return Err(error(
            Event4ErrorCategory::Extension,
            Event4ValidationCode::ExtensionTooLarge,
        ));
    }
    let mut scalars = 0usize;
    for (_, namespace) in extensions.iter() {
        for (_, value) in namespace.iter() {
            scalars += match value {
                ExtensionValue::Scalar(_) => 1,
                ExtensionValue::Array(values) => values.len(),
            };
            let values: &[ExtensionScalar] = match value {
                ExtensionValue::Scalar(value) => std::slice::from_ref(value),
                ExtensionValue::Array(values) => values,
            };
            if values.iter().any(
                |value| matches!(value, ExtensionScalar::Number(number) if !number.is_finite()),
            ) {
                return Err(error(
                    Event4ErrorCategory::Extension,
                    Event4ValidationCode::NonFiniteNumber,
                ));
            }
        }
    }
    if scalars > EXTENSIONS_MAX_SCALARS {
        return Err(error(
            Event4ErrorCategory::Extension,
            Event4ValidationCode::ExtensionScalarLimit,
        ));
    }
    Ok(())
}

fn validate_finite(candidate: &Event4Candidate) -> Result<(), Event4ValidationError> {
    if let EventBody::Finding(body) = &candidate.body
        && body
            .confidence_score
            .is_some_and(|value| !value.is_finite())
    {
        return Err(error(
            Event4ErrorCategory::Semantic,
            Event4ValidationCode::NonFiniteNumber,
        ));
    }
    Ok(())
}

fn validate_context(
    event: &MaterializedEvent4,
    content_hash: [u8; 32],
    context: &impl Event4Context,
) -> Result<Event4AcceptanceEffect, Event4ValidationError> {
    if let Some(existing) = context.event(event.event_id()) {
        if existing.content_hash != content_hash {
            return Err(error(
                Event4ErrorCategory::Identity,
                Event4ValidationCode::IdentityCollision,
            ));
        }
        return Ok(Event4AcceptanceEffect {
            event_id: event.event_id().to_owned(),
            event: existing,
            approval: None,
            disposition: AcceptanceDisposition::Idempotent,
        });
    }

    let candidate = event.candidate();
    let mut decision_fact = None;
    let mut approval_effect = None;
    match &candidate.body {
        EventBody::Decision(body) => {
            if let Some(basis) = &body.basis_event_ids {
                for event_id in basis {
                    if context.event(event_id).is_none() {
                        return Err(error(
                            Event4ErrorCategory::Reference,
                            Event4ValidationCode::MissingReference,
                        ));
                    }
                }
            }
            decision_fact = Some(Event4DecisionFact {
                requested: body.requested,
                approval_id: body.approval_id.clone(),
                approval_state: body.approval_state,
            });
            match candidate.event_action {
                EventAction::ApprovalRequested => {
                    let approval_id = body.approval_id.as_ref().expect("validated approval id");
                    if context.approval(approval_id).is_some() {
                        return Err(error(
                            Event4ErrorCategory::Context,
                            Event4ValidationCode::ApprovalTransition,
                        ));
                    }
                    approval_effect = Some((
                        approval_id.clone(),
                        Event4ApprovalFact {
                            state: ApprovalState::Requested,
                            decision_event_id: candidate.event_id.clone(),
                        },
                    ));
                }
                EventAction::ApprovalResolved => {
                    let approval_id = body.approval_id.as_ref().expect("validated approval id");
                    let Some((state, _)) = context.approval(approval_id) else {
                        return Err(error(
                            Event4ErrorCategory::Context,
                            Event4ValidationCode::ApprovalTransition,
                        ));
                    };
                    if state != ApprovalState::Requested {
                        return Err(error(
                            Event4ErrorCategory::Context,
                            Event4ValidationCode::ApprovalTransition,
                        ));
                    }
                    approval_effect = Some((
                        approval_id.clone(),
                        Event4ApprovalFact {
                            state: body.approval_state.expect("validated approval state"),
                            decision_event_id: candidate.event_id.clone(),
                        },
                    ));
                }
                _ => {}
            }
        }
        EventBody::Action(body) => validate_action_context(body, context)?,
        _ => {}
    }
    let fact = Event4AcceptedFact {
        content_hash,
        event_type: candidate.event_type,
        decision: decision_fact,
    };
    Ok(Event4AcceptanceEffect {
        event_id: candidate.event_id.clone(),
        event: fact,
        approval: approval_effect,
        disposition: AcceptanceDisposition::New,
    })
}

fn validate_action_context(
    body: &ActionBody,
    context: &impl Event4Context,
) -> Result<(), Event4ValidationError> {
    let Some(fact) = context.event(&body.decision_ref) else {
        return Err(error(
            Event4ErrorCategory::Reference,
            Event4ValidationCode::MissingReference,
        ));
    };
    let Some(decision) = fact.decision else {
        return Err(error(
            Event4ErrorCategory::Reference,
            Event4ValidationCode::ReferenceTypeMismatch,
        ));
    };
    if body.requested != decision.requested {
        return Err(error(
            Event4ErrorCategory::Reference,
            Event4ValidationCode::RequestedOutcomeMismatch,
        ));
    }
    match (
        &body.approval_id,
        &decision.approval_id,
        decision.approval_state,
    ) {
        (None, None, None) => {}
        (Some(action_id), Some(decision_id), Some(state)) if action_id == decision_id => {
            if body.status == ActionStatus::Succeeded && state != ApprovalState::Granted {
                return Err(error(
                    Event4ErrorCategory::Reference,
                    Event4ValidationCode::ApprovalActionMismatch,
                ));
            }
        }
        _ => {
            return Err(error(
                Event4ErrorCategory::Reference,
                Event4ValidationCode::ApprovalActionMismatch,
            ));
        }
    }
    Ok(())
}

fn parse_time(value: &str) -> Result<OffsetDateTime, Event4ValidationError> {
    OffsetDateTime::parse(value, &Rfc3339).map_err(|_| {
        error(
            Event4ErrorCategory::Time,
            Event4ValidationCode::InvalidTimestamp,
        )
    })
}

fn valid_opaque_reference(value: &str) -> bool {
    OPAQUE_REFERENCE.is_match(value)
}

fn require_observation_id(value: &str) -> Result<(), Event4ValidationError> {
    if valid_observation_id(value) {
        Ok(())
    } else {
        Err(error(
            Event4ErrorCategory::Identity,
            Event4ValidationCode::InvalidObservationId,
        ))
    }
}

fn action_semantic_error() -> Event4ValidationError {
    error(
        Event4ErrorCategory::Semantic,
        Event4ValidationCode::ActionSemanticMismatch,
    )
}

fn container_depth(value: &Value, depth: usize) -> usize {
    match value {
        Value::Array(values) => values
            .iter()
            .map(|value| container_depth(value, depth + 1))
            .max()
            .unwrap_or(depth),
        Value::Object(values) => values
            .values()
            .map(|value| container_depth(value, depth + 1))
            .max()
            .unwrap_or(depth),
        _ => depth.saturating_sub(1),
    }
}

#[cfg(test)]
pub(super) fn test_container_depth(value: &Value) -> usize {
    container_depth(value, 1)
}
