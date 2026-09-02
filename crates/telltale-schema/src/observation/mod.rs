//! Canonical Observation v2 domain types and validation.
//!
//! Callers must not log these types. Nested types may retain `Debug`
//! implementations that expose local or sensitive values when logged directly.

mod body;
mod identity;
mod value;

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

pub use body::{
    BrowserObservation, ContentPart, FileObservation, InferenceMetrics, InferenceObservation,
    McpObservation, MessageObservation, NetworkObservation, ObservationBody, OtherObservation,
    ProcessObservation, RuntimeObservation, SessionObservation, ToolDefinitionObservation,
    ToolObservation,
};
pub use identity::{
    ASSIGNMENT_COMMITMENT_PREFIX, ASSIGNMENT_COMPARISON_DOMAIN, AssignmentStore, IdentityBasis,
    IdentityBasisKind, IdentityCoordinateKind, IdentityCoordinateValue, InMemoryAssignmentStore,
    KEYED_FINGERPRINT_PREFIX, KeyedFingerprint, OBSERVATION_ID_PREFIX, SEMANTIC_FINGERPRINT_PREFIX,
    canonical_identity_json, valid_observation_id,
};
pub use value::{
    JsonValue, LOCAL_MAX_ARRAY_ITEMS, LOCAL_MAX_DEPTH, LOCAL_MAX_ENTRIES, LOCAL_MAX_KEY_BYTES,
    LOCAL_MAX_OBJECT_MEMBERS, LOCAL_MAX_SEARCHABLE_BYTES, LOCAL_MAX_STRING_BYTES,
    LOCAL_MAX_TOTAL_BYTES, LOCAL_MAX_VALUE_BYTES, LocalEvidence, LocalReference, LocalValue,
    SemanticFacet,
};

pub const OTHER_REGISTRY_VERSION: &str = "other-v1";

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ObservationId(String);
impl ObservationId {
    pub fn new(value: impl AsRef<str>) -> Result<Self, ObservationError> {
        if !identity::valid_observation_id(value.as_ref()) {
            return Err(ObservationError::new(ValidationCode::InvalidId));
        }
        Ok(Self(value.as_ref().to_owned()))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationFamily {
    Message,
    Inference,
    Tool,
    ToolDefinition,
    Mcp,
    Process,
    File,
    Network,
    Browser,
    Runtime,
    Session,
    Other,
}

impl ObservationFamily {
    pub const ALL: [Self; 12] = [
        Self::Message,
        Self::Inference,
        Self::Tool,
        Self::ToolDefinition,
        Self::Mcp,
        Self::Process,
        Self::File,
        Self::Network,
        Self::Browser,
        Self::Runtime,
        Self::Session,
        Self::Other,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Message => "message",
            Self::Inference => "inference",
            Self::Tool => "tool",
            Self::ToolDefinition => "tool_definition",
            Self::Mcp => "mcp",
            Self::Process => "process",
            Self::File => "file",
            Self::Network => "network",
            Self::Browser => "browser",
            Self::Runtime => "runtime",
            Self::Session => "session",
            Self::Other => "other",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationStage {
    MessageObserved,
    InferenceRequested,
    InferenceStarted,
    InferenceCompleted,
    InferenceFailed,
    ToolProposed,
    ToolRequested,
    ToolExecutionStarted,
    ToolExecutionCompleted,
    ToolResultReturned,
    DefinitionChanged,
    McpInventoryChanged,
    ProcessObserved,
    FileObserved,
    NetworkObserved,
    BrowserObserved,
    RuntimeObserved,
    RuntimeChanged,
    SessionOpened,
    SessionUpdated,
    SessionClosed,
    OtherObserved,
}

impl ObservationStage {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MessageObserved => "observed",
            Self::InferenceRequested => "requested",
            Self::InferenceStarted => "started",
            Self::InferenceCompleted => "completed",
            Self::InferenceFailed => "failed",
            Self::ToolProposed => "proposed",
            Self::ToolRequested => "requested",
            Self::ToolExecutionStarted => "execution_started",
            Self::ToolExecutionCompleted => "execution_completed",
            Self::ToolResultReturned => "result_returned",
            Self::DefinitionChanged => "changed",
            Self::McpInventoryChanged => "inventory_changed",
            Self::ProcessObserved
            | Self::FileObserved
            | Self::NetworkObserved
            | Self::BrowserObserved
            | Self::OtherObserved => "observed",
            Self::RuntimeObserved => "observed",
            Self::RuntimeChanged => "changed",
            Self::SessionOpened => "opened",
            Self::SessionUpdated => "updated",
            Self::SessionClosed => "closed",
        }
    }

    fn is_compatible(self, family: ObservationFamily) -> bool {
        matches!(
            (family, self),
            (ObservationFamily::Message, Self::MessageObserved)
                | (
                    ObservationFamily::Inference,
                    Self::InferenceRequested
                        | Self::InferenceStarted
                        | Self::InferenceCompleted
                        | Self::InferenceFailed
                )
                | (
                    ObservationFamily::Tool,
                    Self::ToolProposed
                        | Self::ToolRequested
                        | Self::ToolExecutionStarted
                        | Self::ToolExecutionCompleted
                        | Self::ToolResultReturned
                )
                | (ObservationFamily::ToolDefinition, Self::DefinitionChanged)
                | (ObservationFamily::Mcp, Self::McpInventoryChanged)
                | (ObservationFamily::Process, Self::ProcessObserved)
                | (ObservationFamily::File, Self::FileObserved)
                | (ObservationFamily::Network, Self::NetworkObserved)
                | (ObservationFamily::Browser, Self::BrowserObserved)
                | (
                    ObservationFamily::Runtime,
                    Self::RuntimeObserved | Self::RuntimeChanged
                )
                | (
                    ObservationFamily::Session,
                    Self::SessionOpened | Self::SessionUpdated | Self::SessionClosed
                )
                | (ObservationFamily::Other, Self::OtherObserved)
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageRole {
    System,
    Developer,
    User,
    Assistant,
    Tool,
    Other,
}
impl MessageRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::System => "system",
            Self::Developer => "developer",
            Self::User => "user",
            Self::Assistant => "assistant",
            Self::Tool => "tool",
            Self::Other => "other",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContentPartKind {
    Text,
    ImageReference,
    ToolUse,
    ToolResult,
    Other,
}
impl ContentPartKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::ImageReference => "image_reference",
            Self::ToolUse => "tool_use",
            Self::ToolResult => "tool_result",
            Self::Other => "other",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolStatus {
    Succeeded,
    Failed,
    Cancelled,
    Denied,
    Unknown,
}
impl ToolStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::Denied => "denied",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionLifecycle {
    Opened,
    Updated,
    Closed,
}
impl SessionLifecycle {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Opened => "opened",
            Self::Updated => "updated",
            Self::Closed => "closed",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IngestionMode {
    SessionStore,
    Harness,
    Gateway,
    Browser,
    OsContext,
    Import,
    Other,
}
impl IngestionMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SessionStore => "session_store",
            Self::Harness => "harness",
            Self::Gateway => "gateway",
            Self::Browser => "browser",
            Self::OsContext => "os_context",
            Self::Import => "import",
            Self::Other => "other",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Fidelity {
    FullNative,
    PartialStructured,
    FlattenedLossy,
    DerivedOnly,
    Unknown,
}
impl Fidelity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FullNative => "full_native",
            Self::PartialStructured => "partial_structured",
            Self::FlattenedLossy => "flattened_lossy",
            Self::DerivedOnly => "derived_only",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityAvailability {
    Supported,
    Unsupported,
    Unknown,
}
impl CapabilityAvailability {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Supported => "supported",
            Self::Unsupported => "unsupported",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityId {
    ToolCall,
    ToolExecution,
    UserContext,
}
impl CapabilityId {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ToolCall => "tool_call",
            Self::ToolExecution => "tool_execution",
            Self::UserContext => "user_context",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FactProvenance {
    Reported,
    Parsed,
    Derived,
    Inferred,
    Observed,
}
impl FactProvenance {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reported => "reported",
            Self::Parsed => "parsed",
            Self::Derived => "derived",
            Self::Inferred => "inferred",
            Self::Observed => "observed",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Sensitivity {
    Normal,
    Sensitive,
    Secret,
    ReferenceOnly,
    Prohibited,
}
impl Sensitivity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::Sensitive => "sensitive",
            Self::Secret => "secret",
            Self::ReferenceOnly => "reference_only",
            Self::Prohibited => "prohibited",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CorrelationOrigin {
    SourceReported,
    TelltaleOriginated,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorrelationId {
    value: String,
    origin: CorrelationOrigin,
}
impl CorrelationId {
    pub fn new(
        value: impl AsRef<str>,
        origin: CorrelationOrigin,
    ) -> Result<Self, ObservationError> {
        Ok(Self {
            value: value::opaque_text(value.as_ref(), ValidationCode::PathDerivedId)?,
            origin,
        })
    }
    pub fn value(&self) -> &str {
        &self.value
    }
    pub fn origin(&self) -> CorrelationOrigin {
        self.origin
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CorrelationIds {
    turn_id: Option<CorrelationId>,
    request_id: Option<CorrelationId>,
    response_id: Option<CorrelationId>,
    call_id: Option<CorrelationId>,
    trace_id: Option<CorrelationId>,
    span_id: Option<CorrelationId>,
    delegation_id: Option<CorrelationId>,
    parent_observation_id: Option<CorrelationId>,
    process_instance_id: Option<CorrelationId>,
}
macro_rules! correlation_setters {
    ($(($field:ident, $method:ident)),+ $(,)?) => { $(
        pub fn $method(mut self, value: CorrelationId) -> Self { self.$field = Some(value); self }
    )+ };
}
impl CorrelationIds {
    pub fn new() -> Self {
        Self::default()
    }
    correlation_setters!(
        (turn_id, with_turn_id),
        (request_id, with_request_id),
        (response_id, with_response_id),
        (call_id, with_call_id),
        (trace_id, with_trace_id),
        (span_id, with_span_id),
        (delegation_id, with_delegation_id),
        (parent_observation_id, with_parent_observation_id),
        (process_instance_id, with_process_instance_id)
    );
    pub fn call_id(&self) -> Option<&CorrelationId> {
        self.call_id.as_ref()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionedReference {
    id: String,
    version: String,
}
impl VersionedReference {
    pub fn new(id: impl AsRef<str>, version: impl AsRef<str>) -> Result<Self, ObservationError> {
        Ok(Self {
            id: value::opaque_text(id.as_ref(), ValidationCode::InvalidReference)?,
            version: value::non_empty(version.as_ref(), ValidationCode::InvalidReference)?,
        })
    }
    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn version(&self) -> &str {
        &self.version
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceTimestamp(String);
impl SourceTimestamp {
    pub fn new(value: impl AsRef<str>) -> Result<Self, ObservationError> {
        validate_time(value.as_ref(), ValidationCode::InvalidTime).map(Self)
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedAt(String);
impl ObservedAt {
    pub fn new(value: impl AsRef<str>) -> Result<Self, ObservationError> {
        validate_time(value.as_ref(), ValidationCode::InvalidTime).map(Self)
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn validate_time(value: &str, code: ValidationCode) -> Result<String, ObservationError> {
    let value = value::non_empty(value, code)?;
    OffsetDateTime::parse(&value, &Rfc3339)
        .map_err(|_| ObservationError::new(ValidationCode::InvalidTime))?;
    Ok(value)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceProvenance {
    ingestion_mode: IngestionMode,
    adapter_type: String,
    adapter_id: String,
    adapter_version: Option<String>,
    native_id: Option<String>,
    source_sequence: Option<u64>,
    offset: Option<String>,
    source_path_hash: Option<String>,
    profile_refs: Vec<VersionedReference>,
    normalization_refs: Vec<LocalReference>,
    producer_identity_key_ref: Option<LocalReference>,
    fidelity: Fidelity,
}
impl SourceProvenance {
    pub fn new(
        ingestion_mode: IngestionMode,
        adapter_type: impl AsRef<str>,
        adapter_id: impl AsRef<str>,
        fidelity: Fidelity,
    ) -> Result<Self, ObservationError> {
        Ok(Self {
            ingestion_mode,
            adapter_type: value::non_empty(adapter_type.as_ref(), ValidationCode::InvalidSource)?,
            adapter_id: value::non_empty(adapter_id.as_ref(), ValidationCode::InvalidSource)?,
            adapter_version: None,
            native_id: None,
            source_sequence: None,
            offset: None,
            source_path_hash: None,
            profile_refs: Vec::new(),
            normalization_refs: Vec::new(),
            producer_identity_key_ref: None,
            fidelity,
        })
    }
    pub fn with_adapter_version(
        mut self,
        value: impl AsRef<str>,
    ) -> Result<Self, ObservationError> {
        self.adapter_version = Some(value::non_empty(
            value.as_ref(),
            ValidationCode::InvalidSource,
        )?);
        Ok(self)
    }
    pub fn with_native_id(mut self, value: impl AsRef<str>) -> Result<Self, ObservationError> {
        self.native_id = Some(value::opaque_text(
            value.as_ref(),
            ValidationCode::PathDerivedId,
        )?);
        Ok(self)
    }
    pub fn with_source_sequence(mut self, value: u64) -> Self {
        self.source_sequence = Some(value);
        self
    }
    pub fn with_offset(mut self, value: impl AsRef<str>) -> Result<Self, ObservationError> {
        self.offset = Some(value::opaque_text(
            value.as_ref(),
            ValidationCode::PathDerivedId,
        )?);
        Ok(self)
    }
    pub fn with_source_path_hash(
        mut self,
        value: impl AsRef<str>,
    ) -> Result<Self, ObservationError> {
        self.source_path_hash = Some(value::non_empty(
            value.as_ref(),
            ValidationCode::InvalidSource,
        )?);
        Ok(self)
    }
    pub fn with_profile_ref(mut self, value: VersionedReference) -> Self {
        self.profile_refs.push(value);
        self
    }
    pub fn with_normalization_ref(mut self, value: LocalReference) -> Self {
        self.normalization_refs.push(value);
        self
    }
    pub fn with_producer_identity_key_ref(
        mut self,
        value: LocalReference,
    ) -> Result<Self, ObservationError> {
        if value.retention_class() != "identity_key" {
            return Err(ObservationError::new(ValidationCode::InvalidSource));
        }
        self.producer_identity_key_ref = Some(value);
        Ok(self)
    }
    pub fn ingestion_mode(&self) -> IngestionMode {
        self.ingestion_mode
    }
    pub fn adapter_type(&self) -> &str {
        &self.adapter_type
    }
    pub fn adapter_id(&self) -> &str {
        &self.adapter_id
    }
    pub fn adapter_version(&self) -> Option<&str> {
        self.adapter_version.as_deref()
    }
    pub fn native_id(&self) -> Option<&str> {
        self.native_id.as_deref()
    }
    pub fn source_sequence(&self) -> Option<u64> {
        self.source_sequence
    }
    pub fn offset(&self) -> Option<&str> {
        self.offset.as_deref()
    }
    pub fn fidelity(&self) -> Fidelity {
        self.fidelity
    }
    pub fn profile_refs(&self) -> &[VersionedReference] {
        &self.profile_refs
    }
    pub fn normalization_refs(&self) -> &[LocalReference] {
        &self.normalization_refs
    }
    pub fn producer_identity_key_ref(&self) -> Option<&LocalReference> {
        self.producer_identity_key_ref.as_ref()
    }
    pub fn source_path_hash(&self) -> Option<&str> {
        self.source_path_hash.as_deref()
    }
    pub(crate) fn selected_coordinate(
        &self,
    ) -> Option<(
        identity::IdentityCoordinateKind,
        identity::IdentityCoordinateValue,
    )> {
        self.native_id
            .as_ref()
            .map(|v| {
                (
                    identity::IdentityCoordinateKind::NativeId,
                    identity::IdentityCoordinateValue::NativeId(v.clone()),
                )
            })
            .or_else(|| {
                self.source_sequence.map(|v| {
                    (
                        identity::IdentityCoordinateKind::SourceSequence,
                        identity::IdentityCoordinateValue::SourceSequence(v),
                    )
                })
            })
            .or_else(|| {
                self.offset.as_ref().map(|v| {
                    (
                        identity::IdentityCoordinateKind::Offset,
                        identity::IdentityCoordinateValue::Offset(v.clone()),
                    )
                })
            })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityContext {
    profile_ref: Option<VersionedReference>,
    overrides: BTreeMap<CapabilityId, CapabilityAvailability>,
}
impl CapabilityContext {
    pub fn new() -> Self {
        Self {
            profile_ref: None,
            overrides: BTreeMap::new(),
        }
    }
    pub fn with_profile_ref(mut self, value: VersionedReference) -> Self {
        self.profile_ref = Some(value);
        self
    }
    pub fn with_override(
        mut self,
        capability: CapabilityId,
        availability: CapabilityAvailability,
    ) -> Self {
        self.overrides.insert(capability, availability);
        self
    }
    pub fn resolve(&self, capability: CapabilityId) -> CapabilityAvailability {
        self.overrides
            .get(&capability)
            .copied()
            .unwrap_or(CapabilityAvailability::Unknown)
    }
    pub fn overrides(&self) -> &BTreeMap<CapabilityId, CapabilityAvailability> {
        &self.overrides
    }
}
impl Default for CapabilityContext {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct FactMetadata {
    provenance: FactProvenance,
    fidelity_override: Option<Fidelity>,
    sensitivity: Sensitivity,
    keyed_fingerprints: Vec<KeyedFingerprint>,
}
impl FactMetadata {
    pub fn new(
        provenance: FactProvenance,
        sensitivity: Sensitivity,
    ) -> Result<Self, ObservationError> {
        if sensitivity == Sensitivity::Prohibited {
            return Err(ObservationError::new(ValidationCode::ProhibitedSensitivity));
        }
        Ok(Self {
            provenance,
            fidelity_override: None,
            sensitivity,
            keyed_fingerprints: Vec::new(),
        })
    }
    pub fn with_fidelity_override(mut self, fidelity: Fidelity) -> Self {
        self.fidelity_override = Some(fidelity);
        self
    }
    pub fn with_keyed_fingerprint(
        mut self,
        value: KeyedFingerprint,
    ) -> Result<Self, ObservationError> {
        if self.sensitivity == Sensitivity::Normal {
            return Err(ObservationError::new(
                ValidationCode::FingerprintSensitivity,
            ));
        }
        self.keyed_fingerprints.push(value);
        Ok(self)
    }
    pub fn provenance(&self) -> FactProvenance {
        self.provenance
    }
    pub fn fidelity_override(&self) -> Option<Fidelity> {
        self.fidelity_override
    }
    pub fn sensitivity(&self) -> Sensitivity {
        self.sensitivity
    }
    pub fn keyed_fingerprints(&self) -> &[KeyedFingerprint] {
        &self.keyed_fingerprints
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssignmentRecord {
    observation_id: String,
    comparison_key_ref: String,
    comparison_domain: String,
    commitment: String,
}
impl AssignmentRecord {
    pub fn new(
        observation_id: impl AsRef<str>,
        comparison_key_ref: impl AsRef<str>,
        commitment: impl AsRef<str>,
    ) -> Result<Self, ObservationError> {
        if !identity::valid_observation_id(observation_id.as_ref())
            || !identity::valid_assignment_commitment(commitment.as_ref())
        {
            return Err(ObservationError::new(ValidationCode::InvalidAssignment));
        }
        let comparison_key_ref = value::opaque_text(
            comparison_key_ref.as_ref(),
            ValidationCode::InvalidAssignment,
        )?;
        Ok(Self {
            observation_id: observation_id.as_ref().to_owned(),
            comparison_key_ref,
            comparison_domain: identity::ASSIGNMENT_COMPARISON_DOMAIN.to_owned(),
            commitment: commitment.as_ref().to_owned(),
        })
    }
    pub fn observation_id(&self) -> &str {
        &self.observation_id
    }
    pub fn comparison_key_ref(&self) -> &str {
        &self.comparison_key_ref
    }
    pub fn comparison_domain(&self) -> &str {
        &self.comparison_domain
    }
    pub fn commitment(&self) -> &str {
        &self.commitment
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationCode {
    InvalidId,
    InvalidStage,
    InvalidTime,
    InvalidSource,
    InvalidBody,
    FamilyMinimum,
    MetadataCoverage,
    InvalidMetadata,
    InvalidFacet,
    InvalidCorrelation,
    PathDerivedId,
    UnboundedValue,
    NonFiniteNumber,
    DuplicateObjectKey,
    InvalidLocalKey,
    InvalidReference,
    ExportableReference,
    ReferenceSensitivity,
    ProhibitedSensitivity,
    FingerprintSensitivity,
    InvalidFingerprint,
    InvalidIdentityBasis,
    UnsupportedOther,
    ReplayUnverifiable,
    ReplayCollision,
    InvalidAssignment,
}
impl ValidationCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidId => "invalid_id",
            Self::InvalidStage => "invalid_stage",
            Self::InvalidTime => "invalid_time",
            Self::InvalidSource => "invalid_source",
            Self::InvalidBody => "invalid_body",
            Self::FamilyMinimum => "family_minimum",
            Self::MetadataCoverage => "metadata_coverage",
            Self::InvalidMetadata => "invalid_metadata",
            Self::InvalidFacet => "invalid_facet",
            Self::InvalidCorrelation => "invalid_correlation",
            Self::PathDerivedId => "path_derived_id",
            Self::UnboundedValue => "unbounded_value",
            Self::NonFiniteNumber => "non_finite_number",
            Self::DuplicateObjectKey => "duplicate_object_key",
            Self::InvalidLocalKey => "invalid_local_key",
            Self::InvalidReference => "invalid_reference",
            Self::ExportableReference => "exportable_reference",
            Self::ReferenceSensitivity => "reference_sensitivity",
            Self::ProhibitedSensitivity => "prohibited_sensitivity",
            Self::FingerprintSensitivity => "fingerprint_sensitivity",
            Self::InvalidFingerprint => "invalid_fingerprint",
            Self::InvalidIdentityBasis => "invalid_identity_basis",
            Self::UnsupportedOther => "unsupported_other",
            Self::ReplayUnverifiable => "replay_unverifiable",
            Self::ReplayCollision => "replay_collision",
            Self::InvalidAssignment => "invalid_assignment",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObservationError {
    code: ValidationCode,
}
impl ObservationError {
    pub(crate) fn new(code: ValidationCode) -> Self {
        Self { code }
    }
    pub fn code(&self) -> &'static str {
        self.code.as_str()
    }
    pub fn validation_code(&self) -> ValidationCode {
        self.code
    }
}
impl fmt::Display for ObservationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "canonical observation rejected ({})",
            self.code.as_str()
        )
    }
}
impl std::error::Error for ObservationError {}

#[derive(Clone)]
pub struct CanonicalObservationV2 {
    observation_id: ObservationId,
    body: ObservationBody,
    stage: ObservationStage,
    occurred_at: Option<SourceTimestamp>,
    observed_at: ObservedAt,
    sequence: Option<u64>,
    session_id: Option<CorrelationId>,
    workflow_id: Option<CorrelationId>,
    correlation: CorrelationIds,
    source: SourceProvenance,
    capability_context: Option<CapabilityContext>,
    facets: BTreeMap<String, SemanticFacet>,
    fact_metadata: BTreeMap<String, FactMetadata>,
    local: Option<LocalEvidence>,
    identity_basis: IdentityBasis,
}

impl fmt::Debug for CanonicalObservationV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CanonicalObservationV2")
            .field("observation_id", &self.observation_id)
            .field("kind", &self.kind())
            .field("stage", &self.stage)
            .field("occurred_at", &self.occurred_at)
            .field("observed_at", &self.observed_at)
            .field("source", &self.source)
            .field("body", &"<redacted>")
            .field("facets", &"<redacted>")
            .field("fact_metadata", &"<redacted>")
            .field("local", &"<redacted>")
            .finish()
    }
}

#[derive(Clone)]
pub struct ObservationBuilder {
    body: ObservationBody,
    stage: ObservationStage,
    occurred_at: Option<SourceTimestamp>,
    observed_at: ObservedAt,
    sequence: Option<u64>,
    session_id: Option<CorrelationId>,
    workflow_id: Option<CorrelationId>,
    correlation: CorrelationIds,
    source: SourceProvenance,
    capability_context: Option<CapabilityContext>,
    facets: BTreeMap<String, SemanticFacet>,
    fact_metadata: BTreeMap<String, FactMetadata>,
    local: Option<LocalEvidence>,
    identity_basis: Option<IdentityBasis>,
    child_ordinal: u32,
}
impl ObservationBuilder {
    pub fn occurred_at(mut self, value: SourceTimestamp) -> Self {
        self.occurred_at = Some(value);
        self
    }
    pub fn sequence(mut self, value: u64) -> Self {
        self.sequence = Some(value);
        self
    }
    pub fn child_ordinal(mut self, value: u32) -> Self {
        self.child_ordinal = value;
        self
    }
    pub fn session_id(mut self, value: CorrelationId) -> Self {
        self.session_id = Some(value);
        self
    }
    pub fn workflow_id(mut self, value: CorrelationId) -> Self {
        self.workflow_id = Some(value);
        self
    }
    pub fn correlation(mut self, value: CorrelationIds) -> Self {
        self.correlation = value;
        self
    }
    pub fn capability_context(mut self, value: CapabilityContext) -> Self {
        self.capability_context = Some(value);
        self
    }
    pub fn facet(
        mut self,
        name: impl AsRef<str>,
        value: SemanticFacet,
    ) -> Result<Self, ObservationError> {
        let name = value::nfc(name.as_ref());
        validate_facet_name(&name)?;
        self.facets.insert(name, value);
        Ok(self)
    }
    pub fn fact_metadata(mut self, path: impl AsRef<str>, value: FactMetadata) -> Self {
        self.fact_metadata.insert(value::nfc(path.as_ref()), value);
        self
    }
    pub fn local(mut self, value: LocalEvidence) -> Self {
        self.local = Some(value);
        self
    }
    pub fn identity_basis(mut self, value: IdentityBasis) -> Self {
        self.identity_basis = Some(value);
        self
    }
    pub fn assignment_commitment(&self, key: &[u8]) -> Result<String, ObservationError> {
        if key.is_empty() {
            return Err(ObservationError::new(ValidationCode::ReplayUnverifiable));
        }
        let mut canonical = self.clone();
        canonical.canonicalize_json()?;
        canonical.validate_shape()?;
        identity::assignment_commitment(
            canonical.body.kind(),
            canonical.stage,
            &canonical.body,
            &canonical.facets,
            &canonical.fact_metadata,
            canonical.local.as_ref(),
            key,
        )
    }
    pub fn build(self) -> Result<CanonicalObservationV2, ObservationError> {
        self.build_with_store(None)
    }
    pub fn build_with_assignments(
        self,
        store: &impl AssignmentStore,
    ) -> Result<CanonicalObservationV2, ObservationError> {
        self.build_with_store(Some(store))
    }

    fn build_with_store(
        self,
        store: Option<&dyn AssignmentStore>,
    ) -> Result<CanonicalObservationV2, ObservationError> {
        let mut builder = self;
        builder.canonicalize_json()?;
        builder.build_with_store_canonical(store)
    }

    fn build_with_store_canonical(
        self,
        store: Option<&dyn AssignmentStore>,
    ) -> Result<CanonicalObservationV2, ObservationError> {
        self.validate_shape()?;
        let family = self.body.kind();
        let coordinate = self.source.selected_coordinate();
        let allow_unkeyed = matches!(&self.identity_basis, Some(IdentityBasis::PersistedAssignment { fingerprint_key_epoch_ref, .. }) if fingerprint_key_epoch_ref == "unavailable");
        let epoch = validate_fingerprints(
            &self.body,
            &self.facets,
            &self.fact_metadata,
            self.local.as_ref(),
            &self.source,
            allow_unkeyed,
        )?;
        let semantic = if epoch != "unavailable" {
            Some(identity::semantic_fingerprint(
                family,
                self.stage,
                &self.body,
                &self.facets,
                self.local.as_ref(),
                &self.fact_metadata,
            )?)
        } else {
            None
        };
        let expected_domain = format!(
            "{}:{}:{}",
            self.source.adapter_type(),
            self.source.adapter_id(),
            self.source.adapter_version().unwrap_or("unversioned")
        );
        let (observation_id, basis) = match (coordinate, self.identity_basis) {
            (
                Some((coordinate_kind, coordinate_value)),
                Some(IdentityBasis::StableSourceCoordinate {
                    domain,
                    coordinate_kind: basis_kind,
                    coordinate_value: basis_value,
                    semantic_fingerprint,
                    child_ordinal,
                    fingerprint_key_epoch_ref,
                }),
            ) => {
                if domain != expected_domain
                    || basis_kind != coordinate_kind
                    || basis_value != coordinate_value
                    || semantic_fingerprint != semantic.as_deref().unwrap_or("")
                    || fingerprint_key_epoch_ref != epoch
                {
                    return Err(ObservationError::new(ValidationCode::InvalidIdentityBasis));
                }
                let id = identity::derive_stable_id(
                    &self.source,
                    family,
                    self.stage,
                    semantic.as_deref().unwrap_or(""),
                    child_ordinal,
                    &epoch,
                )?;
                (
                    id,
                    IdentityBasis::StableSourceCoordinate {
                        domain,
                        coordinate_kind,
                        coordinate_value,
                        semantic_fingerprint,
                        child_ordinal,
                        fingerprint_key_epoch_ref,
                    },
                )
            }
            (Some((coordinate_kind, coordinate_value)), None) => {
                let semantic = semantic
                    .ok_or_else(|| ObservationError::new(ValidationCode::ReplayUnverifiable))?;
                let id = identity::derive_stable_id(
                    &self.source,
                    family,
                    self.stage,
                    &semantic,
                    self.child_ordinal,
                    &epoch,
                )?;
                (
                    id.clone(),
                    IdentityBasis::stable(
                        expected_domain,
                        coordinate_kind,
                        coordinate_value,
                        semantic,
                        self.child_ordinal,
                        epoch,
                    )?,
                )
            }
            (Some(_), Some(IdentityBasis::PersistedAssignment { .. })) => {
                return Err(ObservationError::new(ValidationCode::InvalidIdentityBasis));
            }
            (
                None,
                Some(IdentityBasis::PersistedAssignment {
                    domain,
                    replay_key,
                    assignment_ref,
                    child_ordinal,
                    fingerprint_key_epoch_ref,
                }),
            ) => {
                if domain != expected_domain || fingerprint_key_epoch_ref != epoch {
                    return Err(ObservationError::new(ValidationCode::InvalidIdentityBasis));
                }
                let store = store
                    .ok_or_else(|| ObservationError::new(ValidationCode::ReplayUnverifiable))?;
                let record = store
                    .lookup(assignment_ref.handle())?
                    .ok_or_else(|| ObservationError::new(ValidationCode::ReplayUnverifiable))?;
                if record.comparison_domain != identity::ASSIGNMENT_COMPARISON_DOMAIN {
                    return Err(ObservationError::new(ValidationCode::ReplayUnverifiable));
                }
                let key = store
                    .comparison_key(&record.comparison_key_ref)?
                    .ok_or_else(|| ObservationError::new(ValidationCode::ReplayUnverifiable))?;
                let commitment = identity::assignment_commitment(
                    family,
                    self.stage,
                    &self.body,
                    &self.facets,
                    &self.fact_metadata,
                    self.local.as_ref(),
                    &key,
                )?;
                if commitment != record.commitment {
                    return Err(ObservationError::new(ValidationCode::ReplayCollision));
                }
                if !identity::valid_observation_id(&record.observation_id) {
                    return Err(ObservationError::new(ValidationCode::InvalidAssignment));
                }
                (
                    record.observation_id,
                    IdentityBasis::PersistedAssignment {
                        domain,
                        replay_key,
                        assignment_ref,
                        child_ordinal,
                        fingerprint_key_epoch_ref,
                    },
                )
            }
            (None, Some(IdentityBasis::StableSourceCoordinate { .. })) | (None, None) => {
                return Err(ObservationError::new(ValidationCode::ReplayUnverifiable));
            }
        };
        Ok(CanonicalObservationV2 {
            observation_id: ObservationId::new(observation_id)?,
            body: self.body,
            stage: self.stage,
            occurred_at: self.occurred_at,
            observed_at: self.observed_at,
            sequence: self.sequence,
            session_id: self.session_id,
            workflow_id: self.workflow_id,
            correlation: self.correlation,
            source: self.source,
            capability_context: self.capability_context,
            facets: self.facets,
            fact_metadata: self.fact_metadata,
            local: self.local,
            identity_basis: basis,
        })
    }

    fn validate_shape(&self) -> Result<(), ObservationError> {
        let family = self.body.kind();
        if !self.stage.is_compatible(family) {
            return Err(ObservationError::new(ValidationCode::InvalidStage));
        }
        validate_semantic_json_bounds(&self.body, &self.facets)?;
        self.body.validate_minimum(self.stage)?;
        if matches!(
            family,
            ObservationFamily::Process | ObservationFamily::File | ObservationFamily::Network
        ) && !has_observed_activity(&self.body, &self.fact_metadata)
        {
            return Err(ObservationError::new(ValidationCode::FamilyMinimum));
        }
        if family == ObservationFamily::Session && self.session_id.is_none() {
            return Err(ObservationError::new(ValidationCode::FamilyMinimum));
        }
        validate_metadata_coverage(&self.body, &self.facets, &self.fact_metadata)?;
        if matches!(
            self.source.fidelity,
            Fidelity::FlattenedLossy | Fidelity::DerivedOnly
        ) && self
            .fact_metadata
            .values()
            .any(|item| item.fidelity_override() == Some(Fidelity::FullNative))
        {
            return Err(ObservationError::new(ValidationCode::InvalidMetadata));
        }
        if let Some(local) = &self.local {
            local.validate_bounds()?;
        }
        if let Some(id) = &self.session_id {
            validate_correlation_id(id)?;
        }
        if let Some(id) = &self.workflow_id {
            validate_correlation_id(id)?;
        }
        validate_correlation_ids(&self.correlation)?;
        Ok(())
    }

    fn canonicalize_json(&mut self) -> Result<(), ObservationError> {
        self.body = self.body.clone().canonicalize()?;
        self.facets = self
            .facets
            .clone()
            .into_iter()
            .map(|(name, facet)| Ok((name, facet.canonicalize()?)))
            .collect::<Result<BTreeMap<_, _>, ObservationError>>()?;
        Ok(())
    }
}

impl CanonicalObservationV2 {
    pub fn new(
        body: ObservationBody,
        stage: ObservationStage,
        observed_at: ObservedAt,
        source: SourceProvenance,
    ) -> Result<Self, ObservationError> {
        Self::builder(body, stage, observed_at, source).build()
    }
    pub fn builder(
        body: ObservationBody,
        stage: ObservationStage,
        observed_at: ObservedAt,
        source: SourceProvenance,
    ) -> ObservationBuilder {
        ObservationBuilder {
            body,
            stage,
            occurred_at: None,
            observed_at,
            sequence: None,
            session_id: None,
            workflow_id: None,
            correlation: CorrelationIds::new(),
            source,
            capability_context: None,
            facets: BTreeMap::new(),
            fact_metadata: BTreeMap::new(),
            local: None,
            identity_basis: None,
            child_ordinal: 0,
        }
    }
    pub fn observation_id(&self) -> &str {
        self.observation_id.as_str()
    }
    pub fn kind(&self) -> ObservationFamily {
        self.body.kind()
    }
    pub fn stage(&self) -> ObservationStage {
        self.stage
    }
    pub fn occurred_at(&self) -> Option<&SourceTimestamp> {
        self.occurred_at.as_ref()
    }
    pub fn observed_at(&self) -> &ObservedAt {
        &self.observed_at
    }
    pub fn sequence(&self) -> Option<u64> {
        self.sequence
    }
    pub fn session_id(&self) -> Option<&CorrelationId> {
        self.session_id.as_ref()
    }
    pub fn workflow_id(&self) -> Option<&CorrelationId> {
        self.workflow_id.as_ref()
    }
    pub fn correlation(&self) -> &CorrelationIds {
        &self.correlation
    }
    pub fn source(&self) -> &SourceProvenance {
        &self.source
    }
    pub fn body(&self) -> &ObservationBody {
        &self.body
    }
    pub fn facets(&self) -> &BTreeMap<String, SemanticFacet> {
        &self.facets
    }
    pub fn fact_metadata(&self) -> &BTreeMap<String, FactMetadata> {
        &self.fact_metadata
    }
    pub fn local(&self) -> Option<&LocalEvidence> {
        self.local.as_ref()
    }
    pub fn identity_basis(&self) -> &IdentityBasis {
        &self.identity_basis
    }
    pub fn validate(&self) -> Result<(), ObservationError> {
        Self::builder_from(self).validate_shape().and_then(|_| {
            validate_fingerprints(
                &self.body,
                &self.facets,
                &self.fact_metadata,
                self.local.as_ref(),
                &self.source,
                self.identity_basis.fingerprint_key_epoch_ref() == "unavailable",
            )
            .map(|_| ())
        })
    }
    fn builder_from(value: &Self) -> ObservationBuilder {
        ObservationBuilder {
            body: value.body.clone(),
            stage: value.stage,
            occurred_at: value.occurred_at.clone(),
            observed_at: value.observed_at.clone(),
            sequence: value.sequence,
            session_id: value.session_id.clone(),
            workflow_id: value.workflow_id.clone(),
            correlation: value.correlation.clone(),
            source: value.source.clone(),
            capability_context: value.capability_context.clone(),
            facets: value.facets.clone(),
            fact_metadata: value.fact_metadata.clone(),
            local: value.local.clone(),
            identity_basis: Some(value.identity_basis.clone()),
            child_ordinal: value.identity_basis.child_ordinal(),
        }
    }
}

fn has_observed_activity(
    body: &ObservationBody,
    metadata: &BTreeMap<String, FactMetadata>,
) -> bool {
    let activity_paths = match body {
        ObservationBody::Process(body) => [
            (body.operation().is_some(), "process.operation"),
            (body.state().is_some(), "process.state"),
        ],
        ObservationBody::File(body) => [
            (body.operation().is_some(), "file.operation"),
            (body.state().is_some(), "file.state"),
        ],
        ObservationBody::Network(body) => [
            (body.operation().is_some(), "network.operation"),
            (body.state().is_some(), "network.state"),
        ],
        _ => return false,
    };
    activity_paths.iter().any(|(populated, path)| {
        *populated
            && metadata
                .get(*path)
                .is_some_and(|item| item.provenance() == FactProvenance::Observed)
    })
}

fn validate_metadata_coverage(
    body: &ObservationBody,
    facets: &BTreeMap<String, SemanticFacet>,
    metadata: &BTreeMap<String, FactMetadata>,
) -> Result<(), ObservationError> {
    let mut expected: BTreeMap<String, ()> = body
        .semantic_fields()
        .into_iter()
        .map(|(path, _)| (path, ()))
        .collect();
    for path in facets.keys() {
        validate_facet_name(path)?;
        expected.insert(path.clone(), ());
    }
    if expected.len() != metadata.len() || expected.keys().ne(metadata.keys()) {
        return Err(ObservationError::new(ValidationCode::MetadataCoverage));
    }
    for (path, item) in metadata {
        if item.sensitivity() == Sensitivity::Prohibited
            || (item.sensitivity() == Sensitivity::Normal && !item.keyed_fingerprints().is_empty())
        {
            return Err(ObservationError::new(ValidationCode::InvalidMetadata));
        }
        if path.starts_with("native.") || path.is_empty() {
            return Err(ObservationError::new(ValidationCode::InvalidMetadata));
        }
    }
    Ok(())
}

fn validate_semantic_json_bounds(
    body: &ObservationBody,
    facets: &BTreeMap<String, SemanticFacet>,
) -> Result<(), ObservationError> {
    for (_, value) in body.semantic_fields() {
        validate_bounded_json(&value)?;
    }
    for facet in facets.values() {
        validate_bounded_json(facet.value())?;
    }
    Ok(())
}

fn validate_bounded_json(value: &JsonValue) -> Result<(), ObservationError> {
    if value::bounded_json_bytes(value, 1)? > LOCAL_MAX_VALUE_BYTES {
        return Err(ObservationError::new(ValidationCode::UnboundedValue));
    }
    Ok(())
}

fn validate_facet_name(name: &str) -> Result<(), ObservationError> {
    let Some((namespace, suffix)) = name.split_once('.') else {
        return Err(ObservationError::new(ValidationCode::InvalidFacet));
    };
    if !matches!(
        namespace,
        "session"
            | "message"
            | "tool"
            | "command"
            | "resource"
            | "network"
            | "process"
            | "inference"
            | "mcp"
            | "runtime"
            | "browser"
    ) || suffix.is_empty()
        || suffix.split('.').any(|part| {
            part.is_empty()
                || !part
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        })
    {
        return Err(ObservationError::new(ValidationCode::InvalidFacet));
    }
    Ok(())
}

fn validate_correlation_id(value: &CorrelationId) -> Result<(), ObservationError> {
    if value.value.is_empty() {
        Err(ObservationError::new(ValidationCode::InvalidCorrelation))
    } else {
        Ok(())
    }
}
fn validate_correlation_ids(value: &CorrelationIds) -> Result<(), ObservationError> {
    for item in [
        &value.turn_id,
        &value.request_id,
        &value.response_id,
        &value.call_id,
        &value.trace_id,
        &value.span_id,
        &value.delegation_id,
        &value.parent_observation_id,
        &value.process_instance_id,
    ]
    .into_iter()
    .flatten()
    {
        validate_correlation_id(item)?;
    }
    Ok(())
}

fn validate_fingerprints(
    body: &ObservationBody,
    facets: &BTreeMap<String, SemanticFacet>,
    metadata: &BTreeMap<String, FactMetadata>,
    local: Option<&LocalEvidence>,
    source: &SourceProvenance,
    allow_unkeyed: bool,
) -> Result<String, ObservationError> {
    let mut epochs = Vec::new();
    for (path, value) in body.semantic_fields() {
        let item = metadata
            .get(&path)
            .ok_or_else(|| ObservationError::new(ValidationCode::MetadataCoverage))?;
        epochs.extend(validate_value_fingerprints(
            &value,
            path.as_str(),
            item,
            allow_unkeyed,
        )?);
    }
    for (path, facet) in facets {
        let item = metadata
            .get(path)
            .ok_or_else(|| ObservationError::new(ValidationCode::MetadataCoverage))?;
        epochs.extend(validate_value_fingerprints(
            facet.value(),
            path,
            item,
            allow_unkeyed,
        )?);
    }
    if let Some(local) = local {
        for (key, value) in local.structured_values() {
            if value.sensitivity() == Sensitivity::Normal && value.keyed_fingerprint().is_some() {
                return Err(ObservationError::new(
                    ValidationCode::FingerprintSensitivity,
                ));
            }
            if value.sensitivity() != Sensitivity::Normal {
                if let Some(fingerprint) = value.keyed_fingerprint() {
                    if fingerprint.location() != format!("local.{key}") {
                        return Err(ObservationError::new(ValidationCode::InvalidFingerprint));
                    }
                    epochs.push(fingerprint.key_epoch_ref().to_owned());
                } else if !allow_unkeyed {
                    return Err(ObservationError::new(ValidationCode::ReplayUnverifiable));
                }
            }
        }
    }
    if source.producer_identity_key_ref.is_none() && !epochs.is_empty() {
        return Err(ObservationError::new(ValidationCode::InvalidFingerprint));
    }
    epochs.sort();
    epochs.dedup();
    if epochs.len() > 1 {
        return Err(ObservationError::new(ValidationCode::InvalidFingerprint));
    }
    Ok(epochs.into_iter().next().unwrap_or_else(|| {
        if allow_unkeyed {
            "unavailable".to_owned()
        } else {
            "none".to_owned()
        }
    }))
}

fn validate_value_fingerprints(
    value: &JsonValue,
    path: &str,
    metadata: &FactMetadata,
    allow_unkeyed: bool,
) -> Result<Vec<String>, ObservationError> {
    if metadata.sensitivity() == Sensitivity::Normal {
        return Ok(Vec::new());
    }
    let fingerprints = metadata.keyed_fingerprints();
    if path == "message.content_parts" {
        let JsonValue::Array(parts) = value else {
            return Err(ObservationError::new(ValidationCode::InvalidFingerprint));
        };
        if fingerprints.is_empty() {
            if allow_unkeyed {
                return Ok(Vec::new());
            }
            return Err(ObservationError::new(ValidationCode::ReplayUnverifiable));
        }
        if fingerprints.len() != parts.len() {
            return Err(ObservationError::new(ValidationCode::InvalidFingerprint));
        }
        let mut epochs = Vec::new();
        for index in 0..parts.len() {
            let expected = format!("{path}[{index}]");
            let fingerprint = fingerprints
                .iter()
                .find(|item| item.location() == expected)
                .ok_or_else(|| ObservationError::new(ValidationCode::InvalidFingerprint))?;
            epochs.push(fingerprint.key_epoch_ref().to_owned());
        }
        return Ok(epochs);
    }
    if fingerprints.is_empty() {
        if allow_unkeyed {
            return Ok(Vec::new());
        }
        return Err(ObservationError::new(ValidationCode::ReplayUnverifiable));
    }
    if fingerprints.len() != 1 || fingerprints[0].location() != path {
        return Err(ObservationError::new(ValidationCode::InvalidFingerprint));
    }
    Ok(vec![fingerprints[0].key_epoch_ref().to_owned()])
}

pub(crate) fn other_classification_allowed(kind: &str, classification: &str) -> bool {
    matches!(
        (kind, classification),
        (
            "adapter_notice",
            "capability_gap" | "schema_drift" | "source_boundary"
        ) | (
            "normalization_notice",
            "lossy_flattening" | "derived_value" | "omitted_source_fact"
        ) | (
            "privacy_notice",
            "redaction" | "local_only" | "reference_only"
        )
    )
}

#[cfg(test)]
mod tests;
