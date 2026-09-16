//! Non-production Event4 4.0 contract foundation.
//!
//! Inputs to this module must already have passed the future privacy/export
//! projection. Validation proves contract conformance, not that arbitrary text
//! is safe to export. This module performs no I/O and is not connected to the
//! production Event3 pipeline.
//!
//! Field declaration order in closed wire structs is the `event4-json-v1`
//! contract order. Open maps use [`OpenMap`] for NFC-normalized sorted keys.

mod validate;

use std::fmt;

use serde::Serialize;
use serde::ser::{SerializeMap, Serializer};
use unicode_normalization::UnicodeNormalization;

pub use validate::{
    AcceptanceDisposition, AcceptedEvent4, EVENT4_MAX_BYTES, EVENT4_MAX_DEPTH, EVENT4_SCHEMA,
    EVENT4_SERIALIZER_ID, EXTENSIONS_MAX_BYTES, EXTENSIONS_MAX_SCALARS, Event4AcceptanceEffect,
    Event4AcceptedFact, Event4ApprovalFact, Event4Context, Event4DecisionFact, Event4ErrorCategory,
    Event4InMemoryContext, Event4ValidationCode, Event4ValidationError, validate_event4_structure,
    validate_terminal,
};

pub const EVENT4_SCHEMA_VERSION: &str = "4.0";

macro_rules! string_enum {
    ($name:ident { $($variant:ident => $value:literal),+ $(,)? }) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub enum $name { $($variant),+ }

        impl $name {
            pub const ALL: &'static [Self] = &[$(Self::$variant),+];
            pub const fn as_str(self) -> &'static str {
                match self { $(Self::$variant => $value),+ }
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where S: Serializer {
                serializer.serialize_str(self.as_str())
            }
        }
    };
}

string_enum!(EventType {
    Session => "session", Observation => "observation", Finding => "finding",
    Decision => "decision", Action => "action", State => "state", Health => "health",
    Summary => "summary"
});

string_enum!(EventAction {
    SessionOpened => "session.opened", SessionUpdated => "session.updated",
    SessionClosed => "session.closed", MessageObserved => "message.observed",
    InferenceRequested => "inference.requested", InferenceCompleted => "inference.completed",
    InferenceFailed => "inference.failed", ToolProposed => "tool.proposed",
    ToolRequested => "tool.requested", ToolExecutionStarted => "tool.execution_started",
    ToolExecutionCompleted => "tool.execution_completed", ToolResultReturned => "tool.result_returned",
    ToolDefinitionChanged => "tool_definition.changed", McpInventoryChanged => "mcp.inventory_changed",
    ProcessObserved => "process.observed", FileObserved => "file.observed",
    NetworkObserved => "network.observed", BrowserObserved => "browser.observed",
    RuntimeObserved => "runtime.observed", RuleMatched => "rule.matched",
    SequenceMatched => "sequence.matched", GuardModelMatched => "guard_model.matched",
    ClassifierMatched => "classifier.matched", BaselineDeviation => "baseline.deviation",
    CorrelationMatched => "correlation.matched", PolicyEvaluated => "policy.evaluated",
    ApprovalRequested => "approval.requested", ApprovalResolved => "approval.resolved",
    EnforcementApplied => "enforcement.applied", EnforcementDegraded => "enforcement.degraded",
    RuntimeChanged => "runtime.changed", IsolationChanged => "isolation.changed",
    CapabilitiesChanged => "capabilities.changed", RulesetActivated => "ruleset.activated",
    PolicyActivated => "policy.activated", ToolsetChanged => "toolset.changed",
    SensorHeartbeat => "sensor.heartbeat", HealthDegraded => "health.degraded",
    HealthFailed => "health.failed", SummaryEmitted => "summary.emitted"
});

impl EventAction {
    pub const fn event_type(self) -> EventType {
        match self {
            Self::SessionOpened | Self::SessionUpdated | Self::SessionClosed => EventType::Session,
            Self::MessageObserved
            | Self::InferenceRequested
            | Self::InferenceCompleted
            | Self::InferenceFailed
            | Self::ToolProposed
            | Self::ToolRequested
            | Self::ToolExecutionStarted
            | Self::ToolExecutionCompleted
            | Self::ToolResultReturned
            | Self::ToolDefinitionChanged
            | Self::McpInventoryChanged
            | Self::ProcessObserved
            | Self::FileObserved
            | Self::NetworkObserved
            | Self::BrowserObserved
            | Self::RuntimeObserved => EventType::Observation,
            Self::RuleMatched
            | Self::SequenceMatched
            | Self::GuardModelMatched
            | Self::ClassifierMatched
            | Self::BaselineDeviation
            | Self::CorrelationMatched => EventType::Finding,
            Self::PolicyEvaluated | Self::ApprovalRequested | Self::ApprovalResolved => {
                EventType::Decision
            }
            Self::EnforcementApplied | Self::EnforcementDegraded => EventType::Action,
            Self::RuntimeChanged
            | Self::IsolationChanged
            | Self::CapabilitiesChanged
            | Self::RulesetActivated
            | Self::PolicyActivated
            | Self::ToolsetChanged
            | Self::SensorHeartbeat => EventType::State,
            Self::HealthDegraded | Self::HealthFailed => EventType::Health,
            Self::SummaryEmitted => EventType::Summary,
        }
    }
}

string_enum!(SessionLifecycle { Opened => "opened", Updated => "updated", Closed => "closed" });
string_enum!(ObservationKind {
    Message => "message", Inference => "inference", Tool => "tool",
    ToolDefinition => "tool_definition", Mcp => "mcp", Process => "process", File => "file",
    Network => "network", Browser => "browser", Runtime => "runtime", Session => "session",
    Other => "other"
});
string_enum!(ObservationStage {
    Observed => "observed", Requested => "requested", Completed => "completed", Failed => "failed",
    Proposed => "proposed", ExecutionStarted => "execution_started",
    ExecutionCompleted => "execution_completed", ResultReturned => "result_returned",
    Changed => "changed", InventoryChanged => "inventory_changed"
});
string_enum!(FactProvenance {
    Reported => "reported", Parsed => "parsed", Derived => "derived", Inferred => "inferred",
    Observed => "observed"
});
string_enum!(Availability { Supported => "supported", Unsupported => "unsupported", Unknown => "unknown" });
string_enum!(SourceMode {
    SessionStore => "session_store", Harness => "harness", Gateway => "gateway", Browser => "browser",
    OsContext => "os_context", Import => "import", Other => "other"
});
string_enum!(Fidelity { Exact => "exact", Partial => "partial", Lossy => "lossy" });
string_enum!(DetectorKind {
    Rule => "rule", Process => "process", Sequence => "sequence", Correlation => "correlation",
    Baseline => "baseline", GuardModel => "guard_model", Classifier => "classifier",
    Imported => "imported", External => "external"
});
string_enum!(FindingKind {
    SecurityDetection => "security_detection", PolicyViolation => "policy_violation",
    BehavioralDeviation => "behavioral_deviation", Guardrail => "guardrail",
    ComplianceObservation => "compliance_observation", ThreatHunt => "threat_hunt",
    Correlation => "correlation", Informational => "informational"
});
string_enum!(Severity { Informational => "informational", Low => "low", Medium => "medium", High => "high", Critical => "critical" });
string_enum!(Confidence { Low => "low", Medium => "medium", High => "high" });
string_enum!(EvidenceRepresentation {
    RedactedExcerpt => "redacted_excerpt", Hash => "hash", Classification => "classification",
    Count => "count", Reference => "reference"
});
string_enum!(Outcome {
    Allow => "allow", Observe => "observe", Warn => "warn", RequireApproval => "require_approval",
    Reprompt => "reprompt", Block => "block", Remediate => "remediate"
});
string_enum!(ApprovalState {
    Required => "required", Requested => "requested", Granted => "granted", Denied => "denied",
    Expired => "expired", Cancelled => "cancelled"
});
string_enum!(DecisionStatus { Evaluated => "evaluated", Degraded => "degraded", Pending => "pending", Cancelled => "cancelled" });
string_enum!(ActionStatus {
    Succeeded => "succeeded", Failed => "failed", Degraded => "degraded", Pending => "pending",
    Cancelled => "cancelled", Expired => "expired"
});
string_enum!(StateKind {
    Runtime => "runtime", Isolation => "isolation", Capabilities => "capabilities", Ruleset => "ruleset",
    Policy => "policy", Toolset => "toolset", Mcp => "mcp", Heartbeat => "heartbeat"
});
string_enum!(StateChange { Snapshot => "snapshot", Changed => "changed", Removed => "removed" });
string_enum!(HealthStatus { Healthy => "healthy", Degraded => "degraded", Failed => "failed", Unknown => "unknown" });
string_enum!(SummaryKind { AgentActivity => "agent_activity", FindingRollup => "finding_rollup" });
string_enum!(SummaryScope { Session => "session", Workflow => "workflow", Agent => "agent" });

/// An open Event4 map. Keys retain caller spelling until validation so NFC
/// collisions can be detected instead of silently overwritten.
#[derive(Clone, PartialEq)]
pub struct OpenMap<V>(Vec<(String, V)>);

impl<V> Default for OpenMap<V> {
    fn default() -> Self {
        Self(Vec::new())
    }
}

impl<V> OpenMap<V> {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn insert(&mut self, key: impl Into<String>, value: V) {
        self.0.push((key.into(), value));
    }
    pub fn from_entries(entries: impl IntoIterator<Item = (String, V)>) -> Self {
        Self(entries.into_iter().collect())
    }
    pub fn iter(&self) -> impl Iterator<Item = (&str, &V)> {
        self.0.iter().map(|(key, value)| (key.as_str(), value))
    }
    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl<V: fmt::Debug> fmt::Debug for OpenMap<V> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpenMap")
            .field("entries", &self.0.len())
            .finish()
    }
}

impl<V: Serialize> Serialize for OpenMap<V> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut entries: Vec<(String, &V)> = self
            .0
            .iter()
            .map(|(key, value)| (key.nfc().collect(), value))
            .collect();
        entries.sort_by(|left, right| left.0.cmp(&right.0));
        if entries.windows(2).any(|pair| pair[0].0 == pair[1].0) {
            return Err(serde::ser::Error::custom("duplicate normalized map key"));
        }
        let mut map = serializer.serialize_map(Some(entries.len()))?;
        for (key, value) in entries {
            map.serialize_entry(&key, value)?;
        }
        map.end()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum ExtensionScalar {
    String(String),
    Number(f64),
    Bool(bool),
    Null,
}

impl Serialize for ExtensionScalar {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::String(value) => serializer.serialize_str(value),
            Self::Number(value) => serializer.serialize_f64(*value),
            Self::Bool(value) => serializer.serialize_bool(*value),
            Self::Null => serializer.serialize_unit(),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum ExtensionValue {
    Scalar(ExtensionScalar),
    Array(Vec<ExtensionScalar>),
}

impl Serialize for ExtensionValue {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Scalar(value) => value.serialize(serializer),
            Self::Array(values) => values.serialize(serializer),
        }
    }
}

pub type Extensions = OpenMap<OpenMap<ExtensionValue>>;

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CapabilityOutcome {
    pub availability: Availability,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limitation: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Source {
    pub mode: SourceMode,
    pub adapter_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub adapter_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub native_event_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_path_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<String>,
    pub fidelity: Fidelity,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<OpenMap<Availability>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fact_provenance: Option<OpenMap<FactProvenance>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Default)]
pub struct Correlation {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub turn_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub call_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_observation_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_instance_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delegation_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SessionBody {
    pub session_id: String,
    pub lifecycle: SessionLifecycle,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ruleset_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capability_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub toolset_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mcp_ref: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ToolDescriptor {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_keys: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ObservationBody {
    pub observation_id: String,
    pub kind: ObservationKind,
    pub stage: ObservationStage,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provenance: Option<FactProvenance>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fact_provenance: Option<OpenMap<FactProvenance>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<OpenMap<Availability>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capability: Option<CapabilityOutcome>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<Source>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correlation: Option<Correlation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capability_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub toolset_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mcp_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool: Option<ToolDescriptor>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Detector {
    pub kind: DetectorKind,
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub engine: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_ref: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Evidence {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observation_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    pub representation: EvidenceRepresentation,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<ExtensionScalar>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct FindingBody {
    pub kind: FindingKind,
    pub category: String,
    pub severity: Severity,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub risk_points: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<Confidence>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence_score: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_ids: Option<Vec<String>>,
    pub detector: Detector,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub related_observation_ids: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ruleset_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capability_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub labels: Option<OpenMap<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub techniques: Option<OpenMap<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<Vec<Evidence>>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DecisionBody {
    pub requested: Outcome,
    pub effective: Outcome,
    pub status: DecisionStatus,
    pub reason_code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capability_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub basis_event_ids: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_state: Option<ApprovalState>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capability: Option<CapabilityOutcome>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub degradation_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ActionBody {
    pub action_id: String,
    pub decision_ref: String,
    pub requested: Outcome,
    pub effective: Outcome,
    pub status: ActionStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enforcement_point: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capability_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capability: Option<CapabilityOutcome>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub degradation_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct StateBody {
    pub kind: StateKind,
    pub state_ref: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub change: Option<StateChange>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct HealthBody {
    pub component: String,
    pub status: HealthStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SummaryBody {
    pub kind: SummaryKind,
    pub scope: SummaryScope,
    pub count: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub enum EventBody {
    Session(SessionBody),
    Observation(Box<ObservationBody>),
    Finding(Box<FindingBody>),
    Decision(DecisionBody),
    Action(ActionBody),
    State(StateBody),
    Health(HealthBody),
    Summary(SummaryBody),
}

impl EventBody {
    pub const fn event_type(&self) -> EventType {
        match self {
            Self::Session(_) => EventType::Session,
            Self::Observation(_) => EventType::Observation,
            Self::Finding(_) => EventType::Finding,
            Self::Decision(_) => EventType::Decision,
            Self::Action(_) => EventType::Action,
            Self::State(_) => EventType::State,
            Self::Health(_) => EventType::Health,
            Self::Summary(_) => EventType::Summary,
        }
    }
}

/// A post-privacy Event4 candidate before terminal materialization.
#[derive(Debug, Clone, PartialEq)]
pub struct Event4Candidate {
    pub schema_version: String,
    pub event_id: String,
    pub event_type: EventType,
    pub event_action: EventAction,
    pub occurred_at: Option<String>,
    pub observed_at: String,
    pub sequence: Option<u64>,
    pub session_id: Option<String>,
    pub workflow_id: Option<String>,
    pub trace_id: Option<String>,
    pub span_id: Option<String>,
    pub body: EventBody,
    pub extensions: Option<Extensions>,
}

impl Event4Candidate {
    /// Consumes the candidate and assigns the caller-selected terminal time.
    /// No clock is read and the returned value has no materialization setter.
    pub fn materialize(self, materialized_at: impl Into<String>) -> MaterializedEvent4 {
        MaterializedEvent4 {
            candidate: self,
            materialized_at: materialized_at.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct MaterializedEvent4 {
    candidate: Event4Candidate,
    materialized_at: String,
}

impl MaterializedEvent4 {
    pub(crate) fn candidate(&self) -> &Event4Candidate {
        &self.candidate
    }
    pub fn materialized_at(&self) -> &str {
        &self.materialized_at
    }
    pub fn event_id(&self) -> &str {
        &self.candidate.event_id
    }
    pub fn event_type(&self) -> EventType {
        self.candidate.event_type
    }
}

impl Serialize for MaterializedEvent4 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let event = &self.candidate;
        let mut map = serializer.serialize_map(None)?;
        map.serialize_entry("schema_version", &event.schema_version)?;
        map.serialize_entry("event_id", &event.event_id)?;
        map.serialize_entry("type", &event.event_type)?;
        map.serialize_entry("event_action", &event.event_action)?;
        if let Some(value) = &event.occurred_at {
            map.serialize_entry("occurred_at", value)?;
        }
        map.serialize_entry("observed_at", &event.observed_at)?;
        map.serialize_entry("materialized_at", &self.materialized_at)?;
        if let Some(value) = event.sequence {
            map.serialize_entry("sequence", &value)?;
        }
        if let Some(value) = &event.session_id {
            map.serialize_entry("session_id", value)?;
        }
        if let Some(value) = &event.workflow_id {
            map.serialize_entry("workflow_id", value)?;
        }
        if let Some(value) = &event.trace_id {
            map.serialize_entry("trace_id", value)?;
        }
        if let Some(value) = &event.span_id {
            map.serialize_entry("span_id", value)?;
        }
        match &event.body {
            EventBody::Session(value) => map.serialize_entry("session", value)?,
            EventBody::Observation(value) => map.serialize_entry("observation", value)?,
            EventBody::Finding(value) => map.serialize_entry("finding", value)?,
            EventBody::Decision(value) => map.serialize_entry("decision", value)?,
            EventBody::Action(value) => map.serialize_entry("action", value)?,
            EventBody::State(value) => map.serialize_entry("state", value)?,
            EventBody::Health(value) => map.serialize_entry("health", value)?,
            EventBody::Summary(value) => map.serialize_entry("summary", value)?,
        }
        if let Some(value) = &event.extensions {
            map.serialize_entry("extensions", value)?;
        }
        map.end()
    }
}

#[cfg(test)]
mod tests;
