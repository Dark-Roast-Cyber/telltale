//! A validated, typed consumer view of terminal Event 3.0 JSON.
//!
//! This module deliberately does not deserialize the native [`super::Event`].
//! Native events are trusted producer values; this API is the lower-level
//! boundary for already terminalized bytes supplied by another process.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::str::FromStr;
use std::sync::LazyLock;

use jsonschema::{Validator, validator_for};
use serde::Deserialize;
use serde_json::Value;
use uuid::Uuid;

use super::{
    NATIVE_SCHEMA_VERSION, is_canonical_opaque_identifier_for_kind, parse_event_timestamp,
    validate_risk_accounting_scope, validate_rule_ids,
};
use crate::scoring::{RiskContribution, canonicalize_contributions, checked_risk_sum};

/// The exact Event 3.0 schema used by the consumer boundary.
pub const EVENT3_SCHEMA: &str = include_str!("../../data/event-3.0.schema.json");

/// SHA-256 of the current and historical Event 3.0 schema artifact.
pub const EVENT3_SCHEMA_SHA256: &str =
    "9014a15c010bc613b4deb7e0195ec56f702e9e950fb13a12c6937a733e38d754";

/// Maximum input accepted by [`Event3Record::from_json`]. This is an API
/// resource bound and is not a limit declared by the Event 3.0 schema.
pub const EVENT3_MAX_INPUT_BYTES: usize = super::redaction::MAX_SERIALIZED_EVENT_BYTES;

static EVENT3_VALIDATOR: LazyLock<Result<Validator, ()>> = LazyLock::new(|| {
    let schema: Value = serde_json::from_str(EVENT3_SCHEMA).map_err(|_| ())?;
    validator_for(&schema).map_err(|_| ())
});

/// Stable error categories exposed by the Event 3.0 consumer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event3ErrorCategory {
    Malformed,
    Version,
    Structure,
    Identity,
    Semantic,
    Family,
}

/// Privacy-safe Event 3.0 consumer error.
///
/// The error stores only code-owned constants. It never stores a payload,
/// serde diagnostic, property value, path, or input-derived text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Event3ConsumerError {
    category: Event3ErrorCategory,
    code: &'static str,
}

impl Event3ConsumerError {
    const fn new(category: Event3ErrorCategory, code: &'static str) -> Self {
        Self { category, code }
    }

    pub const fn category(self) -> Event3ErrorCategory {
        self.category
    }

    pub const fn code(self) -> &'static str {
        self.code
    }
}

impl fmt::Display for Event3ConsumerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "event3 consumer error: {}", self.code)
    }
}

impl std::error::Error for Event3ConsumerError {}

/// Closed Event 3.0 timing source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event3TimeSource {
    Observed,
    Source,
    Override,
}

/// Closed Event 3.0 timing confidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event3TimeConfidence {
    Low,
    Medium,
    High,
}

/// Event 3.0 severity, including the operational warning value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event3Severity {
    Informational,
    Low,
    Medium,
    High,
    Critical,
    Warning,
}

/// Event 3.0 detection taxonomy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event3DetectionClass {
    SecurityDetection,
    PolicyViolation,
    ThreatHunting,
    ComplianceObservation,
    OperationalHealth,
    BaselineDeviation,
}

/// Event 3.0 signal type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event3SignalType {
    Atomic,
    Chain,
    Correlation,
    BaselineDeviation,
}

/// Event 3.0 analytic intent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event3AnalyticIntent {
    Alert,
    Hunt,
    Enrich,
    Baseline,
    Audit,
}

/// Event 3.0 process-chain confidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event3Confidence {
    Low,
    Medium,
    High,
}

/// Event 3.0 risk entity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event3RiskEntityType {
    Host,
    User,
    Session,
}

/// Common, family-independent Event 3.0 fields.
///
/// `event_id` identifies this Event 3.0 record only; it is not a session,
/// source, delivery-attempt, host, or device identity. `session_id` is semantic
/// agent-session correlation when present and is not globally unique across
/// machines. Host, device, tenant, and collector metadata are outside Event
/// 3.0. Family projections expose `source_path_hash` where applicable as
/// privacy-safe source correlation, not a path, not reversible, or host
/// identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event3Common {
    pub schema_version: String,
    pub event_id: String,
    pub telltale_version: String,
    pub timestamp: String,
    pub event_time: Option<String>,
    pub observed_at: String,
    pub ingested_at: String,
    pub time_source: Event3TimeSource,
    pub time_confidence: Event3TimeConfidence,
    pub time_override_reason: Option<String>,
    pub severity: Event3Severity,
    pub risk_score: u64,
    pub risk_contributions: Vec<RiskContribution>,
    pub client: String,
    pub agent: Option<String>,
    pub model: Option<String>,
    pub provider: Option<String>,
    pub session_id: String,
    pub tags: Vec<String>,
    pub evidence: Vec<Event3Evidence>,
}

/// Terminal evidence is typed separately from the native producer evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event3Evidence {
    pub field: String,
    pub redacted_value: String,
    pub hash: Option<String>,
    pub rule_id: Option<String>,
}

/// A terminal timeline anchor.
///
/// `entry_index` locates the corresponding normalized session timeline entry;
/// it is not a canonical observation ID and does not guarantee immutable
/// source-history storage. If source context later disappears, the containing
/// [`Event3Record`] remains authoritative while the richer session context may
/// be unavailable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event3TimelineAnchor {
    pub entry_index: usize,
    pub rule_ids: Vec<String>,
    pub categories: Vec<String>,
    pub evidence_fields: Vec<String>,
}

/// Typed response guidance.
///
/// These fields describe guidance for a consumer and do not represent an
/// executed action or authorize one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event3Response {
    pub recommended_action: String,
    pub response_playbook: String,
    pub investigation_summary: String,
    pub escalation: String,
}

/// The standard activity branch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event3StandardActivity {
    pub event_time: Option<String>,
    pub source_path_hash: String,
    pub tool_name: Option<String>,
}

/// The metadata-only install inventory branch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event3InstallInventoryActivity {
    pub component: String,
    pub check_name: String,
    pub status: String,
}

/// The two `activity` branches remain distinct in the typed API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event3Activity {
    Standard(Event3StandardActivity),
    InstallInventory(Event3InstallInventoryActivity),
}

/// A detection projection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event3Detection {
    pub event_time: Option<String>,
    pub source_path_hash: String,
    pub tool_name: Option<String>,
    pub rule_ids: Vec<String>,
    pub categories: Vec<String>,
    pub detection_classes: Vec<Event3DetectionClass>,
    pub signal_types: Vec<Event3SignalType>,
    pub analytic_intents: Vec<Event3AnalyticIntent>,
    pub atlas_tags: Vec<String>,
    pub timeline_anchors: Vec<Event3TimelineAnchor>,
    pub response: Option<Event3Response>,
}

/// A session risk summary projection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event3SessionRiskSummary {
    pub event_time: Option<String>,
    pub source_path_hash: Option<String>,
    pub rule_ids: Vec<String>,
    pub categories: Vec<String>,
    pub detection_classes: Vec<Event3DetectionClass>,
    pub signal_types: Vec<Event3SignalType>,
    pub analytic_intents: Vec<Event3AnalyticIntent>,
    pub atlas_tags: Vec<String>,
}

/// A scanner health projection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event3Health {
    pub source_counts: BTreeMap<String, u32>,
    pub component: String,
    pub check_name: String,
    pub status: String,
    pub scan_duration_ms: u64,
    pub rule_count: usize,
    pub threshold_config: Event3Thresholds,
    pub active_policy_name: Option<String>,
    pub emitted_count: u64,
    pub suppressed_count: u64,
    pub scanner_error_count: u64,
}

/// Numeric health thresholds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Event3Thresholds {
    pub low: u32,
    pub medium: u32,
    pub high: u32,
    pub critical: u32,
}

/// A scanner-error projection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event3ScannerError {
    pub source_path_hash: String,
    pub component: String,
    pub check_name: String,
    pub status: String,
}

/// An operational-alert projection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event3OperationalAlert {
    pub categories: Vec<String>,
    pub detection_classes: Vec<Event3DetectionClass>,
    pub signal_types: Vec<Event3SignalType>,
    pub analytic_intents: Vec<Event3AnalyticIntent>,
    pub component: String,
    pub check_name: String,
    pub status: String,
    pub scan_duration_ms: Option<u64>,
    pub scanner_error_count: Option<u64>,
}

/// A terminal process context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event3ProcessContext {
    pub host: Option<String>,
    pub user: Option<String>,
    pub source_process_name: String,
    pub source_process_path: Option<String>,
    pub source_process_id: Option<u64>,
    pub source_process_command_line: Option<String>,
    pub target_process_name: String,
    pub target_process_path: Option<String>,
    pub target_process_id: Option<u64>,
    pub target_process_command_line: Option<String>,
    pub parent_process_name: Option<String>,
    pub parent_process_path: Option<String>,
    pub source_event_id: Option<String>,
    pub source_process_inferred: bool,
    pub rule_name: String,
    pub secondary_rule_ids: Vec<String>,
    pub investigation_fields: Vec<String>,
    pub falsepositives: Vec<String>,
    pub dedup_key: String,
    pub suppression_window_seconds: u64,
    pub rule_severity: String,
    pub risk_adjustment: Option<String>,
}

/// A process-chain projection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event3ProcessChain {
    pub event_time: Option<String>,
    pub source_path_hash: String,
    pub tool_name: Option<String>,
    pub rule_ids: Vec<String>,
    pub categories: Vec<String>,
    pub detection_classes: Vec<Event3DetectionClass>,
    pub signal_types: Vec<Event3SignalType>,
    pub analytic_intents: Vec<Event3AnalyticIntent>,
    pub response: Event3Response,
    pub informational: bool,
    pub confidence: Event3Confidence,
    pub detection_reason: String,
    pub mitre_attack_techniques: Vec<String>,
    pub risk_entity_type: Event3RiskEntityType,
    pub risk_entity_value: String,
    pub process: Event3ProcessContext,
}

/// A cross-session correlation projection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event3Correlation {
    pub event_time: String,
    pub rule_ids: Vec<String>,
    pub categories: Vec<String>,
    pub detection_classes: Vec<Event3DetectionClass>,
    pub signal_types: Vec<Event3SignalType>,
    pub analytic_intents: Vec<Event3AnalyticIntent>,
}

/// The reviewed nine-family Event 3.0 projection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event3Family {
    Detection(Event3Detection),
    Activity(Event3Activity),
    SessionRiskSummary(Event3SessionRiskSummary),
    Health(Event3Health),
    ScannerError(Event3ScannerError),
    OperationalAlert(Event3OperationalAlert),
    ProcessChain(Box<Event3ProcessChain>),
    Correlation(Event3Correlation),
}

impl Event3Family {
    pub const fn event_type(&self) -> &'static str {
        match self {
            Self::Detection(_) => "detection",
            Self::Activity(_) => "activity",
            Self::SessionRiskSummary(_) => "session_risk_summary",
            Self::Health(_) => "health",
            Self::ScannerError(_) => "scanner_error",
            Self::OperationalAlert(_) => "operational_alert",
            Self::ProcessChain(_) => "process_chain",
            Self::Correlation(_) => "correlation",
        }
    }
}

/// A complete, validated typed view of one terminal Event 3.0 record.
///
/// Native [`super::Event`] is the trusted producer model; this type consumes
/// already terminal-safe bytes and is not a producer, provenance record,
/// session-store reader, or action executor. `event_id` is the record identity,
/// not a session, source, delivery-attempt, host, or device identity. Event
/// 3.0 has no public scan/run identity, and health counters are not scan IDs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event3Record {
    common: Event3Common,
    family: Event3Family,
}

impl Event3Record {
    /// Parse one complete terminal Event 3.0 JSON object.
    pub fn from_json(bytes: &[u8]) -> Result<Self, Event3ConsumerError> {
        if bytes.len() > EVENT3_MAX_INPUT_BYTES {
            return Err(Event3ConsumerError::new(
                Event3ErrorCategory::Structure,
                "input_too_large",
            ));
        }
        let value: Value = serde_json::from_slice(bytes).map_err(|_| {
            Event3ConsumerError::new(Event3ErrorCategory::Malformed, "malformed_json")
        })?;
        Self::from_value(value)
    }

    /// Alias for [`Self::from_json`] for callers that prefer parser language.
    pub fn parse(bytes: &[u8]) -> Result<Self, Event3ConsumerError> {
        Self::from_json(bytes)
    }

    /// Parse a UTF-8 JSON string without exposing a parsing diagnostic.
    pub fn from_json_str(json: &str) -> Result<Self, Event3ConsumerError> {
        Self::from_json(json.as_bytes())
    }

    pub fn common(&self) -> &Event3Common {
        &self.common
    }

    pub fn family(&self) -> &Event3Family {
        &self.family
    }

    pub fn event_type(&self) -> &'static str {
        self.family.event_type()
    }

    fn from_value(value: Value) -> Result<Self, Event3ConsumerError> {
        let object = value.as_object().ok_or_else(|| {
            Event3ConsumerError::new(Event3ErrorCategory::Structure, "event_not_object")
        })?;
        let version = object.get("schema_version").ok_or_else(|| {
            Event3ConsumerError::new(Event3ErrorCategory::Version, "missing_schema_version")
        })?;
        let version = version.as_str().ok_or_else(|| {
            Event3ConsumerError::new(Event3ErrorCategory::Version, "schema_version_not_string")
        })?;
        if version != NATIVE_SCHEMA_VERSION {
            return Err(Event3ConsumerError::new(
                Event3ErrorCategory::Version,
                "unsupported_schema_version",
            ));
        }

        let validator = EVENT3_VALIDATOR.as_ref().map_err(|_| {
            Event3ConsumerError::new(Event3ErrorCategory::Structure, "schema_unavailable")
        })?;
        if validator.validate(&value).is_err() {
            return Err(classify_schema_failure(object));
        }

        let wire: Event3Wire = serde_json::from_value(value).map_err(|_| {
            Event3ConsumerError::new(Event3ErrorCategory::Structure, "wire_deserialization")
        })?;
        validate_wire(&wire)?;
        project_wire(wire)
    }
}

impl FromStr for Event3Record {
    type Err = Event3ConsumerError;

    fn from_str(json: &str) -> Result<Self, Self::Err> {
        Self::from_json_str(json)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Event3Wire {
    schema_version: String,
    event_id: String,
    telltale_version: String,
    timestamp: String,
    #[serde(default)]
    event_time: Option<String>,
    observed_at: String,
    ingested_at: String,
    time_source: String,
    time_confidence: String,
    #[serde(default)]
    time_override_reason: Option<String>,
    event_type: String,
    severity: String,
    risk_score: u64,
    risk_contributions: Vec<RiskContribution>,
    client: String,
    #[serde(default)]
    agent: Option<String>,
    #[serde(default)]
    model: Option<String>,
    #[serde(default)]
    provider: Option<String>,
    session_id: String,
    #[serde(default)]
    source_path_hash: Option<String>,
    #[serde(default)]
    tool_name: Option<String>,
    #[serde(default)]
    rule_ids: Vec<String>,
    #[serde(default)]
    categories: Vec<String>,
    #[serde(default)]
    detection_classes: Vec<String>,
    #[serde(default)]
    signal_types: Vec<String>,
    #[serde(default)]
    analytic_intents: Vec<String>,
    #[serde(default)]
    atlas_tags: Vec<String>,
    tags: Vec<String>,
    evidence: Vec<WireEvidence>,
    #[serde(default)]
    timeline_anchors: Vec<WireTimelineAnchor>,
    #[serde(default)]
    response: Option<WireResponse>,
    #[serde(default)]
    source_counts: Option<BTreeMap<String, u32>>,
    #[serde(default)]
    component: Option<String>,
    #[serde(default)]
    check_name: Option<String>,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    scan_duration_ms: Option<u64>,
    #[serde(default)]
    rule_count: Option<usize>,
    #[serde(default)]
    threshold_config: Option<WireThresholds>,
    #[serde(default)]
    active_policy_name: Option<String>,
    #[serde(default)]
    emitted_count: Option<u64>,
    #[serde(default)]
    suppressed_count: Option<u64>,
    #[serde(default)]
    scanner_error_count: Option<u64>,
    #[serde(default)]
    informational: Option<bool>,
    #[serde(default)]
    confidence: Option<String>,
    #[serde(default)]
    detection_reason: Option<String>,
    #[serde(default)]
    mitre_attack_techniques: Vec<String>,
    #[serde(default)]
    risk_entity_type: Option<String>,
    #[serde(default)]
    risk_entity_value: Option<String>,
    #[serde(default)]
    process: Option<WireProcessContext>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireEvidence {
    field: String,
    redacted_value: String,
    #[serde(default)]
    hash: Option<String>,
    #[serde(default)]
    rule_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireTimelineAnchor {
    entry_index: usize,
    rule_ids: Vec<String>,
    categories: Vec<String>,
    evidence_fields: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireResponse {
    recommended_action: String,
    response_playbook: String,
    investigation_summary: String,
    escalation: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireThresholds {
    low: u32,
    medium: u32,
    high: u32,
    critical: u32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireProcessContext {
    #[serde(default)]
    host: Option<String>,
    #[serde(default)]
    user: Option<String>,
    source_process_name: String,
    #[serde(default)]
    source_process_path: Option<String>,
    #[serde(default)]
    source_process_id: Option<u64>,
    #[serde(default)]
    source_process_command_line: Option<String>,
    target_process_name: String,
    #[serde(default)]
    target_process_path: Option<String>,
    #[serde(default)]
    target_process_id: Option<u64>,
    #[serde(default)]
    target_process_command_line: Option<String>,
    #[serde(default)]
    parent_process_name: Option<String>,
    #[serde(default)]
    parent_process_path: Option<String>,
    #[serde(default)]
    source_event_id: Option<String>,
    source_process_inferred: bool,
    rule_name: String,
    #[serde(default)]
    secondary_rule_ids: Vec<String>,
    #[serde(default)]
    investigation_fields: Vec<String>,
    #[serde(default)]
    falsepositives: Vec<String>,
    dedup_key: String,
    suppression_window_seconds: u64,
    rule_severity: String,
    #[serde(default)]
    risk_adjustment: Option<String>,
}

const KNOWN_FIELDS: &[&str] = &[
    "schema_version",
    "event_id",
    "telltale_version",
    "timestamp",
    "event_time",
    "observed_at",
    "ingested_at",
    "time_source",
    "time_confidence",
    "time_override_reason",
    "event_type",
    "severity",
    "risk_score",
    "risk_contributions",
    "client",
    "agent",
    "model",
    "provider",
    "session_id",
    "source_path_hash",
    "tool_name",
    "rule_ids",
    "categories",
    "detection_classes",
    "signal_types",
    "analytic_intents",
    "atlas_tags",
    "tags",
    "evidence",
    "timeline_anchors",
    "response",
    "source_counts",
    "component",
    "check_name",
    "status",
    "scan_duration_ms",
    "rule_count",
    "threshold_config",
    "active_policy_name",
    "emitted_count",
    "suppressed_count",
    "scanner_error_count",
    "informational",
    "confidence",
    "detection_reason",
    "mitre_attack_techniques",
    "risk_entity_type",
    "risk_entity_value",
    "process",
];

fn classify_schema_failure(object: &serde_json::Map<String, Value>) -> Event3ConsumerError {
    if !object
        .keys()
        .all(|field| KNOWN_FIELDS.contains(&field.as_str()))
    {
        return Event3ConsumerError::new(Event3ErrorCategory::Structure, "extra_property");
    }
    let Some(event_type) = object.get("event_type").and_then(Value::as_str) else {
        return Event3ConsumerError::new(Event3ErrorCategory::Family, "missing_event_family");
    };
    if !matches!(
        event_type,
        "activity"
            | "detection"
            | "session_risk_summary"
            | "health"
            | "scanner_error"
            | "operational_alert"
            | "process_chain"
            | "correlation"
    ) {
        return Event3ConsumerError::new(Event3ErrorCategory::Family, "unknown_event_family");
    }
    if object
        .get("event_id")
        .is_some_and(|value| value.as_str().is_some_and(|id| !is_event_id(id)))
        || object.get("timestamp").is_some_and(|value| {
            value
                .as_str()
                .is_some_and(|timestamp| parse_event_timestamp(timestamp).is_none())
        })
        || object.get("observed_at").is_some_and(|value| {
            value
                .as_str()
                .is_some_and(|timestamp| parse_event_timestamp(timestamp).is_none())
        })
        || object.get("ingested_at").is_some_and(|value| {
            value
                .as_str()
                .is_some_and(|timestamp| parse_event_timestamp(timestamp).is_none())
        })
    {
        return Event3ConsumerError::new(Event3ErrorCategory::Identity, "invalid_identity_or_time");
    }
    if has_invalid_taxonomy(object) {
        return Event3ConsumerError::new(Event3ErrorCategory::Semantic, "invalid_taxonomy");
    }
    if has_missing_common_field(object) {
        return Event3ConsumerError::new(Event3ErrorCategory::Structure, "missing_common_field");
    }
    if family_shape_is_incomplete(object, event_type) {
        return Event3ConsumerError::new(Event3ErrorCategory::Family, "incomplete_event_family");
    }
    Event3ConsumerError::new(Event3ErrorCategory::Structure, "schema_violation")
}

fn has_missing_common_field(object: &serde_json::Map<String, Value>) -> bool {
    [
        "schema_version",
        "event_id",
        "telltale_version",
        "timestamp",
        "observed_at",
        "ingested_at",
        "time_source",
        "time_confidence",
        "severity",
        "risk_score",
        "risk_contributions",
        "client",
        "session_id",
        "tags",
        "evidence",
    ]
    .iter()
    .any(|field| !object.contains_key(*field))
}

fn family_shape_is_incomplete(object: &serde_json::Map<String, Value>, event_type: &str) -> bool {
    let required: &[&str] = match event_type {
        "activity" if object.get("client").and_then(Value::as_str) == Some("install_inventory") => {
            &["component", "check_name", "status"]
        }
        "activity" => &["source_path_hash"],
        "detection" => &[
            "source_path_hash",
            "rule_ids",
            "categories",
            "detection_classes",
            "signal_types",
            "analytic_intents",
        ],
        "health" => &[
            "source_counts",
            "component",
            "check_name",
            "status",
            "scan_duration_ms",
            "rule_count",
            "threshold_config",
            "emitted_count",
            "suppressed_count",
            "scanner_error_count",
        ],
        "scanner_error" => &["source_path_hash", "component", "check_name", "status"],
        "operational_alert" => &[
            "categories",
            "detection_classes",
            "signal_types",
            "analytic_intents",
            "component",
            "check_name",
            "status",
        ],
        "process_chain" => &[
            "rule_ids",
            "categories",
            "detection_classes",
            "signal_types",
            "analytic_intents",
            "response",
            "informational",
            "confidence",
            "detection_reason",
            "risk_entity_type",
            "risk_entity_value",
            "process",
        ],
        "correlation" => &[
            "event_time",
            "rule_ids",
            "categories",
            "detection_classes",
            "signal_types",
            "analytic_intents",
        ],
        _ => &[],
    };
    required.iter().any(|field| !object.contains_key(*field))
}

fn has_invalid_taxonomy(object: &serde_json::Map<String, Value>) -> bool {
    let allowed = [
        (
            "time_source",
            &["observed", "source", "override"] as &[&str],
        ),
        ("time_confidence", &["low", "medium", "high"]),
        (
            "severity",
            &[
                "informational",
                "low",
                "medium",
                "high",
                "critical",
                "warning",
            ],
        ),
        (
            "detection_classes",
            &[
                "security_detection",
                "policy_violation",
                "threat_hunting",
                "compliance_observation",
                "operational_health",
                "baseline_deviation",
            ],
        ),
        (
            "signal_types",
            &["atomic", "chain", "correlation", "baseline_deviation"],
        ),
        (
            "analytic_intents",
            &["alert", "hunt", "enrich", "baseline", "audit"],
        ),
        ("confidence", &["low", "medium", "high"]),
        ("risk_entity_type", &["host", "user", "session"]),
    ];
    allowed.iter().any(|(field, values)| {
        let Some(value) = object.get(*field) else {
            return false;
        };
        match value {
            Value::String(value) => !values.contains(&value.as_str()),
            Value::Array(values) => values.iter().any(|value| {
                value
                    .as_str()
                    .is_none_or(|value| !values_for(field).contains(&value))
            }),
            _ => false,
        }
    })
}

fn values_for(field: &str) -> &'static [&'static str] {
    match field {
        "detection_classes" => &[
            "security_detection",
            "policy_violation",
            "threat_hunting",
            "compliance_observation",
            "operational_health",
            "baseline_deviation",
        ],
        "signal_types" => &["atomic", "chain", "correlation", "baseline_deviation"],
        "analytic_intents" => &["alert", "hunt", "enrich", "baseline", "audit"],
        _ => &[],
    }
}

fn validate_wire(wire: &Event3Wire) -> Result<(), Event3ConsumerError> {
    if wire.schema_version != NATIVE_SCHEMA_VERSION {
        return Err(Event3ConsumerError::new(
            Event3ErrorCategory::Version,
            "unsupported_schema_version",
        ));
    }
    if !is_event_id(&wire.event_id)
        || parse_event_timestamp(&wire.timestamp).is_none()
        || parse_event_timestamp(&wire.observed_at).is_none()
        || parse_event_timestamp(&wire.ingested_at).is_none()
    {
        return Err(Event3ConsumerError::new(
            Event3ErrorCategory::Identity,
            "invalid_identity_or_time",
        ));
    }
    validate_timing_relationships(wire)?;
    if wire
        .event_time
        .as_deref()
        .is_some_and(|value| !is_valid_event_time(value))
        || !is_safe_semver(&wire.telltale_version)
    {
        return Err(Event3ConsumerError::new(
            Event3ErrorCategory::Semantic,
            "invalid_time_or_version_metadata",
        ));
    }
    validate_non_empty_strings(&wire.tags)?;
    validate_rule_ids(&wire.rule_ids).map_err(|_| semantic("invalid_rule_id"))?;
    validate_dimensions(wire)?;
    validate_evidence(wire)?;
    validate_anchors(wire)?;
    validate_risk(wire)?;

    match wire.event_type.as_str() {
        "activity" => validate_activity(wire),
        "detection" => validate_detection(wire),
        "session_risk_summary" => validate_summary(wire),
        "health" => validate_health(wire),
        "scanner_error" => validate_scanner_error(wire),
        "operational_alert" => validate_operational_alert(wire),
        "process_chain" => validate_process_chain(wire),
        "correlation" => validate_correlation(wire),
        _ => Err(Event3ConsumerError::new(
            Event3ErrorCategory::Family,
            "unknown_event_family",
        )),
    }
}

fn semantic(code: &'static str) -> Event3ConsumerError {
    Event3ConsumerError::new(Event3ErrorCategory::Semantic, code)
}

fn family(code: &'static str) -> Event3ConsumerError {
    Event3ConsumerError::new(Event3ErrorCategory::Family, code)
}

fn validate_timing_relationships(wire: &Event3Wire) -> Result<(), Event3ConsumerError> {
    let timestamp = parse_event_timestamp(&wire.timestamp).ok_or_else(|| {
        Event3ConsumerError::new(Event3ErrorCategory::Identity, "invalid_identity_or_time")
    })?;
    let observed_at = parse_event_timestamp(&wire.observed_at).ok_or_else(|| {
        Event3ConsumerError::new(Event3ErrorCategory::Identity, "invalid_identity_or_time")
    })?;

    let valid = match wire.time_source.as_str() {
        "source" => {
            wire.time_override_reason.is_none()
                && wire
                    .event_time
                    .as_deref()
                    .and_then(parse_event_timestamp)
                    .is_some_and(|event_time| event_time == timestamp)
        }
        "observed" => {
            wire.event_time.is_none()
                && wire.time_override_reason.is_some()
                && timestamp == observed_at
        }
        "override" => {
            wire.event_time.is_some()
                && wire.time_override_reason.is_some()
                && timestamp == observed_at
        }
        _ => true,
    };

    if !valid {
        return Err(semantic("invalid_time_relationship"));
    }
    Ok(())
}

fn validate_non_empty_strings(values: &[String]) -> Result<(), Event3ConsumerError> {
    if values.iter().any(|value| value.is_empty()) {
        return Err(semantic("empty_text"));
    }
    Ok(())
}

fn validate_dimensions(wire: &Event3Wire) -> Result<(), Event3ConsumerError> {
    validate_non_empty_strings(&wire.rule_ids)?;
    validate_non_empty_strings(&wire.categories)?;
    validate_non_empty_strings(&wire.detection_classes)?;
    validate_non_empty_strings(&wire.signal_types)?;
    validate_non_empty_strings(&wire.analytic_intents)?;
    validate_non_empty_strings(&wire.atlas_tags)?;
    if wire
        .detection_classes
        .iter()
        .any(|value| parse_detection_class(value).is_none())
        || wire
            .signal_types
            .iter()
            .any(|value| parse_signal_type(value).is_none())
        || wire
            .analytic_intents
            .iter()
            .any(|value| parse_analytic_intent(value).is_none())
    {
        return Err(semantic("invalid_taxonomy"));
    }
    Ok(())
}

fn validate_evidence(wire: &Event3Wire) -> Result<(), Event3ConsumerError> {
    if wire.evidence.iter().any(|item| item.field.is_empty()) {
        return Err(semantic("invalid_evidence"));
    }
    for item in &wire.evidence {
        if let Some(rule_id) = item.rule_id.as_ref() {
            validate_rule_ids(std::slice::from_ref(rule_id))
                .map_err(|_| semantic("invalid_evidence_rule_id"))?;
        }
    }
    Ok(())
}

fn validate_anchors(wire: &Event3Wire) -> Result<(), Event3ConsumerError> {
    let mut indexes = BTreeSet::new();
    for anchor in &wire.timeline_anchors {
        if !indexes.insert(anchor.entry_index)
            || anchor.rule_ids.is_empty()
            || anchor.categories.is_empty()
            || anchor.evidence_fields.is_empty()
            || anchor.rule_ids.iter().any(|rule_id| !is_rule_id(rule_id))
            || anchor
                .categories
                .iter()
                .chain(anchor.evidence_fields.iter())
                .any(|value| value.is_empty())
        {
            return Err(semantic("invalid_timeline_anchor"));
        }
    }
    Ok(())
}

fn validate_risk(wire: &Event3Wire) -> Result<(), Event3ConsumerError> {
    let canonical = canonicalize_contributions(wire.risk_contributions.clone())
        .map_err(|_| semantic("invalid_risk_contributions"))?;
    if canonical != wire.risk_contributions {
        return Err(semantic("noncanonical_risk_contributions"));
    }
    checked_risk_sum(&wire.risk_contributions)
        .map_err(|_| semantic("invalid_risk_contributions"))?;
    let accounting_event_type = if wire.event_type == "process_chain" {
        "detection"
    } else {
        wire.event_type.as_str()
    };
    validate_risk_accounting_scope(
        accounting_event_type,
        &wire.rule_ids,
        &wire.risk_contributions,
    )
    .map_err(|_| semantic("invalid_risk_scope"))?;
    Ok(())
}

fn validate_activity(wire: &Event3Wire) -> Result<(), Event3ConsumerError> {
    if wire.client == "install_inventory" {
        if wire.time_source != "observed"
            || wire.time_confidence != "low"
            || wire.severity != "informational"
            || wire.session_id != "scanner"
            || wire.risk_score != 0
            || !wire.risk_contributions.is_empty()
            || wire.source_path_hash.is_some()
            || wire.tags.len() != 3
            || !wire.tags.iter().any(|tag| tag == "scanner")
            || !wire.tags.iter().any(|tag| tag == "install_inventory")
            || !wire.tags.iter().any(|tag| tag == "metadata_only")
            || wire.evidence.is_empty()
            || wire.component.as_deref() != Some("scanner")
            || wire.check_name.as_deref() != Some("install_inventory")
            || wire.status.as_deref() != Some("ok")
            || !no_detection_dimensions(wire)
            || !no_process_fields(wire)
            || wire.response.is_some()
            || wire.source_counts.is_some()
        {
            return Err(family("invalid_install_inventory_activity"));
        }
    } else if wire.severity == "warning"
        || wire.source_path_hash.is_none()
        || !no_detection_dimensions(wire)
        || !no_process_fields(wire)
        || wire.response.is_some()
        || wire.source_counts.is_some()
    {
        return Err(family("invalid_standard_activity"));
    }
    if wire.risk_score != checked_risk_sum(&wire.risk_contributions).unwrap_or(u64::MAX) {
        return Err(semantic("risk_score_mismatch"));
    }
    Ok(())
}

fn validate_detection(wire: &Event3Wire) -> Result<(), Event3ConsumerError> {
    let suppressed = wire.tags.iter().any(|tag| tag == "suppressed");
    if wire.severity == "warning"
        || wire.rule_ids.is_empty()
        || wire.categories.is_empty()
        || wire.detection_classes.is_empty()
        || wire.signal_types.is_empty()
        || wire.analytic_intents.is_empty()
        || wire.source_path_hash.is_none()
        || wire.component.is_some()
        || wire.check_name.is_some()
        || wire.status.is_some()
        || wire.confidence.is_some()
        || wire.risk_entity_type.is_some()
        || wire.process.is_some()
        || wire.source_counts.is_some()
        || wire.informational.is_some()
        || wire.detection_reason.is_some()
        || !wire.mitre_attack_techniques.is_empty()
    {
        return Err(family("invalid_detection_family"));
    }
    if suppressed {
        if wire.response.is_some()
            || wire.severity != "informational"
            || wire.risk_score != 0
            || !wire.risk_contributions.is_empty()
            || !wire.timeline_anchors.is_empty()
        {
            return Err(semantic("invalid_suppressed_detection"));
        }
    } else {
        if wire.response.is_none() {
            return Err(semantic("missing_response_guidance"));
        }
        if wire.risk_score != checked_risk_sum(&wire.risk_contributions).unwrap_or(u64::MAX) {
            return Err(semantic("risk_score_mismatch"));
        }
    }
    Ok(())
}

fn validate_summary(wire: &Event3Wire) -> Result<(), Event3ConsumerError> {
    if wire.severity == "warning"
        || wire.component.is_some()
        || wire.check_name.is_some()
        || wire.status.is_some()
        || !no_process_fields(wire)
        || wire.response.is_some()
        || wire.source_counts.is_some()
        || wire.risk_score != checked_risk_sum(&wire.risk_contributions).unwrap_or(u64::MAX)
    {
        return Err(family("invalid_session_summary"));
    }
    Ok(())
}

fn validate_health(wire: &Event3Wire) -> Result<(), Event3ConsumerError> {
    if wire.severity != "informational"
        || wire.session_id != "scanner"
        || wire.component.as_deref() != Some("scanner")
        || wire.check_name.as_deref() != Some("source_discovery")
        || wire.status.as_deref() != Some("ok")
        || wire.source_counts.is_none()
        || !no_detection_dimensions(wire)
        || !no_process_fields(wire)
        || wire.response.is_some()
        || wire.risk_score != 0
        || !wire.risk_contributions.is_empty()
    {
        return Err(family("invalid_health_family"));
    }
    Ok(())
}

fn validate_scanner_error(wire: &Event3Wire) -> Result<(), Event3ConsumerError> {
    if wire.severity != "informational"
        || wire.session_id != "scanner"
        || wire.source_path_hash.is_none()
        || wire.component.as_deref() != Some("scanner")
        || wire.check_name.as_deref() != Some("source_parse")
        || wire.status.as_deref() != Some("degraded")
        || !no_detection_dimensions(wire)
        || !no_process_fields(wire)
        || wire.response.is_some()
        || wire.source_counts.is_some()
        || wire.risk_score != 0
        || !wire.risk_contributions.is_empty()
    {
        return Err(family("invalid_scanner_error_family"));
    }
    Ok(())
}

fn validate_operational_alert(wire: &Event3Wire) -> Result<(), Event3ConsumerError> {
    if wire.severity != "warning"
        || wire.client != "scanner"
        || wire.session_id != "scanner"
        || wire.categories.is_empty()
        || wire.detection_classes.is_empty()
        || wire
            .detection_classes
            .iter()
            .any(|value| value != "operational_health")
        || wire.signal_types.is_empty()
        || wire.signal_types.iter().any(|value| value != "atomic")
        || wire.analytic_intents.is_empty()
        || wire.analytic_intents.iter().any(|value| value != "alert")
        || wire.component.as_deref() != Some("scanner")
        || !matches!(
            wire.check_name.as_deref(),
            Some(
                "scanner_error_threshold"
                    | "scan_duration_threshold"
                    | "sink_delivery"
                    | "operational_alert"
            )
        )
        || wire.status.as_deref() != Some("degraded")
        || !no_process_fields(wire)
        || wire.response.is_some()
        || wire.source_counts.is_some()
        || wire.risk_score != 0
        || !wire.risk_contributions.is_empty()
    {
        return Err(family("invalid_operational_alert_family"));
    }
    Ok(())
}

fn validate_process_chain(wire: &Event3Wire) -> Result<(), Event3ConsumerError> {
    if wire.severity == "warning"
        || wire.rule_ids.is_empty()
        || wire.categories.is_empty()
        || wire.detection_classes.is_empty()
        || wire.signal_types.is_empty()
        || wire.analytic_intents.is_empty()
        || wire.source_path_hash.is_none()
        || wire.informational.is_none()
        || wire.confidence.is_none()
        || wire.detection_reason.is_none()
        || wire.risk_entity_type.is_none()
        || wire.risk_entity_value.is_none()
        || wire.process.is_none()
        || wire.response.is_none()
        || wire.source_counts.is_some()
        || wire.risk_score != checked_risk_sum(&wire.risk_contributions).unwrap_or(u64::MAX)
        || wire.informational != Some(wire.risk_score == 0)
        || wire
            .confidence
            .as_deref()
            .is_none_or(|value| parse_confidence(value).is_none())
        || wire
            .risk_entity_type
            .as_deref()
            .is_none_or(|value| parse_risk_entity_type(value).is_none())
    {
        return Err(family("invalid_process_chain_family"));
    }
    Ok(())
}

fn validate_correlation(wire: &Event3Wire) -> Result<(), Event3ConsumerError> {
    if wire.severity == "warning"
        || wire.session_id != "correlation"
        || wire.event_time.is_none()
        || wire.rule_ids.is_empty()
        || wire.categories != ["cross_session_correlation"]
        || wire.detection_classes != ["security_detection"]
        || wire.signal_types != ["correlation"]
        || wire.analytic_intents != ["alert"]
        || wire.component.is_some()
        || wire.check_name.is_some()
        || wire.status.is_some()
        || !no_process_fields(wire)
        || wire.response.is_some()
        || wire.source_counts.is_some()
        || !wire.risk_contributions.is_empty()
    {
        return Err(family("invalid_correlation_family"));
    }
    Ok(())
}

fn no_detection_dimensions(wire: &Event3Wire) -> bool {
    wire.rule_ids.is_empty()
        && wire.categories.is_empty()
        && wire.detection_classes.is_empty()
        && wire.signal_types.is_empty()
        && wire.analytic_intents.is_empty()
        && wire.atlas_tags.is_empty()
        && wire.timeline_anchors.is_empty()
}

fn no_process_fields(wire: &Event3Wire) -> bool {
    wire.informational.is_none()
        && wire.confidence.is_none()
        && wire.detection_reason.is_none()
        && wire.mitre_attack_techniques.is_empty()
        && wire.risk_entity_type.is_none()
        && wire.risk_entity_value.is_none()
        && wire.process.is_none()
}

fn is_event_id(value: &str) -> bool {
    let Some(uuid_text) = value.strip_prefix("telltale-") else {
        return false;
    };
    uuid_text.len() == 36
        && Uuid::parse_str(uuid_text).is_ok_and(|uuid| {
            uuid.get_version_num() == 4
                && matches!(uuid_text.as_bytes()[19], b'8' | b'9' | b'a' | b'b')
                && uuid.to_string().as_str() == uuid_text
        })
}

fn is_rule_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 96
        && bytes[0].is_ascii_lowercase()
        && value.split('.').skip(1).all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        })
        && value.contains('.')
}

fn is_valid_event_time(value: &str) -> bool {
    parse_event_timestamp(value).is_some()
        || is_canonical_opaque_identifier_for_kind("invalid-event-time", value)
}

fn is_safe_semver(value: &str) -> bool {
    let (version, build) = value
        .split_once('+')
        .map_or((value, None), |(v, b)| (v, Some(b)));
    if build.is_some_and(|build| {
        build.is_empty()
            || !build
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
    }) {
        return false;
    }
    let (core, prerelease) = version
        .split_once('-')
        .map_or((version, None), |(v, p)| (v, Some(p)));
    if prerelease.is_some_and(|part| {
        part.is_empty()
            || !part
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
    }) {
        return false;
    }
    let components = core.split('.').collect::<Vec<_>>();
    components.len() == 3
        && components.iter().all(|component| {
            !component.is_empty() && component.bytes().all(|byte| byte.is_ascii_digit())
        })
}

fn parse_time_source(value: &str) -> Option<Event3TimeSource> {
    match value {
        "observed" => Some(Event3TimeSource::Observed),
        "source" => Some(Event3TimeSource::Source),
        "override" => Some(Event3TimeSource::Override),
        _ => None,
    }
}

fn parse_time_confidence(value: &str) -> Option<Event3TimeConfidence> {
    match value {
        "low" => Some(Event3TimeConfidence::Low),
        "medium" => Some(Event3TimeConfidence::Medium),
        "high" => Some(Event3TimeConfidence::High),
        _ => None,
    }
}

fn parse_severity(value: &str) -> Option<Event3Severity> {
    match value {
        "informational" => Some(Event3Severity::Informational),
        "low" => Some(Event3Severity::Low),
        "medium" => Some(Event3Severity::Medium),
        "high" => Some(Event3Severity::High),
        "critical" => Some(Event3Severity::Critical),
        "warning" => Some(Event3Severity::Warning),
        _ => None,
    }
}

fn parse_detection_class(value: &str) -> Option<Event3DetectionClass> {
    match value {
        "security_detection" => Some(Event3DetectionClass::SecurityDetection),
        "policy_violation" => Some(Event3DetectionClass::PolicyViolation),
        "threat_hunting" => Some(Event3DetectionClass::ThreatHunting),
        "compliance_observation" => Some(Event3DetectionClass::ComplianceObservation),
        "operational_health" => Some(Event3DetectionClass::OperationalHealth),
        "baseline_deviation" => Some(Event3DetectionClass::BaselineDeviation),
        _ => None,
    }
}

fn parse_signal_type(value: &str) -> Option<Event3SignalType> {
    match value {
        "atomic" => Some(Event3SignalType::Atomic),
        "chain" => Some(Event3SignalType::Chain),
        "correlation" => Some(Event3SignalType::Correlation),
        "baseline_deviation" => Some(Event3SignalType::BaselineDeviation),
        _ => None,
    }
}

fn parse_analytic_intent(value: &str) -> Option<Event3AnalyticIntent> {
    match value {
        "alert" => Some(Event3AnalyticIntent::Alert),
        "hunt" => Some(Event3AnalyticIntent::Hunt),
        "enrich" => Some(Event3AnalyticIntent::Enrich),
        "baseline" => Some(Event3AnalyticIntent::Baseline),
        "audit" => Some(Event3AnalyticIntent::Audit),
        _ => None,
    }
}

fn parse_confidence(value: &str) -> Option<Event3Confidence> {
    match value {
        "low" => Some(Event3Confidence::Low),
        "medium" => Some(Event3Confidence::Medium),
        "high" => Some(Event3Confidence::High),
        _ => None,
    }
}

fn parse_risk_entity_type(value: &str) -> Option<Event3RiskEntityType> {
    match value {
        "host" => Some(Event3RiskEntityType::Host),
        "user" => Some(Event3RiskEntityType::User),
        "session" => Some(Event3RiskEntityType::Session),
        _ => None,
    }
}

fn project_wire(wire: Event3Wire) -> Result<Event3Record, Event3ConsumerError> {
    let family = project_family(&wire)?;
    let common = Event3Common {
        schema_version: wire.schema_version,
        event_id: wire.event_id,
        telltale_version: wire.telltale_version,
        timestamp: wire.timestamp,
        event_time: wire.event_time,
        observed_at: wire.observed_at,
        ingested_at: wire.ingested_at,
        time_source: parse_time_source(&wire.time_source)
            .ok_or_else(|| semantic("invalid_time_source"))?,
        time_confidence: parse_time_confidence(&wire.time_confidence)
            .ok_or_else(|| semantic("invalid_time_confidence"))?,
        time_override_reason: wire.time_override_reason,
        severity: parse_severity(&wire.severity).ok_or_else(|| semantic("invalid_severity"))?,
        risk_score: wire.risk_score,
        risk_contributions: wire.risk_contributions.clone(),
        client: wire.client.clone(),
        agent: wire.agent.clone(),
        model: wire.model.clone(),
        provider: wire.provider.clone(),
        session_id: wire.session_id.clone(),
        tags: wire.tags.clone(),
        evidence: wire
            .evidence
            .iter()
            .map(|item| Event3Evidence {
                field: item.field.clone(),
                redacted_value: item.redacted_value.clone(),
                hash: item.hash.clone(),
                rule_id: item.rule_id.clone(),
            })
            .collect(),
    };
    Ok(Event3Record { common, family })
}

fn project_family(wire: &Event3Wire) -> Result<Event3Family, Event3ConsumerError> {
    let detection_classes = || {
        wire.detection_classes
            .iter()
            .map(|value| parse_detection_class(value).ok_or_else(|| semantic("invalid_taxonomy")))
            .collect::<Result<Vec<_>, _>>()
    };
    let signal_types = || {
        wire.signal_types
            .iter()
            .map(|value| parse_signal_type(value).ok_or_else(|| semantic("invalid_taxonomy")))
            .collect::<Result<Vec<_>, _>>()
    };
    let analytic_intents = || {
        wire.analytic_intents
            .iter()
            .map(|value| parse_analytic_intent(value).ok_or_else(|| semantic("invalid_taxonomy")))
            .collect::<Result<Vec<_>, _>>()
    };
    let anchors = || {
        wire.timeline_anchors
            .iter()
            .map(|anchor| Event3TimelineAnchor {
                entry_index: anchor.entry_index,
                rule_ids: anchor.rule_ids.clone(),
                categories: anchor.categories.clone(),
                evidence_fields: anchor.evidence_fields.clone(),
            })
            .collect()
    };
    let response = || {
        wire.response.as_ref().map(|response| Event3Response {
            recommended_action: response.recommended_action.clone(),
            response_playbook: response.response_playbook.clone(),
            investigation_summary: response.investigation_summary.clone(),
            escalation: response.escalation.clone(),
        })
    };
    match wire.event_type.as_str() {
        "activity" if wire.client == "install_inventory" => Ok(Event3Family::Activity(
            Event3Activity::InstallInventory(Event3InstallInventoryActivity {
                component: wire
                    .component
                    .clone()
                    .ok_or_else(|| family("missing_family_field"))?,
                check_name: wire
                    .check_name
                    .clone()
                    .ok_or_else(|| family("missing_family_field"))?,
                status: wire
                    .status
                    .clone()
                    .ok_or_else(|| family("missing_family_field"))?,
            }),
        )),
        "activity" => Ok(Event3Family::Activity(Event3Activity::Standard(
            Event3StandardActivity {
                event_time: wire.event_time.clone(),
                source_path_hash: wire
                    .source_path_hash
                    .clone()
                    .ok_or_else(|| family("missing_family_field"))?,
                tool_name: wire.tool_name.clone(),
            },
        ))),
        "detection" => Ok(Event3Family::Detection(Event3Detection {
            event_time: wire.event_time.clone(),
            source_path_hash: wire
                .source_path_hash
                .clone()
                .ok_or_else(|| family("missing_family_field"))?,
            tool_name: wire.tool_name.clone(),
            rule_ids: wire.rule_ids.clone(),
            categories: wire.categories.clone(),
            detection_classes: detection_classes()?,
            signal_types: signal_types()?,
            analytic_intents: analytic_intents()?,
            atlas_tags: wire.atlas_tags.clone(),
            timeline_anchors: anchors(),
            response: response(),
        })),
        "session_risk_summary" => Ok(Event3Family::SessionRiskSummary(Event3SessionRiskSummary {
            event_time: wire.event_time.clone(),
            source_path_hash: wire.source_path_hash.clone(),
            rule_ids: wire.rule_ids.clone(),
            categories: wire.categories.clone(),
            detection_classes: detection_classes()?,
            signal_types: signal_types()?,
            analytic_intents: analytic_intents()?,
            atlas_tags: wire.atlas_tags.clone(),
        })),
        "health" => {
            let thresholds = wire
                .threshold_config
                .as_ref()
                .ok_or_else(|| family("missing_family_field"))?;
            Ok(Event3Family::Health(Event3Health {
                source_counts: wire
                    .source_counts
                    .clone()
                    .ok_or_else(|| family("missing_family_field"))?,
                component: wire
                    .component
                    .clone()
                    .ok_or_else(|| family("missing_family_field"))?,
                check_name: wire
                    .check_name
                    .clone()
                    .ok_or_else(|| family("missing_family_field"))?,
                status: wire
                    .status
                    .clone()
                    .ok_or_else(|| family("missing_family_field"))?,
                scan_duration_ms: wire
                    .scan_duration_ms
                    .ok_or_else(|| family("missing_family_field"))?,
                rule_count: wire
                    .rule_count
                    .ok_or_else(|| family("missing_family_field"))?,
                threshold_config: Event3Thresholds {
                    low: thresholds.low,
                    medium: thresholds.medium,
                    high: thresholds.high,
                    critical: thresholds.critical,
                },
                active_policy_name: wire.active_policy_name.clone(),
                emitted_count: wire
                    .emitted_count
                    .ok_or_else(|| family("missing_family_field"))?,
                suppressed_count: wire
                    .suppressed_count
                    .ok_or_else(|| family("missing_family_field"))?,
                scanner_error_count: wire
                    .scanner_error_count
                    .ok_or_else(|| family("missing_family_field"))?,
            }))
        }
        "scanner_error" => Ok(Event3Family::ScannerError(Event3ScannerError {
            source_path_hash: wire
                .source_path_hash
                .clone()
                .ok_or_else(|| family("missing_family_field"))?,
            component: wire
                .component
                .clone()
                .ok_or_else(|| family("missing_family_field"))?,
            check_name: wire
                .check_name
                .clone()
                .ok_or_else(|| family("missing_family_field"))?,
            status: wire
                .status
                .clone()
                .ok_or_else(|| family("missing_family_field"))?,
        })),
        "operational_alert" => Ok(Event3Family::OperationalAlert(Event3OperationalAlert {
            categories: wire.categories.clone(),
            detection_classes: detection_classes()?,
            signal_types: signal_types()?,
            analytic_intents: analytic_intents()?,
            component: wire
                .component
                .clone()
                .ok_or_else(|| family("missing_family_field"))?,
            check_name: wire
                .check_name
                .clone()
                .ok_or_else(|| family("missing_family_field"))?,
            status: wire
                .status
                .clone()
                .ok_or_else(|| family("missing_family_field"))?,
            scan_duration_ms: wire.scan_duration_ms,
            scanner_error_count: wire.scanner_error_count,
        })),
        "process_chain" => Ok(Event3Family::ProcessChain(Box::new(Event3ProcessChain {
            event_time: wire.event_time.clone(),
            source_path_hash: wire
                .source_path_hash
                .clone()
                .ok_or_else(|| family("missing_family_field"))?,
            tool_name: wire.tool_name.clone(),
            rule_ids: wire.rule_ids.clone(),
            categories: wire.categories.clone(),
            detection_classes: detection_classes()?,
            signal_types: signal_types()?,
            analytic_intents: analytic_intents()?,
            response: response().ok_or_else(|| family("missing_family_field"))?,
            informational: wire
                .informational
                .ok_or_else(|| family("missing_family_field"))?,
            confidence: parse_confidence(wire.confidence.as_deref().unwrap_or(""))
                .ok_or_else(|| semantic("invalid_confidence"))?,
            detection_reason: wire
                .detection_reason
                .clone()
                .ok_or_else(|| family("missing_family_field"))?,
            mitre_attack_techniques: wire.mitre_attack_techniques.clone(),
            risk_entity_type: parse_risk_entity_type(
                wire.risk_entity_type.as_deref().unwrap_or(""),
            )
            .ok_or_else(|| semantic("invalid_risk_entity_type"))?,
            risk_entity_value: wire
                .risk_entity_value
                .clone()
                .ok_or_else(|| family("missing_family_field"))?,
            process: project_process(
                wire.process
                    .as_ref()
                    .ok_or_else(|| family("missing_family_field"))?,
            ),
        }))),
        "correlation" => Ok(Event3Family::Correlation(Event3Correlation {
            event_time: wire
                .event_time
                .clone()
                .ok_or_else(|| family("missing_family_field"))?,
            rule_ids: wire.rule_ids.clone(),
            categories: wire.categories.clone(),
            detection_classes: detection_classes()?,
            signal_types: signal_types()?,
            analytic_intents: analytic_intents()?,
        })),
        _ => Err(family("unknown_event_family")),
    }
}

fn project_process(process: &WireProcessContext) -> Event3ProcessContext {
    Event3ProcessContext {
        host: process.host.clone(),
        user: process.user.clone(),
        source_process_name: process.source_process_name.clone(),
        source_process_path: process.source_process_path.clone(),
        source_process_id: process.source_process_id,
        source_process_command_line: process.source_process_command_line.clone(),
        target_process_name: process.target_process_name.clone(),
        target_process_path: process.target_process_path.clone(),
        target_process_id: process.target_process_id,
        target_process_command_line: process.target_process_command_line.clone(),
        parent_process_name: process.parent_process_name.clone(),
        parent_process_path: process.parent_process_path.clone(),
        source_event_id: process.source_event_id.clone(),
        source_process_inferred: process.source_process_inferred,
        rule_name: process.rule_name.clone(),
        secondary_rule_ids: process.secondary_rule_ids.clone(),
        investigation_fields: process.investigation_fields.clone(),
        falsepositives: process.falsepositives.clone(),
        dedup_key: process.dedup_key.clone(),
        suppression_window_seconds: process.suppression_window_seconds,
        rule_severity: process.rule_severity.clone(),
        risk_adjustment: process.risk_adjustment.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        EVENT3_MAX_INPUT_BYTES, EVENT3_SCHEMA, EVENT3_SCHEMA_SHA256, Event3Activity,
        Event3ErrorCategory, Event3Family, Event3Record,
    };
    use crate::clients::ClientId;
    use crate::event::{
        ActivityEventInput, CorrelationEventInput, CorrelationSessionInput, DetectionEventInput,
        Evidence, HealthEventInput, OperationalAlertInput, ProcessChainEventInput, ProcessContext,
        SessionRiskSummaryEventInput, activity_event, correlation_event, detection_event,
        health_event_with_metadata, install_inventory_event, operational_alert_event,
        process_chain_event, scanner_error_event, session_risk_summary_event,
    };
    use crate::scoring::{RiskContribution, RiskContributionType, load_thresholds};
    use crate::source::Source;
    use serde_json::Value;
    use sha2::{Digest, Sha256};
    use std::path::PathBuf;

    fn health_bytes() -> Vec<u8> {
        let event = health_event_with_metadata(HealthEventInput {
            sources: &[],
            source_inventory_change: None,
            scan_duration_ms: 0,
            rule_count: 0,
            threshold_config: load_thresholds(),
            active_policy_name: None,
            emitted_count: 0,
            suppressed_count: 0,
            scanner_error_count: 0,
        });
        serde_json::to_vec(&event).expect("terminal health bytes")
    }

    #[test]
    fn schema_asset_matches_frozen_event3_hash() {
        assert_eq!(
            format!("{:x}", Sha256::digest(EVENT3_SCHEMA.as_bytes())),
            EVENT3_SCHEMA_SHA256
        );
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../schemas/event.schema.json");
        if root.is_file() {
            assert_eq!(
                std::fs::read(root).expect("root schema"),
                EVENT3_SCHEMA.as_bytes()
            );
            let historical = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../schemas/historical/event-3.0.schema.json");
            assert_eq!(
                std::fs::read(historical).expect("historical schema"),
                EVENT3_SCHEMA.as_bytes()
            );
        }
    }

    #[test]
    fn consumes_actual_terminal_bytes_without_native_deserialization() {
        let record = Event3Record::from_json(&health_bytes()).expect("typed health record");
        assert_eq!(record.event_type(), "health");
        assert!(matches!(record.family(), Event3Family::Health(_)));
        assert_eq!(record.common().session_id, "scanner");
    }

    #[test]
    fn distinguishes_standard_and_install_activity() {
        let standard = activity_event(ActivityEventInput {
            client: ClientId::Codex,
            agent: None,
            model: None,
            provider: None,
            session_id: "synthetic-session".to_string(),
            source_path_hash: "synthetic-source".to_string(),
            tool_name: Some("shell".to_string()),
            tags: Vec::new(),
            evidence: vec![Evidence {
                field: "tool_result".to_string(),
                redacted_value: "synthetic redacted result".to_string(),
                hash: None,
                rule_id: None,
            }],
            risk_contributions: Vec::new(),
            event_time: None,
        })
        .expect("activity");
        let standard = Event3Record::from_json(&serde_json::to_vec(&standard).expect("bytes"))
            .expect("standard activity record");
        assert!(matches!(
            standard.family(),
            Event3Family::Activity(Event3Activity::Standard(_))
        ));

        let inventory = crate::event::install_inventory_event(vec![Evidence {
            field: "inventory".to_string(),
            redacted_value: "synthetic inventory".to_string(),
            hash: None,
            rule_id: None,
        }])
        .expect("inventory");
        let inventory = Event3Record::from_json(&serde_json::to_vec(&inventory).expect("bytes"))
            .expect("inventory record");
        assert!(matches!(
            inventory.family(),
            Event3Family::Activity(Event3Activity::InstallInventory(_))
        ));
    }

    fn positive_constructor_corpus() -> Vec<(&'static str, crate::event::Event)> {
        let contributions = vec![
            RiskContribution::new(
                "rule.consumer.atomic",
                RiskContributionType::DeterministicRule,
                2,
                "consumer atomic",
            )
            .expect("contribution"),
            RiskContribution::new(
                "rule.consumer.chain",
                RiskContributionType::ChainModifier,
                3,
                "consumer chain",
            )
            .expect("contribution"),
        ];
        let mut detection = detection_event(DetectionEventInput {
            client: ClientId::Codex,
            agent: Some("codex".to_string()),
            model: Some("gpt-4o".to_string()),
            provider: Some("openai".to_string()),
            session_id: "consumer-detection-session".to_string(),
            source_path_hash: "consumer-detection-source".to_string(),
            tool_name: Some("shell".to_string()),
            rule_ids: vec![
                "rule.consumer.atomic".to_string(),
                "rule.consumer.chain".to_string(),
            ],
            categories: vec!["execution".to_string(), "network".to_string()],
            detection_classes: vec!["security_detection".to_string()],
            signal_types: vec!["atomic".to_string(), "chain".to_string()],
            analytic_intents: vec!["alert".to_string()],
            atlas_tags: vec!["atlas:execution".to_string()],
            tags: vec!["consumer".to_string()],
            evidence: vec![Evidence {
                field: "command".to_string(),
                redacted_value: "synthetic command redacted".to_string(),
                hash: Some("a".repeat(64)),
                rule_id: Some("rule.consumer.atomic".to_string()),
            }],
            risk_contributions: contributions.clone(),
            event_time: Some("2026-05-01T00:00:00Z".to_string()),
        })
        .expect("detection");
        detection.timeline_anchors = vec![crate::event::TimelineAnchor {
            entry_index: 0,
            rule_ids: vec!["rule.consumer.atomic".to_string()],
            categories: vec!["execution".to_string()],
            evidence_fields: vec!["command".to_string()],
        }];

        let summary = session_risk_summary_event(SessionRiskSummaryEventInput {
            client: "codex".to_string(),
            agent: Some("codex".to_string()),
            model: Some("gpt-4o".to_string()),
            provider: Some("openai".to_string()),
            session_id: "consumer-summary-session".to_string(),
            source_path_hash: Some("consumer-summary-source".to_string()),
            rule_ids: vec![
                "rule.consumer.atomic".to_string(),
                "rule.consumer.chain".to_string(),
            ],
            categories: vec!["execution".to_string()],
            detection_classes: vec!["security_detection".to_string()],
            signal_types: vec!["chain".to_string()],
            analytic_intents: vec!["alert".to_string()],
            atlas_tags: vec!["atlas:execution".to_string()],
            tags: vec!["consumer".to_string()],
            evidence: vec![Evidence {
                field: "summary".to_string(),
                redacted_value: "synthetic summary".to_string(),
                hash: None,
                rule_id: None,
            }],
            risk_contributions: contributions.clone(),
            event_time: Some("2026-05-01T00:00:00Z".to_string()),
        })
        .expect("summary");

        let process = process_chain_event(ProcessChainEventInput {
            client: ClientId::Codex,
            agent: Some("codex".to_string()),
            model: Some("gpt-4o".to_string()),
            provider: Some("openai".to_string()),
            session_id: "consumer-process-session".to_string(),
            source_path_hash: "consumer-process-source".to_string(),
            tool_name: Some("shell".to_string()),
            rule_ids: vec!["rule.consumer.atomic".to_string()],
            categories: vec!["execution".to_string()],
            detection_classes: vec!["security_detection".to_string()],
            signal_types: vec!["chain".to_string()],
            analytic_intents: vec!["alert".to_string()],
            tags: vec!["consumer".to_string()],
            evidence: vec![Evidence {
                field: "command".to_string(),
                redacted_value: "synthetic command".to_string(),
                hash: None,
                rule_id: Some("rule.consumer.atomic".to_string()),
            }],
            risk_contributions: vec![
                RiskContribution::new(
                    "rule.consumer.atomic",
                    RiskContributionType::DeterministicRule,
                    2,
                    "consumer process",
                )
                .expect("contribution"),
            ],
            event_time: Some("2026-05-01T00:00:00Z".to_string()),
            confidence: "high".to_string(),
            detection_reason: "synthetic process reason".to_string(),
            mitre_attack_techniques: vec!["T1059".to_string(), "T1059.001".to_string()],
            risk_entity_type: "host".to_string(),
            risk_entity_value: Some("synthetic-host".to_string()),
            process: ProcessContext {
                host: Some("synthetic-host".to_string()),
                user: None,
                source_process_name: "shell".to_string(),
                source_process_path: None,
                source_process_id: Some(10),
                source_process_command_line: Some("synthetic command".to_string()),
                target_process_name: "curl".to_string(),
                target_process_path: None,
                target_process_id: Some(11),
                target_process_command_line: None,
                parent_process_name: None,
                parent_process_path: None,
                source_event_id: Some("synthetic-source-event".to_string()),
                source_process_inferred: false,
                rule_name: "synthetic-rule".to_string(),
                secondary_rule_ids: Vec::new(),
                investigation_fields: Vec::new(),
                falsepositives: Vec::new(),
                dedup_key: "synthetic-dedup".to_string(),
                suppression_window_seconds: 60,
                rule_severity: "high".to_string(),
                risk_adjustment: None,
            },
        })
        .expect("process chain");

        let correlation = correlation_event(CorrelationEventInput {
            client: "codex".to_string(),
            agent: Some("codex".to_string()),
            model: Some("gpt-4o".to_string()),
            provider: Some("openai".to_string()),
            shared_rule_ids: vec!["rule.consumer.atomic".to_string()],
            sessions: vec![
                CorrelationSessionInput {
                    session_id: "consumer-a".to_string(),
                    event_id: "consumer-event-a".to_string(),
                    timestamp: "2026-05-01T00:00:00Z".to_string(),
                    severity: "low".to_string(),
                    risk_score: 2,
                },
                CorrelationSessionInput {
                    session_id: "consumer-b".to_string(),
                    event_id: "consumer-event-b".to_string(),
                    timestamp: "2026-05-01T00:01:00Z".to_string(),
                    severity: "medium".to_string(),
                    risk_score: 3,
                },
            ],
            window_start: "2026-05-01T00:00:00Z".to_string(),
            window_end: "2026-05-01T00:01:00Z".to_string(),
            max_risk_score: 3,
        })
        .expect("correlation");

        let source = Source {
            client: ClientId::Codex,
            kind: crate::clients::SourceKind::Jsonl,
            source_id: "consumer-source".to_string(),
            path: PathBuf::from("synthetic://consumer"),
        };
        vec![
            ("detection", detection),
            (
                "activity_standard",
                activity_event(ActivityEventInput {
                    client: ClientId::Codex,
                    agent: None,
                    model: None,
                    provider: None,
                    session_id: "consumer-activity".to_string(),
                    source_path_hash: "consumer-activity-source".to_string(),
                    tool_name: Some("shell".to_string()),
                    tags: vec!["consumer".to_string()],
                    evidence: vec![Evidence {
                        field: "tool_result".to_string(),
                        redacted_value: "synthetic result".to_string(),
                        hash: None,
                        rule_id: None,
                    }],
                    risk_contributions: Vec::new(),
                    event_time: None,
                })
                .expect("activity"),
            ),
            (
                "install_inventory_activity",
                install_inventory_event(vec![Evidence {
                    field: "inventory".to_string(),
                    redacted_value: "synthetic inventory".to_string(),
                    hash: None,
                    rule_id: None,
                }])
                .expect("inventory"),
            ),
            ("session_risk_summary", summary),
            (
                "health",
                health_event_with_metadata(HealthEventInput {
                    sources: &[],
                    source_inventory_change: None,
                    scan_duration_ms: 1,
                    rule_count: 2,
                    threshold_config: load_thresholds(),
                    active_policy_name: Some("synthetic-policy"),
                    emitted_count: 1,
                    suppressed_count: 0,
                    scanner_error_count: 0,
                }),
            ),
            (
                "scanner_error",
                scanner_error_event(&source, &std::io::Error::other("synthetic parse failure")),
            ),
            (
                "operational_alert",
                operational_alert_event(OperationalAlertInput {
                    alert_type: "sink_delivery_failure".to_string(),
                    threshold: "synthetic threshold".to_string(),
                    actual_value: "synthetic actual".to_string(),
                    scan_duration_ms: Some(1),
                    scanner_error_count: Some(1),
                }),
            ),
            ("process_chain", process),
            ("correlation", correlation),
        ]
    }

    #[test]
    fn actual_terminal_constructor_corpus_covers_all_nine_families() {
        let corpus = positive_constructor_corpus();
        let registered = crate::event::NATIVE_EVENT_CONSTRUCTOR_FAMILIES
            .iter()
            .map(|family| family.name)
            .collect::<std::collections::BTreeSet<_>>();
        let covered = corpus
            .iter()
            .map(|(name, _)| *name)
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(covered, registered);
        for (name, event) in corpus {
            let bytes = serde_json::to_vec(&event).expect("terminal bytes");
            let record = Event3Record::from_json(&bytes).unwrap_or_else(|error| {
                panic!("constructor family {name} did not consume: {error}")
            });
            assert_eq!(record.event_type(), event.event_type);
            match (name, record.family()) {
                ("detection", Event3Family::Detection(detection)) => {
                    assert_eq!(detection.rule_ids.len(), 2);
                    assert_eq!(detection.timeline_anchors.len(), 1);
                    assert!(detection.response.is_some());
                    assert_eq!(
                        record.common().evidence[0].hash.as_ref().map(String::len),
                        Some(64)
                    );
                }
                (
                    "activity_standard",
                    Event3Family::Activity(Event3Activity::Standard(activity)),
                ) => {
                    assert_eq!(activity.source_path_hash.len(), 64);
                    assert!(activity.event_time.is_none());
                }
                (
                    "install_inventory_activity",
                    Event3Family::Activity(Event3Activity::InstallInventory(activity)),
                ) => {
                    assert_eq!(activity.component, "scanner");
                    assert_eq!(activity.check_name, "install_inventory");
                    assert_eq!(activity.status, "ok");
                }
                ("session_risk_summary", Event3Family::SessionRiskSummary(summary)) => {
                    assert_eq!(summary.rule_ids.len(), 2);
                    assert_eq!(summary.source_path_hash.as_ref().map(String::len), Some(64));
                }
                ("health", Event3Family::Health(health)) => {
                    assert_eq!(health.emitted_count, 1);
                    assert!(
                        health
                            .active_policy_name
                            .as_deref()
                            .is_some_and(|name| name.starts_with("[policy:"))
                    );
                }
                ("scanner_error", Event3Family::ScannerError(error)) => {
                    assert_eq!(error.check_name, "source_parse");
                    assert_eq!(error.status, "degraded");
                }
                ("operational_alert", Event3Family::OperationalAlert(alert)) => {
                    assert_eq!(alert.scan_duration_ms, Some(1));
                    assert_eq!(alert.scanner_error_count, None);
                }
                ("process_chain", Event3Family::ProcessChain(process)) => {
                    assert!(!process.informational);
                    assert_eq!(process.process.target_process_name, "curl");
                    assert_eq!(process.response.recommended_action, "monitor");
                }
                ("correlation", Event3Family::Correlation(correlation)) => {
                    assert_eq!(correlation.event_time, "2026-05-01T00:01:00.000Z");
                }
                (family, actual) => panic!("family {family} projected as {actual:?}"),
            }
        }
    }

    #[test]
    fn preserves_source_and_fallback_time_and_valid_suppressed_detection() {
        let corpus = positive_constructor_corpus();
        let detection = corpus
            .iter()
            .find(|(name, _)| *name == "detection")
            .expect("detection corpus")
            .1
            .clone();
        let source = Event3Record::from_json(&serde_json::to_vec(&detection).expect("bytes"))
            .expect("source-time detection");
        assert_eq!(source.common().time_source, super::Event3TimeSource::Source);
        assert_eq!(
            source.common().event_time.as_deref(),
            Some("2026-05-01T00:00:00.000Z")
        );

        let activity = corpus
            .into_iter()
            .find(|(name, _)| *name == "activity_standard")
            .expect("activity corpus")
            .1;
        let fallback = Event3Record::from_json(&serde_json::to_vec(&activity).expect("bytes"))
            .expect("observed-time activity");
        assert_eq!(
            fallback.common().time_source,
            super::Event3TimeSource::Observed
        );
        assert_eq!(
            fallback.common().time_confidence,
            super::Event3TimeConfidence::Low
        );

        let mut suppressed = detection_event(DetectionEventInput {
            client: ClientId::Codex,
            agent: None,
            model: None,
            provider: None,
            session_id: "consumer-suppressed".to_string(),
            source_path_hash: "consumer-suppressed-source".to_string(),
            tool_name: None,
            rule_ids: vec!["rule.consumer.suppressed".to_string()],
            categories: vec!["execution".to_string()],
            detection_classes: vec!["security_detection".to_string()],
            signal_types: vec!["atomic".to_string()],
            analytic_intents: vec!["audit".to_string()],
            atlas_tags: Vec::new(),
            tags: vec!["suppressed".to_string()],
            evidence: vec![Evidence {
                field: "command".to_string(),
                redacted_value: "synthetic suppressed evidence".to_string(),
                hash: None,
                rule_id: Some("rule.consumer.suppressed".to_string()),
            }],
            risk_contributions: Vec::new(),
            event_time: None,
        })
        .expect("suppressed detection");
        suppressed.response = None;
        let suppressed = Event3Record::from_json(&serde_json::to_vec(&suppressed).expect("bytes"))
            .expect("valid suppressed detection");
        assert!(matches!(suppressed.family(), Event3Family::Detection(_)));
        assert_eq!(suppressed.common().risk_score, 0);
    }

    #[test]
    fn errors_are_classified_and_do_not_echo_input() {
        let canary = "TT_EVENT3_CONSUMER_SECRET_CANARY";
        let malformed =
            Event3Record::from_json(format!("{{{canary}").as_bytes()).expect_err("malformed");
        assert_eq!(malformed.category(), Event3ErrorCategory::Malformed);
        assert!(!malformed.to_string().contains(canary));
        assert!(!format!("{malformed:?}").contains(canary));

        let mut missing = serde_json::from_slice::<Value>(&health_bytes()).expect("health JSON");
        missing
            .as_object_mut()
            .expect("object")
            .remove("session_id");
        let error = Event3Record::from_json(&serde_json::to_vec(&missing).expect("JSON"))
            .expect_err("missing common field");
        assert_eq!(error.category(), Event3ErrorCategory::Structure);

        let mut invalid_id = serde_json::from_slice::<Value>(&health_bytes()).expect("health JSON");
        invalid_id["event_id"] = Value::String(canary.to_string());
        let error = Event3Record::from_json(&serde_json::to_vec(&invalid_id).expect("JSON"))
            .expect_err("invalid identity");
        assert_eq!(error.category(), Event3ErrorCategory::Identity);
        assert!(!error.to_string().contains(canary));
    }

    #[test]
    fn oversized_input_is_rejected_before_json_parsing() {
        let canary = "TT_EVENT3_OVERSIZED_INPUT_CANARY";
        let mut oversized = vec![b' '; EVENT3_MAX_INPUT_BYTES + 1];
        oversized.extend_from_slice(canary.as_bytes());
        let error = Event3Record::from_json(&oversized).expect_err("oversized input");
        assert_eq!(error.category(), Event3ErrorCategory::Structure);
        assert_eq!(error.code(), "input_too_large");
        assert!(!error.to_string().contains(canary));
        assert!(!format!("{error:?}").contains(canary));
    }

    #[test]
    fn unknown_property_is_rejected_before_projection() {
        let mut value = serde_json::from_slice::<Value>(&health_bytes()).expect("health JSON");
        value["unexpected"] = Value::String("synthetic".to_string());
        let error = Event3Record::from_json(&serde_json::to_vec(&value).expect("JSON"))
            .expect_err("unknown property");
        assert_eq!(error.category(), Event3ErrorCategory::Structure);

        let mut nested = serde_json::from_slice::<Value>(&health_bytes()).expect("health JSON");
        nested["evidence"][0]["unexpected"] = Value::String("synthetic".to_string());
        let error = Event3Record::from_json(&serde_json::to_vec(&nested).expect("JSON"))
            .expect_err("nested unknown property");
        assert_eq!(error.category(), Event3ErrorCategory::Structure);
    }

    #[test]
    fn adversarial_version_taxonomy_family_anchor_and_semantic_failures_are_classified() {
        let non_object = Event3Record::from_json(b"[]").expect_err("non-object");
        assert_eq!(non_object.category(), Event3ErrorCategory::Structure);

        let mut version = serde_json::from_slice::<Value>(&health_bytes()).expect("health JSON");
        version["schema_version"] = Value::String("4.0".to_string());
        let error = Event3Record::from_json(&serde_json::to_vec(&version).expect("JSON"))
            .expect_err("version failure");
        assert_eq!(error.category(), Event3ErrorCategory::Version);

        let mut taxonomy = serde_json::from_slice::<Value>(&health_bytes()).expect("health JSON");
        taxonomy["time_source"] = Value::String("synthetic-taxonomy".to_string());
        let error = Event3Record::from_json(&serde_json::to_vec(&taxonomy).expect("JSON"))
            .expect_err("taxonomy failure");
        assert_eq!(error.category(), Event3ErrorCategory::Semantic);

        let mut family = serde_json::from_slice::<Value>(&health_bytes()).expect("health JSON");
        family["event_type"] = Value::String("detection".to_string());
        let error = Event3Record::from_json(&serde_json::to_vec(&family).expect("JSON"))
            .expect_err("family failure");
        assert_eq!(error.category(), Event3ErrorCategory::Family);

        let mut missing_family_field =
            serde_json::from_slice::<Value>(&health_bytes()).expect("health JSON");
        missing_family_field
            .as_object_mut()
            .expect("object")
            .remove("component");
        let error =
            Event3Record::from_json(&serde_json::to_vec(&missing_family_field).expect("JSON"))
                .expect_err("missing family field");
        assert_eq!(error.category(), Event3ErrorCategory::Family);

        let mut detection = serde_json::to_value(
            &positive_constructor_corpus()
                .into_iter()
                .find(|(name, _)| *name == "detection")
                .expect("detection corpus")
                .1,
        )
        .expect("detection JSON");
        detection["risk_score"] = Value::Number(99.into());
        let error = Event3Record::from_json(&serde_json::to_vec(&detection).expect("JSON"))
            .expect_err("semantic risk failure");
        assert_eq!(error.category(), Event3ErrorCategory::Semantic);

        let mut process = serde_json::to_value(
            &positive_constructor_corpus()
                .into_iter()
                .find(|(name, _)| *name == "process_chain")
                .expect("process-chain corpus")
                .1,
        )
        .expect("process-chain JSON");
        process["risk_contributions"][0]["type"] = Value::String("baseline_deviation".to_string());
        let error = Event3Record::from_json(&serde_json::to_vec(&process).expect("JSON"))
            .expect_err("process-chain risk scope failure");
        assert_eq!(error.category(), Event3ErrorCategory::Semantic);

        let anchors = detection["timeline_anchors"]
            .as_array_mut()
            .expect("anchors");
        anchors.push(serde_json::json!({
            "entry_index": 0,
            "rule_ids": ["rule.consumer.chain"],
            "categories": ["network"],
            "evidence_fields": ["command"]
        }));
        detection["risk_score"] = Value::Number(5.into());
        let error = Event3Record::from_json(&serde_json::to_vec(&detection).expect("JSON"))
            .expect_err("anchor failure");
        assert_eq!(error.category(), Event3ErrorCategory::Semantic);
    }

    #[test]
    fn rejects_inconsistent_timing_relationships() {
        let mut source_without_event_time =
            serde_json::from_slice::<Value>(&health_bytes()).expect("health JSON");
        source_without_event_time["time_source"] = Value::String("source".to_string());
        let error =
            Event3Record::from_json(&serde_json::to_vec(&source_without_event_time).expect("JSON"))
                .expect_err("source timing must retain event time");
        assert_eq!(error.category(), Event3ErrorCategory::Semantic);
        assert_eq!(error.code(), "invalid_time_relationship");

        let mut unrelated_observed_timestamp =
            serde_json::from_slice::<Value>(&health_bytes()).expect("health JSON");
        unrelated_observed_timestamp["timestamp"] =
            Value::String("2026-05-01T00:00:00.000Z".to_string());
        let error = Event3Record::from_json(
            &serde_json::to_vec(&unrelated_observed_timestamp).expect("JSON"),
        )
        .expect_err("observed timing must use observation time");
        assert_eq!(error.category(), Event3ErrorCategory::Semantic);
        assert_eq!(error.code(), "invalid_time_relationship");
    }

    #[test]
    fn accepts_override_timing_with_retained_event_time() {
        let event = detection_event(DetectionEventInput {
            client: ClientId::Codex,
            agent: None,
            model: None,
            provider: None,
            session_id: "consumer-override-session".to_string(),
            source_path_hash: "consumer-override-source".to_string(),
            tool_name: None,
            rule_ids: vec!["rule.consumer.override".to_string()],
            categories: vec!["execution".to_string()],
            detection_classes: vec!["security_detection".to_string()],
            signal_types: vec!["atomic".to_string()],
            analytic_intents: vec!["alert".to_string()],
            atlas_tags: Vec::new(),
            tags: vec!["consumer".to_string()],
            evidence: Vec::new(),
            risk_contributions: Vec::new(),
            event_time: Some("2999-01-01T00:00:00Z".to_string()),
        })
        .expect("detection event");
        let record = Event3Record::from_json(&serde_json::to_vec(&event).expect("terminal bytes"))
            .expect("override timing");

        assert_eq!(
            record.common().time_source,
            super::Event3TimeSource::Override
        );
        assert_eq!(
            record.common().time_confidence,
            super::Event3TimeConfidence::Low
        );
        assert_eq!(
            record.common().time_override_reason.as_deref(),
            Some("source_timestamp_future_skew")
        );
        assert_eq!(
            record.common().event_time.as_deref(),
            Some("2999-01-01T00:00:00.000Z")
        );
        assert_eq!(record.common().timestamp, record.common().observed_at);
    }
}
