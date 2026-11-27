//! The Event 3.0 model: the frozen external event contract, its native
//! constructors and terminal serialization.
//!
//! Event construction is the privacy boundary: constructors sanitize, and
//! sinks write the resulting bytes unchanged. Do not add fields, change
//! constructors' output or backport new semantics; the current schema must stay
//! byte-identical to `schemas/historical/event-3.0.schema.json`. Consumers
//! parse events with `consumer::Event3Record`, never by deserializing `Event`.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Serialize, Serializer, ser::Error as _};
use serde_json::Value;
use uuid::Uuid;

use crate::clients::ClientId;
use crate::scoring::{
    RiskAccountingError, RiskContribution, RiskContributionType, RiskThresholds,
    assess_risk_with_thresholds, canonicalize_contributions, canonicalize_terminal_contributions,
    checked_risk_sum, checked_terminal_risk_sum, load_thresholds,
};
use crate::source::{Source, SourceInventoryChangeSummary};

mod identifier;
mod inventory;
mod redaction;
mod time;

pub mod consumer;

pub use consumer::{
    EVENT3_MAX_INPUT_BYTES, EVENT3_SCHEMA, EVENT3_SCHEMA_SHA256, Event3Activity,
    Event3AnalyticIntent, Event3Common, Event3Confidence, Event3ConsumerError, Event3Correlation,
    Event3Detection, Event3DetectionClass, Event3ErrorCategory, Event3Evidence, Event3Family,
    Event3Health, Event3InstallInventoryActivity, Event3OperationalAlert, Event3ProcessChain,
    Event3ProcessContext, Event3Record, Event3Response, Event3RiskEntityType, Event3ScannerError,
    Event3SessionRiskSummary, Event3Severity, Event3SignalType, Event3StandardActivity,
    Event3Thresholds, Event3TimeConfidence, Event3TimeSource, Event3TimelineAnchor,
};

pub use identifier::{
    CanonicalOpaqueIdentifier, is_canonical_opaque_identifier_for_kind, opaque_identifier,
    parse_canonical_opaque_identifier, terminal_historical_identifier,
    terminal_historical_product_metadata, terminal_historical_rule_identifier,
    terminal_historical_session_id, terminal_historical_tool_label, terminal_identifier,
    terminal_product_metadata, terminal_rule_identifier, terminal_session_id, terminal_tool_label,
};
pub(crate) use identifier::{is_native_rule_identifier, is_terminal_rule_identifier};
use identifier::{
    is_safe_atlas_tag, is_safe_structured_identifier, is_supported_client_identifier,
    terminal_atlas_tag, terminal_client_id, terminal_historical_client_id,
    terminal_imported_client_id, terminal_imported_identifier, terminal_imported_opaque_identifier,
    terminal_imported_product_metadata, terminal_imported_session_id, terminal_imported_tag,
    terminal_tag,
};

pub use inventory::{evidence_hash, path_hash};
pub use redaction::{
    ControlledMarker, EvidenceExcerpt, PrivacySanitizer, SanitizationContext,
    SerializedMarkerCheckError, check_serialized_event_markers, redact_multiline_bounded,
    redact_sensitive_text,
};
pub(crate) use redaction::{
    contains_credential_material, contains_high_confidence_credential_marker,
};
pub use time::{format_timestamp, parse_event_timestamp};

pub const NATIVE_SCHEMA_VERSION: &str = "3.0";
pub const TELLTALE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Event families with emitted text that require serialized privacy coverage.
pub const TEXT_BEARING_EVENT_TYPES: &[&str] = &[
    "detection",
    "activity",
    "health",
    "scanner_error",
    "operational_alert",
    "session_risk_summary",
    "correlation",
    "process_chain",
];

/// Native constructor families tracked by the Event 3.0 conformance corpus.
///
/// The family name is intentionally separate from `event_type`: install
/// inventory uses the `activity` wire type but follows a distinct constructor
/// and schema branch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeEventConstructorFamily {
    pub name: &'static str,
    pub event_type: &'static str,
}

const CONSTRUCTOR_FAMILY_DETECTION: NativeEventConstructorFamily = NativeEventConstructorFamily {
    name: "detection",
    event_type: "detection",
};
const CONSTRUCTOR_FAMILY_STANDARD_ACTIVITY: NativeEventConstructorFamily =
    NativeEventConstructorFamily {
        name: "activity_standard",
        event_type: "activity",
    };
const CONSTRUCTOR_FAMILY_INSTALL_INVENTORY: NativeEventConstructorFamily =
    NativeEventConstructorFamily {
        name: "install_inventory_activity",
        event_type: "activity",
    };
const CONSTRUCTOR_FAMILY_SESSION_RISK_SUMMARY: NativeEventConstructorFamily =
    NativeEventConstructorFamily {
        name: "session_risk_summary",
        event_type: "session_risk_summary",
    };
const CONSTRUCTOR_FAMILY_HEALTH: NativeEventConstructorFamily = NativeEventConstructorFamily {
    name: "health",
    event_type: "health",
};
const CONSTRUCTOR_FAMILY_SCANNER_ERROR: NativeEventConstructorFamily =
    NativeEventConstructorFamily {
        name: "scanner_error",
        event_type: "scanner_error",
    };
const CONSTRUCTOR_FAMILY_OPERATIONAL_ALERT: NativeEventConstructorFamily =
    NativeEventConstructorFamily {
        name: "operational_alert",
        event_type: "operational_alert",
    };
const CONSTRUCTOR_FAMILY_PROCESS_CHAIN: NativeEventConstructorFamily =
    NativeEventConstructorFamily {
        name: "process_chain",
        event_type: "process_chain",
    };
const CONSTRUCTOR_FAMILY_CORRELATION: NativeEventConstructorFamily = NativeEventConstructorFamily {
    name: "correlation",
    event_type: "correlation",
};

/// The current reviewed native constructor-family inventory used by conformance tests.
pub const NATIVE_EVENT_CONSTRUCTOR_FAMILIES: &[NativeEventConstructorFamily] = &[
    CONSTRUCTOR_FAMILY_DETECTION,
    CONSTRUCTOR_FAMILY_STANDARD_ACTIVITY,
    CONSTRUCTOR_FAMILY_INSTALL_INVENTORY,
    CONSTRUCTOR_FAMILY_SESSION_RISK_SUMMARY,
    CONSTRUCTOR_FAMILY_HEALTH,
    CONSTRUCTOR_FAMILY_SCANNER_ERROR,
    CONSTRUCTOR_FAMILY_OPERATIONAL_ALERT,
    CONSTRUCTOR_FAMILY_PROCESS_CHAIN,
    CONSTRUCTOR_FAMILY_CORRELATION,
];

#[derive(Debug, Clone)]
pub struct Event {
    pub timestamp: String,
    pub event_time: Option<String>,
    pub observed_at: String,
    pub ingested_at: String,
    pub time_source: String,
    pub time_confidence: String,
    pub time_override_reason: Option<String>,
    pub schema_version: String,
    pub event_id: String,
    pub telltale_version: String,
    pub event_type: String,
    pub severity: String,
    pub risk_score: u64,
    pub risk_contributions: Vec<RiskContribution>,
    pub client: String,
    pub agent: Option<String>,
    pub model: Option<String>,
    pub provider: Option<String>,
    pub session_id: String,
    pub source_path_hash: Option<String>,
    pub tool_name: Option<String>,
    pub rule_ids: Vec<String>,
    pub categories: Vec<String>,
    pub detection_classes: Vec<String>,
    pub signal_types: Vec<String>,
    pub analytic_intents: Vec<String>,
    pub atlas_tags: Vec<String>,
    pub tags: Vec<String>,
    pub evidence: Vec<Evidence>,
    pub timeline_anchors: Vec<TimelineAnchor>,
    pub response: Option<ResponseMetadata>,
    pub source_counts: Option<BTreeMap<String, u32>>,
    pub component: Option<String>,
    pub check_name: Option<String>,
    pub status: Option<String>,
    pub scan_duration_ms: Option<u64>,
    pub rule_count: Option<usize>,
    pub threshold_config: Option<RiskThresholds>,
    pub active_policy_name: Option<String>,
    pub emitted_count: Option<u64>,
    pub suppressed_count: Option<u64>,
    pub scanner_error_count: Option<u64>,
    /// Present on detections that scored `0`. An informational event still
    /// carries full rule context; it simply contributes no risk.
    pub informational: Option<bool>,
    /// Fidelity of the match: `low`, `medium`, or `high`.
    pub confidence: Option<String>,
    /// Redaction-safe sentence explaining why the rule fired.
    pub detection_reason: Option<String>,
    pub mitre_attack_techniques: Vec<String>,
    /// Entity that should accumulate this event's risk (`host`, `user`, or
    /// `session`). Informational events name the entity but add no risk.
    pub risk_entity_type: Option<String>,
    pub risk_entity_value: Option<String>,
    pub process: Option<ProcessContext>,
}

/// Private Event 3.0 wire view. Its field order and serde attributes mirror
/// `Event` so terminal serialization stays byte-compatible without recursing
/// through `Event::serialize`.
#[derive(Serialize)]
struct EventWire<'a> {
    timestamp: &'a String,
    #[serde(skip_serializing_if = "Option::is_none")]
    event_time: &'a Option<String>,
    observed_at: &'a String,
    ingested_at: &'a String,
    time_source: &'a String,
    time_confidence: &'a String,
    #[serde(skip_serializing_if = "Option::is_none")]
    time_override_reason: &'a Option<String>,
    schema_version: &'a String,
    event_id: &'a String,
    telltale_version: &'a String,
    event_type: &'a String,
    severity: &'a String,
    risk_score: &'a u64,
    risk_contributions: &'a Vec<RiskContribution>,
    client: &'a String,
    #[serde(skip_serializing_if = "Option::is_none")]
    agent: &'a Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    model: &'a Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    provider: &'a Option<String>,
    session_id: &'a String,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_path_hash: &'a Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tool_name: &'a Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    rule_ids: &'a Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    categories: &'a Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    detection_classes: &'a Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    signal_types: &'a Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    analytic_intents: &'a Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    atlas_tags: &'a Vec<String>,
    tags: &'a Vec<String>,
    evidence: &'a Vec<Evidence>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    timeline_anchors: &'a Vec<TimelineAnchor>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response: &'a Option<ResponseMetadata>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_counts: &'a Option<BTreeMap<String, u32>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    component: &'a Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    check_name: &'a Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    status: &'a Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scan_duration_ms: &'a Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rule_count: &'a Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    threshold_config: &'a Option<RiskThresholds>,
    #[serde(skip_serializing_if = "Option::is_none")]
    active_policy_name: &'a Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    emitted_count: &'a Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    suppressed_count: &'a Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scanner_error_count: &'a Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    informational: &'a Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    confidence: &'a Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    detection_reason: &'a Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    mitre_attack_techniques: &'a Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    risk_entity_type: &'a Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    risk_entity_value: &'a Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    process: &'a Option<ProcessContext>,
}

impl<'a> EventWire<'a> {
    fn new(event: &'a Event) -> Self {
        Self {
            timestamp: &event.timestamp,
            event_time: &event.event_time,
            observed_at: &event.observed_at,
            ingested_at: &event.ingested_at,
            time_source: &event.time_source,
            time_confidence: &event.time_confidence,
            time_override_reason: &event.time_override_reason,
            schema_version: &event.schema_version,
            event_id: &event.event_id,
            telltale_version: &event.telltale_version,
            event_type: &event.event_type,
            severity: &event.severity,
            risk_score: &event.risk_score,
            risk_contributions: &event.risk_contributions,
            client: &event.client,
            agent: &event.agent,
            model: &event.model,
            provider: &event.provider,
            session_id: &event.session_id,
            source_path_hash: &event.source_path_hash,
            tool_name: &event.tool_name,
            rule_ids: &event.rule_ids,
            categories: &event.categories,
            detection_classes: &event.detection_classes,
            signal_types: &event.signal_types,
            analytic_intents: &event.analytic_intents,
            atlas_tags: &event.atlas_tags,
            tags: &event.tags,
            evidence: &event.evidence,
            timeline_anchors: &event.timeline_anchors,
            response: &event.response,
            source_counts: &event.source_counts,
            component: &event.component,
            check_name: &event.check_name,
            status: &event.status,
            scan_duration_ms: &event.scan_duration_ms,
            rule_count: &event.rule_count,
            threshold_config: &event.threshold_config,
            active_policy_name: &event.active_policy_name,
            emitted_count: &event.emitted_count,
            suppressed_count: &event.suppressed_count,
            scanner_error_count: &event.scanner_error_count,
            informational: &event.informational,
            confidence: &event.confidence,
            detection_reason: &event.detection_reason,
            mitre_attack_techniques: &event.mitre_attack_techniques,
            risk_entity_type: &event.risk_entity_type,
            risk_entity_value: &event.risk_entity_value,
            process: &event.process,
        }
    }
}

/// An explicit Event 3.0 representation for persistence or transport.
///
/// `Event` retains raw values so detection, allowlists, timeline construction,
/// state, correlation, and suppression operate on observed data. Both this
/// wrapper and direct `Event` serialization apply the terminal privacy policy.
#[derive(Debug)]
pub struct EmittableEvent<'a> {
    event: &'a Event,
}

/// An Event derived from canonical historical Event 3.0 input.
///
/// Exact recognized opaque markers remain stable pseudonymous labels in this
/// derived output. They are not authenticated or trusted provenance.
#[derive(Debug)]
pub struct HistoricalDerivedEvent<'a> {
    event: &'a Event,
}

impl Event {
    pub fn emittable(&self) -> EmittableEvent<'_> {
        EmittableEvent { event: self }
    }

    pub fn historical_derived(&self) -> HistoricalDerivedEvent<'_> {
        HistoricalDerivedEvent { event: self }
    }
}

impl Serialize for Event {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if !response_playbooks_are_valid(self) {
            return Err(S::Error::custom(INVALID_CONTROLLED_EVENT_ERROR));
        }
        let emitted = terminal_emittable_event(self);
        if !terminal_controlled_fields_are_valid(&emitted, false) {
            return Err(S::Error::custom(INVALID_CONTROLLED_EVENT_ERROR));
        }
        EventWire::new(&emitted).serialize(serializer)
    }
}

/// Serialize an Event through the canonical terminal privacy boundary.
///
/// This is equivalent to serializing [`Event`] directly.
pub fn serialize_event_for_emission<S>(event: &Event, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    event.serialize(serializer)
}

impl Serialize for EmittableEvent<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.event.serialize(serializer)
    }
}

impl Serialize for HistoricalDerivedEvent<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if !response_playbooks_are_valid(self.event) {
            return Err(S::Error::custom(INVALID_CONTROLLED_EVENT_ERROR));
        }
        let emitted = terminal_historical_derived_event(self.event);
        if !terminal_controlled_fields_are_valid(&emitted, true) {
            return Err(S::Error::custom(INVALID_CONTROLLED_EVENT_ERROR));
        }
        EventWire::new(&emitted).serialize(serializer)
    }
}

/// Apply the Event 3.0 terminal privacy policy to an imported JSON event.
///
/// This preserves the original JSON shape for historical JSONL exports, whose
/// records cannot be wrapped as an in-memory [`Event`]. New production events
/// must use [`Event::emittable`] instead.
pub fn sanitize_serialized_event(event: &mut Value) {
    let canonical_event = event
        .get("schema_version")
        .and_then(Value::as_str)
        .is_some_and(|version| version == NATIVE_SCHEMA_VERSION);
    {
        let Some(event) = event.as_object_mut() else {
            return;
        };
        let rule_identifier = if canonical_event {
            terminal_historical_rule_identifier
        } else {
            terminal_rule_identifier
        };

        transform_serialized_string(event, "event_time", |value| {
            terminal_imported_event_time(canonical_event, value)
        });
        for field in ["timestamp", "observed_at", "ingested_at"] {
            transform_serialized_string(event, field, terminal_imported_timestamp);
        }
        transform_serialized_string(event, "event_id", terminal_imported_event_id);
        transform_serialized_string(
            event,
            "telltale_version",
            terminal_historical_telltale_version,
        );
        transform_serialized_string(event, "event_type", terminal_imported_event_type);
        transform_serialized_string(event, "severity", |value| {
            terminal_imported_enum(
                "severity",
                &[
                    "informational",
                    "low",
                    "medium",
                    "high",
                    "critical",
                    "warning",
                ],
                value,
            )
        });
        transform_serialized_string(event, "time_source", |value| {
            terminal_imported_enum("time-source", &["observed", "source", "override"], value)
        });
        transform_serialized_string(event, "time_confidence", |value| {
            terminal_imported_enum("time-confidence", &["low", "medium", "high"], value)
        });
        transform_serialized_string(event, "source_path_hash", terminal_evidence_hash);
        terminalize_serialized_source_counts(event);
        transform_serialized_identifier_array(event, "detection_classes", |value| {
            terminal_imported_enum("detection-class", VALID_DETECTION_CLASSES, value)
        });
        transform_serialized_identifier_array(event, "signal_types", |value| {
            terminal_imported_enum("signal-type", VALID_SIGNAL_TYPES, value)
        });
        transform_serialized_identifier_array(event, "analytic_intents", |value| {
            terminal_imported_enum("analytic-intent", VALID_ANALYTIC_INTENTS, value)
        });
        transform_serialized_string(event, "agent", |value| {
            terminal_imported_product_metadata(canonical_event, "agent", value)
        });
        transform_serialized_string(event, "model", |value| {
            terminal_imported_product_metadata(canonical_event, "model", value)
        });
        transform_serialized_string(event, "provider", |value| {
            terminal_imported_product_metadata(canonical_event, "provider", value)
        });
        transform_serialized_string(event, "session_id", |value| {
            terminal_imported_session_id(canonical_event, value)
        });
        transform_serialized_string(event, "client", |value| {
            terminal_imported_client_id(canonical_event, value)
        });
        transform_serialized_string(event, "tool_name", |value| {
            terminal_imported_identifier(canonical_event, "tool", value)
        });
        transform_serialized_identifier_array(event, "rule_ids", rule_identifier);
        transform_serialized_identifier_array(event, "categories", |value| {
            terminal_imported_identifier(canonical_event, "category", value)
        });
        transform_serialized_identifier_array(event, "atlas_tags", terminal_atlas_tag);
        transform_serialized_identifier_array(
            event,
            "mitre_attack_techniques",
            terminal_mitre_attack_technique,
        );
        transform_serialized_string(event, "detection_reason", |value| {
            PrivacySanitizer::sanitize(SanitizationContext::Summary, value)
        });
        transform_serialized_string(event, "time_override_reason", |value| {
            PrivacySanitizer::sanitize(SanitizationContext::Diagnostic, value)
        });
        transform_serialized_string(event, "active_policy_name", |value| {
            terminal_imported_opaque_identifier(canonical_event, "policy", value)
        });

        let risk_entity_type = event
            .get("risk_entity_type")
            .and_then(Value::as_str)
            .map(str::to_string);
        if risk_entity_type.as_deref() == Some("session") {
            transform_serialized_string(event, "risk_entity_value", |value| {
                terminal_imported_session_id(canonical_event, value)
            });
        } else if let Some(kind) = risk_entity_type
            .as_deref()
            .filter(|kind| matches!(*kind, "host" | "user"))
        {
            transform_serialized_string(event, "risk_entity_value", |value| {
                terminal_imported_opaque_identifier(canonical_event, kind, value)
            });
        } else {
            transform_serialized_string(event, "risk_entity_value", |value| {
                PrivacySanitizer::sanitize(SanitizationContext::Summary, value)
            });
        }

        if let Some(tags) = event.get_mut("tags").and_then(Value::as_array_mut) {
            for tag in tags {
                if let Value::String(tag) = tag {
                    *tag = terminal_imported_tag(canonical_event, tag);
                }
            }
        }

        if let Some(evidence) = event.get_mut("evidence").and_then(Value::as_array_mut) {
            for item in evidence {
                let Some(item) = item.as_object_mut() else {
                    continue;
                };
                transform_serialized_string(item, "rule_id", rule_identifier);
                transform_serialized_string(item, "hash", terminal_evidence_hash);
                let Some(field) = item
                    .get("field")
                    .and_then(Value::as_str)
                    .map(str::to_string)
                else {
                    continue;
                };
                transform_serialized_string(item, "field", |value| {
                    terminal_imported_identifier(canonical_event, "evidence-field", value)
                });
                let Some(Value::String(value)) = item.get_mut("redacted_value") else {
                    continue;
                };
                let sanitized = terminal_imported_evidence(
                    canonical_event,
                    Evidence {
                        field,
                        redacted_value: value.to_string(),
                        hash: None,
                        rule_id: None,
                    },
                );
                *value = sanitized.redacted_value;
            }
        }

        if let Some(contributions) = event
            .get_mut("risk_contributions")
            .and_then(Value::as_array_mut)
        {
            let mut rule_id_changed = false;
            for contribution in contributions.iter_mut() {
                let Some(contribution) = contribution.as_object_mut() else {
                    continue;
                };
                let original_id = contribution
                    .get("id")
                    .and_then(Value::as_str)
                    .map(str::to_string);
                transform_serialized_string(contribution, "id", rule_identifier);
                rule_id_changed |=
                    original_id.as_deref() != contribution.get("id").and_then(Value::as_str);
                transform_serialized_string(contribution, "rationale", |value| {
                    RiskContribution::emitted_rationale(value)
                });
            }
            if rule_id_changed {
                sort_serialized_contributions(contributions);
            }
        }

        if let Some(response) = event.get_mut("response") {
            sanitize_serialized_response_metadata(response);
        }

        if let Some(anchors) = event.get_mut("timeline_anchors") {
            sanitize_serialized_timeline_anchors(anchors, canonical_event);
        }

        if let Some(process) = event.get_mut("process") {
            sanitize_serialized_process_context(process, canonical_event);
        }
    }

    sanitize_serialized_value(
        event,
        SanitizationContext::Summary,
        true,
        false,
        canonical_event,
        false,
        SerializedValueScope::Root,
    );
}

fn sort_serialized_contributions(values: &mut Vec<Value>) {
    // Keep the original objects, unknown structure and duplicates. Only a full
    // terminal DTO supplies an ordering key; validators still reject bad data.
    // Validate every transformed row before any reorder. A malformed, extended,
    // or otherwise rejected row leaves the original objects untouched.
    let Ok(parsed) = values
        .iter()
        .map(crate::scoring::historical_risk_contribution)
        .collect::<Result<Vec<_>, _>>()
    else {
        return;
    };
    let mut keyed = std::mem::take(values)
        .into_iter()
        .zip(parsed)
        .collect::<Vec<_>>();
    keyed.sort_by(|(_, left), (_, right)| left.canonical_key().cmp(&right.canonical_key()));
    *values = keyed.into_iter().map(|(value, _)| value).collect();
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SerializedValueScope {
    Root,
    Known(Option<&'static str>),
    RuleIdentifier,
    RuleIdentifiers,
    EvidenceList,
    Evidence,
    ContributionsList,
    Contributions,
    TimelineAnchorList,
    TimelineAnchors,
    Process,
    Extension,
}

fn sanitize_serialized_value(
    value: &mut Value,
    context: SanitizationContext,
    allow_controlled_metadata: bool,
    allow_evidence_hash: bool,
    preserve_historical_markers: bool,
    preserve_terminal_markers: bool,
    scope: SerializedValueScope,
) {
    match value {
        Value::String(text) => {
            let expected_marker = match scope {
                SerializedValueScope::Known(kind) => kind,
                SerializedValueScope::RuleIdentifier => Some("rule"),
                _ => None,
            };
            let preserve_canonical_mitre = expected_marker == Some("mitre-technique")
                && (is_canonical_mitre_attack_technique(text) || is_canonical_mitre_hash(text));
            if preserve_canonical_mitre {
                return;
            }
            // Only the five field-specific rule-ID slots have already crossed
            // their terminal policy. A nested key named `id` is not enough.
            if scope == SerializedValueScope::RuleIdentifier && is_terminal_rule_identifier(text) {
                return;
            }
            if let Some(marker) = parse_canonical_opaque_identifier(text) {
                if preserve_historical_markers && scope == SerializedValueScope::Extension
                    || expected_marker.is_some_and(|kind| kind == marker.kind())
                {
                    return;
                }
                *text = opaque_identifier(expected_marker.unwrap_or("metadata-value"), text);
                return;
            }
            if preserve_terminal_markers
                && text.strip_prefix("allowlist:").is_some_and(|value| {
                    is_canonical_opaque_identifier_for_kind("suppression", value)
                })
            {
                return;
            }
            if context != SanitizationContext::Metadata
                || contains_credential_material(text)
                || !is_safe_structured_identifier(text)
            {
                *text = PrivacySanitizer::sanitize(context, text);
            }
        }
        Value::Array(values) => {
            for value in values {
                let child_scope = match (scope, &*value) {
                    (SerializedValueScope::RuleIdentifiers, Value::String(_)) => {
                        SerializedValueScope::RuleIdentifier
                    }
                    (SerializedValueScope::EvidenceList, Value::Object(_)) => {
                        SerializedValueScope::Evidence
                    }
                    (SerializedValueScope::ContributionsList, Value::Object(_)) => {
                        SerializedValueScope::Contributions
                    }
                    (SerializedValueScope::TimelineAnchorList, Value::Object(_)) => {
                        SerializedValueScope::TimelineAnchors
                    }
                    (
                        SerializedValueScope::RuleIdentifier
                        | SerializedValueScope::RuleIdentifiers
                        | SerializedValueScope::EvidenceList
                        | SerializedValueScope::ContributionsList
                        | SerializedValueScope::TimelineAnchorList
                        | SerializedValueScope::Process,
                        _,
                    ) => SerializedValueScope::Extension,
                    _ => scope,
                };
                sanitize_serialized_value(
                    value,
                    context,
                    false,
                    allow_evidence_hash,
                    preserve_historical_markers,
                    preserve_terminal_markers,
                    child_scope,
                );
            }
        }
        Value::Object(values) => {
            let terminal_evidence_value = allow_evidence_hash
                && values.get("field").and_then(Value::as_str).is_some()
                && values
                    .get("redacted_value")
                    .and_then(Value::as_str)
                    .is_some();
            let risk_entity_type = values
                .get("risk_entity_type")
                .and_then(Value::as_str)
                .map(str::to_string);
            let raw_values = std::mem::take(values);
            for (key, mut value) in raw_values {
                let mut child_scope = serialized_value_scope(scope, &key);
                if key == "risk_entity_value" {
                    child_scope = match risk_entity_type.as_deref() {
                        Some("host") => SerializedValueScope::Known(Some("host")),
                        Some("user") => SerializedValueScope::Known(Some("user")),
                        Some("session") => SerializedValueScope::Known(Some("session")),
                        _ => child_scope,
                    };
                }
                let context = serialized_value_context(&key, allow_controlled_metadata);
                let child_allows_controlled_metadata =
                    allow_controlled_metadata && key == "response";
                let child_preserves_terminal_markers = preserve_terminal_markers
                    || serialized_field_has_terminal_markers(&key)
                    || terminal_evidence_value && key == "field"
                    || key == "risk_entity_value"
                        && matches!(
                            risk_entity_type.as_deref(),
                            Some("host" | "user" | "session")
                        );
                let preserve_hash = (allow_controlled_metadata && key == "source_path_hash"
                    || allow_evidence_hash && key == "hash")
                    && is_canonical_serialized_hash(&value);
                if !(preserve_hash || terminal_evidence_value && key == "redacted_value") {
                    sanitize_serialized_value(
                        &mut value,
                        context,
                        child_allows_controlled_metadata,
                        key == "evidence",
                        preserve_historical_markers,
                        child_preserves_terminal_markers,
                        child_scope,
                    );
                }
                let key = unique_serialized_key(
                    values,
                    terminal_metadata_key(
                        &key,
                        preserve_historical_markers
                            && child_scope == SerializedValueScope::Extension,
                    ),
                );
                values.insert(key, value);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

fn serialized_value_scope(parent: SerializedValueScope, field: &str) -> SerializedValueScope {
    match parent {
        SerializedValueScope::Extension => SerializedValueScope::Extension,
        SerializedValueScope::Root if field == "rule_ids" => SerializedValueScope::RuleIdentifiers,
        SerializedValueScope::Root if field == "evidence" => SerializedValueScope::EvidenceList,
        SerializedValueScope::Root if field == "risk_contributions" => {
            SerializedValueScope::ContributionsList
        }
        SerializedValueScope::Root if field == "timeline_anchors" => {
            SerializedValueScope::TimelineAnchorList
        }
        SerializedValueScope::Root if field == "process" => SerializedValueScope::Process,
        SerializedValueScope::Evidence if field == "rule_id" => {
            SerializedValueScope::RuleIdentifier
        }
        SerializedValueScope::Contributions if field == "id" => {
            SerializedValueScope::RuleIdentifier
        }
        SerializedValueScope::TimelineAnchors if field == "rule_ids" => {
            SerializedValueScope::RuleIdentifiers
        }
        SerializedValueScope::Process if field == "secondary_rule_ids" => {
            SerializedValueScope::RuleIdentifiers
        }
        SerializedValueScope::Root if is_known_serialized_event_field(field) => {
            SerializedValueScope::Known(serialized_field_marker_kind(field))
        }
        SerializedValueScope::Root => SerializedValueScope::Extension,
        _ if is_known_serialized_nested_field(field) => {
            SerializedValueScope::Known(serialized_field_marker_kind(field))
        }
        _ => SerializedValueScope::Extension,
    }
}

fn is_known_serialized_event_field(field: &str) -> bool {
    matches!(
        field,
        "timestamp"
            | "event_time"
            | "observed_at"
            | "ingested_at"
            | "time_source"
            | "time_confidence"
            | "time_override_reason"
            | "schema_version"
            | "event_id"
            | "telltale_version"
            | "event_type"
            | "severity"
            | "risk_score"
            | "risk_contributions"
            | "client"
            | "agent"
            | "model"
            | "provider"
            | "session_id"
            | "source_path_hash"
            | "tool_name"
            | "rule_ids"
            | "categories"
            | "detection_classes"
            | "signal_types"
            | "analytic_intents"
            | "atlas_tags"
            | "tags"
            | "evidence"
            | "timeline_anchors"
            | "response"
            | "source_counts"
            | "component"
            | "check_name"
            | "status"
            | "scan_duration_ms"
            | "rule_count"
            | "threshold_config"
            | "active_policy_name"
            | "emitted_count"
            | "suppressed_count"
            | "scanner_error_count"
            | "informational"
            | "confidence"
            | "detection_reason"
            | "mitre_attack_techniques"
            | "risk_entity_type"
            | "risk_entity_value"
            | "process"
    )
}

fn is_known_serialized_nested_field(field: &str) -> bool {
    matches!(
        field,
        "field"
            | "redacted_value"
            | "hash"
            | "rule_id"
            | "id"
            | "type"
            | "points"
            | "rationale"
            | "entry_index"
            | "recommended_action"
            | "response_playbook"
            | "investigation_summary"
            | "escalation"
            | "host"
            | "user"
            | "source_process_name"
            | "source_process_path"
            | "source_process_id"
            | "source_process_command_line"
            | "target_process_name"
            | "target_process_path"
            | "target_process_id"
            | "target_process_command_line"
            | "parent_process_name"
            | "parent_process_path"
            | "source_event_id"
            | "source_process_inferred"
            | "rule_name"
            | "secondary_rule_ids"
            | "investigation_fields"
            | "falsepositives"
            | "dedup_key"
            | "suppression_window_seconds"
            | "rule_severity"
            | "risk_adjustment"
            | "low"
            | "medium"
            | "high"
            | "critical"
            | "rule_ids"
            | "categories"
            | "evidence_fields"
    )
}

fn serialized_field_marker_kind(field: &str) -> Option<&'static str> {
    match field {
        "event_time" => Some("invalid-event-time"),
        "timestamp" | "observed_at" | "ingested_at" => Some("invalid-timestamp"),
        "time_source" => Some("time-source"),
        "time_confidence" => Some("time-confidence"),
        "event_type" => Some("event-type"),
        "severity" => Some("severity"),
        "agent" => Some("agent"),
        "model" => Some("model"),
        "provider" => Some("provider"),
        "client" => Some("client"),
        "session_id" => Some("session"),
        "tool_name" => Some("tool"),
        "rule_ids" | "rule_id" | "id" | "secondary_rule_ids" => Some("rule"),
        "categories" => Some("category"),
        "field" | "evidence_fields" => Some("evidence-field"),
        "detection_classes" => Some("detection-class"),
        "signal_types" => Some("signal-type"),
        "analytic_intents" => Some("analytic-intent"),
        "atlas_tags" => Some("atlas-tag"),
        "mitre_attack_techniques" => Some("mitre-technique"),
        "tags" => Some("tag"),
        "active_policy_name" => Some("policy"),
        "host" => Some("host"),
        "user" => Some("user"),
        "source_event_id" => Some("source-event"),
        "dedup_key" => Some("dedup"),
        "rule_name" => Some("process-rule"),
        "risk_adjustment" => Some("process-adjustment"),
        "source_process_name" | "target_process_name" | "parent_process_name" => Some("process"),
        "investigation_fields" | "falsepositives" => Some("process-config"),
        _ => None,
    }
}

fn serialized_field_has_terminal_markers(field: &str) -> bool {
    matches!(
        field,
        "event_time"
            | "agent"
            | "model"
            | "provider"
            | "session_id"
            | "client"
            | "tool_name"
            | "categories"
            | "active_policy_name"
            | "tags"
            | "timeline_anchors"
            | "process"
    )
}

fn is_canonical_serialized_hash(value: &Value) -> bool {
    value.as_str().is_some_and(is_canonical_sha256_hex)
}

/// Match the exact lowercase SHA-256 digest form used by canonical Event 3.0
/// evidence and source-path hashes.
pub fn is_canonical_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn terminal_evidence_hash(value: &str) -> String {
    if is_canonical_sha256_hex(value) {
        value.to_string()
    } else {
        evidence_hash(value)
    }
}

fn terminal_source_count_key(value: &str) -> String {
    if is_canonical_source_count_key(value) {
        value.to_string()
    } else {
        format!("source_count:{}", evidence_hash(value))
    }
}

fn is_canonical_source_count_key(value: &str) -> bool {
    let known_source = value.split_once('.').is_some_and(|(client, kind)| {
        is_supported_client_identifier(client) && is_supported_source_kind_identifier(kind)
    });
    if known_source {
        return true;
    }

    let Some(value) = value.strip_prefix("source_count:") else {
        return false;
    };
    let Some((digest, suffix)) = value.split_once(':') else {
        return is_canonical_sha256_hex(value);
    };
    is_canonical_sha256_hex(digest)
        && !suffix.is_empty()
        && suffix.bytes().all(|byte| byte.is_ascii_digit())
}

fn terminal_source_counts(source_counts: BTreeMap<String, u32>) -> BTreeMap<String, u32> {
    let mut emitted = BTreeMap::new();
    let mut pending = Vec::new();
    for (key, count) in source_counts {
        let terminal_key = terminal_source_count_key(&key);
        if is_canonical_source_count_key(&key) {
            emitted.insert(terminal_key, count);
        } else {
            pending.push((terminal_key, count));
        }
    }
    for (key, count) in pending {
        let key = unique_source_count_key(key, |candidate| emitted.contains_key(candidate));
        emitted.insert(key, count);
    }
    emitted
}

fn unique_source_count_key(key: String, key_exists: impl Fn(&str) -> bool) -> String {
    if !key_exists(&key) {
        return key;
    }
    let collision_base = source_count_collision_base(&key);
    let mut suffix = 2;
    loop {
        let candidate = format!("{collision_base}:{suffix}");
        if !key_exists(&candidate) {
            return candidate;
        }
        suffix += 1;
    }
}

fn source_count_collision_base(value: &str) -> String {
    let Some(value) = value.strip_prefix("source_count:") else {
        return format!("source_count:{}", evidence_hash(value));
    };
    let Some((digest, suffix)) = value.split_once(':') else {
        return format!("source_count:{value}");
    };
    if is_canonical_sha256_hex(digest)
        && !suffix.is_empty()
        && suffix.bytes().all(|byte| byte.is_ascii_digit())
    {
        format!("source_count:{digest}")
    } else {
        format!("source_count:{}", evidence_hash(value))
    }
}

fn terminalize_serialized_source_counts(event: &mut serde_json::Map<String, Value>) {
    let Some(source_counts) = event
        .get_mut("source_counts")
        .and_then(Value::as_object_mut)
    else {
        return;
    };
    let mut raw_counts = std::mem::take(source_counts)
        .into_iter()
        .collect::<Vec<_>>();
    raw_counts.sort_by(|left, right| left.0.cmp(&right.0));
    let mut pending = Vec::new();
    for (key, value) in raw_counts {
        let terminal_key = terminal_source_count_key(&key);
        if is_canonical_source_count_key(&key) {
            source_counts.insert(terminal_key, value);
        } else {
            pending.push((terminal_key, value));
        }
    }
    for (key, value) in pending {
        let key = unique_source_count_key(key, |candidate| source_counts.contains_key(candidate));
        source_counts.insert(key, value);
    }
}

fn terminal_mitre_attack_technique(value: &str) -> String {
    if is_canonical_mitre_attack_technique(value) || is_canonical_mitre_hash(value) {
        value.to_string()
    } else {
        format!("mitre:{}", evidence_hash(value))
    }
}

fn is_canonical_mitre_hash(value: &str) -> bool {
    value
        .strip_prefix("mitre:")
        .is_some_and(is_canonical_sha256_hex)
}

/// Accept the ATT&CK technique and sub-technique identifier shape used by the
/// bundled process-chain rules (for example `T1059` and `T1059.001`).
fn is_canonical_mitre_attack_technique(value: &str) -> bool {
    let bytes = value.as_bytes();
    (bytes.len() == 5 || bytes.len() == 9)
        && bytes[0] == b'T'
        && bytes[1..5].iter().all(u8::is_ascii_digit)
        && (bytes.len() == 5 || (bytes[5] == b'.' && bytes[6..].iter().all(u8::is_ascii_digit)))
}

fn terminal_imported_timestamp(value: &str) -> String {
    if parse_event_timestamp(value).is_some()
        || is_canonical_opaque_identifier_for_kind("invalid-timestamp", value)
    {
        value.to_string()
    } else {
        opaque_identifier("invalid-timestamp", value)
    }
}

fn terminal_imported_event_id(value: &str) -> String {
    if is_canonical_event_id(value) {
        return value.to_string();
    }

    let mut digest = evidence_hash(value).into_bytes();
    digest[12] = b'4';
    digest[16] = b'8';
    let digest = String::from_utf8(digest).expect("SHA-256 digest is ASCII");
    format!(
        "telltale-{}-{}-{}-{}-{}",
        &digest[..8],
        &digest[8..12],
        &digest[12..16],
        &digest[16..20],
        &digest[20..32],
    )
}

fn is_canonical_event_id(value: &str) -> bool {
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

fn terminal_imported_event_type(value: &str) -> String {
    terminal_imported_enum("event-type", TEXT_BEARING_EVENT_TYPES, value)
}

fn terminal_imported_enum(kind: &str, allowed: &[&str], value: &str) -> String {
    if allowed.contains(&value) || is_canonical_opaque_identifier_for_kind(kind, value) {
        value.to_string()
    } else {
        opaque_identifier(kind, value)
    }
}

fn serialized_value_context(field: &str, allow_controlled_metadata: bool) -> SanitizationContext {
    if field.contains("error") || field.contains("diagnostic") {
        SanitizationContext::Diagnostic
    } else if field.contains("path") || field == "workspace" {
        SanitizationContext::Path
    } else if field == "url" || field.ends_with("_url") {
        SanitizationContext::Url
    } else if matches!(field, "command" | "arguments" | "tool_result" | "result") {
        SanitizationContext::CommandResult
    } else if allow_controlled_metadata && is_controlled_metadata_key(field) {
        SanitizationContext::Metadata
    } else {
        SanitizationContext::Summary
    }
}

fn is_controlled_metadata_key(field: &str) -> bool {
    matches!(
        field,
        "rule_ids"
            | "categories"
            | "detection_classes"
            | "signal_types"
            | "analytic_intents"
            | "atlas_tags"
            | "response_playbook"
            | "recommended_action"
            | "escalation"
    )
}

fn terminal_metadata_key(key: &str, preserve_historical_markers: bool) -> String {
    if preserve_historical_markers && parse_canonical_opaque_identifier(key).is_some()
        || is_canonical_source_count_key(key)
        || (is_safe_structured_identifier(key) && !contains_credential_material(key))
    {
        key.to_string()
    } else {
        opaque_identifier("metadata-key", key)
    }
}

fn unique_serialized_key(values: &serde_json::Map<String, Value>, key: String) -> String {
    if !values.contains_key(&key) {
        return key;
    }
    let mut suffix = 2;
    loop {
        let candidate = format!("{key}-{suffix}");
        if !values.contains_key(&candidate) {
            return candidate;
        }
        suffix += 1;
    }
}

fn transform_serialized_string(
    event: &mut serde_json::Map<String, Value>,
    field: &str,
    transform: impl FnOnce(&str) -> String,
) {
    let Some(Value::String(value)) = event.get_mut(field) else {
        return;
    };
    *value = transform(value);
}

fn transform_serialized_identifier_array(
    event: &mut serde_json::Map<String, Value>,
    field: &str,
    transform: impl Fn(&str) -> String,
) {
    let Some(values) = event.get_mut(field).and_then(Value::as_array_mut) else {
        return;
    };
    for value in values {
        let Value::String(value) = value else {
            continue;
        };
        *value = transform(value);
    }
}

fn sanitize_serialized_timeline_anchors(anchors: &mut Value, canonical_event: bool) {
    let Some(anchors) = anchors.as_array_mut() else {
        return;
    };
    for anchor in anchors {
        let Some(anchor) = anchor.as_object_mut() else {
            continue;
        };
        transform_serialized_identifier_array(anchor, "rule_ids", |value| {
            if canonical_event {
                terminal_historical_rule_identifier(value)
            } else {
                terminal_rule_identifier(value)
            }
        });
        transform_serialized_identifier_array(anchor, "categories", |value| {
            terminal_imported_identifier(canonical_event, "category", value)
        });
        transform_serialized_identifier_array(anchor, "evidence_fields", |value| {
            terminal_imported_identifier(canonical_event, "evidence-field", value)
        });
    }
}

fn sanitize_serialized_process_context(process: &mut Value, canonical_event: bool) {
    let Some(process) = process.as_object_mut() else {
        return;
    };
    transform_serialized_string(process, "host", |value| {
        terminal_imported_opaque_identifier(canonical_event, "host", value)
    });
    transform_serialized_string(process, "user", |value| {
        terminal_imported_opaque_identifier(canonical_event, "user", value)
    });
    for field in [
        "source_process_name",
        "target_process_name",
        "parent_process_name",
    ] {
        transform_serialized_string(process, field, |value| {
            terminal_imported_identifier(canonical_event, "process", value)
        });
    }
    for field in [
        "source_process_path",
        "target_process_path",
        "parent_process_path",
    ] {
        transform_serialized_string(process, field, |value| {
            PrivacySanitizer::sanitize(SanitizationContext::Path, value)
        });
    }
    for field in ["source_process_command_line", "target_process_command_line"] {
        transform_serialized_string(process, field, |value| {
            PrivacySanitizer::sanitize(SanitizationContext::CommandResult, value)
        });
    }
    transform_serialized_string(process, "source_event_id", |value| {
        terminal_imported_opaque_identifier(canonical_event, "source-event", value)
    });
    transform_serialized_string(process, "dedup_key", |value| {
        terminal_imported_opaque_identifier(canonical_event, "dedup", value)
    });
    transform_serialized_string(process, "rule_name", |value| {
        terminal_imported_opaque_identifier(canonical_event, "process-rule", value)
    });
    transform_serialized_identifier_array(process, "secondary_rule_ids", |value| {
        if canonical_event {
            terminal_historical_rule_identifier(value)
        } else {
            terminal_rule_identifier(value)
        }
    });
    for field in ["investigation_fields", "falsepositives"] {
        let Some(values) = process.get_mut(field).and_then(Value::as_array_mut) else {
            continue;
        };
        for value in values {
            let Value::String(value) = value else {
                continue;
            };
            *value = terminal_imported_opaque_identifier(canonical_event, "process-config", value);
        }
    }
    transform_serialized_string(process, "risk_adjustment", |value| {
        terminal_imported_opaque_identifier(canonical_event, "process-adjustment", value)
    });
}

fn sanitize_serialized_response_metadata(response: &mut Value) {
    let Some(response) = response.as_object_mut() else {
        return;
    };
    for field in [
        "recommended_action",
        "response_playbook",
        "investigation_summary",
        "escalation",
    ] {
        transform_serialized_string(response, field, |value| {
            sanitize_response_text(field, value)
        });
    }
}

fn sanitize_response_text(field: &str, value: &str) -> String {
    let sanitized = PrivacySanitizer::sanitize(SanitizationContext::Summary, value);
    let known_static_value = matches!(
        (field, value),
        (
            "recommended_action",
            "monitor" | "review" | "investigate" | "investigate_immediately"
        ) | ("escalation", "routine_review" | "security_review_required")
    ) || field == "response_playbook"
        && VALID_RESPONSE_PLAYBOOKS.contains(&value);
    if known_static_value {
        value.to_string()
    } else {
        sanitized
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TimelineAnchor {
    pub entry_index: usize,
    pub rule_ids: Vec<String>,
    pub categories: Vec<String>,
    pub evidence_fields: Vec<String>,
}

pub fn canonicalize_timeline_anchors(mut anchors: Vec<TimelineAnchor>) -> Vec<TimelineAnchor> {
    anchors.sort_by_key(|anchor| anchor.entry_index);
    anchors.dedup_by_key(|anchor| anchor.entry_index);
    anchors
}

/// Process-chain context for `process_chain` detections.
///
/// `source_process_*` is the parent, `target_process_*` is the child, and
/// `parent_process_*` is the grandparent when a source reports one. Paths and
/// command lines are preserved as observed, after redaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProcessContext {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    pub source_process_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_process_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_process_id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_process_command_line: Option<String>,
    pub target_process_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_process_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_process_id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_process_command_line: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_process_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_process_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_event_id: Option<String>,
    /// True when the parent was derived from command-line shape rather than
    /// reported by the source.
    pub source_process_inferred: bool,
    pub rule_name: String,
    /// Rules that described the same behaviour and lost deduplication.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub secondary_rule_ids: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub investigation_fields: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub falsepositives: Vec<String>,
    pub dedup_key: String,
    pub suppression_window_seconds: u64,
    /// Severity declared by the rule. The top-level `severity` stays
    /// threshold-derived so that process-chain events band identically to every
    /// other Telltale event; this field preserves the rule author's intent.
    pub rule_severity: String,
    /// Set when a false-positive control lowered the score.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub risk_adjustment: Option<String>,
}

/// The evidence field that marks evidence a detection event omitted to fit
/// within `EVENT3_MAX_INPUT_BYTES`. Its value is the omitted item count for
/// its `rule_id`, in decimal, and it carries no hash.
pub const EVIDENCE_OMITTED_FIELD: &str = "evidence_omitted";

#[derive(Debug, Clone, Serialize)]
pub struct Evidence {
    pub field: String,
    pub redacted_value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ResponseMetadata {
    pub recommended_action: String,
    pub response_playbook: String,
    pub investigation_summary: String,
    pub escalation: String,
}

fn terminal_emittable_event(event: &Event) -> Event {
    let mut emitted = event.clone();
    emitted.event_time = emitted.event_time.as_deref().map(terminal_event_time);
    emitted.time_override_reason = emitted
        .time_override_reason
        .as_deref()
        .map(|value| PrivacySanitizer::sanitize(SanitizationContext::Diagnostic, value));
    emitted.agent = emitted
        .agent
        .as_deref()
        .map(|value| terminal_product_metadata("agent", value));
    emitted.model = emitted
        .model
        .as_deref()
        .map(|value| terminal_product_metadata("model", value));
    emitted.provider = emitted
        .provider
        .as_deref()
        .map(|value| terminal_product_metadata("provider", value));
    emitted.client = terminal_client_id(&emitted.client);
    emitted.session_id = terminal_session_id(&emitted.session_id);
    emitted.telltale_version = TELLTALE_VERSION.to_string();
    emitted.source_path_hash = emitted
        .source_path_hash
        .as_deref()
        .map(terminal_evidence_hash);
    emitted.source_counts = emitted.source_counts.take().map(terminal_source_counts);
    emitted.tool_name = emitted
        .tool_name
        .as_deref()
        .map(|value| terminal_identifier("tool", value));
    emitted.rule_ids = emitted
        .rule_ids
        .iter()
        .map(|value| terminal_rule_identifier(value))
        .collect();
    emitted.categories = emitted
        .categories
        .iter()
        .map(|value| terminal_identifier("category", value))
        .collect();
    emitted.atlas_tags = emitted
        .atlas_tags
        .iter()
        .map(|value| terminal_atlas_tag(value))
        .collect();
    emitted.mitre_attack_techniques = emitted
        .mitre_attack_techniques
        .iter()
        .map(|value| terminal_mitre_attack_technique(value))
        .collect();
    emitted.tags = emitted.tags.iter().map(|tag| terminal_tag(tag)).collect();
    emitted.evidence = emitted
        .evidence
        .iter()
        .cloned()
        .map(terminal_evidence)
        .collect();
    emitted.detection_reason = emitted
        .detection_reason
        .as_deref()
        .map(|value| PrivacySanitizer::sanitize(SanitizationContext::Summary, value));
    emitted.active_policy_name = emitted
        .active_policy_name
        .as_deref()
        .map(|value| opaque_identifier("policy", value));
    emitted.risk_contributions = emitted
        .risk_contributions
        .into_iter()
        .map(RiskContribution::for_emission)
        .collect();
    restore_mapped_contribution_order(&event.risk_contributions, &mut emitted.risk_contributions);
    emitted.timeline_anchors = emitted
        .timeline_anchors
        .iter()
        .cloned()
        .map(|anchor| terminal_timeline_anchor(anchor, terminal_rule_identifier))
        .collect();
    emitted.response = emitted.response.as_ref().map(terminal_response_metadata);
    emitted.risk_entity_value = emitted.risk_entity_value.as_deref().map(|value| {
        match emitted.risk_entity_type.as_deref() {
            Some("host") => opaque_identifier("host", value),
            Some("user") => opaque_identifier("user", value),
            Some("session") => terminal_session_id(value),
            _ => PrivacySanitizer::sanitize(SanitizationContext::Summary, value),
        }
    });
    emitted.process = emitted
        .process
        .as_ref()
        .map(|process| terminal_process_context(process, terminal_rule_identifier));
    emitted
}

const INVALID_CONTROLLED_EVENT_ERROR: &str = "event contains invalid controlled metadata";

const VALID_TIME_SOURCES: &[&str] = &["observed", "source", "override"];
const VALID_TIME_CONFIDENCES: &[&str] = &["low", "medium", "high"];
// Shared with the published vocabulary catalog, not a supported embedding API.
#[doc(hidden)]
pub const VALID_SEVERITIES: &[&str] = &[
    "informational",
    "low",
    "medium",
    "high",
    "critical",
    "warning",
];
// Shared with Rule v1 validation across crates, not a supported embedding API.
// Family-specific profiles below intentionally accept narrower subsets.
#[doc(hidden)]
pub const VALID_DETECTION_CLASSES: &[&str] = &[
    "security_detection",
    "policy_violation",
    "threat_hunting",
    "compliance_observation",
    "operational_health",
    "baseline_deviation",
];
#[doc(hidden)]
pub const VALID_SIGNAL_TYPES: &[&str] = &["atomic", "chain", "correlation", "baseline_deviation"];
#[doc(hidden)]
pub const VALID_ANALYTIC_INTENTS: &[&str] = &["alert", "hunt", "enrich", "baseline", "audit"];
const VALID_CONFIDENCES: &[&str] = &["low", "medium", "high"];
const VALID_RISK_ENTITY_TYPES: &[&str] = &["host", "user", "session"];
// Shared by detection/process-rule validation and the vocabulary catalog.
// Operational Event3 families additionally support `warning` via VALID_SEVERITIES.
#[doc(hidden)]
pub const VALID_DETECTION_SEVERITIES: [&str; 5] =
    ["informational", "low", "medium", "high", "critical"];
const VALID_RESPONSE_ACTIONS: &[&str] = &[
    "monitor",
    "review",
    "investigate",
    "investigate_immediately",
];
const VALID_RESPONSE_PLAYBOOKS: &[&str] = &[
    "telltale-playbook-mcp-prompt-injection",
    "telltale-playbook-credential-access",
    "telltale-playbook-network-egress",
    "telltale-playbook-persistence",
    "telltale-playbook-general-investigation",
];
const VALID_RESPONSE_ESCALATIONS: &[&str] = &["routine_review", "security_review_required"];
const VALID_OPERATIONAL_CHECK_NAMES: &[&str] = &[
    "scanner_error_threshold",
    "scan_duration_threshold",
    "sink_delivery",
    "operational_alert",
];

fn terminal_controlled_fields_are_valid(event: &Event, historical_version: bool) -> bool {
    let version_valid = if historical_version {
        is_schema_valid_telltale_version(&event.telltale_version)
            && !contains_credential_material(&event.telltale_version)
    } else {
        event.telltale_version == TELLTALE_VERSION
    };
    if !is_canonical_event_id(&event.event_id)
        || parse_event_timestamp(&event.timestamp).is_none()
        || parse_event_timestamp(&event.observed_at).is_none()
        || parse_event_timestamp(&event.ingested_at).is_none()
        || event
            .event_time
            .as_deref()
            .is_some_and(|value| !is_valid_terminal_event_time(value))
        || event.schema_version != NATIVE_SCHEMA_VERSION
        || !version_valid
        || !is_allowed_controlled_value(&event.time_source, VALID_TIME_SOURCES)
        || !is_allowed_controlled_value(&event.time_confidence, VALID_TIME_CONFIDENCES)
        || !TEXT_BEARING_EVENT_TYPES.contains(&event.event_type.as_str())
        || !is_allowed_controlled_value(&event.severity, VALID_SEVERITIES)
        || !event
            .detection_classes
            .iter()
            .all(|value| is_allowed_controlled_value(value, VALID_DETECTION_CLASSES))
        || !event
            .signal_types
            .iter()
            .all(|value| is_allowed_controlled_value(value, VALID_SIGNAL_TYPES))
        || !event
            .analytic_intents
            .iter()
            .all(|value| is_allowed_controlled_value(value, VALID_ANALYTIC_INTENTS))
        || event
            .confidence
            .as_deref()
            .is_some_and(|value| !is_allowed_controlled_value(value, VALID_CONFIDENCES))
        || event
            .risk_entity_type
            .as_deref()
            .is_some_and(|value| !is_allowed_controlled_value(value, VALID_RISK_ENTITY_TYPES))
        || event.response.as_ref().is_some_and(|response| {
            !is_allowed_controlled_value(&response.recommended_action, VALID_RESPONSE_ACTIONS)
                || !is_allowed_controlled_value(
                    &response.response_playbook,
                    VALID_RESPONSE_PLAYBOOKS,
                )
                || !is_allowed_controlled_value(&response.escalation, VALID_RESPONSE_ESCALATIONS)
        })
        || event.process.as_ref().is_some_and(|process| {
            !is_allowed_controlled_value(&process.rule_severity, &VALID_DETECTION_SEVERITIES)
        })
    {
        return false;
    }

    match event.event_type.as_str() {
        "activity" => {
            if event.client == "install_inventory" {
                event.time_source == "observed"
                    && event.time_confidence == "low"
                    && event.severity == "informational"
                    && event.session_id == "scanner"
                    && event.risk_score == 0
                    && event.risk_contributions.is_empty()
                    && event.source_path_hash.is_none()
                    && event.tags.len() == 3
                    && event.tags.iter().all(|tag| {
                        matches!(
                            tag.as_str(),
                            "scanner" | "install_inventory" | "metadata_only"
                        )
                    })
                    && event.tags.iter().any(|tag| tag == "scanner")
                    && event.tags.iter().any(|tag| tag == "install_inventory")
                    && event.tags.iter().any(|tag| tag == "metadata_only")
                    && !event.evidence.is_empty()
                    && event.component.as_deref() == Some("scanner")
                    && event.check_name.as_deref() == Some("install_inventory")
                    && event.status.as_deref() == Some("ok")
                    && no_detection_dimensions(event)
                    && no_process_fields(event)
                    && event.response.is_none()
                    && event.source_counts.is_none()
            } else {
                event.severity != "warning"
                    && event.source_path_hash.is_some()
                    && event.component.is_none()
                    && event.check_name.is_none()
                    && event.status.is_none()
                    && no_detection_dimensions(event)
                    && no_process_fields(event)
                    && event.response.is_none()
                    && event.source_counts.is_none()
            }
        }
        "detection" => {
            let suppressed = event.tags.iter().any(|tag| tag == "suppressed");
            let response_controls_valid = if suppressed {
                event.response.is_none()
                    && event.severity == "informational"
                    && event.risk_score == 0
                    && event.risk_contributions.is_empty()
                    && event.timeline_anchors.is_empty()
            } else {
                event.response.is_some()
            };
            event.severity != "warning"
                && !event.rule_ids.is_empty()
                && !event.categories.is_empty()
                && !event.detection_classes.is_empty()
                && !event.signal_types.is_empty()
                && !event.analytic_intents.is_empty()
                && event.source_path_hash.is_some()
                && event.component.is_none()
                && event.check_name.is_none()
                && event.status.is_none()
                && event.confidence.is_none()
                && event.risk_entity_type.is_none()
                && event.process.is_none()
                && event.source_counts.is_none()
                && event.informational.is_none()
                && event.detection_reason.is_none()
                && event.mitre_attack_techniques.is_empty()
                && response_controls_valid
        }
        "session_risk_summary" => {
            event.severity != "warning"
                && event.component.is_none()
                && event.check_name.is_none()
                && event.status.is_none()
                && no_process_fields(event)
                && event.response.is_none()
                && event.source_counts.is_none()
        }
        "health" => {
            event.severity == "informational"
                && event.session_id == "scanner"
                && event.component.as_deref() == Some("scanner")
                && event.check_name.as_deref() == Some("source_discovery")
                && event.status.as_deref() == Some("ok")
                && event.source_counts.is_some()
                && no_detection_dimensions(event)
                && no_process_fields(event)
                && event.response.is_none()
        }
        "scanner_error" => {
            event.severity == "informational"
                && event.session_id == "scanner"
                && event.source_path_hash.is_some()
                && event.component.as_deref() == Some("scanner")
                && event.check_name.as_deref() == Some("source_parse")
                && event.status.as_deref() == Some("degraded")
                && no_detection_dimensions(event)
                && no_process_fields(event)
                && event.response.is_none()
                && event.source_counts.is_none()
        }
        "operational_alert" => {
            event.severity == "warning"
                && event.client == "scanner"
                && event.session_id == "scanner"
                && !event.categories.is_empty()
                && !event.detection_classes.is_empty()
                && event
                    .detection_classes
                    .iter()
                    .all(|value| value == "operational_health")
                && !event.signal_types.is_empty()
                && event.signal_types.iter().all(|value| value == "atomic")
                && !event.analytic_intents.is_empty()
                && event.analytic_intents.iter().all(|value| value == "alert")
                && event.component.as_deref() == Some("scanner")
                && event
                    .check_name
                    .as_deref()
                    .is_some_and(|value| VALID_OPERATIONAL_CHECK_NAMES.contains(&value))
                && event.status.as_deref() == Some("degraded")
                && no_process_fields(event)
                && event.response.is_none()
                && event.source_counts.is_none()
        }
        "process_chain" => {
            event.severity != "warning"
                && !event.rule_ids.is_empty()
                && !event.categories.is_empty()
                && !event.detection_classes.is_empty()
                && !event.signal_types.is_empty()
                && !event.analytic_intents.is_empty()
                && event.source_path_hash.is_some()
                && event.component.is_none()
                && event.check_name.is_none()
                && event.status.is_none()
                && event.informational.is_some()
                && event.confidence.is_some()
                && event.risk_entity_type.is_some()
                && event.risk_entity_value.is_some()
                && event.process.is_some()
                && event.response.is_some()
                && event.source_counts.is_none()
        }
        "correlation" => {
            event.severity != "warning"
                && event.session_id == "correlation"
                && event.event_time.is_some()
                && !event.rule_ids.is_empty()
                && is_exact_controlled_values(&event.categories, &["cross_session_correlation"])
                && is_exact_controlled_values(&event.detection_classes, &["security_detection"])
                && is_exact_controlled_values(&event.signal_types, &["correlation"])
                && is_exact_controlled_values(&event.analytic_intents, &["alert"])
                && event.component.is_none()
                && event.check_name.is_none()
                && event.status.is_none()
                && no_process_fields(event)
                && event.response.is_none()
                && event.source_counts.is_none()
        }
        _ => false,
    }
}

fn response_playbooks_are_valid(event: &Event) -> bool {
    event.response.as_ref().is_none_or(|response| {
        is_allowed_controlled_value(&response.response_playbook, VALID_RESPONSE_PLAYBOOKS)
    })
}

fn is_allowed_controlled_value(value: &str, allowed: &[&str]) -> bool {
    allowed.contains(&value)
}

fn is_valid_terminal_event_time(value: &str) -> bool {
    parse_event_timestamp(value).is_some()
        || is_canonical_opaque_identifier_for_kind("invalid-event-time", value)
}

fn is_exact_controlled_values(values: &[String], expected: &[&str]) -> bool {
    values.len() == expected.len()
        && values
            .iter()
            .zip(expected)
            .all(|(value, expected)| value == expected)
}

fn no_detection_dimensions(event: &Event) -> bool {
    event.rule_ids.is_empty()
        && event.categories.is_empty()
        && event.detection_classes.is_empty()
        && event.signal_types.is_empty()
        && event.analytic_intents.is_empty()
        && event.atlas_tags.is_empty()
        && event.timeline_anchors.is_empty()
}

fn no_process_fields(event: &Event) -> bool {
    event.informational.is_none()
        && event.confidence.is_none()
        && event.detection_reason.is_none()
        && event.mitre_attack_techniques.is_empty()
        && event.risk_entity_type.is_none()
        && event.risk_entity_value.is_none()
        && event.process.is_none()
}

fn terminal_historical_derived_event(event: &Event) -> Event {
    let mut emitted = terminal_emittable_event(event);
    emitted.telltale_version = terminal_historical_telltale_version(&event.telltale_version);
    emitted.agent = event
        .agent
        .as_deref()
        .map(|value| terminal_historical_product_metadata("agent", value));
    emitted.model = event
        .model
        .as_deref()
        .map(|value| terminal_historical_product_metadata("model", value));
    emitted.provider = event
        .provider
        .as_deref()
        .map(|value| terminal_historical_product_metadata("provider", value));
    emitted.client = terminal_historical_client_id(&event.client);
    emitted.session_id = terminal_historical_session_id(&event.session_id);
    emitted.rule_ids = event
        .rule_ids
        .iter()
        .map(|value| terminal_historical_rule_identifier(value))
        .collect();
    emitted.risk_contributions = event
        .risk_contributions
        .iter()
        .cloned()
        .map(RiskContribution::for_historical_emission)
        .collect();
    restore_mapped_contribution_order(&event.risk_contributions, &mut emitted.risk_contributions);
    emitted.categories = event
        .categories
        .iter()
        .map(|value| terminal_historical_identifier("category", value))
        .collect();
    emitted.evidence = event
        .evidence
        .iter()
        .cloned()
        .map(|evidence| terminal_imported_evidence(true, evidence))
        .collect();
    emitted.timeline_anchors = event
        .timeline_anchors
        .iter()
        .cloned()
        .map(|anchor| terminal_timeline_anchor(anchor, terminal_historical_rule_identifier))
        .collect();
    emitted.process = event
        .process
        .as_ref()
        .map(|process| terminal_process_context(process, terminal_historical_rule_identifier));
    emitted
}

fn restore_mapped_contribution_order(before: &[RiskContribution], after: &mut [RiskContribution]) {
    if before
        .iter()
        .zip(after.iter())
        .any(|(before, after)| before.id() != after.id())
    {
        after.sort_by(|left, right| left.canonical_key().cmp(&right.canonical_key()));
    }
}

fn terminal_historical_telltale_version(value: &str) -> String {
    if is_schema_valid_telltale_version(value) && !contains_credential_material(value) {
        value.to_string()
    } else {
        TELLTALE_VERSION.to_string()
    }
}

fn is_schema_valid_telltale_version(value: &str) -> bool {
    let (version, build) = value
        .split_once('+')
        .map_or((value, None), |(version, build)| (version, Some(build)));
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
        .map_or((version, None), |(core, prerelease)| {
            (core, Some(prerelease))
        });
    if prerelease.is_some_and(|prerelease| {
        prerelease.is_empty()
            || !prerelease
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
    }) {
        return false;
    }

    let mut components = core.split('.');
    components.all(|component| {
        !component.is_empty() && component.bytes().all(|byte| byte.is_ascii_digit())
    }) && core.matches('.').count() == 2
}

fn terminal_imported_evidence(canonical_event: bool, evidence: Evidence) -> Evidence {
    let rule_id = evidence.rule_id.as_deref().map(|value| {
        if canonical_event {
            terminal_historical_rule_identifier(value)
        } else {
            terminal_rule_identifier(value)
        }
    });
    let mut emitted = if canonical_event
        && evidence.field == "allowlist"
        && is_canonical_opaque_identifier_for_kind("suppression", &evidence.redacted_value)
    {
        evidence
    } else if evidence.field == "related_detection" {
        Evidence {
            redacted_value: terminal_related_detection(&evidence.redacted_value, canonical_event),
            ..evidence
        }
    } else {
        terminal_evidence(evidence)
    };
    emitted.rule_id = rule_id;
    emitted
}

// Shared with detection projection, which fits a detection event's evidence
// within `EVENT3_MAX_INPUT_BYTES`, not a supported embedding API. The bytes
// this item takes in a serialized event, without its separator.
#[doc(hidden)]
pub fn emitted_evidence_bytes(evidence: &Evidence) -> Option<usize> {
    serde_json::to_vec(&terminal_evidence(evidence.clone()))
        .ok()
        .map(|bytes| bytes.len())
}

fn terminal_evidence(mut evidence: Evidence) -> Evidence {
    if evidence.field == "related_detection" {
        evidence.redacted_value = terminal_related_detection(&evidence.redacted_value, false);
    } else if evidence.field == "allowlist" {
        evidence.redacted_value = opaque_identifier("suppression", &evidence.redacted_value);
    } else {
        let context = if evidence.field.contains("error") {
            SanitizationContext::Diagnostic
        } else if evidence.field.contains("path") || evidence.field == "workspace" {
            SanitizationContext::Path
        } else if evidence.field == "url" || evidence.field.ends_with("_url") {
            SanitizationContext::Url
        } else if matches!(
            evidence.field.as_str(),
            "command" | "arguments" | "tool_result" | "result"
        ) {
            SanitizationContext::CommandResult
        } else {
            SanitizationContext::Evidence
        };
        evidence.redacted_value = PrivacySanitizer::sanitize(context, &evidence.redacted_value);
    }
    evidence.field = terminal_identifier("evidence-field", &evidence.field);
    evidence.hash = evidence.hash.as_deref().map(terminal_evidence_hash);
    evidence.rule_id = evidence.rule_id.as_deref().map(terminal_rule_identifier);
    evidence
}

fn terminal_timeline_anchor(
    mut anchor: TimelineAnchor,
    rule_identifier: fn(&str) -> String,
) -> TimelineAnchor {
    anchor.rule_ids = anchor
        .rule_ids
        .iter()
        .map(|value| rule_identifier(value))
        .collect();
    anchor.categories = anchor
        .categories
        .iter()
        .map(|value| terminal_identifier("category", value))
        .collect();
    anchor.evidence_fields = anchor
        .evidence_fields
        .iter()
        .map(|value| terminal_identifier("evidence-field", value))
        .collect();
    anchor
}

fn terminal_related_detection(value: &str, canonical_event: bool) -> String {
    let mut parts = value.split("; ");
    let Some(session_id) = parts
        .next()
        .and_then(|part| part.strip_prefix("session_id="))
    else {
        return PrivacySanitizer::sanitize(SanitizationContext::Evidence, value);
    };
    let Some(event_id) = parts.next().and_then(|part| part.strip_prefix("event_id=")) else {
        return PrivacySanitizer::sanitize(SanitizationContext::Evidence, value);
    };
    let Some(timestamp) = parts
        .next()
        .and_then(|part| part.strip_prefix("timestamp="))
    else {
        return PrivacySanitizer::sanitize(SanitizationContext::Evidence, value);
    };
    let Some(severity) = parts.next().and_then(|part| part.strip_prefix("severity=")) else {
        return PrivacySanitizer::sanitize(SanitizationContext::Evidence, value);
    };
    let Some(risk_score) = parts
        .next()
        .and_then(|part| part.strip_prefix("risk_score="))
    else {
        return PrivacySanitizer::sanitize(SanitizationContext::Evidence, value);
    };
    if parts.next().is_some() || risk_score.parse::<u64>().is_err() {
        return PrivacySanitizer::sanitize(SanitizationContext::Evidence, value);
    }

    format!(
        "session_id={}; event_id={}; timestamp={}; severity={}; risk_score={risk_score}",
        terminal_imported_session_id(canonical_event, session_id),
        if canonical_event && is_canonical_opaque_identifier_for_kind("event", event_id) {
            event_id.to_string()
        } else {
            terminal_identifier("event", event_id)
        },
        terminal_event_time(timestamp),
        terminal_identifier("severity", severity),
    )
}

fn terminal_process_context(
    process: &ProcessContext,
    rule_identifier: fn(&str) -> String,
) -> ProcessContext {
    let mut emitted = process.clone();
    emitted.host = emitted
        .host
        .as_deref()
        .map(|value| opaque_identifier("host", value));
    emitted.user = emitted
        .user
        .as_deref()
        .map(|value| opaque_identifier("user", value));
    emitted.source_process_name = terminal_identifier("process", &emitted.source_process_name);
    emitted.target_process_name = terminal_identifier("process", &emitted.target_process_name);
    emitted.parent_process_name = emitted
        .parent_process_name
        .as_deref()
        .map(|value| terminal_identifier("process", value));
    emitted.secondary_rule_ids = emitted
        .secondary_rule_ids
        .iter()
        .map(|value| rule_identifier(value))
        .collect();
    emitted.source_process_path = emitted
        .source_process_path
        .as_deref()
        .map(|value| PrivacySanitizer::sanitize(SanitizationContext::Path, value));
    emitted.target_process_path = emitted
        .target_process_path
        .as_deref()
        .map(|value| PrivacySanitizer::sanitize(SanitizationContext::Path, value));
    emitted.parent_process_path = emitted
        .parent_process_path
        .as_deref()
        .map(|value| PrivacySanitizer::sanitize(SanitizationContext::Path, value));
    emitted.source_process_command_line = emitted
        .source_process_command_line
        .as_deref()
        .map(|value| PrivacySanitizer::sanitize(SanitizationContext::CommandResult, value));
    emitted.target_process_command_line = emitted
        .target_process_command_line
        .as_deref()
        .map(|value| PrivacySanitizer::sanitize(SanitizationContext::CommandResult, value));
    emitted.source_event_id = emitted
        .source_event_id
        .as_deref()
        .map(|value| opaque_identifier("source-event", value));
    emitted.dedup_key = opaque_identifier("dedup", &emitted.dedup_key);
    emitted.rule_name = opaque_identifier("process-rule", &emitted.rule_name);
    emitted.investigation_fields = emitted
        .investigation_fields
        .iter()
        .map(|value| opaque_identifier("process-config", value))
        .collect();
    emitted.falsepositives = emitted
        .falsepositives
        .iter()
        .map(|value| opaque_identifier("process-config", value))
        .collect();
    emitted.risk_adjustment = emitted
        .risk_adjustment
        .as_deref()
        .map(|value| opaque_identifier("process-adjustment", value));
    emitted
}

fn terminal_response_metadata(response: &ResponseMetadata) -> ResponseMetadata {
    let mut emitted = response.clone();
    emitted.recommended_action =
        sanitize_response_text("recommended_action", &emitted.recommended_action);
    emitted.response_playbook =
        sanitize_response_text("response_playbook", &emitted.response_playbook);
    emitted.investigation_summary =
        sanitize_response_text("investigation_summary", &emitted.investigation_summary);
    emitted.escalation = sanitize_response_text("escalation", &emitted.escalation);
    emitted
}

fn terminal_event_time(value: &str) -> String {
    if parse_event_timestamp(value).is_some()
        || is_canonical_opaque_identifier_for_kind("invalid-event-time", value)
    {
        value.to_string()
    } else {
        opaque_identifier("invalid-event-time", value)
    }
}

fn terminal_imported_event_time(canonical_event: bool, value: &str) -> String {
    if canonical_event && is_canonical_opaque_identifier_for_kind("invalid-event-time", value) {
        value.to_string()
    } else {
        terminal_event_time(value)
    }
}

fn is_supported_source_kind_identifier(value: &str) -> bool {
    matches!(
        value,
        "json"
            | "jsonl"
            | "archived_jsonl"
            | "headless_jsonl"
            | "sqlite"
            | "legacy_json"
            | "ui_messages_json"
            | "copilot_process_log"
    )
}

#[derive(Debug)]
pub struct DetectionEventInput {
    pub client: ClientId,
    pub agent: Option<String>,
    pub model: Option<String>,
    pub provider: Option<String>,
    pub session_id: String,
    pub source_path_hash: String,
    pub tool_name: Option<String>,
    pub rule_ids: Vec<String>,
    pub categories: Vec<String>,
    pub detection_classes: Vec<String>,
    pub signal_types: Vec<String>,
    pub analytic_intents: Vec<String>,
    pub atlas_tags: Vec<String>,
    pub tags: Vec<String>,
    pub evidence: Vec<Evidence>,
    pub risk_contributions: Vec<RiskContribution>,
    pub event_time: Option<String>,
}

#[derive(Debug)]
pub struct ActivityEventInput {
    pub client: ClientId,
    pub agent: Option<String>,
    pub model: Option<String>,
    pub provider: Option<String>,
    pub session_id: String,
    pub source_path_hash: String,
    pub tool_name: Option<String>,
    pub tags: Vec<String>,
    pub evidence: Vec<Evidence>,
    pub risk_contributions: Vec<RiskContribution>,
    pub event_time: Option<String>,
}

#[derive(Debug)]
pub struct SessionRiskSummaryEventInput {
    pub client: String,
    pub agent: Option<String>,
    pub model: Option<String>,
    pub provider: Option<String>,
    pub session_id: String,
    pub source_path_hash: Option<String>,
    pub rule_ids: Vec<String>,
    pub categories: Vec<String>,
    pub detection_classes: Vec<String>,
    pub signal_types: Vec<String>,
    pub analytic_intents: Vec<String>,
    pub atlas_tags: Vec<String>,
    pub tags: Vec<String>,
    pub evidence: Vec<Evidence>,
    pub risk_contributions: Vec<RiskContribution>,
    pub event_time: Option<String>,
}

#[derive(Debug)]
pub struct OperationalAlertInput {
    pub alert_type: String,
    pub threshold: String,
    pub actual_value: String,
    pub scan_duration_ms: Option<u64>,
    pub scanner_error_count: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OperationalAlertConfig {
    pub max_scanner_errors: u32,
    pub max_scan_duration_ms: u64,
}

impl Default for OperationalAlertConfig {
    fn default() -> Self {
        Self {
            max_scanner_errors: 3,
            max_scan_duration_ms: 300_000, // 5 minutes
        }
    }
}

#[derive(Debug)]
pub struct CorrelationEventInput {
    pub client: String,
    pub agent: Option<String>,
    pub model: Option<String>,
    pub provider: Option<String>,
    pub shared_rule_ids: Vec<String>,
    pub sessions: Vec<CorrelationSessionInput>,
    pub window_start: String,
    pub window_end: String,
    pub max_risk_score: u64,
}

#[derive(Debug)]
pub struct CorrelationSessionInput {
    pub session_id: String,
    pub event_id: String,
    pub timestamp: String,
    pub severity: String,
    pub risk_score: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct HealthEventInput<'a> {
    pub sources: &'a [Source],
    pub source_inventory_change: Option<&'a SourceInventoryChangeSummary>,
    pub scan_duration_ms: u64,
    pub rule_count: usize,
    pub threshold_config: RiskThresholds,
    pub active_policy_name: Option<&'a str>,
    pub emitted_count: u64,
    pub suppressed_count: u64,
    pub scanner_error_count: u64,
}

#[derive(Debug)]
struct EventBuilder {
    constructor_family: NativeEventConstructorFamily,
    event_time: Option<String>,
    event_type: &'static str,
    severity: &'static str,
    risk_score: u64,
    risk_contributions: Vec<RiskContribution>,
    client: String,
    agent: Option<String>,
    model: Option<String>,
    provider: Option<String>,
    session_id: String,
    source_path_hash: Option<String>,
    tool_name: Option<String>,
    rule_ids: Vec<String>,
    categories: Vec<String>,
    detection_classes: Vec<String>,
    signal_types: Vec<String>,
    analytic_intents: Vec<String>,
    atlas_tags: Vec<String>,
    tags: Vec<String>,
    evidence: Vec<Evidence>,
    timeline_anchors: Vec<TimelineAnchor>,
    response: Option<ResponseMetadata>,
    source_counts: Option<BTreeMap<String, u32>>,
    component: Option<String>,
    check_name: Option<String>,
    status: Option<String>,
    scan_duration_ms: Option<u64>,
    rule_count: Option<usize>,
    threshold_config: Option<RiskThresholds>,
    active_policy_name: Option<String>,
    emitted_count: Option<u64>,
    suppressed_count: Option<u64>,
    scanner_error_count: Option<u64>,
}

impl EventBuilder {
    fn build(self) -> Event {
        require_constructor_coverage(self.constructor_family, self.event_type);
        let observed_at_dt = ::time::OffsetDateTime::now_utc();
        let observed_at = time::format_timestamp(observed_at_dt);
        let resolved_time = time::resolve_event_time(self.event_time.as_deref(), observed_at_dt);
        Event {
            timestamp: resolved_time.timestamp,
            event_time: resolved_time.event_time,
            observed_at: observed_at.clone(),
            ingested_at: observed_at,
            time_source: resolved_time.time_source,
            time_confidence: resolved_time.time_confidence,
            time_override_reason: resolved_time.time_override_reason,
            schema_version: NATIVE_SCHEMA_VERSION.to_string(),
            event_id: format!("telltale-{}", Uuid::new_v4()),
            telltale_version: TELLTALE_VERSION.to_string(),
            event_type: self.event_type.to_string(),
            severity: self.severity.to_string(),
            risk_score: self.risk_score,
            risk_contributions: self.risk_contributions,
            client: self.client,
            agent: self.agent,
            model: self.model,
            provider: self.provider,
            session_id: self.session_id,
            source_path_hash: self.source_path_hash,
            tool_name: self.tool_name.filter(|value| value != "null"),
            rule_ids: self.rule_ids,
            categories: self.categories,
            detection_classes: self.detection_classes,
            signal_types: self.signal_types,
            analytic_intents: self.analytic_intents,
            atlas_tags: self.atlas_tags,
            tags: self.tags,
            evidence: self.evidence,
            timeline_anchors: canonicalize_timeline_anchors(self.timeline_anchors),
            response: self.response,
            source_counts: self.source_counts,
            component: self.component,
            check_name: self.check_name,
            status: self.status,
            scan_duration_ms: self.scan_duration_ms,
            rule_count: self.rule_count,
            threshold_config: self.threshold_config,
            active_policy_name: self.active_policy_name,
            emitted_count: self.emitted_count,
            suppressed_count: self.suppressed_count,
            scanner_error_count: self.scanner_error_count,
            // Detection-detail fields are attached by the constructors that
            // have them; every other event type leaves them unset.
            informational: None,
            confidence: None,
            detection_reason: None,
            mitre_attack_techniques: Vec::new(),
            risk_entity_type: None,
            risk_entity_value: None,
            process: None,
        }
    }
}

fn require_constructor_coverage(family: NativeEventConstructorFamily, event_type: &str) {
    assert!(
        NATIVE_EVENT_CONSTRUCTOR_FAMILIES.contains(&family),
        "new Event 3.0 constructor family requires conformance registry coverage"
    );
    assert_eq!(
        family.event_type, event_type,
        "native constructor family and wire event type disagree"
    );
    assert!(
        TEXT_BEARING_EVENT_TYPES.contains(&event_type),
        "new Event 3.0 family requires privacy coverage inventory"
    );
}

fn require_non_empty(
    event_type: &'static str,
    field: &'static str,
    value: &str,
) -> Result<(), RiskAccountingError> {
    if value.trim().is_empty() {
        return Err(RiskAccountingError::EmptyEventField { event_type, field });
    }
    Ok(())
}

fn require_optional_non_empty(
    event_type: &'static str,
    field: &'static str,
    value: Option<&str>,
) -> Result<(), RiskAccountingError> {
    if let Some(value) = value {
        require_non_empty(event_type, field, value)?;
    }
    Ok(())
}

fn require_non_empty_array(
    event_type: &'static str,
    field: &'static str,
    values: &[String],
) -> Result<(), RiskAccountingError> {
    if values.is_empty() || values.iter().any(|value| value.trim().is_empty()) {
        return Err(RiskAccountingError::EmptyEventField { event_type, field });
    }
    Ok(())
}

fn validate_optional_metadata(
    event_type: &'static str,
    agent: Option<&str>,
    model: Option<&str>,
    provider: Option<&str>,
) -> Result<(), RiskAccountingError> {
    require_optional_non_empty(event_type, "agent", agent)?;
    require_optional_non_empty(event_type, "model", model)?;
    require_optional_non_empty(event_type, "provider", provider)
}

fn validate_evidence(
    event_type: &'static str,
    evidence: &[Evidence],
) -> Result<(), RiskAccountingError> {
    for item in evidence {
        require_non_empty(event_type, "evidence.field", &item.field)?;
        require_optional_non_empty(event_type, "evidence.hash", item.hash.as_deref())?;
        if let Some(rule_id) = item.rule_id.as_deref() {
            validate_rule_ids(std::slice::from_ref(&rule_id.to_string()))?;
        }
    }
    Ok(())
}

fn validate_allowed_values(
    event_type: &'static str,
    field: &'static str,
    values: &[String],
    allowed: &[&str],
) -> Result<(), RiskAccountingError> {
    if values
        .iter()
        .any(|value| !allowed.iter().any(|candidate| candidate == value))
    {
        return Err(RiskAccountingError::InvalidEventValue { event_type, field });
    }
    Ok(())
}

fn validate_optional_array_values(
    event_type: &'static str,
    field: &'static str,
    values: &[String],
) -> Result<(), RiskAccountingError> {
    if values.iter().any(|value| value.trim().is_empty()) {
        return Err(RiskAccountingError::EmptyEventField { event_type, field });
    }
    Ok(())
}

fn validate_detection_dimensions(
    event_type: &'static str,
    rule_ids: &[String],
    categories: &[String],
    detection_classes: &[String],
    signal_types: &[String],
    analytic_intents: &[String],
) -> Result<(), RiskAccountingError> {
    require_non_empty_array(event_type, "rule_ids", rule_ids)?;
    require_non_empty_array(event_type, "categories", categories)?;
    require_non_empty_array(event_type, "detection_classes", detection_classes)?;
    require_non_empty_array(event_type, "signal_types", signal_types)?;
    require_non_empty_array(event_type, "analytic_intents", analytic_intents)?;
    validate_allowed_values(
        event_type,
        "detection_classes",
        detection_classes,
        &[
            "security_detection",
            "policy_violation",
            "threat_hunting",
            "compliance_observation",
            "operational_health",
            "baseline_deviation",
        ],
    )?;
    validate_allowed_values(
        event_type,
        "signal_types",
        signal_types,
        &["atomic", "chain", "correlation", "baseline_deviation"],
    )?;
    validate_allowed_values(
        event_type,
        "analytic_intents",
        analytic_intents,
        &["alert", "hunt", "enrich", "baseline", "audit"],
    )?;
    Ok(())
}

fn validate_process_context(process: &ProcessContext) -> Result<(), RiskAccountingError> {
    for (field, value) in [
        ("source_process_name", process.source_process_name.as_str()),
        ("target_process_name", process.target_process_name.as_str()),
        ("rule_name", process.rule_name.as_str()),
        ("dedup_key", process.dedup_key.as_str()),
        ("rule_severity", process.rule_severity.as_str()),
    ] {
        require_non_empty("process_chain", field, value)?;
    }
    for (field, values) in [
        ("secondary_rule_ids", process.secondary_rule_ids.as_slice()),
        (
            "investigation_fields",
            process.investigation_fields.as_slice(),
        ),
        ("falsepositives", process.falsepositives.as_slice()),
    ] {
        if values.iter().any(|value| value.trim().is_empty()) {
            return Err(RiskAccountingError::EmptyEventField {
                event_type: "process_chain",
                field,
            });
        }
    }
    require_optional_non_empty("process_chain", "host", process.host.as_deref())?;
    require_optional_non_empty("process_chain", "user", process.user.as_deref())?;
    require_optional_non_empty(
        "process_chain",
        "source_process_path",
        process.source_process_path.as_deref(),
    )?;
    require_optional_non_empty(
        "process_chain",
        "source_process_command_line",
        process.source_process_command_line.as_deref(),
    )?;
    require_optional_non_empty(
        "process_chain",
        "target_process_path",
        process.target_process_path.as_deref(),
    )?;
    require_optional_non_empty(
        "process_chain",
        "target_process_command_line",
        process.target_process_command_line.as_deref(),
    )?;
    require_optional_non_empty(
        "process_chain",
        "parent_process_name",
        process.parent_process_name.as_deref(),
    )?;
    require_optional_non_empty(
        "process_chain",
        "parent_process_path",
        process.parent_process_path.as_deref(),
    )?;
    require_optional_non_empty(
        "process_chain",
        "source_event_id",
        process.source_event_id.as_deref(),
    )?;
    require_optional_non_empty(
        "process_chain",
        "risk_adjustment",
        process.risk_adjustment.as_deref(),
    )?;
    validate_rule_ids(&process.secondary_rule_ids)?;
    validate_allowed_values(
        "process_chain",
        "rule_severity",
        std::slice::from_ref(&process.rule_severity),
        &["informational", "low", "medium", "high", "critical"],
    )?;
    Ok(())
}

fn validate_correlation_input(input: &CorrelationEventInput) -> Result<(), RiskAccountingError> {
    require_non_empty("correlation", "client", &input.client)?;
    require_non_empty_array("correlation", "shared_rule_ids", &input.shared_rule_ids)?;
    let shared_rule_ids = input.shared_rule_ids.iter().collect::<BTreeSet<_>>();
    if shared_rule_ids.len() != input.shared_rule_ids.len() {
        return Err(RiskAccountingError::DuplicateCorrelationValue {
            field: "shared_rule_ids",
        });
    }
    require_non_empty("correlation", "window_start", &input.window_start)?;
    require_non_empty("correlation", "window_end", &input.window_end)?;

    let window_start = parse_event_timestamp(&input.window_start).ok_or(
        RiskAccountingError::InvalidEventValue {
            event_type: "correlation",
            field: "window_start",
        },
    )?;
    let window_end =
        parse_event_timestamp(&input.window_end).ok_or(RiskAccountingError::InvalidEventValue {
            event_type: "correlation",
            field: "window_end",
        })?;
    if window_start > window_end {
        return Err(RiskAccountingError::InvalidEventValue {
            event_type: "correlation",
            field: "window",
        });
    }

    if input.sessions.len() < 2 {
        return Err(RiskAccountingError::InvalidCorrelationCardinality {
            actual: input.sessions.len(),
        });
    }

    let mut session_ids = BTreeSet::new();
    let mut event_ids = BTreeSet::new();
    for session in &input.sessions {
        require_non_empty("correlation", "session_id", &session.session_id)?;
        require_non_empty("correlation", "event_id", &session.event_id)?;
        require_non_empty("correlation", "timestamp", &session.timestamp)?;
        let timestamp = parse_event_timestamp(&session.timestamp).ok_or(
            RiskAccountingError::InvalidEventValue {
                event_type: "correlation",
                field: "timestamp",
            },
        )?;
        if timestamp < window_start || timestamp > window_end {
            return Err(RiskAccountingError::InvalidEventValue {
                event_type: "correlation",
                field: "timestamp",
            });
        }
        require_non_empty("correlation", "severity", &session.severity)?;
        validate_allowed_values(
            "correlation",
            "severity",
            std::slice::from_ref(&session.severity),
            &["informational", "low", "medium", "high", "critical"],
        )?;
        if !session_ids.insert(&session.session_id) {
            return Err(RiskAccountingError::DuplicateCorrelationValue {
                field: "session_id",
            });
        }
        if !event_ids.insert(&session.event_id) {
            return Err(RiskAccountingError::DuplicateCorrelationValue { field: "event_id" });
        }
    }
    if session_ids.len() < 2 {
        return Err(RiskAccountingError::InvalidCorrelationCardinality {
            actual: session_ids.len(),
        });
    }
    let expected_max = input
        .sessions
        .iter()
        .map(|session| session.risk_score)
        .max()
        .unwrap_or_default();
    if expected_max != input.max_risk_score {
        return Err(RiskAccountingError::InvalidEventValue {
            event_type: "correlation",
            field: "max_risk_score",
        });
    }
    Ok(())
}

pub fn health_event_with_metadata(input: HealthEventInput<'_>) -> Event {
    let sources = input.sources;
    let clients: BTreeSet<&str> = sources
        .iter()
        .map(|source| source.client.as_str())
        .collect();
    let mut evidence = vec![inventory::source_inventory_evidence(sources)];
    if let Some(change) = input.source_inventory_change {
        evidence.push(inventory::source_inventory_change_evidence(change));
    }

    EventBuilder {
        constructor_family: CONSTRUCTOR_FAMILY_HEALTH,
        event_time: None,
        event_type: "health",
        severity: "informational",
        risk_score: 0,
        risk_contributions: Vec::new(),
        client: if clients.is_empty() {
            "none".to_string()
        } else {
            clients.into_iter().collect::<Vec<_>>().join(",")
        },
        agent: None,
        model: None,
        provider: None,
        session_id: "scanner".to_string(),
        source_path_hash: None,
        tool_name: None,
        rule_ids: Vec::new(),
        categories: Vec::new(),
        detection_classes: Vec::new(),
        signal_types: Vec::new(),
        analytic_intents: Vec::new(),
        atlas_tags: Vec::new(),
        tags: vec!["scanner".to_string(), "discovery".to_string()],
        evidence,
        timeline_anchors: Vec::new(),
        response: None,
        source_counts: Some(inventory::source_counts(sources)),
        component: Some("scanner".to_string()),
        check_name: Some("source_discovery".to_string()),
        status: Some("ok".to_string()),
        scan_duration_ms: Some(input.scan_duration_ms),
        rule_count: Some(input.rule_count),
        threshold_config: Some(input.threshold_config),
        active_policy_name: input
            .active_policy_name
            .filter(|name| !name.trim().is_empty())
            .map(str::to_string),
        emitted_count: Some(input.emitted_count),
        suppressed_count: Some(input.suppressed_count),
        scanner_error_count: Some(input.scanner_error_count),
    }
    .build()
}

fn score_for_contributions(
    contributions: &[RiskContribution],
) -> Result<u64, crate::scoring::RiskAccountingError> {
    checked_risk_sum(contributions)
}

pub fn validate_risk_accounting_scope(
    event_type: &str,
    rule_ids: &[String],
    contributions: &[RiskContribution],
) -> Result<(), RiskAccountingError> {
    for contribution in contributions {
        let type_allowed = match event_type {
            "activity" => {
                contribution.contribution_type() == RiskContributionType::BaselineDeviation
            }
            "detection" => matches!(
                contribution.contribution_type(),
                RiskContributionType::DeterministicRule | RiskContributionType::ChainModifier
            ),
            "session_risk_summary" => true,
            _ => true,
        };
        if !type_allowed {
            return Err(RiskAccountingError::ContributionTypeNotAllowed {
                event_type: event_type.to_string(),
                id: contribution.id().to_string(),
                contribution_type: contribution.contribution_type(),
            });
        }

        let rule_backed = matches!(
            contribution.contribution_type(),
            RiskContributionType::DeterministicRule | RiskContributionType::ChainModifier
        );
        if (event_type == "detection" || (event_type == "session_risk_summary" && rule_backed))
            && !rule_ids.iter().any(|rule_id| rule_id == contribution.id())
        {
            return Err(RiskAccountingError::ContributionRuleIdMissing(
                contribution.id().to_string(),
            ));
        }
    }
    Ok(())
}

pub fn validate_rule_ids(rule_ids: &[String]) -> Result<(), RiskAccountingError> {
    for rule_id in rule_ids {
        if !is_native_rule_identifier(rule_id) {
            return Err(RiskAccountingError::InvalidRuleId(rule_id.clone()));
        }
    }
    Ok(())
}

/// Validate identifiers read from terminal Event 3.0, including exact historical
/// replacements. This recognizes syntax, not trusted provenance; native inputs
/// must continue to use [`validate_rule_ids`].
pub fn validate_historical_rule_ids(rule_ids: &[String]) -> Result<(), RiskAccountingError> {
    for rule_id in rule_ids {
        if !is_terminal_rule_identifier(rule_id) {
            return Err(RiskAccountingError::InvalidRuleId(rule_id.clone()));
        }
    }
    Ok(())
}

/// Check historical Event 3.0 accounting without treating replacement IDs as raw
/// native identifiers. Ordering, membership, types, positive points and checked
/// sums remain required. This does not validate the rest of the event.
pub fn validate_historical_risk_accounting(
    event_type: &str,
    rule_ids: &[String],
    contributions: &[RiskContribution],
    declared: u64,
) -> Result<(), RiskAccountingError> {
    validate_historical_rule_ids(rule_ids)?;
    let canonical = canonicalize_terminal_contributions(contributions.to_vec())?;
    if contributions != canonical {
        return Err(RiskAccountingError::NonCanonicalContributions);
    }
    let accounting_event_type = if event_type == "process_chain" {
        "detection"
    } else {
        event_type
    };
    validate_risk_accounting_scope(accounting_event_type, rule_ids, &canonical)?;
    let computed = checked_terminal_risk_sum(&canonical)?;
    if declared != computed {
        return Err(RiskAccountingError::ScoreMismatch { declared, computed });
    }
    Ok(())
}

pub fn detection_event(
    input: DetectionEventInput,
) -> Result<Event, crate::scoring::RiskAccountingError> {
    require_non_empty("detection", "session_id", &input.session_id)?;
    require_non_empty("detection", "source_path_hash", &input.source_path_hash)?;
    validate_optional_metadata(
        "detection",
        input.agent.as_deref(),
        input.model.as_deref(),
        input.provider.as_deref(),
    )?;
    require_optional_non_empty("detection", "tool_name", input.tool_name.as_deref())?;
    validate_rule_ids(&input.rule_ids)?;
    validate_detection_dimensions(
        "detection",
        &input.rule_ids,
        &input.categories,
        &input.detection_classes,
        &input.signal_types,
        &input.analytic_intents,
    )?;
    validate_optional_array_values("detection", "atlas_tags", &input.atlas_tags)?;
    if input.atlas_tags.iter().any(|tag| !is_safe_atlas_tag(tag)) {
        return Err(RiskAccountingError::InvalidEventValue {
            event_type: "detection",
            field: "atlas_tags",
        });
    }
    validate_evidence("detection", &input.evidence)?;
    let risk_contributions = canonicalize_contributions(input.risk_contributions)?;
    validate_risk_accounting_scope("detection", &input.rule_ids, &risk_contributions)?;
    let risk_score = score_for_contributions(&risk_contributions)?;
    let thresholds = load_thresholds();
    let assessment = assess_risk_with_thresholds(risk_score, thresholds);
    let response = time::response_metadata(
        assessment.severity.as_str(),
        &input.rule_ids,
        &input.categories,
        assessment.high_required,
    );
    Ok(EventBuilder {
        constructor_family: CONSTRUCTOR_FAMILY_DETECTION,
        event_time: input.event_time,
        event_type: "detection",
        severity: assessment.severity.as_str(),
        risk_score,
        risk_contributions,
        client: input.client.as_str().to_string(),
        agent: input.agent,
        model: input.model,
        provider: input.provider,
        session_id: input.session_id,
        source_path_hash: Some(input.source_path_hash),
        tool_name: input.tool_name,
        rule_ids: input.rule_ids,
        categories: input.categories,
        detection_classes: input.detection_classes,
        signal_types: input.signal_types,
        analytic_intents: input.analytic_intents,
        atlas_tags: input.atlas_tags,
        tags: input.tags,
        evidence: input.evidence,
        timeline_anchors: Vec::new(),
        response: Some(response),
        source_counts: None,
        component: None,
        check_name: None,
        status: None,
        scan_duration_ms: None,
        rule_count: None,
        threshold_config: None,
        active_policy_name: None,
        emitted_count: None,
        suppressed_count: None,
        scanner_error_count: None,
    }
    .build())
}

#[derive(Debug)]
pub struct ProcessChainEventInput {
    pub client: ClientId,
    pub agent: Option<String>,
    pub model: Option<String>,
    pub provider: Option<String>,
    pub session_id: String,
    pub source_path_hash: String,
    pub tool_name: Option<String>,
    pub rule_ids: Vec<String>,
    pub categories: Vec<String>,
    pub detection_classes: Vec<String>,
    pub signal_types: Vec<String>,
    pub analytic_intents: Vec<String>,
    pub tags: Vec<String>,
    pub evidence: Vec<Evidence>,
    pub risk_contributions: Vec<RiskContribution>,
    pub event_time: Option<String>,
    pub confidence: String,
    pub detection_reason: String,
    pub mitre_attack_techniques: Vec<String>,
    pub risk_entity_type: String,
    pub risk_entity_value: Option<String>,
    pub process: ProcessContext,
}

/// Builds a `process_chain` event.
///
/// Emission and risk are independent: an input with no risk contributions still
/// produces an event, marked `informational` with `risk_score: 0`. Raw process
/// fields remain available to internal state and correlation; emitted bytes use
/// the terminal privacy wrapper.
pub fn process_chain_event(
    input: ProcessChainEventInput,
) -> Result<Event, crate::scoring::RiskAccountingError> {
    require_non_empty("process_chain", "session_id", &input.session_id)?;
    require_non_empty("process_chain", "source_path_hash", &input.source_path_hash)?;
    validate_optional_metadata(
        "process_chain",
        input.agent.as_deref(),
        input.model.as_deref(),
        input.provider.as_deref(),
    )?;
    require_optional_non_empty("process_chain", "tool_name", input.tool_name.as_deref())?;
    validate_detection_dimensions(
        "process_chain",
        &input.rule_ids,
        &input.categories,
        &input.detection_classes,
        &input.signal_types,
        &input.analytic_intents,
    )?;
    require_non_empty("process_chain", "confidence", &input.confidence)?;
    validate_allowed_values(
        "process_chain",
        "confidence",
        std::slice::from_ref(&input.confidence),
        &["low", "medium", "high"],
    )?;
    require_non_empty("process_chain", "detection_reason", &input.detection_reason)?;
    require_non_empty("process_chain", "risk_entity_type", &input.risk_entity_type)?;
    validate_allowed_values(
        "process_chain",
        "risk_entity_type",
        std::slice::from_ref(&input.risk_entity_type),
        &["host", "user", "session"],
    )?;
    let risk_entity_value =
        input
            .risk_entity_value
            .as_deref()
            .ok_or(RiskAccountingError::EmptyEventField {
                event_type: "process_chain",
                field: "risk_entity_value",
            })?;
    require_non_empty("process_chain", "risk_entity_value", risk_entity_value)?;
    validate_process_context(&input.process)?;
    validate_evidence("process_chain", &input.evidence)?;
    validate_optional_array_values(
        "process_chain",
        "mitre_attack_techniques",
        &input.mitre_attack_techniques,
    )?;
    validate_rule_ids(&input.rule_ids)?;
    let risk_contributions = canonicalize_contributions(input.risk_contributions)?;
    // Process-chain risk must be attributable to a rule ID, exactly like a
    // regular detection.
    validate_risk_accounting_scope("detection", &input.rule_ids, &risk_contributions)?;
    let risk_score = score_for_contributions(&risk_contributions)?;
    let thresholds = load_thresholds();
    let assessment = assess_risk_with_thresholds(risk_score, thresholds);
    let response = time::response_metadata(
        assessment.severity.as_str(),
        &input.rule_ids,
        &input.categories,
        assessment.high_required,
    );

    let mut event = EventBuilder {
        constructor_family: CONSTRUCTOR_FAMILY_PROCESS_CHAIN,
        event_time: input.event_time,
        event_type: "process_chain",
        severity: assessment.severity.as_str(),
        risk_score,
        risk_contributions,
        client: input.client.as_str().to_string(),
        agent: input.agent,
        model: input.model,
        provider: input.provider,
        session_id: input.session_id,
        source_path_hash: Some(input.source_path_hash),
        tool_name: input.tool_name,
        rule_ids: input.rule_ids,
        categories: input.categories,
        detection_classes: input.detection_classes,
        signal_types: input.signal_types,
        analytic_intents: input.analytic_intents,
        atlas_tags: Vec::new(),
        tags: input.tags,
        evidence: input.evidence,
        timeline_anchors: Vec::new(),
        response: Some(response),
        source_counts: None,
        component: None,
        check_name: None,
        status: None,
        scan_duration_ms: None,
        rule_count: None,
        threshold_config: None,
        active_policy_name: None,
        emitted_count: None,
        suppressed_count: None,
        scanner_error_count: None,
    }
    .build();

    event.informational = Some(risk_score == 0);
    event.confidence = Some(input.confidence);
    event.detection_reason = Some(input.detection_reason);
    event.mitre_attack_techniques = input.mitre_attack_techniques;
    event.risk_entity_type = Some(input.risk_entity_type);
    event.risk_entity_value = input.risk_entity_value;
    event.process = Some(input.process);
    Ok(event)
}

pub fn activity_event(
    input: ActivityEventInput,
) -> Result<Event, crate::scoring::RiskAccountingError> {
    require_non_empty("activity", "session_id", &input.session_id)?;
    require_non_empty("activity", "source_path_hash", &input.source_path_hash)?;
    validate_optional_metadata(
        "activity",
        input.agent.as_deref(),
        input.model.as_deref(),
        input.provider.as_deref(),
    )?;
    require_optional_non_empty("activity", "tool_name", input.tool_name.as_deref())?;
    validate_evidence("activity", &input.evidence)?;
    let risk_contributions = canonicalize_contributions(input.risk_contributions)?;
    validate_risk_accounting_scope("activity", &[], &risk_contributions)?;
    let risk_score = score_for_contributions(&risk_contributions)?;
    let thresholds = load_thresholds();
    let assessment = assess_risk_with_thresholds(risk_score, thresholds);
    Ok(EventBuilder {
        constructor_family: CONSTRUCTOR_FAMILY_STANDARD_ACTIVITY,
        event_time: input.event_time,
        event_type: "activity",
        severity: assessment.severity.as_str(),
        risk_score,
        risk_contributions,
        client: input.client.as_str().to_string(),
        agent: input.agent,
        model: input.model,
        provider: input.provider,
        session_id: input.session_id,
        source_path_hash: Some(input.source_path_hash),
        tool_name: input.tool_name,
        rule_ids: Vec::new(),
        categories: Vec::new(),
        detection_classes: Vec::new(),
        signal_types: Vec::new(),
        analytic_intents: Vec::new(),
        atlas_tags: Vec::new(),
        tags: input.tags,
        evidence: input.evidence,
        timeline_anchors: Vec::new(),
        response: None,
        source_counts: None,
        component: None,
        check_name: None,
        status: None,
        scan_duration_ms: None,
        rule_count: None,
        threshold_config: None,
        active_policy_name: None,
        emitted_count: None,
        suppressed_count: None,
        scanner_error_count: None,
    }
    .build())
}

pub fn install_inventory_event(
    evidence: Vec<Evidence>,
) -> Result<Event, crate::scoring::RiskAccountingError> {
    if evidence.is_empty() {
        return Err(RiskAccountingError::EmptyEventField {
            event_type: "activity",
            field: "evidence",
        });
    }
    validate_evidence("activity", &evidence)?;
    Ok(EventBuilder {
        constructor_family: CONSTRUCTOR_FAMILY_INSTALL_INVENTORY,
        event_time: None,
        event_type: "activity",
        severity: "informational",
        risk_score: 0,
        risk_contributions: Vec::new(),
        client: "install_inventory".to_string(),
        agent: None,
        model: None,
        provider: None,
        session_id: "scanner".to_string(),
        source_path_hash: None,
        tool_name: None,
        rule_ids: Vec::new(),
        categories: Vec::new(),
        detection_classes: Vec::new(),
        signal_types: Vec::new(),
        analytic_intents: Vec::new(),
        atlas_tags: Vec::new(),
        tags: vec![
            "scanner".to_string(),
            "install_inventory".to_string(),
            "metadata_only".to_string(),
        ],
        evidence,
        timeline_anchors: Vec::new(),
        response: None,
        source_counts: None,
        component: Some("scanner".to_string()),
        check_name: Some("install_inventory".to_string()),
        status: Some("ok".to_string()),
        scan_duration_ms: None,
        rule_count: None,
        threshold_config: None,
        active_policy_name: None,
        emitted_count: None,
        suppressed_count: None,
        scanner_error_count: None,
    }
    .build())
}

pub fn session_risk_summary_event(
    input: SessionRiskSummaryEventInput,
) -> Result<Event, crate::scoring::RiskAccountingError> {
    require_non_empty("session_risk_summary", "client", &input.client)?;
    require_non_empty("session_risk_summary", "session_id", &input.session_id)?;
    validate_optional_metadata(
        "session_risk_summary",
        input.agent.as_deref(),
        input.model.as_deref(),
        input.provider.as_deref(),
    )?;
    require_optional_non_empty(
        "session_risk_summary",
        "source_path_hash",
        input.source_path_hash.as_deref(),
    )?;
    validate_rule_ids(&input.rule_ids)?;
    validate_optional_array_values("session_risk_summary", "categories", &input.categories)?;
    validate_optional_array_values(
        "session_risk_summary",
        "detection_classes",
        &input.detection_classes,
    )?;
    validate_optional_array_values("session_risk_summary", "signal_types", &input.signal_types)?;
    validate_optional_array_values(
        "session_risk_summary",
        "analytic_intents",
        &input.analytic_intents,
    )?;
    validate_allowed_values(
        "session_risk_summary",
        "detection_classes",
        &input.detection_classes,
        &[
            "security_detection",
            "policy_violation",
            "threat_hunting",
            "compliance_observation",
            "operational_health",
            "baseline_deviation",
        ],
    )?;
    validate_allowed_values(
        "session_risk_summary",
        "signal_types",
        &input.signal_types,
        &["atomic", "chain", "correlation", "baseline_deviation"],
    )?;
    validate_allowed_values(
        "session_risk_summary",
        "analytic_intents",
        &input.analytic_intents,
        &["alert", "hunt", "enrich", "baseline", "audit"],
    )?;
    validate_optional_array_values("session_risk_summary", "atlas_tags", &input.atlas_tags)?;
    if input.atlas_tags.iter().any(|tag| !is_safe_atlas_tag(tag)) {
        return Err(RiskAccountingError::InvalidEventValue {
            event_type: "session_risk_summary",
            field: "atlas_tags",
        });
    }
    validate_evidence("session_risk_summary", &input.evidence)?;
    let risk_contributions = canonicalize_contributions(input.risk_contributions)?;
    validate_risk_accounting_scope("session_risk_summary", &input.rule_ids, &risk_contributions)?;
    let risk_score = score_for_contributions(&risk_contributions)?;
    let thresholds = load_thresholds();
    let assessment = assess_risk_with_thresholds(risk_score, thresholds);
    Ok(EventBuilder {
        constructor_family: CONSTRUCTOR_FAMILY_SESSION_RISK_SUMMARY,
        event_time: input.event_time,
        event_type: "session_risk_summary",
        severity: assessment.severity.as_str(),
        risk_score,
        risk_contributions,
        client: input.client,
        agent: input.agent,
        model: input.model,
        provider: input.provider,
        session_id: input.session_id,
        source_path_hash: input.source_path_hash,
        tool_name: None,
        rule_ids: input.rule_ids,
        categories: input.categories,
        detection_classes: input.detection_classes,
        signal_types: input.signal_types,
        analytic_intents: input.analytic_intents,
        atlas_tags: input.atlas_tags,
        tags: input.tags,
        evidence: input.evidence,
        timeline_anchors: Vec::new(),
        response: None,
        source_counts: None,
        component: None,
        check_name: None,
        status: None,
        scan_duration_ms: None,
        rule_count: None,
        threshold_config: None,
        active_policy_name: None,
        emitted_count: None,
        suppressed_count: None,
        scanner_error_count: None,
    }
    .build())
}

pub fn correlation_event(
    input: CorrelationEventInput,
) -> Result<Event, crate::scoring::RiskAccountingError> {
    validate_optional_metadata(
        "correlation",
        input.agent.as_deref(),
        input.model.as_deref(),
        input.provider.as_deref(),
    )?;
    validate_rule_ids(&input.shared_rule_ids)?;
    validate_correlation_input(&input)?;
    let thresholds = load_thresholds();
    let assessment = assess_risk_with_thresholds(input.max_risk_score, thresholds);
    let mut evidence = vec![
        Evidence {
            field: "shared_rule_ids".to_string(),
            redacted_value: input.shared_rule_ids.join(","),
            hash: None,
            rule_id: None,
        },
        Evidence {
            field: "correlation_window".to_string(),
            redacted_value: format!("{}..{}", input.window_start, input.window_end),
            hash: None,
            rule_id: None,
        },
    ];
    evidence.extend(input.sessions.into_iter().map(|session| Evidence {
        field: "related_detection".to_string(),
        redacted_value: format!(
            "session_id={}; event_id={}; timestamp={}; severity={}; risk_score={}",
            session.session_id,
            session.event_id,
            session.timestamp,
            session.severity,
            session.risk_score
        ),
        hash: Some(inventory::evidence_hash(&session.event_id)),
        rule_id: None,
    }));

    Ok(EventBuilder {
        constructor_family: CONSTRUCTOR_FAMILY_CORRELATION,
        event_time: Some(input.window_end.clone()),
        event_type: "correlation",
        severity: assessment.severity.as_str(),
        risk_score: input.max_risk_score,
        risk_contributions: Vec::new(),
        client: input.client,
        agent: input.agent,
        model: input.model,
        provider: input.provider,
        session_id: "correlation".to_string(),
        source_path_hash: None,
        tool_name: None,
        rule_ids: input.shared_rule_ids,
        categories: vec!["cross_session_correlation".to_string()],
        detection_classes: vec!["security_detection".to_string()],
        signal_types: vec!["correlation".to_string()],
        analytic_intents: vec!["alert".to_string()],
        atlas_tags: Vec::new(),
        tags: vec!["correlation".to_string(), "cross_session".to_string()],
        evidence,
        timeline_anchors: Vec::new(),
        response: None,
        source_counts: None,
        component: None,
        check_name: None,
        status: None,
        scan_duration_ms: None,
        rule_count: None,
        threshold_config: None,
        active_policy_name: None,
        emitted_count: None,
        suppressed_count: None,
        scanner_error_count: None,
    }
    .build())
}

pub fn scanner_error_event(source: &Source, error: &impl std::fmt::Display) -> Event {
    let error_msg = redaction::redact_error_message(&error.to_string());
    let source_label = format!(
        "{}:{}:{}",
        source.client.as_str(),
        source.kind.as_str(),
        inventory::display_name(source)
    );
    EventBuilder {
        constructor_family: CONSTRUCTOR_FAMILY_SCANNER_ERROR,
        event_time: None,
        event_type: "scanner_error",
        severity: "informational",
        risk_score: 0,
        risk_contributions: Vec::new(),
        client: source.client.as_str().to_string(),
        agent: None,
        model: None,
        provider: None,
        session_id: "scanner".to_string(),
        source_path_hash: Some(inventory::path_hash(&source.path)),
        tool_name: None,
        rule_ids: Vec::new(),
        categories: Vec::new(),
        detection_classes: Vec::new(),
        signal_types: Vec::new(),
        analytic_intents: Vec::new(),
        atlas_tags: Vec::new(),
        tags: vec!["scanner".to_string(), "parse_failure".to_string()],
        evidence: vec![
            Evidence {
                field: "error".to_string(),
                redacted_value: error_msg,
                hash: None,
                rule_id: None,
            },
            Evidence {
                field: "source_path".to_string(),
                redacted_value: source_label,
                hash: Some(inventory::path_hash(&source.path)),
                rule_id: None,
            },
        ],
        timeline_anchors: Vec::new(),
        response: None,
        source_counts: None,
        component: Some("scanner".to_string()),
        check_name: Some("source_parse".to_string()),
        status: Some("degraded".to_string()),
        scan_duration_ms: None,
        rule_count: None,
        threshold_config: None,
        active_policy_name: None,
        emitted_count: None,
        suppressed_count: None,
        scanner_error_count: None,
    }
    .build()
}

pub fn operational_alert_event(input: OperationalAlertInput) -> Event {
    let mut evidence = vec![
        Evidence {
            field: "alert_type".to_string(),
            redacted_value: input.alert_type.clone(),
            hash: None,
            rule_id: None,
        },
        Evidence {
            field: "threshold".to_string(),
            redacted_value: input.threshold.clone(),
            hash: None,
            rule_id: None,
        },
        Evidence {
            field: "actual_value".to_string(),
            redacted_value: input.actual_value.clone(),
            hash: None,
            rule_id: None,
        },
    ];
    if let Some(duration) = input.scan_duration_ms {
        evidence.push(Evidence {
            field: "scan_duration_ms".to_string(),
            redacted_value: duration.to_string(),
            hash: None,
            rule_id: None,
        });
    }
    if let Some(count) = input.scanner_error_count {
        evidence.push(Evidence {
            field: "scanner_error_count".to_string(),
            redacted_value: count.to_string(),
            hash: None,
            rule_id: None,
        });
    }

    EventBuilder {
        constructor_family: CONSTRUCTOR_FAMILY_OPERATIONAL_ALERT,
        event_time: None,
        event_type: "operational_alert",
        severity: "warning",
        risk_score: 0,
        risk_contributions: Vec::new(),
        client: "scanner".to_string(),
        agent: None,
        model: None,
        provider: None,
        session_id: "scanner".to_string(),
        source_path_hash: None,
        tool_name: None,
        rule_ids: Vec::new(),
        categories: vec!["operational".to_string()],
        detection_classes: vec!["operational_health".to_string()],
        signal_types: vec!["atomic".to_string()],
        analytic_intents: vec!["alert".to_string()],
        atlas_tags: Vec::new(),
        tags: vec!["operational".to_string(), "scanner_health".to_string()],
        evidence,
        timeline_anchors: Vec::new(),
        response: None,
        source_counts: None,
        component: Some("scanner".to_string()),
        check_name: Some(operational_alert_check_name(&input.alert_type).to_string()),
        status: Some("degraded".to_string()),
        scan_duration_ms: input.scan_duration_ms,
        rule_count: None,
        threshold_config: None,
        active_policy_name: None,
        emitted_count: None,
        suppressed_count: None,
        scanner_error_count: None,
    }
    .build()
}

fn operational_alert_check_name(alert_type: &str) -> &str {
    match alert_type {
        "scanner_error_threshold_exceeded" => "scanner_error_threshold",
        "scan_duration_threshold_exceeded" => "scan_duration_threshold",
        "sink_delivery_failure" => "sink_delivery",
        _ => "operational_alert",
    }
}

#[cfg(test)]
mod tests;
