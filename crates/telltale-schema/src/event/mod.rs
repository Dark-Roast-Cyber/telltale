use std::collections::{BTreeMap, BTreeSet};

use serde::{Serialize, Serializer, ser::Error as _};
use serde_json::Value;
use uuid::Uuid;

use crate::clients::ClientId;
use crate::scoring::{
    RiskAccountingError, RiskContribution, RiskContributionType, RiskThresholds,
    assess_risk_with_thresholds, canonicalize_contributions, checked_risk_sum,
    is_canonical_contribution_id, load_thresholds,
};
use crate::source::{Source, SourceInventoryChangeSummary};

mod inventory;
mod redaction;
mod time;

pub use inventory::{evidence_hash, path_hash};
pub use redaction::{
    ControlledMarker, PrivacySanitizer, SanitizationContext, SerializedMarkerCheckError,
    check_serialized_event_markers, redact_sensitive_text,
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
            terminal_imported_enum(
                "detection-class",
                &[
                    "security_detection",
                    "policy_violation",
                    "threat_hunting",
                    "compliance_observation",
                    "operational_health",
                    "baseline_deviation",
                ],
                value,
            )
        });
        transform_serialized_identifier_array(event, "signal_types", |value| {
            terminal_imported_enum(
                "signal-type",
                &["atomic", "chain", "correlation", "baseline_deviation"],
                value,
            )
        });
        transform_serialized_identifier_array(event, "analytic_intents", |value| {
            terminal_imported_enum(
                "analytic-intent",
                &["alert", "hunt", "enrich", "baseline", "audit"],
                value,
            )
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
        transform_serialized_identifier_array(event, "rule_ids", |value| {
            terminal_rule_identifier(value)
        });
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
                transform_serialized_string(item, "rule_id", terminal_rule_identifier);
                transform_serialized_string(item, "hash", terminal_evidence_hash);
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
            for contribution in contributions {
                let Some(contribution) = contribution.as_object_mut() else {
                    continue;
                };
                transform_serialized_string(contribution, "id", terminal_rule_identifier);
                transform_serialized_string(contribution, "rationale", |value| {
                    RiskContribution::emitted_rationale(value)
                });
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

#[derive(Clone, Copy, PartialEq, Eq)]
enum SerializedValueScope {
    Root,
    Known(Option<&'static str>),
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
                SerializedValueScope::Root | SerializedValueScope::Extension => None,
            };
            let preserve_canonical_mitre = expected_marker == Some("mitre-technique")
                && (is_canonical_mitre_attack_technique(text) || is_canonical_mitre_hash(text));
            if preserve_canonical_mitre {
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
                sanitize_serialized_value(
                    value,
                    context,
                    false,
                    allow_evidence_hash,
                    preserve_historical_markers,
                    preserve_terminal_markers,
                    scope,
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
        SerializedValueScope::Root if is_known_serialized_event_field(field) => {
            SerializedValueScope::Known(serialized_field_marker_kind(field))
        }
        SerializedValueScope::Root => SerializedValueScope::Extension,
        SerializedValueScope::Known(_) if is_known_serialized_nested_field(field) => {
            SerializedValueScope::Known(serialized_field_marker_kind(field))
        }
        SerializedValueScope::Known(_) => SerializedValueScope::Extension,
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
        "rule_ids" | "rule_id" | "id" => Some("rule"),
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
        transform_serialized_identifier_array(anchor, "rule_ids", terminal_rule_identifier);
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
    transform_serialized_identifier_array(process, "secondary_rule_ids", terminal_rule_identifier);
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
    emitted.timeline_anchors = emitted
        .timeline_anchors
        .iter()
        .cloned()
        .map(terminal_timeline_anchor)
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
    emitted.process = emitted.process.as_ref().map(terminal_process_context);
    emitted
}

const INVALID_CONTROLLED_EVENT_ERROR: &str = "event contains invalid controlled metadata";

const VALID_TIME_SOURCES: &[&str] = &["observed", "source", "override"];
const VALID_TIME_CONFIDENCES: &[&str] = &["low", "medium", "high"];
const VALID_SEVERITIES: &[&str] = &[
    "informational",
    "low",
    "medium",
    "high",
    "critical",
    "warning",
];
const VALID_DETECTION_CLASSES: &[&str] = &[
    "security_detection",
    "policy_violation",
    "threat_hunting",
    "compliance_observation",
    "operational_health",
    "baseline_deviation",
];
const VALID_SIGNAL_TYPES: &[&str] = &["atomic", "chain", "correlation", "baseline_deviation"];
const VALID_ANALYTIC_INTENTS: &[&str] = &["alert", "hunt", "enrich", "baseline", "audit"];
const VALID_CONFIDENCES: &[&str] = &["low", "medium", "high"];
const VALID_RISK_ENTITY_TYPES: &[&str] = &["host", "user", "session"];
const VALID_PROCESS_RULE_SEVERITIES: &[&str] =
    &["informational", "low", "medium", "high", "critical"];
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
            !is_allowed_controlled_value(&process.rule_severity, VALID_PROCESS_RULE_SEVERITIES)
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
        .map(|value| terminal_rule_identifier(value))
        .collect();
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
    emitted
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
    if let Some(build) = build
        && (build.is_empty()
            || !build
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-')))
    {
        return false;
    }

    let (core, prerelease) = version
        .split_once('-')
        .map_or((version, None), |(core, prerelease)| {
            (core, Some(prerelease))
        });
    if let Some(prerelease) = prerelease
        && (prerelease.is_empty()
            || !prerelease
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-')))
    {
        return false;
    }

    let mut components = core.split('.');
    components.all(|component| {
        !component.is_empty() && component.bytes().all(|byte| byte.is_ascii_digit())
    }) && core.matches('.').count() == 2
}

fn terminal_tag(tag: &str) -> String {
    if let Some(name) = tag.strip_prefix("allowlist:") {
        return format!("allowlist:{}", opaque_identifier("suppression", name));
    }
    terminal_identifier("tag", tag)
}

fn terminal_imported_session_id(canonical_event: bool, value: &str) -> String {
    if canonical_event {
        terminal_historical_session_id(value)
    } else {
        terminal_session_id(value)
    }
}

fn terminal_imported_product_metadata(canonical_event: bool, kind: &str, value: &str) -> String {
    if canonical_event {
        terminal_historical_product_metadata(kind, value)
    } else {
        terminal_product_metadata(kind, value)
    }
}

fn terminal_imported_opaque_identifier(canonical_event: bool, kind: &str, value: &str) -> String {
    if canonical_event {
        terminal_historical_opaque_identifier(kind, value)
    } else {
        opaque_identifier(kind, value)
    }
}

fn terminal_imported_tag(canonical_event: bool, tag: &str) -> String {
    if canonical_event {
        if is_canonical_opaque_identifier_for_kind("tag", tag) {
            return tag.to_string();
        }
        if tag
            .strip_prefix("allowlist:")
            .is_some_and(|value| is_canonical_opaque_identifier_for_kind("suppression", value))
        {
            return tag.to_string();
        }
        terminal_tag(tag)
    } else {
        terminal_tag(tag)
    }
}

fn terminal_imported_evidence(canonical_event: bool, evidence: Evidence) -> Evidence {
    if canonical_event
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
    }
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

fn terminal_timeline_anchor(mut anchor: TimelineAnchor) -> TimelineAnchor {
    anchor.rule_ids = anchor
        .rule_ids
        .iter()
        .map(|value| terminal_rule_identifier(value))
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

fn terminal_process_context(process: &ProcessContext) -> ProcessContext {
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
        .map(|value| terminal_rule_identifier(value))
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

/// Produce an opaque marker for a raw source-derived identifier that must
/// remain correlatable without leaving the terminal privacy boundary.
pub fn opaque_identifier(kind: &str, value: &str) -> String {
    opaque_identifier_for_hash_input(kind, value, value)
}

fn opaque_identifier_for_hash_input(kind: &str, _value: &str, hash_input: &str) -> String {
    let prefix = format!("[{kind}:");
    format!("{prefix}{}]", evidence_hash(hash_input))
}

const CANONICAL_OPAQUE_IDENTIFIER_KINDS: &[&str] = &[
    "agent",
    "analytic-intent",
    "atlas-tag",
    "call",
    "category",
    "client",
    "dedup",
    "detection-class",
    "event",
    "event-type",
    "evidence-field",
    "host",
    "invalid-event-time",
    "invalid-timestamp",
    "metadata-key",
    "metadata-value",
    "model",
    "policy",
    "process",
    "process-adjustment",
    "process-config",
    "process-rule",
    "provider",
    "provenance-kind",
    "risk-summary",
    "rule",
    "rule-source",
    "session",
    "severity",
    "sink",
    "signal-type",
    "source-event",
    "suppression",
    "tag",
    "time-confidence",
    "time-source",
    "tool",
    "user",
];

/// A full-string canonical opaque marker parsed without assigning provenance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CanonicalOpaqueIdentifier<'a> {
    kind: &'a str,
    digest: &'a str,
}

impl CanonicalOpaqueIdentifier<'_> {
    pub fn kind(&self) -> &str {
        self.kind
    }

    pub fn digest(&self) -> &str {
        self.digest
    }
}

/// Recognize the exact marker form emitted by Telltale.
///
/// This validates only marker syntax and a registered marker kind. It does not
/// authenticate the source that supplied the value.
pub fn parse_canonical_opaque_identifier(value: &str) -> Option<CanonicalOpaqueIdentifier<'_>> {
    let body = value.strip_prefix('[')?.strip_suffix(']')?;
    let (kind, digest) = body.split_once(':')?;
    if !CANONICAL_OPAQUE_IDENTIFIER_KINDS.contains(&kind)
        || digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return None;
    }
    Some(CanonicalOpaqueIdentifier { kind, digest })
}

/// Match an exact canonical opaque marker for its expected identity kind.
pub fn is_canonical_opaque_identifier_for_kind(kind: &str, value: &str) -> bool {
    parse_canonical_opaque_identifier(value).is_some_and(|marker| marker.kind == kind)
}

/// Preserve only an exact historical canonical session marker; source values
/// that merely resemble markers are processed through the native policy.
pub fn terminal_historical_session_id(value: &str) -> String {
    if is_canonical_opaque_identifier_for_kind("session", value) {
        value.to_string()
    } else {
        terminal_session_id(value)
    }
}

/// Preserve only an exact historical canonical product marker.
pub fn terminal_historical_product_metadata(kind: &str, value: &str) -> String {
    if is_canonical_opaque_identifier_for_kind(kind, value) {
        value.to_string()
    } else {
        terminal_product_metadata(kind, value)
    }
}

fn terminal_historical_client_id(value: &str) -> String {
    if is_canonical_opaque_identifier_for_kind("client", value) {
        value.to_string()
    } else {
        terminal_client_id(value)
    }
}

/// Preserve only an exact historical canonical marker for an identifier kind.
pub fn terminal_historical_identifier(kind: &str, value: &str) -> String {
    if is_canonical_opaque_identifier_for_kind(kind, value) {
        value.to_string()
    } else {
        terminal_identifier(kind, value)
    }
}

/// Preserve canonical rule identifiers and replace every other value with a
/// deterministic schema-compatible identifier.
pub fn terminal_rule_identifier(value: &str) -> String {
    if is_canonical_contribution_id(value) && !contains_credential_material(value) {
        value.to_string()
    } else {
        format!("redacted.{}", evidence_hash(value))
    }
}

fn terminal_historical_opaque_identifier(kind: &str, value: &str) -> String {
    if is_canonical_opaque_identifier_for_kind(kind, value) {
        value.to_string()
    } else {
        opaque_identifier(kind, value)
    }
}

fn terminal_imported_identifier(canonical_event: bool, kind: &str, value: &str) -> String {
    if canonical_event {
        terminal_historical_identifier(kind, value)
    } else {
        terminal_identifier(kind, value)
    }
}

/// Preserve structurally safe source session identifiers. Other source values
/// remain correlatable through a session-specific domain-separated hash.
pub fn terminal_session_id(value: &str) -> String {
    if is_safe_structured_identifier(value) && !contains_credential_material(value) {
        return value.to_string();
    }
    opaque_identifier_for_hash_input("session", value, &format!("session-id:v1\0{value}"))
}

fn terminal_client_id(value: &str) -> String {
    if matches!(value, "scanner" | "none" | "install_inventory")
        || value.split(',').all(is_supported_client_identifier)
    {
        return value.to_string();
    }
    opaque_identifier("client", value)
}

fn terminal_imported_client_id(canonical_event: bool, value: &str) -> String {
    if canonical_event {
        terminal_historical_client_id(value)
    } else {
        terminal_client_id(value)
    }
}

fn is_supported_client_identifier(value: &str) -> bool {
    matches!(
        value,
        "codex"
            | "claude"
            | "gemini"
            | "openclaw"
            | "qwen"
            | "roocode"
            | "kilocode"
            | "opencode"
            | "copilot"
    )
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

/// Agent, model, and provider are controlled product metadata contexts, not
/// arbitrary evidence. Preserve bounded structured identifiers and hash all
/// other source-provided values under their provenance label.
pub fn terminal_product_metadata(kind: &str, value: &str) -> String {
    if is_safe_product_metadata(kind, value) {
        return value.to_string();
    }
    opaque_identifier(kind, value)
}

fn is_safe_product_metadata(kind: &str, value: &str) -> bool {
    if !is_safe_structured_identifier(value) || contains_credential_material(value) {
        return false;
    }
    match kind {
        "agent" => matches!(
            value,
            "codex"
                | "claude"
                | "gemini"
                | "openclaw"
                | "qwen"
                | "roocode"
                | "kilocode"
                | "opencode"
                | "copilot"
        ),
        "provider" => matches!(
            value,
            "openai"
                | "anthropic"
                | "google"
                | "github"
                | "microsoft"
                | "azure"
                | "ollama"
                | "openrouter"
        ),
        "model" => [
            "gpt-",
            "o1",
            "o3",
            "o4",
            "claude-",
            "gemini-",
            "qwen",
            "llama",
            "mistral",
            "deepseek-",
        ]
        .iter()
        .any(|prefix| value.starts_with(prefix)),
        _ => false,
    }
}

fn is_safe_structured_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'_' | b'-' | b'.' | b':')
        })
}

/// Sanitize an identifier while retaining canonical static labels where safe.
pub fn terminal_identifier(kind: &str, value: &str) -> String {
    if value.len() <= 128
        && !contains_credential_material(value)
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'_' | b'-' | b'.' | b':' | b'>' | b'+')
        })
    {
        return value.to_string();
    }
    opaque_identifier(kind, value)
}

fn is_safe_atlas_tag(value: &str) -> bool {
    value.len() <= 128
        && value.starts_with("atlas:")
        && !contains_credential_material(value)
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_uppercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'_' | b'-' | b'.' | b':')
        })
}

fn terminal_atlas_tag(value: &str) -> String {
    if is_safe_atlas_tag(value) {
        return value.to_string();
    }
    format!("atlas:{}", evidence_hash(value))
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

#[derive(Debug, Clone, Copy)]
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

pub fn load_operational_alert_config() -> OperationalAlertConfig {
    OperationalAlertConfig {
        max_scanner_errors: std::env::var("TELLTALE_OP_ALERT_MAX_SCANNER_ERRORS")
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(3),
        max_scan_duration_ms: std::env::var("TELLTALE_OP_ALERT_MAX_SCAN_DURATION_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(300_000),
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
        if !is_canonical_contribution_id(rule_id) || contains_credential_material(rule_id) {
            return Err(RiskAccountingError::InvalidRuleId(rule_id.clone()));
        }
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
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use super::{
        ActivityEventInput, ControlledMarker, CorrelationEventInput, CorrelationSessionInput,
        DetectionEventInput, Evidence, HealthEventInput, INVALID_CONTROLLED_EVENT_ERROR,
        NATIVE_EVENT_CONSTRUCTOR_FAMILIES, NativeEventConstructorFamily, OperationalAlertInput,
        ProcessChainEventInput, ProcessContext, SessionRiskSummaryEventInput, TELLTALE_VERSION,
        VALID_RESPONSE_PLAYBOOKS, activity_event, check_serialized_event_markers,
        correlation_event, detection_event, evidence_hash, health_event_with_metadata,
        install_inventory_event, is_canonical_opaque_identifier_for_kind, opaque_identifier,
        operational_alert_event, parse_canonical_opaque_identifier, path_hash, process_chain_event,
        sanitize_serialized_event, scanner_error_event, serialize_event_for_emission,
        session_risk_summary_event, terminal_historical_session_id, terminal_identifier,
        terminal_product_metadata, terminal_session_id, validate_risk_accounting_scope,
        validate_rule_ids,
    };
    use crate::clients::ClientId;
    use crate::event::SanitizationContext;
    use crate::scoring::{
        RiskContribution, RiskContributionType, RiskSeverity, RiskThresholds,
        assess_risk_with_thresholds,
    };

    fn test_contribution(points: u64) -> Vec<RiskContribution> {
        vec![
            RiskContribution::new(
                "rule.test",
                RiskContributionType::DeterministicRule,
                points,
                "test rationale",
            )
            .expect("contribution"),
        ]
    }

    fn assert_no_top_level_nulls(event: &serde_json::Value) {
        let fields = event.as_object().expect("serialized event object");
        assert!(
            fields.values().all(|value| !value.is_null()),
            "serialized event contains a top-level null: {event}"
        );
    }

    fn truncated_tail_input(tail: &str) -> (String, String) {
        const INPUT_CAP: usize = 4096;
        let start = INPUT_CAP - 10;
        let input = format!(
            "safe-prefix{}{}",
            " ".repeat(start - "safe-prefix".len()),
            tail
        );
        (input, tail[..INPUT_CAP - start].to_string())
    }

    fn controlled_health_event() -> super::Event {
        health_event_with_metadata(HealthEventInput {
            sources: &[],
            source_inventory_change: None,
            scan_duration_ms: 0,
            rule_count: 0,
            threshold_config: crate::scoring::load_thresholds(),
            active_policy_name: None,
            emitted_count: 0,
            suppressed_count: 0,
            scanner_error_count: 0,
        })
    }

    fn controlled_process_event() -> super::Event {
        process_chain_event(ProcessChainEventInput {
            client: ClientId::Codex,
            agent: None,
            model: None,
            provider: None,
            session_id: "controlled-process-session".to_string(),
            source_path_hash: "controlled-process-source".to_string(),
            tool_name: Some("shell".to_string()),
            rule_ids: vec!["rule.synthetic".to_string()],
            categories: vec!["execution".to_string()],
            detection_classes: vec!["security_detection".to_string()],
            signal_types: vec!["chain".to_string()],
            analytic_intents: vec!["alert".to_string()],
            tags: Vec::new(),
            evidence: Vec::new(),
            risk_contributions: Vec::new(),
            event_time: None,
            confidence: "low".to_string(),
            detection_reason: "synthetic controlled-field fixture".to_string(),
            mitre_attack_techniques: Vec::new(),
            risk_entity_type: "session".to_string(),
            risk_entity_value: Some("controlled-process-session".to_string()),
            process: ProcessContext {
                host: None,
                user: None,
                source_process_name: "shell".to_string(),
                source_process_path: None,
                source_process_id: None,
                source_process_command_line: None,
                target_process_name: "curl".to_string(),
                target_process_path: None,
                target_process_id: None,
                target_process_command_line: None,
                parent_process_name: None,
                parent_process_path: None,
                source_event_id: None,
                source_process_inferred: false,
                rule_name: "synthetic".to_string(),
                secondary_rule_ids: Vec::new(),
                investigation_fields: Vec::new(),
                falsepositives: Vec::new(),
                dedup_key: "controlled-process".to_string(),
                suppression_window_seconds: 0,
                rule_severity: "low".to_string(),
                risk_adjustment: None,
            },
        })
        .expect("controlled process event")
    }

    fn controlled_install_inventory_event() -> super::Event {
        install_inventory_event(vec![Evidence {
            field: "inventory".to_string(),
            redacted_value: "synthetic".to_string(),
            hash: None,
            rule_id: None,
        }])
        .expect("controlled install inventory event")
    }

    fn controlled_correlation_event() -> super::Event {
        correlation_event(CorrelationEventInput {
            client: "codex".to_string(),
            agent: None,
            model: None,
            provider: None,
            shared_rule_ids: vec!["rule.synthetic".to_string()],
            sessions: vec![
                CorrelationSessionInput {
                    session_id: "session-a".to_string(),
                    event_id: "event-a".to_string(),
                    timestamp: "2026-05-01T00:00:00Z".to_string(),
                    severity: "low".to_string(),
                    risk_score: 1,
                },
                CorrelationSessionInput {
                    session_id: "session-b".to_string(),
                    event_id: "event-b".to_string(),
                    timestamp: "2026-05-01T00:01:00Z".to_string(),
                    severity: "low".to_string(),
                    risk_score: 2,
                },
            ],
            window_start: "2026-05-01T00:00:00Z".to_string(),
            window_end: "2026-05-01T00:01:00Z".to_string(),
            max_risk_score: 2,
        })
        .expect("controlled correlation event")
    }

    fn schema_event_type_consts(value: &serde_json::Value, event_types: &mut BTreeSet<String>) {
        match value {
            serde_json::Value::Array(values) => {
                for value in values {
                    schema_event_type_consts(value, event_types);
                }
            }
            serde_json::Value::Object(values) => {
                if let Some(event_type) = values.get("event_type")
                    && let Some(event_type) =
                        event_type.get("const").and_then(|value| value.as_str())
                {
                    event_types.insert(event_type.to_string());
                }
                for value in values.values() {
                    schema_event_type_consts(value, event_types);
                }
            }
            _ => {}
        }
    }

    #[test]
    fn text_bearing_event_types_match_canonical_schema_inventory() {
        let schema_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../schemas/event.schema.json");
        if !schema_path.exists() {
            // Published crate verification intentionally excludes repository-
            // level schemas; the gate runs whenever the canonical schema is
            // present in the repository worktree.
            return;
        }
        let schema_bytes = std::fs::read(schema_path).expect("read canonical event schema");
        let schema: serde_json::Value =
            serde_json::from_slice(&schema_bytes).expect("canonical event schema JSON");
        let mut schema_event_types = BTreeSet::new();
        schema_event_type_consts(&schema, &mut schema_event_types);

        let text_bearing_event_types = super::TEXT_BEARING_EVENT_TYPES
            .iter()
            .map(|event_type| (*event_type).to_string())
            .collect::<BTreeSet<_>>();
        assert_eq!(text_bearing_event_types, schema_event_types);
        let constructor_event_types = NATIVE_EVENT_CONSTRUCTOR_FAMILIES
            .iter()
            .map(|family| family.event_type.to_string())
            .collect::<BTreeSet<_>>();
        assert_eq!(constructor_event_types, schema_event_types);
    }

    #[test]
    fn direct_event_serialization_drops_partial_truncated_credential_prefix() {
        let tail = "sk-abcdefghijklmnopqrstuvwxyz0123456789TT_PRIVACY_DIRECT_TAIL_25";
        let (input, retained_prefix) = truncated_tail_input(tail);
        let event = activity_event(ActivityEventInput {
            client: ClientId::Codex,
            agent: None,
            model: None,
            provider: None,
            session_id: "safe-session".to_string(),
            source_path_hash: "source-hash".to_string(),
            tool_name: Some("shell".to_string()),
            tags: Vec::new(),
            evidence: vec![Evidence {
                field: "evidence".to_string(),
                redacted_value: input,
                hash: None,
                rule_id: None,
            }],
            risk_contributions: Vec::new(),
            event_time: None,
        })
        .expect("activity event");
        let bytes = serde_json::to_vec(&event).expect("direct Event serialization");
        let serialized: serde_json::Value =
            serde_json::from_slice(&bytes).expect("serialized Event JSON");
        let evidence = serialized["evidence"][0]["redacted_value"]
            .as_str()
            .expect("serialized evidence text");

        assert!(!evidence.contains(&retained_prefix));
        assert!(evidence.starts_with("safe-prefix"));
    }

    #[test]
    fn historical_recursion_drops_partial_prefix_in_known_and_unknown_nested_text() {
        let tail = "QWxhZGRpbjpvcGVuIHNlc2FtZQ==TT_PRIVACY_HISTORICAL_TAIL_25";
        let (input, retained_prefix) = truncated_tail_input(tail);
        let mut historical = serde_json::json!({
            "schema_version": "3.0",
            "event_type": "activity",
            "evidence": [{"field": "evidence", "redacted_value": input.clone()}],
            "extensions": {"deep": [{"object": {"array": [input]}}]}
        });

        sanitize_serialized_event(&mut historical);
        let bytes = serde_json::to_vec(&historical).expect("historical Event JSON");
        let serialized = String::from_utf8(bytes).expect("historical UTF-8 JSON");

        assert!(!serialized.contains(&retained_prefix));
        assert!(serialized.contains("safe-prefix"));
        assert!(!serialized.contains(tail));
    }

    #[test]
    fn event_constructor_family_registry_distinguishes_activity_variants() {
        // This checks the current reviewed descriptor inventory. Source review
        // and test maintenance remain necessary for future same-wire families.
        let names = NATIVE_EVENT_CONSTRUCTOR_FAMILIES
            .iter()
            .map(|family| family.name)
            .collect::<BTreeSet<_>>();
        assert_eq!(names.len(), 9);
        assert_eq!(
            NATIVE_EVENT_CONSTRUCTOR_FAMILIES
                .iter()
                .filter(|family| family.event_type == "activity")
                .count(),
            2,
            "standard activity and install inventory must remain separate families"
        );

        let result = std::panic::catch_unwind(|| {
            super::require_constructor_coverage(
                NativeEventConstructorFamily {
                    name: "unregistered",
                    event_type: "activity",
                },
                "activity",
            )
        });
        assert!(
            result.is_err(),
            "constructor registry gate must remain active in all builds"
        );
    }

    #[test]
    fn historical_source_hash_and_mitre_values_are_terminalized_idempotently() {
        let source_hash_marker = "TT_PRIVACY_HISTORICAL_SOURCE_HASH_30";
        let mitre_marker = "TT_PRIVACY_HISTORICAL_MITRE_30";
        let source_count_marker = "TT_PRIVACY_HISTORICAL_SOURCE_COUNT_KEY_30";
        let mut historical = serde_json::json!({
            "schema_version": "3.0",
            "source_path_hash": source_hash_marker,
            "mitre_attack_techniques": [mitre_marker, "T1059.001"],
            "source_counts": {
                "codex.jsonl": 2
            }
        });
        historical["source_counts"][source_count_marker] = serde_json::json!(4);

        sanitize_serialized_event(&mut historical);
        let first = historical.clone();
        sanitize_serialized_event(&mut historical);

        assert_eq!(historical, first);
        assert_eq!(
            historical["source_path_hash"],
            evidence_hash(source_hash_marker)
        );
        assert_eq!(
            historical["mitre_attack_techniques"][0],
            format!("mitre:{}", evidence_hash(mitre_marker))
        );
        assert_eq!(historical["mitre_attack_techniques"][1], "T1059.001");
        let source_count_key = format!("source_count:{}", evidence_hash(source_count_marker));
        assert_eq!(historical["source_counts"][&source_count_key], 4);
        assert_eq!(historical["source_counts"]["codex.jsonl"], 2);
        let bytes = serde_json::to_vec(&historical).expect("historical Event JSON");
        assert!(
            check_serialized_event_markers(
                &bytes,
                "historical-source-and-mitre",
                &[
                    ControlledMarker {
                        id: "source-hash",
                        value: source_hash_marker,
                    },
                    ControlledMarker {
                        id: "mitre-technique",
                        value: mitre_marker,
                    },
                    ControlledMarker {
                        id: "source-count-key",
                        value: source_count_marker,
                    },
                ],
            )
            .is_ok()
        );
    }

    #[test]
    fn direct_source_count_keys_are_terminalized_without_merging_collisions() {
        let marker = "TT_PRIVACY_SOURCE_COUNTS_KEY_30";
        let canonical_fallback = format!("source_count:{}", evidence_hash(marker));
        let canonical_collision = format!("{canonical_fallback}:2");
        let mut source_counts = BTreeMap::new();
        source_counts.insert(marker.to_string(), 3);
        source_counts.insert(canonical_fallback.clone(), 5);
        source_counts.insert(canonical_collision.clone(), 7);
        source_counts.insert("codex.jsonl".to_string(), 11);

        let mut event = health_event_with_metadata(HealthEventInput {
            sources: &[],
            source_inventory_change: None,
            scan_duration_ms: 0,
            rule_count: 0,
            threshold_config: crate::scoring::load_thresholds(),
            active_policy_name: None,
            emitted_count: 0,
            suppressed_count: 0,
            scanner_error_count: 0,
        });
        event.source_counts = Some(source_counts);
        let direct_bytes = serde_json::to_vec(&event).expect("direct health event serialization");
        let repeated_bytes =
            serde_json::to_vec(&event).expect("repeated health event serialization");
        assert_eq!(direct_bytes, repeated_bytes);
        assert!(
            check_serialized_event_markers(
                &direct_bytes,
                "source-count-key",
                &[ControlledMarker {
                    id: "source-count-key",
                    value: marker,
                }],
            )
            .is_ok()
        );

        let emitted: serde_json::Value =
            serde_json::from_slice(&direct_bytes).expect("serialized health event");
        let counts = emitted["source_counts"]
            .as_object()
            .expect("source counts map");
        let mut sanitized = serde_json::json!({ "source_counts": emitted["source_counts"] });
        sanitize_serialized_event(&mut sanitized);
        let first_sanitized = sanitized.clone();
        sanitize_serialized_event(&mut sanitized);
        assert_eq!(sanitized, first_sanitized);
        assert_eq!(counts.len(), 4);
        assert_eq!(counts["codex.jsonl"], 11);
        assert_eq!(counts[&canonical_fallback], 5);
        assert_eq!(counts[&canonical_collision], 7);
        assert_eq!(counts[&format!("{canonical_fallback}:3")], 3);
        assert_eq!(
            counts
                .values()
                .filter_map(serde_json::Value::as_u64)
                .sum::<u64>(),
            26
        );
        assert_eq!(event.source_counts.unwrap().get(marker), Some(&3));
    }

    #[test]
    fn direct_terminal_serialization_replaces_credential_bearing_telltale_version() {
        let credential_version = format!("1.2.3-AKIA{}", "T".repeat(16));
        assert!(super::contains_credential_material(&credential_version));
        let mut event = health_event_with_metadata(HealthEventInput {
            sources: &[],
            source_inventory_change: None,
            scan_duration_ms: 0,
            rule_count: 0,
            threshold_config: crate::scoring::load_thresholds(),
            active_policy_name: None,
            emitted_count: 0,
            suppressed_count: 0,
            scanner_error_count: 0,
        });
        event.telltale_version = credential_version.clone();

        let first = serde_json::to_vec(&event).expect("direct Event serialization");
        let second = serde_json::to_vec(&event).expect("repeated Event serialization");
        assert_eq!(first, second);
        assert!(!String::from_utf8_lossy(&first).contains(&credential_version));
        let emitted: serde_json::Value = serde_json::from_slice(&first).expect("Event JSON");
        assert_eq!(emitted["telltale_version"], TELLTALE_VERSION);
        assert_eq!(event.telltale_version, credential_version);

        let historical_version = "0.4.0-rc.1+build.7";
        let mut historical_event = health_event_with_metadata(HealthEventInput {
            sources: &[],
            source_inventory_change: None,
            scan_duration_ms: 0,
            rule_count: 0,
            threshold_config: crate::scoring::load_thresholds(),
            active_policy_name: None,
            emitted_count: 0,
            suppressed_count: 0,
            scanner_error_count: 0,
        });
        historical_event.telltale_version = historical_version.to_string();
        let historical = serde_json::to_value(historical_event.historical_derived())
            .expect("historical derived Event serialization");
        assert_eq!(historical["telltale_version"], historical_version);
    }

    #[test]
    fn direct_serialization_rejects_invalid_controlled_fields_without_echoing_markers() {
        let marker = |field: &str| format!("TT_PRIVACY_CONTROLLED_{field}_31");
        let mut cases = Vec::new();

        let mut event = controlled_health_event();
        event.time_source = marker("time_source");
        cases.push(("time_source", marker("time_source"), event));

        let mut event = controlled_health_event();
        event.time_confidence = marker("time_confidence");
        cases.push(("time_confidence", marker("time_confidence"), event));

        let mut event = controlled_health_event();
        event.event_type = marker("event_type");
        cases.push(("event_type", marker("event_type"), event));

        let mut event = controlled_health_event();
        event.severity = marker("severity");
        cases.push(("severity", marker("severity"), event));

        let mut event = controlled_process_event();
        event.confidence = Some(marker("confidence"));
        cases.push(("confidence", marker("confidence"), event));

        let mut event = controlled_health_event();
        event.detection_classes = vec![marker("detection_classes")];
        cases.push(("detection_classes", marker("detection_classes"), event));

        let mut event = controlled_health_event();
        event.signal_types = vec![marker("signal_types")];
        cases.push(("signal_types", marker("signal_types"), event));

        let mut event = controlled_health_event();
        event.analytic_intents = vec![marker("analytic_intents")];
        cases.push(("analytic_intents", marker("analytic_intents"), event));

        let mut event = controlled_process_event();
        event.risk_entity_type = Some(marker("risk_entity_type"));
        cases.push(("risk_entity_type", marker("risk_entity_type"), event));

        let mut event = controlled_health_event();
        event.component = Some(marker("component"));
        cases.push(("component", marker("component"), event));

        let mut event = controlled_health_event();
        event.check_name = Some(marker("check_name"));
        cases.push(("check_name", marker("check_name"), event));

        let mut event = controlled_health_event();
        event.status = Some(marker("status"));
        cases.push(("status", marker("status"), event));

        let mut event = controlled_process_event();
        event
            .process
            .as_mut()
            .expect("process context")
            .rule_severity = marker("rule_severity");
        cases.push(("process.rule_severity", marker("rule_severity"), event));

        let mut event = controlled_health_event();
        event.schema_version = marker("schema_version");
        cases.push(("schema_version", marker("schema_version"), event));

        let mut event = controlled_process_event();
        event
            .response
            .as_mut()
            .expect("process response")
            .recommended_action = marker("recommended_action");
        cases.push((
            "response.recommended_action",
            marker("recommended_action"),
            event,
        ));

        let mut event = controlled_process_event();
        event
            .response
            .as_mut()
            .expect("process response")
            .escalation = marker("escalation");
        cases.push(("response.escalation", marker("escalation"), event));

        let mut event = controlled_install_inventory_event();
        event.client = marker("client");
        cases.push(("client", marker("client"), event));

        let mut event = controlled_install_inventory_event();
        event.session_id = marker("session_id");
        cases.push(("session_id", marker("session_id"), event));

        let mut event = controlled_install_inventory_event();
        event.tags[0] = marker("install_tag");
        cases.push(("install.tags", marker("install_tag"), event));

        let mut event = controlled_correlation_event();
        event.categories = vec![marker("correlation_category")];
        cases.push((
            "correlation.categories",
            marker("correlation_category"),
            event,
        ));

        for (field, marker, event) in cases {
            let error = serde_json::to_vec(&event).expect_err(field);
            let message = error.to_string();
            assert!(
                message.contains(INVALID_CONTROLLED_EVENT_ERROR),
                "{field} did not fail with the generic controlled-field error: {message}"
            );
            assert!(
                !message.contains(&marker),
                "{field} echoed its marker: {message}"
            );

            let mut explicit_bytes = Vec::new();
            let mut serializer = serde_json::Serializer::new(&mut explicit_bytes);
            let explicit_error =
                serialize_event_for_emission(&event, &mut serializer).expect_err(field);
            assert_eq!(
                explicit_bytes.len(),
                0,
                "{field} emitted bytes before rejecting its controlled mutation"
            );
            assert_eq!(explicit_error.to_string(), message);
        }
    }

    #[test]
    fn direct_serialization_rejects_unreviewed_response_playbooks_without_echoing_values() {
        let sensitive = "telltale-playbook-credential-access-ghp_AbCdEfGhIjKlMnOpQrStUvWxYz12";
        let cases = [
            (
                "telltale-playbook-unreviewed-operator-escalation",
                "unreviewed",
            ),
            (sensitive, "sensitive"),
        ];

        for (value, case_name) in cases {
            let mut event = controlled_process_event();
            event
                .response
                .as_mut()
                .expect("process response")
                .response_playbook = value.to_string();

            let error = serde_json::to_vec(&event).expect_err(case_name);
            let message = error.to_string();
            assert_eq!(message, INVALID_CONTROLLED_EVENT_ERROR);
            assert!(!message.contains(value));

            let mut bytes = Vec::new();
            let mut serializer = serde_json::Serializer::new(&mut bytes);
            let explicit_error =
                serialize_event_for_emission(&event, &mut serializer).expect_err(case_name);
            assert!(
                bytes.is_empty(),
                "{case_name} emitted bytes before rejection"
            );
            assert_eq!(explicit_error.to_string(), message);
        }
    }

    #[test]
    fn direct_serialization_preserves_reviewed_response_playbooks() {
        for playbook in VALID_RESPONSE_PLAYBOOKS {
            let mut event = controlled_process_event();
            event
                .response
                .as_mut()
                .expect("process response")
                .response_playbook = (*playbook).to_string();

            let emitted: serde_json::Value =
                serde_json::from_slice(&serde_json::to_vec(&event).expect("serialize event"))
                    .expect("serialized event JSON");
            assert_eq!(emitted["response"]["response_playbook"], *playbook);
        }
    }

    #[test]
    fn direct_and_historical_serialization_reject_invalid_event_identity_and_timestamps() {
        let marker = |field: &str| format!("TT_PRIVACY_CANONICAL_{field}_32");
        let mut cases = Vec::new();
        for field in ["event_id", "timestamp", "observed_at", "ingested_at"] {
            let mut event = controlled_health_event();
            let value = marker(field);
            match field {
                "event_id" => event.event_id = value.clone(),
                "timestamp" => event.timestamp = value.clone(),
                "observed_at" => event.observed_at = value.clone(),
                "ingested_at" => event.ingested_at = value.clone(),
                _ => unreachable!("canonical field test case is exhaustive"),
            }
            cases.push((field, value, event));
        }

        for (field, marker, event) in cases {
            let direct_error = serde_json::to_vec(&event).expect_err(field);
            let direct_message = direct_error.to_string();
            assert_eq!(direct_message, INVALID_CONTROLLED_EVENT_ERROR);
            assert!(!direct_message.contains(&marker));

            let historical_error =
                serde_json::to_vec(&event.historical_derived()).expect_err(field);
            let historical_message = historical_error.to_string();
            assert_eq!(historical_message, INVALID_CONTROLLED_EVENT_ERROR);
            assert!(!historical_message.contains(&marker));
        }
    }

    #[test]
    fn terminal_event_time_preserves_only_canonical_or_parseable_values() {
        let marker = "TT_PRIVACY_EVENT_TIME_32";
        let mut event = controlled_process_event();
        event.event_time = Some(marker.to_string());

        let first = serde_json::to_vec(&event).expect("serialize terminal event time");
        let second = serde_json::to_vec(&event).expect("repeat terminal event time");
        assert_eq!(first, second);
        assert!(
            !first
                .as_slice()
                .windows(marker.len())
                .any(|window| window == marker.as_bytes())
        );

        let emitted: serde_json::Value = serde_json::from_slice(&first).expect("event JSON");
        let emitted_event_time = emitted["event_time"].as_str().expect("event_time");
        assert!(is_canonical_opaque_identifier_for_kind(
            "invalid-event-time",
            emitted_event_time
        ));

        let historical = serde_json::to_vec(&event.historical_derived())
            .expect("historical terminal event time");
        assert_eq!(historical, first);
    }

    #[test]
    fn historical_unknown_values_default_to_summary_while_controlled_metadata_is_preserved() {
        let triage_marker = "TT_PRIVACY_HISTORICAL_TRIAGE_25";
        let note_marker = "TT_PRIVACY_HISTORICAL_NOTE_25";
        let deep_marker = "TT_PRIVACY_HISTORICAL_DEEP_25";
        let session_marker = "TT_PRIVACY_HISTORICAL_SESSION_25";
        let key_marker = "TT_PRIVACY_HISTORICAL_UNSAFE_KEY_25";
        let nested_metadata_marker = "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz12";
        let playbook = "telltale-playbook-credential-access";
        let mut historical = serde_json::json!({
            "event_type": "activity",
            "session_id": session_marker,
            "rule_ids": ["secret.env.read"],
            "response": { "response_playbook": playbook },
            "triage": { "reason": format!("TOKEN={triage_marker}") },
            "unknown_extension": {
                "note": format!("TOKEN={note_marker}"),
                "deep": { "array": [{ "text": format!("TOKEN={deep_marker}") }] },
                "rule_ids": [nested_metadata_marker],
                "hash": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
            }
        });
        historical
            .as_object_mut()
            .expect("historical event object")
            .insert(key_marker.to_string(), serde_json::json!("safe value"));

        sanitize_serialized_event(&mut historical);
        let bytes = serde_json::to_vec(&historical).expect("sanitized historical JSON");
        let markers = [
            ControlledMarker {
                id: "triage",
                value: triage_marker,
            },
            ControlledMarker {
                id: "note",
                value: note_marker,
            },
            ControlledMarker {
                id: "deep",
                value: deep_marker,
            },
            ControlledMarker {
                id: "session",
                value: session_marker,
            },
            ControlledMarker {
                id: "key",
                value: key_marker,
            },
            ControlledMarker {
                id: "nested-metadata",
                value: nested_metadata_marker,
            },
        ];
        assert!(check_serialized_event_markers(&bytes, "historical-default", &markers).is_ok());
        assert_eq!(
            super::serialized_value_context("unknown_extension", true),
            SanitizationContext::Summary
        );
        assert_eq!(historical["rule_ids"][0], "secret.env.read");
        assert_eq!(historical["response"]["response_playbook"], playbook);
        assert!(
            historical["triage"]["reason"]
                .as_str()
                .is_some_and(|value| value.contains("[redacted-secret]"))
        );
        assert!(
            historical["unknown_extension"]["note"]
                .as_str()
                .is_some_and(|value| value.contains("[redacted-secret]"))
        );
        assert!(
            historical["unknown_extension"]["deep"]["array"][0]["text"]
                .as_str()
                .is_some_and(|value| value.contains("[redacted-secret]"))
        );
        assert!(
            historical["unknown_extension"]["rule_ids"][0]
                .as_str()
                .is_some_and(|value| value.contains("[redacted-secret]"))
        );
        assert_eq!(historical["unknown_extension"]["hash"], "[encoded-blob]");
    }

    #[test]
    fn native_and_historical_events_hide_sensitive_filesystem_url_paths() {
        let native_marker = "TT_PRIVACY_NATIVE_URL_PATH_USER_25";
        let historical_marker = "TT_PRIVACY_HISTORICAL_URL_PATH_USER_25";
        let deep_marker = "TT_PRIVACY_HISTORICAL_URL_PATH_DEEP_25";
        let authority_marker = "TT_PRIVACY_HISTORICAL_URL_AUTHORITY_25";
        let event = activity_event(ActivityEventInput {
            client: ClientId::Codex,
            agent: None,
            model: None,
            provider: None,
            session_id: "safe-session".to_string(),
            source_path_hash: "source-hash".to_string(),
            tool_name: Some("shell".to_string()),
            tags: Vec::new(),
            evidence: vec![Evidence {
                field: "url".to_string(),
                redacted_value: format!("https://example.invalid/home/{native_marker}/.ssh/id_rsa"),
                hash: None,
                rule_id: None,
            }],
            risk_contributions: Vec::new(),
            event_time: None,
        })
        .expect("native activity event");
        let native_bytes = serde_json::to_vec(&event).expect("native event JSON");
        assert!(!String::from_utf8_lossy(&native_bytes).contains(native_marker));
        assert!(
            String::from_utf8_lossy(&native_bytes)
                .contains("https://example.invalid/[sensitive-path]")
        );

        let mut historical = serde_json::json!({
            "schema_version": "1.0",
            "unknown_extension": {
                "note": format!("https://example.invalid/home/{historical_marker}/.ssh/id_rsa"),
                "deep": [{"value": format!("https://example.invalid/home/{deep_marker}/%2Essh/id%5Frsa")}],
                "authority": {"nested": [format!("https://example.invalid%2Fhome%2F{authority_marker}%2F.ssh%2Fid_rsa")]},
            }
        });
        sanitize_serialized_event(&mut historical);
        let historical_bytes = serde_json::to_vec(&historical).expect("historical JSON");
        assert!(!String::from_utf8_lossy(&historical_bytes).contains(historical_marker));
        assert!(!String::from_utf8_lossy(&historical_bytes).contains(deep_marker));
        assert!(!String::from_utf8_lossy(&historical_bytes).contains(authority_marker));
        assert!(
            String::from_utf8_lossy(&historical_bytes)
                .matches("[sensitive-path]")
                .count()
                >= 2
        );
        assert!(String::from_utf8_lossy(&historical_bytes).contains("[redacted-url]"));
    }

    #[test]
    fn direct_and_historical_events_redact_nested_encoded_urls_inside_outer_components() {
        let marker = "TT_PRIVACY_NESTED_EVENT_BOUNDARY_25";
        let query = format!("https://outer.invalid/?next=https%3A%2F%2Finner.invalid%252F{marker}");
        let path =
            format!("https://outer.invalid/redirect/https%3A%2F%2Finner.invalid%252F{marker}");
        let fragment = format!(
            "https://outer.invalid/#next=https%3A%2F%2Finner.invalid%2523token%253D{marker}"
        );
        let event = activity_event(ActivityEventInput {
            client: ClientId::Codex,
            agent: None,
            model: None,
            provider: None,
            session_id: "nested-boundary-session".to_string(),
            source_path_hash: "nested-boundary-source".to_string(),
            tool_name: Some("shell".to_string()),
            tags: Vec::new(),
            evidence: vec![
                Evidence {
                    field: "url".to_string(),
                    redacted_value: query.clone(),
                    hash: None,
                    rule_id: None,
                },
                Evidence {
                    field: "path".to_string(),
                    redacted_value: path.clone(),
                    hash: None,
                    rule_id: None,
                },
                Evidence {
                    field: "fragment".to_string(),
                    redacted_value: fragment.clone(),
                    hash: None,
                    rule_id: None,
                },
            ],
            risk_contributions: Vec::new(),
            event_time: None,
        })
        .expect("nested URL activity event");

        let direct = serde_json::to_vec(&event).expect("direct Event JSON");
        assert!(
            check_serialized_event_markers(
                &direct,
                "direct-nested-url-components",
                &[ControlledMarker {
                    id: "nested-url",
                    value: marker,
                }],
            )
            .is_ok(),
            "direct Event serialization retained a nested URL marker"
        );
        let direct_text = String::from_utf8_lossy(&direct);
        assert!(
            !direct_text.contains("https%3A%2F%2Finner.invalid"),
            "direct Event serialization retained a nested encoded URL prefix"
        );
        assert!(direct_text.contains("[redacted-url]"));
        assert_eq!(
            serde_json::to_vec(&event).expect("repeat direct Event JSON"),
            direct,
            "direct Event serialization must be idempotent"
        );

        let mut historical = serde_json::json!({
            "schema_version": "1.0",
            "unknown_extension": {
                "diagnostic": query,
                "nested": {
                    "path": path,
                    "fragment": fragment,
                },
            },
        });
        sanitize_serialized_event(&mut historical);
        let first_historical = historical.clone();
        sanitize_serialized_event(&mut historical);
        assert_eq!(
            historical, first_historical,
            "historical sanitization must be idempotent"
        );
        let historical_bytes = serde_json::to_vec(&historical).expect("historical Event JSON");
        assert!(
            check_serialized_event_markers(
                &historical_bytes,
                "historical-nested-url-components",
                &[ControlledMarker {
                    id: "nested-url",
                    value: marker,
                }],
            )
            .is_ok(),
            "historical recursive sanitization retained a nested URL marker"
        );
        let historical_text = String::from_utf8_lossy(&historical_bytes);
        assert!(
            !historical_text.contains("https%3A%2F%2Finner.invalid"),
            "historical recursive sanitization retained a nested encoded URL prefix"
        );
        assert!(historical_text.contains("[redacted-url]"));
    }

    #[test]
    fn activity_event_serialization_omits_unset_optional_fields() {
        let event = serde_json::to_value(
            activity_event(ActivityEventInput {
                client: ClientId::Codex,
                agent: None,
                model: None,
                provider: None,
                session_id: "session".to_string(),
                source_path_hash: "hash".to_string(),
                tool_name: Some("shell".to_string()),
                tags: vec!["tag".to_string()],
                evidence: vec![Evidence {
                    field: "activity".to_string(),
                    redacted_value: "summary".to_string(),
                    hash: None,
                    rule_id: None,
                }],
                risk_contributions: Vec::new(),
                event_time: None,
            })
            .expect("build activity event"),
        )
        .expect("serialize activity event");

        assert_no_top_level_nulls(&event);
        assert_eq!(event["event_type"], "activity");
        assert_eq!(event["risk_score"], 0);
        assert_eq!(event["risk_contributions"], serde_json::json!([]));
        assert_eq!(event["source_path_hash"], evidence_hash("hash"));
        assert_eq!(event["tool_name"], "shell");
        assert!(event.get("agent").is_none());
        assert!(event.get("component").is_none());
        for field in [
            "rule_ids",
            "categories",
            "detection_classes",
            "signal_types",
            "analytic_intents",
            "atlas_tags",
        ] {
            assert!(event.get(field).is_none(), "{field} should be omitted");
        }
        assert!(event["evidence"][0].get("hash").is_none());
        assert!(event["evidence"][0].get("rule_id").is_none());
    }

    #[test]
    fn workspace_is_not_a_top_level_field_but_workspace_evidence_stays_path_safe() {
        let marker = "TT_PRIVACY_WORKSPACE_EVIDENCE_30";
        let event = activity_event(ActivityEventInput {
            client: ClientId::Codex,
            agent: None,
            model: None,
            provider: None,
            session_id: "workspace-evidence-session".to_string(),
            source_path_hash: "workspace-evidence-source".to_string(),
            tool_name: None,
            tags: Vec::new(),
            evidence: vec![Evidence {
                field: "workspace".to_string(),
                redacted_value: format!("/home/{marker}/.ssh/id_rsa"),
                hash: None,
                rule_id: None,
            }],
            risk_contributions: Vec::new(),
            event_time: None,
        })
        .expect("activity event");
        let bytes = serde_json::to_vec(&event).expect("terminal activity event");
        let emitted: serde_json::Value = serde_json::from_slice(&bytes).expect("event JSON");

        assert!(emitted.get("workspace").is_none());
        assert_eq!(emitted["evidence"][0]["field"], "workspace");
        assert_eq!(emitted["evidence"][0]["redacted_value"], "[sensitive-path]");
        assert!(
            check_serialized_event_markers(
                &bytes,
                "workspace-evidence",
                &[ControlledMarker {
                    id: "workspace-marker",
                    value: marker,
                }],
            )
            .is_ok()
        );
    }

    #[test]
    fn activity_event_emits_canonical_contribution_order_and_sum() {
        let z = RiskContribution::new(
            "baseline.z",
            RiskContributionType::BaselineDeviation,
            3,
            "z",
        )
        .expect("contribution");
        let a = RiskContribution::new(
            "baseline.a",
            RiskContributionType::BaselineDeviation,
            4,
            "a",
        )
        .expect("contribution");
        let event = activity_event(ActivityEventInput {
            client: ClientId::Codex,
            agent: None,
            model: None,
            provider: None,
            session_id: "session".to_string(),
            source_path_hash: "hash".to_string(),
            tool_name: Some("shell".to_string()),
            tags: Vec::new(),
            evidence: Vec::new(),
            risk_contributions: vec![z.clone(), a.clone(), z],
            event_time: None,
        })
        .expect("build activity event");

        assert_eq!(event.risk_score, 7);
        assert_eq!(event.risk_contributions.len(), 2);
        assert_eq!(event.risk_contributions[0], a);
        assert_eq!(event.risk_contributions[1].id(), "baseline.z");
    }

    #[test]
    fn risk_accounting_scope_rejects_invalid_types_and_rule_links() {
        let deterministic = RiskContribution::new(
            "rule.detected",
            RiskContributionType::DeterministicRule,
            1,
            "detected",
        )
        .expect("contribution");
        let baseline = RiskContribution::new(
            "baseline.deviation",
            RiskContributionType::BaselineDeviation,
            1,
            "baseline",
        )
        .expect("contribution");

        assert!(matches!(
            validate_risk_accounting_scope("activity", &[], std::slice::from_ref(&deterministic)),
            Err(crate::scoring::RiskAccountingError::ContributionTypeNotAllowed { .. })
        ));
        assert!(matches!(
            validate_risk_accounting_scope("detection", &[], std::slice::from_ref(&baseline)),
            Err(crate::scoring::RiskAccountingError::ContributionTypeNotAllowed { .. })
        ));
        assert!(matches!(
            validate_risk_accounting_scope("detection", &[], std::slice::from_ref(&deterministic)),
            Err(crate::scoring::RiskAccountingError::ContributionRuleIdMissing(id))
                if id == "rule.detected"
        ));
        assert!(
            validate_risk_accounting_scope(
                "detection",
                &["rule.detected".to_string()],
                std::slice::from_ref(&deterministic)
            )
            .is_ok()
        );
        assert!(
            validate_risk_accounting_scope(
                "session_risk_summary",
                &["rule.detected".to_string()],
                &[deterministic]
            )
            .is_ok()
        );
    }

    #[test]
    fn event_builders_enforce_contribution_scope() {
        let invalid_activity = activity_event(ActivityEventInput {
            client: ClientId::Codex,
            agent: None,
            model: None,
            provider: None,
            session_id: "session".to_string(),
            source_path_hash: "hash".to_string(),
            tool_name: None,
            tags: Vec::new(),
            evidence: Vec::new(),
            risk_contributions: vec![
                RiskContribution::new(
                    "rule.activity",
                    RiskContributionType::DeterministicRule,
                    1,
                    "invalid",
                )
                .expect("contribution"),
            ],
            event_time: None,
        });
        assert!(invalid_activity.is_err());

        let invalid_detection = detection_event(DetectionEventInput {
            client: ClientId::Codex,
            agent: None,
            model: None,
            provider: None,
            session_id: "session".to_string(),
            source_path_hash: "hash".to_string(),
            tool_name: None,
            rule_ids: vec!["rule".to_string()],
            categories: Vec::new(),
            detection_classes: Vec::new(),
            signal_types: Vec::new(),
            analytic_intents: Vec::new(),
            atlas_tags: Vec::new(),
            tags: Vec::new(),
            evidence: Vec::new(),
            risk_contributions: Vec::new(),
            event_time: None,
        });
        assert!(matches!(
            invalid_detection,
            Err(crate::scoring::RiskAccountingError::InvalidRuleId(id)) if id == "rule"
        ));

        let invalid_summary = session_risk_summary_event(SessionRiskSummaryEventInput {
            client: "codex".to_string(),
            agent: None,
            model: None,
            provider: None,
            session_id: "session".to_string(),
            source_path_hash: None,
            rule_ids: vec!["rule".to_string()],
            categories: Vec::new(),
            detection_classes: Vec::new(),
            signal_types: Vec::new(),
            analytic_intents: Vec::new(),
            atlas_tags: Vec::new(),
            tags: Vec::new(),
            evidence: Vec::new(),
            risk_contributions: Vec::new(),
            event_time: None,
        });
        assert!(matches!(
            invalid_summary,
            Err(crate::scoring::RiskAccountingError::InvalidRuleId(id)) if id == "rule"
        ));

        let invalid_correlation = correlation_event(CorrelationEventInput {
            client: "codex".to_string(),
            agent: None,
            model: None,
            provider: None,
            shared_rule_ids: vec!["rule".to_string()],
            sessions: Vec::new(),
            window_start: "2026-05-01T00:00:00Z".to_string(),
            window_end: "2026-05-01T00:00:00Z".to_string(),
            max_risk_score: 0,
        });
        assert!(matches!(
            invalid_correlation,
            Err(crate::scoring::RiskAccountingError::InvalidRuleId(id)) if id == "rule"
        ));

        let valid_session = session_risk_summary_event(SessionRiskSummaryEventInput {
            client: "codex".to_string(),
            agent: None,
            model: None,
            provider: None,
            session_id: "session".to_string(),
            source_path_hash: None,
            rule_ids: vec!["rule.session".to_string()],
            categories: Vec::new(),
            detection_classes: Vec::new(),
            signal_types: Vec::new(),
            analytic_intents: Vec::new(),
            atlas_tags: Vec::new(),
            tags: Vec::new(),
            evidence: Vec::new(),
            risk_contributions: vec![
                RiskContribution::new(
                    "rule.session",
                    RiskContributionType::DeterministicRule,
                    1,
                    "valid",
                )
                .expect("contribution"),
            ],
            event_time: None,
        });
        assert!(valid_session.is_ok());
    }

    #[test]
    fn native_detection_process_and_correlation_inputs_require_dimensions() {
        let invalid_detection = detection_event(DetectionEventInput {
            client: ClientId::Codex,
            agent: None,
            model: None,
            provider: None,
            session_id: "session".to_string(),
            source_path_hash: "hash".to_string(),
            tool_name: None,
            rule_ids: vec!["rule.test".to_string()],
            categories: Vec::new(),
            detection_classes: vec!["security_detection".to_string()],
            signal_types: vec!["atomic".to_string()],
            analytic_intents: vec!["alert".to_string()],
            atlas_tags: Vec::new(),
            tags: vec!["test".to_string()],
            evidence: Vec::new(),
            risk_contributions: Vec::new(),
            event_time: None,
        })
        .expect_err("empty detection categories");
        assert!(matches!(
            invalid_detection,
            crate::scoring::RiskAccountingError::EmptyEventField {
                event_type: "detection",
                field: "categories"
            }
        ));

        let invalid_process = process_chain_event(ProcessChainEventInput {
            client: ClientId::Codex,
            agent: None,
            model: None,
            provider: None,
            session_id: "session".to_string(),
            source_path_hash: "hash".to_string(),
            tool_name: None,
            rule_ids: vec!["rule.test".to_string()],
            categories: vec!["process_chain".to_string()],
            detection_classes: Vec::new(),
            signal_types: vec!["chain".to_string()],
            analytic_intents: vec!["alert".to_string()],
            tags: vec!["test".to_string()],
            evidence: Vec::new(),
            risk_contributions: Vec::new(),
            event_time: None,
            confidence: "low".to_string(),
            detection_reason: "test".to_string(),
            mitre_attack_techniques: Vec::new(),
            risk_entity_type: "session".to_string(),
            risk_entity_value: Some("session".to_string()),
            process: ProcessContext {
                host: None,
                user: None,
                source_process_name: "parent".to_string(),
                source_process_path: None,
                source_process_id: None,
                source_process_command_line: None,
                target_process_name: "child".to_string(),
                target_process_path: None,
                target_process_id: None,
                target_process_command_line: None,
                parent_process_name: None,
                parent_process_path: None,
                source_event_id: None,
                source_process_inferred: true,
                rule_name: "test".to_string(),
                secondary_rule_ids: Vec::new(),
                investigation_fields: Vec::new(),
                falsepositives: Vec::new(),
                dedup_key: "test".to_string(),
                suppression_window_seconds: 0,
                rule_severity: "low".to_string(),
                risk_adjustment: None,
            },
        })
        .expect_err("empty process detection classes");
        assert!(matches!(
            invalid_process,
            crate::scoring::RiskAccountingError::EmptyEventField {
                event_type: "process_chain",
                field: "detection_classes"
            }
        ));

        let invalid_correlation = correlation_event(CorrelationEventInput {
            client: "codex".to_string(),
            agent: None,
            model: None,
            provider: None,
            shared_rule_ids: Vec::new(),
            sessions: vec![CorrelationSessionInput {
                session_id: "one".to_string(),
                event_id: "event-one".to_string(),
                timestamp: "2026-05-01T00:00:00Z".to_string(),
                severity: "high".to_string(),
                risk_score: 70,
            }],
            window_start: "2026-05-01T00:00:00Z".to_string(),
            window_end: "2026-05-01T00:00:00Z".to_string(),
            max_risk_score: 70,
        })
        .expect_err("empty correlation shared IDs");
        assert!(matches!(
            invalid_correlation,
            crate::scoring::RiskAccountingError::EmptyEventField {
                event_type: "correlation",
                field: "shared_rule_ids"
            }
        ));

        let invalid_cardinality = correlation_event(CorrelationEventInput {
            client: "codex".to_string(),
            agent: None,
            model: None,
            provider: None,
            shared_rule_ids: vec!["rule.test".to_string()],
            sessions: vec![CorrelationSessionInput {
                session_id: "one".to_string(),
                event_id: "event-one".to_string(),
                timestamp: "2026-05-01T00:00:00Z".to_string(),
                severity: "high".to_string(),
                risk_score: 70,
            }],
            window_start: "2026-05-01T00:00:00Z".to_string(),
            window_end: "2026-05-01T00:00:00Z".to_string(),
            max_risk_score: 70,
        })
        .expect_err("one-session correlation");
        assert!(matches!(
            invalid_cardinality,
            crate::scoring::RiskAccountingError::InvalidCorrelationCardinality { actual: 1 }
        ));
    }

    #[test]
    fn detection_event_serialization_omits_unset_optional_fields() {
        let event = serde_json::to_value(
            detection_event(DetectionEventInput {
                client: ClientId::Codex,
                agent: Some("agent".to_string()),
                model: Some("model".to_string()),
                provider: Some("provider".to_string()),
                session_id: "session".to_string(),
                source_path_hash: "hash".to_string(),
                tool_name: None,
                rule_ids: vec!["rule.test".to_string()],
                categories: vec!["category".to_string()],
                detection_classes: vec!["security_detection".to_string()],
                signal_types: vec!["atomic".to_string()],
                analytic_intents: vec!["alert".to_string()],
                atlas_tags: vec!["atlas:AML.T0051".to_string()],
                tags: vec!["tag".to_string()],
                evidence: vec![Evidence {
                    field: "matched_field".to_string(),
                    redacted_value: "redacted".to_string(),
                    hash: Some("evidence-hash".to_string()),
                    rule_id: Some("rule.test".to_string()),
                }],
                risk_contributions: Vec::new(),
                event_time: Some("2026-05-01T00:00:00Z".to_string()),
            })
            .expect("build detection event"),
        )
        .expect("serialize detection event");

        assert_no_top_level_nulls(&event);
        assert_eq!(event["event_type"], "detection");
        assert_eq!(
            event["agent"],
            format!("[agent:{}]", evidence_hash("agent"))
        );
        assert_eq!(event["event_time"], "2026-05-01T00:00:00.000Z");
        assert_eq!(event["rule_ids"][0], "rule.test");
        assert_eq!(event["categories"][0], "category");
        assert_eq!(event["detection_classes"][0], "security_detection");
        assert_eq!(event["signal_types"][0], "atomic");
        assert_eq!(event["analytic_intents"][0], "alert");
        assert_eq!(event["atlas_tags"][0], "atlas:AML.T0051");
        assert_eq!(event["evidence"][0]["hash"], evidence_hash("evidence-hash"));
        assert_eq!(event["evidence"][0]["rule_id"], "rule.test");
        assert!(event["schema_version"] == "3.0");
        assert!(
            event["event_id"]
                .as_str()
                .is_some_and(|value| value.starts_with("telltale-"))
        );
        assert!(event["telltale_version"].is_string());
        assert!(event.get("triage").is_none());
        assert!(event.get("adr_version").is_none());
        assert!(event.get("tool_name").is_none());
        assert!(event.get("source_counts").is_none());
    }

    #[test]
    fn health_event_serialization_omits_unset_optional_fields() {
        let event = serde_json::to_value(health_event_with_metadata(HealthEventInput {
            sources: &[],
            source_inventory_change: None,
            scan_duration_ms: 7,
            rule_count: 3,
            threshold_config: crate::scoring::load_thresholds(),
            active_policy_name: None,
            emitted_count: 0,
            suppressed_count: 0,
            scanner_error_count: 0,
        }))
        .expect("serialize health event");

        assert_no_top_level_nulls(&event);
        assert_eq!(event["event_type"], "health");
        assert_eq!(event["component"], "scanner");
        assert_eq!(event["scan_duration_ms"], 7);
        assert!(event["source_counts"].is_object());
        assert!(event.get("agent").is_none());
        assert!(event.get("active_policy_name").is_none());
        for field in [
            "rule_ids",
            "categories",
            "detection_classes",
            "signal_types",
            "analytic_intents",
            "atlas_tags",
        ] {
            assert!(event.get(field).is_none(), "{field} should be omitted");
        }
        assert!(event["evidence"][0]["hash"].is_string());
        assert!(event["evidence"][0].get("rule_id").is_none());
    }

    #[test]
    fn health_event_constructor_omits_blank_policy_names() {
        for active_policy_name in [Some(""), Some(" \t\n ")] {
            let event = health_event_with_metadata(HealthEventInput {
                sources: &[],
                source_inventory_change: None,
                scan_duration_ms: 0,
                rule_count: 0,
                threshold_config: crate::scoring::load_thresholds(),
                active_policy_name,
                emitted_count: 0,
                suppressed_count: 0,
                scanner_error_count: 0,
            });

            assert_eq!(event.active_policy_name, None);
        }
    }

    #[test]
    fn detection_event_uses_threshold_based_severity() {
        assert_eq!(
            assess_risk_with_thresholds(
                69,
                RiskThresholds {
                    low: 20,
                    medium: 50,
                    high: 70,
                    critical: 90,
                },
            )
            .severity,
            RiskSeverity::Medium
        );
        assert_eq!(
            assess_risk_with_thresholds(
                70,
                RiskThresholds {
                    low: 20,
                    medium: 50,
                    high: 70,
                    critical: 90,
                },
            )
            .severity,
            RiskSeverity::High
        );
        assert_eq!(
            assess_risk_with_thresholds(
                90,
                RiskThresholds {
                    low: 20,
                    medium: 50,
                    high: 70,
                    critical: 90,
                },
            )
            .severity,
            RiskSeverity::Critical
        );
    }

    #[test]
    fn health_event_has_steady_state_check_dimensions() {
        let event = health_event_with_metadata(HealthEventInput {
            sources: &[],
            source_inventory_change: None,
            scan_duration_ms: 7,
            rule_count: 3,
            threshold_config: crate::scoring::load_thresholds(),
            active_policy_name: None,
            emitted_count: 0,
            suppressed_count: 0,
            scanner_error_count: 0,
        });

        assert_eq!(event.event_type, "health");
        assert_eq!(event.component.as_deref(), Some("scanner"));
        assert_eq!(event.check_name.as_deref(), Some("source_discovery"));
        assert_eq!(event.status.as_deref(), Some("ok"));
    }

    #[test]
    fn health_event_can_include_source_inventory_change_marker() {
        let change = crate::source::SourceInventoryChangeSummary {
            baseline: false,
            added: 0,
            removed: 0,
            unchanged: 2,
            hash: "0".repeat(64),
        };
        let event = health_event_with_metadata(HealthEventInput {
            sources: &[],
            source_inventory_change: Some(&change),
            scan_duration_ms: 7,
            rule_count: 3,
            threshold_config: crate::scoring::load_thresholds(),
            active_policy_name: None,
            emitted_count: 0,
            suppressed_count: 0,
            scanner_error_count: 0,
        });

        let evidence = event
            .evidence
            .iter()
            .find(|item| item.field == "source_inventory_change")
            .expect("source inventory change evidence");
        assert_eq!(
            evidence.redacted_value,
            "baseline=false; added=0; removed=0; unchanged=2"
        );
        assert_eq!(
            evidence.hash.as_deref(),
            Some("0000000000000000000000000000000000000000000000000000000000000000")
        );
    }

    #[test]
    fn detection_event_has_no_triage_compatibility_fields_for_high_scores() {
        let event = detection_event(DetectionEventInput {
            client: ClientId::Codex,
            agent: None,
            model: None,
            provider: None,
            session_id: "session".to_string(),
            source_path_hash: "hash".to_string(),
            tool_name: None,
            rule_ids: vec!["rule.test".to_string()],
            categories: vec!["category".to_string()],
            detection_classes: vec!["security_detection".to_string()],
            signal_types: vec!["atomic".to_string()],
            analytic_intents: vec!["alert".to_string()],
            atlas_tags: Vec::new(),
            tags: vec!["tag".to_string()],
            evidence: Vec::new(),
            risk_contributions: test_contribution(90),
            event_time: Some("2026-05-01T00:00:00Z".to_string()),
        })
        .expect("build detection event");

        assert_eq!(event.severity, "critical");
        assert_eq!(event.timestamp, "2026-05-01T00:00:00.000Z");
        assert_eq!(
            event.event_time.as_deref(),
            Some("2026-05-01T00:00:00.000Z")
        );
        assert_eq!(event.time_source, "source");
        assert_eq!(event.time_confidence, "high");
        let serialized = serde_json::to_value(&event).expect("serialized event");
        assert!(serialized.get("triage").is_none());
        assert!(serialized.get("adr_version").is_none());
    }

    #[test]
    fn detection_event_has_no_triage_compatibility_fields_for_low_scores() {
        let event = detection_event(DetectionEventInput {
            client: ClientId::Codex,
            agent: None,
            model: None,
            provider: None,
            session_id: "session".to_string(),
            source_path_hash: "hash".to_string(),
            tool_name: None,
            rule_ids: vec!["rule.test".to_string()],
            categories: vec!["category".to_string()],
            detection_classes: vec!["security_detection".to_string()],
            signal_types: vec!["atomic".to_string()],
            analytic_intents: vec!["alert".to_string()],
            atlas_tags: Vec::new(),
            tags: vec!["tag".to_string()],
            evidence: Vec::new(),
            risk_contributions: Vec::new(),
            event_time: Some("2026-05-01T00:00:00Z".to_string()),
        })
        .expect("build detection event");

        assert_eq!(event.severity, "informational");
        let serialized = serde_json::to_value(&event).expect("serialized event");
        assert!(serialized.get("triage").is_none());
        assert!(serialized.get("adr_version").is_none());
    }

    #[test]
    fn detection_event_populates_response_metadata() {
        let event = detection_event(DetectionEventInput {
            client: ClientId::Codex,
            agent: None,
            model: None,
            provider: None,
            session_id: "session".to_string(),
            source_path_hash: "hash".to_string(),
            tool_name: None,
            rule_ids: vec!["mcp.tool_metadata.prompt_injection".to_string()],
            categories: vec!["mcp_prompt_injection".to_string()],
            detection_classes: vec!["security_detection".to_string()],
            signal_types: vec!["atomic".to_string()],
            analytic_intents: vec!["alert".to_string()],
            atlas_tags: vec!["atlas:AML.T0051".to_string()],
            tags: vec!["tag".to_string()],
            evidence: Vec::new(),
            risk_contributions: vec![
                RiskContribution::new(
                    "mcp.tool_metadata.prompt_injection",
                    RiskContributionType::DeterministicRule,
                    90,
                    "test rationale",
                )
                .expect("contribution"),
            ],
            event_time: Some("2026-05-01T00:00:00Z".to_string()),
        })
        .expect("build detection event");

        let response = event.response.expect("response metadata");
        assert_eq!(response.recommended_action, "investigate_immediately");
        assert_eq!(
            response.response_playbook,
            "telltale-playbook-mcp-prompt-injection"
        );
        assert_eq!(response.escalation, "security_review_required");
        assert!(response.investigation_summary.contains("critical"));
        assert!(
            response
                .investigation_summary
                .contains("mcp.tool_metadata.prompt_injection")
        );
        assert_eq!(event.detection_classes, vec!["security_detection"]);
        assert_eq!(event.signal_types, vec!["atomic"]);
        assert_eq!(event.analytic_intents, vec!["alert"]);
        assert_eq!(event.atlas_tags, vec!["atlas:AML.T0051"]);
    }

    #[test]
    fn event_builder_sanitizes_null_string_tool_name() {
        let event = detection_event(DetectionEventInput {
            client: ClientId::Codex,
            agent: None,
            model: None,
            provider: None,
            session_id: "session".to_string(),
            source_path_hash: "hash".to_string(),
            tool_name: Some("null".to_string()),
            rule_ids: vec!["rule.test".to_string()],
            categories: vec!["category".to_string()],
            detection_classes: vec!["security_detection".to_string()],
            signal_types: vec!["atomic".to_string()],
            analytic_intents: vec!["alert".to_string()],
            atlas_tags: Vec::new(),
            tags: vec!["tag".to_string()],
            evidence: Vec::new(),
            risk_contributions: Vec::new(),
            event_time: Some("2026-05-01T00:00:00Z".to_string()),
        })
        .expect("build detection event");

        assert_eq!(event.tool_name, None);
    }

    #[test]
    fn detection_event_falls_back_to_observed_time_for_future_source_timestamp() {
        let event = detection_event(DetectionEventInput {
            client: ClientId::Codex,
            agent: None,
            model: None,
            provider: None,
            session_id: "session".to_string(),
            source_path_hash: "hash".to_string(),
            tool_name: None,
            rule_ids: vec!["rule.test".to_string()],
            categories: vec!["category".to_string()],
            detection_classes: vec!["security_detection".to_string()],
            signal_types: vec!["atomic".to_string()],
            analytic_intents: vec!["alert".to_string()],
            atlas_tags: Vec::new(),
            tags: vec!["tag".to_string()],
            evidence: Vec::new(),
            risk_contributions: Vec::new(),
            event_time: Some("2999-01-01T00:00:00Z".to_string()),
        })
        .expect("build detection event");

        assert_eq!(event.time_source, "override");
        assert_eq!(event.time_confidence, "low");
        assert_eq!(
            event.time_override_reason.as_deref(),
            Some("source_timestamp_future_skew")
        );
        assert_eq!(
            event.event_time.as_deref(),
            Some("2999-01-01T00:00:00.000Z")
        );
        assert_eq!(event.timestamp, event.observed_at);
        assert_eq!(event.ingested_at, event.observed_at);
    }

    #[test]
    fn detection_event_falls_back_to_observed_time_for_missing_source_timestamp() {
        let event = detection_event(DetectionEventInput {
            client: ClientId::Codex,
            agent: None,
            model: None,
            provider: None,
            session_id: "session".to_string(),
            source_path_hash: "hash".to_string(),
            tool_name: None,
            rule_ids: vec!["rule.test".to_string()],
            categories: vec!["category".to_string()],
            detection_classes: vec!["security_detection".to_string()],
            signal_types: vec!["atomic".to_string()],
            analytic_intents: vec!["alert".to_string()],
            atlas_tags: Vec::new(),
            tags: vec!["tag".to_string()],
            evidence: Vec::new(),
            risk_contributions: Vec::new(),
            event_time: None,
        })
        .expect("build detection event");

        assert_eq!(event.time_source, "observed");
        assert_eq!(event.time_confidence, "low");
        assert_eq!(
            event.time_override_reason.as_deref(),
            Some("missing_source_timestamp")
        );
        assert_eq!(event.event_time, None);
        assert_eq!(event.timestamp, event.observed_at);
        assert_eq!(event.ingested_at, event.observed_at);
    }

    #[test]
    fn detection_event_normalizes_non_utc_source_timestamp() {
        let event = detection_event(DetectionEventInput {
            client: ClientId::Codex,
            agent: None,
            model: None,
            provider: None,
            session_id: "session".to_string(),
            source_path_hash: "hash".to_string(),
            tool_name: None,
            rule_ids: vec!["rule.test".to_string()],
            categories: vec!["category".to_string()],
            detection_classes: vec!["security_detection".to_string()],
            signal_types: vec!["atomic".to_string()],
            analytic_intents: vec!["alert".to_string()],
            atlas_tags: Vec::new(),
            tags: vec!["tag".to_string()],
            evidence: Vec::new(),
            risk_contributions: Vec::new(),
            event_time: Some("2026-05-01T12:00:00+02:00".to_string()),
        })
        .expect("build detection event");

        assert_eq!(event.time_source, "source");
        assert_eq!(event.time_confidence, "high");
        assert_eq!(event.time_override_reason, None);
        assert_eq!(
            event.event_time.as_deref(),
            Some("2026-05-01T10:00:00.000Z")
        );
        assert_eq!(event.timestamp, "2026-05-01T10:00:00.000Z");
    }

    #[test]
    fn scanner_error_event_has_correct_shape() {
        use crate::clients::SourceKind;
        use crate::source::Source;
        use std::path::PathBuf;

        let source = Source {
            client: ClientId::OpenCode,
            kind: SourceKind::Sqlite,
            source_id: "opencode.sqlite".to_string(),
            path: PathBuf::from("/home/user/.local/share/opencode/opencode.db"),
        };
        let error = "sqlite error: Query is not read-only";

        let event = scanner_error_event(&source, &error);

        assert_eq!(event.event_type, "scanner_error");
        assert_eq!(event.severity, "informational");
        assert_eq!(event.risk_score, 0);
        assert_eq!(event.client, "opencode");
        assert_eq!(event.session_id, "scanner");
        assert_eq!(event.agent, None);
        assert_eq!(event.model, None);
        assert_eq!(event.tool_name, None);
        assert_eq!(event.rule_ids.len(), 0);
        assert!(event.source_path_hash.is_some());
        assert_eq!(event.tags, vec!["scanner", "parse_failure"]);
        assert_eq!(event.evidence.len(), 2);
        assert_eq!(event.evidence[0].field, "error");
        assert_eq!(event.evidence[0].redacted_value, error);
        assert_eq!(event.evidence[1].field, "source_path");
        assert!(event.evidence[1].hash.is_some());
        assert!(event.timeline_anchors.is_empty());
        assert_eq!(event.response, None);
        assert_eq!(event.source_counts, None);
        assert_eq!(event.component.as_deref(), Some("scanner"));
        assert_eq!(event.check_name.as_deref(), Some("source_parse"));
        assert_eq!(event.status.as_deref(), Some("degraded"));
    }

    #[test]
    fn scanner_error_event_preserves_redacted_state_fingerprint_input() {
        use crate::clients::SourceKind;
        use crate::source::Source;
        use std::path::PathBuf;

        let source = Source {
            client: ClientId::OpenCode,
            kind: SourceKind::Sqlite,
            source_id: "opencode.sqlite".to_string(),
            path: PathBuf::from("/synthetic/opencode.db"),
        };
        let raw_error =
            "failed at /home/TT_PRIVACY_SCANNER_25/.config/state TOKEN=TT_PRIVACY_SCANNER_25";
        let event = scanner_error_event(&source, &raw_error);

        assert_eq!(
            event.evidence[0].redacted_value,
            super::PrivacySanitizer::sanitize(super::SanitizationContext::Diagnostic, raw_error)
        );
        assert!(
            !event.evidence[0]
                .redacted_value
                .contains("TT_PRIVACY_SCANNER_25")
        );
    }

    #[test]
    fn operational_alert_event_has_correct_shape() {
        let event = operational_alert_event(OperationalAlertInput {
            alert_type: "scanner_error_threshold_exceeded".to_string(),
            threshold: "max_scanner_errors=3".to_string(),
            actual_value: "scanner_error_count=5".to_string(),
            scan_duration_ms: Some(1500),
            scanner_error_count: Some(5),
        });

        assert_eq!(event.event_type, "operational_alert");
        assert_eq!(event.severity, "warning");
        assert_eq!(event.risk_score, 0);
        assert_eq!(event.client, "scanner");
        assert_eq!(event.session_id, "scanner");
        assert_eq!(event.component.as_deref(), Some("scanner"));
        assert_eq!(event.check_name.as_deref(), Some("scanner_error_threshold"));
        assert_eq!(event.status.as_deref(), Some("degraded"));
        assert_eq!(event.categories, vec!["operational"]);
        assert!(event.tags.contains(&"operational".to_string()));
        assert!(event.tags.contains(&"scanner_health".to_string()));
        assert_eq!(event.scan_duration_ms, Some(1500));
        assert_eq!(event.telltale_version, env!("CARGO_PKG_VERSION"));
        assert!(event.timeline_anchors.is_empty());
        assert_eq!(event.response, None);
        assert!(event.source_path_hash.is_none());

        let alert_type = event
            .evidence
            .iter()
            .find(|e| e.field == "alert_type")
            .expect("alert_type evidence");
        assert_eq!(
            alert_type.redacted_value,
            "scanner_error_threshold_exceeded"
        );

        let threshold = event
            .evidence
            .iter()
            .find(|e| e.field == "threshold")
            .expect("threshold evidence");
        assert_eq!(threshold.redacted_value, "max_scanner_errors=3");

        let actual = event
            .evidence
            .iter()
            .find(|e| e.field == "actual_value")
            .expect("actual_value evidence");
        assert_eq!(actual.redacted_value, "scanner_error_count=5");

        let error_count = event
            .evidence
            .iter()
            .find(|e| e.field == "scanner_error_count")
            .expect("scanner_error_count evidence");
        assert_eq!(error_count.redacted_value, "5");

        let duration = event
            .evidence
            .iter()
            .find(|e| e.field == "scan_duration_ms")
            .expect("scan_duration_ms evidence");
        assert_eq!(duration.redacted_value, "1500");
    }

    #[test]
    fn operational_alert_event_includes_duration_evidence() {
        let event = operational_alert_event(OperationalAlertInput {
            alert_type: "scan_duration_threshold_exceeded".to_string(),
            threshold: "max_scan_duration_ms=300000".to_string(),
            actual_value: "scan_duration_ms=600000".to_string(),
            scan_duration_ms: Some(600_000),
            scanner_error_count: None,
        });

        assert_eq!(event.event_type, "operational_alert");
        assert_eq!(event.severity, "warning");
        assert_eq!(event.check_name.as_deref(), Some("scan_duration_threshold"));
        assert_eq!(event.status.as_deref(), Some("degraded"));
        assert!(event.evidence.iter().any(|e| e.field == "scan_duration_ms"));
        assert!(
            event
                .evidence
                .iter()
                .all(|e| e.field != "scanner_error_count")
        );
    }

    #[test]
    fn load_operational_alert_config_returns_defaults() {
        let config = super::load_operational_alert_config();
        assert_eq!(config.max_scanner_errors, 3);
        assert_eq!(config.max_scan_duration_ms, 300_000);
    }

    #[test]
    fn serialized_privacy_corpus_covers_all_current_event_families() {
        use crate::clients::SourceKind;
        use crate::source::Source;
        use std::path::PathBuf;

        let marker = "TT_PRIVACY_EVENT_25";
        let raw_evidence = format!("API_KEY=\"{marker}\"; command=inspect");
        let evidence = Evidence {
            field: "arguments".to_string(),
            redacted_value: raw_evidence.clone(),
            hash: Some(evidence_hash(&raw_evidence)),
            rule_id: Some("rule.privacy".to_string()),
        };
        let detection = detection_event(DetectionEventInput {
            client: ClientId::Codex,
            agent: Some(marker.to_string()),
            model: Some(marker.to_string()),
            provider: Some(marker.to_string()),
            session_id: "opaque-session".to_string(),
            source_path_hash: "source-hash".to_string(),
            tool_name: Some(marker.to_string()),
            rule_ids: vec!["rule.privacy".to_string()],
            categories: vec!["privacy".to_string()],
            detection_classes: vec!["security_detection".to_string()],
            signal_types: vec!["atomic".to_string()],
            analytic_intents: vec!["alert".to_string()],
            atlas_tags: Vec::new(),
            tags: vec![marker.to_string()],
            evidence: vec![evidence],
            risk_contributions: Vec::new(),
            event_time: None,
        })
        .expect("detection event");
        assert_eq!(detection.agent.as_deref(), Some(marker));
        assert_eq!(detection.model.as_deref(), Some(marker));
        assert_eq!(detection.provider.as_deref(), Some(marker));
        assert_eq!(detection.tool_name.as_deref(), Some(marker));
        assert_eq!(
            detection.evidence[0].hash.as_deref(),
            Some(evidence_hash(&raw_evidence).as_str())
        );
        assert!(detection.evidence[0].redacted_value.contains("API_KEY"));

        let activity = activity_event(ActivityEventInput {
            client: ClientId::Codex,
            agent: None,
            model: None,
            provider: None,
            session_id: "opaque-session".to_string(),
            source_path_hash: "source-hash".to_string(),
            tool_name: Some("shell".to_string()),
            tags: Vec::new(),
            evidence: vec![Evidence {
                field: "tool_result".to_string(),
                redacted_value: format!("token: {marker}; result=ok"),
                hash: None,
                rule_id: None,
            }],
            risk_contributions: Vec::new(),
            event_time: None,
        })
        .expect("activity event");

        let source_path = PathBuf::from(format!("/home/{marker}/.local/state/session.db"));
        let source = Source {
            client: ClientId::OpenCode,
            kind: SourceKind::Sqlite,
            source_id: "fixture.source".to_string(),
            path: source_path.clone(),
        };
        let health = health_event_with_metadata(HealthEventInput {
            sources: std::slice::from_ref(&source),
            source_inventory_change: None,
            scan_duration_ms: 1,
            rule_count: 1,
            threshold_config: crate::scoring::load_thresholds(),
            active_policy_name: Some(marker),
            emitted_count: 0,
            suppressed_count: 0,
            scanner_error_count: 0,
        });
        let mut scanner_error = scanner_error_event(
            &source,
            &format!(
                "parse failed at /home/{marker}/.config/state.db using https://user:{marker}@example.invalid/?token={marker}"
            ),
        );
        scanner_error.evidence.push(Evidence {
            field: "error".to_string(),
            redacted_value: format!("TOKEN={marker}"),
            hash: None,
            rule_id: None,
        });
        assert_eq!(
            scanner_error.source_path_hash.as_deref(),
            Some(path_hash(&source_path).as_str())
        );

        let operational = operational_alert_event(OperationalAlertInput {
            alert_type: "sink_delivery_failure".to_string(),
            threshold: "attempts_made=1".to_string(),
            actual_value: format!("error=https://user:{marker}@example.invalid/?SECRET={marker}"),
            scan_duration_ms: None,
            scanner_error_count: None,
        });

        let session_summary = session_risk_summary_event(SessionRiskSummaryEventInput {
            client: "codex".to_string(),
            agent: None,
            model: None,
            provider: None,
            session_id: "opaque-session".to_string(),
            source_path_hash: Some("source-hash".to_string()),
            rule_ids: vec!["rule.privacy".to_string()],
            categories: vec!["privacy".to_string()],
            detection_classes: vec!["security_detection".to_string()],
            signal_types: vec!["atomic".to_string()],
            analytic_intents: vec!["alert".to_string()],
            atlas_tags: Vec::new(),
            tags: Vec::new(),
            evidence: vec![Evidence {
                field: "session_summary".to_string(),
                redacted_value: format!("password: {marker}"),
                hash: None,
                rule_id: None,
            }],
            risk_contributions: Vec::new(),
            event_time: None,
        })
        .expect("session summary event");

        let correlation = correlation_event(CorrelationEventInput {
            client: "codex".to_string(),
            agent: None,
            model: None,
            provider: None,
            shared_rule_ids: vec!["rule.privacy".to_string()],
            sessions: vec![
                CorrelationSessionInput {
                    session_id: format!("TOKEN={marker}"),
                    event_id: "opaque-event-a".to_string(),
                    timestamp: "2026-05-01T00:00:00Z".to_string(),
                    severity: "informational".to_string(),
                    risk_score: 0,
                },
                CorrelationSessionInput {
                    session_id: "opaque-session-b".to_string(),
                    event_id: "opaque-event-b".to_string(),
                    timestamp: "2026-05-01T00:01:00Z".to_string(),
                    severity: "informational".to_string(),
                    risk_score: 0,
                },
            ],
            window_start: "2026-05-01T00:00:00Z".to_string(),
            window_end: "2026-05-01T00:01:00Z".to_string(),
            max_risk_score: 0,
        })
        .expect("correlation event");
        assert!(
            correlation
                .evidence
                .iter()
                .any(|item| item.field == "related_detection")
        );

        let process_chain = process_chain_event(ProcessChainEventInput {
            client: ClientId::Codex,
            agent: None,
            model: None,
            provider: None,
            session_id: "opaque-session".to_string(),
            source_path_hash: "source-hash".to_string(),
            tool_name: Some("shell".to_string()),
            rule_ids: vec!["rule.privacy".to_string()],
            categories: vec!["privacy".to_string()],
            detection_classes: vec!["security_detection".to_string()],
            signal_types: vec!["chain".to_string()],
            analytic_intents: vec!["alert".to_string()],
            tags: Vec::new(),
            evidence: vec![Evidence {
                field: "command".to_string(),
                redacted_value: format!("export TOKEN={marker}"),
                hash: None,
                rule_id: Some("rule.privacy".to_string()),
            }],
            risk_contributions: Vec::new(),
            event_time: None,
            confidence: "low".to_string(),
            detection_reason: "privacy fixture".to_string(),
            mitre_attack_techniques: Vec::new(),
            risk_entity_type: "host".to_string(),
            risk_entity_value: Some(marker.to_string()),
            process: ProcessContext {
                host: Some(marker.to_string()),
                user: Some(marker.to_string()),
                source_process_name: "shell".to_string(),
                source_process_path: Some(format!("C:\\Users\\{marker}\\.ssh\\id_ed25519")),
                source_process_id: Some(1),
                source_process_command_line: Some(format!("TOKEN={marker} run")),
                target_process_name: "curl".to_string(),
                target_process_path: None,
                target_process_id: Some(2),
                target_process_command_line: None,
                parent_process_name: None,
                parent_process_path: None,
                source_event_id: Some("opaque-source-event".to_string()),
                source_process_inferred: false,
                rule_name: "privacy fixture".to_string(),
                secondary_rule_ids: Vec::new(),
                investigation_fields: Vec::new(),
                falsepositives: Vec::new(),
                dedup_key: marker.to_string(),
                suppression_window_seconds: 0,
                rule_severity: "low".to_string(),
                risk_adjustment: None,
            },
        })
        .expect("process chain event");
        let process = process_chain.process.as_ref().expect("raw process context");
        assert_eq!(process.host.as_deref(), Some(marker));
        assert_eq!(process.user.as_deref(), Some(marker));
        assert_eq!(process.dedup_key, marker);
        assert_eq!(process_chain.risk_entity_value.as_deref(), Some(marker));
        assert!(
            process
                .source_process_command_line
                .as_deref()
                .is_some_and(|line| line.contains(marker))
        );

        let install_inventory = install_inventory_event(vec![Evidence {
            field: "install_inventory".to_string(),
            redacted_value: format!("credential={marker}"),
            hash: None,
            rule_id: None,
        }])
        .expect("install inventory event");

        let markers = [ControlledMarker {
            id: "event-marker",
            value: marker,
        }];
        let events = [
            ("detection", detection),
            ("activity_standard", activity),
            ("health", health),
            ("scanner_error", scanner_error),
            ("operational_alert", operational),
            ("session_risk_summary", session_summary),
            ("correlation", correlation),
            ("process_chain", process_chain),
            ("install_inventory_activity", install_inventory),
        ];
        let covered_families = events
            .iter()
            .map(|(family, _)| *family)
            .collect::<std::collections::BTreeSet<_>>();
        let expected_families = NATIVE_EVENT_CONSTRUCTOR_FAMILIES
            .iter()
            .map(|family| family.name)
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(covered_families, expected_families);
        let covered_event_types = events
            .iter()
            .map(|(_, event)| event.event_type.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        let expected_event_types = NATIVE_EVENT_CONSTRUCTOR_FAMILIES
            .iter()
            .map(|family| family.event_type)
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            super::TEXT_BEARING_EVENT_TYPES
                .iter()
                .copied()
                .collect::<std::collections::BTreeSet<_>>(),
            expected_event_types,
            "wire event-type inventory must track the constructor registry"
        );
        assert_eq!(covered_event_types, expected_event_types);
        for (family_name, event) in events {
            let family = NATIVE_EVENT_CONSTRUCTOR_FAMILIES
                .iter()
                .find(|family| family.name == family_name)
                .unwrap_or_else(|| panic!("privacy corpus family {family_name} is not registered"));
            assert_eq!(
                event.event_type, family.event_type,
                "privacy corpus family {family_name} has the wrong wire event type"
            );
            let case_id = family_name;
            assert!(
                raw_event_contains_marker(&event, marker),
                "privacy corpus case {case_id} must exercise a raw controlled marker"
            );
            let bytes = serde_json::to_vec(&event.emittable()).expect("serialize event");
            assert_eq!(
                serde_json::to_vec(&event.emittable()).expect("serialize event again"),
                bytes,
                "terminal serialization must be route-independent"
            );
            assert!(
                check_serialized_event_markers(&bytes, case_id, &markers).is_ok(),
                "privacy marker remained in {case_id}"
            );
            let mut historical = serde_json::to_value(&event).expect("serialize raw event value");
            sanitize_serialized_event(&mut historical);
            let historical_bytes =
                serde_json::to_vec(&historical).expect("serialize sanitized historical event");
            assert!(
                check_serialized_event_markers(&historical_bytes, case_id, &markers).is_ok(),
                "privacy marker remained in historical {case_id}"
            );
            if case_id == "process_chain" {
                let emitted: serde_json::Value =
                    serde_json::from_slice(&bytes).expect("emittable process event");
                assert_eq!(
                    emitted["risk_entity_value"], emitted["process"]["host"],
                    "host risk entities must use the process host representation"
                );
                assert_eq!(
                    emitted["process"]["host"],
                    format!("[host:{}]", evidence_hash(marker)),
                    "host identities must be hashed exactly once"
                );
            }
        }
    }

    fn raw_event_contains_marker(event: &super::Event, marker: &str) -> bool {
        event
            .agent
            .as_deref()
            .is_some_and(|value| value.contains(marker))
            || event
                .model
                .as_deref()
                .is_some_and(|value| value.contains(marker))
            || event
                .provider
                .as_deref()
                .is_some_and(|value| value.contains(marker))
            || event.session_id.contains(marker)
            || event
                .tool_name
                .as_deref()
                .is_some_and(|value| value.contains(marker))
            || event.tags.iter().any(|value| value.contains(marker))
            || event
                .evidence
                .iter()
                .any(|value| value.redacted_value.contains(marker))
            || event
                .active_policy_name
                .as_deref()
                .is_some_and(|value| value.contains(marker))
            || event
                .risk_entity_value
                .as_deref()
                .is_some_and(|value| value.contains(marker))
            || event.process.as_ref().is_some_and(|process| {
                process
                    .host
                    .as_deref()
                    .is_some_and(|value| value.contains(marker))
                    || process
                        .user
                        .as_deref()
                        .is_some_and(|value| value.contains(marker))
                    || process.dedup_key.contains(marker)
                    || process
                        .source_process_command_line
                        .as_deref()
                        .is_some_and(|value| value.contains(marker))
            })
    }

    #[test]
    fn direct_event_serialization_sanitizes_raw_text_and_preserves_fields() {
        let event_time_marker = "tt_privacy_terminal_event_time_25";
        let source_hash_marker = "TT_PRIVACY_TERMINAL_SOURCE_HASH_30";
        let mitre_marker = "TT_PRIVACY_TERMINAL_MITRE_30";
        let agent_marker = "tt_privacy_terminal_agent_25";
        let model_marker = "tt_privacy_terminal_model_25";
        let provider_marker = "tt_privacy_terminal_provider_25";
        let response_marker = "tt_privacy_terminal_response_25";
        let rationale_marker = "tt_privacy_terminal_rationale_25";
        let rule_name_marker = "tt_privacy_terminal_rule_name_25";
        let investigation_marker = "tt_privacy_terminal_investigation_25";
        let falsepositive_marker = "tt_privacy_terminal_falsepositive_25";
        let adjustment_marker = "tt_privacy_terminal_adjustment_25";
        let policy_marker = "tt_privacy_terminal_policy_25";
        let contribution = RiskContribution::new(
            "rule.privacy",
            RiskContributionType::DeterministicRule,
            1,
            format!("TOKEN={rationale_marker}"),
        )
        .expect("synthetic contribution");
        let mut event = process_chain_event(ProcessChainEventInput {
            client: ClientId::Codex,
            agent: Some(agent_marker.to_string()),
            model: Some(model_marker.to_string()),
            provider: Some(provider_marker.to_string()),
            session_id: "opaque-session".to_string(),
            source_path_hash: source_hash_marker.to_string(),
            tool_name: Some("shell".to_string()),
            rule_ids: vec!["rule.privacy".to_string()],
            categories: vec!["privacy".to_string()],
            detection_classes: vec!["security_detection".to_string()],
            signal_types: vec!["chain".to_string()],
            analytic_intents: vec!["alert".to_string()],
            tags: Vec::new(),
            evidence: Vec::new(),
            risk_contributions: vec![contribution],
            event_time: Some(event_time_marker.to_string()),
            confidence: "low".to_string(),
            detection_reason: "privacy fixture".to_string(),
            mitre_attack_techniques: vec![mitre_marker.to_string(), "T1059.001".to_string()],
            risk_entity_type: "session".to_string(),
            risk_entity_value: Some("opaque-session".to_string()),
            process: ProcessContext {
                host: None,
                user: None,
                source_process_name: "shell".to_string(),
                source_process_path: None,
                source_process_id: None,
                source_process_command_line: None,
                target_process_name: "curl".to_string(),
                target_process_path: None,
                target_process_id: None,
                target_process_command_line: None,
                parent_process_name: None,
                parent_process_path: None,
                source_event_id: Some("source-event".to_string()),
                source_process_inferred: false,
                rule_name: rule_name_marker.to_string(),
                secondary_rule_ids: Vec::new(),
                investigation_fields: vec![investigation_marker.to_string()],
                falsepositives: vec![falsepositive_marker.to_string()],
                dedup_key: "dedup".to_string(),
                suppression_window_seconds: 0,
                rule_severity: "low".to_string(),
                risk_adjustment: Some(adjustment_marker.to_string()),
            },
        })
        .expect("process event");
        event
            .response
            .as_mut()
            .expect("process event response")
            .recommended_action = "investigate_immediately".to_string();
        let response = event.response.as_mut().expect("process event response");
        response.response_playbook = "telltale-playbook-credential-access".to_string();
        response.investigation_summary = format!("TOKEN={response_marker}");
        response.escalation = "security_review_required".to_string();

        // Source-derived actor values remain available to in-process matching
        // and correlation; only terminal bytes become opaque.
        assert!(
            event
                .agent
                .as_deref()
                .is_some_and(|value| value == agent_marker)
        );
        assert!(
            event
                .model
                .as_deref()
                .is_some_and(|value| value == model_marker)
        );
        assert!(
            event
                .provider
                .as_deref()
                .is_some_and(|value| value == provider_marker)
        );

        let markers = [
            ControlledMarker {
                id: "event-time",
                value: event_time_marker,
            },
            ControlledMarker {
                id: "source-hash",
                value: source_hash_marker,
            },
            ControlledMarker {
                id: "mitre-technique",
                value: mitre_marker,
            },
            ControlledMarker {
                id: "agent",
                value: agent_marker,
            },
            ControlledMarker {
                id: "model",
                value: model_marker,
            },
            ControlledMarker {
                id: "provider",
                value: provider_marker,
            },
            ControlledMarker {
                id: "response",
                value: response_marker,
            },
            ControlledMarker {
                id: "rationale",
                value: rationale_marker,
            },
            ControlledMarker {
                id: "rule-name",
                value: rule_name_marker,
            },
            ControlledMarker {
                id: "investigation",
                value: investigation_marker,
            },
            ControlledMarker {
                id: "falsepositive",
                value: falsepositive_marker,
            },
            ControlledMarker {
                id: "adjustment",
                value: adjustment_marker,
            },
            ControlledMarker {
                id: "policy",
                value: policy_marker,
            },
        ];
        let direct_bytes = serde_json::to_vec(&event).expect("direct event serialization");
        let emittable_bytes =
            serde_json::to_vec(&event.emittable()).expect("emittable event serialization");
        assert_eq!(direct_bytes, emittable_bytes);
        assert_eq!(
            serde_json::to_vec(&event).expect("repeat direct event serialization"),
            direct_bytes,
            "terminal serialization must be deterministic and idempotent"
        );
        assert!(check_serialized_event_markers(&direct_bytes, "terminal-event", &markers).is_ok());
        let emitted: serde_json::Value =
            serde_json::from_slice(&direct_bytes).expect("directly serialized event");
        let emittable = emitted.clone();
        assert_eq!(
            emitted["source_path_hash"],
            evidence_hash(source_hash_marker),
            "source path hashes must preserve only canonical digest values"
        );
        assert_eq!(
            emitted["mitre_attack_techniques"][0],
            format!("mitre:{}", evidence_hash(mitre_marker)),
            "unsafe technique values must use a deterministic opaque fallback"
        );
        assert_eq!(
            emitted["mitre_attack_techniques"][1], "T1059.001",
            "canonical ATT&CK technique values remain readable"
        );
        let mut canonical_hash_event = event.clone();
        let canonical_source_hash = "a".repeat(64);
        canonical_hash_event.source_path_hash = Some(canonical_source_hash.clone());
        let canonical_emitted = serde_json::to_value(canonical_hash_event.emittable())
            .expect("canonical source hash event");
        assert_eq!(canonical_emitted["source_path_hash"], canonical_source_hash);
        assert_eq!(event.agent.as_deref(), Some(agent_marker));
        assert_eq!(
            event
                .response
                .as_ref()
                .expect("raw response metadata")
                .recommended_action,
            "investigate_immediately"
        );
        assert_eq!(
            event
                .process
                .as_ref()
                .expect("raw process context")
                .rule_name,
            rule_name_marker
        );
        assert_eq!(
            emittable["risk_contributions"][0]["rationale"], "TOKEN redacted-secret",
            "terminal rationale remains useful rather than becoming an opaque marker"
        );
        assert_eq!(
            emittable["process"]["source_event_id"],
            format!("[source-event:{}]", evidence_hash("source-event"))
        );
        assert_eq!(
            emittable["process"]["dedup_key"],
            format!("[dedup:{}]", evidence_hash("dedup"))
        );
        let raw = serde_json::to_value(&event).expect("direct event");
        assert_eq!(
            raw.as_object().expect("raw object").len(),
            emittable.as_object().expect("emittable object").len(),
            "terminal sanitization must not change Event 3.0 shape"
        );

        let mut historical = raw;
        sanitize_serialized_event(&mut historical);
        let historical_bytes = serde_json::to_vec(&historical).expect("historical bytes");
        assert!(
            check_serialized_event_markers(&historical_bytes, "historical-event", &markers).is_ok()
        );

        let health = health_event_with_metadata(HealthEventInput {
            sources: &[],
            source_inventory_change: None,
            scan_duration_ms: 1,
            rule_count: 1,
            threshold_config: crate::scoring::load_thresholds(),
            active_policy_name: Some(policy_marker),
            emitted_count: 0,
            suppressed_count: 0,
            scanner_error_count: 0,
        });
        let health_bytes = serde_json::to_vec(&health.emittable()).expect("emittable health");
        assert!(check_serialized_event_markers(&health_bytes, "terminal-health", &markers).is_ok());

        let mut valid_time = event.clone();
        valid_time.event_time = Some("2026-05-01T12:00:00+02:00".to_string());
        let valid_emitted = serde_json::to_value(valid_time.emittable()).expect("valid time event");
        assert_eq!(
            valid_emitted["event_time"], "2026-05-01T12:00:00+02:00",
            "valid RFC3339 event_time values are terminally unchanged"
        );
    }

    #[test]
    fn direct_event_serialization_replaces_malformed_percent_encoded_url_authorities() {
        let path_marker = "TT_PRIVACY_PATH_25";
        let query_marker = "TT_PRIVACY_QUERY_25";
        let event = activity_event(ActivityEventInput {
            client: ClientId::Codex,
            agent: None,
            model: None,
            provider: None,
            session_id: "opaque-session".to_string(),
            source_path_hash: "source-hash".to_string(),
            tool_name: Some("shell".to_string()),
            tags: Vec::new(),
            evidence: vec![Evidence {
                field: "url".to_string(),
                redacted_value: format!(
                    "https://@/home/{path_marker}/.ssh/id_rsa?token={query_marker} https://example.invalid%2Fhome%2F{path_marker}%2F.ssh%2Fid_rsa"
                ),
                hash: None,
                rule_id: None,
            }],
            risk_contributions: Vec::new(),
            event_time: None,
        })
        .expect("activity event");

        let bytes = serde_json::to_vec(&event).expect("direct event serialization");
        assert!(
            check_serialized_event_markers(
                &bytes,
                "direct-malformed-url-authority",
                &[
                    ControlledMarker {
                        id: "path",
                        value: path_marker,
                    },
                    ControlledMarker {
                        id: "query",
                        value: query_marker,
                    },
                ],
            )
            .is_ok(),
            "direct Event serialization retained a malformed URL authority marker"
        );
        let serialized: serde_json::Value =
            serde_json::from_slice(&bytes).expect("serialized Event JSON");
        assert_eq!(
            serialized["evidence"][0]["redacted_value"],
            "[redacted-url] [redacted-url]"
        );
    }

    #[test]
    fn direct_event_serialization_replaces_fully_encoded_url_authority_candidates() {
        let marker = "TT_PRIVACY_DIRECT_ENCODED_AUTHORITY_25";
        let cases = [
            format!("https%3A%2F%2Fexample.invalid%252F{marker}%2Fsafe"),
            format!("https%3A%2F%2Fexample.invalid%255C{marker}%2Fsafe"),
            format!("https%3A%2F%2Fexample.invalid%253Fnext%253D{marker}%2Fsafe"),
            format!("https%3A%2F%2Fexample.invalid%2523safe%253D{marker}%2Fsafe"),
            format!("https%3A%2F%2Fexample.invalid%2540{marker}%2Fsafe"),
            format!("https%3A%2F%2Fexample.invalid%252f{marker}%2Fsafe"),
            format!("https%253A%252F%252Fexample.invalid%25252F{marker}%252Fsafe"),
        ];
        let event = activity_event(ActivityEventInput {
            client: ClientId::Codex,
            agent: None,
            model: None,
            provider: None,
            session_id: "opaque-session".to_string(),
            source_path_hash: "source-hash".to_string(),
            tool_name: Some("shell".to_string()),
            tags: Vec::new(),
            evidence: vec![Evidence {
                field: "url".to_string(),
                redacted_value: cases.join(" "),
                hash: None,
                rule_id: None,
            }],
            risk_contributions: Vec::new(),
            event_time: None,
        })
        .expect("activity event");

        let bytes = serde_json::to_vec(&event).expect("direct event serialization");
        assert!(
            check_serialized_event_markers(
                &bytes,
                "direct-fully-encoded-url-authority",
                &[ControlledMarker {
                    id: "authority",
                    value: marker,
                }],
            )
            .is_ok(),
            "direct Event serialization retained a fully encoded URL authority marker"
        );
        let serialized: serde_json::Value =
            serde_json::from_slice(&bytes).expect("serialized Event JSON");
        assert_eq!(
            serialized["evidence"][0]["redacted_value"],
            "[redacted-url] [redacted-url] [redacted-url] [redacted-url] [redacted-url] [redacted-url] [redacted-url]"
        );
    }

    #[test]
    fn direct_event_serialization_redacts_encoded_url_candidate_prefix_forms_atomically() {
        let path_marker = "TT_PRIVACY_DIRECT_ENCODED_CANDIDATE_PATH_25";
        let authority_marker = "TT_PRIVACY_DIRECT_ENCODED_CANDIDATE_AUTHORITY_25";
        let evidence = format!(
            "%68%74%74%70%73%3A%2F%2Fexample.invalid%2Fhome%2F{path_marker}%2F.ssh%2Fid_rsa https%3A//example.invalid%252Fhome%252F{authority_marker}%252F.ssh%252Fid_rsa"
        );
        let event = activity_event(ActivityEventInput {
            client: ClientId::Codex,
            agent: None,
            model: None,
            provider: None,
            session_id: "opaque-session".to_string(),
            source_path_hash: "source-hash".to_string(),
            tool_name: Some("shell".to_string()),
            tags: Vec::new(),
            evidence: vec![Evidence {
                field: "url".to_string(),
                redacted_value: evidence,
                hash: None,
                rule_id: None,
            }],
            risk_contributions: Vec::new(),
            event_time: None,
        })
        .expect("activity event");

        let bytes = serde_json::to_vec(&event).expect("direct event serialization");
        assert!(
            check_serialized_event_markers(
                &bytes,
                "direct-encoded-url-candidate-prefix",
                &[
                    ControlledMarker {
                        id: "path",
                        value: path_marker,
                    },
                    ControlledMarker {
                        id: "authority",
                        value: authority_marker,
                    },
                ],
            )
            .is_ok(),
            "direct Event serialization retained an encoded URL candidate marker"
        );
        let serialized: serde_json::Value =
            serde_json::from_slice(&bytes).expect("serialized Event JSON");
        assert_eq!(
            serialized["evidence"][0]["redacted_value"],
            "https://example.invalid/[sensitive-path] [redacted-url]"
        );
        assert_eq!(
            serde_json::to_vec(&event).expect("repeat direct Event serialization"),
            bytes,
            "direct Event serialization was not stable"
        );
    }

    #[test]
    fn terminal_session_policy_rejects_assignment_token_and_credential_url_forms() {
        let sessions = [
            "TOKEN=TT_PRIVACY_NATIVE_SESSION_ASSIGNMENT_25",
            "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz12",
            "https://user:TT_PRIVACY_NATIVE_SESSION_URL_25@session.example.invalid",
        ];

        for (index, session) in sessions.into_iter().enumerate() {
            let event = activity_event(ActivityEventInput {
                client: ClientId::Codex,
                agent: Some("codex".to_string()),
                model: Some("gpt-5".to_string()),
                provider: Some("openai".to_string()),
                session_id: session.to_string(),
                source_path_hash: "source-hash".to_string(),
                tool_name: Some("shell".to_string()),
                tags: Vec::new(),
                evidence: Vec::new(),
                risk_contributions: Vec::new(),
                event_time: None,
            })
            .expect("activity event");
            let bytes = serde_json::to_vec(&event).expect("serialize event");
            let emitted: serde_json::Value =
                serde_json::from_slice(&bytes).expect("serialized event JSON");
            assert!(
                check_serialized_event_markers(
                    &bytes,
                    &format!("native-session-{index}"),
                    &[ControlledMarker {
                        id: "session",
                        value: session,
                    }],
                )
                .is_ok(),
                "native event retained a credential-shaped session"
            );
            assert_eq!(emitted["session_id"], terminal_session_id(session));
            assert!(
                emitted["session_id"]
                    .as_str()
                    .is_some_and(|value| value.starts_with("[session:"))
            );
        }
    }

    #[test]
    fn correlation_evidence_applies_the_shared_session_and_identifier_policies() {
        let session = "TOKEN=TT_PRIVACY_CORRELATION_SESSION_25";
        let event_id = "sk-abcdefghijklmnop";
        let event = correlation_event(CorrelationEventInput {
            client: "codex".to_string(),
            agent: None,
            model: None,
            provider: None,
            shared_rule_ids: vec!["rule.privacy".to_string()],
            sessions: vec![
                CorrelationSessionInput {
                    session_id: session.to_string(),
                    event_id: event_id.to_string(),
                    timestamp: "2026-05-01T00:00:00Z".to_string(),
                    severity: "high".to_string(),
                    risk_score: 80,
                },
                CorrelationSessionInput {
                    session_id: "safe-session".to_string(),
                    event_id: "safe-event".to_string(),
                    timestamp: "2026-05-01T00:01:00Z".to_string(),
                    severity: "low".to_string(),
                    risk_score: 20,
                },
            ],
            window_start: "2026-05-01T00:00:00Z".to_string(),
            window_end: "2026-05-01T00:01:00Z".to_string(),
            max_risk_score: 80,
        })
        .expect("correlation event");
        assert!(event.evidence[2].redacted_value.contains(session));
        assert!(event.evidence[2].redacted_value.contains(event_id));

        let emitted = serde_json::to_value(&event).expect("serialize correlation");
        let related = emitted["evidence"][2]["redacted_value"]
            .as_str()
            .expect("related detection evidence");
        assert!(!related.contains(session));
        assert!(!related.contains(event_id));
        assert!(related.contains(&terminal_session_id(session)));
        assert!(related.contains(&terminal_identifier("event", event_id)));

        let mut imported = emitted.clone();
        sanitize_serialized_event(&mut imported);
        assert_eq!(
            imported["evidence"][2]["redacted_value"], emitted["evidence"][2]["redacted_value"],
            "canonical correlation identities must survive historical re-export"
        );
    }

    #[test]
    fn terminal_identifiers_reject_lowercase_known_credentials() {
        for credential in ["sk-abcdefghijklmnop", "ghp_abcdefghijklmnopqrstuvwxyz12"] {
            assert!(terminal_identifier("tool", credential).starts_with("[tool:"));
        }
        assert_eq!(
            terminal_identifier("rule", "secret.env.read"),
            "secret.env.read"
        );
    }

    #[test]
    fn terminal_identifiers_reject_lowercase_path_and_url_shapes() {
        for value in [
            "https://source.example.invalid/private",
            "relative/source/path",
        ] {
            assert!(
                terminal_identifier("tool", value).starts_with("[tool:"),
                "path-shaped source identifier remained terminal text"
            );
            assert!(
                terminal_identifier("process", value).starts_with("[process:"),
                "path-shaped source process identifier remained terminal text"
            );
        }
    }

    #[test]
    fn historical_correlation_client_identity_is_opaque() {
        let client = "customer_internal_tenant";
        let mut historical = serde_json::json!({
            "schema_version": "2.0",
            "event_type": "correlation",
            "client": client,
        });

        sanitize_serialized_event(&mut historical);

        assert_eq!(historical["client"], opaque_identifier("client", client));
    }

    #[test]
    fn source_values_cannot_spoof_terminal_opaque_session_or_product_markers() {
        let forged_hash = "a".repeat(64);
        let forged_session = format!("[session:{forged_hash}]");
        let forged_model = format!("[model:{forged_hash}]");

        assert_ne!(terminal_session_id(&forged_session), forged_session);
        assert_ne!(
            terminal_product_metadata("model", &forged_model),
            forged_model
        );

        let mut legacy = serde_json::json!({
            "schema_version": "2.0",
            "session_id": forged_session.clone(),
            "extension": forged_model.clone(),
        });
        sanitize_serialized_event(&mut legacy);
        assert_ne!(legacy["session_id"], forged_session);
        assert_ne!(legacy["extension"], forged_model);
    }

    #[test]
    fn canonical_opaque_identifier_recognizer_requires_registered_exact_markers() {
        let digest = "a".repeat(64);
        let marker = format!("[session:{digest}]");
        let parsed = parse_canonical_opaque_identifier(&marker).expect("exact marker");
        assert_eq!(parsed.kind(), "session");
        assert_eq!(parsed.digest(), digest);
        assert!(is_canonical_opaque_identifier_for_kind("session", &marker));
        assert!(!is_canonical_opaque_identifier_for_kind("model", &marker));

        for malformed in [
            format!("[session:{}]", "a".repeat(63)),
            format!("[session:{}]", "a".repeat(65)),
            format!("[session:{}]", "g".repeat(64)),
            format!("[session:{}]", "A".repeat(64)),
            format!("prefix{marker}"),
            format!("{marker}suffix"),
            format!("[unknown:{digest}]"),
        ] {
            assert!(
                parse_canonical_opaque_identifier(&malformed).is_none(),
                "malformed marker received canonical recognition"
            );
            assert_ne!(
                terminal_historical_session_id(&malformed),
                malformed,
                "malformed marker received historical preservation"
            );
        }
    }

    #[test]
    fn historical_canonical_markers_are_idempotent_unauthenticated_labels() {
        let session = format!("[session:{}]", "a".repeat(64));
        let model = format!("[model:{}]", "b".repeat(64));
        let key = format!("[metadata-key:{}]", "c".repeat(64));
        let mut historical = serde_json::json!({
            "schema_version": "3.0",
            "event_type": "activity",
            "session_id": session,
            "model": model,
            key.clone(): "safe",
        });

        for _ in 0..3 {
            sanitize_serialized_event(&mut historical);
        }

        assert_eq!(historical["session_id"], session);
        assert_eq!(historical["model"], model);
        assert_eq!(historical[&key], "safe");
    }

    #[test]
    fn attacker_supplied_historical_exact_marker_is_preserved_without_authentication() {
        let marker = format!("[session:{}]", "d".repeat(64));
        let mut historical = serde_json::json!({
            "schema_version": "3.0",
            "event_type": "activity",
            "session_id": marker,
        });

        sanitize_serialized_event(&mut historical);

        // Preservation is only a pseudonymous-label contract. It is not proof
        // that Telltale generated the historical JSON value.
        assert_eq!(historical["session_id"], marker);
        assert!(is_canonical_opaque_identifier_for_kind(
            "session",
            historical["session_id"].as_str().expect("session marker")
        ));
    }

    #[test]
    fn historical_typed_markers_are_exact_kind_scoped_and_idempotent() {
        let marker = |kind| opaque_identifier(kind, &format!("{kind} source value"));
        let agent = marker("agent");
        let model = marker("model");
        let provider = marker("provider");
        let client = marker("client");
        let session = marker("session");
        let tool = marker("tool");
        let category = marker("category");
        let tag = marker("tag");
        let suppression = marker("suppression");
        let evidence_field = marker("evidence-field");
        let invalid_time = marker("invalid-event-time");
        let process = marker("process");
        let host = marker("host");
        let user = marker("user");
        let source_event = marker("source-event");
        let dedup = marker("dedup");
        let process_rule = marker("process-rule");
        let process_config = marker("process-config");
        let process_adjustment = marker("process-adjustment");
        let policy = marker("policy");
        let extension = marker("metadata-key");
        let mut historical = serde_json::json!({
            "schema_version": "3.0",
            "event_type": "detection",
            "event_time": invalid_time,
            "agent": agent,
            "model": model,
            "provider": provider,
            "client": client,
            "session_id": session,
            "tool_name": tool,
            "categories": [category],
            "tags": [tag, format!("allowlist:{suppression}")],
            "active_policy_name": policy,
            "risk_entity_type": "session",
            "risk_entity_value": session,
            "evidence": [{
                "field": evidence_field,
                "redacted_value": "safe",
            }, {
                "field": "allowlist",
                "redacted_value": suppression,
            }],
            "process": {
                "host": host,
                "user": user,
                "source_process_name": process,
                "target_process_name": process,
                "parent_process_name": process,
                "source_event_id": source_event,
                "dedup_key": dedup,
                "rule_name": process_rule,
                "investigation_fields": [process_config],
                "falsepositives": [process_config],
                "risk_adjustment": process_adjustment,
            },
            "timeline_anchors": [{
                "rule_ids": ["rule.test"],
                "categories": [category],
                "evidence_fields": [evidence_field],
            }],
            "extension": extension,
        });
        let expected = historical.clone();

        sanitize_serialized_event(&mut historical);
        assert_eq!(historical, expected);
        sanitize_serialized_event(&mut historical);
        assert_eq!(historical, expected);

        let wrong_kind = marker("session");
        let mut wrong = serde_json::json!({
            "schema_version": "3.0",
            "event_time": wrong_kind,
            "tool_name": wrong_kind,
            "categories": [wrong_kind],
            "tags": [wrong_kind],
            "evidence": [{ "field": wrong_kind, "redacted_value": "safe" }],
            "process": { "source_process_name": wrong_kind },
            "timeline_anchors": [{
                "rule_ids": ["rule.test"],
                "categories": [wrong_kind],
                "evidence_fields": [wrong_kind],
            }],
        });
        sanitize_serialized_event(&mut wrong);
        assert_ne!(wrong["event_time"], wrong_kind);
        assert_ne!(wrong["tool_name"], wrong_kind);
        assert_ne!(wrong["categories"][0], wrong_kind);
        assert_ne!(wrong["tags"][0], wrong_kind);
        assert_ne!(wrong["evidence"][0]["field"], wrong_kind);
        assert_ne!(wrong["process"]["source_process_name"], wrong_kind);
        assert_ne!(wrong["timeline_anchors"][0]["categories"][0], wrong_kind);
        assert_ne!(
            wrong["timeline_anchors"][0]["evidence_fields"][0],
            wrong_kind
        );
    }

    #[test]
    fn historical_known_fields_do_not_use_generic_marker_preservation() {
        let marker = opaque_identifier("session", "wrong typed marker");
        let canonical_hash = "a".repeat(64);
        let mut historical = serde_json::json!({
            "schema_version": "3.0",
            "event_id": marker,
            "timestamp": marker,
            "observed_at": marker,
            "ingested_at": marker,
            "event_type": marker,
            "severity": marker,
            "time_source": marker,
            "time_confidence": marker,
            "source_path_hash": marker,
            "detection_classes": [marker],
            "signal_types": [marker],
            "analytic_intents": [marker],
            "extension": marker,
            "response": {"extension": marker},
            "evidence": [{
                "field": "test",
                "redacted_value": "safe",
                "hash": canonical_hash,
            }],
        });

        sanitize_serialized_event(&mut historical);

        for field in [
            "event_id",
            "timestamp",
            "observed_at",
            "ingested_at",
            "event_type",
            "severity",
            "time_source",
            "time_confidence",
            "source_path_hash",
        ] {
            assert_ne!(
                historical[field], marker,
                "known field preserved wrong marker"
            );
        }
        for field in ["detection_classes", "signal_types", "analytic_intents"] {
            assert_ne!(
                historical[field][0], marker,
                "known enum preserved wrong marker"
            );
        }
        assert_eq!(historical["extension"], marker);
        assert_eq!(historical["response"]["extension"], marker);
        assert_eq!(historical["evidence"][0]["hash"], canonical_hash);

        let once = historical.clone();
        sanitize_serialized_event(&mut historical);
        assert_eq!(historical, once);
    }

    #[test]
    fn credential_shaped_schema_identifiers_are_rejected_before_emission() {
        let credential_rule = "rule.ghp_abcdefghijklmnop".to_string();
        assert!(validate_rule_ids(std::slice::from_ref(&credential_rule)).is_err());
        assert!(
            RiskContribution::new(
                &credential_rule,
                RiskContributionType::DeterministicRule,
                1,
                "safe rationale",
            )
            .is_err()
        );

        let invalid_evidence = detection_event(DetectionEventInput {
            client: ClientId::Codex,
            agent: None,
            model: None,
            provider: None,
            session_id: "session".to_string(),
            source_path_hash: "hash".to_string(),
            tool_name: None,
            rule_ids: vec!["rule.safe".to_string()],
            categories: vec!["test".to_string()],
            detection_classes: vec!["security_detection".to_string()],
            signal_types: vec!["atomic".to_string()],
            analytic_intents: vec!["alert".to_string()],
            atlas_tags: Vec::new(),
            tags: Vec::new(),
            evidence: vec![Evidence {
                field: "safe_field".to_string(),
                redacted_value: "safe".to_string(),
                hash: None,
                rule_id: Some(credential_rule.clone()),
            }],
            risk_contributions: vec![
                RiskContribution::new(
                    "rule.safe",
                    RiskContributionType::DeterministicRule,
                    1,
                    "safe",
                )
                .expect("contribution"),
            ],
            event_time: None,
        });
        assert!(invalid_evidence.is_err());

        let invalid_atlas_tag = detection_event(DetectionEventInput {
            client: ClientId::Codex,
            agent: None,
            model: None,
            provider: None,
            session_id: "session".to_string(),
            source_path_hash: "hash".to_string(),
            tool_name: None,
            rule_ids: vec!["rule.test".to_string()],
            categories: vec!["test".to_string()],
            detection_classes: vec!["security_detection".to_string()],
            signal_types: vec!["atomic".to_string()],
            analytic_intents: vec!["alert".to_string()],
            atlas_tags: vec!["atlas:ghp_abcdefghijklmnop".to_string()],
            tags: Vec::new(),
            evidence: Vec::new(),
            risk_contributions: test_contribution(1),
            event_time: None,
        });
        assert!(invalid_atlas_tag.is_err());
    }

    #[test]
    fn historical_canonical_hashes_and_terminal_identities_are_preserved() {
        let source_hash = "a".repeat(64);
        let evidence_hash = "b".repeat(64);
        let session = format!("[session:{}]", "c".repeat(64));
        let mut event = serde_json::json!({
            "schema_version": "3.0",
            "event_type": "activity",
            "session_id": session,
            "source_path_hash": source_hash,
            "evidence": [{
                "field": "arguments",
                "redacted_value": "safe",
                "hash": evidence_hash
            }]
        });

        sanitize_serialized_event(&mut event);

        assert_eq!(event["session_id"], session);
        assert_eq!(event["source_path_hash"], source_hash);
        assert_eq!(event["evidence"][0]["hash"], evidence_hash);
    }

    #[test]
    fn terminal_product_metadata_preserves_known_ids_and_rejects_credentials() {
        let credential_model = "gpt-5-ghp_AbCdEfGhIjKlMnOpQrStUvWxYz12";
        assert_eq!(terminal_product_metadata("agent", "codex"), "codex");
        assert_eq!(terminal_product_metadata("model", "gpt-5"), "gpt-5");
        assert_eq!(terminal_product_metadata("provider", "openai"), "openai");
        assert!(terminal_product_metadata("model", credential_model).starts_with("[model:"));
        assert!(terminal_product_metadata("agent", "TOKEN=short").starts_with("[agent:"));
        assert!(
            terminal_product_metadata("provider", "https://user:pass@host.invalid")
                .starts_with("[provider:")
        );

        let event = activity_event(ActivityEventInput {
            client: ClientId::Codex,
            agent: Some("codex".to_string()),
            model: Some(credential_model.to_string()),
            provider: Some("openai".to_string()),
            session_id: "safe-session".to_string(),
            source_path_hash: "source-hash".to_string(),
            tool_name: Some("shell".to_string()),
            tags: Vec::new(),
            evidence: Vec::new(),
            risk_contributions: Vec::new(),
            event_time: None,
        })
        .expect("activity event");
        let bytes = serde_json::to_vec(&event).expect("serialize event");
        assert!(
            check_serialized_event_markers(
                &bytes,
                "credential-model",
                &[ControlledMarker {
                    id: "model",
                    value: credential_model,
                }],
            )
            .is_ok()
        );
    }

    #[test]
    fn terminal_event_serialization_hashes_unsafe_sessions_but_keeps_safe_product_metadata() {
        let unsafe_session = "TT_PRIVACY_UNSAFE_SESSION_25";
        let event = activity_event(ActivityEventInput {
            client: ClientId::Codex,
            agent: Some("codex".to_string()),
            model: Some("gpt-5".to_string()),
            provider: Some("openai".to_string()),
            session_id: unsafe_session.to_string(),
            source_path_hash: "source-hash".to_string(),
            tool_name: Some("shell".to_string()),
            tags: Vec::new(),
            evidence: Vec::new(),
            risk_contributions: Vec::new(),
            event_time: None,
        })
        .expect("activity event");
        let bytes = serde_json::to_vec(&event).expect("serialize event");
        let emitted: serde_json::Value = serde_json::from_slice(&bytes).expect("event JSON");

        assert!(
            check_serialized_event_markers(
                &bytes,
                "unsafe-session",
                &[ControlledMarker {
                    id: "unsafe-session",
                    value: unsafe_session,
                }],
            )
            .is_ok(),
            "serialized event retained an unsafe session marker"
        );
        assert_eq!(emitted["agent"], "codex");
        assert_eq!(emitted["model"], "gpt-5");
        assert_eq!(emitted["provider"], "openai");
        assert_eq!(
            emitted["session_id"],
            format!(
                "[session:{}]",
                evidence_hash(&format!("session-id:v1\0{unsafe_session}"))
            )
        );
        assert_eq!(event.session_id, unsafe_session);
    }
}
