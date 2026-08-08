use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;
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
pub(crate) use redaction::contains_high_confidence_credential_marker;
pub use redaction::redact_sensitive_text;
pub use time::{format_timestamp, parse_event_timestamp};

const SCHEMA_VERSION: &str = "2.0";

#[derive(Debug, Clone, Serialize)]
pub struct Event {
    pub timestamp: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_time: Option<String>,
    pub observed_at: String,
    pub ingested_at: String,
    pub time_source: String,
    pub time_confidence: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_override_reason: Option<String>,
    pub schema_version: String,
    pub event_id: String,
    pub event_type: String,
    pub severity: String,
    pub risk_score: u64,
    pub risk_contributions: Vec<RiskContribution>,
    pub client: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    pub session_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workspace: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_path_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_name: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub rule_ids: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub categories: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub detection_classes: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub signal_types: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub analytic_intents: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub atlas_tags: Vec<String>,
    pub tags: Vec<String>,
    pub evidence: Vec<Evidence>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub triage: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<ResponseMetadata>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_counts: Option<BTreeMap<String, u32>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub component: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub check_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub adr_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scan_duration_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threshold_config: Option<RiskThresholds>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_policy_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub emitted_count: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suppressed_count: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scanner_error_count: Option<u64>,
    /// Present on detections that scored `0`. An informational event still
    /// carries full rule context; it simply contributes no risk.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub informational: Option<bool>,
    /// Fidelity of the match: `low`, `medium`, or `high`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<String>,
    /// Redaction-safe sentence explaining why the rule fired.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detection_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mitre_attack_techniques: Vec<String>,
    /// Entity that should accumulate this event's risk (`host`, `user`, or
    /// `session`). Informational events name the entity but add no risk.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub risk_entity_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub risk_entity_value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process: Option<ProcessContext>,
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
        max_scanner_errors: std::env::var("ADR_OP_ALERT_MAX_SCANNER_ERRORS")
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(3),
        max_scan_duration_ms: std::env::var("ADR_OP_ALERT_MAX_SCAN_DURATION_MS")
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
    emitted_count: Option<u64>,
    suppressed_count: Option<u64>,
    scanner_error_count: Option<u64>,
}

impl EventBuilder {
    fn build(self) -> Event {
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
            schema_version: SCHEMA_VERSION.to_string(),
            event_id: format!("adr-{}", Uuid::new_v4()),
            event_type: self.event_type.to_string(),
            severity: self.severity.to_string(),
            risk_score: self.risk_score,
            risk_contributions: self.risk_contributions,
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
        source_counts: Some(inventory::source_counts(sources)),
        component: Some("scanner".to_string()),
        check_name: Some("source_discovery".to_string()),
        status: Some("ok".to_string()),
        adr_version: Some(format!(
            "{} ({})",
            env!("CARGO_PKG_VERSION"),
            env!("ADR_GIT_HASH")
        )),
        scan_duration_ms: Some(input.scan_duration_ms),
        rule_count: Some(input.rule_count),
        threshold_config: Some(input.threshold_config),
        active_policy_name: input.active_policy_name.map(str::to_string),
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

pub fn validate_schema_two_rule_ids(rule_ids: &[String]) -> Result<(), RiskAccountingError> {
    for rule_id in rule_ids {
        if !is_canonical_contribution_id(rule_id) {
            return Err(RiskAccountingError::InvalidRuleId(rule_id.clone()));
        }
    }
    Ok(())
}

pub fn detection_event(
    input: DetectionEventInput,
) -> Result<Event, crate::scoring::RiskAccountingError> {
    validate_schema_two_rule_ids(&input.rule_ids)?;
    let risk_contributions = canonicalize_contributions(input.risk_contributions)?;
    validate_risk_accounting_scope("detection", &input.rule_ids, &risk_contributions)?;
    let risk_score = score_for_contributions(&risk_contributions)?;
    let thresholds = load_thresholds();
    let assessment = assess_risk_with_thresholds(risk_score, thresholds);
    let response = time::response_metadata(
        assessment.severity.as_str(),
        &input.rule_ids,
        &input.categories,
        assessment.triage_required,
    );
    let triage = if assessment.triage_required {
        serde_json::json!({
            "required": true,
            "verdict": "config_missing"
        })
    } else {
        serde_json::json!({
            "required": false,
            "verdict": "not_required"
        })
    };
    Ok(EventBuilder {
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
/// produces an event, marked `informational` with `risk_score: 0`. Command
/// lines and paths in `process` are redacted before they reach the event.
pub fn process_chain_event(
    input: ProcessChainEventInput,
) -> Result<Event, crate::scoring::RiskAccountingError> {
    validate_schema_two_rule_ids(&input.rule_ids)?;
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
        assessment.triage_required,
    );

    let mut event = EventBuilder {
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
        workspace: None,
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
        triage: None,
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
        emitted_count: None,
        suppressed_count: None,
        scanner_error_count: None,
    }
    .build();

    event.informational = Some(risk_score == 0);
    event.confidence = Some(input.confidence);
    event.detection_reason = Some(redact_sensitive_text(&input.detection_reason));
    event.mitre_attack_techniques = input.mitre_attack_techniques;
    event.risk_entity_type = Some(input.risk_entity_type);
    event.risk_entity_value = input.risk_entity_value;
    event.process = Some(redact_process_context(input.process));
    Ok(event)
}

fn redact_process_context(mut process: ProcessContext) -> ProcessContext {
    process.source_process_command_line = process
        .source_process_command_line
        .as_deref()
        .map(redact_sensitive_text);
    process.target_process_command_line = process
        .target_process_command_line
        .as_deref()
        .map(redact_sensitive_text);
    process.source_process_path = process
        .source_process_path
        .as_deref()
        .map(redact_sensitive_text);
    process.target_process_path = process
        .target_process_path
        .as_deref()
        .map(redact_sensitive_text);
    process.parent_process_path = process
        .parent_process_path
        .as_deref()
        .map(redact_sensitive_text);
    process
}

pub fn activity_event(
    input: ActivityEventInput,
) -> Result<Event, crate::scoring::RiskAccountingError> {
    let risk_contributions = canonicalize_contributions(input.risk_contributions)?;
    validate_risk_accounting_scope("activity", &[], &risk_contributions)?;
    let risk_score = score_for_contributions(&risk_contributions)?;
    let thresholds = load_thresholds();
    let assessment = assess_risk_with_thresholds(risk_score, thresholds);
    Ok(EventBuilder {
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
        emitted_count: None,
        suppressed_count: None,
        scanner_error_count: None,
    }
    .build())
}

pub fn install_inventory_event(evidence: Vec<Evidence>) -> Event {
    EventBuilder {
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
        workspace: None,
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
        triage: None,
        response: None,
        source_counts: None,
        component: Some("scanner".to_string()),
        check_name: Some("install_inventory".to_string()),
        status: Some("ok".to_string()),
        adr_version: Some(env!("CARGO_PKG_VERSION").to_string()),
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

pub fn session_risk_summary_event(
    input: SessionRiskSummaryEventInput,
) -> Result<Event, crate::scoring::RiskAccountingError> {
    validate_schema_two_rule_ids(&input.rule_ids)?;
    let risk_contributions = canonicalize_contributions(input.risk_contributions)?;
    validate_risk_accounting_scope("session_risk_summary", &input.rule_ids, &risk_contributions)?;
    let risk_score = score_for_contributions(&risk_contributions)?;
    let thresholds = load_thresholds();
    let assessment = assess_risk_with_thresholds(risk_score, thresholds);
    Ok(EventBuilder {
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
        emitted_count: None,
        suppressed_count: None,
        scanner_error_count: None,
    }
    .build())
}

pub fn correlation_event(
    input: CorrelationEventInput,
) -> Result<Event, crate::scoring::RiskAccountingError> {
    validate_schema_two_rule_ids(&input.shared_rule_ids)?;
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
        workspace: None,
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
    use super::{
        ActivityEventInput, CorrelationEventInput, DetectionEventInput, Evidence, HealthEventInput,
        OperationalAlertInput, SessionRiskSummaryEventInput, activity_event, correlation_event,
        detection_event, health_event_with_metadata, operational_alert_event, scanner_error_event,
        session_risk_summary_event, validate_risk_accounting_scope,
    };
    use crate::clients::ClientId;
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
        assert_eq!(event["source_path_hash"], "hash");
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
        assert_eq!(event["agent"], "agent");
        assert_eq!(event["event_time"], "2026-05-01T00:00:00.000Z");
        assert_eq!(event["rule_ids"][0], "rule.test");
        assert_eq!(event["categories"][0], "category");
        assert_eq!(event["detection_classes"][0], "security_detection");
        assert_eq!(event["signal_types"][0], "atomic");
        assert_eq!(event["analytic_intents"][0], "alert");
        assert_eq!(event["atlas_tags"][0], "atlas:AML.T0051");
        assert_eq!(event["evidence"][0]["hash"], "evidence-hash");
        assert_eq!(event["evidence"][0]["rule_id"], "rule.test");
        assert!(event["triage"].is_object());
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
    fn detection_event_serializes_config_missing_for_high_scores() {
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
            detection_classes: Vec::new(),
            signal_types: Vec::new(),
            analytic_intents: Vec::new(),
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
        let triage = event.triage.expect("triage metadata");
        assert_eq!(triage["required"], true);
        assert_eq!(triage["verdict"], "config_missing");
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
            rule_ids: vec!["rule.test".to_string()],
            categories: vec!["category".to_string()],
            detection_classes: Vec::new(),
            signal_types: Vec::new(),
            analytic_intents: Vec::new(),
            atlas_tags: Vec::new(),
            tags: vec!["tag".to_string()],
            evidence: Vec::new(),
            risk_contributions: Vec::new(),
            event_time: Some("2026-05-01T00:00:00Z".to_string()),
        })
        .expect("build detection event");

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
            detection_classes: Vec::new(),
            signal_types: Vec::new(),
            analytic_intents: Vec::new(),
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
            detection_classes: Vec::new(),
            signal_types: Vec::new(),
            analytic_intents: Vec::new(),
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
            detection_classes: Vec::new(),
            signal_types: Vec::new(),
            analytic_intents: Vec::new(),
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
            detection_classes: Vec::new(),
            signal_types: Vec::new(),
            analytic_intents: Vec::new(),
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
