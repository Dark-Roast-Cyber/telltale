//! Rule v1 compatibility compiler.
//!
//! This compiler consumes the effective compiled-rule view.  It intentionally
//! does not parse YAML and does not carry the legacy allowlist or evaluator into
//! Detection v2.

use std::collections::BTreeSet;
use std::fmt;

use telltale_rules::{
    RuleV1CompatibilityExport, RuleV1CompatibilityModifier, RuleV1CompatibilityRule,
};
use telltale_schema::observation::{CapabilityId, JsonValue, ObservationFamily, ObservationStage};

use super::matcher::{MatcherOperator, MatcherSpec};
use super::observation_match::{CompiledObservationMatchDetector, ObservationMatchSpec};
use super::types::{
    DetectionError, DetectorIdentity, DetectorKind, FindingKind, FindingMetadata, Severity,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleV1CompileError {
    InvalidRule,
    UnknownTarget,
    UnmappableDetectionClass,
    InvalidSeverity,
    ScoreOutOfRange,
    InvalidMetadata,
}

impl RuleV1CompileError {
    pub fn code(self) -> &'static str {
        match self {
            Self::InvalidRule => "invalid_rule",
            Self::UnknownTarget => "unknown_target",
            Self::UnmappableDetectionClass => "unmappable_detection_class",
            Self::InvalidSeverity => "invalid_severity",
            Self::ScoreOutOfRange => "score_out_of_range",
            Self::InvalidMetadata => "invalid_metadata",
        }
    }
}

impl fmt::Display for RuleV1CompileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for RuleV1CompileError {}

#[derive(Debug, Clone)]
pub struct RuleV1ModifierPlan {
    id: String,
    score: u64,
    detection_class: String,
    signal_type: String,
    analytic_intent: String,
    atlas_tags: Vec<String>,
    when_all_categories: Vec<String>,
    when_all_rule_ids: Vec<String>,
    falsepositives: Vec<String>,
    explanation: String,
}

impl RuleV1ModifierPlan {
    fn from_export(value: &RuleV1CompatibilityModifier) -> Self {
        Self {
            id: value.id.clone(),
            score: value.score,
            detection_class: value.detection_class.clone(),
            signal_type: value.signal_type.clone(),
            analytic_intent: value.analytic_intent.clone(),
            atlas_tags: value.atlas_tags.clone(),
            when_all_categories: value.when_all_categories.clone(),
            when_all_rule_ids: value.when_all_rule_ids.clone(),
            falsepositives: value.falsepositives.clone(),
            explanation: value.explanation.clone(),
        }
    }

    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn score(&self) -> u64 {
        self.score
    }
    pub fn detection_class(&self) -> &str {
        &self.detection_class
    }
    pub fn signal_type(&self) -> &str {
        &self.signal_type
    }
    pub fn analytic_intent(&self) -> &str {
        &self.analytic_intent
    }
    pub fn atlas_tags(&self) -> &[String] {
        &self.atlas_tags
    }
    pub fn when_all_categories(&self) -> &[String] {
        &self.when_all_categories
    }
    pub fn when_all_rule_ids(&self) -> &[String] {
        &self.when_all_rule_ids
    }
    pub fn falsepositives(&self) -> &[String] {
        &self.falsepositives
    }
    pub fn explanation(&self) -> &str {
        &self.explanation
    }
}

#[derive(Debug, Clone)]
pub struct RuleV1CompatibilityPlan {
    policy_name: Option<String>,
    detectors: Vec<CompiledObservationMatchDetector>,
    modifiers: Vec<RuleV1ModifierPlan>,
}

impl RuleV1CompatibilityPlan {
    pub fn policy_name(&self) -> Option<&str> {
        self.policy_name.as_deref()
    }
    pub fn detectors(&self) -> &[CompiledObservationMatchDetector] {
        &self.detectors
    }
    pub fn modifiers(&self) -> &[RuleV1ModifierPlan] {
        &self.modifiers
    }
}

/// Compile every effective Rule v1 rule to an observation matcher.  A single
/// compatibility detector may apply to Message and Tool observations because
/// legacy targets span those two canonical families; it still evaluates one
/// observation at a time and never aggregates a session.
pub fn compile_rule_v1(
    rules: &RuleV1CompatibilityExport,
) -> Result<RuleV1CompatibilityPlan, RuleV1CompileError> {
    let detectors = rules
        .rules()
        .iter()
        .map(compile_rule)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(RuleV1CompatibilityPlan {
        policy_name: rules.policy_name().map(str::to_owned),
        detectors,
        modifiers: rules
            .modifiers()
            .iter()
            .map(RuleV1ModifierPlan::from_export)
            .collect(),
    })
}

fn compile_rule(
    rule: &RuleV1CompatibilityRule,
) -> Result<CompiledObservationMatchDetector, RuleV1CompileError> {
    if rule.signal_type != "atomic" {
        return Err(RuleV1CompileError::InvalidMetadata);
    }
    let finding_kind = finding_kind(&rule.detection_class)?;
    let severity = severity(&rule.severity)?;
    if rule.score > 100 {
        return Err(RuleV1CompileError::ScoreOutOfRange);
    }
    let tags = rule.tags.iter().map(String::as_str).collect::<Vec<_>>();
    let techniques = rule
        .atlas_tags
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    let metadata = FindingMetadata::new(finding_kind, &rule.category, severity)
        .map_err(|_| RuleV1CompileError::InvalidMetadata)?
        .with_risk_points(rule.score)
        .map_err(|_| RuleV1CompileError::ScoreOutOfRange)?
        .with_tags(tags)
        .map_err(|_| RuleV1CompileError::InvalidMetadata)?
        .with_techniques(techniques)
        .map_err(|_| RuleV1CompileError::InvalidMetadata)?;

    if rule.matchers.is_empty() {
        return Err(RuleV1CompileError::InvalidRule);
    }
    let mut clauses = Vec::new();
    let mut families = Vec::new();
    for matcher in &rule.matchers {
        let selector = compat_selector(&matcher.target)?;
        for family in selector_families(&matcher.target) {
            if !families.contains(&family) {
                families.push(family);
            }
        }
        clauses.push(MatcherSpec::predicate(
            selector,
            MatcherOperator::Regex,
            Some(JsonValue::string(&matcher.regex)),
        ));
    }
    let matcher = MatcherSpec::any(clauses);
    let identity = DetectorIdentity::new(DetectorKind::ObservationMatch, &rule.id)
        .map_err(|_| RuleV1CompileError::InvalidMetadata)?
        .with_version("1")
        .map_err(|_| RuleV1CompileError::InvalidMetadata)?
        .with_rule_version(1)
        .map_err(|_| RuleV1CompileError::InvalidMetadata)?;
    let stages = families
        .iter()
        .flat_map(|family| family_stages(*family).iter().copied())
        .collect::<Vec<_>>();
    ObservationMatchSpec::new_for_families(identity, families, stages, matcher, metadata)
        .with_required_capabilities(required_capabilities(rule))
        .compile()
        .map_err(|error| match error {
            DetectionError::InvalidSelector => RuleV1CompileError::UnknownTarget,
            DetectionError::ScoreOutOfRange => RuleV1CompileError::ScoreOutOfRange,
            _ => RuleV1CompileError::InvalidMetadata,
        })
}

fn compat_selector(target: &str) -> Result<String, RuleV1CompileError> {
    match target {
        "arguments" | "assistant_context" | "command" | "file_path" | "tool_name"
        | "tool_result" | "url" | "user_context" => Ok(format!("compat.v1.{target}")),
        _ => Err(RuleV1CompileError::UnknownTarget),
    }
}

fn selector_families(target: &str) -> [ObservationFamily; 1] {
    match target {
        "assistant_context" | "user_context" => [ObservationFamily::Message],
        _ => [ObservationFamily::Tool],
    }
}

fn family_stages(family: ObservationFamily) -> &'static [ObservationStage] {
    const MESSAGE: &[ObservationStage] = &[ObservationStage::MessageObserved];
    const TOOL: &[ObservationStage] = &[
        ObservationStage::ToolProposed,
        ObservationStage::ToolRequested,
        ObservationStage::ToolExecutionStarted,
        ObservationStage::ToolExecutionCompleted,
        ObservationStage::ToolResultReturned,
    ];
    match family {
        ObservationFamily::Message => MESSAGE,
        ObservationFamily::Tool => TOOL,
        _ => &[],
    }
}

fn required_capabilities(rule: &RuleV1CompatibilityRule) -> Vec<CapabilityId> {
    let mut capabilities = BTreeSet::new();
    for matcher in &rule.matchers {
        match matcher.target.as_str() {
            "assistant_context" | "user_context" => {
                capabilities.insert(CapabilityId::UserContext);
            }
            _ => {
                capabilities.insert(CapabilityId::ToolCall);
            }
        }
    }
    capabilities.into_iter().collect()
}

fn finding_kind(class: &str) -> Result<FindingKind, RuleV1CompileError> {
    match class {
        "security_detection" => Ok(FindingKind::SecurityDetection),
        "policy_violation" => Ok(FindingKind::PolicyViolation),
        "threat_hunting" => Ok(FindingKind::ThreatHunt),
        "compliance_observation" => Ok(FindingKind::ComplianceObservation),
        "baseline_deviation" => Ok(FindingKind::BehavioralDeviation),
        // Operational health is not a truthful security meaning for an atomic
        // Rule v1 observation match.  Do not silently map it to informational.
        "operational_health" => Err(RuleV1CompileError::UnmappableDetectionClass),
        _ => Err(RuleV1CompileError::UnmappableDetectionClass),
    }
}

fn severity(value: &str) -> Result<Severity, RuleV1CompileError> {
    match value {
        "informational" => Ok(Severity::Informational),
        "low" => Ok(Severity::Low),
        "medium" => Ok(Severity::Medium),
        "high" => Ok(Severity::High),
        "critical" => Ok(Severity::Critical),
        _ => Err(RuleV1CompileError::InvalidSeverity),
    }
}
