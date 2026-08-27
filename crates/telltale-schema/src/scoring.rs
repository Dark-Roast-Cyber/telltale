use std::collections::BTreeMap;
use std::env;

use serde::{Deserialize, Serialize};

pub const MAX_RISK_RATIONALE_LENGTH: usize = 256;
pub const DEFAULT_RISK_RATIONALE: &str = "risk contribution";

pub fn normalize_risk_rationale(raw: &str) -> String {
    let mut normalized = String::with_capacity(raw.len().min(MAX_RISK_RATIONALE_LENGTH));
    let mut pending_space = false;
    for character in raw.chars() {
        let allowed = character.is_ascii_alphanumeric()
            || matches!(
                character,
                ' ' | ',' | '_' | ';' | ':' | '\'' | '(' | ')' | '-'
            );
        if character.is_ascii_whitespace() {
            pending_space = !normalized.is_empty();
        } else if allowed {
            if pending_space
                && !normalized.ends_with(' ')
                && normalized.len() < MAX_RISK_RATIONALE_LENGTH
            {
                normalized.push(' ');
            }
            if normalized.len() < MAX_RISK_RATIONALE_LENGTH {
                normalized.push(character);
            }
            pending_space = false;
        } else {
            pending_space = !normalized.is_empty();
        }
        if normalized.len() >= MAX_RISK_RATIONALE_LENGTH {
            break;
        }
    }
    while normalized
        .chars()
        .next()
        .is_some_and(|character| !character.is_ascii_alphanumeric())
    {
        normalized.remove(0);
    }
    while normalized.ends_with(' ') {
        normalized.pop();
    }
    if normalized.is_empty() {
        DEFAULT_RISK_RATIONALE.to_string()
    } else {
        normalized
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskContributionType {
    DeterministicRule,
    ChainModifier,
    BaselineDeviation,
}

#[derive(Debug, Clone, PartialEq, Eq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(try_from = "RiskContributionWire")]
pub struct RiskContribution {
    id: String,
    #[serde(rename = "type")]
    contribution_type: RiskContributionType,
    points: u64,
    rationale: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RiskAccountingError {
    NonPositiveContribution(String),
    EmptyContributionId,
    RationaleTooLong(String),
    RationaleContainsControlCharacter(String),
    InvalidRationale(String),
    InvalidContributionId(String),
    UnsafeRationale(String),
    Overflow,
    ScoreMismatch {
        declared: u64,
        computed: u64,
    },
    ConflictingContribution(String),
    NonCanonicalContributions,
    InvalidRuleId(String),
    ContributionTypeNotAllowed {
        event_type: String,
        id: String,
        contribution_type: RiskContributionType,
    },
    ContributionRuleIdMissing(String),
    EmptyEventField {
        event_type: &'static str,
        field: &'static str,
    },
    InvalidEventValue {
        event_type: &'static str,
        field: &'static str,
    },
    InvalidCorrelationCardinality {
        actual: usize,
    },
    DuplicateCorrelationValue {
        field: &'static str,
    },
}

impl std::fmt::Display for RiskAccountingError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NonPositiveContribution(id) => {
                write!(formatter, "risk contribution {id} must be positive")
            }
            Self::EmptyContributionId => {
                formatter.write_str("risk contribution id must not be empty")
            }
            Self::RationaleTooLong(id) => {
                write!(formatter, "risk contribution {id} rationale is too long")
            }
            Self::RationaleContainsControlCharacter(id) => write!(
                formatter,
                "risk contribution {id} rationale contains a control character"
            ),
            Self::InvalidRationale(id) => {
                write!(formatter, "risk contribution {id} has invalid rationale")
            }
            Self::InvalidContributionId(id) => {
                write!(formatter, "risk contribution id {id} is not canonical")
            }
            Self::UnsafeRationale(id) => {
                write!(
                    formatter,
                    "risk contribution {id} rationale contains a credential marker"
                )
            }
            Self::Overflow => formatter.write_str("risk contribution total overflowed u64"),
            Self::ScoreMismatch { declared, computed } => {
                write!(
                    formatter,
                    "risk score {declared} does not equal contribution total {computed}"
                )
            }
            Self::ConflictingContribution(id) => {
                write!(formatter, "conflicting risk contribution {id}")
            }
            Self::NonCanonicalContributions => {
                formatter.write_str("risk contributions are not in canonical order")
            }
            Self::InvalidRuleId(id) => write!(formatter, "rule id {id} is not canonical"),
            Self::ContributionTypeNotAllowed {
                event_type,
                id,
                contribution_type,
            } => write!(
                formatter,
                "risk contribution {id} of type {contribution_type:?} is not allowed on {event_type} events"
            ),
            Self::ContributionRuleIdMissing(id) => {
                write!(formatter, "risk contribution {id} is missing from rule_ids")
            }
            Self::EmptyEventField { event_type, field } => {
                write!(
                    formatter,
                    "{event_type} event field {field} must not be empty"
                )
            }
            Self::InvalidEventValue { event_type, field } => {
                write!(
                    formatter,
                    "{event_type} event field {field} has an invalid value"
                )
            }
            Self::InvalidCorrelationCardinality { actual } => write!(
                formatter,
                "correlation event requires at least two distinct sessions, got {actual}"
            ),
            Self::DuplicateCorrelationValue { field } => {
                write!(formatter, "correlation event contains duplicate {field}")
            }
        }
    }
}

impl std::error::Error for RiskAccountingError {}

impl RiskContribution {
    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn contribution_type(&self) -> RiskContributionType {
        self.contribution_type
    }

    pub fn points(&self) -> u64 {
        self.points
    }

    pub fn rationale(&self) -> &str {
        &self.rationale
    }

    /// Keep rule/config rationale useful while applying the terminal emitted-
    /// text privacy policy. Event serialization is the only caller.
    pub(crate) fn for_emission(mut self) -> Self {
        self.id = crate::event::terminal_rule_identifier(&self.id);
        self.rationale = Self::emitted_rationale(&self.rationale);
        self
    }

    pub(crate) fn emitted_rationale(rationale: &str) -> String {
        let sanitized = crate::event::PrivacySanitizer::sanitize(
            crate::event::SanitizationContext::Summary,
            rationale,
        );
        // Rationale has a schema-constrained safe-text grammar. Preserve that
        // established representation after terminal sanitization.
        normalize_risk_rationale(&sanitized)
    }

    pub fn new(
        id: impl Into<String>,
        contribution_type: RiskContributionType,
        points: u64,
        rationale: impl Into<String>,
    ) -> Result<Self, RiskAccountingError> {
        let id = id.into();
        let raw_rationale = rationale.into();
        if crate::event::contains_high_confidence_credential_marker(&raw_rationale) {
            return Err(RiskAccountingError::UnsafeRationale(id));
        }
        let rationale = crate::event::redact_sensitive_text(&raw_rationale);
        let rationale = normalize_risk_rationale(&rationale);
        let contribution = Self {
            id,
            contribution_type,
            points,
            rationale,
        };
        contribution.validate()?;
        Ok(contribution)
    }

    pub fn validate(&self) -> Result<(), RiskAccountingError> {
        if self.id.trim().is_empty() {
            return Err(RiskAccountingError::EmptyContributionId);
        }
        if !is_canonical_contribution_id(&self.id)
            || crate::event::contains_credential_material(&self.id)
        {
            return Err(RiskAccountingError::InvalidContributionId(self.id.clone()));
        }
        if self.points == 0 {
            return Err(RiskAccountingError::NonPositiveContribution(
                self.id.clone(),
            ));
        }
        if self.rationale.len() > MAX_RISK_RATIONALE_LENGTH {
            return Err(RiskAccountingError::RationaleTooLong(self.id.clone()));
        }
        if self.rationale.chars().any(char::is_control) {
            return Err(RiskAccountingError::RationaleContainsControlCharacter(
                self.id.clone(),
            ));
        }
        if crate::event::contains_high_confidence_credential_marker(&self.rationale) {
            return Err(RiskAccountingError::UnsafeRationale(self.id.clone()));
        }
        if !self
            .rationale
            .chars()
            .next()
            .is_some_and(|character| character.is_ascii_alphanumeric())
            || self.rationale.chars().any(|character| {
                !character.is_ascii_alphanumeric()
                    && !matches!(
                        character,
                        ' ' | ',' | '_' | ';' | ':' | '\'' | '(' | ')' | '-'
                    )
            })
        {
            return Err(RiskAccountingError::InvalidRationale(self.id.clone()));
        }
        Ok(())
    }
}

pub fn is_canonical_contribution_id(id: &str) -> bool {
    if !(1..=96).contains(&id.len()) || !id.is_ascii() {
        return false;
    }
    let mut components = id.split('.');
    let Some(first) = components.next() else {
        return false;
    };
    if first.is_empty()
        || !first
            .chars()
            .next()
            .is_some_and(|character| character.is_ascii_lowercase())
        || !first.chars().all(|character| {
            character.is_ascii_lowercase() || character.is_ascii_digit() || character == '_'
        })
    {
        return false;
    }
    let mut has_suffix = false;
    for component in components {
        if component.is_empty()
            || !component.chars().all(|character| {
                character.is_ascii_lowercase() || character.is_ascii_digit() || character == '_'
            })
        {
            return false;
        }
        has_suffix = true;
    }
    has_suffix
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RiskContributionWire {
    id: String,
    #[serde(rename = "type")]
    contribution_type: RiskContributionType,
    points: u64,
    rationale: String,
}

impl TryFrom<RiskContributionWire> for RiskContribution {
    type Error = RiskAccountingError;

    fn try_from(wire: RiskContributionWire) -> Result<Self, Self::Error> {
        let contribution = Self {
            id: wire.id,
            contribution_type: wire.contribution_type,
            points: wire.points,
            rationale: wire.rationale,
        };
        contribution.validate()?;
        Ok(contribution)
    }
}

pub fn checked_risk_sum(contributions: &[RiskContribution]) -> Result<u64, RiskAccountingError> {
    contributions.iter().try_fold(0_u64, |total, contribution| {
        contribution.validate()?;
        total
            .checked_add(contribution.points())
            .ok_or(RiskAccountingError::Overflow)
    })
}

pub fn canonicalize_contributions(
    contributions: Vec<RiskContribution>,
) -> Result<Vec<RiskContribution>, RiskAccountingError> {
    let mut canonical = BTreeMap::new();
    for contribution in contributions {
        contribution.validate()?;
        let key = (
            contribution.contribution_type(),
            contribution.id().to_string(),
        );
        if let Some(existing) = canonical.get(&key) {
            if existing != &contribution {
                return Err(RiskAccountingError::ConflictingContribution(
                    contribution.id().to_string(),
                ));
            }
        } else {
            canonical.insert(key, contribution);
        }
    }
    let canonical = canonical.into_values().collect::<Vec<_>>();
    checked_risk_sum(&canonical)?;
    Ok(canonical)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct RiskThresholds {
    pub low: u32,
    pub medium: u32,
    pub high: u32,
    pub critical: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RiskSeverity {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

impl RiskSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            RiskSeverity::Informational => "informational",
            RiskSeverity::Low => "low",
            RiskSeverity::Medium => "medium",
            RiskSeverity::High => "high",
            RiskSeverity::Critical => "critical",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RiskAssessment {
    pub severity: RiskSeverity,
    pub high_required: bool,
    pub critical_required: bool,
}

pub fn assess_risk_with_thresholds(score: u64, thresholds: RiskThresholds) -> RiskAssessment {
    let severity = if score >= u64::from(thresholds.critical) {
        RiskSeverity::Critical
    } else if score >= u64::from(thresholds.high) {
        RiskSeverity::High
    } else if score >= u64::from(thresholds.medium) {
        RiskSeverity::Medium
    } else if score >= u64::from(thresholds.low) {
        RiskSeverity::Low
    } else {
        RiskSeverity::Informational
    };

    RiskAssessment {
        severity,
        high_required: score >= u64::from(thresholds.high),
        critical_required: score >= u64::from(thresholds.critical),
    }
}

pub fn load_thresholds() -> RiskThresholds {
    load_thresholds_with(|name| env::var(name).ok())
}

fn load_thresholds_with(get: impl Fn(&str) -> Option<String>) -> RiskThresholds {
    RiskThresholds {
        low: read_threshold("TELLTALE_RISK_THRESHOLD_LOW", 20, &get),
        medium: read_threshold("TELLTALE_RISK_THRESHOLD_MEDIUM", 50, &get),
        high: read_threshold("TELLTALE_RISK_THRESHOLD_HIGH", 70, &get),
        critical: read_threshold("TELLTALE_RISK_THRESHOLD_CRITICAL", 90, &get),
    }
}

fn read_threshold(name: &str, default: u32, get: &impl Fn(&str) -> Option<String>) -> u32 {
    get(name)
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(default)
}

#[cfg(test)]
mod tests {
    use super::{
        MAX_RISK_RATIONALE_LENGTH, RiskAccountingError, RiskContribution, RiskContributionType,
        RiskSeverity, RiskThresholds, assess_risk_with_thresholds, canonicalize_contributions,
        checked_risk_sum, is_canonical_contribution_id, load_thresholds_with,
    };

    #[test]
    fn maps_scores_to_expected_severity_bands() {
        let thresholds = RiskThresholds {
            low: 20,
            medium: 50,
            high: 70,
            critical: 90,
        };

        for (score, expected) in [
            (19, RiskSeverity::Informational),
            (20, RiskSeverity::Low),
            (49, RiskSeverity::Low),
            (50, RiskSeverity::Medium),
            (69, RiskSeverity::Medium),
            (70, RiskSeverity::High),
            (89, RiskSeverity::High),
            (90, RiskSeverity::Critical),
        ] {
            assert_eq!(
                assess_risk_with_thresholds(score, thresholds).severity,
                expected
            );
        }
    }

    #[test]
    fn maps_scores_to_configured_low_and_medium_thresholds() {
        let thresholds = RiskThresholds {
            low: 10,
            medium: 30,
            high: 70,
            critical: 90,
        };

        assert_eq!(
            assess_risk_with_thresholds(9, thresholds).severity,
            RiskSeverity::Informational
        );
        assert_eq!(
            assess_risk_with_thresholds(10, thresholds).severity,
            RiskSeverity::Low
        );
        assert_eq!(
            assess_risk_with_thresholds(30, thresholds).severity,
            RiskSeverity::Medium
        );
    }

    #[test]
    fn only_canonical_threshold_names_control_native_scores() {
        let canonical_names =
            load_thresholds_with(|name| name.starts_with("TELLTALE_").then(|| "1".to_string()));
        assert_eq!(
            canonical_names,
            RiskThresholds {
                low: 1,
                medium: 1,
                high: 1,
                critical: 1,
            }
        );

        let custom_telltale_names = load_thresholds_with(|name| {
            Some(
                match name {
                    "TELLTALE_RISK_THRESHOLD_LOW" => "11",
                    "TELLTALE_RISK_THRESHOLD_MEDIUM" => "22",
                    "TELLTALE_RISK_THRESHOLD_HIGH" => "33",
                    "TELLTALE_RISK_THRESHOLD_CRITICAL" => "44",
                    _ => return None,
                }
                .to_string(),
            )
        });
        assert_eq!(
            custom_telltale_names,
            RiskThresholds {
                low: 11,
                medium: 22,
                high: 33,
                critical: 44,
            }
        );
    }

    #[test]
    fn contribution_serialization_uses_closed_canonical_fields() {
        let contribution = RiskContribution::new(
            "rule.secret",
            RiskContributionType::DeterministicRule,
            4_294_967_296,
            "matched a synthetic secret path",
        )
        .expect("valid contribution");
        assert_eq!(
            serde_json::to_value(contribution).expect("serialize contribution"),
            serde_json::json!({
                "id": "rule.secret",
                "type": "deterministic_rule",
                "points": 4294967296_u64,
                "rationale": "matched a synthetic secret path"
            })
        );
    }

    #[test]
    fn risk_sum_is_checked_and_supports_values_above_u32() {
        let contributions = vec![
            RiskContribution::new(
                "rule.a",
                RiskContributionType::DeterministicRule,
                u64::MAX - 1,
                "a",
            )
            .expect("valid contribution"),
            RiskContribution::new("chain.b", RiskContributionType::ChainModifier, 1, "b")
                .expect("valid contribution"),
        ];
        assert_eq!(checked_risk_sum(&contributions), Ok(u64::MAX));
        let overflow = RiskContribution::new(
            "baseline.c",
            RiskContributionType::BaselineDeviation,
            2,
            "c",
        )
        .expect("valid contribution");
        assert!(matches!(
            checked_risk_sum(&[contributions[0].clone(), overflow]),
            Err(super::RiskAccountingError::Overflow)
        ));
    }

    #[test]
    fn contribution_deserialization_rejects_non_positive_points() {
        let result = serde_json::from_value::<RiskContribution>(serde_json::json!({
            "id": "rule.zero",
            "type": "deterministic_rule",
            "points": 0,
            "rationale": "zero"
        }));
        assert!(result.is_err());
    }

    #[test]
    fn canonicalization_sorts_and_collapses_exact_duplicates() {
        let first =
            RiskContribution::new("rule.z", RiskContributionType::DeterministicRule, 3, "z")
                .expect("contribution");
        let second = RiskContribution::new("chain.a", RiskContributionType::ChainModifier, 4, "a")
            .expect("contribution");
        let canonical =
            canonicalize_contributions(vec![first.clone(), second.clone(), first.clone()])
                .expect("canonical contributions");
        assert_eq!(canonical.len(), 2);
        assert_eq!(canonical[0], first);
        assert_eq!(canonical[1], second);
        assert_eq!(checked_risk_sum(&canonical), Ok(7));
    }

    #[test]
    fn canonicalization_rejects_conflicts_and_overflow() {
        let make = |points, rationale| {
            RiskContribution::new(
                "rule.same",
                RiskContributionType::DeterministicRule,
                points,
                rationale,
            )
            .expect("contribution")
        };
        assert!(matches!(
            canonicalize_contributions(vec![make(1, "one"), make(2, "two")]),
            Err(RiskAccountingError::ConflictingContribution(id)) if id == "rule.same"
        ));
        let max = RiskContribution::new(
            "rule.max",
            RiskContributionType::DeterministicRule,
            u64::MAX,
            "max",
        )
        .expect("contribution");
        let one = RiskContribution::new(
            "rule.one",
            RiskContributionType::DeterministicRule,
            1,
            "one",
        )
        .expect("contribution");
        assert!(matches!(
            canonicalize_contributions(vec![one, max]),
            Err(RiskAccountingError::Overflow)
        ));
    }

    #[test]
    fn rationale_normalization_matches_manifest_safe_text() {
        let contribution = RiskContribution::new(
            "rule.safe",
            RiskContributionType::DeterministicRule,
            1,
            "  .secret/path @ value;  ",
        )
        .expect("valid contribution");
        assert_eq!(contribution.rationale(), "secret path value;");
        assert!(contribution.rationale().len() <= MAX_RISK_RATIONALE_LENGTH);
        assert!(contribution.rationale().chars().all(|character| {
            character.is_ascii_alphanumeric()
                || matches!(
                    character,
                    ' ' | ',' | '_' | ';' | ':' | '\'' | '(' | ')' | '-'
                )
        }));
    }

    #[test]
    fn rationale_normalization_never_exceeds_manifest_limit() {
        let raw = format!("{} /x", "a".repeat(MAX_RISK_RATIONALE_LENGTH - 2));
        let contribution = RiskContribution::new(
            "rule.bounded",
            RiskContributionType::DeterministicRule,
            1,
            raw,
        )
        .expect("bounded contribution");

        assert!(contribution.rationale().len() <= MAX_RISK_RATIONALE_LENGTH);
    }

    #[test]
    fn contribution_deserialization_rejects_noncanonical_rationale() {
        let result = serde_json::from_value::<RiskContribution>(serde_json::json!({
            "id": "rule.invalid",
            "type": "deterministic_rule",
            "points": 1,
            "rationale": "invalid/path"
        }));

        assert!(result.is_err());
    }

    #[test]
    fn contribution_ids_and_deserialized_markers_are_rejected() {
        assert!(is_canonical_contribution_id("rule.valid_id"));
        for id in [
            "rule",
            "Rule.invalid",
            "1rule.invalid",
            "rule..invalid",
            "rule.invalid/extra",
        ] {
            assert!(
                !is_canonical_contribution_id(id),
                "unexpected valid id: {id}"
            );
        }
        assert!(!is_canonical_contribution_id(&format!(
            "rule.{}",
            "x".repeat(96)
        )));

        let constructor = RiskContribution::new(
            "rule.marker",
            RiskContributionType::DeterministicRule,
            1,
            "ghp_12345678901234567890",
        )
        .expect_err("constructor must reject marker before redaction");
        assert!(!constructor.to_string().contains("ghp_"));
        let imported = serde_json::from_value::<RiskContribution>(serde_json::json!({
            "id": "rule.marker",
            "type": "deterministic_rule",
            "points": 1,
            "rationale": "ghp_12345678901234567890"
        }));
        assert!(imported.is_err());
    }

    #[test]
    fn exact_credential_markers_are_rejected_by_constructor_and_deserialization() {
        for (index, marker) in [
            "GhP_12345678",
            "SK-abcdefgh",
            "akia1234567890ab",
            "XoXb-12345678",
            "eYj_12345678.segment_5678.segment_9012",
            "-----begin openssh private key-----",
        ]
        .into_iter()
        .enumerate()
        {
            let raw_rationale = format!("prefix {marker} suffix");
            let constructor = RiskContribution::new(
                format!("rule.marker_{index}"),
                RiskContributionType::DeterministicRule,
                1,
                &raw_rationale,
            );
            let error = constructor.expect_err("constructor accepted embedded marker");
            assert!(!error.to_string().contains(marker));
            let imported = serde_json::from_value::<RiskContribution>(serde_json::json!({
                "id": format!("rule.imported_{index}"),
                "type": "deterministic_rule",
                "points": 1,
                "rationale": raw_rationale,
            }));
            assert!(
                imported.is_err(),
                "deserialization accepted marker: {marker}"
            );
        }
    }

    #[test]
    fn credential_marker_near_misses_remain_valid_safe_text() {
        for (index, rationale) in [
            "ghp_1234567",
            "sk-1234567",
            "AKIA1234567890A",
            "xoxb-1234567",
            "segment_1234.segment_5678.segment_9012",
            "-----BEGIN OPENSSH PUBLIC KEY-----",
        ]
        .into_iter()
        .enumerate()
        {
            let contribution = RiskContribution::new(
                format!("rule.near_miss_{index}"),
                RiskContributionType::DeterministicRule,
                1,
                rationale,
            )
            .expect("near miss should remain valid");
            assert!(!contribution.rationale().is_empty());
        }
    }
}
