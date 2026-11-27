//! Event 3.0 risk accounting: risk contributions, their checked sum, and the
//! severity thresholds. This is Event3 compatibility scoring; Detection v2 has
//! no aggregate risk model.

use std::collections::BTreeMap;
use std::sync::OnceLock;

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

    pub(crate) fn canonical_key(&self) -> (RiskContributionType, &str) {
        (self.contribution_type, &self.id)
    }

    /// Keep rule/config rationale useful while applying the terminal emitted-
    /// text privacy policy. Event serialization is the only caller.
    pub(crate) fn for_emission(mut self) -> Self {
        self.id = crate::event::terminal_rule_identifier(&self.id);
        self.rationale = Self::emitted_rationale(&self.rationale);
        self
    }

    pub(crate) fn for_historical_emission(mut self) -> Self {
        self.id = crate::event::terminal_historical_rule_identifier(&self.id);
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
        self.validate_with_rule_id(crate::event::is_native_rule_identifier)
    }

    pub(crate) fn validate_terminal(&self) -> Result<(), RiskAccountingError> {
        self.validate_with_rule_id(crate::event::is_terminal_rule_identifier)
    }

    fn validate_with_rule_id(&self, valid_id: fn(&str) -> bool) -> Result<(), RiskAccountingError> {
        if self.id.trim().is_empty() {
            return Err(RiskAccountingError::EmptyContributionId);
        }
        if !valid_id(&self.id) {
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
        // Native callers deserialize through this path. Historical Event 3
        // readback must use [`historical_risk_contribution`] instead.
        Self::from_wire(wire, Self::validate)
    }
}

impl RiskContribution {
    fn from_wire(
        wire: RiskContributionWire,
        validate: fn(&Self) -> Result<(), RiskAccountingError>,
    ) -> Result<Self, RiskAccountingError> {
        let contribution = Self {
            id: wire.id,
            contribution_type: wire.contribution_type,
            points: wire.points,
            rationale: wire.rationale,
        };
        validate(&contribution)?;
        Ok(contribution)
    }
}

/// Read one contribution from terminal Event 3 JSON.
///
/// A `redacted.<64 lowercase hex>` ID is recognized as historical syntax only.
/// It is not native admission; [`TryFrom`] for [`RiskContribution`] stays strict.
pub fn historical_risk_contribution(
    value: &serde_json::Value,
) -> Result<RiskContribution, RiskAccountingError> {
    let wire = serde_json::from_value::<RiskContributionWire>(value.clone())
        .map_err(|_| RiskAccountingError::InvalidContributionId("historical-wire".to_string()))?;
    RiskContribution::from_wire(wire, RiskContribution::validate_terminal)
}

pub fn checked_risk_sum(contributions: &[RiskContribution]) -> Result<u64, RiskAccountingError> {
    checked_risk_sum_with(contributions, RiskContribution::validate)
}

pub(crate) fn checked_terminal_risk_sum(
    contributions: &[RiskContribution],
) -> Result<u64, RiskAccountingError> {
    checked_risk_sum_with(contributions, RiskContribution::validate_terminal)
}

fn checked_risk_sum_with(
    contributions: &[RiskContribution],
    validate: fn(&RiskContribution) -> Result<(), RiskAccountingError>,
) -> Result<u64, RiskAccountingError> {
    contributions.iter().try_fold(0_u64, |total, contribution| {
        validate(contribution)?;
        total
            .checked_add(contribution.points())
            .ok_or(RiskAccountingError::Overflow)
    })
}

pub fn canonicalize_contributions(
    contributions: Vec<RiskContribution>,
) -> Result<Vec<RiskContribution>, RiskAccountingError> {
    canonicalize_contributions_with(contributions, RiskContribution::validate)
}

pub(crate) fn canonicalize_terminal_contributions(
    contributions: Vec<RiskContribution>,
) -> Result<Vec<RiskContribution>, RiskAccountingError> {
    canonicalize_contributions_with(contributions, RiskContribution::validate_terminal)
}

fn canonicalize_contributions_with(
    contributions: Vec<RiskContribution>,
    validate: fn(&RiskContribution) -> Result<(), RiskAccountingError>,
) -> Result<Vec<RiskContribution>, RiskAccountingError> {
    let mut canonical = BTreeMap::new();
    for contribution in contributions {
        validate(&contribution)?;
        let (kind, id) = contribution.canonical_key();
        let key = (kind, id.to_string());
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
    checked_risk_sum_with(&canonical, validate)?;
    Ok(canonical)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct RiskThresholds {
    pub low: u32,
    pub medium: u32,
    pub high: u32,
    pub critical: u32,
}

impl Default for RiskThresholds {
    fn default() -> Self {
        Self {
            low: 20,
            medium: 50,
            high: 70,
            critical: 90,
        }
    }
}

/// A process already runs with different configured thresholds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThresholdsAlreadyConfigured;

impl std::fmt::Display for ThresholdsAlreadyConfigured {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("risk thresholds are already configured with different values")
    }
}

impl std::error::Error for ThresholdsAlreadyConfigured {}

static CONFIGURED_THRESHOLDS: OnceLock<RiskThresholds> = OnceLock::new();

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

/// Fix this process's Event 3 severity thresholds before any event is built.
///
/// The library never reads the environment: a host that resolves operator
/// settings configures them here once, and an unconfigured process uses
/// [`RiskThresholds::default`]. Repeating the same values is accepted.
pub fn configure_thresholds(thresholds: RiskThresholds) -> Result<(), ThresholdsAlreadyConfigured> {
    if *CONFIGURED_THRESHOLDS.get_or_init(|| thresholds) == thresholds {
        Ok(())
    } else {
        Err(ThresholdsAlreadyConfigured)
    }
}

/// The thresholds every Event 3 constructor in this process uses.
pub fn load_thresholds() -> RiskThresholds {
    CONFIGURED_THRESHOLDS.get().copied().unwrap_or_default()
}

#[cfg(test)]
mod tests;
