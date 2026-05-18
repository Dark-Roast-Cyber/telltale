use std::env;

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct RiskThresholds {
    pub low: u32,
    pub medium: u32,
    pub triage: u32,
    pub alert: u32,
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
    pub triage_required: bool,
    pub alert_required: bool,
}

pub fn assess_risk_with_thresholds(score: u32, thresholds: RiskThresholds) -> RiskAssessment {
    let severity = if score >= thresholds.alert {
        RiskSeverity::Critical
    } else if score >= thresholds.triage {
        RiskSeverity::High
    } else if score >= thresholds.medium {
        RiskSeverity::Medium
    } else if score >= thresholds.low {
        RiskSeverity::Low
    } else {
        RiskSeverity::Informational
    };

    RiskAssessment {
        severity,
        triage_required: score >= thresholds.triage,
        alert_required: score >= thresholds.alert,
    }
}

pub fn load_thresholds() -> RiskThresholds {
    RiskThresholds {
        low: read_threshold("ADR_RISK_THRESHOLD_LOW", 20),
        medium: read_threshold("ADR_RISK_THRESHOLD_MEDIUM", 50),
        triage: read_threshold("ADR_RISK_THRESHOLD_TRIAGE", 70),
        alert: read_threshold("ADR_RISK_THRESHOLD_ALERT", 90),
    }
}

fn read_threshold(name: &str, default: u32) -> u32 {
    env::var(name)
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(default)
}

#[cfg(test)]
mod tests {
    use super::{RiskSeverity, RiskThresholds, assess_risk_with_thresholds};

    #[test]
    fn maps_scores_to_expected_severity_bands() {
        let thresholds = RiskThresholds {
            low: 20,
            medium: 50,
            triage: 70,
            alert: 90,
        };

        assert_eq!(
            assess_risk_with_thresholds(0, thresholds).severity,
            RiskSeverity::Informational
        );
        assert_eq!(
            assess_risk_with_thresholds(20, thresholds).severity,
            RiskSeverity::Low
        );
        assert_eq!(
            assess_risk_with_thresholds(50, thresholds).severity,
            RiskSeverity::Medium
        );
        assert_eq!(
            assess_risk_with_thresholds(70, thresholds).severity,
            RiskSeverity::High
        );
        assert_eq!(
            assess_risk_with_thresholds(90, thresholds).severity,
            RiskSeverity::Critical
        );
    }

    #[test]
    fn maps_scores_to_configured_low_and_medium_thresholds() {
        let thresholds = RiskThresholds {
            low: 10,
            medium: 30,
            triage: 70,
            alert: 90,
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
}
