use super::{DetectionError, FindingKind};

pub(super) fn finding_kind_for_detection_class(
    detection_class: &str,
) -> Result<FindingKind, DetectionError> {
    match detection_class {
        "security_detection" => Ok(FindingKind::SecurityDetection),
        "policy_violation" => Ok(FindingKind::PolicyViolation),
        "threat_hunting" => Ok(FindingKind::ThreatHunt),
        "compliance_observation" => Ok(FindingKind::ComplianceObservation),
        "baseline_deviation" => Ok(FindingKind::BehavioralDeviation),
        _ => Err(DetectionError::UnmappableRuleClass),
    }
}
