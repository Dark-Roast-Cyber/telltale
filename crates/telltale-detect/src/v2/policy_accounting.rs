//! Accounting for policy-filtered canonical detection evaluations.

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct PolicyMatchAccounting {
    pub pre_policy_detection_candidate_count: u64,
    pub fully_filtered_detection_candidate_count: u64,
    pub filtered_rule_id_count: u64,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct PolicyMatchAccountingError;

impl std::fmt::Display for PolicyMatchAccountingError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("policy match accounting unavailable")
    }
}

impl std::error::Error for PolicyMatchAccountingError {}
