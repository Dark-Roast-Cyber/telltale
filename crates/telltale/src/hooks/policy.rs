//! Host promotion policy: turns Telltale action scores plus session history
//! into a verdict. Telltale decides what was detected; this decides what to do.

use serde::Serialize;

use crate::hooks::config::Thresholds;
use crate::hooks::state::Verdict;

/// Why a verdict was reached. Stable snake_case labels for telemetry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Basis {
    /// No Telltale action was anchored at this call.
    NoFinding,
    /// Scored, but below every threshold.
    BelowThreshold,
    ActionScore,
    SessionScore,
    RepeatedDenials,
    /// The hook could not evaluate (infrastructure failure); `on_error` applied.
    EvaluationGap,
    /// The tool input could not be fully evaluated; `on_unevaluable` applied.
    UnevaluableInput,
}

impl Basis {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NoFinding => "no_finding",
            Self::BelowThreshold => "below_threshold",
            Self::ActionScore => "action_score",
            Self::SessionScore => "session_score",
            Self::RepeatedDenials => "repeated_denials",
            Self::EvaluationGap => "evaluation_gap",
            Self::UnevaluableInput => "unevaluable_input",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Inputs {
    /// Highest Telltale promotion score among actions anchored at this call.
    pub action_score: u64,
    /// Cumulative session score before this call.
    pub session_score: u64,
    /// Denied attempts earlier in this session.
    pub denied_attempts: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Outcome {
    pub verdict: Verdict,
    pub basis: Basis,
    /// Session score including this call.
    pub session_score_after: u64,
}

/// Escalation ladder. Unscored calls are always allowed: session history
/// raises scrutiny of risky calls, it never blocks benign ones.
pub fn decide(inputs: Inputs, thresholds: &Thresholds) -> Outcome {
    let after = inputs.session_score.saturating_add(inputs.action_score);
    let outcome = |verdict, basis| Outcome {
        verdict,
        basis,
        session_score_after: after,
    };
    if inputs.action_score == 0 {
        return outcome(Verdict::Allow, Basis::NoFinding);
    }
    if inputs.action_score >= thresholds.action_deny {
        return outcome(Verdict::Deny, Basis::ActionScore);
    }
    if thresholds.repeated_denials > 0 && inputs.denied_attempts >= thresholds.repeated_denials {
        return outcome(Verdict::Deny, Basis::RepeatedDenials);
    }
    if after >= thresholds.session_deny {
        return outcome(Verdict::Deny, Basis::SessionScore);
    }
    if inputs.action_score >= thresholds.action_ask {
        return outcome(Verdict::Ask, Basis::ActionScore);
    }
    if after >= thresholds.session_ask {
        return outcome(Verdict::Ask, Basis::SessionScore);
    }
    outcome(Verdict::Allow, Basis::BelowThreshold)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(action_score: u64, session_score: u64, denied_attempts: u32) -> (Verdict, Basis) {
        let outcome = decide(
            Inputs {
                action_score,
                session_score,
                denied_attempts,
            },
            &Thresholds::default(),
        );
        (outcome.verdict, outcome.basis)
    }

    #[test]
    fn unscored_calls_are_allowed_even_in_hot_sessions() {
        assert_eq!(run(0, 10_000, 99), (Verdict::Allow, Basis::NoFinding));
    }

    #[test]
    fn action_thresholds() {
        assert_eq!(run(20, 0, 0), (Verdict::Allow, Basis::BelowThreshold));
        assert_eq!(run(50, 0, 0), (Verdict::Ask, Basis::ActionScore));
        assert_eq!(run(90, 0, 0), (Verdict::Deny, Basis::ActionScore));
        assert_eq!(run(115, 0, 0), (Verdict::Deny, Basis::ActionScore));
    }

    #[test]
    fn cumulative_session_risk_escalates_low_actions() {
        // Individually low (20) actions: ask once the session reaches 150, deny at 300.
        assert_eq!(run(20, 120, 0), (Verdict::Allow, Basis::BelowThreshold));
        assert_eq!(run(20, 130, 0), (Verdict::Ask, Basis::SessionScore));
        assert_eq!(run(20, 280, 0), (Verdict::Deny, Basis::SessionScore));
    }

    #[test]
    fn repeated_denials_harden_the_session() {
        assert_eq!(run(20, 0, 2), (Verdict::Allow, Basis::BelowThreshold));
        assert_eq!(run(20, 0, 3), (Verdict::Deny, Basis::RepeatedDenials));
    }
}
