use telltale_schema::observation::ObservationId;

use super::*;
use crate::v2::{DetectorResult, Diagnostic, DiagnosticKind, FindingKind, NonEvaluationReason};

fn identity() -> DetectorIdentity {
    DetectorIdentity::new(DetectorKind::ObservationMatch, "synthetic.aggregate").unwrap()
}

fn metadata() -> FindingMetadata {
    FindingMetadata::new(FindingKind::SecurityDetection, "synthetic", Severity::Low).unwrap()
}

#[test]
fn detector_session_precedence_retains_counts_and_reasons() {
    let mut aggregate = RuleV1DetectorSessionEvaluation {
        detector_id: "synthetic.aggregate".to_owned(),
        ..RuleV1DetectorSessionEvaluation::default()
    };
    add_detector_result(
        &mut aggregate,
        DetectorResult::new(identity(), EvaluationStatus::NotApplicable, metadata()).unwrap(),
    );
    assert_eq!(aggregate.outcome(), RuleV1DetectorOutcome::NotApplicable);
    add_detector_result(
        &mut aggregate,
        DetectorResult::new(identity(), EvaluationStatus::EvaluatedNoMatch, metadata()).unwrap(),
    );
    assert_eq!(aggregate.outcome(), RuleV1DetectorOutcome::NoMatch);
    for reason in [
        NonEvaluationReason::TypeMismatch,
        NonEvaluationReason::RequiredCapabilityUnknown,
    ] {
        add_detector_result(
            &mut aggregate,
            DetectorResult::not_evaluated(identity(), reason, metadata()).unwrap(),
        );
    }
    assert_eq!(aggregate.outcome(), RuleV1DetectorOutcome::Indeterminate);
    add_detector_result(
        &mut aggregate,
        DetectorResult::detector_error(
            identity(),
            metadata(),
            Diagnostic::new(DiagnosticKind::RuntimeDetectorError, "synthetic_error").unwrap(),
        )
        .unwrap(),
    );
    assert_eq!(aggregate.outcome(), RuleV1DetectorOutcome::Error);
    let observation_id = ObservationId::new(
        "obs:v2:sha256:1111111111111111111111111111111111111111111111111111111111111111",
    )
    .unwrap();
    add_detector_result(
        &mut aggregate,
        DetectorResult::evaluated_match(identity(), &[observation_id], metadata())
            .unwrap()
            .with_matched_selector_paths(vec!["compat.v1.command".to_owned()])
            .unwrap(),
    );

    assert_eq!(aggregate.outcome(), RuleV1DetectorOutcome::Match);
    assert_eq!(aggregate.evaluated_match_count(), 1);
    assert_eq!(aggregate.evaluated_no_match_count(), 1);
    assert_eq!(aggregate.not_evaluated_count(), 2);
    assert_eq!(aggregate.not_applicable_count(), 1);
    assert_eq!(aggregate.detector_error_count(), 1);
    assert_eq!(
        aggregate.non_evaluation_reason_counts(),
        &BTreeMap::from([
            ("required_capability_unknown".to_owned(), 1),
            ("type_mismatch".to_owned(), 1),
        ])
    );
}
