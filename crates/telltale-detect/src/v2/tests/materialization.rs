use super::*;

#[test]
fn invalid_matcher_content_is_rejected_before_evaluation() {
    for (name, expected) in [
        ("equals", MatcherOperator::Equals),
        ("not_equals", MatcherOperator::NotEquals),
        ("contains", MatcherOperator::Contains),
        ("regex", MatcherOperator::Regex),
        ("glob", MatcherOperator::Glob),
        ("exists", MatcherOperator::Exists),
        ("not_exists", MatcherOperator::NotExists),
        ("in", MatcherOperator::In),
        ("not_in", MatcherOperator::NotIn),
        ("starts_with", MatcherOperator::StartsWith),
        ("ends_with", MatcherOperator::EndsWith),
        ("gt", MatcherOperator::Gt),
        ("gte", MatcherOperator::Gte),
        ("lt", MatcherOperator::Lt),
        ("lte", MatcherOperator::Lte),
    ] {
        assert_eq!(MatcherOperator::parse(name).expect("operator"), expected);
    }
    assert_eq!(
        MatcherOperator::parse("greater_than").unwrap_err(),
        DetectionError::InvalidOperator
    );
    assert_eq!(
        SelectorId::parse("actor.id").unwrap_err(),
        DetectionError::InvalidSelector
    );
    assert_eq!(
        SelectorId::parse("native.source_field").unwrap_err(),
        DetectionError::InvalidSelector
    );
    assert_eq!(
        MatcherSpec::all(Vec::new()).compile().unwrap_err(),
        DetectionError::EmptyBooleanGroup
    );
    assert!(matches!(
        MatcherSpec::predicate(
            "message.content",
            MatcherOperator::Regex,
            Some(JsonValue::string("[")),
        )
        .compile(),
        Err(DetectionError::InvalidPattern)
    ));
    assert!(matches!(
        MatcherSpec::predicate(
            "message.content",
            MatcherOperator::Glob,
            Some(JsonValue::string("[unterminated")),
        )
        .compile(),
        Err(DetectionError::InvalidPattern)
    ));
    assert!(matches!(
        MatcherSpec::predicate(
            "message.content",
            MatcherOperator::Regex,
            Some(JsonValue::string("x".repeat(MAX_PATTERN_BYTES + 1))),
        )
        .compile(),
        Err(DetectionError::PatternTooLong)
    ));
}

#[test]
fn statuses_and_diagnostics_are_closed_and_materialization_is_gated() {
    assert_eq!(
        [
            EvaluationStatus::EvaluatedMatch,
            EvaluationStatus::EvaluatedNoMatch,
            EvaluationStatus::NotApplicable,
            EvaluationStatus::NotEvaluated,
            EvaluationStatus::DetectorError,
        ]
        .iter()
        .map(|status| status.as_str())
        .collect::<Vec<_>>(),
        vec![
            "evaluated_match",
            "evaluated_no_match",
            "not_applicable",
            "not_evaluated",
            "detector_error",
        ]
    );
    assert_eq!(
        [
            NonEvaluationReason::InsufficientVisibility,
            NonEvaluationReason::RequiredCapabilityUnsupported,
            NonEvaluationReason::RequiredCapabilityUnknown,
            NonEvaluationReason::MissingOrderingField,
            NonEvaluationReason::MissingCorrelationKey,
            NonEvaluationReason::TypeMismatch,
            NonEvaluationReason::IneligibleInput,
        ]
        .iter()
        .map(|reason| reason.as_str())
        .collect::<Vec<_>>(),
        vec![
            "insufficient_visibility",
            "required_capability_unsupported",
            "required_capability_unknown",
            "missing_ordering_field",
            "missing_correlation_key",
            "type_mismatch",
            "ineligible_input",
        ]
    );

    let identity =
        DetectorIdentity::new(DetectorKind::ObservationMatch, "test.status").expect("identity");
    let finding_metadata = metadata(FindingKind::Informational, "synthetic");
    assert_eq!(
        DetectorResult::new(
            identity.clone(),
            EvaluationStatus::NotEvaluated,
            finding_metadata.clone()
        )
        .unwrap_err(),
        DetectionError::InvalidStatus
    );
    assert_eq!(
        DetectorResult::new(
            identity.clone(),
            EvaluationStatus::DetectorError,
            finding_metadata.clone()
        )
        .unwrap_err(),
        DetectionError::InvalidStatus
    );
    let result = DetectorResult::detector_error(
        identity,
        finding_metadata,
        Diagnostic::new(DiagnosticKind::RuntimeDetectorError, "synthetic_failure")
            .expect("diagnostic"),
    )
    .expect("detector error");
    assert!(result.signal().expect("materialization").is_none());
    assert!(result.finding().expect("materialization").is_none());
    assert_eq!(
        result.diagnostics().expect("diagnostic").code(),
        "synthetic_failure"
    );

    let unsupported = DetectorResult::unsupported(
        DetectorIdentity::new(DetectorKind::Sequence, "test.reserved").expect("identity"),
        metadata(FindingKind::Informational, "synthetic"),
    )
    .expect("unsupported result");
    assert_eq!(
        unsupported.evaluation_status(),
        EvaluationStatus::DetectorError
    );
    assert_eq!(
        unsupported.diagnostics().expect("diagnostic").code(),
        "unsupported_detector_kind"
    );
}

#[test]
fn evidence_references_are_typed_safe_handles_and_debug_is_redacted() {
    let secret_marker = "synthetic-secret-marker";
    for representation in [
        EvidenceRepresentation::RedactedExcerpt,
        EvidenceRepresentation::Hash,
        EvidenceRepresentation::Classification,
        EvidenceRepresentation::LocalStructuredValue,
        EvidenceRepresentation::Correlation,
        EvidenceRepresentation::Timeline,
    ] {
        assert!(
            EvidenceRef::new(representation, secret_marker).is_err(),
            "raw marker accepted for {:?}",
            representation
        );
    }
    assert!(EvidenceRef::new(EvidenceRepresentation::Hash, "a".repeat(64)).is_ok());
    assert!(
        EvidenceRef::new(
            EvidenceRepresentation::RedactedExcerpt,
            format!("redacted:{}", "b".repeat(64)),
        )
        .is_ok()
    );
    assert!(EvidenceRef::classification("classification:secret").is_ok());
    assert!(EvidenceRef::timeline("timeline:signal.synthetic").is_ok());
    assert!(EvidenceReference::hash(secret_marker).is_err());
    let classification =
        EvidenceReference::classification(format!("classification:{secret_marker}"))
            .expect("safe classification");
    assert!(!format!("{classification:?}").contains(secret_marker));
    let safe_hash = EvidenceReference::hash("d".repeat(64)).expect("typed hash");
    assert!(EvidenceRef::from_reference(safe_hash).is_ok());

    let local = LocalReference::new("synthetic-local-handle", "identity_key").expect("local ref");
    let local_ref = EvidenceRef::local_structured(&local).expect("local evidence ref");
    assert_eq!(
        local_ref.representation(),
        EvidenceRepresentation::LocalStructuredValue
    );
    let correlation = CorrelationId::source_reported("session:synthetic").expect("correlation");
    let correlation_ref = EvidenceRef::correlation(&correlation).expect("correlation ref");
    assert_eq!(correlation_ref.reference(), "correlation:session:synthetic");

    let observation = message(MessageRole::User, secret_marker, "evidence");
    let observation_id = ObservationId::new(observation.observation_id()).expect("observation id");
    let evidence = EvidenceRef::hash("c".repeat(64))
        .expect("hash ref")
        .with_observation_id(&observation_id)
        .expect("observation ref")
        .with_field("message.content")
        .expect("field ref");
    assert!(!format!("{evidence:?}").contains(secret_marker));

    let finding_metadata =
        FindingMetadata::new(FindingKind::Informational, secret_marker, Severity::Low)
            .expect("metadata")
            .with_semantic_identity(secret_marker)
            .expect("semantic identity")
            .with_evidence_refs(vec![evidence])
            .expect("evidence metadata");
    let result = DetectorResult::evaluated_match(
        DetectorIdentity::new(DetectorKind::ObservationMatch, secret_marker).expect("identity"),
        &[observation_id],
        finding_metadata,
    )
    .expect("evaluated match");
    let signal = result.signal().expect("signal").expect("match");
    let finding = signal.finding().expect("finding");
    for debug in [
        format!("{result:?}"),
        format!("{signal:?}"),
        format!("{finding:?}"),
    ] {
        assert!(
            !debug.contains(secret_marker),
            "debug leaked evidence: {debug}"
        );
    }
}

#[test]
fn evaluated_matches_require_observation_identity_before_materialization() {
    let detector = DetectorIdentity::new(DetectorKind::ObservationMatch, "synthetic.invariant")
        .expect("identity");
    let finding_metadata = metadata(FindingKind::Informational, "synthetic");
    assert_eq!(
        DetectorResult::new(
            detector.clone(),
            EvaluationStatus::EvaluatedMatch,
            finding_metadata.clone(),
        )
        .unwrap_err(),
        DetectionError::MissingObservationId
    );

    let observation = message(MessageRole::User, "synthetic", "invariant");
    let observation_id = ObservationId::new(observation.observation_id()).expect("observation id");
    let result = DetectorResult::evaluated_match(
        detector.clone(),
        std::slice::from_ref(&observation_id),
        finding_metadata.clone(),
    )
    .expect("evaluated match");
    assert!(result.signal().expect("signal").is_some());
    assert!(result.finding().expect("finding").is_some());
    assert_eq!(
        result.with_observation_ids(&[]).unwrap_err(),
        DetectionError::MissingObservationId
    );

    let no_match = DetectorResult::new(
        detector,
        EvaluationStatus::EvaluatedNoMatch,
        finding_metadata,
    )
    .expect("no match");
    assert!(no_match.signal().expect("signal").is_none());
    assert!(no_match.finding().expect("finding").is_none());
}
