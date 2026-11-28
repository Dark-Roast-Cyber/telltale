use super::*;

#[test]
fn tool_stage_is_absent_outside_tool_family() {
    let registry = SelectorRegistry::new();
    let selector = SelectorId::parse("tool.stage").expect("selector");
    let tool_observation = tool("synthetic", "tool-stage");
    let tool_resolution = registry.resolve(selector, &tool_observation).unwrap();
    assert_eq!(tool_resolution.presence(), SelectorPresence::Present);
    assert_eq!(
        tool_resolution.value(),
        Some(&JsonValue::string("requested"))
    );
    assert_eq!(
        tool_resolution
            .metadata()
            .expect("derived stage metadata")
            .provenance(),
        FactProvenance::Derived
    );

    let message_observation = message(MessageRole::User, "synthetic", "message-stage");
    let runtime_observation = body_observation(
        ObservationBody::Runtime(
            RuntimeObservation::new()
                .with_state_marker("observed")
                .expect("runtime state"),
        ),
        ObservationStage::RuntimeObserved,
        "runtime-stage",
        &[("runtime.state_marker", FactProvenance::Reported)],
    );
    for observation in [message_observation, runtime_observation] {
        let resolution = registry.resolve(selector, &observation).unwrap();
        assert_eq!(resolution.presence(), SelectorPresence::Absent);
        assert!(resolution.value().is_none());
        assert_eq!(
            matcher_state(MatcherSpec::exists("tool.stage"), &observation),
            MatchState::NoMatch
        );
    }
}

#[test]
fn present_not_exists_is_no_match_after_capability_and_provenance_preflight() {
    let supported = tool("synthetic", "present-not-exists");
    let matcher = MatcherSpec::predicate_with_requirements(
        "tool.name",
        MatcherOperator::NotExists,
        None,
        None,
        Some(CapabilityId::ToolCall),
    );
    assert_eq!(matcher_state(matcher, &supported), MatchState::NoMatch);

    let detector = ObservationMatchSpec::new(
        DetectorIdentity::new(DetectorKind::ObservationMatch, "test.present-not-exists")
            .expect("identity"),
        ObservationFamily::Tool,
        vec![ObservationStage::ToolRequested],
        MatcherSpec::predicate_with_requirements(
            "tool.name",
            MatcherOperator::NotExists,
            None,
            None,
            Some(CapabilityId::ToolCall),
        ),
        metadata(FindingKind::Informational, "synthetic"),
    )
    .compile()
    .expect("detector");
    let unsupported = observation_with_capability(
        &supported,
        CapabilityContext::new()
            .with_override(CapabilityId::ToolCall, CapabilityAvailability::Unsupported),
    );
    let result = detector.evaluate(&unsupported);
    assert_eq!(result.evaluation_status(), EvaluationStatus::NotEvaluated);
    assert_eq!(
        result.non_evaluation_reason(),
        Some(NonEvaluationReason::RequiredCapabilityUnsupported)
    );

    let provenance_mismatch = replace_metadata(&supported, "tool.name", FactProvenance::Parsed);
    let matcher = MatcherSpec::predicate_with_requirements(
        "tool.name",
        MatcherOperator::NotExists,
        None,
        Some(FactProvenance::Observed),
        None,
    );
    assert_eq!(
        matcher_state(matcher, &provenance_mismatch),
        MatchState::NotEvaluated(NonEvaluationReason::IneligibleInput)
    );
}

#[test]
fn capability_preflight_is_explicit_and_result_visibility_is_not_execution_visibility() {
    let matcher = MatcherSpec::equals("compat.v1.tool_name", JsonValue::string("shell"));
    let detector = detector(matcher);
    // The test above uses a supported ToolCall context.  A missing context is
    // the published unknown state; an explicit unsupported override is checked
    // through the direct selector matcher below.
    let no_context = tool("synthetic command", "cap-unknown");
    let (result, signal) = detector.evaluate_to_signal(&no_context);
    assert_eq!(result.evaluation_status(), EvaluationStatus::NotApplicable);
    assert!(signal.is_none());
    let result = detector.evaluate(&no_context);
    assert_eq!(result.evaluation_status(), EvaluationStatus::NotApplicable);

    let result = ObservationMatchSpec::new(
        DetectorIdentity::new(DetectorKind::ObservationMatch, "test.tool").expect("identity"),
        ObservationFamily::Tool,
        vec![ObservationStage::ToolRequested],
        MatcherSpec::equals("compat.v1.tool_name", JsonValue::string("shell")),
        metadata(FindingKind::Informational, "synthetic"),
    )
    .compile()
    .expect("tool detector")
    .evaluate(&no_context);
    assert_eq!(result.evaluation_status(), EvaluationStatus::EvaluatedMatch);

    let result = ObservationMatchSpec::new(
        DetectorIdentity::new(DetectorKind::ObservationMatch, "test.result").expect("identity"),
        ObservationFamily::Tool,
        vec![ObservationStage::ToolRequested],
        MatcherSpec::equals("compat.v1.tool_result", JsonValue::string("synthetic")),
        metadata(FindingKind::Informational, "synthetic"),
    )
    .compile()
    .expect("result detector")
    .evaluate(&no_context);
    assert_eq!(
        result.evaluation_status(),
        EvaluationStatus::EvaluatedNoMatch
    );
}

#[test]
fn missing_context_is_unknown_and_unsupported_is_not_a_no_match() {
    let observation = tool("synthetic", "missing-context");
    let detector = ObservationMatchSpec::new(
        DetectorIdentity::new(DetectorKind::ObservationMatch, "test.capability").expect("identity"),
        ObservationFamily::Tool,
        vec![ObservationStage::ToolRequested],
        MatcherSpec::equals("compat.v1.tool_name", JsonValue::string("shell")),
        metadata(FindingKind::Informational, "synthetic"),
    )
    .compile()
    .expect("detector");
    let result = detector.evaluate(&observation_without_capability(&observation));
    assert_eq!(result.evaluation_status(), EvaluationStatus::NotEvaluated);
    assert_eq!(
        result.non_evaluation_reason(),
        Some(NonEvaluationReason::RequiredCapabilityUnknown)
    );

    let unsupported = observation_with_capability(
        &observation,
        CapabilityContext::new()
            .with_override(CapabilityId::ToolCall, CapabilityAvailability::Unsupported),
    );
    let result = detector.evaluate(&unsupported);
    assert_eq!(result.evaluation_status(), EvaluationStatus::NotEvaluated);
    assert_eq!(
        result.non_evaluation_reason(),
        Some(NonEvaluationReason::RequiredCapabilityUnsupported)
    );
}

#[test]
fn parsed_facts_do_not_satisfy_observed_provenance() {
    let mut observation = tool("synthetic command", "parsed-provenance");
    observation = add_facet(
        observation,
        "command.text",
        "synthetic command",
        FactProvenance::Parsed,
    );
    let matcher = MatcherSpec::predicate_with_requirements(
        "command.text",
        MatcherOperator::Exists,
        None,
        Some(FactProvenance::Observed),
        None,
    );
    let result = ObservationMatchSpec::new(
        DetectorIdentity::new(DetectorKind::ObservationMatch, "test.provenance").expect("identity"),
        ObservationFamily::Tool,
        vec![ObservationStage::ToolRequested],
        matcher,
        metadata(FindingKind::Informational, "synthetic"),
    )
    .compile()
    .expect("detector")
    .evaluate(&observation);
    assert_eq!(result.evaluation_status(), EvaluationStatus::NotEvaluated);
    assert_eq!(
        result.non_evaluation_reason(),
        Some(NonEvaluationReason::IneligibleInput)
    );
}

#[test]
fn boolean_algebra_is_three_state_and_reason_precedence_is_stable() {
    let provenance_mismatch = MatcherSpec::predicate_with_requirements(
        "message.content",
        MatcherOperator::Equals,
        Some(JsonValue::string("different")),
        Some(FactProvenance::Observed),
        None,
    );
    let different = MatcherSpec::equals("message.content", JsonValue::string("different"));
    let all = detector(MatcherSpec::all(vec![
        MatcherSpec::equals("message.content", JsonValue::string("synthetic")),
        different,
    ]));
    let result = all.evaluate(&message(MessageRole::User, "synthetic", "boolean-all"));
    assert_eq!(
        result.evaluation_status(),
        EvaluationStatus::EvaluatedNoMatch
    );

    let any = detector(MatcherSpec::any(vec![provenance_mismatch.clone()]));
    let result = any.evaluate(&replace_metadata(
        &message(MessageRole::User, "synthetic", "boolean-any"),
        "message.content",
        FactProvenance::Parsed,
    ));
    assert_eq!(result.evaluation_status(), EvaluationStatus::NotEvaluated);
    assert_eq!(
        result.non_evaluation_reason(),
        Some(NonEvaluationReason::IneligibleInput)
    );

    let not = detector(MatcherSpec::not(provenance_mismatch));
    let result = not.evaluate(&message(MessageRole::User, "synthetic", "boolean-not"));
    assert_eq!(result.evaluation_status(), EvaluationStatus::NotEvaluated);
    assert_eq!(
        result.non_evaluation_reason(),
        Some(NonEvaluationReason::IneligibleInput)
    );
}

#[test]
fn provenance_mismatch_is_ineligible_for_every_operator() {
    let observation = replace_metadata(
        &message(MessageRole::User, "synthetic", "all-operators"),
        "message.content",
        FactProvenance::Parsed,
    );
    let operators = [
        (
            MatcherOperator::Equals,
            Some(JsonValue::string("synthetic")),
        ),
        (
            MatcherOperator::NotEquals,
            Some(JsonValue::string("different")),
        ),
        (MatcherOperator::Contains, Some(JsonValue::string("synt"))),
        (MatcherOperator::Regex, Some(JsonValue::string("synthetic"))),
        (MatcherOperator::Glob, Some(JsonValue::string("synthetic*"))),
        (MatcherOperator::Exists, None),
        (MatcherOperator::NotExists, None),
        (
            MatcherOperator::In,
            Some(JsonValue::Array(vec![JsonValue::string("synthetic")])),
        ),
        (
            MatcherOperator::NotIn,
            Some(JsonValue::Array(vec![JsonValue::string("different")])),
        ),
        (MatcherOperator::StartsWith, Some(JsonValue::string("synt"))),
        (MatcherOperator::EndsWith, Some(JsonValue::string("etic"))),
        (MatcherOperator::Gt, Some(JsonValue::Integer(1))),
        (MatcherOperator::Gte, Some(JsonValue::Integer(1))),
        (MatcherOperator::Lt, Some(JsonValue::Integer(1))),
        (MatcherOperator::Lte, Some(JsonValue::Integer(1))),
    ];

    for (operator, expected) in operators {
        let matcher = MatcherSpec::predicate_with_requirements(
            "message.content",
            operator,
            expected,
            Some(FactProvenance::Observed),
            None,
        );
        assert_eq!(
            matcher_state(matcher, &observation),
            MatchState::NotEvaluated(NonEvaluationReason::IneligibleInput),
            "{}",
            operator.as_str()
        );
    }
}
