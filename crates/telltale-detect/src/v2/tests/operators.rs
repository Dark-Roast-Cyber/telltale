use super::*;

#[test]
fn matcher_implements_all_typed_operators() {
    let observation = tool_with_result(ObservationStage::ToolResultReturned, "operators");
    let string_cases = [
        (MatcherOperator::Equals, JsonValue::string("shell")),
        (MatcherOperator::NotEquals, JsonValue::string("read")),
        (MatcherOperator::Contains, JsonValue::string("hel")),
        (MatcherOperator::Regex, JsonValue::string("^sh")),
        (MatcherOperator::Glob, JsonValue::string("s*ll")),
        (MatcherOperator::StartsWith, JsonValue::string("sh")),
        (MatcherOperator::EndsWith, JsonValue::string("ll")),
    ];
    for (operator, value) in string_cases {
        let matcher = MatcherSpec::predicate("tool.name", operator, Some(value));
        assert_eq!(
            matcher_state(matcher, &observation),
            MatchState::Match,
            "{}",
            operator.as_str()
        );
    }

    assert_eq!(
        matcher_state(MatcherSpec::exists("tool.name"), &observation),
        MatchState::Match
    );
    assert_eq!(
        matcher_state(MatcherSpec::not_exists("resource.path"), &observation),
        MatchState::Match
    );
    assert_eq!(
        matcher_state(
            MatcherSpec::predicate(
                "tool.name",
                MatcherOperator::In,
                Some(JsonValue::Array(vec![
                    JsonValue::string("read"),
                    JsonValue::string("shell")
                ])),
            ),
            &observation,
        ),
        MatchState::Match
    );
    assert_eq!(
        matcher_state(
            MatcherSpec::predicate(
                "tool.name",
                MatcherOperator::NotIn,
                Some(JsonValue::Array(vec![JsonValue::string("read")])),
            ),
            &observation,
        ),
        MatchState::Match
    );

    for (operator, expected) in [
        (MatcherOperator::Gt, false),
        (MatcherOperator::Gte, true),
        (MatcherOperator::Lt, false),
        (MatcherOperator::Lte, true),
    ] {
        assert_eq!(
            matcher_state(
                MatcherSpec::predicate(
                    "tool.result.exit_code",
                    operator,
                    Some(JsonValue::Unsigned(3)),
                ),
                &observation,
            ),
            if expected {
                MatchState::Match
            } else {
                MatchState::NoMatch
            },
            "{}",
            operator.as_str()
        );
    }
    assert_eq!(
        matcher_state(
            MatcherSpec::equals("tool.result.exit_code", JsonValue::Unsigned(3)),
            &observation,
        ),
        MatchState::Match
    );
    assert_eq!(
        matcher_state(
            MatcherSpec::equals("tool.result.is_error", JsonValue::Bool(true)),
            &observation,
        ),
        MatchState::Match
    );
    assert_eq!(
        matcher_state(
            MatcherSpec::predicate(
                "tool.name",
                MatcherOperator::Contains,
                Some(JsonValue::Bool(true)),
            ),
            &observation,
        ),
        MatchState::NotEvaluated(NonEvaluationReason::TypeMismatch)
    );
}

#[test]
fn numeric_matching_is_exact_at_integer_and_float_boundaries() {
    const TWO_TO_53: u64 = 9_007_199_254_740_992;

    let exact = tool_with_result_exit(
        ObservationStage::ToolResultReturned,
        "numeric-exact",
        TWO_TO_53 as i64,
    );
    assert_eq!(
        matcher_state(
            MatcherSpec::equals("tool.exit_code", JsonValue::Number(TWO_TO_53 as f64),),
            &exact,
        ),
        MatchState::Match
    );

    let unsafe_mixed = tool_with_result_exit(
        ObservationStage::ToolResultReturned,
        "numeric-unsafe-mixed",
        (TWO_TO_53 + 1) as i64,
    );
    assert_eq!(
        matcher_state(
            MatcherSpec::equals("tool.exit_code", JsonValue::Number((TWO_TO_53 + 1) as f64),),
            &unsafe_mixed,
        ),
        MatchState::NotEvaluated(NonEvaluationReason::TypeMismatch)
    );

    let signed_min = tool_with_result_exit(
        ObservationStage::ToolResultReturned,
        "numeric-signed-min",
        i64::MIN,
    );
    assert_eq!(
        matcher_state(
            MatcherSpec::equals("tool.exit_code", JsonValue::Number(i64::MIN as f64),),
            &signed_min,
        ),
        MatchState::Match
    );
    let signed_max = tool_with_result_exit(
        ObservationStage::ToolResultReturned,
        "numeric-signed-max",
        i64::MAX,
    );
    assert_eq!(
        matcher_state(
            MatcherSpec::equals("tool.exit_code", JsonValue::Number(i64::MAX as f64),),
            &signed_max,
        ),
        MatchState::NotEvaluated(NonEvaluationReason::TypeMismatch)
    );

    let unsigned_edge = body_observation(
        ObservationBody::Process(
            ProcessObservation::new()
                .with_operation("observe")
                .expect("operation")
                .with_pid(u64::MAX),
        ),
        ObservationStage::ProcessObserved,
        "numeric-unsigned-edge",
        &[
            ("process.operation", FactProvenance::Observed),
            ("process.pid", FactProvenance::Reported),
        ],
    );
    assert_eq!(
        matcher_state(
            MatcherSpec::predicate(
                "process.pid",
                MatcherOperator::Gt,
                Some(JsonValue::Integer(i64::MAX)),
            ),
            &unsigned_edge,
        ),
        MatchState::Match
    );

    let signed_negative = tool_with_result_exit(
        ObservationStage::ToolResultReturned,
        "numeric-signed-negative",
        -1,
    );
    assert_eq!(
        matcher_state(
            MatcherSpec::predicate(
                "tool.exit_code",
                MatcherOperator::Lt,
                Some(JsonValue::Unsigned(0)),
            ),
            &signed_negative,
        ),
        MatchState::Match
    );

    for non_finite in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
        assert_eq!(
            matcher_state(
                MatcherSpec::equals("tool.exit_code", JsonValue::Number(non_finite),),
                &exact,
            ),
            MatchState::NotEvaluated(NonEvaluationReason::TypeMismatch)
        );
    }
}

#[test]
fn missing_and_provenance_mismatch_follow_negative_operator_rules() {
    let observation = tool("synthetic arguments", "missing-fields");
    assert_eq!(
        matcher_state(
            MatcherSpec::equals("resource.path", JsonValue::string("missing")),
            &observation,
        ),
        MatchState::NoMatch
    );
    assert_eq!(
        matcher_state(
            MatcherSpec::predicate(
                "resource.path",
                MatcherOperator::NotEquals,
                Some(JsonValue::string("missing")),
            ),
            &observation,
        ),
        MatchState::NotEvaluated(NonEvaluationReason::IneligibleInput)
    );
    assert_eq!(
        matcher_state(
            MatcherSpec::predicate(
                "command.text",
                MatcherOperator::NotIn,
                Some(JsonValue::Array(vec![JsonValue::string("missing")])),
            ),
            &observation,
        ),
        MatchState::NotEvaluated(NonEvaluationReason::IneligibleInput)
    );
    assert_eq!(
        matcher_state(
            MatcherSpec::predicate_with_requirements(
                "resource.path",
                MatcherOperator::NotExists,
                None,
                Some(FactProvenance::Observed),
                None,
            ),
            &observation,
        ),
        MatchState::Match
    );

    let parsed = add_facet(
        observation,
        "command.text",
        "synthetic parsed command",
        FactProvenance::Parsed,
    );
    let observed_only_exists = MatcherSpec::predicate_with_requirements(
        "command.text",
        MatcherOperator::Exists,
        None,
        Some(FactProvenance::Observed),
        None,
    );
    assert_eq!(
        matcher_state(observed_only_exists, &parsed),
        MatchState::NotEvaluated(NonEvaluationReason::IneligibleInput)
    );
    let observed_only_not_exists = MatcherSpec::predicate_with_requirements(
        "command.text",
        MatcherOperator::NotExists,
        None,
        Some(FactProvenance::Observed),
        None,
    );
    assert_eq!(
        matcher_state(observed_only_not_exists, &parsed),
        MatchState::NotEvaluated(NonEvaluationReason::IneligibleInput)
    );
    let observed_only_not_equals = MatcherSpec::predicate_with_requirements(
        "command.text",
        MatcherOperator::NotEquals,
        Some(JsonValue::string("other")),
        Some(FactProvenance::Observed),
        None,
    );
    assert_eq!(
        matcher_state(observed_only_not_equals, &parsed),
        MatchState::NotEvaluated(NonEvaluationReason::IneligibleInput)
    );
}

#[test]
fn capability_precedence_is_independent_of_boolean_branch_order() {
    let matcher = MatcherSpec::any(vec![
        MatcherSpec::predicate_with_requirements(
            "message.content",
            MatcherOperator::Exists,
            None,
            None,
            Some(CapabilityId::UserContext),
        ),
        MatcherSpec::predicate_with_requirements(
            "tool.name",
            MatcherOperator::Exists,
            None,
            None,
            Some(CapabilityId::ToolCall),
        ),
    ]);
    let compiled = matcher.compile().expect("matcher");
    let observation = observation_with_capability(
        &tool("synthetic", "capability-precedence"),
        CapabilityContext::new()
            .with_override(CapabilityId::ToolCall, CapabilityAvailability::Unsupported),
    );
    assert_eq!(
        compiled.evaluate(&observation).unwrap().state(),
        &MatchState::NotEvaluated(NonEvaluationReason::RequiredCapabilityUnsupported)
    );

    let observation = observation_with_capability(
        &tool("synthetic", "capability-precedence-unknown"),
        CapabilityContext::new()
            .with_override(CapabilityId::ToolCall, CapabilityAvailability::Supported),
    );
    assert_eq!(
        compiled.evaluate(&observation).unwrap().state(),
        &MatchState::NotEvaluated(NonEvaluationReason::RequiredCapabilityUnknown)
    );
}

#[test]
fn recursive_bounds_and_result_metadata_are_enforced() {
    let too_many = MatcherSpec::all(
        (0..=MAX_MATCHER_BRANCHES)
            .map(|_| MatcherSpec::exists("tool.name"))
            .collect(),
    );
    assert_eq!(
        too_many.compile().unwrap_err(),
        DetectionError::BooleanBranchLimit
    );

    let too_many_capabilities = ObservationMatchSpec::new(
        DetectorIdentity::new(DetectorKind::ObservationMatch, "test.capability.bounds")
            .expect("identity"),
        ObservationFamily::Tool,
        vec![ObservationStage::ToolRequested],
        MatcherSpec::exists("tool.name"),
        metadata(FindingKind::Informational, "synthetic"),
    )
    .with_required_capabilities(vec![CapabilityId::ToolCall; MAX_REQUIRED_CAPABILITIES + 1]);
    assert_eq!(
        too_many_capabilities.compile().unwrap_err(),
        DetectionError::InvalidBounds
    );

    assert_eq!(
        Score::new(1.1).unwrap_err(),
        DetectionError::ScoreOutOfRange
    );
    assert_eq!(
        metadata(FindingKind::Informational, "synthetic")
            .with_risk_points(101)
            .unwrap_err(),
        DetectionError::ScoreOutOfRange
    );
    assert!(
        metadata(FindingKind::Informational, "synthetic")
            .with_techniques(["atlas:AML.T0051"])
            .is_ok()
    );
    assert!(
        metadata(FindingKind::Informational, "synthetic")
            .with_techniques(["raw-technique"])
            .is_err()
    );
}
