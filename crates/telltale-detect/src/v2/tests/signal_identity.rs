use super::*;

#[test]
fn identity_and_materialization_never_include_matched_values() {
    let detector = detector(MatcherSpec::contains(
        "message.content",
        JsonValue::string("marker"),
    ));
    let left = detector.evaluate(&message(MessageRole::User, "marker-one", "identity"));
    let right = detector.evaluate(&message(MessageRole::User, "marker-two", "identity"));
    let left_signal = left.signal().expect("signal").expect("match");
    let right_signal = right.signal().expect("signal").expect("match");
    assert_eq!(left_signal.signal_id(), right_signal.signal_id());
    assert!(left_signal.signal_id().starts_with(SIGNAL_ID_PREFIX));
    assert!(!format!("{:?}", left_signal).contains("message.content"));
    let finding = left_signal.finding().expect("finding");
    assert!(finding.finding_id().starts_with(FINDING_ID_PREFIX));
    assert_eq!(finding.signal_ids(), &[left_signal.signal_id().to_owned()]);

    let no_match = detector.evaluate(&message(MessageRole::User, "other", "no-match"));
    assert_eq!(
        no_match.evaluation_status(),
        EvaluationStatus::EvaluatedNoMatch
    );
    assert!(no_match.signal().expect("materialization").is_none());
    assert!(no_match.finding().expect("materialization").is_none());

    let resolution = SelectorRegistry::new()
        .resolve(
            SelectorId::MessageContent,
            &message(MessageRole::User, "synthetic-private-marker", "debug"),
        )
        .unwrap();
    assert!(!format!("{resolution:?}").contains("synthetic-private-marker"));
    let compiled = MatcherSpec::contains(
        "message.content",
        JsonValue::string("synthetic-private-marker"),
    )
    .compile()
    .expect("matcher");
    assert!(!format!("{compiled:?}").contains("synthetic-private-marker"));
}

#[test]
fn signal_identity_includes_every_detector_identity_field() {
    let observation = message(MessageRole::User, "synthetic", "identity-fields");
    let observation_id = ObservationId::new(observation.observation_id()).expect("observation id");
    let make_signal_id = |identity: DetectorIdentity| {
        DetectorResult::evaluated_match(
            identity,
            std::slice::from_ref(&observation_id),
            metadata(FindingKind::Informational, "synthetic"),
        )
        .expect("evaluated match")
        .with_match_surface("structured")
        .expect("match surface")
        .with_matched_selector_paths(vec!["message.content".to_owned()])
        .expect("selector paths")
        .signal()
        .expect("signal")
        .expect("match")
        .signal_id()
        .to_owned()
    };

    let base = make_signal_id(
        DetectorIdentity::new(DetectorKind::ObservationMatch, "synthetic.identity.base")
            .expect("identity"),
    );
    let variants = [
        DetectorIdentity::new(DetectorKind::ObservationMatch, "synthetic.identity.other")
            .expect("identity"),
        DetectorIdentity::new(DetectorKind::ObservationMatch, "synthetic.identity.base")
            .expect("identity")
            .with_version("2")
            .expect("version"),
        DetectorIdentity::new(DetectorKind::ObservationMatch, "synthetic.identity.base")
            .expect("identity")
            .with_engine("synthetic-engine")
            .expect("engine"),
        DetectorIdentity::new(DetectorKind::ObservationMatch, "synthetic.identity.base")
            .expect("identity")
            .with_content_ref("synthetic-content")
            .expect("content ref"),
        DetectorIdentity::new(DetectorKind::ObservationMatch, "synthetic.identity.base")
            .expect("identity")
            .with_rule_version(1)
            .expect("rule version"),
    ];
    for identity in variants {
        assert_ne!(base, make_signal_id(identity));
    }
}

#[test]
fn signal_identity_tuple_includes_kind_and_explicit_optional_nulls() {
    let result = DetectorResult::not_evaluated(
        DetectorIdentity::new(DetectorKind::Sequence, "synthetic.sequence").expect("identity"),
        NonEvaluationReason::IneligibleInput,
        metadata(FindingKind::Informational, "synthetic"),
    )
    .expect("not evaluated");
    let tuple = signal_identity_tuple(&result).expect("identity tuple");
    let JsonValue::Array(fields) = tuple else {
        panic!("signal identity must be an array");
    };
    assert_eq!(fields.len(), 13);
    assert_eq!(fields[0], JsonValue::string("telltale:detection-v2-signal"));
    assert_eq!(fields[1], JsonValue::Unsigned(2));
    assert_eq!(fields[2], JsonValue::string("sequence"));
    assert_eq!(fields[4], JsonValue::Null);
    assert_eq!(fields[5], JsonValue::Null);
    assert_eq!(fields[6], JsonValue::Null);
    assert_eq!(fields[7], JsonValue::Null);
    assert_eq!(fields[8], JsonValue::Null);
    assert_eq!(fields[9], JsonValue::Array(Vec::new()));
    assert_eq!(fields[10], JsonValue::Null);
    assert_eq!(fields[11], JsonValue::string("not_evaluated"));
}

#[test]
fn signal_identity_normalizes_observations_and_selectors_and_finding_identity() {
    let observation_one = message(MessageRole::User, "synthetic", "identity-one");
    let observation_two = message(MessageRole::User, "synthetic", "identity-two");
    let observation_id_one =
        ObservationId::new(observation_one.observation_id()).expect("observation id");
    let observation_id_two =
        ObservationId::new(observation_two.observation_id()).expect("observation id");
    assert_ne!(observation_id_one, observation_id_two);

    let make_result = |observation_ids: &[ObservationId], paths: Vec<&str>| {
        DetectorResult::evaluated_match(
            DetectorIdentity::new(DetectorKind::ObservationMatch, "synthetic.normalized")
                .expect("identity"),
            observation_ids,
            metadata(FindingKind::Informational, "synthetic"),
        )
        .expect("evaluated match")
        .with_match_surface("text")
        .expect("match surface")
        .with_matched_selector_paths(paths.into_iter().map(str::to_owned).collect())
        .expect("selector paths")
    };

    let normalized_ids = [observation_id_two.clone(), observation_id_one.clone()];
    let duplicate_ids = [
        observation_id_one.clone(),
        observation_id_two.clone(),
        observation_id_one.clone(),
    ];
    let base = make_result(&normalized_ids, vec!["message.role", "message.content"]);
    let base_signal = base.signal().expect("signal").expect("match");
    let base_finding = base_signal.finding().expect("finding");

    let reordered = make_result(
        &duplicate_ids,
        vec!["message.content", "message.role", "message.content"],
    );
    let reordered_signal = reordered.signal().expect("signal").expect("match");
    assert_eq!(base_signal.signal_id(), reordered_signal.signal_id());
    assert_eq!(
        base_finding.finding_id(),
        reordered_signal.finding().expect("finding").finding_id()
    );

    let different_observation = make_result(
        std::slice::from_ref(&observation_id_two),
        vec!["message.role", "message.content"],
    );
    assert_ne!(
        base_signal.signal_id(),
        different_observation
            .signal()
            .expect("signal")
            .expect("match")
            .signal_id()
    );

    let different_selector_set = make_result(
        std::slice::from_ref(&observation_id_one),
        vec!["message.content"],
    );
    assert_ne!(
        base_signal.signal_id(),
        different_selector_set
            .signal()
            .expect("signal")
            .expect("match")
            .signal_id()
    );
}

#[test]
fn fixed_identity_vector_matches_architecture_tuple() {
    let observation_one = telltale_schema::observation::ObservationId::new(
        "obs:v2:sha256:1111111111111111111111111111111111111111111111111111111111111111",
    )
    .expect("observation id");
    let observation_two = telltale_schema::observation::ObservationId::new(
        "obs:v2:sha256:2222222222222222222222222222222222222222222222222222222222222222",
    )
    .expect("observation id");
    let identity = DetectorIdentity::new(DetectorKind::ObservationMatch, "synthetic.identity")
        .expect("identity")
        .with_version("2")
        .expect("version");
    let metadata = metadata(FindingKind::SecurityDetection, "synthetic")
        .with_semantic_identity("session:synthetic")
        .expect("semantic identity");
    let result =
        DetectorResult::evaluated_match(identity, &[observation_two, observation_one], metadata)
            .expect("result")
            .with_match_surface("structured")
            .expect("surface")
            .with_matched_selector_paths(vec!["resource.path".to_owned(), "tool.name".to_owned()])
            .expect("paths");
    let signal = result.signal().expect("signal").expect("match");
    assert_eq!(
        signal.signal_id(),
        "sig:v2:sha256:7ec2c26030843a0a829c482344bae3f678f4fe4dcfcc4cbdeba62be0fb119e77",
        "selector digest {}",
        signal.selector_digest()
    );
    assert_eq!(
        signal.finding().expect("finding").finding_id(),
        "fnd:v2:sha256:6323443e36bc349b4ba13471d5c849dcdc8e9ac320364d3fc45d0dc03f08b4d2"
    );
}
