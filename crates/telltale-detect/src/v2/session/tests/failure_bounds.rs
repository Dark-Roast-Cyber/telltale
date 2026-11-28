use super::*;

#[test]
fn errors_are_bounded_and_do_not_contain_source_data() {
    for error in [
        ProcessingError::InvalidSource,
        ProcessingError::Evaluation,
        ProcessingError::Projection,
        ProcessingError::Bounds,
    ] {
        assert!(error.to_string().len() < 64);
        assert!(format!("{error:?}").len() < 64);
    }
}

#[test]
fn long_message_suffix_matches_with_full_hash_and_safe_bounded_evidence() {
    let text = format!(
        "{}needle api_key=SYNTHETIC-LONG-SECRET",
        "ordinary ".repeat(1_000)
    );
    let observations = [message(
        "suffix",
        Some("session"),
        &text,
        CapabilityAvailability::Supported,
    )];
    let evaluation = evaluate(&observations, &plan(0)).unwrap();
    assert_eq!(
        evaluation.sessions()[0].detectors()[0].evaluated_match_count(),
        1
    );
    let projected = super::super::super::event3::project_event3(&evaluation, &context()).unwrap();
    let json = serde_json::to_string(&projected.events).unwrap();
    assert!(!json.contains("SYNTHETIC-LONG-SECRET"));
    let evidence = projected.events[0]
        .evidence
        .iter()
        .find(|e| e.field == "user_context")
        .unwrap();
    assert_eq!(
        evidence.hash.as_deref(),
        Some(telltale_schema::event::evidence_hash(&text).as_str())
    );
    assert!(evidence.redacted_value.len() <= 512);
}

#[test]
fn overflow_and_projection_failure_never_return_partial_success() {
    let observations = [message(
        "one",
        Some("session"),
        "needle",
        CapabilityAvailability::Supported,
    )];
    assert!(matches!(
        evaluate(&observations, &plan(u64::MAX)),
        Err(ProcessingError::Evaluation)
    ));
    let observations = [
        message(
            "one",
            Some("session"),
            "needle",
            CapabilityAvailability::Supported,
        ),
        message(
            "unscoped",
            None,
            "needle",
            CapabilityAvailability::Supported,
        ),
    ];
    let evaluation = evaluate(&observations, &plan(0)).unwrap();
    assert!(matches!(
        super::super::super::event3::project_event3(&evaluation, &context()),
        Err(ProcessingError::Projection)
    ));
    let evaluation = evaluate(&observations[..1], &plan(0)).unwrap();
    let invalid = super::super::super::event3::Event3CompatibilityContext {
        source_path_hash: "",
        ..context()
    };
    assert!(matches!(
        super::super::super::event3::project_event3(&evaluation, &invalid),
        Err(ProcessingError::Projection)
    ));
}

#[test]
fn caller_controlled_identity_and_metadata_bounds_fail_without_content_leaks() {
    let marker = "S".repeat(MAX_COMPATIBILITY_STRING_BYTES + 1);
    let instance = CorrelationId::source_reported(&marker).unwrap();
    let observations = [observation("bounded", Some("session"), None, 1)];
    let error = match evaluate_source(
        CanonicalSourceInput {
            client: ClientId::Claude,
            source_id: "claude.projects",
            source_instance: Some(&instance),
            observations: &observations,
        },
        &plan(0),
        None,
    ) {
        Err(error) => error,
        Ok(_) => panic!("oversized source identity accepted"),
    };
    assert_eq!(error, ProcessingError::Bounds);
    assert!(!error.to_string().contains(&marker));
    assert!(!format!("{error:?}").contains(&marker));

    let evaluation = evaluate(
        &[message(
            "metadata-bound",
            Some("session"),
            "needle",
            CapabilityAvailability::Supported,
        )],
        &plan(0),
    )
    .unwrap();
    let session_id = CorrelationId::source_reported("session").unwrap();
    let metadata = [super::super::super::event3::Event3SessionMetadata {
        session_id: &session_id,
        agent: Some(&marker),
        model: None,
        provider: None,
    }];
    let error = match super::super::super::event3::project_event3(
        &evaluation,
        &super::super::super::event3::Event3CompatibilityContext {
            sessions: &metadata,
            ..context()
        },
    ) {
        Err(error) => error,
        Ok(_) => panic!("oversized metadata accepted"),
    };
    assert_eq!(error, ProcessingError::Bounds);
    assert!(!error.to_string().contains(&marker));
    assert!(!format!("{error:?}").contains(&marker));
}

#[test]
fn duplicate_observations_and_mismatched_sources_fail_before_evaluation() {
    let first = observation("one", Some("session"), None, 1);
    assert!(matches!(
        evaluate(&[first.clone(), first.clone()], &plan(0)),
        Err(ProcessingError::DuplicateObservation)
    ));
    let observations = [first];
    assert!(matches!(
        evaluate_source(
            CanonicalSourceInput {
                client: ClientId::Codex,
                source_id: "codex.sessions",
                source_instance: None,
                observations: &observations
            },
            &plan(0),
            None
        ),
        Err(ProcessingError::InvalidSource)
    ));
}
