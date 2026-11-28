use super::*;

#[test]
fn action_registry_is_closed_unique_and_type_scoped() {
    assert_eq!(EventAction::ALL.len(), 40);
    let names: BTreeSet<_> = EventAction::ALL
        .iter()
        .map(|action| action.as_str())
        .collect();
    assert_eq!(names.len(), EventAction::ALL.len());
    let schema: Value = serde_json::from_str(EVENT4_SCHEMA).unwrap();
    let schema_names: BTreeSet<_> = schema["properties"]["event_action"]["enum"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap())
        .collect();
    assert_eq!(names, schema_names);

    let mut counts = [0usize; 8];
    for action in EventAction::ALL {
        counts[match action.event_type() {
            EventType::Session => 0,
            EventType::Observation => 1,
            EventType::Finding => 2,
            EventType::Decision => 3,
            EventType::Action => 4,
            EventType::State => 5,
            EventType::Health => 6,
            EventType::Summary => 7,
        }] += 1;
    }
    assert_eq!(counts, [3, 16, 6, 3, 2, 7, 2, 1]);
}

#[test]
fn all_eight_body_families_validate_against_runtime_schema() {
    let mut context = Event4InMemoryContext::new();
    for candidate in [
        session("evt-session"),
        observation("evt-observation"),
        finding("evt-finding"),
        decision("evt-decision"),
        state("evt-state"),
        health("evt-health"),
        summary("evt-summary"),
    ] {
        accept(candidate, &mut context);
    }
    accept(action("evt-action", "evt-decision"), &mut context);
}

#[test]
fn tool_actions_require_their_distinct_observation_stages() {
    let context = Event4InMemoryContext::new();
    for (action, stage) in [
        (EventAction::ToolProposed, ObservationStage::Proposed),
        (EventAction::ToolRequested, ObservationStage::Requested),
        (
            EventAction::ToolExecutionStarted,
            ObservationStage::ExecutionStarted,
        ),
        (
            EventAction::ToolExecutionCompleted,
            ObservationStage::ExecutionCompleted,
        ),
        (
            EventAction::ToolResultReturned,
            ObservationStage::ResultReturned,
        ),
    ] {
        let mut candidate = observation("evt-tool-stage");
        candidate.event_action = action;
        if let EventBody::Observation(body) = &mut candidate.body {
            body.kind = ObservationKind::Tool;
            body.stage = stage;
        }
        assert!(
            validate_terminal(&candidate.materialize(MATERIALIZED), &context).is_ok(),
            "{action:?} / {stage:?}"
        );
    }

    let mut mismatch = observation("evt-tool-mismatch");
    mismatch.event_action = EventAction::ToolRequested;
    if let EventBody::Observation(body) = &mut mismatch.body {
        body.kind = ObservationKind::Tool;
        body.stage = ObservationStage::Proposed;
    }
    assert_eq!(
        validate_terminal(&mismatch.materialize(MATERIALIZED), &context)
            .unwrap_err()
            .code(),
        Event4ValidationCode::ActionSemanticMismatch
    );
}

#[test]
fn schema_rejects_extra_body_alias_and_bad_rfc3339() {
    let event = summary("evt-structural").materialize(MATERIALIZED);
    let mut value = serde_json::to_value(&event).unwrap();
    value.as_object_mut().unwrap().insert(
        "health".to_owned(),
        json!({"component":"x","status":"failed"}),
    );
    assert_eq!(
        validate_event4_structure(&value).unwrap_err().code(),
        Event4ValidationCode::InvalidStructure
    );

    let mut value = serde_json::to_value(&event).unwrap();
    value
        .as_object_mut()
        .unwrap()
        .insert("received_at".to_owned(), json!(OBSERVED));
    assert!(validate_event4_structure(&value).is_err());

    let mut value = serde_json::to_value(&event).unwrap();
    value
        .as_object_mut()
        .unwrap()
        .insert("observed_at".to_owned(), json!("not-a-time"));
    assert!(validate_event4_structure(&value).is_err());

    let mut value = serde_json::to_value(&event).unwrap();
    value.as_object_mut().unwrap().remove("materialized_at");
    assert!(validate_event4_structure(&value).is_err());

    let finding = finding("evt-required").materialize(MATERIALIZED);
    let mut value = serde_json::to_value(&finding).unwrap();
    value.as_object_mut().unwrap().remove("session_id");
    assert!(validate_event4_structure(&value).is_err());
}

#[test]
fn type_action_and_family_semantics_fail_closed() {
    let context = Event4InMemoryContext::new();

    let mut candidate = summary("evt-type");
    candidate.event_type = EventType::Health;
    assert_eq!(
        validate_terminal(&candidate.materialize(MATERIALIZED), &context)
            .unwrap_err()
            .code(),
        Event4ValidationCode::InvalidStructure
    );

    let mut candidate = summary("evt-action-type");
    candidate.event_action = EventAction::HealthFailed;
    assert_eq!(
        validate_terminal(&candidate.materialize(MATERIALIZED), &context)
            .unwrap_err()
            .code(),
        Event4ValidationCode::ActionTypeMismatch
    );

    let mut candidate = observation("evt-stage");
    if let EventBody::Observation(body) = &mut candidate.body {
        body.stage = ObservationStage::Requested;
    }
    assert_eq!(
        validate_terminal(&candidate.materialize(MATERIALIZED), &context)
            .unwrap_err()
            .code(),
        Event4ValidationCode::ActionSemanticMismatch
    );

    let mut candidate = session("evt-lifecycle");
    if let EventBody::Session(body) = &mut candidate.body {
        body.lifecycle = SessionLifecycle::Closed;
    }
    assert!(validate_terminal(&candidate.materialize(MATERIALIZED), &context).is_err());

    let mut candidate = finding("evt-detector");
    if let EventBody::Finding(body) = &mut candidate.body {
        body.detector.kind = DetectorKind::Sequence;
    }
    assert!(validate_terminal(&candidate.materialize(MATERIALIZED), &context).is_err());

    let mut candidate = state("evt-state-kind");
    if let EventBody::State(body) = &mut candidate.body {
        body.kind = StateKind::Policy;
    }
    assert!(validate_terminal(&candidate.materialize(MATERIALIZED), &context).is_err());
}

#[test]
fn identity_contracts_are_distinct_and_canonical_observation_ids_are_reused() {
    let context = Event4InMemoryContext::new();
    let mut candidate = observation("evt-invalid-observation");
    if let EventBody::Observation(body) = &mut candidate.body {
        body.observation_id = "observation-1".to_owned();
    }
    assert_eq!(
        validate_terminal(&candidate.materialize(MATERIALIZED), &context)
            .unwrap_err()
            .code(),
        Event4ValidationCode::InvalidStructure
    );

    let candidate = observation(OBS_A);
    assert_eq!(
        validate_terminal(&candidate.materialize(MATERIALIZED), &context)
            .unwrap_err()
            .code(),
        Event4ValidationCode::IdentityNotDistinct
    );

    let candidate = summary(OBS_B);
    assert_eq!(
        validate_terminal(&candidate.materialize(MATERIALIZED), &context)
            .unwrap_err()
            .code(),
        Event4ValidationCode::IdentityNotDistinct
    );

    let mut candidate = action("evt-action-same", "evt-decision");
    if let EventBody::Action(body) = &mut candidate.body {
        body.action_id = "evt-action-same".to_owned();
    }
    assert_eq!(
        validate_terminal(&candidate.materialize(MATERIALIZED), &context)
            .unwrap_err()
            .code(),
        Event4ValidationCode::IdentityNotDistinct
    );

    let mut candidate = finding("evt-related");
    if let EventBody::Finding(body) = &mut candidate.body {
        body.related_observation_ids = Some(vec!["bad".to_owned()]);
    }
    assert_eq!(
        validate_terminal(&candidate.materialize(MATERIALIZED), &context)
            .unwrap_err()
            .code(),
        Event4ValidationCode::InvalidStructure
    );

    candidate = finding("evt-evidence-id");
    if let EventBody::Finding(body) = &mut candidate.body {
        body.evidence.as_mut().unwrap()[0].observation_id = Some(OBS_B.to_owned());
    }
    assert!(validate_terminal(&candidate.materialize(MATERIALIZED), &context).is_ok());
}

#[test]
fn timestamp_semantics_do_not_invent_occurred_at_ordering() {
    let context = Event4InMemoryContext::new();
    let mut candidate = summary("evt-time-invalid");
    candidate.observed_at = "secret-not-a-time".to_owned();
    assert_eq!(
        validate_terminal(&candidate.materialize(MATERIALIZED), &context)
            .unwrap_err()
            .code(),
        Event4ValidationCode::InvalidStructure
    );

    let candidate = summary("evt-time-order");
    assert_eq!(
        validate_terminal(&candidate.materialize("2026-09-16T11:59:59Z"), &context)
            .unwrap_err()
            .code(),
        Event4ValidationCode::MaterializationBeforeObservation
    );

    let mut candidate = summary("evt-occurred");
    candidate.occurred_at = Some("2027-01-01T00:00:00Z".to_owned());
    assert!(validate_terminal(&candidate.materialize(MATERIALIZED), &context).is_ok());
}

#[test]
fn requested_effective_and_degraded_rules_are_exact() {
    let context = Event4InMemoryContext::new();
    let mut candidate = decision("evt-different");
    if let EventBody::Decision(body) = &mut candidate.body {
        body.effective = Outcome::Observe;
    }
    assert_eq!(
        validate_terminal(&candidate.materialize(MATERIALIZED), &context)
            .unwrap_err()
            .code(),
        Event4ValidationCode::InvalidOutcomeRelationship
    );

    let mut candidate = decision("evt-equal-degraded");
    candidate.event_action = EventAction::PolicyEvaluated;
    if let EventBody::Decision(body) = &mut candidate.body {
        body.status = DecisionStatus::Degraded;
        body.capability = Some(CapabilityOutcome {
            availability: Availability::Unsupported,
            limitation: Some("not available".to_owned()),
        });
        body.degradation_reason = Some("unsupported".to_owned());
    }
    assert_eq!(
        validate_terminal(&candidate.materialize(MATERIALIZED), &context)
            .unwrap_err()
            .code(),
        Event4ValidationCode::InvalidOutcomeRelationship
    );

    let mut candidate = decision("evt-valid-degraded");
    if let EventBody::Decision(body) = &mut candidate.body {
        body.effective = Outcome::Observe;
        body.status = DecisionStatus::Degraded;
        body.capability = Some(CapabilityOutcome {
            availability: Availability::Unknown,
            limitation: Some("unknown capability".to_owned()),
        });
        body.degradation_reason = Some("capability_unknown".to_owned());
    }
    assert!(validate_terminal(&candidate.materialize(MATERIALIZED), &context).is_ok());
}

#[test]
fn runtime_schema_compiles_with_draft_and_format_validation() {
    let schema: Value = serde_json::from_str(EVENT4_SCHEMA).unwrap();
    assert_eq!(
        schema["$schema"],
        "https://json-schema.org/draft/2020-12/schema"
    );
    let valid = serde_json::to_value(summary("evt-schema").materialize(MATERIALIZED)).unwrap();
    validate_event4_structure(&valid).unwrap();
    let mut invalid = valid;
    invalid
        .as_object_mut()
        .unwrap()
        .insert("materialized_at".to_owned(), json!("2026-99-99"));
    assert!(validate_event4_structure(&invalid).is_err());
}
