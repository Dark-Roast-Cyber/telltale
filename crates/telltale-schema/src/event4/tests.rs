use std::collections::BTreeSet;

use serde_json::{Value, json};

use super::*;

const OBS_A: &str =
    "obs:v2:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const OBS_B: &str =
    "obs:v2:sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const OBSERVED: &str = "2026-09-16T12:00:00Z";
const MATERIALIZED: &str = "2026-09-16T12:00:01Z";

fn base(id: &str, event_type: EventType, action: EventAction, body: EventBody) -> Event4Candidate {
    Event4Candidate {
        schema_version: EVENT4_SCHEMA_VERSION.to_owned(),
        event_id: id.to_owned(),
        event_type,
        event_action: action,
        occurred_at: None,
        observed_at: OBSERVED.to_owned(),
        sequence: None,
        session_id: None,
        workflow_id: None,
        trace_id: None,
        span_id: None,
        body,
        extensions: None,
    }
}

fn session(id: &str) -> Event4Candidate {
    let mut candidate = base(
        id,
        EventType::Session,
        EventAction::SessionOpened,
        EventBody::Session(SessionBody {
            session_id: "session-1".to_owned(),
            lifecycle: SessionLifecycle::Opened,
            client_ref: None,
            runtime_ref: None,
            ruleset_ref: None,
            policy_ref: None,
            capability_ref: None,
            toolset_ref: None,
            mcp_ref: None,
        }),
    );
    candidate.session_id = Some("session-1".to_owned());
    candidate
}

fn observation(id: &str) -> Event4Candidate {
    base(
        id,
        EventType::Observation,
        EventAction::MessageObserved,
        EventBody::Observation(Box::new(ObservationBody {
            observation_id: OBS_A.to_owned(),
            kind: ObservationKind::Message,
            stage: ObservationStage::Observed,
            provenance: Some(FactProvenance::Parsed),
            fact_provenance: None,
            capabilities: None,
            capability: None,
            source: None,
            correlation: None,
            runtime_ref: None,
            capability_ref: None,
            toolset_ref: None,
            mcp_ref: None,
            tool: None,
        })),
    )
}

fn finding(id: &str) -> Event4Candidate {
    let mut candidate = base(
        id,
        EventType::Finding,
        EventAction::RuleMatched,
        EventBody::Finding(Box::new(FindingBody {
            kind: FindingKind::SecurityDetection,
            category: "example".to_owned(),
            severity: Severity::Low,
            risk_points: Some(10),
            confidence: Some(Confidence::High),
            confidence_score: Some(0.75),
            title: None,
            reason: None,
            rule_ids: Some(vec!["rule.example".to_owned()]),
            detector: Detector {
                kind: DetectorKind::Rule,
                id: "rule.example".to_owned(),
                engine: None,
                version: None,
                content_ref: None,
            },
            related_observation_ids: Some(vec![OBS_A.to_owned()]),
            runtime_ref: None,
            ruleset_ref: None,
            policy_ref: None,
            capability_ref: None,
            labels: None,
            techniques: None,
            evidence: Some(vec![Evidence {
                observation_id: Some(OBS_A.to_owned()),
                field: Some("message.content".to_owned()),
                representation: EvidenceRepresentation::Classification,
                value: Some(ExtensionScalar::String("suspicious".to_owned())),
            }]),
        })),
    );
    candidate.session_id = Some("session-1".to_owned());
    candidate
}

fn decision(id: &str) -> Event4Candidate {
    base(
        id,
        EventType::Decision,
        EventAction::PolicyEvaluated,
        EventBody::Decision(DecisionBody {
            requested: Outcome::Allow,
            effective: Outcome::Allow,
            status: DecisionStatus::Evaluated,
            reason_code: "policy.allowed".to_owned(),
            policy_ref: None,
            capability_ref: None,
            basis_event_ids: None,
            approval_id: None,
            approval_state: None,
            capability: None,
            degradation_reason: None,
        }),
    )
}

fn action(id: &str, decision_ref: &str) -> Event4Candidate {
    base(
        id,
        EventType::Action,
        EventAction::EnforcementApplied,
        EventBody::Action(ActionBody {
            action_id: format!("action-{id}"),
            decision_ref: decision_ref.to_owned(),
            requested: Outcome::Allow,
            effective: Outcome::Allow,
            status: ActionStatus::Succeeded,
            reason_code: None,
            enforcement_point: Some("test".to_owned()),
            approval_id: None,
            capability_ref: None,
            capability: None,
            degradation_reason: None,
        }),
    )
}

fn state(id: &str) -> Event4Candidate {
    base(
        id,
        EventType::State,
        EventAction::RuntimeChanged,
        EventBody::State(StateBody {
            kind: StateKind::Runtime,
            state_ref: "runtime-1".to_owned(),
            change: Some(StateChange::Changed),
        }),
    )
}

fn health(id: &str) -> Event4Candidate {
    base(
        id,
        EventType::Health,
        EventAction::HealthDegraded,
        EventBody::Health(HealthBody {
            component: "sensor".to_owned(),
            status: HealthStatus::Degraded,
            reason_code: Some("sensor.partial".to_owned()),
        }),
    )
}

fn summary(id: &str) -> Event4Candidate {
    base(
        id,
        EventType::Summary,
        EventAction::SummaryEmitted,
        EventBody::Summary(SummaryBody {
            kind: SummaryKind::AgentActivity,
            scope: SummaryScope::Session,
            count: 1,
        }),
    )
}

fn accept(candidate: Event4Candidate, context: &mut Event4InMemoryContext) -> AcceptedEvent4 {
    let materialized = candidate.materialize(MATERIALIZED);
    let accepted = validate_terminal(&materialized, context).expect("valid event");
    context.apply(accepted.effect()).expect("apply effect");
    accepted
}

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
fn record_local_approval_rules_are_enforced() {
    let context = Event4InMemoryContext::new();
    let mut candidate = decision("evt-request-invalid");
    candidate.event_action = EventAction::ApprovalRequested;
    assert_eq!(
        validate_terminal(&candidate.materialize(MATERIALIZED), &context)
            .unwrap_err()
            .code(),
        Event4ValidationCode::InvalidApproval
    );

    let mut candidate = approval_request("evt-request-valid", "approval-1");
    if let EventBody::Decision(body) = &mut candidate.body {
        body.effective = Outcome::Allow;
    }
    assert_eq!(
        validate_terminal(&candidate.materialize(MATERIALIZED), &context)
            .unwrap_err()
            .code(),
        Event4ValidationCode::InvalidOutcomeRelationship
    );

    let candidate = approval_resolution(
        "evt-resolution-invalid",
        "approval-1",
        ApprovalState::Requested,
    );
    assert_eq!(
        validate_terminal(&candidate.materialize(MATERIALIZED), &context)
            .unwrap_err()
            .code(),
        Event4ValidationCode::InvalidApproval
    );

    let mut candidate = decision("evt-policy-terminal-approval");
    if let EventBody::Decision(body) = &mut candidate.body {
        body.approval_id = Some("approval-1".to_owned());
        body.approval_state = Some(ApprovalState::Granted);
    }
    assert_eq!(
        validate_terminal(&candidate.materialize(MATERIALIZED), &context)
            .unwrap_err()
            .code(),
        Event4ValidationCode::ActionSemanticMismatch
    );
}

fn approval_request(id: &str, approval_id: &str) -> Event4Candidate {
    let mut candidate = decision(id);
    candidate.event_action = EventAction::ApprovalRequested;
    if let EventBody::Decision(body) = &mut candidate.body {
        body.requested = Outcome::RequireApproval;
        body.effective = Outcome::RequireApproval;
        body.status = DecisionStatus::Pending;
        body.approval_id = Some(approval_id.to_owned());
        body.approval_state = Some(ApprovalState::Requested);
    }
    candidate
}

fn approval_resolution(id: &str, approval_id: &str, state: ApprovalState) -> Event4Candidate {
    let mut candidate = decision(id);
    candidate.event_action = EventAction::ApprovalResolved;
    if let EventBody::Decision(body) = &mut candidate.body {
        body.approval_id = Some(approval_id.to_owned());
        body.approval_state = Some(state);
    }
    candidate
}

#[test]
fn context_tracks_approval_transitions_across_separate_calls() {
    let mut context = Event4InMemoryContext::new();
    accept(approval_request("evt-request", "approval-1"), &mut context);

    let unresolved =
        approval_resolution("evt-resolution-wrong", "approval-2", ApprovalState::Granted);
    assert_eq!(
        validate_terminal(&unresolved.materialize(MATERIALIZED), &context)
            .unwrap_err()
            .code(),
        Event4ValidationCode::ApprovalTransition
    );

    accept(
        approval_resolution("evt-resolution", "approval-1", ApprovalState::Granted),
        &mut context,
    );

    let mut candidate = action("evt-approved-action", "evt-resolution");
    if let EventBody::Action(body) = &mut candidate.body {
        body.approval_id = Some("approval-1".to_owned());
    }
    accept(candidate, &mut context);

    let mut candidate = action("evt-wrong-approval", "evt-resolution");
    if let EventBody::Action(body) = &mut candidate.body {
        body.approval_id = Some("approval-2".to_owned());
    }
    assert_eq!(
        validate_terminal(&candidate.materialize(MATERIALIZED), &context)
            .unwrap_err()
            .code(),
        Event4ValidationCode::ApprovalActionMismatch
    );
}

#[test]
fn acceptance_effect_rechecks_context_before_atomic_apply() {
    let mut validation_context = Event4InMemoryContext::new();
    accept(
        approval_request("evt-request-shared", "approval-shared"),
        &mut validation_context,
    );
    let granted = approval_resolution(
        "evt-resolution-granted",
        "approval-shared",
        ApprovalState::Granted,
    )
    .materialize(MATERIALIZED);
    let granted = validate_terminal(&granted, &validation_context).unwrap();

    let mut changed_context = Event4InMemoryContext::new();
    accept(
        approval_request("evt-request-shared", "approval-shared"),
        &mut changed_context,
    );
    accept(
        approval_resolution(
            "evt-resolution-denied",
            "approval-shared",
            ApprovalState::Denied,
        ),
        &mut changed_context,
    );

    assert_eq!(
        changed_context.apply(granted.effect()).unwrap_err().code(),
        Event4ValidationCode::ContextConflict
    );
    assert!(changed_context.event("evt-resolution-granted").is_none());
}

#[test]
fn action_and_basis_references_resolve_only_accepted_facts() {
    let mut context = Event4InMemoryContext::new();
    let missing = action("evt-action-missing", "evt-missing").materialize(MATERIALIZED);
    assert_eq!(
        validate_terminal(&missing, &context).unwrap_err().code(),
        Event4ValidationCode::MissingReference
    );
    assert!(context.event("evt-action-missing").is_none());

    accept(summary("evt-basis"), &mut context);
    let mut candidate = decision("evt-with-basis");
    if let EventBody::Decision(body) = &mut candidate.body {
        body.basis_event_ids = Some(vec!["evt-basis".to_owned()]);
    }
    accept(candidate, &mut context);

    let mut candidate = action("evt-no-enforcement-point", "evt-with-basis");
    if let EventBody::Action(body) = &mut candidate.body {
        body.enforcement_point = None;
    }
    assert_eq!(
        validate_terminal(&candidate.materialize(MATERIALIZED), &context)
            .unwrap_err()
            .code(),
        Event4ValidationCode::ActionSemanticMismatch
    );

    let mut candidate = decision("evt-outcome");
    if let EventBody::Decision(body) = &mut candidate.body {
        body.requested = Outcome::Block;
        body.effective = Outcome::Block;
    }
    accept(candidate, &mut context);
    let candidate = action("evt-mismatch", "evt-outcome");
    assert_eq!(
        validate_terminal(&candidate.materialize(MATERIALIZED), &context)
            .unwrap_err()
            .code(),
        Event4ValidationCode::RequestedOutcomeMismatch
    );
}

#[test]
fn same_id_bytes_are_idempotent_and_different_bytes_collide() {
    let mut context = Event4InMemoryContext::new();
    let first_event = summary("evt-repeat").materialize(MATERIALIZED);
    let first = validate_terminal(&first_event, &context).unwrap();
    context.apply(first.effect()).unwrap();

    let repeated = validate_terminal(&first_event, &context).unwrap();
    assert_eq!(repeated.disposition(), AcceptanceDisposition::Idempotent);
    assert_eq!(first.canonical_bytes(), repeated.canonical_bytes());

    let mut changed = summary("evt-repeat");
    if let EventBody::Summary(body) = &mut changed.body {
        body.count = 2;
    }
    assert_eq!(
        validate_terminal(&changed.materialize(MATERIALIZED), &context)
            .unwrap_err()
            .code(),
        Event4ValidationCode::IdentityCollision
    );
}

#[test]
fn applying_a_stale_same_id_effect_fails_without_mutation() {
    let empty = Event4InMemoryContext::new();
    let first_event = summary("evt-apply-conflict").materialize(MATERIALIZED);
    let first = validate_terminal(&first_event, &empty).unwrap();

    let mut changed = summary("evt-apply-conflict");
    if let EventBody::Summary(body) = &mut changed.body {
        body.count = 2;
    }
    let changed = changed.materialize(MATERIALIZED);
    let changed = validate_terminal(&changed, &empty).unwrap();

    let mut context = Event4InMemoryContext::new();
    context.apply(first.effect()).unwrap();
    assert_eq!(
        context.apply(changed.effect()).unwrap_err().code(),
        Event4ValidationCode::ContextConflict
    );
}

fn one_extension(namespace: &str, property: &str, value: ExtensionValue) -> Extensions {
    let mut local = OpenMap::new();
    local.insert(property, value);
    let mut extensions = OpenMap::new();
    extensions.insert(namespace, local);
    extensions
}

#[test]
fn extensions_reject_names_nesting_and_reserved_properties() {
    let context = Event4InMemoryContext::new();
    for (namespace, property) in [
        ("notqualified", "custom"),
        ("telltale.vendor", "custom"),
        ("vendor.example", "event_id"),
        ("vendor.example", "materialized_at"),
        ("vendor.example", "finding"),
        ("vendor.example", "risk_score"),
    ] {
        let mut candidate = summary("evt-extension-invalid");
        candidate.extensions = Some(one_extension(
            namespace,
            property,
            ExtensionValue::Scalar(ExtensionScalar::Bool(true)),
        ));
        assert!(validate_terminal(&candidate.materialize(MATERIALIZED), &context).is_err());
    }

    let event = summary("evt-extension-nested").materialize(MATERIALIZED);
    let mut value = serde_json::to_value(&event).unwrap();
    value.as_object_mut().unwrap().insert(
        "extensions".to_owned(),
        json!({"vendor.example":{"custom":{"nested":true}}}),
    );
    assert!(validate_event4_structure(&value).is_err());

    let mut value = serde_json::to_value(&event).unwrap();
    value.as_object_mut().unwrap().insert(
        "extensions".to_owned(),
        json!({"vendor.example":{"custom":[[true]]}}),
    );
    assert!(validate_event4_structure(&value).is_err());
}

fn scalar_boundary_extensions(extra: bool) -> Extensions {
    let mut extensions = OpenMap::new();
    for namespace_index in 0..16 {
        let mut namespace = OpenMap::new();
        for property_index in 0..16 {
            let count = if extra && namespace_index == 0 && property_index == 0 {
                3
            } else {
                2
            };
            namespace.insert(
                format!("p{property_index}"),
                ExtensionValue::Array(vec![ExtensionScalar::Bool(true); count]),
            );
        }
        extensions.insert(format!("vendor{namespace_index}.space"), namespace);
    }
    extensions
}

#[test]
fn extension_scalar_limit_accepts_512_and_rejects_513() {
    let context = Event4InMemoryContext::new();
    let mut candidate = summary("evt-512");
    candidate.extensions = Some(scalar_boundary_extensions(false));
    assert!(validate_terminal(&candidate.materialize(MATERIALIZED), &context).is_ok());

    let mut candidate = summary("evt-513");
    candidate.extensions = Some(scalar_boundary_extensions(true));
    assert_eq!(
        validate_terminal(&candidate.materialize(MATERIALIZED), &context)
            .unwrap_err()
            .code(),
        Event4ValidationCode::ExtensionScalarLimit
    );
}

#[test]
fn extension_collection_and_string_limits_are_enforced() {
    let context = Event4InMemoryContext::new();

    let mut candidate = summary("evt-array-32");
    candidate.extensions = Some(one_extension(
        "vendor.example",
        "items",
        ExtensionValue::Array(vec![ExtensionScalar::Bool(true); 32]),
    ));
    assert!(validate_terminal(&candidate.materialize(MATERIALIZED), &context).is_ok());

    let mut candidate = summary("evt-array-33");
    candidate.extensions = Some(one_extension(
        "vendor.example",
        "items",
        ExtensionValue::Array(vec![ExtensionScalar::Bool(true); 33]),
    ));
    assert!(validate_terminal(&candidate.materialize(MATERIALIZED), &context).is_err());

    for (length, accepted) in [(1024, true), (1025, false)] {
        let mut candidate = summary(if accepted {
            "evt-string-1024"
        } else {
            "evt-string-1025"
        });
        candidate.extensions = Some(one_extension(
            "vendor.example",
            "text",
            ExtensionValue::Scalar(ExtensionScalar::String("x".repeat(length))),
        ));
        assert_eq!(
            validate_terminal(&candidate.materialize(MATERIALIZED), &context).is_ok(),
            accepted
        );
    }

    let mut namespaces = OpenMap::new();
    for index in 0..17 {
        namespaces.insert(format!("vendor{index}.example"), OpenMap::new());
    }
    let mut candidate = summary("evt-namespace-17");
    candidate.extensions = Some(namespaces);
    assert!(validate_terminal(&candidate.materialize(MATERIALIZED), &context).is_err());

    let mut properties = OpenMap::new();
    for index in 0..17 {
        properties.insert(
            format!("property_{index}"),
            ExtensionValue::Scalar(ExtensionScalar::Null),
        );
    }
    let mut extensions = OpenMap::new();
    extensions.insert("vendor.example", properties);
    let mut candidate = summary("evt-property-17");
    candidate.extensions = Some(extensions);
    assert!(validate_terminal(&candidate.materialize(MATERIALIZED), &context).is_err());
}

fn sized_extensions(target: usize) -> Extensions {
    let mut extensions = OpenMap::new();
    for namespace_index in 0..16 {
        let mut namespace = OpenMap::new();
        for property_index in 0..16 {
            namespace.insert(
                format!("p{property_index}"),
                ExtensionValue::Scalar(ExtensionScalar::String(String::new())),
            );
        }
        extensions.insert(format!("vendor{namespace_index}.space"), namespace);
    }
    let mut current = serde_json::to_vec(&extensions).unwrap().len();
    assert!(current <= target);
    for (_, namespace) in &mut extensions.0 {
        for (_, value) in &mut namespace.0 {
            let ExtensionValue::Scalar(ExtensionScalar::String(text)) = value else {
                unreachable!()
            };
            let add = (target - current).min(1024);
            text.push_str(&"x".repeat(add));
            current += add;
            if current == target {
                return extensions;
            }
        }
    }
    panic!("target exceeds extension fixture capacity");
}

#[test]
fn extension_byte_limit_accepts_16384_and_rejects_16385() {
    let context = Event4InMemoryContext::new();
    for (size, accepted) in [
        (EXTENSIONS_MAX_BYTES, true),
        (EXTENSIONS_MAX_BYTES + 1, false),
    ] {
        let extensions = sized_extensions(size);
        assert_eq!(serde_json::to_vec(&extensions).unwrap().len(), size);
        let mut candidate = summary(if accepted {
            "evt-ext-max"
        } else {
            "evt-ext-over"
        });
        candidate.extensions = Some(extensions);
        let result = validate_terminal(&candidate.materialize(MATERIALIZED), &context);
        assert_eq!(result.is_ok(), accepted);
    }
}

fn sized_event(target: usize) -> MaterializedEvent4 {
    let mut candidate = finding("evt-size");
    if let EventBody::Finding(body) = &mut candidate.body {
        body.reason = Some(String::new());
    }
    let base = serde_json::to_vec(&candidate.clone().materialize(MATERIALIZED))
        .unwrap()
        .len();
    assert!(base <= target);
    if let EventBody::Finding(body) = &mut candidate.body {
        body.reason = Some("x".repeat(target - base));
    }
    let event = candidate.materialize(MATERIALIZED);
    assert_eq!(serde_json::to_vec(&event).unwrap().len(), target);
    event
}

#[test]
fn full_event_byte_limit_accepts_65536_and_rejects_65537() {
    let context = Event4InMemoryContext::new();
    assert!(validate_terminal(&sized_event(EVENT4_MAX_BYTES), &context).is_ok());
    assert_eq!(
        validate_terminal(&sized_event(EVENT4_MAX_BYTES + 1), &context)
            .unwrap_err()
            .code(),
        Event4ValidationCode::EventTooLarge
    );
}

#[test]
fn object_array_depth_counts_root_as_one() {
    let depth8 = json!({"a":{"b":[{"c":{"d":[{"e":[]} ]}}]}});
    assert_eq!(super::validate::test_container_depth(&depth8), 8);
    let depth9 = json!({"a":{"b":[{"c":{"d":[{"e":[[]]}]}}]}});
    assert_eq!(super::validate::test_container_depth(&depth9), 9);
}

#[test]
fn canonical_open_maps_sort_normalize_and_preserve_array_order() {
    let context = Event4InMemoryContext::new();
    let mut first = summary("evt-map");
    let mut extensions = OpenMap::new();
    extensions.insert(
        "zeta.example",
        OpenMap::from_entries([(
            "b".to_owned(),
            ExtensionValue::Scalar(ExtensionScalar::Bool(true)),
        )]),
    );
    extensions.insert(
        "alpha.example",
        OpenMap::from_entries([(
            "a".to_owned(),
            ExtensionValue::Array(vec![
                ExtensionScalar::Number(1.0),
                ExtensionScalar::Number(2.0),
            ]),
        )]),
    );
    first.extensions = Some(extensions);

    let mut second = summary("evt-map");
    let mut extensions = OpenMap::new();
    extensions.insert(
        "alpha.example",
        OpenMap::from_entries([(
            "a".to_owned(),
            ExtensionValue::Array(vec![
                ExtensionScalar::Number(1.0),
                ExtensionScalar::Number(2.0),
            ]),
        )]),
    );
    extensions.insert(
        "zeta.example",
        OpenMap::from_entries([(
            "b".to_owned(),
            ExtensionValue::Scalar(ExtensionScalar::Bool(true)),
        )]),
    );
    second.extensions = Some(extensions);
    let first = validate_terminal(&first.materialize(MATERIALIZED), &context).unwrap();
    let second = validate_terminal(&second.materialize(MATERIALIZED), &context).unwrap();
    assert_eq!(first.canonical_bytes(), second.canonical_bytes());
    let repeated =
        summary_with_same_extensions("evt-map", first.canonical_bytes()).materialize(MATERIALIZED);
    assert_eq!(
        first.canonical_bytes(),
        validate_terminal(&repeated, &context)
            .unwrap()
            .canonical_bytes()
    );

    let mut forward = summary("evt-map-array");
    forward.extensions = Some(one_extension(
        "alpha.example",
        "a",
        ExtensionValue::Array(vec![
            ExtensionScalar::Number(1.0),
            ExtensionScalar::Number(2.0),
        ]),
    ));
    let mut reversed = summary("evt-map-array");
    reversed.extensions = Some(one_extension(
        "alpha.example",
        "a",
        ExtensionValue::Array(vec![
            ExtensionScalar::Number(2.0),
            ExtensionScalar::Number(1.0),
        ]),
    ));
    let forward = forward.materialize(MATERIALIZED);
    let forward = validate_terminal(&forward, &context).unwrap();
    let reversed = reversed.materialize(MATERIALIZED);
    assert_ne!(
        forward.canonical_bytes(),
        validate_terminal(&reversed, &context)
            .unwrap()
            .canonical_bytes()
    );
}

fn summary_with_same_extensions(id: &str, bytes: &[u8]) -> Event4Candidate {
    let value: Value = serde_json::from_slice(bytes).unwrap();
    let mut extensions = OpenMap::new();
    for (namespace, properties) in value["extensions"].as_object().unwrap() {
        let mut local = OpenMap::new();
        for (property, value) in properties.as_object().unwrap() {
            let extension = if let Some(values) = value.as_array() {
                ExtensionValue::Array(
                    values
                        .iter()
                        .map(|value| ExtensionScalar::Number(value.as_f64().unwrap()))
                        .collect(),
                )
            } else {
                ExtensionValue::Scalar(ExtensionScalar::Bool(value.as_bool().unwrap()))
            };
            local.insert(property.clone(), extension);
        }
        extensions.insert(namespace.clone(), local);
    }
    let mut candidate = summary(id);
    candidate.extensions = Some(extensions);
    candidate
}

#[test]
fn nfc_equivalent_open_map_keys_are_rejected() {
    let context = Event4InMemoryContext::new();
    let mut candidate = observation("evt-nfc");
    if let EventBody::Observation(body) = &mut candidate.body {
        body.fact_provenance = Some(OpenMap::from_entries([
            ("caf\u{e9}".to_owned(), FactProvenance::Parsed),
            ("cafe\u{301}".to_owned(), FactProvenance::Parsed),
        ]));
    }
    assert_eq!(
        validate_terminal(&candidate.materialize(MATERIALIZED), &context)
            .unwrap_err()
            .code(),
        Event4ValidationCode::DuplicateNormalizedKey
    );
}

#[test]
fn non_finite_numbers_and_oversized_excerpts_fail() {
    let context = Event4InMemoryContext::new();
    let mut candidate = finding("evt-nan");
    if let EventBody::Finding(body) = &mut candidate.body {
        body.confidence_score = Some(f64::NAN);
    }
    assert_eq!(
        validate_terminal(&candidate.materialize(MATERIALIZED), &context)
            .unwrap_err()
            .code(),
        Event4ValidationCode::InvalidStructure
    );

    let mut candidate = finding("evt-evidence-nan");
    if let EventBody::Finding(body) = &mut candidate.body {
        body.evidence = Some(vec![Evidence {
            observation_id: Some(OBS_A.to_owned()),
            field: None,
            representation: EvidenceRepresentation::Count,
            value: Some(ExtensionScalar::Number(f64::INFINITY)),
        }]);
    }
    assert_eq!(
        validate_terminal(&candidate.materialize(MATERIALIZED), &context)
            .unwrap_err()
            .code(),
        Event4ValidationCode::NonFiniteNumber
    );

    let mut candidate = summary("evt-extension-nan");
    candidate.extensions = Some(one_extension(
        "vendor.example",
        "number",
        ExtensionValue::Scalar(ExtensionScalar::Number(f64::NEG_INFINITY)),
    ));
    assert_eq!(
        validate_terminal(&candidate.materialize(MATERIALIZED), &context)
            .unwrap_err()
            .code(),
        Event4ValidationCode::NonFiniteNumber
    );

    let mut candidate = finding("evt-excerpt");
    if let EventBody::Finding(body) = &mut candidate.body {
        body.evidence = Some(vec![Evidence {
            observation_id: Some(OBS_A.to_owned()),
            field: None,
            representation: EvidenceRepresentation::RedactedExcerpt,
            value: Some(ExtensionScalar::String("x".repeat(513))),
        }]);
    }
    assert_eq!(
        validate_terminal(&candidate.materialize(MATERIALIZED), &context)
            .unwrap_err()
            .code(),
        Event4ValidationCode::InvalidEvidence
    );

    for (count, accepted) in [(32, true), (33, false)] {
        let mut candidate = finding(if accepted {
            "evt-evidence-32"
        } else {
            "evt-evidence-33"
        });
        if let EventBody::Finding(body) = &mut candidate.body {
            body.evidence = Some(
                (0..count)
                    .map(|_| Evidence {
                        observation_id: Some(OBS_A.to_owned()),
                        field: None,
                        representation: EvidenceRepresentation::Classification,
                        value: Some(ExtensionScalar::String("safe".to_owned())),
                    })
                    .collect(),
            );
        }
        assert_eq!(
            validate_terminal(&candidate.materialize(MATERIALIZED), &context).is_ok(),
            accepted
        );
    }
}

#[test]
fn canonical_property_order_and_escaping_are_stable() {
    let context = Event4InMemoryContext::new();
    let mut candidate = summary("evt-order");
    candidate.extensions = Some(one_extension(
        "vendor.example",
        "escaped",
        ExtensionValue::Scalar(ExtensionScalar::String("quote\"line\n".to_owned())),
    ));
    let accepted =
        validate_terminal(&candidate.clone().materialize(MATERIALIZED), &context).unwrap();
    let text = std::str::from_utf8(accepted.canonical_bytes()).unwrap();
    assert!(text.starts_with("{\"schema_version\":\"4.0\",\"event_id\":\"evt-order\",\"type\":\"summary\",\"event_action\":\"summary.emitted\",\"observed_at\":"));
    assert!(text.contains("\"materialized_at\":\"2026-09-16T12:00:01Z\",\"summary\":"));
    assert!(text.contains("\"escaped\":\"quote\\\"line\\n\""));
    assert_eq!(
        accepted.canonical_bytes(),
        validate_terminal(&candidate.materialize(MATERIALIZED), &context)
            .unwrap()
            .canonical_bytes()
    );
}

#[test]
fn error_surfaces_never_echo_candidate_markers() {
    let context = Event4InMemoryContext::new();
    let marker = "SYNTHETIC_SECRET_MARKER";
    let mut candidate = summary("evt-private-error");
    candidate.observed_at = marker.to_owned();
    let error = validate_terminal(&candidate.materialize(MATERIALIZED), &context).unwrap_err();
    assert!(!error.to_string().contains(marker));
    assert!(!format!("{error:?}").contains(marker));
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
