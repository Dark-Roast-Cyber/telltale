use super::*;

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
