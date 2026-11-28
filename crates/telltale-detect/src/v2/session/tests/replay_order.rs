use super::*;

#[test]
fn canonical_order_is_replay_stable_and_untimed_last() {
    let observations = vec![
        observation("three", Some("session"), None, 3),
        observation("two", Some("session"), Some("2026-09-18T00:00:00Z"), 2),
        observation("one", Some("session"), Some("2026-09-18T00:00:00Z"), 1),
    ];
    let groups = group_sessions(&observations, true);
    assert_eq!(groups.len(), 1);
    assert_eq!(
        groups[0]
            .iter()
            .map(|o| o.sequence().unwrap())
            .collect::<Vec<_>>(),
        vec![1, 2, 3]
    );
    let reversed = observations.into_iter().rev().collect::<Vec<_>>();
    assert_eq!(
        group_sessions(&reversed, true)[0]
            .iter()
            .map(|o| o.sequence().unwrap())
            .collect::<Vec<_>>(),
        vec![1, 2, 3]
    );
}

#[test]
fn unknown_identity_never_groups_unrelated_occurrences() {
    let observations = vec![
        observation("one", Some("same"), None, 1),
        observation("two", Some("same"), None, 2),
    ];
    assert_eq!(group_sessions(&observations, false).len(), 2);
    let unscoped = vec![
        observation("one", None, None, 1),
        observation("two", None, None, 2),
    ];
    assert_eq!(group_sessions(&unscoped, true).len(), 2);
}

#[test]
fn unrelated_source_instances_with_identical_sessions_are_isolated() {
    let plan = crate::v2::bundled_plan();
    let observations = vec![observation("one", Some("same"), None, 1)];
    let first = CorrelationId::source_reported("instance-one").unwrap();
    let second = CorrelationId::source_reported("instance-two").unwrap();
    for instance in [&first, &second] {
        let output = evaluate_source(
            CanonicalSourceInput {
                client: ClientId::Claude,
                source_id: "claude.projects",
                source_instance: Some(instance),
                observations: &observations,
            },
            plan,
            None,
        )
        .unwrap();
        assert_eq!(output.sessions().len(), 1);
        assert_eq!(output.source_instance(), Some(instance));
    }
}

#[test]
fn equal_time_and_untimed_ties_preserve_caller_occurrence_order() {
    let observations = [
        observation("z-first", Some("session"), None, 1),
        observation("a-second", Some("session"), None, 1),
    ];
    let grouped = group_sessions(&observations, true);
    assert_eq!(
        grouped[0][0].observation_id(),
        observations[0].observation_id()
    );
    let reversed = [observations[1].clone(), observations[0].clone()];
    assert_eq!(
        group_sessions(&reversed, true)[0][0].observation_id(),
        observations[1].observation_id()
    );
}

#[test]
fn source_instance_none_keeps_deterministic_singletons_and_limited_visibility() {
    let observations = [
        observation("one", Some("same"), Some("2026-09-17T00:00:00Z"), 1),
        observation("two", Some("same"), Some("2026-09-17T00:00:01Z"), 2),
    ];
    let compatibility = crate::v2::bundled_plan();
    let unverified = evaluate_source(
        CanonicalSourceInput {
            client: ClientId::Claude,
            source_id: "claude.projects",
            source_instance: None,
            observations: &observations,
        },
        compatibility,
        None,
    )
    .unwrap();
    assert_eq!(unverified.sessions().len(), 2);
    assert_eq!(
        unverified.completion(),
        EvaluationCompletion::VisibilityLimited
    );
    assert!(unverified.source_instance().is_none());
    let session_ids = unverified
        .sessions()
        .iter()
        .map(|session| session.session_id().unwrap().value())
        .collect::<Vec<_>>();
    assert_eq!(session_ids, ["same", "same"]);

    let instance = CorrelationId::source_reported("verified").unwrap();
    let verified = evaluate_source(
        CanonicalSourceInput {
            client: ClientId::Claude,
            source_id: "claude.projects",
            source_instance: Some(&instance),
            observations: &observations,
        },
        compatibility,
        None,
    )
    .unwrap();
    assert_eq!(verified.sessions().len(), 1);
}
