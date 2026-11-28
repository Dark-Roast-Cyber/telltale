use super::*;

#[test]
fn canonical_source_hash_is_required_without_normalization() {
    let observations = [message(
        "hash",
        Some("session"),
        "needle",
        CapabilityAvailability::Supported,
    )];
    let evaluation = evaluate(&observations, &plan(0)).unwrap();
    let canonical = "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd";
    let projected = super::super::super::event3::project_event3(
        &evaluation,
        &super::super::super::event3::Event3CompatibilityContext {
            source_path_hash: canonical,
            sessions: &[],
        },
    )
    .unwrap();
    assert_eq!(
        projected.events[0].source_path_hash.as_deref(),
        Some(canonical)
    );
    for invalid in [
        "ABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCD",
        "abcdef",
        "gbcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd",
    ] {
        assert!(matches!(
            super::super::super::event3::project_event3(
                &evaluation,
                &super::super::super::event3::Event3CompatibilityContext {
                    source_path_hash: invalid,
                    sessions: &[],
                }
            ),
            Err(ProcessingError::Projection)
        ));
    }
}

/// Every client has a hook-journal identity, by one rule and no table. It is
/// accepted only with the feature, only for its own client, and only for
/// observations stamped with it.
#[test]
fn every_clients_hook_journal_follows_the_feature_and_its_own_client() {
    let plan = plan(0);
    let observations = [observation("one", Some("session"), None, 1)];
    let input = |client, source_id| CanonicalSourceInput {
        client,
        source_id,
        source_instance: None,
        observations: &observations,
    };
    for (index, &client) in ClientId::ALL.iter().enumerate() {
        let source_id = client.hook_journal_source_id();
        // The observation says `claude.projects`, which is not this identity.
        assert!(matches!(
            evaluate_source(input(client, source_id), &plan, None),
            Err(ProcessingError::InvalidSource)
        ));
        let other = ClientId::ALL[(index + 1) % ClientId::ALL.len()];
        assert!(matches!(
            evaluate_source(input(other, source_id), &plan, None),
            Err(ProcessingError::InvalidSource)
        ));
        #[cfg(feature = "hook-journal")]
        {
            let stamped = [stamped_observation(source_id)];
            let accepted = |client, source_id| CanonicalSourceInput {
                client,
                source_id,
                source_instance: None,
                observations: &stamped,
            };
            evaluate_source(accepted(client, source_id), &plan, None).unwrap();
            assert!(matches!(
                evaluate_source(accepted(other, source_id), &plan, None),
                Err(ProcessingError::InvalidSource)
            ));
        }
    }
}
