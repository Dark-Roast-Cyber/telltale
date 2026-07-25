use super::*;

#[test]
fn detects_uc002_credential_harvesting_before_publish_in_codex_fixture() {
    let source = Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "uc002-positive-credential-publish".to_string(),
        path: PathBuf::from(crate::test_fixture_path(
            "session_stores/codex/sessions/2026/04/uc002-positive-credential-publish.jsonl",
        )),
    };

    let detections = detect_sources(&[source]);

    assert_eq!(detections.len(), 1);
    let event = &detections[0].1;
    assert_eq!(event.session_id, "uc002-positive-credential-publish");
    assert_eq!(event.severity, "critical");
    assert!(
        event
            .rule_ids
            .contains(&"credential.cloud_harvest".to_string())
    );
    assert!(event.rule_ids.contains(&"supply_chain.publish".to_string()));
    assert!(
        event
            .rule_ids
            .contains(&"chain.credential_then_publish".to_string())
    );
    assert!(
        event
            .categories
            .contains(&"credential_harvesting".to_string())
    );
    assert!(event.categories.contains(&"supply_chain".to_string()));
    assert!(
        event
            .evidence
            .iter()
            .all(|item| item.hash.is_some() && !item.redacted_value.is_empty())
    );
}

#[test]
fn does_not_apply_uc002_chain_to_publish_only_codex_fixture() {
    let source = Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "uc002-negative-publish-only".to_string(),
        path: PathBuf::from(crate::test_fixture_path(
            "session_stores/codex/sessions/2026/04/uc002-negative-publish-only.jsonl",
        )),
    };

    let detections = detect_sources(&[source]);

    assert_eq!(detections.len(), 1);
    let event = &detections[0].1;
    assert_eq!(event.session_id, "uc002-negative-publish-only");
    assert!(event.rule_ids.contains(&"supply_chain.publish".to_string()));
    assert!(
        !event
            .rule_ids
            .contains(&"credential.cloud_harvest".to_string())
    );
    assert!(
        !event
            .rule_ids
            .contains(&"chain.credential_then_publish".to_string())
    );
    assert!(
        !event
            .categories
            .contains(&"credential_harvesting".to_string())
    );
    assert!(event.categories.contains(&"supply_chain".to_string()));
}

#[test]
fn detects_uc002_credential_harvesting_before_publish_in_opencode_fixture() {
    let source = Source {
        client: ClientId::OpenCode,
        kind: SourceKind::LegacyJson,
        source_id: "opencode.legacy_json".to_string(),
        path: PathBuf::from(crate::test_fixture_path(
            "session_stores/opencode/storage/message/session-uc002/uc002-credential-publish.json",
        )),
    };

    let detections = detect_sources(&[source]);

    assert_eq!(detections.len(), 1);
    let event = &detections[0].1;
    assert_eq!(event.session_id, "opencode-uc002-credential-publish");
    assert_eq!(event.severity, "critical");
    assert!(
        event
            .rule_ids
            .contains(&"credential.cloud_harvest".to_string())
    );
    assert!(event.rule_ids.contains(&"supply_chain.publish".to_string()));
    assert!(
        event
            .rule_ids
            .contains(&"chain.credential_then_publish".to_string())
    );
    assert!(
        event
            .categories
            .contains(&"credential_harvesting".to_string())
    );
    assert!(event.categories.contains(&"supply_chain".to_string()));
    assert!(
        event
            .evidence
            .iter()
            .all(|item| item.hash.is_some() && !item.redacted_value.is_empty())
    );
}

#[test]
fn detects_uc002_credential_harvesting_before_publish_in_copilot_fixture() {
    let source = Source {
        client: ClientId::Copilot,
        kind: SourceKind::CopilotProcessLog,
        source_id: "copilot.process_log".to_string(),
        path: PathBuf::from(crate::test_fixture_path(
            "session_stores/copilot/process-uc002.log",
        )),
    };

    let detections = detect_sources(&[source]);

    assert_eq!(detections.len(), 1);
    let event = &detections[0].1;
    assert_eq!(event.session_id, "copilot-uc002-credential-publish");
    assert_eq!(event.severity, "critical");
    assert!(
        event
            .rule_ids
            .contains(&"credential.cloud_harvest".to_string())
    );
    assert!(event.rule_ids.contains(&"supply_chain.publish".to_string()));
    assert!(
        event
            .rule_ids
            .contains(&"chain.credential_then_publish".to_string())
    );
    assert!(
        event
            .categories
            .contains(&"credential_harvesting".to_string())
    );
    assert!(event.categories.contains(&"supply_chain".to_string()));
    assert!(
        event
            .evidence
            .iter()
            .all(|item| item.hash.is_some() && !item.redacted_value.is_empty())
    );
}
