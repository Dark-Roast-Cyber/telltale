use super::*;

#[test]
fn detects_api_key_pattern_in_assistant_context() {
    let sources = discover_sources(&crate::test_fixture_path("session_stores"));
    let detections = detect_sources(&sources);

    let event = detections
        .iter()
        .find(|(_, event)| event.session_id == "api-key-pattern")
        .map(|(_, event)| event)
        .expect("api key detection");
    assert_eq!(event.severity, "low");
    assert!(
        event
            .rule_ids
            .contains(&"credential.api_key.pattern".to_string())
    );
    assert!(event.categories.contains(&"credential_pattern".to_string()));
    assert!(!event.tags.contains(&"chain".to_string()));
    assert!(event.evidence.iter().all(|item| item.hash.is_some()
        && !item.redacted_value.is_empty()
        && !item.redacted_value.contains("ghp_1234567890abcdef1234")));
}

#[test]
fn detects_api_key_pattern_in_session_store_fixture() {
    let source = Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "api-key-pattern".to_string(),
        path: PathBuf::from(crate::test_fixture_path(
            "session_stores/codex/sessions/2026/04/api-key-pattern.jsonl",
        )),
    };

    let detections = detect_sources(&[source]);

    assert_eq!(detections.len(), 1);
    let event = &detections[0].1;
    assert_eq!(event.session_id, "api-key-pattern");
    assert_eq!(event.severity, "low");
    assert!(
        event
            .rule_ids
            .contains(&"credential.api_key.pattern".to_string())
    );
    assert!(event.categories.contains(&"credential_pattern".to_string()));
    assert!(event.evidence.iter().all(|item| item.hash.is_some()
        && !item.redacted_value.is_empty()
        && !item.redacted_value.contains("ghp_1234567890abcdef1234")));
}

#[test]
fn detects_api_key_pattern_in_session_store_fixture_directly() {
    let source = Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "api-key-pattern".to_string(),
        path: PathBuf::from(crate::test_fixture_path(
            "session_stores/codex/sessions/2026/04/api-key-pattern.jsonl",
        )),
    };

    let detections = detect_sources(&[source]);

    assert_eq!(detections.len(), 1);
    let event = &detections[0].1;
    assert_eq!(event.session_id, "api-key-pattern");
    assert_eq!(event.severity, "low");
    assert!(
        event
            .rule_ids
            .contains(&"credential.api_key.pattern".to_string())
    );
    assert!(event.categories.contains(&"credential_pattern".to_string()));
    assert!(event.evidence.iter().all(|item| item.hash.is_some()
        && !item.redacted_value.is_empty()
        && !item.redacted_value.contains("ghp_1234567890abcdef1234")));
}

#[test]
fn detects_and_redacts_aws_and_slack_token_patterns_in_rule_sample() {
    let source = Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "aws-slack-token-pattern".to_string(),
        path: PathBuf::from(crate::test_fixture_path(
            "rule_samples/aws-slack-token-pattern.jsonl",
        )),
    };

    let detections = detect_sources(&[source]);

    assert_eq!(detections.len(), 1);
    let event = &detections[0].1;
    assert_eq!(event.session_id, "aws-slack-token-pattern");
    assert_eq!(event.severity, "low");
    assert!(
        event
            .rule_ids
            .contains(&"credential.api_key.pattern".to_string())
    );
    assert!(event.categories.contains(&"credential_pattern".to_string()));
    assert!(event.evidence.iter().all(|item| {
        item.hash.is_some()
            && !item.redacted_value.is_empty()
            && !item.redacted_value.contains("AKIA1234567890ABCDEF")
            && !item.redacted_value.contains("xoxb-1234567890abcdefABCDE")
    }));
}

#[test]
fn detects_and_redacts_jwt_and_bearer_token_patterns_in_rule_sample() {
    let source = Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "jwt-bearer-token-pattern".to_string(),
        path: PathBuf::from(crate::test_fixture_path(
            "rule_samples/jwt-bearer-token-pattern.jsonl",
        )),
    };

    let detections = detect_sources(&[source]);

    assert_eq!(detections.len(), 1);
    let event = &detections[0].1;
    assert_eq!(event.session_id, "jwt-bearer-token-pattern");
    assert_eq!(event.severity, "low");
    assert!(
        event
            .rule_ids
            .contains(&"credential.api_key.pattern".to_string())
    );
    assert!(event.categories.contains(&"credential_pattern".to_string()));
    assert!(event.evidence.iter().all(|item| {
        item.hash.is_some()
            && !item.redacted_value.is_empty()
            && !item
                .redacted_value
                .contains("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ")
            && !item
                .redacted_value
                .contains("fixture_oauth_token_1234567890abcdef")
    }));
}

#[test]
fn detects_and_redacts_jwt_and_bearer_token_patterns_in_session_store_fixture() {
    let source = Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "jwt-bearer-token-pattern".to_string(),
        path: PathBuf::from(crate::test_fixture_path(
            "session_stores/codex/sessions/2026/04/jwt-bearer-token-pattern.jsonl",
        )),
    };

    let detections = detect_sources(&[source]);

    assert_eq!(detections.len(), 1);
    let event = &detections[0].1;
    assert_eq!(event.session_id, "jwt-bearer-token-pattern");
    assert_eq!(event.severity, "low");
    assert!(
        event
            .rule_ids
            .contains(&"credential.api_key.pattern".to_string())
    );
    assert!(event.categories.contains(&"credential_pattern".to_string()));
    assert!(event.evidence.iter().all(|item| {
        item.hash.is_some()
            && !item.redacted_value.is_empty()
            && !item
                .redacted_value
                .contains("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ")
            && !item
                .redacted_value
                .contains("fixture_session_token_1234567890abcdef")
    }));
}

#[test]
fn detects_private_key_read_in_session_store_fixture() {
    let source = Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "private-key-read".to_string(),
        path: PathBuf::from(crate::test_fixture_path(
            "session_stores/codex/sessions/2026/04/private-key-read.jsonl",
        )),
    };

    let detections = detect_sources(&[source]);

    assert_eq!(detections.len(), 1);
    let event = &detections[0].1;
    assert_eq!(event.session_id, "private-key-read");
    assert_eq!(event.severity, "high");
    assert!(
        event
            .rule_ids
            .contains(&"secret.private_key.read".to_string())
    );
    assert!(event.categories.contains(&"secret_access".to_string()));
    assert!(!event.evidence.is_empty());
    assert!(event.evidence.iter().all(|item| {
        item.hash.is_some()
            && !item.redacted_value.is_empty()
            && !item.redacted_value.contains(".env")
            && !item.redacted_value.contains("darkroastcyber.io")
            && !item.redacted_value.contains("base64 --decode")
    }));
    assert!(
        event
            .evidence
            .iter()
            .all(|item| !item.redacted_value.contains("id_rsa"))
    );
}

#[test]
fn detects_private_key_header_fixture_without_leaking_header() {
    let source = Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "private-key-header-pattern".to_string(),
        path: PathBuf::from(crate::test_fixture_path(
            "rule_samples/private-key-header-pattern.jsonl",
        )),
    };

    let detections = detect_sources(&[source]);

    assert_eq!(detections.len(), 1);
    let event = &detections[0].1;
    assert_eq!(event.session_id, "private-key-header-pattern");
    assert_eq!(event.severity, "medium");
    assert!(
        event
            .rule_ids
            .contains(&"secret.private_key.read".to_string())
    );
    assert!(event.categories.contains(&"secret_access".to_string()));
    assert!(!event.evidence.is_empty());
    assert!(event.evidence.iter().all(|item| {
        item.hash.is_some()
            && !item.redacted_value.contains("BEGIN")
            && !item.redacted_value.contains("END")
            && !item.redacted_value.contains("PRIVATE KEY")
            && !item.redacted_value.contains("OpenSSH")
    }));
}

#[test]
fn detects_secret_network_chain_in_session_store_fixture() {
    let source = Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "secret-network-chain".to_string(),
        path: PathBuf::from(crate::test_fixture_path(
            "session_stores/codex/sessions/2026/04/secret-network-chain.jsonl",
        )),
    };

    let detections = detect_sources(&[source]);

    assert_eq!(detections.len(), 1);
    let event = &detections[0].1;
    assert_eq!(event.session_id, "secret-network-chain");
    assert_eq!(event.severity, "critical");
    assert!(event.categories.contains(&"secret_access".to_string()));
    assert!(event.categories.contains(&"download".to_string()));
    assert!(event.rule_ids.contains(&"secret.env.read".to_string()));
    assert!(event.rule_ids.contains(&"network.download".to_string()));
    assert!(
        event
            .rule_ids
            .contains(&"chain.secret_then_network".to_string())
    );
    assert!(event.tags.contains(&"chain".to_string()));
    assert!(event.evidence.iter().all(|item| {
        item.hash.is_some()
            && !item.redacted_value.is_empty()
            && !item.redacted_value.contains(".env")
            && !item.redacted_value.contains("darkroastcyber.io")
    }));
}

#[test]
fn detects_secret_then_network_chain() {
    let source = Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "secret-network-chain".to_string(),
        path: PathBuf::from(crate::test_fixture_path(
            "rule_samples/secret-network-chain.jsonl",
        )),
    };

    let detections = detect_sources(&[source]);

    assert_eq!(detections.len(), 1);
    let event = &detections[0].1;
    assert_eq!(event.session_id, "secret-network-chain");
    assert_eq!(event.severity, "critical");
    assert!(event.rule_ids.contains(&"secret.env.read".to_string()));
    assert!(event.rule_ids.contains(&"network.download".to_string()));
    assert!(
        event
            .rule_ids
            .contains(&"chain.secret_then_network".to_string())
    );
    assert!(event.categories.contains(&"secret_access".to_string()));
    assert!(event.categories.contains(&"download".to_string()));
}

#[test]
fn detects_secret_then_network_chain_in_session_store_fixture() {
    let source = Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "secret-network-chain".to_string(),
        path: PathBuf::from(crate::test_fixture_path(
            "session_stores/codex/sessions/2026/04/secret-network-chain.jsonl",
        )),
    };

    let detections = detect_sources(&[source]);

    assert_eq!(detections.len(), 1);
    let event = &detections[0].1;
    assert_eq!(event.session_id, "secret-network-chain");
    assert_eq!(event.severity, "critical");
    assert!(event.rule_ids.contains(&"secret.env.read".to_string()));
    assert!(event.rule_ids.contains(&"network.download".to_string()));
    assert!(
        event
            .rule_ids
            .contains(&"chain.secret_then_network".to_string())
    );
    assert!(event.categories.contains(&"secret_access".to_string()));
    assert!(event.categories.contains(&"download".to_string()));
}

#[test]
fn ignores_copied_auth_failure_boilerplate_for_secret_access() {
    let source = Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "secret-access-auth-log".to_string(),
        path: PathBuf::from(crate::test_fixture_path(
            "session_stores/codex/sessions/2026/04/secret-access-auth-log.jsonl",
        )),
    };

    let detections = detect_sources(&[source]);

    assert!(detections.is_empty());
}

#[test]
fn ignores_opencode_auth_failure_boilerplate_for_secret_access() {
    let source = Source {
        client: ClientId::OpenCode,
        kind: SourceKind::LegacyJson,
        source_id: "opencode.legacy_json".to_string(),
        path: PathBuf::from(crate::test_fixture_path(
            "session_stores/opencode/storage/message/session-noise/secret-access-auth-log.json",
        )),
    };

    let detections = detect_sources(&[source]);

    assert!(
        !detections
            .iter()
            .any(|(_, event)| event.event_type == "detection")
    );
}

#[test]
fn detects_secret_then_network_chain_in_tool_calls() {
    let source = Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "secret-network-chain".to_string(),
        path: PathBuf::from(crate::test_fixture_path(
            "rule_samples/secret-network-chain.jsonl",
        )),
    };

    let detections = detect_sources(&[source]);

    assert_eq!(detections.len(), 1);
    let event = &detections[0].1;
    assert_eq!(event.session_id, "secret-network-chain");
    assert!(event.rule_ids.contains(&"secret.env.read".to_string()));
    assert!(event.rule_ids.contains(&"network.download".to_string()));
    assert!(
        event
            .rule_ids
            .contains(&"chain.secret_then_network".to_string())
    );
    assert!(event.categories.contains(&"secret_access".to_string()));
    assert!(event.categories.contains(&"download".to_string()));
}
