use super::*;

#[test]
fn detects_download_execute_chain_in_session_store_fixture() {
    let source = Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "codex.sessions".to_string(),
        path: PathBuf::from(crate::test_fixture_path(
            "session_stores/codex/sessions/2026/04/download-execute-chain.jsonl",
        )),
    };

    let detections = detect_sources(&[source]);

    assert_eq!(detections.len(), 1);
    let event = &detections[0].1;
    assert_eq!(event.session_id, "download-execute-chain");
    assert_eq!(event.severity, "high");
    assert!(event.categories.contains(&"download".to_string()));
    assert!(event.categories.contains(&"execution".to_string()));
    assert!(event.rule_ids.contains(&"network.download".to_string()));
    assert!(event.rule_ids.contains(&"execution.shell".to_string()));
    assert!(
        event
            .rule_ids
            .contains(&"chain.download_then_execute".to_string())
    );
    assert!(event.evidence.iter().all(|item| {
        item.hash.is_some()
            && !item.redacted_value.is_empty()
            && !item.redacted_value.contains(".env")
            && !item.redacted_value.contains("darkroastcyber.io")
    }));
}

#[test]
fn detects_download_then_execute_chain_in_session_store_fixture() {
    let source = Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "codex.sessions".to_string(),
        path: PathBuf::from(crate::test_fixture_path(
            "session_stores/codex/sessions/2026/04/download-execute-chain.jsonl",
        )),
    };

    let detections = detect_sources(&[source]);

    assert_eq!(detections.len(), 1);
    let event = &detections[0].1;
    assert_eq!(event.session_id, "download-execute-chain");
    assert_eq!(event.severity, "high");
    assert!(event.rule_ids.contains(&"network.download".to_string()));
    assert!(event.rule_ids.contains(&"execution.shell".to_string()));
    assert!(
        event
            .rule_ids
            .contains(&"chain.download_then_execute".to_string())
    );
    assert!(event.categories.contains(&"download".to_string()));
    assert!(event.categories.contains(&"execution".to_string()));
    assert!(!event.evidence.is_empty());
    assert!(event.evidence.iter().all(|item| {
        item.hash.is_some()
            && !item.redacted_value.is_empty()
            && !item.redacted_value.contains(".env")
            && !item.redacted_value.contains("darkroastcyber.io")
    }));
    assert!(
        event
            .evidence
            .iter()
            .all(|item| !item.redacted_value.contains("darkroastcyber.io"))
    );
}

#[test]
fn detects_encoded_payload_chain_in_session_store_fixture() {
    let source = Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "codex.sessions".to_string(),
        path: PathBuf::from(crate::test_fixture_path(
            "session_stores/codex/sessions/2026/04/encoded-payload-chain.jsonl",
        )),
    };

    let detections = detect_sources(&[source]);

    assert_eq!(detections.len(), 1);
    let event = &detections[0].1;
    assert_eq!(event.session_id, "encoded-payload-chain");
    assert_eq!(event.severity, "high");
    assert!(event.rule_ids.contains(&"execution.shell".to_string()));
    assert!(
        event
            .rule_ids
            .contains(&"execution.encoded_payload".to_string())
    );
    assert!(
        event
            .rule_ids
            .contains(&"chain.shell_encoded_payload".to_string())
    );
    assert!(event.categories.contains(&"execution".to_string()));
    assert!(event.tags.contains(&"chain".to_string()));
    assert!(
        event
            .evidence
            .iter()
            .any(|item| item.field == "command" || item.field == "arguments")
    );
    assert!(event.evidence.iter().all(|item| {
        item.hash.is_some()
            && !item.redacted_value.is_empty()
            && !item.redacted_value.contains(".env")
            && !item.redacted_value.contains("darkroastcyber.io")
    }));
}

#[test]
fn detects_install_then_persistence_chain_in_session_store_fixture() {
    let source = Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "codex.sessions".to_string(),
        path: PathBuf::from(crate::test_fixture_path(
            "session_stores/codex/sessions/2026/04/install-persistence-chain.jsonl",
        )),
    };

    let detections = detect_sources(&[source]);

    assert_eq!(detections.len(), 1);
    let event = &detections[0].1;
    assert_eq!(event.session_id, "install-persistence-chain");
    assert_eq!(event.severity, "critical");
    assert!(
        event
            .rule_ids
            .contains(&"install.package_manager".to_string())
    );
    assert!(
        event
            .rule_ids
            .contains(&"persistence.shell_profile".to_string())
    );
    assert!(
        event
            .rule_ids
            .contains(&"chain.install_then_persistence".to_string())
    );
    assert!(event.categories.contains(&"install".to_string()));
    assert!(event.categories.contains(&"persistence".to_string()));
    assert!(
        event
            .evidence
            .iter()
            .any(|item| item.field == "command" || item.field == "arguments")
    );
    assert!(event.evidence.iter().all(|item| {
        item.hash.is_some()
            && !item.redacted_value.is_empty()
            && !item.redacted_value.contains("darkroastcyber.io")
            && !item.redacted_value.contains("pip install")
            && !item.redacted_value.contains("~/.bashrc")
    }));
}

#[test]
fn detects_download_then_execute_chain_in_tool_calls() {
    let source = Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "codex.sessions".to_string(),
        path: PathBuf::from(crate::test_fixture_path(
            "rule_samples/download-execute-chain.jsonl",
        )),
    };

    let detections = detect_sources(&[source]);

    assert_eq!(detections.len(), 1);
    let event = &detections[0].1;
    assert_eq!(event.session_id, "download-execute-chain");
    assert!(event.rule_ids.contains(&"network.download".to_string()));
    assert!(event.rule_ids.contains(&"execution.shell".to_string()));
    assert!(
        event
            .rule_ids
            .contains(&"chain.download_then_execute".to_string())
    );
    assert!(event.categories.contains(&"download".to_string()));
    assert!(event.categories.contains(&"execution".to_string()));
}

#[test]
fn detects_encoded_payload_chain_in_tool_calls() {
    let source = Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "codex.sessions".to_string(),
        path: PathBuf::from(crate::test_fixture_path(
            "session_stores/codex/sessions/2026/04/encoded-payload-chain.jsonl",
        )),
    };

    let detections = detect_sources(&[source]);

    assert_eq!(detections.len(), 1);
    let event = &detections[0].1;
    assert_eq!(event.session_id, "encoded-payload-chain");
    assert!(event.rule_ids.contains(&"execution.shell".to_string()));
    assert!(
        event
            .rule_ids
            .contains(&"execution.encoded_payload".to_string())
    );
    assert!(
        event
            .rule_ids
            .contains(&"chain.shell_encoded_payload".to_string())
    );
    assert!(event.categories.contains(&"execution".to_string()));
    assert_eq!(event.severity, "high");
}

#[test]
fn detects_install_then_persistence_chain_in_tool_calls() {
    let source = Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "codex.sessions".to_string(),
        path: PathBuf::from(crate::test_fixture_path(
            "session_stores/codex/sessions/2026/04/install-persistence-chain.jsonl",
        )),
    };

    let detections = detect_sources(&[source]);

    assert_eq!(detections.len(), 1);
    let event = &detections[0].1;
    assert_eq!(event.session_id, "install-persistence-chain");
    assert!(
        event
            .rule_ids
            .contains(&"install.package_manager".to_string())
    );
    assert!(
        event
            .rule_ids
            .contains(&"persistence.shell_profile".to_string())
    );
    assert!(
        event
            .rule_ids
            .contains(&"chain.install_then_persistence".to_string())
    );
    assert!(event.categories.contains(&"install".to_string()));
    assert!(event.categories.contains(&"persistence".to_string()));
}
