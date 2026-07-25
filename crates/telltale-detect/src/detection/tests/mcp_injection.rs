use super::*;

#[test]
fn detects_uc001_mcp_injection_chain_only() {
    let sources = discover_sources(&crate::test_fixture_path("session_stores"));
    let detections = detect_sources(&sources);

    assert_eq!(detections.len(), 36);
    let event = detections
        .iter()
        .find(|(_, event)| event.session_id == "uc001-positive")
        .map(|(_, event)| event)
        .expect("uc001 detection");
    assert_eq!(event.event_type, "detection");
    assert_eq!(event.severity, "critical");
    assert_eq!(event.session_id, "uc001-positive");
    assert_eq!(event.tool_name.as_deref(), Some("repo_status"));
    assert!(
        event
            .rule_ids
            .contains(&"mcp.tool_metadata.prompt_injection".to_string())
    );
    assert!(
        event
            .rule_ids
            .contains(&"network.controlled_test_domain.darkroast".to_string())
    );
    assert!(
        event
            .rule_ids
            .contains(&"chain.mcp_injection_then_egress".to_string())
    );
    assert!(
        event
            .categories
            .contains(&"mcp_prompt_injection".to_string())
    );
    assert!(event.categories.contains(&"exfiltration".to_string()));
    for item in &event.evidence {
        assert!(!item.redacted_value.contains(".env"));
        assert!(!item.redacted_value.contains("mcp-lab"));
        assert!(item.hash.is_some());
    }
}

#[test]
fn uc001_critical_fixture_coverage_includes_every_supported_client() {
    let supported_clients = supported_clients()
        .iter()
        .map(|client| client.id.as_str())
        .collect::<BTreeSet<_>>();
    let sources = discover_sources(&crate::test_fixture_path("session_stores"));
    let detections = detect_sources(&sources);

    let covered_clients = detections
        .iter()
        .filter(|(_, event)| {
            event.severity == "critical"
                && event
                    .rule_ids
                    .contains(&"mcp.tool_metadata.prompt_injection".to_string())
                && event
                    .rule_ids
                    .contains(&"chain.mcp_injection_then_egress".to_string())
        })
        .map(|(_, event)| event.client.as_str())
        .collect::<BTreeSet<_>>();

    assert_eq!(covered_clients, supported_clients);
}

#[test]
fn detects_uc001_positive_in_session_store_fixture() {
    let source = Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "uc001-positive".to_string(),
        path: PathBuf::from(crate::test_fixture_path(
            "session_stores/codex/sessions/2026/04/uc001-positive.jsonl",
        )),
    };

    let detections = detect_sources(&[source]);

    assert_eq!(detections.len(), 1);
    let event = &detections[0].1;
    assert_eq!(event.session_id, "uc001-positive");
    assert_eq!(event.severity, "critical");
    assert_eq!(event.tool_name.as_deref(), Some("repo_status"));
    assert!(
        event
            .rule_ids
            .contains(&"mcp.tool_metadata.prompt_injection".to_string())
    );
    assert!(
        event
            .rule_ids
            .contains(&"network.controlled_test_domain.darkroast".to_string())
    );
    assert!(
        event
            .rule_ids
            .contains(&"chain.mcp_injection_then_egress".to_string())
    );
    assert!(event.evidence.iter().all(|item| {
        item.hash.is_some()
            && !item.redacted_value.contains(".env")
            && !item.redacted_value.contains("darkroastcyber.io")
    }));
}

#[test]
fn ignores_benign_controlled_domain_mentions_in_user_text() {
    let sources = discover_sources(&crate::test_fixture_path("session_stores"));
    let detections = detect_sources(&sources);

    assert!(
        !detections
            .iter()
            .any(|(_, event)| event.session_id == "uc001-negative-domain-user-text")
    );
}

#[test]
fn ignores_benign_mcp_user_text_fixture() {
    let sources = discover_sources(&crate::test_fixture_path("session_stores"));
    let detections = detect_sources(&sources);

    assert!(
        !detections
            .iter()
            .any(|(_, event)| event.session_id == "uc001-negative-mcp-user-text")
    );
}

#[test]
fn ignores_benign_mcp_user_text_session_fixture() {
    let source = Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "uc001-negative-mcp-user-text".to_string(),
        path: PathBuf::from(crate::test_fixture_path(
            "session_stores/codex/sessions/2026/04/uc001-negative-mcp-user-text.jsonl",
        )),
    };

    let detections = detect_sources(&[source]);

    assert!(detections.is_empty());
}

#[test]
fn ignores_benign_normal_mcp_fixture() {
    let sources = discover_sources(&crate::test_fixture_path("session_stores"));
    let detections = detect_sources(&sources);

    assert!(
        !detections
            .iter()
            .any(|(_, event)| event.session_id == "uc001-negative-normal-mcp")
    );
}

#[test]
fn ignores_benign_normal_mcp_session_fixture() {
    let source = Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "uc001-negative-normal-mcp".to_string(),
        path: PathBuf::from(crate::test_fixture_path(
            "session_stores/codex/sessions/2026/04/uc001-negative-normal-mcp.jsonl",
        )),
    };

    let detections = detect_sources(&[source]);

    assert!(detections.is_empty());
}

#[test]
fn ignores_benign_tools_list_session_fixture() {
    let source = Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "uc001-negative-tools-list".to_string(),
        path: PathBuf::from(crate::test_fixture_path(
            "session_stores/codex/sessions/2026/04/uc001-negative-tools-list.jsonl",
        )),
    };

    let detections = detect_sources(&[source]);

    assert!(detections.is_empty());
}

#[test]
fn detects_mcp_server_enumeration_session_fixture() {
    let source = Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "mcp-server-enumeration".to_string(),
        path: PathBuf::from(crate::test_fixture_path(
            "session_stores/codex/sessions/2026/04/mcp-server-enumeration.jsonl",
        )),
    };

    let detections = detect_sources(&[source]);

    let event = detections
        .iter()
        .find(|(_, event)| event.session_id == "mcp-server-enumeration")
        .map(|(_, event)| event)
        .expect("mcp enumeration detection");
    assert_eq!(event.event_type, "detection");
    assert_eq!(event.severity, "low");
    assert!(
        event
            .rule_ids
            .contains(&"mcp.server_enumeration".to_string())
    );
    assert!(event.categories.contains(&"mcp_enumeration".to_string()));
    assert!(event.evidence.iter().any(|item| item.field == "command"
        || item.field == "arguments"
        || item.field == "tool_result"));
    assert!(
        !event
            .evidence
            .iter()
            .any(|item| item.field == "assistant_context")
    );
    assert!(event.evidence.iter().all(|item| item.hash.is_some()));
}

#[test]
fn ignores_benign_normal_mcp_tool_result_session_fixture() {
    let source = Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "normal-mcp-tool-result".to_string(),
        path: PathBuf::from(crate::test_fixture_path(
            "session_stores/codex/sessions/2026/04/normal-mcp-tool-result.jsonl",
        )),
    };

    let detections = detect_sources(&[source]);

    assert!(detections.is_empty());
}

#[test]
fn ignores_benign_server_instructions_fixture() {
    let sources = discover_sources(&crate::test_fixture_path("session_stores"));
    let detections = detect_sources(&sources);

    assert!(
        !detections
            .iter()
            .any(|(_, event)| event.session_id == "uc001-negative-server-instructions")
    );
}

#[test]
fn ignores_benign_server_instructions_session_fixture() {
    let source = Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "uc001-negative-server-instructions".to_string(),
        path: PathBuf::from(crate::test_fixture_path(
            "session_stores/codex/sessions/2026/04/uc001-negative-server-instructions.jsonl",
        )),
    };

    let detections = detect_sources(&[source]);

    assert!(detections.is_empty());
}

#[test]
fn detects_uc001_positive_server_instructions_in_session_store_fixture() {
    let source = Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "uc001-positive-server-instructions".to_string(),
        path: PathBuf::from(crate::test_fixture_path(
            "session_stores/codex/sessions/2026/04/uc001-positive-server-instructions.jsonl",
        )),
    };

    let detections = detect_sources(&[source]);

    let event = detections
        .iter()
        .find(|(_, event)| event.session_id == "uc001-positive-server-instructions")
        .map(|(_, event)| event)
        .expect("server instructions detection");
    assert_eq!(event.event_type, "detection");
    assert_eq!(event.severity, "critical");
    assert_eq!(event.tool_name.as_deref(), Some("repo_status"));
    assert!(
        event
            .rule_ids
            .contains(&"mcp.tool_metadata.prompt_injection".to_string())
    );
    assert!(
        event
            .categories
            .contains(&"mcp_prompt_injection".to_string())
    );
    assert!(event.evidence.iter().all(|item| {
        item.hash.is_some()
            && !item.redacted_value.contains(".env")
            && !item.redacted_value.contains("darkroastcyber.io")
    }));
}

#[test]
fn detects_uc001_positive_tool_description_in_session_store_fixture() {
    let source = Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "uc001-positive-tool-description".to_string(),
        path: PathBuf::from(crate::test_fixture_path(
            "session_stores/codex/sessions/2026/04/uc001-positive-tool-description.jsonl",
        )),
    };

    let detections = detect_sources(&[source]);

    let event = detections
        .iter()
        .find(|(_, event)| event.session_id == "uc001-positive-tool-description")
        .map(|(_, event)| event)
        .expect("tool description detection");
    assert_eq!(event.event_type, "detection");
    assert_eq!(event.severity, "critical");
    assert_eq!(event.tool_name.as_deref(), Some("repo_status"));
    assert!(
        event
            .rule_ids
            .contains(&"mcp.tool_metadata.prompt_injection".to_string())
    );
    assert!(
        event
            .rule_ids
            .contains(&"approval.bypass.context".to_string())
    );
    assert!(
        event
            .categories
            .contains(&"mcp_prompt_injection".to_string())
    );
    assert!(event.categories.contains(&"approval_bypass".to_string()));
    assert!(
        event
            .evidence
            .iter()
            .any(|item| item.field == "assistant_context" || item.field == "tool_result")
    );
    assert!(event.evidence.iter().all(|item| {
        item.hash.is_some()
            && !item.redacted_value.contains(".env")
            && !item.redacted_value.contains("darkroastcyber.io")
    }));
}

#[test]
fn detects_uc001_positive_parameter_description_in_session_store_fixture() {
    let source = Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "uc001-positive-parameter-description".to_string(),
        path: PathBuf::from(crate::test_fixture_path(
            "session_stores/codex/sessions/2026/04/uc001-positive-parameter-description.jsonl",
        )),
    };

    let detections = detect_sources(&[source]);

    let event = detections
        .iter()
        .find(|(_, event)| event.session_id == "uc001-positive-parameter-description")
        .map(|(_, event)| event)
        .expect("parameter description detection");
    assert_eq!(event.event_type, "detection");
    assert_eq!(event.severity, "critical");
    assert_eq!(event.tool_name.as_deref(), Some("repo_status"));
    assert!(
        event
            .rule_ids
            .contains(&"mcp.tool_metadata.prompt_injection".to_string())
    );
    assert!(
        event
            .categories
            .contains(&"mcp_prompt_injection".to_string())
    );
    assert!(event.evidence.iter().all(|item| {
        item.hash.is_some()
            && !item.redacted_value.contains(".env")
            && !item.redacted_value.contains("darkroastcyber.io")
    }));
}

#[test]
fn detects_uc001_positive_reversed_injection_in_session_store_fixture() {
    let source = Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "uc001-positive-reversed-injection".to_string(),
        path: PathBuf::from(crate::test_fixture_path(
            "session_stores/codex/sessions/2026/04/uc001-positive-reversed-injection.jsonl",
        )),
    };

    let detections = detect_sources(&[source]);

    let event = detections
        .iter()
        .find(|(_, event)| event.session_id == "uc001-positive-reversed-injection")
        .map(|(_, event)| event)
        .expect("reversed injection detection");
    assert_eq!(event.event_type, "detection");
    assert_eq!(event.severity, "critical");
    assert_eq!(event.tool_name.as_deref(), Some("repo_status"));
    assert!(
        event
            .rule_ids
            .contains(&"mcp.tool_metadata.prompt_injection".to_string())
    );
    assert!(
        event
            .rule_ids
            .contains(&"chain.mcp_injection_then_egress".to_string())
    );
    assert!(
        event
            .categories
            .contains(&"mcp_prompt_injection".to_string())
    );
    assert!(event.evidence.iter().all(|item| {
        item.hash.is_some()
            && !item.redacted_value.contains(".env")
            && !item.redacted_value.contains("darkroastcyber.io")
    }));
}

#[test]
fn detects_mcp_injection_in_nested_codex_tool_call_arguments() {
    let source = Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "codex-payload-arguments-injection".to_string(),
        path: PathBuf::from(crate::test_fixture_path(
            "rule_samples/codex-payload-arguments-injection.jsonl",
        )),
    };

    let detections = detect_sources(&[source]);

    assert_eq!(detections.len(), 1);
    let event = &detections[0].1;
    assert_eq!(event.session_id, "codex-payload-arguments-injection");
    assert_eq!(event.severity, "critical");
    assert_eq!(event.tool_name.as_deref(), Some("repo_status"));
    assert!(
        event
            .rule_ids
            .contains(&"mcp.tool_metadata.prompt_injection".to_string())
    );
    assert!(
        event
            .rule_ids
            .contains(&"network.controlled_test_domain.darkroast".to_string())
    );
    assert!(
        event
            .rule_ids
            .contains(&"chain.mcp_injection_then_egress".to_string())
    );
    assert!(
        event
            .evidence
            .iter()
            .any(|item| item.rule_id.as_deref() == Some("mcp.tool_metadata.prompt_injection"))
    );
    assert!(event.evidence.iter().all(|item| {
        item.hash.is_some()
            && !item.redacted_value.contains(".env")
            && !item.redacted_value.contains("darkroastcyber.io")
    }));
}

#[test]
fn detects_uc001_positive_compliance_tool_name_variant() {
    let source = Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "uc001-positive-compliance-tool".to_string(),
        path: PathBuf::from(crate::test_fixture_path(
            "session_stores/codex/sessions/2026/04/uc001-positive-compliance-tool.jsonl",
        )),
    };

    let detections = detect_sources(&[source]);

    assert_eq!(detections.len(), 1);
    let event = &detections[0].1;
    assert_eq!(event.session_id, "uc001-positive-compliance-tool");
    assert_eq!(event.severity, "critical");
    assert_eq!(event.tool_name.as_deref(), Some("get_compliance_status"));
    assert!(
        event
            .rule_ids
            .contains(&"mcp.tool_metadata.prompt_injection".to_string())
    );
    assert!(
        event
            .rule_ids
            .contains(&"network.controlled_test_domain.darkroast".to_string())
    );
    assert!(
        event
            .rule_ids
            .contains(&"chain.mcp_injection_then_egress".to_string())
    );
    assert!(
        event
            .categories
            .contains(&"mcp_prompt_injection".to_string())
    );
    assert!(event.evidence.iter().all(|item| {
        item.hash.is_some()
            && !item.redacted_value.contains(".env")
            && !item.redacted_value.contains("darkroastcyber.io")
    }));
}

#[test]
fn ignores_controlled_domain_mentions_in_isolated_user_text_fixture() {
    let source = Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "controlled-domain-user-text".to_string(),
        path: PathBuf::from(crate::test_fixture_path(
            "rule_samples/controlled-domain-user-text.jsonl",
        )),
    };

    let detections = detect_sources(&[source]);

    assert!(detections.is_empty());
}

#[test]
fn ignores_benign_controlled_domain_mentions_in_session_store_user_text() {
    let source = Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "controlled-domain-user-text".to_string(),
        path: PathBuf::from(crate::test_fixture_path(
            "session_stores/codex/sessions/2026/04/controlled-domain-user-text.jsonl",
        )),
    };

    let detections = detect_sources(&[source]);

    assert!(detections.is_empty());
}

#[test]
fn ignores_benign_controlled_domain_mentions_in_negative_domain_user_text_session_fixture() {
    let source = Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "uc001-negative-domain-user-text".to_string(),
        path: PathBuf::from(crate::test_fixture_path(
            "session_stores/codex/sessions/2026/04/uc001-negative-domain-user-text.jsonl",
        )),
    };

    let detections = detect_sources(&[source]);

    assert!(detections.is_empty());
}

#[test]
fn ignores_benign_controlled_domain_mentions_in_session_store_assistant_text() {
    let source = Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "controlled-domain-assistant-text".to_string(),
        path: PathBuf::from(crate::test_fixture_path(
            "session_stores/codex/sessions/2026/04/controlled-domain-assistant-text.jsonl",
        )),
    };

    let detections = detect_sources(&[source]);

    assert!(detections.is_empty());
}

#[test]
fn ignores_benign_controlled_domain_mentions_in_tool_results() {
    let sources = discover_sources(&crate::test_fixture_path("session_stores"));
    let detections = detect_sources(&sources);

    assert!(
        !detections
            .iter()
            .any(|(_, event)| event.session_id == "uc001-negative-domain-tool-result")
    );
}

#[test]
fn ignores_benign_controlled_domain_mentions_in_session_store_tool_result_fixture() {
    let source = Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "uc001-negative-domain-tool-result".to_string(),
        path: PathBuf::from(crate::test_fixture_path(
            "session_stores/codex/sessions/2026/04/uc001-negative-domain-tool-result.jsonl",
        )),
    };

    let detections = detect_sources(&[source]);

    assert!(detections.is_empty());
}

#[test]
fn detects_uc001_positive_tool_result_in_session_store_fixture() {
    let source = Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "tool-result-injection".to_string(),
        path: PathBuf::from(crate::test_fixture_path(
            "session_stores/codex/sessions/2026/04/tool-result-injection.jsonl",
        )),
    };

    let detections = detect_sources(&[source]);

    let event = detections
        .iter()
        .find(|(_, event)| event.session_id == "tool-result-injection")
        .map(|(_, event)| event)
        .expect("tool result injection detection");
    assert_eq!(event.event_type, "detection");
    assert_eq!(event.severity, "critical");
    assert_eq!(event.tool_name.as_deref(), Some("repo_status"));
    assert!(
        event
            .rule_ids
            .contains(&"mcp.tool_metadata.prompt_injection".to_string())
    );
    assert!(
        event
            .rule_ids
            .contains(&"approval.bypass.context".to_string())
    );
    assert!(!event.rule_ids.contains(&"secret.env.read".to_string()));
    assert!(
        event
            .categories
            .contains(&"mcp_prompt_injection".to_string())
    );
    assert!(event.categories.contains(&"approval_bypass".to_string()));
    assert!(!event.categories.contains(&"secret_access".to_string()));
    assert!(
        event
            .evidence
            .iter()
            .any(|item| item.field == "tool_result")
    );
    assert!(event.evidence.iter().all(|item| {
        item.hash.is_some()
            && !item.redacted_value.contains(".env")
            && !item.redacted_value.contains("darkroastcyber.io")
    }));
}

#[test]
fn ignores_benign_mcp_tool_results_without_injection_language() {
    let source = Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "normal-mcp-tool-result".to_string(),
        path: PathBuf::from(crate::test_fixture_path(
            "rule_samples/normal-mcp-tool-result.jsonl",
        )),
    };

    let detections = detect_sources(&[source]);

    assert!(detections.is_empty());
}

#[test]
fn ignores_benign_mcp_server_instructions_without_injection_language() {
    let source = Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "uc001-negative-server-instructions".to_string(),
        path: PathBuf::from(crate::test_fixture_path(
            "session_stores/codex/sessions/2026/04/uc001-negative-server-instructions.jsonl",
        )),
    };

    let detections = detect_sources(&[source]);

    assert!(detections.is_empty());
}

#[test]
fn ignores_benign_mcp_tool_metadata_without_injection_language() {
    let source = Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "uc001-negative-normal-mcp".to_string(),
        path: PathBuf::from(crate::test_fixture_path(
            "session_stores/codex/sessions/2026/04/uc001-negative-normal-mcp.jsonl",
        )),
    };

    let detections = detect_sources(&[source]);

    assert!(detections.is_empty());
}
