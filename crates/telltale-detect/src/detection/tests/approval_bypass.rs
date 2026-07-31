use super::*;

#[test]
fn ignores_quoted_approval_bypass_tool_result_session_fixture() {
    let source = Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "codex.sessions".to_string(),
        path: PathBuf::from(crate::test_fixture_path(
            "session_stores/codex/sessions/2026/04/approval-bypass-tool-result.jsonl",
        )),
    };

    let detections = detect_sources(&[source]);

    assert!(detections.is_empty());
}

#[test]
fn ignores_quoted_approval_bypass_user_text_session_fixture() {
    let source = Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "codex.sessions".to_string(),
        path: PathBuf::from(crate::test_fixture_path(
            "session_stores/codex/sessions/2026/04/approval-bypass-user-text.jsonl",
        )),
    };

    let detections = detect_sources(&[source]);

    assert!(detections.is_empty());
}

#[test]
fn ignores_benign_controlled_domain_mentions_in_user_text_session_fixture() {
    let sources = discover_sources_best_effort(&crate::test_fixture_path("session_stores"));
    let detections = detect_sources(&sources);

    assert!(
        !detections
            .iter()
            .any(|(_, event)| event.session_id == "uc001-negative-domain-only")
    );
}

#[test]
fn ignores_benign_controlled_domain_mentions_in_session_store_domain_only_fixture() {
    let source = Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "codex.sessions".to_string(),
        path: PathBuf::from(crate::test_fixture_path(
            "session_stores/codex/sessions/2026/04/uc001-negative-domain-only.jsonl",
        )),
    };

    let detections = detect_sources(&[source]);

    assert!(detections.is_empty());
}

#[test]
fn ignores_quoted_approval_bypass_examples() {
    let source = Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "codex.sessions".to_string(),
        path: PathBuf::from(crate::test_fixture_path(
            "rule_samples/approval-bypass-quoted-example.jsonl",
        )),
    };

    let detections = detect_sources(&[source]);

    assert!(detections.is_empty());
}

#[test]
fn ignores_quoted_approval_bypass_session_fixture() {
    let source = Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "codex.sessions".to_string(),
        path: PathBuf::from(crate::test_fixture_path(
            "session_stores/codex/sessions/2026/04/approval-bypass-quoted-example.jsonl",
        )),
    };

    let detections = detect_sources(&[source]);

    assert!(detections.is_empty());
}

#[test]
fn ignores_quoted_approval_bypass_session_store_fixture() {
    let source = Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "codex.sessions".to_string(),
        path: PathBuf::from(crate::test_fixture_path(
            "session_stores/codex/sessions/2026/04/approval-bypass-quoted-example.jsonl",
        )),
    };

    let detections = detect_sources(&[source]);

    assert!(detections.is_empty());
}

#[test]
fn ignores_benign_approval_bypass_user_text_fixture() {
    let sources = discover_sources_best_effort(&crate::test_fixture_path("session_stores"));
    let detections = detect_sources(&sources);

    assert!(
        !detections
            .iter()
            .any(|(_, event)| event.session_id == "approval-bypass-user-text")
    );
}

#[test]
fn ignores_benign_approval_bypass_user_text_session_fixture() {
    let source = Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "codex.sessions".to_string(),
        path: PathBuf::from(crate::test_fixture_path(
            "session_stores/codex/sessions/2026/04/approval-bypass-user-text.jsonl",
        )),
    };

    let detections = detect_sources(&[source]);

    assert!(detections.is_empty());
}

#[test]
fn ignores_benign_approval_bypass_tool_result_fixture() {
    let sources = discover_sources_best_effort(&crate::test_fixture_path("session_stores"));
    let detections = detect_sources(&sources);

    assert!(
        !detections
            .iter()
            .any(|(_, event)| event.session_id == "approval-bypass-tool-result")
    );
}

#[test]
fn detects_uc001_server_instructions_chain() {
    let sources = discover_sources_best_effort(&crate::test_fixture_path("session_stores"));
    let detections = detect_sources(&sources);

    let event = detections
        .iter()
        .find(|(_, event)| event.session_id == "uc001-positive-server-instructions")
        .map(|(_, event)| event)
        .expect("server instructions detection");
    assert_eq!(event.severity, "critical");
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
fn detects_uc001_tool_description_chain() {
    let sources = discover_sources_best_effort(&crate::test_fixture_path("session_stores"));
    let detections = detect_sources(&sources);

    let event = detections
        .iter()
        .find(|(_, event)| event.session_id == "uc001-positive-tool-description")
        .map(|(_, event)| event)
        .expect("tool description detection");
    assert_eq!(event.severity, "critical");
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
fn detects_uc001_tool_result_injection_chain() {
    let sources = discover_sources_best_effort(&crate::test_fixture_path("session_stores"));
    let detections = detect_sources(&sources);

    let event = detections
        .iter()
        .find(|(_, event)| event.session_id == "tool-result-injection")
        .map(|(_, event)| event)
        .expect("tool result detection");
    assert_eq!(event.severity, "critical");
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
fn detects_tool_injection_shape_in_assistant_context() {
    let source = Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "codex.sessions".to_string(),
        path: PathBuf::from(crate::test_fixture_path(
            "rule_samples/tool-injection-shape.jsonl",
        )),
    };

    let detections = detect_sources(&[source]);

    assert_eq!(detections.len(), 1);
    let event = &detections[0].1;
    assert_eq!(event.session_id, "tool-injection-shape");
    assert!(event.rule_ids.contains(&"tool.injection.shape".to_string()));
    assert!(event.categories.contains(&"tool_injection".to_string()));
    assert!(
        event
            .evidence
            .iter()
            .all(|item| !item.redacted_value.is_empty())
    );
}

#[test]
fn detects_tool_injection_shape_in_session_store_fixture() {
    let source = Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "codex.sessions".to_string(),
        path: PathBuf::from(crate::test_fixture_path(
            "session_stores/codex/sessions/2026/04/tool-injection-shape-session.jsonl",
        )),
    };

    let detections = detect_sources(&[source]);

    assert_eq!(detections.len(), 1);
    let event = &detections[0].1;
    assert_eq!(event.session_id, "tool-injection-shape-session");
    assert!(event.rule_ids.contains(&"tool.injection.shape".to_string()));
    assert!(event.categories.contains(&"tool_injection".to_string()));
    assert!(
        event
            .evidence
            .iter()
            .all(|item| item.hash.is_some() && !item.redacted_value.contains("mcp-lab"))
    );
}

#[test]
fn detects_prompt_injection_in_tool_results() {
    let source = Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "codex.sessions".to_string(),
        path: PathBuf::from(crate::test_fixture_path(
            "rule_samples/tool-result-injection.jsonl",
        )),
    };

    let detections = detect_sources(&[source]);

    assert_eq!(detections.len(), 1);
    let event = &detections[0].1;
    assert_eq!(event.session_id, "tool-result-injection");
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
fn detects_prompt_injection_in_session_store_tool_results() {
    let source = Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "codex.sessions".to_string(),
        path: PathBuf::from(crate::test_fixture_path(
            "session_stores/codex/sessions/2026/04/tool-result-injection.jsonl",
        )),
    };

    let detections = detect_sources(&[source]);

    assert_eq!(detections.len(), 1);
    let event = &detections[0].1;
    assert_eq!(event.session_id, "tool-result-injection");
    assert_eq!(event.severity, "critical");
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
    assert!(event.categories.contains(&"approval_bypass".to_string()));
    assert!(!event.categories.contains(&"secret_access".to_string()));
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
fn detects_approval_bypass_context_in_assistant_messages() {
    let source = Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "codex.sessions".to_string(),
        path: PathBuf::from(crate::test_fixture_path(
            "rule_samples/approval-bypass-context.jsonl",
        )),
    };

    let detections = detect_sources(&[source]);

    assert_eq!(detections.len(), 1);
    let event = &detections[0].1;
    assert_eq!(event.session_id, "approval-bypass-context");
    assert!(
        event
            .rule_ids
            .contains(&"approval.bypass.context".to_string())
    );
    assert!(event.categories.contains(&"approval_bypass".to_string()));
    assert!(
        event
            .evidence
            .iter()
            .any(|item| item.field == "assistant_context" || item.field == "tool_result")
    );
}

#[test]
fn detects_approval_bypass_context_in_session_store_fixture() {
    let source = Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "codex.sessions".to_string(),
        path: PathBuf::from(crate::test_fixture_path(
            "session_stores/codex/sessions/2026/04/approval-bypass-context.jsonl",
        )),
    };

    let detections = detect_sources(&[source]);

    assert_eq!(detections.len(), 1);
    let event = &detections[0].1;
    assert_eq!(event.session_id, "approval-bypass-context");
    assert!(
        event
            .rule_ids
            .contains(&"approval.bypass.context".to_string())
    );
    assert!(event.categories.contains(&"approval_bypass".to_string()));
    assert!(
        event
            .evidence
            .iter()
            .any(|item| item.field == "assistant_context" || item.field == "tool_result")
    );
    assert!(
        event
            .evidence
            .iter()
            .all(|item| item.hash.is_some() && !item.redacted_value.is_empty())
    );
    assert!(
        event
            .evidence
            .iter()
            .all(|item| item.hash.is_some() && !item.redacted_value.is_empty())
    );
}

#[test]
fn ignores_benign_approval_bypass_mentions_in_user_text() {
    let source = Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "codex.sessions".to_string(),
        path: PathBuf::from(crate::test_fixture_path(
            "session_stores/codex/sessions/2026/04/approval-bypass-user-text.jsonl",
        )),
    };

    let detections = detect_sources(&[source]);

    assert!(detections.is_empty());
}

#[test]
fn ignores_benign_approval_bypass_mentions_in_tool_results() {
    let source = Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "codex.sessions".to_string(),
        path: PathBuf::from(crate::test_fixture_path(
            "session_stores/codex/sessions/2026/04/approval-bypass-tool-result.jsonl",
        )),
    };

    let detections = detect_sources(&[source]);

    assert!(detections.is_empty());
}

#[test]
fn ignores_copied_cost_data_boilerplate_for_approval_bypass() {
    let source = Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "codex.sessions".to_string(),
        path: PathBuf::from(crate::test_fixture_path(
            "session_stores/codex/sessions/2026/04/approval-bypass-cost-data.jsonl",
        )),
    };

    let detections = detect_sources(&[source]);

    assert!(detections.is_empty());
}

#[test]
fn ignores_opencode_cost_data_boilerplate_for_approval_bypass() {
    let source = Source {
        client: ClientId::OpenCode,
        kind: SourceKind::LegacyJson,
        source_id: "opencode.legacy_json".to_string(),
        path: PathBuf::from(crate::test_fixture_path(
            "session_stores/opencode/storage/message/session-noise/approval-bypass-cost-data.json",
        )),
    };

    let detections = detect_sources(&[source]);

    assert!(detections.is_empty());
}
