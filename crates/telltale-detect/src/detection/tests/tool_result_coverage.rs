use super::*;

#[test]
fn detects_uc001_positive_claude_tool_result_fixture() {
    let source = Source {
        client: ClientId::Claude,
        kind: SourceKind::Jsonl,
        source_id: "claude.projects".to_string(),
        path: PathBuf::from(crate::test_fixture_path(
            "session_stores/claude/projects/project-c/uc001-claude-tool-result.jsonl",
        )),
    };

    let detections = detect_sources(&[source]);

    assert_eq!(detections.len(), 1);
    let event = &detections[0].1;
    assert_eq!(event.event_type, "detection");
    assert_eq!(event.client, "claude");
    assert_eq!(event.session_id, "claude-uc001-tool-result");
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
            .categories
            .contains(&"mcp_prompt_injection".to_string())
    );
    assert!(event.categories.contains(&"exfiltration".to_string()));
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
            && !item.redacted_value.contains("mcp-lab")
    }));
}

#[test]
fn detects_uc001_positive_qwen_tool_result_fixture() {
    let source = Source {
        client: ClientId::Qwen,
        kind: SourceKind::Jsonl,
        source_id: "qwen.projects".to_string(),
        path: PathBuf::from(crate::test_fixture_path(
            "session_stores/qwen/projects/project-b/chats/uc001-qwen-tool-result.jsonl",
        )),
    };

    let detections = detect_sources(&[source]);

    assert_eq!(detections.len(), 1);
    let event = &detections[0].1;
    assert_eq!(event.event_type, "detection");
    assert_eq!(event.client, "qwen");
    assert_eq!(event.session_id, "qwen-uc001-tool-result");
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
            .categories
            .contains(&"mcp_prompt_injection".to_string())
    );
    assert!(event.categories.contains(&"exfiltration".to_string()));
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
            && !item.redacted_value.contains("mcp-lab")
    }));
}

#[test]
fn detects_uc001_positive_openclaw_tool_result_fixture() {
    let source = Source {
        client: ClientId::OpenClaw,
        kind: SourceKind::Jsonl,
        source_id: "openclaw.agents".to_string(),
        path: PathBuf::from(crate::test_fixture_path(
            "session_stores/openclaw/agents/project-b/uc001-openclaw-tool-result.jsonl",
        )),
    };

    let detections = detect_sources(&[source]);

    assert_eq!(detections.len(), 1);
    let event = &detections[0].1;
    assert_eq!(event.event_type, "detection");
    assert_eq!(event.client, "openclaw");
    assert_eq!(event.session_id, "openclaw-uc001-tool-result");
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
            .categories
            .contains(&"mcp_prompt_injection".to_string())
    );
    assert!(event.categories.contains(&"exfiltration".to_string()));
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
            && !item.redacted_value.contains("mcp-lab")
    }));
}

#[test]
fn detects_uc001_positive_opencode_sqlite_tool_result_fixture() {
    let source = Source {
        client: ClientId::OpenCode,
        kind: SourceKind::Sqlite,
        source_id: "opencode.sqlite".to_string(),
        path: PathBuf::from(crate::test_fixture_path(
            "session_stores/opencode/opencode.db",
        )),
    };

    let detections = detect_sources(&[source]);

    assert_eq!(detections.len(), 1);
    let event = &detections[0].1;
    assert_eq!(event.event_type, "detection");
    assert_eq!(event.client, "opencode");
    assert_eq!(event.session_id, "opencode-uc001-sqlite-tool-result");
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
            .categories
            .contains(&"mcp_prompt_injection".to_string())
    );
    assert!(event.categories.contains(&"exfiltration".to_string()));
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
            && !item.redacted_value.contains("mcp-lab")
    }));
}

#[test]
fn detects_uc001_positive_copilot_tool_result_fixture() {
    let source = Source {
        client: ClientId::Copilot,
        kind: SourceKind::CopilotProcessLog,
        source_id: "copilot.process_log".to_string(),
        path: PathBuf::from(crate::test_fixture_path(
            "session_stores/copilot/process-uc001.log",
        )),
    };

    let detections = detect_sources(&[source]);

    assert_eq!(detections.len(), 1);
    let event = &detections[0].1;
    assert_eq!(event.event_type, "detection");
    assert_eq!(event.client, "copilot");
    assert_eq!(event.session_id, "copilot-uc001-tool-result");
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
            .categories
            .contains(&"mcp_prompt_injection".to_string())
    );
    assert!(event.categories.contains(&"exfiltration".to_string()));
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
            && !item.redacted_value.contains("mcp-lab")
    }));
}
