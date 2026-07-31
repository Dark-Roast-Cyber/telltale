use super::*;

#[test]
fn ignores_headless_codex_session_fixture() {
    let source = Source {
        client: ClientId::Codex,
        kind: SourceKind::HeadlessJsonl,
        source_id: "codex.headless_sessions".to_string(),
        path: PathBuf::from(crate::test_fixture_path(
            "session_stores/codex/headless/headless-a.jsonl",
        )),
    };

    let detections = detect_sources(&[source]);

    assert!(detections.is_empty());
}

#[test]
fn detects_uc001_positive_headless_codex_fixture() {
    let source = Source {
        client: ClientId::Codex,
        kind: SourceKind::HeadlessJsonl,
        source_id: "codex.headless_sessions".to_string(),
        path: PathBuf::from(crate::test_fixture_path(
            "session_stores/codex/headless/uc001-headless.jsonl",
        )),
    };

    let detections = detect_sources(&[source]);

    assert_eq!(detections.len(), 1);
    let event = &detections[0].1;
    assert_eq!(event.session_id, "uc001-headless");
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
fn detects_uc001_positive_archived_codex_fixture() {
    let source = Source {
        client: ClientId::Codex,
        kind: SourceKind::ArchivedJsonl,
        source_id: "codex.archived_sessions".to_string(),
        path: PathBuf::from(crate::test_fixture_path(
            "session_stores/codex/archived_sessions/uc001-archived.jsonl",
        )),
    };

    let detections = detect_sources(&[source]);

    assert_eq!(detections.len(), 1);
    let event = &detections[0].1;
    assert_eq!(event.session_id, "uc001-archived");
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
fn ignores_synthetic_codex_session_fixture() {
    let source = Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "codex.sessions".to_string(),
        path: PathBuf::from(crate::test_fixture_path(
            "session_stores/codex/sessions/2026/04/session-a.jsonl",
        )),
    };

    let detections = detect_sources(&[source]);

    assert!(detections.is_empty());
}

#[test]
fn ignores_opencode_legacy_session_fixture() {
    let source = Source {
        client: ClientId::OpenCode,
        kind: SourceKind::LegacyJson,
        source_id: "opencode.legacy_json".to_string(),
        path: PathBuf::from(crate::test_fixture_path(
            "session_stores/opencode/storage/message/session-a/message-a.json",
        )),
    };

    let detections = detect_sources(&[source]);

    assert!(detections.is_empty());
}

#[test]
fn detects_opencode_sqlite_session_fixture() {
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
    assert_eq!(
        detections[0].1.session_id,
        "opencode-uc001-sqlite-tool-result"
    );
}

#[test]
fn ignores_normal_mcp_tool_result_fixture() {
    let source = Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "codex.sessions".to_string(),
        path: PathBuf::from(crate::test_fixture_path(
            "rule_samples/normal-mcp-tool-result.jsonl",
        )),
    };

    let detections = detect_sources(&[source]);

    assert!(detections.is_empty());
}

#[test]
fn ignores_normal_mcp_tool_result_session_fixture() {
    let source = Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "codex.sessions".to_string(),
        path: PathBuf::from(crate::test_fixture_path(
            "session_stores/codex/sessions/2026/04/normal-mcp-tool-result.jsonl",
        )),
    };

    let detections = detect_sources(&[source]);

    assert!(detections.is_empty());
}
