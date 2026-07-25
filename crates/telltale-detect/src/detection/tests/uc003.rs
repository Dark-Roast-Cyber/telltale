use super::*;

#[test]
fn detects_uc003_dns_exfiltration_chain_in_codex_fixture() {
    let source = Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "uc003-positive-dns-exfil".to_string(),
        path: PathBuf::from(crate::test_fixture_path(
            "session_stores/codex/sessions/2026/04/uc003-positive-dns-exfil.jsonl",
        )),
    };

    let detections = detect_sources(&[source]);

    assert_eq!(detections.len(), 1);
    let event = &detections[0].1;
    assert_eq!(event.session_id, "uc003-positive-dns-exfil");
    assert_eq!(event.severity, "critical");
    assert!(event.rule_ids.contains(&"execution.shell".to_string()));
    assert!(
        event
            .rule_ids
            .contains(&"execution.encoded_payload".to_string())
    );
    assert!(event.rule_ids.contains(&"exfil.dns_encoding".to_string()));
    assert!(
        event
            .rule_ids
            .contains(&"chain.shell_encoded_payload".to_string())
    );
    assert!(event.categories.contains(&"execution".to_string()));
    assert!(event.categories.contains(&"exfiltration".to_string()));
    assert!(event.tags.contains(&"dns".to_string()));
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
            && !item.redacted_value.contains("U1lOVEhFVElDX1BBWUxPQUQ")
    }));
}

#[test]
fn ignores_uc003_negative_dns_troubleshooting_fixture() {
    let source = Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "uc003-negative-dns-troubleshooting".to_string(),
        path: PathBuf::from(crate::test_fixture_path(
            "session_stores/codex/sessions/2026/04/uc003-negative-dns-troubleshooting.jsonl",
        )),
    };

    let detections = detect_sources(&[source]);

    assert!(detections.is_empty());
}

#[test]
fn detects_encoded_http_exfiltration_in_codex_fixture() {
    let source = Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "encoded-http-exfil".to_string(),
        path: PathBuf::from(crate::test_fixture_path(
            "session_stores/codex/sessions/2026/04/encoded-http-exfil.jsonl",
        )),
    };

    let detections = detect_sources(&[source]);

    assert_eq!(detections.len(), 1);
    let event = &detections[0].1;
    assert_eq!(event.session_id, "encoded-http-exfil");
    assert_eq!(event.severity, "critical");
    assert!(event.rule_ids.contains(&"network.download".to_string()));
    assert!(event.rule_ids.contains(&"exfil.encoded_http".to_string()));
    assert!(event.categories.contains(&"download".to_string()));
    assert!(event.categories.contains(&"exfiltration".to_string()));
    assert!(event.tags.contains(&"encoding".to_string()));
    assert!(
        event
            .evidence
            .iter()
            .any(|item| item.rule_id.as_deref() == Some("exfil.encoded_http"))
    );
    assert!(event.evidence.iter().all(|item| {
        item.hash.is_some()
            && !item.redacted_value.is_empty()
            && !item.redacted_value.contains("U1lOVEhFVElD")
    }));
}

#[test]
fn detects_outbound_upload_exfiltration_in_codex_fixture() {
    let source = Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "outbound-upload-exfil".to_string(),
        path: PathBuf::from(crate::test_fixture_path(
            "session_stores/codex/sessions/2026/04/outbound-upload-exfil.jsonl",
        )),
    };

    let detections = detect_sources(&[source]);

    assert_eq!(detections.len(), 1);
    let event = &detections[0].1;
    assert_eq!(event.session_id, "outbound-upload-exfil");
    assert_eq!(event.severity, "critical");
    assert!(event.rule_ids.contains(&"network.download".to_string()));
    assert!(
        event
            .rule_ids
            .contains(&"exfil.outbound_upload".to_string())
    );
    assert!(event.categories.contains(&"download".to_string()));
    assert!(event.categories.contains(&"exfiltration".to_string()));
    assert!(event.tags.contains(&"exfiltration".to_string()));
    assert!(
        event
            .evidence
            .iter()
            .any(|item| item.rule_id.as_deref() == Some("exfil.outbound_upload"))
    );
    assert!(
        event
            .evidence
            .iter()
            .all(|item| item.hash.is_some() && !item.redacted_value.is_empty())
    );
}
