use super::*;

#[test]
fn empty_gemini_source_produces_no_events() {
    let source = Source {
        client: ClientId::Gemini,
        kind: SourceKind::Json,
        source_id: "gemini-empty".to_string(),
        path: PathBuf::from(crate::test_fixture_path(
            "session_stores/gemini/tmp/empty-session.json",
        )),
    };

    let detections = detect_sources(&[source]);

    assert!(
        detections.is_empty(),
        "empty Gemini source should produce no events, not scanner_error events"
    );
}

#[test]
fn continues_detection_when_one_source_fails_to_parse() {
    let malformed_source = Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "malformed-source".to_string(),
        path: PathBuf::from(crate::test_fixture_path(
            "rule_samples/malformed-source.jsonl",
        )),
    };
    let valid_source = Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "uc001-positive".to_string(),
        path: PathBuf::from(crate::test_fixture_path(
            "session_stores/codex/sessions/2026/04/uc001-positive.jsonl",
        )),
    };

    let detections = detect_sources(&[malformed_source, valid_source]);

    assert_eq!(detections.len(), 2);
    assert_eq!(detections[0].1.event_type, "scanner_error");
    assert_eq!(detections[0].1.severity, "informational");
    assert_eq!(detections[0].1.session_id, "scanner");
    assert_eq!(detections[1].1.session_id, "uc001-positive");
    assert_eq!(detections[1].1.severity, "critical");
}
