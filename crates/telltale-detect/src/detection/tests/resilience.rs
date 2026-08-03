use std::{fs, path::PathBuf};

use super::*;

#[test]
fn empty_gemini_source_produces_no_events() {
    let source = Source {
        client: ClientId::Gemini,
        kind: SourceKind::Json,
        source_id: "gemini.tmp".to_string(),
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
        source_id: "codex.sessions".to_string(),
        path: PathBuf::from(crate::test_fixture_path(
            "rule_samples/malformed-source.jsonl",
        )),
    };
    let valid_source = Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "codex.sessions".to_string(),
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

#[test]
fn claude_schema_drift_emits_scanner_error_without_generic_records() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("schema-drift.jsonl");
    fs::write(&path, b"[\"Synthetic schema envelope drift input.\"]\n")
        .expect("schema drift fixture");
    let source = Source {
        client: ClientId::Claude,
        kind: SourceKind::Jsonl,
        source_id: "claude.projects".to_string(),
        path,
    };

    let detections = detect_sources(&[source]);

    assert_eq!(detections.len(), 1);
    let event = &detections[0].1;
    assert_eq!(event.event_type, "scanner_error");
    assert_eq!(event.client, "claude");
    assert_eq!(event.session_id, "scanner");
    assert!(
        event
            .evidence
            .iter()
            .any(|item| { item.field == "error" && item.redacted_value.contains("schema drift") })
    );
}

#[test]
fn unsupported_unicode_identity_emits_redacted_scanner_error() {
    let unknown_source_id = format!("unsupported-{}", "界".repeat(100));
    let source = Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: unknown_source_id.clone(),
        path: PathBuf::from("not-read.jsonl"),
    };

    let detections = detect_sources(&[source]);

    assert_eq!(detections.len(), 1);
    let event = &detections[0].1;
    assert_eq!(event.event_type, "scanner_error");
    assert!(
        event
            .evidence
            .iter()
            .all(|item| !item.redacted_value.contains(&unknown_source_id))
    );
}
